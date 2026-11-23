#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2026 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.

Synthetic targets for the defects the Docker testbed cannot reach: a small local server that
answers the way the broken target would, or a fault put in the place the defect lived. Each test
names the defect it pins and fails on the build that still has it.
"""

import os
import re
import sys
import json
import shutil
import tempfile
import threading
import subprocess
import unittest

try:
  from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
except ImportError:  # Python 2
  from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer as ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
# What the runner was given is not for the option parser the modules below read it with.
sys.argv = ["commix.py"]

from src.utils import settings

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


class Server(object):
  """
  A target on 127.0.0.1 that records every request it is sent and answers through 'respond'.

  'respond(handler, number)' writes the answer itself; 'number' is how many requests the target had
  been sent before this one.
  """
  def __init__(self, respond):
    self.requests = []
    self._lock = threading.Lock()
    owner = self

    class Handler(BaseHTTPRequestHandler):
      protocol_version = "HTTP/1.0"

      def log_message(self, *args):
        pass

      def _serve(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        with owner._lock:
          number = len(owner.requests)
          owner.requests.append({"method": self.command, "path": self.path, "headers": dict((k.lower(), v) for k, v in self.headers.items()), "body": body})
        respond(self, number)

      do_GET = do_POST = do_HEAD = do_PUT = _serve

    self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    self.httpd.daemon_threads = True
    self.port = self.httpd.server_address[1]
    self.thread = threading.Thread(target=self.httpd.serve_forever)
    self.thread.daemon = True

  def __enter__(self):
    self.thread.start()
    return self

  def __exit__(self, *exc):
    self.httpd.shutdown()
    self.httpd.server_close()

  def url(self, path="/"):
    return "http://127.0.0.1:" + str(self.port) + path


def reply(handler, body, code=200, content_type="text/html", headers=()):
  data = body if isinstance(body, bytes) else body.encode("utf-8")
  handler.send_response(code)
  handler.send_header("Content-Type", content_type)
  handler.send_header("Content-Length", str(len(data)))
  for name, value in headers:
    handler.send_header(name, value)
  handler.end_headers()
  if handler.command != "HEAD":
    handler.wfile.write(data)


def run_commix(arguments, before="", timeout=180, extra_env=None):
  """
  Commix in a process of its own, as a user runs it. 'before' is Python run first in that process,
  which is where a fault is put in (the entry point is called after it).
  """
  output_dir = tempfile.mkdtemp(prefix="commix-synthetic-")
  code = "import sys, os\nsys.path.insert(0, os.getcwd())\n" + before + "\nimport src.core.main as _m\nsys.argv = ['commix.py'] + sys.argv[1:]\n_m.entry_point()\n"
  environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", **(extra_env or {}))
  try:
    process = subprocess.Popen([sys.executable, "-c", code] + list(arguments) + ["--batch", "--output-dir=" + output_dir],
                               cwd=ROOT, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
    try:
      out, _ = process.communicate(timeout=timeout) if sys.version_info[0] >= 3 else process.communicate()
    except subprocess.TimeoutExpired:
      process.kill()
      out, _ = process.communicate()
      out += b"\n[synthetic test timeout]"
  finally:
    shutil.rmtree(output_dir, ignore_errors=True)
  return ANSI.sub("", out.decode("utf-8", errors="replace"))


class M5_AFailureInABulkRunIsNamed(unittest.TestCase):
  """
  A target that makes the run raise used to be swallowed by a bare 'except: pass', so a crash read
  as 'nothing found' and the next target started without a word.
  """
  FAULT = (
    "import src.core.main as _main\n"
    "_calls = []\n"
    "_real = _main.main\n"
    "def _faulty(filename, url, method):\n"
    "  _calls.append(url)\n"
    "  if len(_calls) == 1:\n"
    "    raise RuntimeError('synthetic fault')\n"
    "  open(os.environ['SYNTHETIC_MARK'], 'a').write('REACHED ' + url + '\\n')\n"
    "_main.main = _faulty\n"
  )

  def test_the_fault_is_reported_and_the_next_target_is_still_tested(self):
    with Server(lambda h, n: reply(h, "<html>ok</html>")) as server:
      listing = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
      try:
        listing.write(server.url("/one.php?a=1") + "\n" + server.url("/two.php?b=2") + "\n")
        listing.close()
        mark = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        mark.close()
        output = run_commix(["-m", listing.name, "--technique=r"], before=self.FAULT, timeout=120, extra_env={"SYNTHETIC_MARK": mark.name})
        with open(mark.name) as handle:
          reached = handle.read()
      finally:
        os.unlink(listing.name)
        os.unlink(mark.name)
    self.assertIn("synthetic fault", output)
    self.assertIn("RuntimeError", output)
    self.assertIn("REACHED " + server.url("/two.php?b=2"), reached)


class M8_TheLastErrorIsPerThread(unittest.TestCase):
  """
  The error the last request came back with is read to decide whether to send it again. Another
  thread starting its own request used to wipe it in between, and the request was sent again
  although its answer (a 404) was final. Interleaved here by hand, so it does not depend on timing.
  """
  def test_another_threads_request_does_not_make_a_final_answer_repeatable(self):
    from src.core.requests import headers, stability
    from src.core.parse import cmdline as menu
    from src.thirdparty.six.moves import urllib as _urllib

    class Options(object):
      def __getattr__(self, name):
        return None

    saved_options = menu.options
    menu.options = Options()
    try:
      with Server(lambda h, n: reply(h, "gone", code=404)) as server:
        request = _urllib.request.Request(server.url("/a.php"))
        error = _urllib.error.HTTPError(server.url("/a.php"), 404, "Not Found", {}, None)
        stability.set_last_http_error(error)
        other = threading.Thread(target=stability.set_last_http_error, args=(None,))
        other.start()
        other.join()
        try:
          headers.resend(request)
        except _urllib.error.HTTPError:
          pass
        self.assertEqual(0, len(server.requests), "a 404 was sent again")
    finally:
      menu.options = saved_options
      stability.set_last_http_error(None)


class M14_AScriptFromAnotherHostIsNotFetched(unittest.TestCase):
  """
  A page that names a script on another host must not get it fetched with the cookie and
  credentials that were given for this one.
  """
  PAGE = ('<html><script src="%s"></script></html>')

  def test_only_the_same_host_and_port_is_mined(self):
    from src.core.requests import mining
    base = "http://127.0.0.1:8081/app/index.php"
    for foreign in ("http://127.0.0.1:9999/x.js",
                    "http://127.0.0.1:8081.evil.test/x.js",
                    "http://127.0.0.1.evil.test:8081/x.js",
                    "http://127.0.0.1:8081@evil.test/x.js",
                    "//evil.test/x.js"):
      self.assertEqual([], mining.script_sources(base, self.PAGE % foreign), foreign)
    self.assertEqual(["http://127.0.0.1:8081/app/x.js"], mining.script_sources(base, self.PAGE % "x.js"))
    self.assertEqual(["http://127.0.0.1:8081/y.js"], mining.script_sources(base, self.PAGE % "/y.js"))

  def test_a_foreign_server_is_never_sent_the_operators_cookie(self):
    with Server(lambda h, n: reply(h, "var a = '/hidden/api.php?x=1';", content_type="application/javascript")) as foreign:
      page = '<html><body><a href="/b.php?z=1">b</a><script src="/own.js"></script><script src="%s"></script></body></html>' % foreign.url("/x.js")
      def answer(handler, number):
        if handler.path.startswith("/own.js"):
          reply(handler, "var a = '/hidden/api.php?x=1';", content_type="application/javascript")
        else:
          reply(handler, page)
      with Server(answer) as home:
        run_commix(["-u", home.url("/a.php?q=1"), "--crawl=1", "--mine-endpoints", "--cookie=SESSION=secret", "--technique=r"], timeout=120)
    # The script of the target's own was read, so the mining did run - and the other host heard nothing of it.
    self.assertTrue([r for r in home.requests if r["path"].startswith("/own.js")], "the mining never ran")
    self.assertEqual([], [r for r in foreign.requests if "secret" in r["headers"].get("cookie", "")])
    self.assertEqual(0, len(foreign.requests))


class M15_NullConnectionKeepsCompressionForTheOthers(unittest.TestCase):
  """
  '--null-connection' turns compression off for the one request that reads a length. Per request
  and global, two threads overlapping left it off for everyone once the first had finished.
  """
  def test_overlapping_requests_restore_what_was_set(self):
    from src.core.techniques.boolean_based import bb_injector
    saved = settings.PAGE_COMPRESSION
    settings.PAGE_COMPRESSION = True
    inside, release = threading.Event(), threading.Event()
    seen = []

    def first():
      bb_injector._compression_off()
      inside.set()
      release.wait(5)
      bb_injector._compression_restore()

    def second():
      inside.wait(5)
      bb_injector._compression_off()
      seen.append(settings.PAGE_COMPRESSION)
      release.set()
      bb_injector._compression_restore()

    try:
      threads = [threading.Thread(target=first), threading.Thread(target=second)]
      [t.start() for t in threads]
      [t.join(10) for t in threads]
      self.assertEqual([False], seen)
      self.assertTrue(settings.PAGE_COMPRESSION, "compression was left off")
    finally:
      settings.PAGE_COMPRESSION = saved


class M19_TheEvaluatedLanguageIsTheOneThatAnsweredMost(unittest.TestCase):
  """
  Python and Ruby (and JavaScript) share the word 'SyntaxError'. The last language swept used to
  be the one reported, so a Python traceback came back as Ruby.
  """
  # No 'Error: message' line, which would read as the shell's own complaint and not the interpreter's.
  TRACEBACK = ("<html><pre>Traceback (most recent call last)\n  File \"<string>\", line 1\n"
               "  SyntaxError</pre></html>")

  def test_a_python_traceback_is_reported_as_python(self):
    def respond(handler, number):
      # Only what was sent with a payload in it is answered with the traceback; the page as it is carries none of those words.
      reply(handler, "<html>welcome</html>" if handler.path.endswith("code=1") else self.TRACEBACK)
    with Server(respond) as server:
      output = run_commix(["-u", server.url("/e.php?code=1"), "--technique=r", "--skip-waf"], timeout=180)
    self.assertIn("identified evaluated language: 'Python'", output)
    self.assertNotIn("identified evaluated language: 'Ruby'", output)


class M20_AShellshockSweepOutlivesAnErrorPage(unittest.TestCase):
  """
  One 500 from the target used to end the whole header sweep, so a CGI that failed once was
  reported as not vulnerable on every header it never got asked about. The error is raised where
  the sweep sends its header, which is where a target's 500 reaches it.
  """
  FAULT = (
    "import os\n"
    "import src.core.modules.shellshock.shellshock as _s\n"
    "from src.thirdparty.six.moves import urllib as _u\n"
    "_real = _s._send_header_payload\n"
    "_first = []\n"
    "def _faulty(url, header, payload):\n"
    "  open(os.environ['SYNTHETIC_MARK'], 'a').write(header + '\\n')\n"
    "  if not _first:\n"
    "    _first.append(header)\n"
    "  if header == _first[0]:\n"
    "    raise _u.error.HTTPError(url, 500, 'Internal Server Error', {}, None)\n"
    "  return _real(url, header, payload)\n"
    "_s._send_header_payload = _faulty\n"
  )

  def test_the_sweep_goes_on_to_the_next_header(self):
    with Server(lambda h, n: reply(h, "<html>cgi</html>")) as server:
      mark = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
      mark.close()
      try:
        run_commix(["-u", server.url("/cgi-bin/status.cgi"), "--module=shellshock"], before=self.FAULT, timeout=240, extra_env={"SYNTHETIC_MARK": mark.name})
        with open(mark.name) as handle:
          probed = set(line.strip() for line in handle if line.strip())
      finally:
        os.unlink(mark.name)
    self.assertGreater(len(probed), 1, "the sweep stopped at the first header: " + repr(sorted(probed)))


class M22_ASlowerSecondTargetIsMeasuredForItself(unittest.TestCase):
  """
  The delay and the response time worked out for the first target stayed in force for the second,
  whose latency is its own: the second was never measured. Two targets in a list, a quick one and
  one that answers late. Each is left as soon as its timing model has been taken, which is the
  point at which what it holds is read.
  """
  WATCH = (
    "import os\n"
    "from src.utils import settings\n"
    "from src.core.controller import checks as _c\n"
    "def _watched(*a, **k):\n"
    "  open(os.environ['SYNTHETIC_MARK'], 'a').write('TARGET %r %r\\n' % (settings.ESTIMATED_TIMESEC, settings.URL_TIME_RESPONSE))\n"
    "  raise settings.NextTargetException()\n"
    "_c.warm_up_response_baseline = _watched\n"
  )

  @unittest.skipUnless(os.environ.get("COMMIX_SLOW_TESTS"), "about 2.5 minutes - set COMMIX_SLOW_TESTS=1")
  def test_each_target_in_a_list_is_measured_for_itself(self):
    import time as _time
    def late(handler, number):
      _time.sleep(1.5)
      reply(handler, "<html>late</html>")
    with Server(lambda h, n: reply(h, "<html>quick</html>")) as quick:
      with Server(late) as slow:
        listing = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        mark = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        mark.close()
        try:
          listing.write(quick.url("/q.php?a=1") + "\n" + slow.url("/s.php?b=2") + "\n")
          listing.close()
          run_commix(["-m", listing.name, "--technique=t", "--time-sec=3"], before=self.WATCH, timeout=240, extra_env={"SYNTHETIC_MARK": mark.name})
          with open(mark.name) as handle:
            seen = [line.split() for line in handle if line.startswith("TARGET")]
        finally:
          os.unlink(listing.name)
          os.unlink(mark.name)
    self.assertEqual(2, len(seen), seen)
    quick_response, slow_response = float(seen[0][2]), float(seen[1][2])
    self.assertGreater(slow_response, quick_response + 1.0, seen)


class Auth_ATargetThatWantsCredentialsIsSettledBeforeAnyTechnique(unittest.TestCase):
  """
  The dictionary attack was started from the first response-time measurement, so a run that tests
  no time-based technique never asked for credentials and reported the login challenge as not
  injectable - and one that did test it spent the techniques before it on that challenge.
  """
  def _server(self):
    import base64
    wanted = "Basic " + base64.b64encode(b"admin:admin").decode()
    def respond(handler, number):
      if handler.headers.get("Authorization") == wanted:
        reply(handler, "<html>welcome</html>")
      else:
        reply(handler, "Authentication required", code=401, headers=(("WWW-Authenticate", 'Basic realm="Restricted area"'),))
    return Server(respond)

  def test_a_run_without_a_time_based_technique_still_finds_the_credentials(self):
    with self._server() as server:
      output = run_commix(["-u", server.url("/a.php?addr=1"), "--technique=r"], timeout=120)
    self.assertIn("Authentication succeeded using credentials: 'admin:admin'", output)

  def test_the_credentials_come_before_the_first_technique(self):
    with self._server() as server:
      output = run_commix(["-u", server.url("/a.php?addr=1"), "--technique=rb"], timeout=120)
    self.assertIn("Authentication succeeded using credentials", output)
    self.assertLess(output.index("Authentication succeeded"), output.index("Testing the results-based classic command injection technique"))

  def test_credentials_given_are_not_attacked(self):
    with self._server() as server:
      output = run_commix(["-u", server.url("/a.php?addr=1"), "--technique=r", "--auth-type=basic", "--auth-cred=admin:admin"], timeout=120)
    self.assertNotIn("dictionary-based attack", output)


class A7_APageThatEchoesTheQuestionIsNotAnAnswer(unittest.TestCase):
  """
  A page that repeats the value it was given, with quotes and expansions taken out of it, differs between a
  true and a false question by the text of the questions alone. The reflection filter cannot recognise
  what the page made of them, and a boolean finding was announced for a target that runs nothing.
  """
  def _echoing_target(self):
    def respond(handler, number):
      from urllib.parse import urlparse, parse_qs
      value = (parse_qs(urlparse(handler.path).query).get("user") or [""])[0]
      for dropped in ("'", '"', "\\", "${IFS}"):
        value = value.replace(dropped, "")
      reply(handler, "<html><body><b>" + value + "</b></body></html>")
    return Server(respond)

  def test_an_echoing_page_yields_no_boolean_finding(self):
    with self._echoing_target() as server:
      output = run_commix(["-u", server.url("/e.php?user=abc"), "--technique=b", "--os=unix", "--skip-waf"], timeout=180)
    self.assertNotIn("injectable via boolean-based blind command injection", output)


class M26_ASkippedTimeBasedTechniqueRunsNothingElse(unittest.TestCase):
  """
  Answering 'skip' to the lagging question used to run the file-based flow under the time-based
  label, and leave the time-related flag set for every technique after it.
  """
  def test_skip_returns_false_and_clears_the_flag(self):
    from src.core.techniques.time_based import tb_handler
    from src.core.controller import checks
    from src.utils import common
    ran = []
    saved = (checks.response_times_unsteady, common.read_input, tb_handler.tb_injection_handler, settings.TIME_RELATED_ATTACK)
    checks.response_times_unsteady = lambda: True
    common.read_input = lambda *a, **k: "s"
    tb_handler.tb_injection_handler = lambda *a, **k: ran.append(a) or True
    try:
      result = tb_handler.exploitation("http://t/a.php?x=1", 3, "f", "GET", 0, "Blind command injection", "time-based")
      self.assertIs(False, result)
      self.assertEqual([], ran)
      self.assertFalse(settings.TIME_RELATED_ATTACK)
    finally:
      (checks.response_times_unsteady, common.read_input, tb_handler.tb_injection_handler, settings.TIME_RELATED_ATTACK) = saved


class M3_AnUnknownSystemIsAskedAboutEvenWithoutHeuristics(unittest.TestCase):
  """
  '--skip-heuristics' used to go on to the techniques with the system never settled, because the
  question lived in the heuristic it skipped.
  """
  def test_the_question_is_put_and_the_run_goes_on(self):
    with Server(lambda h, n: reply(h, "<html>plain</html>")) as server:
      output = run_commix(["-u", server.url("/a.php?addr=1"), "--skip-heuristics", "--technique=r"], timeout=120)
    self.assertIn("Do you recognize the target's operating system", output)
    self.assertLess(output.index("Do you recognize the target's operating system"), output.index("Testing the results-based classic command injection technique"))


class M17_AnEvalSinkTakesTheTimeModelBeforeItsTimeBasedTechnique(unittest.TestCase):
  """
  Once the heuristic had named the language, the command-injection skip flag was set and the
  warm-up that read it never estimated the response time for the code sink's time-based technique.
  """
  PHP_VERSION = '<html><table><tr><td>PHP Version </td><td class="v">8.1.2</td></tr></table></html>'
  WATCH = (
    "import os\n"
    "from src.core.requests import requests as _r\n"
    "_real = _r.estimate_response_time\n"
    "def _watched(*a, **k):\n"
    "  open(os.environ['SYNTHETIC_MARK'], 'a').write('ESTIMATED\\n')\n"
    "  return _real(*a, **k)\n"
    "_r.estimate_response_time = _watched\n"
  )

  def test_the_response_time_is_estimated_after_the_heuristic_names_the_language(self):
    def respond(handler, number):
      reply(handler, self.PHP_VERSION if "phpinfo" in handler.path else "<html>plain</html>")
    with Server(respond) as server:
      mark = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
      mark.close()
      try:
        output = run_commix(["-u", server.url("/e.php?code=1"), "--eval=php", "--technique=t", "--time-sec=3"], before=self.WATCH, timeout=45, extra_env={"SYNTHETIC_MARK": mark.name})
        with open(mark.name) as handle:
          estimated = handle.read()
      finally:
        os.unlink(mark.name)
    self.assertIn("identified PHP version", output)
    self.assertIn("ESTIMATED", estimated)


class M21_ASkippedSubstitutionHasNoLengthToCompare(unittest.TestCase):
  """
  Without '$(...)' the payload cannot carry a length, so the control it is compared against would be
  the probe itself - and every answer read as a statistical anomaly.
  """
  def test_a_length_is_compared_only_where_one_can_be_carried(self):
    from src.core.controller import checks
    saved = (settings.TARGET_OS, settings.SKIP_SUBST)
    try:
      settings.TARGET_OS = settings.OS.UNIX
      settings.SKIP_SUBST = False
      self.assertTrue(checks.decision_is_length_based())
      settings.SKIP_SUBST = True
      self.assertFalse(checks.decision_is_length_based())
      settings.TARGET_OS = settings.OS.WINDOWS
      self.assertFalse(checks.decision_is_length_based())
    finally:
      settings.TARGET_OS, settings.SKIP_SUBST = saved

  def test_the_decision_payload_carries_no_length_when_substitution_is_skipped(self):
    from src.core.techniques.time_based import tb_payloads
    saved = (settings.TARGET_OS, settings.SKIP_SUBST)
    try:
      settings.TARGET_OS = settings.OS.UNIX
      settings.SKIP_SUBST = True
      payload = tb_payloads.decision(";", "TAG", 5, 5, "GET")
      self.assertEqual(";sleep 5", payload)
    finally:
      settings.TARGET_OS, settings.SKIP_SUBST = saved


class M22_NothingLearnedAboutOneTargetIsCarriedToTheNext(unittest.TestCase):
  """
  The delay worked out for the first target, the model taken, and a stored answer to the lagging
  question were still in force for the second, whose latency is its own.
  """
  def test_the_time_state_goes_back_to_what_it_was_before_the_first_target(self):
    saved = (dict(settings._TARGET_STATE_BASELINE), dict(settings._OPTIONS_BASELINE))
    names = ("ESTIMATED_TIMESEC", "CALIBRATED_TIMESEC", "PAYLOAD_BASELINE_SAMPLED", "UNSTABLE_REQUEST_CHOICE")
    before = dict((name, getattr(settings, name)) for name in names)
    try:
      settings._TARGET_STATE_BASELINE.clear()
      settings._OPTIONS_BASELINE.clear()
      settings.reset_target_state()
      settings.ESTIMATED_TIMESEC = 9
      settings.CALIBRATED_TIMESEC = 9
      settings.PAYLOAD_BASELINE_SAMPLED = True
      settings.UNSTABLE_REQUEST_CHOICE = "s"
      settings.reset_target_state()
      for name in names:
        self.assertEqual(before[name], getattr(settings, name), name)
    finally:
      settings._TARGET_STATE_BASELINE.clear()
      settings._TARGET_STATE_BASELINE.update(saved[0])
      settings._OPTIONS_BASELINE.clear()
      settings._OPTIONS_BASELINE.update(saved[1])
      for name in names:
        setattr(settings, name, before[name])


class Bisect_AMissAndAnEmptyAnswerAreTold(unittest.TestCase):
  """
  '_bisect' used to return None both for a search whose every answer was no and for one that lost
  an answer part-way, so a question the oracle never answered while the length was being halved
  read as an output of zero length, with nothing flagged.
  """
  def _run(self, answer):
    from src.core.techniques.boolean_based import bb_handler
    saved = bb_handler._ask
    bb_handler._ask = lambda channel, payload: answer(payload)
    try:
      return bb_handler._bisect(None, lambda n: n, 0, 64)
    finally:
      bb_handler._ask = saved

  def test_a_search_of_nothing_but_noes_is_none_and_a_miss_is_not(self):
    from src.core.techniques.boolean_based import bb_handler
    self.assertIsNone(self._run(lambda n: False))
    self.assertIs(bb_handler.MISSED, self._run(lambda n: None))
    self.assertFalse(bb_handler.MISSED)

  def test_a_found_value_is_returned(self):
    self.assertEqual(37, self._run(lambda n: n <= 37))
    self.assertEqual(0, self._run(lambda n: n <= 0))

  def _length(self, answers):
    # The questions asked of the oracle, in order: whatever it is told to say for the nth one.
    from src.core.techniques.boolean_based import bb_handler
    saved = (bb_handler._ask, settings.INCOMPLETE_OUTPUT, settings.print_data_to_stdout, settings.VERBOSITY_LEVEL)
    asked = []
    def ask(channel, payload):
      asked.append(payload)
      return answers(len(asked), payload)
    class Payloads(object):
      def get_length(self, separator, cmd, candidate, operator=None):
        return candidate
    bb_handler._ask = ask
    settings.INCOMPLETE_OUTPUT = False
    settings.print_data_to_stdout = lambda *a, **k: None
    settings.VERBOSITY_LEVEL = 1
    try:
      class Channel(object):
        separator = ";"
      length = bb_handler.output_length(Channel(), "id", payloads=Payloads())
      return length, settings.INCOMPLETE_OUTPUT
    finally:
      bb_handler._ask, settings.INCOMPLETE_OUTPUT, settings.print_data_to_stdout, settings.VERBOSITY_LEVEL = saved

  def test_a_question_lost_while_halving_the_length_is_flagged_not_read_as_empty(self):
    # Yes up to a length of 2 (so the span grows to 1, 2 and is halved between 2 and 4), then nothing answers.
    length, incomplete = self._length(lambda n, q: (True if q <= 2 else None) if n <= 3 else None)
    self.assertEqual("", length)
    self.assertTrue(incomplete)

  def test_an_output_that_really_is_empty_is_not_flagged(self):
    length, incomplete = self._length(lambda n, q: q <= 0)
    self.assertEqual(0, length)
    self.assertFalse(incomplete)

  def test_a_byte_whose_answers_were_lost_asks_no_wider_range(self):
    from src.core.techniques.boolean_based import bb_handler
    asked = []
    saved = bb_handler._ask
    bb_handler._ask = lambda channel, payload: asked.append(payload)
    class Payloads(object):
      def get_char(self, separator, cmd, position, candidate, operator=None):
        return (candidate, operator)
    class Channel(object):
      separator = ";"
    try:
      result = bb_handler._confirmed(Channel(), "id", 1, Payloads(), bb_handler.MISSED, 32, 126)
    finally:
      bb_handler._ask = saved
    self.assertIsNone(result)
    self.assertEqual([], asked)


if __name__ == "__main__":
  unittest.main()


class JSON_TheParametersOwnValueStaysInFrontOfThePayload(unittest.TestCase):
  """
  A JSON body had the payload stand in place of the parameter's value, so a sink that echoes the value gave a true-answer page unlike the page the
  value returns, and the boolean sweep refused every boundary until the replace-value pass. The value is put in front of the payload as it is for
  a form, and only the replace-value retry (REPLACE_VALUE) or a resumed session leaves it off.
  """
  NAMES = ("IS_JSON", "TESTABLE_VALUE", "LOAD_SESSION", "REPLACE_VALUE")

  def setUp(self):
    from src.core.parse import cmdline as menu
    self.menu = menu
    self._saved = dict((name, getattr(settings, name)) for name in self.NAMES)
    self._options = (menu.options.data, menu.options.prefix)
    menu.options.prefix = None
    settings.LOAD_SESSION = settings.REPLACE_VALUE = False
    settings.TESTABLE_VALUE = "127.0.0.1"

  def tearDown(self):
    for name, value in self._saved.items():
      setattr(settings, name, value)
    self.menu.options.data, self.menu.options.prefix = self._options

  def _sent(self, data, is_json=True, value="127.0.0.1"):
    from src.core.requests import requests
    settings.IS_JSON = is_json
    settings.TESTABLE_VALUE = value
    self.menu.options.data = data.replace("<TAG>", settings.INJECT_TAG)
    with Server(lambda h, n: reply(h, "<html>ok</html>")) as server:
      requests.perform_injection("", "", " ", "PAYLOAD", "", "POST", server.url("/x.php"))
      return server.requests[-1]["body"].decode("utf-8")

  def test_the_value_comes_first_in_a_json_body(self):
    body = self._sent('{"addr":"127.0.0.1<TAG>"}')
    self.assertEqual("127.0.0.1PAYLOAD", json.loads(body)["addr"])

  def test_a_form_body_carries_it_the_same_way(self):
    body = self._sent("addr=127.0.0.1<TAG>", is_json=False)
    self.assertTrue(body.startswith("addr=127.0.0.1PAYLOAD"), body)

  def test_a_numeric_looking_value_is_kept_too(self):
    body = self._sent('{"addr":"127<TAG>"}', value="127")
    self.assertEqual("127PAYLOAD", json.loads(body)["addr"])

  def test_the_other_members_of_the_body_are_untouched(self):
    body = self._sent('{"addr":"127.0.0.1<TAG>","name":"ancst"}')
    self.assertEqual({"addr": "127.0.0.1PAYLOAD", "name": "ancst"}, json.loads(body))

  def test_standing_in_place_of_the_value_still_drops_it(self):
    settings.REPLACE_VALUE = True
    body = self._sent('{"addr":"127.0.0.1<TAG>"}')
    self.assertEqual("PAYLOAD", json.loads(body)["addr"])

  def test_a_resumed_session_is_left_as_it_was(self):
    settings.LOAD_SESSION = True
    body = self._sent('{"addr":"127.0.0.1<TAG>"}')
    self.assertEqual("PAYLOAD", json.loads(body)["addr"])


class JSON_LiveAgainstTheTestbed(unittest.TestCase):
  """
  The two scenarios the change was found on. Opt-in: needs the commix-testbed container, with its address in COMMIX_TESTBED (for example http://localhost:8081).
  """
  BASE = os.environ.get("COMMIX_TESTBED")

  def _run(self, path, data, *extra):
    return run_commix(["-u", self.BASE + path, "--host=www.commix-testbed.com", "--data=" + data, "--flush-session"] + list(extra), timeout=420)

  @unittest.skipUnless(BASE, "needs the commix-testbed container - set COMMIX_TESTBED=http://localhost:8081")
  def test_blind_json_is_confirmed_without_a_retry_pass(self):
    out = self._run("/scenarios/regular/POST/blind_json.php", '{"addr":"127.0.0.1"}', "--technique=b", "--os-cmd=hostname")
    self.assertIn("appears to be injectable via boolean-based blind command injection technique", out)
    for script in ("space2ifs", "space2htab", "dashlesstest", "printf2echo"):
      self.assertNotIn("Loading tamper module '" + script + "'", out)
    self.assertNotIn("????", out)

  @unittest.skipUnless(BASE, "needs the commix-testbed container - set COMMIX_TESTBED=http://localhost:8081")
  def test_eval_json_also_reports_the_boolean_based_technique(self):
    out = self._run("/scenarios/regular/POST/eval_json.php", '{"name":"ancst"}')
    self.assertIn("appears to be injectable via boolean-based blind code injection technique", out)
