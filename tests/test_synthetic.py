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
