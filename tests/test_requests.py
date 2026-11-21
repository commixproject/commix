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
"""

import unittest

from src.utils import settings
from src.core.requests import requests, headers
from src.core.parse import cmdline as menu
from src.thirdparty.six.moves import urllib as _urllib

class WhatIsRecordedIsThePayloadNotTheRequest(unittest.TestCase):
  """
  The scripts rewrite a payload for the run they are loaded in, and what they write belongs to that
  run - a name drawn at random this time is not the one the next run draws. Handed back, it becomes
  the payload of record, written into the session and read out of it by a run that can no longer
  make sense of it.
  """
  PAYLOAD = "AAA;echo TAG$((1+2))$(echo TAG)TAG;"

  def setUp(self):
    self._state = (list(settings.MULTI_ENCODED_PAYLOAD), settings.TARGET_OS, list(settings.WHITESPACES),
                   settings.INJECT_TAG, requests.init_injection)
    settings.TARGET_OS = settings.OS.UNIX
    settings.WHITESPACES = [settings.SINGLE_WHITESPACE]
    self.sent = []
    requests.init_injection = lambda payload, method, url: (self.sent.append(payload), (0.0, "addr"))[1]

  def tearDown(self):
    (settings.MULTI_ENCODED_PAYLOAD, settings.TARGET_OS, settings.WHITESPACES,
     settings.INJECT_TAG, requests.init_injection) = self._state

  def _injected(self):
    _, _, payload, _, _ = requests.perform_injection("", "", settings.SINGLE_WHITESPACE, self.PAYLOAD,
                                                     "addr", settings.HTTPMETHOD.GET, "http://t/a.php?addr=1")
    return payload

  def test_with_no_script_in_use_it_is_what_went_out(self):
    settings.MULTI_ENCODED_PAYLOAD = []
    self.assertEqual(self.PAYLOAD, self._injected())
    self.assertEqual([self.PAYLOAD], self.sent)

  def test_a_script_rewrites_what_is_sent_and_not_what_is_recorded(self):
    settings.MULTI_ENCODED_PAYLOAD = ["uninitializedvariable"]
    recorded = self._injected()
    self.assertEqual(self.PAYLOAD, recorded)
    # The request itself still carries the rewrite, which is the whole point of the script.
    self.assertNotEqual(self.PAYLOAD, self.sent[0])
    self.assertIn("${", self.sent[0])

class ResponseTimeSample(unittest.TestCase):
  """
  Which answers count as one, when the model that times them is being filled.
  """
  def setUp(self):
    self.ignore_code = list(settings.IGNORE_CODE)
    self.send_raw = headers.send_raw
    self.apply_request_policy = headers.apply_request_policy
    self.do_check = headers.do_check
    headers.apply_request_policy = lambda *a, **k: None
    headers.do_check = lambda *a, **k: None

  def tearDown(self):
    settings.IGNORE_CODE[:] = self.ignore_code
    headers.send_raw = self.send_raw
    headers.apply_request_policy = self.apply_request_policy
    headers.do_check = self.do_check

  # A target answering every request with the same error code, as '--ignore-code' was given for.
  def refuse_with(self, code):
    def send_raw(request, policy=True):
      raise _urllib.error.HTTPError(request.full_url, code, "refused", {}, None)
    headers.send_raw = send_raw

  def test_an_ignored_error_code_is_still_a_timed_answer(self):
    """
    Every technique reads such a response as the target speaking. Thrown away here, a target that
    answers each request the same way fills nothing in, and the run is stopped for having had no
    answer at all - on a parameter other techniques may already be confirmed on.
    """
    settings.IGNORE_CODE[:] = [500]
    self.refuse_with(500)
    sample = requests.quick_response_time_sample("http://127.0.0.1/x.php?a=1", "GET")
    self.assertIsNotNone(sample)
    self.assertGreaterEqual(sample, 0)

  def test_an_error_code_nobody_asked_to_ignore_is_not(self):
    settings.IGNORE_CODE[:] = []
    self.refuse_with(500)
    self.assertIsNone(requests.quick_response_time_sample("http://127.0.0.1/x.php?a=1", "GET"))

class AnHttpProxyFollowsARedirect(unittest.TestCase):
  """
  An HTTP proxy is named on each request, so the request a redirect builds went straight to the
  host it named, past the proxy the run was told to use.
  """
  def setUp(self):
    self._state = (menu.options.proxy, menu.options.ignore_proxy, menu.options.tor,
                   menu.options.tor_type, menu.options.proxy_cred, settings.PROXY_SCHEME,
                   settings.FOLLOW_REDIRECT)
    menu.options.proxy = "127.0.0.1:18093"
    menu.options.ignore_proxy = False
    menu.options.tor = False
    menu.options.proxy_cred = None
    settings.PROXY_SCHEME = "http"
    settings.FOLLOW_REDIRECT = True

  def tearDown(self):
    (menu.options.proxy, menu.options.ignore_proxy, menu.options.tor, menu.options.tor_type,
     menu.options.proxy_cred, settings.PROXY_SCHEME, settings.FOLLOW_REDIRECT) = self._state

  def _redirected(self, target="http://other.example/next"):
    from src.core.requests import redirection
    original = redirection.Request("http://first.example/a", method="GET")
    handler = redirection.RedirectHandler()
    return handler.redirect_request(original, None, 302, "Found", {}, target)

  def test_the_request_a_redirect_makes_goes_through_the_proxy(self):
    self.assertEqual("127.0.0.1:18093", self._redirected().host)

  def test_a_run_told_to_ignore_the_proxy_is_not_sent_through_it(self):
    menu.options.ignore_proxy = True
    self.assertEqual("other.example", self._redirected().host)

  def test_a_tor_run_leaves_it_to_the_opener_s_own_handler(self):
    menu.options.tor = True
    menu.options.tor_type = settings.PROXY_TYPE.HTTP
    self.assertEqual("other.example", self._redirected().host)

class AnErrorStatusIsKeptPerThread(unittest.TestCase):
  """
  Another thread's request cleared it, and the request that had been answered was sent again.
  """
  def test_what_one_thread_recorded_is_not_seen_by_another(self):
    import threading
    from src.core.requests import stability
    stability.set_last_http_error("answered 404")
    seen = []
    worker = threading.Thread(target=lambda: seen.append(stability.last_http_error()))
    worker.start()
    worker.join()
    self.assertEqual("answered 404", stability.last_http_error())
    self.assertEqual([None], seen)
    stability.set_last_http_error(None)

class ABodyTravelsWithAMarkedAddress(unittest.TestCase):
  def setUp(self):
    from src.core.requests import parameters
    self._state = (settings.USER_DEFINED_POST_DATA, settings.IGNORE_USER_DEFINED_POST_DATA, settings.TIME_RELATED_ATTACK,
                   headers.do_check, requests.get_request_response, requests.second_order_response)
    # Building a request reads the address and leaves what it learned in settings, which the other tests start from.
    import copy
    self._everything = dict((name, copy.deepcopy(value)) for name, value in vars(settings).items()
                            if name.isupper() and isinstance(value, (str, int, float, bool, type(None), list, dict, tuple)))
    headers.do_check = lambda request: None
    self.sent = []
    requests.get_request_response = lambda request: (self.sent.append(request), "")[1]
    requests.second_order_response = lambda payload: None
    settings.TIME_RELATED_ATTACK = False

  def tearDown(self):
    (settings.USER_DEFINED_POST_DATA, settings.IGNORE_USER_DEFINED_POST_DATA, settings.TIME_RELATED_ATTACK,
     headers.do_check, requests.get_request_response, requests.second_order_response) = self._state
    for name, value in self._everything.items():
      setattr(settings, name, value)

  def test_a_body_that_is_not_under_test_is_still_sent(self):
    settings.USER_DEFINED_POST_DATA = "b=2&csrf=xyz"
    settings.IGNORE_USER_DEFINED_POST_DATA = True
    requests.init_injection("1", "POST", "http://t/x.php?a=1" + settings.INJECT_TAG)
    self.assertEqual(b"b=2&csrf=xyz", self.sent[0].data)

class ACookiesFileIsReadForTheSiteItIsSentTo(unittest.TestCase):
  def setUp(self):
    self._state = (menu.options.url, menu.options.host)
    menu.options.url, menu.options.host = "http://127.0.0.1:18091/x.php?a=1", None

  def tearDown(self):
    menu.options.url, menu.options.host = self._state

  def _file(self, *rows):
    return "\n".join("\t".join(row) for row in rows)

  def test_only_the_cookies_of_that_site_are_sent(self):
    from src.core.requests import cookies
    content = self._file((".google.com", "TRUE", "/", "FALSE", "0", "SID", "g"),
                         (".bank.example", "TRUE", "/", "FALSE", "0", "session", "b"),
                         ("127.0.0.1", "FALSE", "/", "FALSE", "0", "PHPSESSID", "abc"))
    self.assertEqual("PHPSESSID=abc", cookies._parse_netscape_format(content))

  def test_an_expired_cookie_is_not_sent(self):
    from src.core.requests import cookies
    content = self._file(("127.0.0.1", "FALSE", "/", "FALSE", "1000", "old", "x"),
                         ("127.0.0.1", "FALSE", "/", "FALSE", "0", "kept", "y"))
    self.assertEqual("kept=y", cookies._parse_netscape_format(content))

  def test_the_file_is_read_again_for_each_target_of_many(self):
    # The target is handed in rather than read off the option, which belongs to whichever came first.
    from src.core.requests import cookies
    content = self._file(("127.0.0.1", "FALSE", "/", "FALSE", "0", "one", "1"),
                         ("other.example", "FALSE", "/", "FALSE", "0", "two", "2"))
    self.assertEqual("one=1", cookies._parse_netscape_format(content, "http://127.0.0.1:18091/x"))
    self.assertEqual("two=2", cookies._parse_netscape_format(content, "http://other.example/x"))

  def test_a_file_with_nothing_for_one_target_does_not_stop_the_run(self):
    import os, tempfile
    from src.core.requests import cookies
    path = os.path.join(tempfile.mkdtemp(prefix="commix-cookies-"), "cookies.txt")
    with open(path, "w") as handle:
      handle.write(self._file(("other.example", "FALSE", "/", "FALSE", "0", "two", "2")))
    state = menu.options.load_cookies
    menu.options.load_cookies = path
    try:
      self.assertIsNone(cookies.load_cookies("http://127.0.0.1:18091/x", strict=False))
      with self.assertRaises(SystemExit):
        out = settings.print_data_to_stdout
        settings.print_data_to_stdout = lambda *args: None
        try:
          cookies.load_cookies("http://127.0.0.1:18091/x")
        finally:
          settings.print_data_to_stdout = out
    finally:
      menu.options.load_cookies = state

  def test_a_name_the_run_gave_as_host_stands_for_the_site(self):
    from src.core.requests import cookies
    menu.options.host = "app.example:8080"
    content = self._file((".example", "TRUE", "/", "FALSE", "0", "sid", "z"))
    self.assertEqual("sid=z", cookies._parse_netscape_format(content))

class AScriptIsMinedOnlyFromTheSiteItIsOn(unittest.TestCase):
  def test_an_address_that_merely_contains_the_site_s_name_is_not_the_site(self):
    from src.core.requests import mining
    page = ('<script src="/a.js"></script>'
            '<script src="https://evil.example/a.js?x=127.0.0.1:18091"></script>'
            '<script src="//127.0.0.1:18091.evil.example/b.js"></script>')
    self.assertEqual(["http://127.0.0.1:18091/a.js"], mining.script_sources("http://127.0.0.1:18091/p", page))

class AnArrayBodyStaysAnArray(unittest.TestCase):
  def test_the_objects_of_an_array_are_all_kept(self):
    import json
    from src.core.requests import parameters
    tag = settings.INJECT_TAG
    body = parameters.json_int_check('[{"cmd":"1' + tag + '","k":"v"},{"cmd":"2"}]', "1")
    self.assertEqual([{"cmd": "1" + tag, "k": "v"}, {"cmd": "2"}], json.loads(body))

  def test_the_array_is_text_again_when_it_is_sent(self):
    # 'json_data' handed back the parsed list where it could not rebuild it - which the request then
    # could not encode, and every injection request of the run failed without a word.
    import json
    from src.core.controller import checks
    tag = settings.INJECT_TAG
    sent = checks.json_data('[{"cmd":"1' + tag + '"},{"cmd":"2"}]')
    self.assertTrue(isinstance(sent, str))
    self.assertEqual([{"cmd": "1" + tag}, {"cmd": "2"}], json.loads(sent))

  def test_a_body_that_cannot_be_rebuilt_is_handed_back_as_it_came(self):
    from src.core.controller import checks
    for body in ('[{"a":', "not json at all"):
      self.assertEqual(body, checks.json_data(body))

  def test_an_object_is_still_an_object(self):
    import json
    from src.core.requests import parameters
    tag = settings.INJECT_TAG
    self.assertEqual({"cmd": "1" + tag}, json.loads(parameters.json_int_check('{"cmd":"1' + tag + '"}', "1")))

class CompressionIsOnlyPutBackByTheLastRequestThatTurnedItOff(unittest.TestCase):
  def test_the_first_to_finish_does_not_put_it_back_under_another(self):
    from src.core.techniques.boolean_based import bb_injector
    saved = settings.PAGE_COMPRESSION
    try:
      settings.PAGE_COMPRESSION = True
      bb_injector._compression_off()
      bb_injector._compression_off()
      bb_injector._compression_restore()
      self.assertFalse(settings.PAGE_COMPRESSION)
      bb_injector._compression_restore()
      self.assertTrue(settings.PAGE_COMPRESSION)
    finally:
      settings.PAGE_COMPRESSION = saved

class ALowFixesInTheRequests(unittest.TestCase):
  def test_a_code_stands_alone_or_is_not_named(self):
    self.assertEqual([], requests.named_status_codes(Exception(), "IncompleteRead(4012 bytes read, 3 more expected)"))
    self.assertEqual(["401"], requests.named_status_codes(Exception(), "HTTP Error 401: Unauthorized"))
    error = _urllib.error.HTTPError("http://t/", 404, "Not Found", {}, None)
    self.assertEqual(["404"], requests.named_status_codes(error, str(error)))

  def test_a_realm_is_read_wherever_it_sits(self):
    self.assertEqual("My Realm", headers.realm_of('Digest qop="auth", realm="My Realm", nonce="x"'))
    self.assertEqual("plain", headers.realm_of("Basic realm=plain"))
    self.assertIsNone(headers.realm_of("Basic"))

  def test_a_chunk_is_sized_in_bytes(self):
    from src.core.requests import chunked
    body = chunked.split_post_data("\u0391\u03b8\u03ae\u03bd\u03b1")
    sizes = [int(line.split(";")[0], 16) for line in body.split("\r\n")[0:-3:2]]
    self.assertEqual(len("\u0391\u03b8\u03ae\u03bd\u03b1".encode("utf-8")), sum(sizes))

  def test_a_redirect_leaves_the_host_and_what_was_said_to_it_behind(self):
    from src.core.requests import redirection
    state = (menu.options.proxy, settings.FOLLOW_REDIRECT)
    menu.options.proxy, settings.FOLLOW_REDIRECT = None, True
    try:
      original = redirection.Request("https://a.example/x", headers={"Host": "a.example", "Cookie": "s=1", "X-Api-Key": "k", "Accept": "*/*"}, method="GET")
      handler = redirection.RedirectHandler()
      across = handler.redirect_request(original, None, 302, "Found", {}, "https://b.example/n")
      self.assertEqual(["Accept"], sorted(across.headers))
      downgraded = handler.redirect_request(original, None, 302, "Found", {}, "http://a.example/n")
      self.assertNotIn("Cookie", downgraded.headers)
      same = handler.redirect_request(original, None, 302, "Found", {}, "https://a.example/n")
      self.assertIn("Cookie", same.headers)
    finally:
      menu.options.proxy, settings.FOLLOW_REDIRECT = state

class MiningSkipsOnlyTheNamesTheAddressCarries(unittest.TestCase):
  def test_a_name_inside_another_is_not_carried(self):
    from src.core.requests import mining
    originals = (mining._candidates, mining._page)
    sent = []
    mining._candidates = lambda: ["id", "userid", "data", "metadata"]
    mining._page = lambda url, method: (sent.append(url), "same page")[1]
    try:
      mining.mine_parameters("http://t/a?userid=1&metadata=2", "GET")
    finally:
      mining._candidates, mining._page = originals
    asked = [url for url in sent if "&id=" in url or "&data=" in url]
    self.assertTrue(asked, "'id' and 'data' were never asked for")
    # 'userid' and 'metadata' are the address's own, and are not asked for a second time.
    self.assertTrue(all(url.count("userid=") == 1 and url.count("metadata=") == 1 for url in sent))

  def test_the_decoys_go_in_ahead_of_a_fragment(self):
    from src.core.requests import mining
    self.assertTrue(mining._with("http://t/a?x=1#f", ["id"]).endswith("#f"))
    self.assertIn("?id=", mining._with("http://t/a#f", ["id"]))

class AConnectionThatFailedIsNotAWrongPassword(unittest.TestCase):
  def setUp(self):
    from src.core.requests import authentication
    self.module = authentication
    self._once = authentication._try_credentials_once

  def tearDown(self):
    self.module._try_credentials_once = self._once

  def _answers(self, *answers):
    queue = list(answers)
    self.module._try_credentials_once = lambda *args: queue.pop(0)
    return self.module._try_credentials("http://t/", "r", "GET", "basic", "u", "p")

  def test_a_pair_that_got_through_on_the_second_try_is_right(self):
    self.assertTrue(self._answers(None, True))

  def test_a_pair_the_target_refused_is_not_asked_again(self):
    self.assertFalse(self._answers(False))

  def test_a_target_never_reached_leaves_the_pair_unproved(self):
    self.assertFalse(self._answers(None, None, None))

class ARequestIsTimedForWhatTheTargetDid(unittest.TestCase):
  """
  The plain baseline is taken outside the pacing and the token fetch, and a probe was taken inside
  them: with a delay of any size every undelayed probe was later than the baseline's threshold, and
  was read as the payload having asked for it.
  """
  def setUp(self):
    import copy
    self._everything = dict((name, copy.deepcopy(value)) for name, value in vars(settings).items()
                            if name.isupper() and isinstance(value, (str, int, float, bool, type(None), list, dict, tuple)))
    self._saved = (headers.do_check, requests.get_request_response, requests.second_order_response, headers.send_request)
    requests.second_order_response = lambda payload: None
    settings.TIME_RELATED_ATTACK = True
    settings.DELAY, settings.ADAPTIVE_DELAY = 0.3, 0
    self._jitter = menu.options.jitter
    menu.options.jitter = None

  def tearDown(self):
    headers.do_check, requests.get_request_response, requests.second_order_response, headers.send_request = self._saved
    menu.options.jitter = self._jitter
    for name, value in self._everything.items():
      setattr(settings, name, value)

  def test_the_pacing_a_run_keeps_is_not_the_targets_time(self):
    headers.do_check = lambda request: None
    requests.get_request_response = lambda request: (headers.apply_request_policy(), "")[1]
    elapsed, _ = requests.init_injection("1", "GET", "http://t/x.php?a=1" + settings.INJECT_TAG)
    self.assertLess(elapsed, 0.15)

  def test_a_token_fetched_for_the_request_is_not_the_targets_time(self):
    import time
    from src.core.requests import stability
    def fetch(request):
      with stability.excluded_span():
        time.sleep(0.3)
    headers.do_check = fetch
    requests.get_request_response = lambda request: ""
    elapsed, _ = requests.init_injection("1", "GET", "http://t/x.php?a=1" + settings.INJECT_TAG)
    self.assertLess(elapsed, 0.15)

  def test_what_the_target_took_is_still_counted(self):
    import time
    headers.do_check = lambda request: None
    requests.get_request_response = lambda request: (headers.apply_request_policy(), time.sleep(0.3), "")[2]
    elapsed, _ = requests.init_injection("1", "GET", "http://t/x.php?a=1" + settings.INJECT_TAG)
    self.assertGreaterEqual(elapsed, 0.28)
    self.assertLess(elapsed, 0.5)

  def test_a_header_injection_is_timed_the_same_way(self):
    headers.send_request = lambda request: (headers.apply_request_policy(), "")[1]
    elapsed = requests.header_injection("http://t/x.php", "1", "GET", lambda request, payload: None)
    self.assertLess(elapsed, 0.15)

  def test_a_span_inside_a_span_is_one_stretch_of_time(self):
    import time
    from src.core.requests import stability
    before = stability.excluded_seconds()
    with stability.excluded_span():
      with stability.excluded_span():
        time.sleep(0.1)
    spent = stability.excluded_seconds() - before
    self.assertGreaterEqual(spent, 0.09)
    self.assertLess(spent, 0.17)

  def test_the_time_is_kept_per_thread(self):
    import time
    import threading
    from src.core.requests import stability
    seen = []
    def work():
      with stability.excluded_span():
        time.sleep(0.1)
    worker = threading.Thread(target=work)
    before = stability.excluded_seconds()
    worker.start()
    worker.join()
    self.assertEqual(before, stability.excluded_seconds())

class AGivenUpTimeoutIsNotReadAsADelay(unittest.TestCase):
  """
  '--ignore-timeouts' gives up on a request that never answered rather than treating the target as
  unreachable - but the elapsed time of that give-up is the connection timeout's own length, not
  anything the target did, and reading it as a delay could confirm a finding from a target that
  never ran anything at all.
  """
  def setUp(self):
    import copy
    from src.core.requests import stability
    self._everything = dict((name, copy.deepcopy(value)) for name, value in vars(settings).items()
                            if name.isupper() and isinstance(value, (str, int, float, bool, type(None), list, dict, tuple)))
    self._saved = (headers.do_check, requests.get_request_response, requests.second_order_response)
    self._ignore_timeouts = menu.options.ignore_timeouts
    headers.do_check = lambda request: None
    requests.second_order_response = lambda payload: None
    menu.options.ignore_timeouts = True
    settings.TIME_RELATED_ATTACK = True
    settings.TIME_RELATED_ATTACK_RETRIES = 2
    stability.clear_gave_up_on_timeout()

  def tearDown(self):
    from src.core.requests import stability
    headers.do_check, requests.get_request_response, requests.second_order_response = self._saved
    menu.options.ignore_timeouts = self._ignore_timeouts
    stability.clear_gave_up_on_timeout()
    for name, value in self._everything.items():
      setattr(settings, name, value)

  def test_every_attempt_timing_out_reads_as_no_answer(self):
    from src.core.requests import stability
    def never_answers(request):
      stability.note_gave_up_on_timeout()
      return False
    requests.get_request_response = never_answers
    elapsed, _ = requests.init_injection("1", "GET", "http://t/x.php?a=1" + settings.INJECT_TAG)
    self.assertIsNone(elapsed)

  def test_a_real_answer_after_a_timeout_is_still_timed(self):
    from src.core.requests import stability
    calls = []
    def answers_on_second_try(request):
      calls.append(request)
      if len(calls) == 1:
        stability.note_gave_up_on_timeout()
        return False
      stability.clear_gave_up_on_timeout()
      return ""
    requests.get_request_response = answers_on_second_try
    elapsed, _ = requests.init_injection("1", "GET", "http://t/x.php?a=1" + settings.INJECT_TAG)
    self.assertIsNotNone(elapsed)
    self.assertGreaterEqual(elapsed, 0.0)

  def test_a_header_injection_given_up_on_is_not_read_as_a_delay(self):
    from src.core.requests import stability
    headers.send_request = lambda request: (stability.note_gave_up_on_timeout(), False)[1]
    elapsed = requests.header_injection("http://t/x.php", "1", "GET", lambda request, payload: None)
    self.assertIsNone(elapsed)

  def test_time_related_shell_reads_no_answer_as_not_delayed(self):
    from src.core.controller import checks
    self.assertFalse(checks.time_related_shell(None, 5))

  def test_a_give_up_is_not_folded_into_the_timing_model(self):
    from src.core.controller import checks
    state = (list(settings.PROBE_RESPONSE_TIMES), list(settings.RESPONSE_TIMES))
    try:
      checks.record_probe_response_time(None)
      checks.record_baseline_response_time(None)
      self.assertEqual(state[0], settings.PROBE_RESPONSE_TIMES)
      self.assertEqual(state[1], settings.RESPONSE_TIMES)
    finally:
      settings.PROBE_RESPONSE_TIMES[:], settings.RESPONSE_TIMES[:] = state

if __name__ == "__main__":
  unittest.main()

class AStatusIsReadOnEveryRequestNotJustTheFirst(unittest.TestCase):
  """
  What a status says about the target is true of whichever request it answered. Read only on the
  run's opening request, a '414' went unexplained, a chunked body the target would not take was
  never sent again without it, and every other error code passed in silence.
  """
  def setUp(self):
    self._state = (settings.TOTAL_OF_REQUESTS, set(settings.WARNED_HTTP_ERROR_CODES),
                   settings.print_data_to_stdout, settings.USER_DEFINED_POST_DATA)
    self.said = []
    settings.print_data_to_stdout = lambda text: self.said.append(str(text))
    settings.WARNED_HTTP_ERROR_CODES = set()
    # Well past the opening request, which is where every real payload is sent from.
    settings.TOTAL_OF_REQUESTS = 42

  def tearDown(self):
    (settings.TOTAL_OF_REQUESTS, settings.WARNED_HTTP_ERROR_CODES,
     settings.print_data_to_stdout, settings.USER_DEFINED_POST_DATA) = self._state

  def _refused(self, code, reason):
    return _urllib.error.HTTPError("http://target/x", code, reason, {}, None)

  def test_a_request_line_the_target_will_not_take_is_explained(self):
    requests.request_failed(self._refused(414, "Request-URI Too Long"))
    said = " ".join(self.said)
    self.assertIn("414", said)
    self.assertIn("longer than it accepts", said)

  def test_the_way_past_it_is_named(self):
    settings.USER_DEFINED_POST_DATA = ""
    requests.request_failed(self._refused(414, "Request-URI Too Long"))
    self.assertIn("--data", " ".join(self.said))

  def test_any_other_error_code_is_still_reported_as_interference(self):
    requests.request_failed(self._refused(500, "Internal Server Error"))
    self.assertIn("could interfere", " ".join(self.said))

  def test_a_chunked_body_the_target_will_not_read_is_turned_off(self):
    from src.core.parse import cmdline as menu
    self._chunked = (menu.options.chunked, settings.CHUNKED_UNSUPPORTED)
    try:
      menu.options.chunked, settings.CHUNKED_UNSUPPORTED = True, False
      self.assertTrue(requests.request_failed(self._refused(405, "Method Not Allowed")))
      self.assertFalse(menu.options.chunked)
      self.assertIn("chunked", " ".join(self.said))
    finally:
      menu.options.chunked, settings.CHUNKED_UNSUPPORTED = self._chunked

  def test_it_is_said_once_rather_than_on_every_request_that_is_refused(self):
    for _ in range(4):
      requests.request_failed(self._refused(414, "Request-URI Too Long"))
    self.assertEqual(1, len([_ for _ in self.said if "longer than it accepts" in _]))

class WhatARedirectSaidIsTrueOfItsOwnRequest(unittest.TestCase):
  """
  The code is set by the redirect handler as a request is answered. Never cleared, it outlived that
  request: the one named in the question put to the user, and read by whatever asked later whether
  a redirect had happened at all, was whichever the run had last been sent anywhere.
  """
  def setUp(self):
    self._state = (settings.REDIRECT_CODE, settings.DELAY, settings.ADAPTIVE_DELAY,
                   settings.REQUEST_COUNTER, menu.options.jitter, menu.options.proxy_freq,
                   menu.options.safe_freq)
    settings.DELAY = 0
    settings.ADAPTIVE_DELAY = 0
    menu.options.jitter = 0
    menu.options.proxy_freq = None
    menu.options.safe_freq = None

  def tearDown(self):
    (settings.REDIRECT_CODE, settings.DELAY, settings.ADAPTIVE_DELAY, settings.REQUEST_COUNTER,
     menu.options.jitter, menu.options.proxy_freq, menu.options.safe_freq) = self._state

  def test_a_request_does_not_start_carrying_the_one_before_it(self):
    settings.REDIRECT_CODE = 301
    headers.apply_request_policy()
    self.assertFalse(settings.REDIRECT_CODE)

  def test_a_request_that_was_never_redirected_says_so(self):
    headers.apply_request_policy()
    self.assertEqual("", settings.REDIRECT_CODE)


class ACodeTheRequestWentLookingForIsNotInterference(unittest.TestCase):
  """
  The read that checks whether the output file is still served answers "deleted" with a '404', so
  warning about it told the operator that the one thing which had gone right might be interfering
  with the tests.
  """
  def setUp(self):
    self._state = (settings.TOTAL_OF_REQUESTS, set(settings.WARNED_HTTP_ERROR_CODES))
    # Past the first request, which is where this warning used to be confined.
    settings.TOTAL_OF_REQUESTS = 42
    settings.WARNED_HTTP_ERROR_CODES = set()
    self.said = []
    self._print = settings.print_data_to_stdout
    settings.print_data_to_stdout = lambda text: self.said.append(str(text))

  def tearDown(self):
    settings.print_data_to_stdout = self._print
    settings.TOTAL_OF_REQUESTS, settings.WARNED_HTTP_ERROR_CODES = self._state
    settings.set_side_request("file_check", False)

  def _not_found(self):
    return _urllib.error.HTTPError("http://t/o.txt", 404, "Not Found", {}, None)

  def test_a_404_on_an_ordinary_request_is_still_worth_saying(self):
    requests.request_failed(self._not_found())
    self.assertTrue([_ for _ in self.said if "could interfere" in _])

  def test_the_file_check_is_not_warned_about_for_finding_what_it_asked(self):
    settings.set_side_request("file_check", True)
    requests.request_failed(self._not_found())
    self.assertFalse([_ for _ in self.said if "could interfere" in _])

  def test_the_check_puts_the_marker_back_when_it_is_done(self):
    from src.core.controller import checks
    settings.DEFINED_WEBROOT = ""
    checks.output_file_still_served()
    self.assertFalse(settings.in_side_request("file_check"))
