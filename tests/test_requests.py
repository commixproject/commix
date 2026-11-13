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
