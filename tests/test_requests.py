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
