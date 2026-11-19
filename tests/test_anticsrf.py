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
from src.core.requests import anticsrf, headers
from src.core.parse import cmdline as menu
from src.thirdparty.six.moves import urllib as _urllib

SETTINGS_STATE = ("CSRF_TOKEN", "CSRF_TOKEN_ORIGINAL")
OPTIONS_STATE = ("cookie", "csrf_url", "csrf_method", "csrf_data", "csrf_retries", "live_cookies")

class ARequestCarryingTheTokenInItsCookie(unittest.TestCase):
  """
  What 'anticsrf.apply_token' puts into 'menu.options.cookie' is global, process-wide state - a
  second call, on another thread, moves it on to a token this request never validated before the
  first request's own caller gets to read it back. Proved by simulating exactly that sequence
  without real threads: deterministic, and the race does not depend on how the scheduler happens
  to interleave two live ones.
  """
  def setUp(self):
    self._settings = {name: getattr(settings, name) for name in SETTINGS_STATE}
    self._options = {name: getattr(menu.options, name, None) for name in OPTIONS_STATE}
    settings.CSRF_TOKEN = "csrftoken"
    settings.CSRF_TOKEN_ORIGINAL = "csrftoken"
    menu.options.cookie = "PHPSESSID=x; csrftoken=OLD"
    menu.options.csrf_url = None
    menu.options.csrf_method = None
    menu.options.csrf_data = None
    menu.options.csrf_retries = 0
    menu.options.live_cookies = None
    self._fetch = anticsrf._fetch_token_page
    self._find = anticsrf._find_token
    anticsrf._fetch_token_page = lambda url, method: ("", None, settings.OK_RESPONSE_CODE)
    self._tokens = iter(("AAA", "BBB"))
    anticsrf._find_token = lambda page, resp_headers: ("csrftoken", next(self._tokens))

  def tearDown(self):
    anticsrf._fetch_token_page = self._fetch
    anticsrf._find_token = self._find
    for name, value in self._settings.items():
      setattr(settings, name, value)
    for name, value in self._options.items():
      setattr(menu.options, name, value)

  def _request(self):
    return _urllib.request.Request("http://t/a.php?addr=1&csrftoken=x", method="GET")

  def test_the_returned_cookie_is_this_calls_own_not_a_later_calls(self):
    result_a = anticsrf.apply_token(self._request())
    self.assertIn("csrftoken=AAA", result_a)
    # A second call - standing in for a concurrent thread's - moves the global on.
    result_b = anticsrf.apply_token(self._request())
    self.assertIn("csrftoken=BBB", result_b)
    self.assertIn("csrftoken=BBB", menu.options.cookie)
    # The first call's own return value is untouched by the second call having run since.
    self.assertIn("csrftoken=AAA", result_a)
    self.assertNotIn("csrftoken=BBB", result_a)

  def test_do_check_sends_this_requests_own_token_not_a_later_calls(self):
    """
    The exact symptom: 'headers.do_check()' used to read 'menu.options.cookie' back *after*
    'apply_token' returned, which a second call's token had by then already moved on from.
    """
    request_a = self._request()
    saved_apply = anticsrf.apply_token
    # A second, concurrent-standing-in call lands between the token being applied to request A
    # and 'do_check' going on to build its headers from it.
    def apply_then_race(request):
      result = saved_apply(request)
      if request is request_a:
        anticsrf.apply_token(self._request())
      return result
    anticsrf.apply_token = apply_then_race
    try:
      headers.do_check(request_a)
    finally:
      anticsrf.apply_token = saved_apply
    sent = dict((name.lower(), value) for name, value in request_a.header_items())
    self.assertIn("csrftoken=AAA", sent.get(settings.COOKIE.lower(), ""))

class AParameterIsFoundAtEitherKindOfBoundary(unittest.TestCase):
  """
  'adjust_parameter' writes the token into a query string or a body, chained on '&', and into a
  cookie header, chained on ';' - found as such a bug: anchored on '&' alone, it silently left a
  cookie's token untouched whenever another cookie came before it, so the stale token went out
  unchanged and the target's check failed it the same way a non-injectable parameter would.
  """
  def test_a_cookie_token_before_the_last_pair_is_still_found(self):
    self.assertEqual("PHPSESSID=x;csrftoken=NEW",
                     anticsrf.adjust_parameter("PHPSESSID=x; csrftoken=OLD", "csrftoken", "NEW"))

  def test_a_cookie_token_as_the_first_pair_is_still_found(self):
    self.assertEqual("csrftoken=NEW; PHPSESSID=x",
                     anticsrf.adjust_parameter("csrftoken=OLD; PHPSESSID=x", "csrftoken", "NEW"))

  def test_a_query_string_token_is_unaffected(self):
    self.assertEqual("PHPSESSID=x&csrftoken=NEW&other=1",
                     anticsrf.adjust_parameter("PHPSESSID=x&csrftoken=OLD&other=1", "csrftoken", "NEW"))

  def test_a_name_that_is_only_a_substring_of_another_is_not_matched(self):
    self.assertEqual("user_token=zzz;csrftoken=NEW",
                     anticsrf.adjust_parameter("user_token=zzz;csrftoken=OLD", "csrftoken", "NEW"))

if __name__ == '__main__':
  unittest.main()

# eof
