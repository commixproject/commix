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
from src.core.controller import checks
from src.core.requests import headers
from src.core.parse import cmdline as menu
from src.thirdparty.six.moves import urllib as _urllib

FINGERPRINT_STATE = ("WAF_EVASION_FINGERPRINT_APPLIED", "BROWSER_LIKE_HEADERS", "WAF_ENABLED",
                     "WAF_EVASION_CONSENT", "USER_APPLIED_TAMPER", "USER_AGENT_INJECTION",
                     "VERBOSITY_LEVEL")
OPTIONS_STATE = ("agent", "requestfile", "logfile", "skip_waf", "tamper", "data", "cookie",
                 "live_cookies", "referer", "host", "chunked")

class _AFreshRun(unittest.TestCase):
  """
  What a run holds about the request it names itself with, put back the way it was found.
  """
  def setUp(self):
    self._settings = {name: getattr(settings, name) for name in FINGERPRINT_STATE}
    self._options = {name: getattr(menu.options, name, None) for name in OPTIONS_STATE}
    self._printed = []
    self._print = settings.print_data_to_stdout
    settings.print_data_to_stdout = lambda text: self._printed.append(str(text))
    settings.WAF_EVASION_FINGERPRINT_APPLIED = False
    settings.BROWSER_LIKE_HEADERS = False
    settings.USER_AGENT_INJECTION = None
    settings.VERBOSITY_LEVEL = 0
    menu.options.agent = settings.DEFAULT_USER_AGENT
    menu.options.requestfile = None
    menu.options.logfile = None

  def tearDown(self):
    settings.print_data_to_stdout = self._print
    for name, value in self._settings.items():
      setattr(settings, name, value)
    for name, value in self._options.items():
      setattr(menu.options, name, value)

class TheRequestStopsNamingTheToolOnceTheProtectionIsAnswered(_AFreshRun):
  """
  A filter reading the "User-Agent" has settled what to do with the request before anything it
  carries is looked at, so the header is answered first and the payload second.
  """
  def test_the_default_header_is_replaced_with_a_browsers_own(self):
    self.assertTrue(checks.neutralize_request_fingerprint())
    self.assertNotEqual(settings.DEFAULT_USER_AGENT, menu.options.agent)
    self.assertIn(menu.options.agent, common_user_agents())

  def test_the_headers_that_go_with_it_follow(self):
    checks.neutralize_request_fingerprint()
    self.assertTrue(settings.BROWSER_LIKE_HEADERS)

  def test_it_is_only_done_once(self):
    checks.neutralize_request_fingerprint()
    chosen = menu.options.agent
    self.assertFalse(checks.neutralize_request_fingerprint())
    self.assertEqual(chosen, menu.options.agent)

  def test_a_header_the_user_settled_is_left_as_it_stands(self):
    menu.options.agent = "Hello/1.0"
    self.assertFalse(checks.neutralize_request_fingerprint())
    self.assertEqual("Hello/1.0", menu.options.agent)
    self.assertFalse(settings.BROWSER_LIKE_HEADERS)

  def test_the_header_being_injected_through_is_left_as_it_stands(self):
    settings.USER_AGENT_INJECTION = True
    self.assertFalse(checks.neutralize_request_fingerprint())
    self.assertEqual(settings.DEFAULT_USER_AGENT, menu.options.agent)
    self.assertFalse(settings.BROWSER_LIKE_HEADERS)

class ConsentCarriedOverFromAnEarlierRunStillAnswersIt(_AFreshRun):
  """
  The answer is remembered rather than asked again, so a resumed run would otherwise go on naming
  the tool to the very protection it was told to get past.
  """
  def setUp(self):
    _AFreshRun.setUp(self)
    settings.WAF_ENABLED = True
    settings.WAF_EVASION_CONSENT = True
    settings.USER_APPLIED_TAMPER = ""
    menu.options.skip_waf = False
    menu.options.tamper = None

  def test_the_stored_yes_is_acted_on_without_asking_again(self):
    self.assertTrue(checks.waf_evasion_consent())
    self.assertNotEqual(settings.DEFAULT_USER_AGENT, menu.options.agent)

  def test_a_stored_no_leaves_the_request_as_it_is(self):
    settings.WAF_EVASION_CONSENT = False
    self.assertFalse(checks.waf_evasion_consent())
    self.assertEqual(settings.DEFAULT_USER_AGENT, menu.options.agent)
    self.assertFalse(settings.BROWSER_LIKE_HEADERS)

class TheHeadersAreSentAsASet(_AFreshRun):
  """
  A browser's "User-Agent" over a "*/*" nothing but a scanner sends, and with no "Accept-Language"
  behind it, is still a scanner to anything reading the three together.
  """
  def setUp(self):
    _AFreshRun.setUp(self)
    menu.options.data = None
    menu.options.cookie = None
    menu.options.live_cookies = None
    menu.options.referer = None
    menu.options.host = None
    menu.options.chunked = False

  def _headers_of_a_request(self):
    request = _urllib.request.Request("http://t/a.php?addr=1", method="GET")
    headers.do_check(request)
    return dict((name.lower(), value) for name, value in request.header_items())

  def test_a_run_that_names_the_tool_asks_the_way_it_always_has(self):
    sent = self._headers_of_a_request()
    self.assertEqual(settings.ACCEPT_VALUE, sent[settings.ACCEPT.lower()])
    self.assertNotIn(settings.ACCEPT_LANGUAGE.lower(), sent)

  def test_a_run_that_reads_as_a_browser_asks_the_way_one_does(self):
    settings.BROWSER_LIKE_HEADERS = True
    sent = self._headers_of_a_request()
    self.assertEqual(settings.HTTP_ACCEPT_BROWSER_VALUE, sent[settings.ACCEPT.lower()])
    self.assertEqual(settings.HTTP_ACCEPT_LANGUAGE_BROWSER_VALUE, sent[settings.ACCEPT_LANGUAGE.lower()])

  def test_a_request_carrying_no_body_names_no_type_for_one(self):
    self.assertNotIn(settings.CONTENT_TYPE.lower(), self._headers_of_a_request())

  def test_a_request_carrying_one_says_what_it_is(self):
    request = _urllib.request.Request("http://t/a.php", b"addr=1", method="POST")
    headers.do_check(request)
    sent = dict((name.lower(), value) for name, value in request.header_items())
    self.assertEqual(settings.DEFAULT_HTTP_CONTENT_TYPE_VALUE, sent[settings.CONTENT_TYPE.lower()])

class TheVisitThatKeepsTheSessionIsAnOrdinaryOne(_AFreshRun):
  """
  Sent for the session rather than to test anything, so what the evasion turned on is left off it -
  a fresh spoofed client address on each of them is the surest way to lose the very session it was
  sent to hold, and the target is not the one being evaded.
  """
  def setUp(self):
    _AFreshRun.setUp(self)
    self._script = settings.TAMPER_SCRIPTS["xforwardedfor"]
    settings.TAMPER_SCRIPTS["xforwardedfor"] = True
    menu.options.chunked = True
    menu.options.data = None
    menu.options.cookie = None
    menu.options.live_cookies = None
    menu.options.referer = None
    menu.options.host = None

  def tearDown(self):
    settings.TAMPER_SCRIPTS["xforwardedfor"] = self._script
    _AFreshRun.tearDown(self)

  def _sent(self, **kwargs):
    request = _urllib.request.Request("http://t/a.php", b"addr=1", method="POST")
    headers.do_check(request, **kwargs)
    return dict((name.lower(), value) for name, value in request.header_items())

  def test_a_request_being_tested_still_carries_what_the_evasion_turned_on(self):
    sent = self._sent()
    self.assertIn("x-forwarded-for", sent)
    self.assertEqual("chunked", sent[settings.TRANSFER_ENCODING.lower()])

  def test_the_visit_that_keeps_the_session_carries_none_of_it(self):
    sent = self._sent(safe=True)
    self.assertNotIn("x-forwarded-for", sent)
    self.assertNotIn(settings.TRANSFER_ENCODING.lower(), sent)

  def test_it_still_carries_what_the_session_is_held_by(self):
    menu.options.cookie = "PHPSESSID=abc"
    sent = self._sent(safe=True)
    self.assertEqual("PHPSESSID=abc", sent[settings.COOKIE.lower()])
    self.assertIn(settings.USER_AGENT.lower(), sent)

"""
The browser User-Agent values switch '--random-agent' draws from.
"""
def common_user_agents():
  from src.utils import common
  return common.load_list_from_file(settings.USER_AGENT_LIST, "user-agent list")

if __name__ == '__main__':
  unittest.main()

# eof
