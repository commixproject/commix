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
from src.core.parse import cmdline as menu

ORDINARY = "<html><body>" + ("the page this target answers with, " * 40) + "</body></html>"
REFUSAL = "Hack attempt detected!"

class _Answer(object):
  """
  Only what reads a page off a response is used here, which is the body and nothing else.
  """
  def __init__(self, body):
    self.body = body.encode(settings.DEFAULT_CODEC)
    self.headers = {}

  def read(self):
    return self.body

  def info(self):
    return {}

  def getheader(self, *args, **kwargs):
    return None

class ARefusalServedAsAnAnswerIsStillABlock(unittest.TestCase):
  """
  A filter does not have to answer with a status code. One that answers in-band serves its own
  short page with a 200 and the application below is never reached - which anything reading the
  code alone takes for an ordinary answer, and goes on sending payloads that were already refused.
  """
  def setUp(self):
    self._state = (settings.WAF_ENABLED, settings.WAF_CHECK_BASELINE, settings.ORIGINAL_PAGE,
                   settings.WAF_IDENTIFIED, settings.HOST_INJECTION, menu.options.skip_waf,
                   settings.TARGET_NETLOC)
    self._out = settings.print_data_to_stdout
    self.said = []
    settings.print_data_to_stdout = self.said.append
    settings.WAF_ENABLED = False
    settings.WAF_IDENTIFIED = None
    settings.HOST_INJECTION = False
    settings.TARGET_NETLOC = ""
    menu.options.skip_waf = False
    settings.WAF_CHECK_BASELINE = ORDINARY
    settings.ORIGINAL_PAGE = ""

  def tearDown(self):
    (settings.WAF_ENABLED, settings.WAF_CHECK_BASELINE, settings.ORIGINAL_PAGE,
     settings.WAF_IDENTIFIED, settings.HOST_INJECTION, menu.options.skip_waf,
     settings.TARGET_NETLOC) = self._state
    settings.print_data_to_stdout = self._out

  def test_a_page_that_does_not_resemble_the_targets_own_is_one(self):
    self.assertTrue(checks.detect_waf_in_page(_Answer(REFUSAL)))
    self.assertTrue(settings.WAF_ENABLED)
    self.assertTrue(any("WAF/IPS" in str(line) for line in self.said))

  def test_the_targets_own_page_is_not(self):
    self.assertFalse(checks.detect_waf_in_page(_Answer(ORDINARY)))
    self.assertFalse(settings.WAF_ENABLED)

  def test_a_page_that_merely_moved_a_little_is_not(self):
    self.assertFalse(checks.detect_waf_in_page(_Answer(ORDINARY.replace("</body>", "<p>1</p></body>"))))
    self.assertFalse(settings.WAF_ENABLED)

  def test_nothing_is_read_into_it_where_the_check_was_turned_off(self):
    menu.options.skip_waf = True
    self.assertFalse(checks.detect_waf_in_page(_Answer(REFUSAL)))

  def test_one_already_found_is_not_found_again(self):
    settings.WAF_ENABLED = True
    self.assertFalse(checks.detect_waf_in_page(_Answer(REFUSAL)))
    self.assertEqual([], self.said)

  def test_nothing_to_compare_against_answers_nothing(self):
    settings.WAF_CHECK_BASELINE = ""
    self.assertFalse(checks.detect_waf_in_page(_Answer(REFUSAL)))

  def test_what_is_not_a_response_answers_nothing(self):
    for value in (None, False, True):
      self.assertFalse(checks.detect_waf_in_page(value))

class TheDelayIsWrittenAsAWholeNumber(unittest.TestCase):
  """
  It goes into the payload's own arithmetic, which a POSIX shell evaluates over integers alone - a
  fractional second there is a syntax error rather than a delay.
  """
  def test_the_option_takes_an_integer(self):
    option = menu.parser.get_option("--time-sec")
    self.assertEqual("int", option.type)

if __name__ == '__main__':
  unittest.main()

# eof
