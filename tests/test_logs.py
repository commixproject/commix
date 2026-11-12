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

import os
import json
import shutil
import tempfile
import unittest

from src.utils import logs
from src.utils import settings
from src.core.parse import cmdline as menu

class AFindingReadsTheSameWhereverItIsRead(unittest.TestCase):
  """
  The line a finding is written out as is one line, whether it is read off the screen, out of the
  log file or out of the report. The command beside it is the exception, and says why: it carries
  the request as it went out, because that is what brings the finding back.
  """
  PAYLOAD = "QQE;echo TAG;"

  def setUp(self):
    self.directory = tempfile.mkdtemp()
    self._state = (menu.options.no_logging, menu.options.results_file, menu.options.report_json,
                   menu.options.url, menu.options.data, settings.REPORT_JSON,
                   settings.TESTABLE_VALUE, settings.TESTABLE_VALUE_STOOD_IN_FOR,
                   settings.LOGGED_FINDINGS_HEADER, settings.LAST_LOGGED_PARAMETER)
    menu.options.no_logging = True
    menu.options.results_file = None
    menu.options.data = None
    menu.options.url = "http://t/a.php?addr=QQE"
    menu.options.report_json = os.path.join(self.directory, "report.json")
    settings.REPORT_JSON = {}
    settings.LOGGED_FINDINGS_HEADER = False
    settings.LAST_LOGGED_PARAMETER = None
    settings.TESTABLE_VALUE, settings.TESTABLE_VALUE_STOOD_IN_FOR = "QQE", "127.0.0.1"
    logs.add_finding(os.path.join(self.directory, "logs.txt"), settings.INJECTION_TYPE.RESULTS_BASED_CI,
                     settings.INJECTION_TECHNIQUE.RESULTS_BASED, "GET", "addr", self.PAYLOAD)
    self.finding = settings.REPORT_JSON["findings"][0]

  def tearDown(self):
    (menu.options.no_logging, menu.options.results_file, menu.options.report_json,
     menu.options.url, menu.options.data, settings.REPORT_JSON,
     settings.TESTABLE_VALUE, settings.TESTABLE_VALUE_STOOD_IN_FOR,
     settings.LOGGED_FINDINGS_HEADER, settings.LAST_LOGGED_PARAMETER) = self._state
    shutil.rmtree(self.directory, ignore_errors=True)

  def test_the_reported_payload_carries_the_parameters_own_value(self):
    self.assertEqual("127.0.0.1;echo TAG;", self.finding["payload"])

  def test_the_command_carries_what_was_sent_instead(self):
    # It is run as it stands, so the stand-in the sink ignores has to stay in it.
    self.assertIn(self.PAYLOAD, self.finding["reproduce"])

  def test_the_difference_between_the_two_is_said_rather_than_left_there(self):
    self.assertTrue(any("QQE" in caveat for caveat in self.finding["reproduce_caveats"]))

  def test_the_report_on_disk_says_the_same(self):
    with open(menu.options.report_json, encoding=settings.DEFAULT_CODEC) as handle:
      self.assertEqual("127.0.0.1;echo TAG;", json.load(handle)["findings"][0]["payload"])

class AFindingFoundWithTheValueIsWrittenOutAsItWas(unittest.TestCase):
  """
  Nothing stood in for the value, so there is nothing to put back - and a value carried over from a
  parameter tested earlier is not this parameter's to write in.
  """
  def setUp(self):
    self._state = (menu.options.no_logging, menu.options.results_file, menu.options.report_json,
                   menu.options.url, menu.options.data, settings.REPORT_JSON,
                   settings.TESTABLE_VALUE, settings.TESTABLE_VALUE_STOOD_IN_FOR,
                   settings.LOGGED_FINDINGS_HEADER, settings.LAST_LOGGED_PARAMETER)
    self.directory = tempfile.mkdtemp()
    menu.options.no_logging = True
    menu.options.results_file = None
    menu.options.data = None
    menu.options.url = "http://t/a.php?addr=1"
    menu.options.report_json = os.path.join(self.directory, "report.json")
    settings.REPORT_JSON = {}
    settings.LOGGED_FINDINGS_HEADER = False
    settings.LAST_LOGGED_PARAMETER = None
    settings.TESTABLE_VALUE, settings.TESTABLE_VALUE_STOOD_IN_FOR = "1", ""
    logs.add_finding(os.path.join(self.directory, "logs.txt"), settings.INJECTION_TYPE.RESULTS_BASED_CI,
                     settings.INJECTION_TECHNIQUE.RESULTS_BASED, "GET", "addr", "1;echo TAG;")
    self.finding = settings.REPORT_JSON["findings"][0]

  def tearDown(self):
    (menu.options.no_logging, menu.options.results_file, menu.options.report_json,
     menu.options.url, menu.options.data, settings.REPORT_JSON,
     settings.TESTABLE_VALUE, settings.TESTABLE_VALUE_STOOD_IN_FOR,
     settings.LOGGED_FINDINGS_HEADER, settings.LAST_LOGGED_PARAMETER) = self._state
    shutil.rmtree(self.directory, ignore_errors=True)

  def test_the_payload_is_the_one_that_was_sent(self):
    self.assertEqual("1;echo TAG;", self.finding["payload"])

  def test_nothing_is_said_about_a_stand_in(self):
    self.assertNotIn("reproduce_caveats", self.finding)

if __name__ == '__main__':
  unittest.main()

# eof
