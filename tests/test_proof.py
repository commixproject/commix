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
import re
import shutil
import tempfile
import unittest

from tests import _testutils
from src.core.parse import cmdline as menu
from src.utils import settings
from src.core.controller import proof

class ProofFixture(unittest.TestCase):
  """
  One proof per test, run against an executor that answers the way a target which ran the command
  would - so the report is the real one rather than a rendering of hand-written fields.
  """
  URL = "http://t/a.php?addr=127.0.0.1"

  def setUp(self):
    self._dir = tempfile.mkdtemp(prefix="commix-proof-")
    self._state = (settings.PROOF_DONE, list(settings.PROOF_EXECUTORS), settings.WAF_ENABLED,
                   settings.WAF_EVASION_APPLIED, settings.ADAPTIVE_DELAY, settings.TARGET_OS,
                   settings.TARGET_ARCH, settings.ORIGINAL_PAGE, list(settings.RESPONSE_TIMES),
                   set(settings.WARNED_HTTP_ERROR_CODES), settings.USER_DEFINED_POST_DATA,
                   settings.TOTAL_OF_REQUESTS, menu.options.proof, menu.options.tamper,
                   menu.options.delay, menu.options.url)
    self._out = settings.print_data_to_stdout
    self.said = []
    settings.print_data_to_stdout = self.said.append
    settings.PROOF_DONE = False
    settings.PROOF_EXECUTORS = []
    settings.WAF_ENABLED = False
    settings.WAF_EVASION_APPLIED = False
    settings.ADAPTIVE_DELAY = 0
    settings.TARGET_OS = settings.OS.UNIX
    settings.TARGET_ARCH = ""
    settings.ORIGINAL_PAGE = "nothing of the answer is in here"
    settings.RESPONSE_TIMES = []
    settings.WARNED_HTTP_ERROR_CODES = set()
    settings.USER_DEFINED_POST_DATA = ""
    menu.options.proof = True
    menu.options.tamper = None
    menu.options.delay = 0
    menu.options.url = self.URL

  def tearDown(self):
    (settings.PROOF_DONE, settings.PROOF_EXECUTORS, settings.WAF_ENABLED,
     settings.WAF_EVASION_APPLIED, settings.ADAPTIVE_DELAY, settings.TARGET_OS,
     settings.TARGET_ARCH, settings.ORIGINAL_PAGE, settings.RESPONSE_TIMES,
     settings.WARNED_HTTP_ERROR_CODES, settings.USER_DEFINED_POST_DATA,
     settings.TOTAL_OF_REQUESTS, menu.options.proof, menu.options.tamper,
     menu.options.delay, menu.options.url) = self._state
    settings.print_data_to_stdout = self._out
    shutil.rmtree(self._dir, ignore_errors=True)

  """
  What a target that ran the challenge would send back: the sum, bracketed by the marker the
  challenge wrapped it in.
  """
  def oracle(self, cmd):
    sum_up = re.search(r"echo (\w+)\$\(\((\d+)\+(\d+)\)\)(\w+)$", cmd)
    if not sum_up:
      return ""
    return sum_up.group(1) + str(int(sum_up.group(2)) + int(sum_up.group(3))) + sum_up.group(4)

  def report(self):
    proof.register(settings.INJECTION_TECHNIQUE.RESULTS_BASED, "addr", "GET", self.oracle)
    proof.prove(os.path.join(self._dir, "commix.log"), self.URL)
    return settings.strip_ansi_codes("\n".join(str(_) for _ in self.said))

class TheProofStatesWhatItGotThrough(ProofFixture):
  """
  Evidence is worth more where the report also says what was in the way. A run through a protection,
  behind tamper scripts or spaced out by a delay proves the same point under conditions the next
  reader cannot reconstruct from the challenge alone.
  """
  def test_a_run_with_nothing_in_the_way_states_no_conditions(self):
    self.assertNotIn("Conditions:", self.report())

  def test_a_protection_in_front_of_the_application_is_stated(self):
    settings.WAF_ENABLED = True
    self.assertIn("protection detected in front of the application", self.report())

  def test_evasion_chosen_by_the_run_itself_is_stated(self):
    settings.WAF_EVASION_APPLIED = True
    self.assertIn("evasion applied automatically", self.report())

  def test_tamper_scripts_in_effect_are_named(self):
    menu.options.tamper = "space2ifs,rev"
    self.assertIn("tamper scripts in effect: space2ifs,rev", self.report())

  def test_the_statuses_a_protection_returned_are_stated(self):
    settings.WAF_ENABLED = True
    settings.WARNED_HTTP_ERROR_CODES = set(list(settings.WAF_BLOCK_HTTP_CODES)[:1])
    said = self.report()
    self.assertIn("statuses a protection returns, seen during the run", said)

  def test_a_delay_the_target_asked_for_is_stated(self):
    settings.ADAPTIVE_DELAY = 1.25
    self.assertIn("requests were spaced out by 1.2s after the target asked for it", self.report())

  def test_a_delay_the_user_asked_for_is_stated_where_the_target_asked_for_none(self):
    menu.options.delay = 2
    self.assertIn("requests were delayed by 2.0s each", self.report())

  def test_the_conditions_sit_above_the_findings_rather_than_inside_each_one(self):
    settings.WAF_ENABLED = True
    said = self.report()
    self.assertLess(said.index("Conditions:"), said.index("Technique:"))
    self.assertEqual(1, said.count("protection detected in front of the application"))

  def test_the_written_file_carries_them_as_the_report_does(self):
    settings.WAF_ENABLED = True
    self.report()
    with open(os.path.join(self._dir, "proof.txt")) as written:
      self.assertIn("protection detected in front of the application", written.read())

  def test_the_report_is_assembled_from_the_evasion_lines_themselves(self):
    self.assertIn("_evasion", proof.prove.__code__.co_names)

if __name__ == "__main__":
  unittest.main()

# eof
