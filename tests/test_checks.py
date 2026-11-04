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

from tests._testutils import stage
from src.utils import settings
from src.core.controller import checks
from src.core.parse import cmdline as menu

class CurrentBoundary(unittest.TestCase):
  """
  What a rewrite reads back about the boundary the parameter at hand was proved on.
  """
  def test_whitespace_falls_back_to_a_plain_space(self):
    settings.WHITESPACES = []
    self.assertEqual(settings.SINGLE_WHITESPACE, checks.current_whitespace())
    settings.WHITESPACES = ["\t"]
    self.assertEqual("\t", checks.current_whitespace())

  def test_separator_is_none_until_a_boundary_is_recorded(self):
    settings.CONFIRMED_BOUNDARY = {}
    settings.CHECKING_PARAMETER = "P"
    self.assertIsNone(checks.current_separator())

  def test_separator_comes_back_from_the_recorded_boundary(self):
    for separator in (";", "&", "&&", "|", settings.END_LINE.LF):
      stage(separator)
      self.assertEqual(separator, checks.current_separator())

  def test_a_parameter_does_not_read_another_ones_boundary(self):
    stage(";")
    settings.CHECKING_PARAMETER = "OTHER"
    self.assertIsNone(checks.current_separator())

class AwkProgram(unittest.TestCase):
  """
  The program handed to awk, whose own statements are separated by the one under test.
  """
  def test_only_a_statement_separator_awk_reads_is_usable(self):
    self.assertTrue(checks.awk_separator_usable(";"))
    self.assertTrue(checks.awk_separator_usable(settings.END_LINE.LF))
    for separator in ("&", "&&", "|", "", None):
      self.assertFalse(checks.awk_separator_usable(separator), repr(separator) + " was taken as usable")

  def test_the_program_carries_nothing_but_its_own_separator(self):
    for separator in (";", settings.END_LINE.LF):
      program = checks.awk_reverse_program(separator)
      for smuggled in ("|", "&"):
        self.assertNotIn(smuggled, program)
      if separator != ";":
        self.assertNotIn(";", program)

  def test_the_program_has_no_space_inside_its_quotes(self):
    # A space there is the whitespace substitution's to replace, which awk would then read as text.
    for separator in (";", settings.END_LINE.LF):
      for fold in (False, True):
        program = checks.awk_reverse_program(separator, fold=fold)
        self.assertNotIn(settings.SINGLE_WHITESPACE, program.strip("'"))

  def test_the_fold_is_asked_for_explicitly(self):
    self.assertIn("tolower", checks.awk_reverse_program(";", fold=True))
    self.assertNotIn("tolower", checks.awk_reverse_program(";"))

class SmallDecisions(unittest.TestCase):
  """
  Helpers a run leans on in passing. None of them reaches the network, and each one decides
  something a later line reads back as fact.
  """
  def test_a_port_is_a_number_inside_the_range(self):
    for port in ("1", "80", "8080", "65535"):
      self.assertTrue(checks._validate_port(port), port)
    for port in ("0", "65536", "-1", "", "abc", "80.5"):
      self.assertFalse(checks._validate_port(port), port)

  def test_a_uid_is_classified_by_the_range_it_falls_in(self):
    self.assertEqual("root user", checks.classify_uid("0"))
    for uid in ("1", "98"):
      self.assertEqual("system user", checks.classify_uid(uid), uid)
    for uid in ("100", "500", "1000"):
      self.assertEqual("regular user", checks.classify_uid(uid), uid)
    for uid in ("99", "60001", "65534"):
      self.assertEqual("anonymous user", checks.classify_uid(uid), uid)
    self.assertEqual("non-trusted user", checks.classify_uid("60002"))

  def test_a_uid_past_the_last_range_is_not_classified(self):
    self.assertEqual("", checks.classify_uid("65535"))

  def test_a_uid_that_is_not_a_number_is_refused(self):
    # Read off the target's own output, so it is not trusted to be a number.
    self.assertRaises(ValueError, checks.classify_uid, "nobody")

  def test_a_command_is_wrapped_so_its_output_comes_back(self):
    was = (settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX)
    try:
      settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX = "$(", ")"
      wrapped = checks.add_command_substitution("id")
      self.assertIn("id", wrapped)
      self.assertIn(settings.CMD_SUB_PREFIX, wrapped)
    finally:
      settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX = was

class TamperDependencies(unittest.TestCase):
  """
  Why a script cannot be applied to the target at hand, or nothing where it can.
  """
  def test_a_shell_gate_answers_for_the_settled_operating_system(self):
    settings.TARGET_OS = settings.OS.UNIX
    self.assertIsNone(checks.tamper_dep_unix_only("x"))
    self.assertIsNotNone(checks.tamper_dep_windows_only("x"))
    settings.TARGET_OS = settings.OS.WINDOWS
    self.assertIsNotNone(checks.tamper_dep_unix_only("x"))
    self.assertIsNone(checks.tamper_dep_windows_only("x"))

  def test_a_sink_gate_reads_the_heuristic_as_well_as_the_switch(self):
    eval_sink, eval_state = menu.options.eval_sink, settings.EVAL_BASED_STATE
    try:
      menu.options.eval_sink, settings.EVAL_BASED_STATE = None, False
      self.assertIsNotNone(checks.tamper_dep_command_incompatible("x"))
      self.assertIsNone(checks.tamper_dep_eval_incompatible("x"))
      # The heuristic probe carries eval syntax before '--eval' is ever set.
      menu.options.eval_sink, settings.EVAL_BASED_STATE = None, True
      self.assertIsNone(checks.tamper_dep_command_incompatible("x"))
      self.assertIsNotNone(checks.tamper_dep_eval_incompatible("x"))
    finally:
      menu.options.eval_sink, settings.EVAL_BASED_STATE = eval_sink, eval_state

class BooleanOracleNoise(unittest.TestCase):
  """
  What the page moves on its own, weighed against what the question answered.
  """
  def setUp(self):
    self.markings = settings.DYNAMIC_MARKINGS
    settings.DYNAMIC_MARKINGS = []

  def tearDown(self):
    settings.DYNAMIC_MARKINGS = self.markings

  # The same page, twice, with only the command's own timing moving between them.
  def page(self, timing):
    return ("<html><body><p>the command was asked and answered here</p>"
            "<b>rtt min/avg/max/mdev = " + timing + " ms</b>"
            "<p>and the rest of this page stands perfectly still</p></body></html>")

  def test_a_difference_that_moves_on_its_own_is_not_an_answer(self):
    """
    Two answers that are meant to differ, differing only where two answers that are meant to match
    already did. Taken for an answer, a boundary is confirmed on the strength of a timing.
    """
    true_page, false_page = self.page("0.015/0.048/0.073/0.022"), self.page("0.042/0.058/0.065/0.009")
    # Nothing learned about the page yet, so the timing reads as the two answers differing.
    self.assertTrue(checks.calibrate_boolean_oracle(true_page, false_page))
    # The same question asked twice is what says which part of it was never an answer.
    checks.find_dynamic_content(true_page, self.page("0.031/0.052/0.061/0.011"))
    self.assertTrue(settings.DYNAMIC_MARKINGS)
    self.assertFalse(checks.calibrate_boolean_oracle(true_page, false_page))

class DelayThreshold(unittest.TestCase):
  """
  How late an answer has to be before it counts as a delay that was asked for.
  """
  def setUp(self):
    self.disable_stats = menu.options.disable_stats
    menu.options.disable_stats = False
    settings.PROBE_RESPONSE_TIMES[:] = []

  def tearDown(self):
    menu.options.disable_stats = self.disable_stats
    settings.RESPONSE_TIMES[:] = []
    settings.PROBE_RESPONSE_TIMES[:] = []

  # A steady target around the given pace, varying by a hundredth of a second either way.
  def steady_at(self, mean):
    settings.RESPONSE_TIMES[:] = [mean + (0.01 if index % 2 else -0.01) for index in range(8)]

  def test_a_delay_that_fires_is_seen_however_slow_the_target_is(self):
    for mean in (3.0, 6.0, 11.0, 20.0, 40.0):
      self.steady_at(mean)
      timesec = 5
      self.assertTrue(checks.time_related_shell(mean + timesec, timesec),
                      "a delay of " + str(timesec) + "s was missed on a target answering in " + str(mean) + "s")

  def test_an_ordinary_answer_is_not_read_as_a_delay(self):
    for mean in (3.0, 6.0, 11.0, 20.0, 40.0):
      self.steady_at(mean)
      self.assertFalse(checks.time_related_shell(mean, 5),
                       "a plain answer of " + str(mean) + "s was read as delayed")

  def test_the_margin_is_not_raised_past_the_delay_being_asked_for(self):
    self.steady_at(20.0)
    # Half of the delay asked for, where half the target's own pace would stand well above it.
    self.assertAlmostEqual(22.5, checks.current_delay_threshold(5), places=2)
    # Nothing to measure it against leaves the margin read off the target alone.
    self.assertAlmostEqual(30.0, checks.current_delay_threshold(), places=2)

if __name__ == "__main__":
  unittest.main()
