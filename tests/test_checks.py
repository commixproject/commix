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

if __name__ == "__main__":
  unittest.main()
