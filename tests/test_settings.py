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

import re
import unittest

from tests._testutils import tamper_modules
from src.utils import settings

class TamperTables(unittest.TestCase):
  """
  Every table that names a tamper script has to name one that exists, or the run reaches for a
  module that is not there - and nothing short of hitting that line would say so.
  """
  def setUp(self):
    self.scripts = set(tamper_modules())

  def test_the_flag_dictionary_covers_exactly_the_scripts_on_disk(self):
    self.assertEqual(self.scripts, set(settings.TAMPER_SCRIPTS))

  def test_the_evasion_profile_names_scripts_that_exist(self):
    missing = []
    for target_os, tiers in settings.WAF_EVASION_PROFILE.items():
      for tier in tiers:
        for script in tier.split(","):
          if script.strip() not in self.scripts:
            missing.append(target_os + ": " + script)
    self.assertEqual([], missing)

  def test_the_evasion_profile_tiers_hold_no_conflicting_pair(self):
    conflicts = set(tuple(sorted(pair)) for pair in settings.INCOMPATIBLE_TAMPER_SCRIPTS)
    offenders = []
    for target_os, tiers in settings.WAF_EVASION_PROFILE.items():
      for tier in tiers:
        scripts = [_.strip() for _ in tier.split(",")]
        for first in scripts:
          for second in scripts:
            if first < second and (first, second) in conflicts:
              offenders.append(target_os + ": " + first + " with " + second)
    self.assertEqual([], offenders)

  def test_the_conflict_pairs_name_scripts_that_exist(self):
    missing = []
    for pair in settings.INCOMPATIBLE_TAMPER_SCRIPTS:
      for script in pair:
        if script not in self.scripts:
          missing.append(script)
    self.assertEqual([], missing)

  def test_a_script_is_never_declared_to_conflict_with_itself(self):
    self.assertEqual([], [_ for _ in settings.INCOMPATIBLE_TAMPER_SCRIPTS if _[0] == _[1]])

class SeparatorTables(unittest.TestCase):
  """
  The separators a payload can be built on.
  """
  def test_each_level_holds_the_one_below_it(self):
    self.assertTrue(set(settings.SEPARATORS_LVL1).issubset(set(settings.SEPARATORS_LVL2)))
    self.assertTrue(set(settings.SEPARATORS_LVL2).issubset(set(settings.SEPARATORS_LVL3)))

  def test_the_default_separators_are_all_offered(self):
    self.assertTrue(set(settings.DEFAULT_SEPARATORS).issubset(set(settings.SEPARATORS_LVL1)))

  def test_the_pipe_separator_is_the_one_the_scripts_compare_against(self):
    self.assertIn(settings.PIPE_SEPARATOR, settings.DEFAULT_SEPARATORS)

class TamperMetadata(unittest.TestCase):
  """
  What every script has to declare for the loader to read it back.
  """
  def test_every_script_declares_its_own_name_and_tier(self):
    offenders = []
    for name, module in tamper_modules().items():
      if not hasattr(module, "__tamper__"):
        offenders.append(name + ": no '__tamper__'")
      elif module.__tamper__ != name:
        offenders.append(name + ": declares '" + str(module.__tamper__) + "'")
      if not hasattr(module, "__priority__"):
        offenders.append(name + ": no '__priority__'")
    self.assertEqual([], offenders)

  def test_every_script_says_what_it_does(self):
    # Read the way '--list-tampers' reads it - out of the file, not off the imported module.
    missing = []
    for name, module in tamper_modules().items():
      with open(module.__file__) as script:
        if not re.search(r"About:(.*)\n", script.read()):
          missing.append(name)
    self.assertEqual([], missing)

if __name__ == "__main__":
  unittest.main()
