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
import subprocess
import sys
import tempfile
import unittest

from tests._testutils import tamper_modules
from src.utils import settings

class IgnoreCodeWildcard(unittest.TestCase):
  """
  What '--ignore-code' is given to mean every code rather than a list of them.
  """
  def test_the_wildcard_is_one_character(self):
    self.assertEqual("*", settings.IGNORE_CODE_WILDCARD)

  def test_it_is_not_a_code_any_list_could_hold(self):
    self.assertFalse(settings.IGNORE_CODE_WILDCARD.isdigit())

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

class FirstLevelBoundaries(unittest.TestCase):
  """
  What the level nobody has to ask for is willing to try.
  """
  def test_the_first_level_can_open_and_close_a_quote(self):
    """
    The commonest shape a real sink has is a value spliced into a quoted string. Without a quote
    here those targets answer every boundary the same way and are reported as not injectable, which
    is true of what was tried and false of the target.
    """
    for quote in settings.QUOTES:
      self.assertIn(quote, settings.PREFIXES_LVL1)
      self.assertIn(quote, settings.SUFFIXES_LVL1)

  def test_the_levels_above_it_lost_nothing(self):
    # The quotes moved down rather than being added, so the wider levels carry what they carried.
    for quote in settings.QUOTES:
      self.assertIn(quote, settings.PREFIXES_LVL3)
      self.assertIn(quote, settings.SUFFIXES_LVL3)
    self.assertIn(" #", settings.SUFFIXES_LVL3)

  def test_the_shell_list_carries_only_a_comment_the_shell_reads(self):
    """
    '//' and '\\' were added for the evaluation sinks before those had grammars of their own, and
    every grammar carries them now - so in the shell's own list they were boundaries no shell reads
    as an ending, asked once per separator on every parameter tested.
    """
    for borrowed in ("//", "\\"):
      self.assertNotIn(borrowed, settings.SUFFIXES_LVL3)
    from src.core import eval as _eval
    self.assertIn("//", _eval.grammar("php").SUFFIXES_LVL3)
    self.assertIn("//", _eval.grammar("javascript").SUFFIXES_LVL3)

class ConsentCarriesAcrossTargets(unittest.TestCase):
  """
  Each retry consent asks whether another pass around an obstacle is worth what it costs, which is
  the question the WAF/IPS consent asks about a filter it identified. Asked once and held for the
  run, as all four say they are - a list, a crawl or a page of forms otherwise puts the same three
  questions to the user once per target.
  """
  CONSENTS = ("WHITESPACE_RETRY_CHOICE", "REPLACE_VALUE_RETRY_CHOICE", "DASHLESS_RETRY_CHOICE")

  def setUp(self):
    self._baseline = dict(settings._TARGET_STATE_BASELINE)
    self._answers = {name: getattr(settings, name) for name in self.CONSENTS}
    self._arch = settings.TARGET_ARCH
    settings._TARGET_STATE_BASELINE.clear()
    for name in self.CONSENTS:
      setattr(settings, name, None)

  def tearDown(self):
    settings._TARGET_STATE_BASELINE.clear()
    settings._TARGET_STATE_BASELINE.update(self._baseline)
    for name, answer in self._answers.items():
      setattr(settings, name, answer)
    settings.TARGET_ARCH = self._arch

  def test_each_consent_is_listed_beside_the_one_it_is_modelled_on(self):
    self.assertIn("WAF_EVASION_CONSENT", settings.RUN_WIDE_STATE)
    for name in self.CONSENTS:
      self.assertIn(name, settings.RUN_WIDE_STATE)

  def test_an_answer_given_for_one_target_is_not_asked_again_for_the_next(self):
    # The first call records the baseline, every call after it is the next target starting.
    settings.reset_target_state()
    settings.TARGET_ARCH = "x86_64"
    for name in self.CONSENTS:
      setattr(settings, name, False)
    settings.reset_target_state()
    for name in self.CONSENTS:
      self.assertIs(False, getattr(settings, name), name + " was asked again")
    # What the target itself answered does go back, or the next one is tested as though it were this
    # one - which is what the reset exists for.
    self.assertEqual("", settings.TARGET_ARCH)

if __name__ == "__main__":
  unittest.main()

class ColoringIsDroppedHoweverTheSwitchArrives(unittest.TestCase):
  """
  The switch is answered from the command line before anything is parsed, so that the first message
  is already written the way it was asked for - and a profile naming it is answered once the file
  has been read, rather than parsed and dropped.
  """
  PROBE = ("import sys, os\n"
           "sys.path.insert(0, sys.argv[2])\n"
           "sys.argv = ['commix.py', '-c', sys.argv[1], '--batch']\n"
           "from src.core.parse import cmdline\n"
           "from src.utils import colors\n"
           "print('CARRIED', cmdline.options.disable_coloring, colors.ENABLE_COLORING)\n")

  def setUp(self):
    from src.utils import colors
    self.colors = colors
    self._enabled = colors.ENABLE_COLORING

  def tearDown(self):
    self.colors.ENABLE_COLORING = self._enabled

  def test_dropping_it_holds_and_asks_nothing_of_a_second_call(self):
    self.colors.ENABLE_COLORING = True
    settings.drop_coloring()
    self.assertFalse(self.colors.ENABLE_COLORING)
    settings.drop_coloring()
    self.assertFalse(self.colors.ENABLE_COLORING)

  def test_a_profile_naming_it_turns_coloring_off(self):
    # Parsed into the option and never read, the value reached the run as an answer it did not act
    # on: the switch worked written out on the command line and did nothing from a file.
    directory = tempfile.mkdtemp()
    try:
      profile = os.path.join(directory, "profile.ini")
      with open(profile, "w") as handle:
        handle.write("[Target]\nurl = http://127.0.0.1/?x=1\n\n[Miscellaneous]\ndisable_coloring = True\n")
      probe = os.path.join(directory, "probe.py")
      with open(probe, "w") as handle:
        handle.write(self.PROBE)
      root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
      said = subprocess.check_output([sys.executable, "-I", probe, profile, root],
                                     stderr=subprocess.STDOUT).decode("utf-8", "replace")
      carried = [_ for _ in said.splitlines() if _.startswith("CARRIED")]
      self.assertEqual(["CARRIED True False"], carried, said)
    finally:
      for name in os.listdir(directory):
        os.unlink(os.path.join(directory, name))
      os.rmdir(directory)

class NothingIsKeptThatNothingReads(unittest.TestCase):
  """
  A value written on every finding and never read once is weight the next reader has to account
  for, and reads as state something depends on.
  """
  def test_the_write_only_names_are_gone(self):
    for name in ("FOUND_EXEC_TIME", "FOUND_DIFF", "IDENTIFIED_SERVER_OS", "WAF_DETECTION_PHASE"):
      self.assertFalse(hasattr(settings, name), name + " is written and never read")
