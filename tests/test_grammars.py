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
import glob
import importlib
import unittest


# What every evaluated language has to say about itself for the techniques to speak it.
REQUIRED = ("NAME", "LABEL", "TERMINATOR", "PROBE", "PROBE_REGEX",
            "EXECUTION_FUNCTIONS_LVL1", "EXECUTION_FUNCTIONS_LVL2", "EXECUTION_FUNCTIONS_LVL3",
            "PREFIXES_LVL1", "PREFIXES_LVL2", "PREFIXES_LVL3",
            "SUFFIXES_LVL1", "SUFFIXES_LVL2", "SUFFIXES_LVL3",
            "SEPARATORS_LVL1", "SEPARATORS_LVL2", "SEPARATORS_LVL3")

def grammars():
  loaded = {}
  root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
  for path in sorted(glob.glob(os.path.join(root, "src", "core", "eval", "grammars", "*.py"))):
    name = os.path.basename(path)[:-len(".py")]
    if name == "__init__":
      continue
    loaded[name] = importlib.import_module("src.core.eval.grammars." + name)
  return loaded

class GrammarCompleteness(unittest.TestCase):
  def test_every_grammar_declares_what_the_techniques_ask_it_for(self):
    missing = []
    for name, grammar in grammars().items():
      for attribute in REQUIRED:
        if not hasattr(grammar, attribute):
          missing.append(name + ": " + attribute)
    self.assertEqual([], missing)

  def test_a_grammar_is_named_after_its_own_file(self):
    self.assertEqual([], [name for name, grammar in grammars().items() if grammar.NAME != name])

  def test_each_level_holds_the_one_below_it(self):
    offenders = []
    for name, grammar in grammars().items():
      for table in ("PREFIXES", "SUFFIXES", "SEPARATORS", "EXECUTION_FUNCTIONS"):
        levels = [set(getattr(grammar, table + "_LVL" + str(_))) for _ in (1, 2, 3)]
        if not (levels[0] <= levels[1] <= levels[2]):
          offenders.append(name + ": " + table)
    self.assertEqual([], offenders)

  def test_the_execution_functions_are_not_empty(self):
    self.assertEqual([], [name for name, grammar in grammars().items()
                          if not grammar.EXECUTION_FUNCTIONS_LVL1])

class GrammarSeparators(unittest.TestCase):
  """
  An evaluated language chains its own statements, so its separators are its own - not the shell's.
  """
  def test_no_grammar_offers_a_shell_separator(self):
    offenders = []
    for name, grammar in grammars().items():
      for separator in grammar.SEPARATORS_LVL3:
        if separator in ("&", "&&", "|", "||"):
          offenders.append(name + ": " + repr(separator))
    self.assertEqual([], offenders)

if __name__ == "__main__":
  unittest.main()
