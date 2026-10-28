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

"""
The patterns that drive recognition - of an encoding, of a directory, of an evaluated language.
A bad edit to one of them fails silently: nothing raises, the thing it looked for simply stops
being found. Compiled here in one sweep, with the busiest ones pinned to a case that must match
and a case that must not.
"""

import re
import unittest

from src.utils import settings

def regex_constants():
  return dict((name, getattr(settings, name)) for name in dir(settings)
              if name.endswith("_REGEX") and isinstance(getattr(settings, name), str))

class EveryPatternCompiles(unittest.TestCase):
  def test_the_sweep_finds_the_patterns_at_all(self):
    # Without this the sweep below passes by finding nothing, which is the one way it must not pass.
    self.assertGreater(len(regex_constants()), 15)

  def test_every_pattern_compiles(self):
    failures = []
    for name, pattern in regex_constants().items():
      try:
        re.compile(pattern.replace("%s", "X") if "%s" in pattern else pattern)
      except re.error as error:
        failures.append(name + ": " + str(error))
    self.assertEqual([], failures)

class RecognitionPatterns(unittest.TestCase):
  """
  What each one is supposed to recognise, and what it must leave alone.
  """
  def test_base64_recognition(self):
    self.assertTrue(re.search(settings.BASE64_RECOGNITION_REGEX, "Y29tbWl4"))
    self.assertFalse(re.search(settings.BASE64_RECOGNITION_REGEX, "not base64!"))

  def test_hex_recognition(self):
    self.assertTrue(re.search(settings.HEX_RECOGNITION_REGEX, "0x636f6d6d6978"))
    self.assertFalse(re.search(settings.HEX_RECOGNITION_REGEX, "zzz"))

  def test_a_directory_is_recognised_by_the_file_at_the_end_of_it(self):
    # The web root is read back out of a path the target printed, which is a path to a file.
    self.assertEqual("/var/www/html/index.php",
                     re.search(settings.DIRECTORY_REGEX, "in /var/www/html/index.php on line 3").group(0))
    self.assertIsNone(re.search(settings.DIRECTORY_REGEX, "/var/www/html"))

  def test_the_php_probe_reads_the_version_back(self):
    answer = '<tr><td class="e">PHP Version </td><td class="v">8.2.7</td></tr>'
    self.assertEqual("8.2.7", re.search(settings.EVAL_PROBE_REGEX, answer).group(1))
    self.assertIsNone(re.search(settings.EVAL_PROBE_REGEX, "<h1>nothing here</h1>"))

class EvalGrammarProbes(unittest.TestCase):
  """
  Each evaluated language answers a probe of its own, and the pattern that reads the answer back
  has to match what that language actually prints.
  """
  def test_every_grammar_probe_regex_compiles(self):
    import glob, os, importlib
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    checked, failures = 0, []
    for path in sorted(glob.glob(os.path.join(root, "src", "core", "eval", "grammars", "*.py"))):
      name = os.path.basename(path)[:-len(".py")]
      if name == "__init__":
        continue
      grammar = importlib.import_module("src.core.eval.grammars." + name)
      checked += 1
      try:
        re.compile(grammar.PROBE_REGEX)
      except re.error as error:
        failures.append(name + ": " + str(error))
    self.assertGreater(checked, 4)
    self.assertEqual([], failures)

if __name__ == "__main__":
  unittest.main()
