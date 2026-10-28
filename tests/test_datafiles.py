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
The word lists and the tamper contract. A file that moved, emptied or picked up a duplicate costs
nothing at import time and shows up only as a run quietly looking for less than it used to.
"""

import os
import unittest

from tests._testutils import tamper_modules
from src.utils import settings

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEXT_FILES = os.path.join(ROOT, "data", "txt")

def text_files():
  return sorted(_ for _ in os.listdir(TEXT_FILES) if _.endswith(".txt"))

class WordLists(unittest.TestCase):
  def test_the_sweep_finds_the_files_at_all(self):
    self.assertGreater(len(text_files()), 3)

  def test_every_list_is_readable_and_holds_something(self):
    empty = []
    for name in text_files():
      with open(os.path.join(TEXT_FILES, name), "rb") as handle:
        if not handle.read().strip():
          empty.append(name)
    self.assertEqual([], empty)

  def test_no_list_repeats_an_entry(self):
    # A duplicate is wasted requests, one per repeat, on every run that reads the list.
    offenders = []
    for name in text_files():
      with open(os.path.join(TEXT_FILES, name), "rb") as handle:
        entries = [_.strip() for _ in handle.read().decode(settings.DEFAULT_CODEC).splitlines()
                   if _.strip() and not _.strip().startswith("#")]
      if len(entries) != len(set(entries)):
        repeated = sorted(set(_ for _ in entries if entries.count(_) > 1))
        offenders.append(name + ": " + ", ".join(repeated[:5]))
    self.assertEqual([], offenders)

  def test_the_lists_the_code_names_are_the_lists_on_disk(self):
    missing = []
    for name in dir(settings):
      value = getattr(settings, name)
      if isinstance(value, str) and value.endswith(".txt") and os.sep in value:
        if not os.path.isfile(value):
          missing.append(name + " -> " + value)
    self.assertEqual([], missing)

class TamperContract(unittest.TestCase):
  """
  What the loader calls on every script it is given, and what it would raise on if absent.
  """
  def test_the_sweep_finds_the_scripts_at_all(self):
    self.assertGreater(len(tamper_modules()), 40)

  def test_every_script_offers_a_callable_tamper(self):
    offenders = [name for name, module in tamper_modules().items()
                 if not callable(getattr(module, "tamper", None))]
    self.assertEqual([], offenders)

  def test_every_dependency_check_is_callable(self):
    offenders = []
    for name, module in tamper_modules().items():
      dependency = getattr(module, "dependencies", None)
      if dependency is not None and not callable(dependency):
        offenders.append(name)
    self.assertEqual([], offenders)

  def test_every_priority_is_one_of_the_declared_tiers(self):
    tiers = set(getattr(settings.PRIORITY, _) for _ in dir(settings.PRIORITY) if _.isupper())
    offenders = []
    for name, module in tamper_modules().items():
      priority = getattr(module, "__priority__", None)
      if priority is not None and priority not in tiers:
        offenders.append(name + ": " + str(priority))
    self.assertEqual([], offenders)

  def test_a_dependency_check_hands_back_a_reason_or_nothing(self):
    # The loader prints whatever comes back, so anything but a string reads as a broken message.
    settings.TARGET_OS = settings.OS.UNIX
    offenders = []
    for name, module in tamper_modules().items():
      dependency = getattr(module, "dependencies", None)
      if not callable(dependency):
        continue
      try:
        answer = dependency()
      except Exception as error:
        offenders.append(name + ": raised " + type(error).__name__)
        continue
      if answer is not None and not isinstance(answer, str):
        offenders.append(name + ": " + type(answer).__name__)
    self.assertEqual([], offenders)

if __name__ == "__main__":
  unittest.main()
