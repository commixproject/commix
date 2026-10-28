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
import unittest

from tests._testutils import SEPARATORS, stage, tamper_modules, separators_in
from src.utils import settings

# The scripts that cannot write their rewrite without an operator of their own, and why.
SMUGGLES_BY_DESIGN = {
                  # 'rev' reads from a pipe, and a filter stripping '|' has stripped '&' before it.
                  "rev": ("&", "&&"),
                  "randomcase": ("&", "&&"),
                  # 'od' reads a byte from its standard input alone; see the script's own notes.
                  "printf2echo": SEPARATORS,
}

class TamperSeparators(unittest.TestCase):
  # 'xforwardedfor' rewrites the request's headers, not the payload, so it takes no payload at all.
  NOT_A_PAYLOAD_REWRITE = ("xforwardedfor",)

  def test_the_sweep_reaches_every_script(self):
    """
    A script this cannot call raises, is skipped, and takes its separators with it - so the sweep
    below would pass by never asking. Counting what was found would not show that.
    """
    self.assertGreater(len(tamper_modules()), 40)
    raised = []
    for name, module in tamper_modules().items():
      if not hasattr(module, "tamper") or name in self.NOT_A_PAYLOAD_REWRITE:
        continue
      for separator in SEPARATORS:
        for target_os in (settings.OS.UNIX, settings.OS.WINDOWS):
          try:
            module.tamper(stage(separator, target_os=target_os))
          except Exception as error:
            raised.append(name + ": " + type(error).__name__)
    self.assertEqual([], sorted(set(raised)))

  """
  A payload must carry only the separator it is proving, anywhere in the string.
  """
  def test_no_script_smuggles_an_unproved_separator(self):
    offenders = []
    for separator in SEPARATORS:
      for name, module in tamper_modules().items():
        if not hasattr(module, "tamper"):
          continue
        for target_os in (settings.OS.UNIX, settings.OS.WINDOWS):
          payload = stage(separator, target_os=target_os)
          try:
            tampered = module.tamper(payload)
          except Exception:
            continue
          before, after = separators_in(payload), separators_in(tampered)
          added = [_ for _ in after if after[_] > before[_] and _ != separator]
          if added and separator not in SMUGGLES_BY_DESIGN.get(name, ()):
            offenders.append(name + " adds " + ",".join(added) + " under " + repr(separator))
    self.assertEqual([], offenders)

  def test_fold_alone_carries_no_operator_at_all(self):
    from src.tamper.obfuscation.posix import randomcase
    for separator in SEPARATORS:
      payload = stage(separator, rev=False)
      tampered = randomcase.tamper(payload)
      before, after = separators_in(payload), separators_in(tampered)
      self.assertEqual(before, after, "randomcase changed the separator count under " + repr(separator))

class TamperOperatingSystem(unittest.TestCase):
  """
  A script declared for one shell must answer for the other, since the operating system can settle
  after it was accepted - a target that sends no banner is not fingerprinted until a payload lands.
  """
  def test_every_os_specific_script_guards_at_runtime(self):
    unguarded = []
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for directory, _, filenames in os.walk(os.path.join(root, "src", "tamper")):
      if "posix" not in directory and "windows" not in directory:
        continue
      for filename in filenames:
        if not filename.endswith(".py") or filename == "__init__.py":
          continue
        with open(os.path.join(directory, filename)) as script:
          source = script.read()
        start = source.find("def tamper(payload)")
        if start != -1 and "TARGET_OS" not in source[start:]:
          unguarded.append(filename)
    self.assertEqual([], unguarded)

class TamperCommandIntegrity(unittest.TestCase):
  """
  What the user asked to run is what has to run: a rewrite may hide the command, never change it.
  """
  def test_arguments_keep_their_own_case(self):
    from src.tamper.obfuscation.posix import randomcase
    # 'awk -F' is what the operating system users are read with, and '-f' is a different flag.
    for command in ("echo Hello", "awk -F ':' '{print $1}' /etc/passwd", "ping -n 1 127.0.0.1"):
      arguments = command.partition(settings.SINGLE_WHITESPACE)[2]
      for separator in SEPARATORS:
        for rev in (False, True):
          payload = stage(separator, command=command, rev=rev)
          self.assertIn(arguments, randomcase.tamper(payload),
                        "randomcase altered the arguments of '" + command + "' under " + repr(separator))

  def test_reversal_keeps_every_word_of_the_command(self):
    from src.core.controller import checks
    # The words come back in reverse order too, so a command and its arguments read as they were.
    for separator in (";", settings.END_LINE.LF):
      program = checks.awk_reverse_program(separator)
      self.assertNotIn("|", program)
      if separator == settings.END_LINE.LF:
        self.assertNotIn(";", program, "the newline-separated program still carries a ';'")

  def test_only_the_name_is_varied(self):
    from src.tamper.obfuscation.posix import randomcase
    for target_os in (settings.OS.UNIX, settings.OS.WINDOWS):
      payload = stage(";", command="echo Hello", target_os=target_os)
      self.assertIn("Hello", randomcase.tamper(payload))

class TamperFormSelection(unittest.TestCase):
  """
  Where a rewrite needs an operator, the one it is given is the separator under test.
  """
  def test_rev_reads_back_through_the_proved_operator(self):
    from src.tamper.obfuscation.posix import rev
    expected = {";": "awk", settings.END_LINE.LF: "awk", "|": "|rev", "&": "|rev", "&&": "|rev"}
    for separator, marker in expected.items():
      payload = stage(separator, rev=True)
      self.assertIn(marker, rev.tamper(payload),
                    "rev did not use '" + marker + "' under " + repr(separator))

  def test_no_separator_leaves_the_command_untouched(self):
    from src.tamper.obfuscation.posix import rev
    for separator in list(SEPARATORS) + ["|"]:
      payload = stage(separator, rev=True)
      self.assertNotEqual(payload, rev.tamper(payload),
                          "rev handed back the payload unchanged under " + repr(separator))

if __name__ == "__main__":
  unittest.main()
