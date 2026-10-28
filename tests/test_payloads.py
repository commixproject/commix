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
import inspect
import importlib
import unittest

from tests._testutils import SEPARATORS, separators_in
from src.utils import settings

TECHNIQUES = ("results_based.rb_payloads", "time_based.tb_payloads", "file_based.fb_payloads",
              "tempfile_based.tfb_payloads", "boolean_based.bb_payloads")

"""
Builders that cannot write their shape with the separator under test alone. Empty, and meant to
stay that way: a payload measures something and then delays on the answer, and that is written as
one command - the delay scaled by the comparison itself - rather than as two chained by an
operator of their own. Nothing goes in here without a reason that says why its shape cannot.
"""
UNRESOLVED = set()

"""
A value for whatever the builder asks for, named the way the builders name it.
"""
def argument_for(name):
  if name in ("TAG", "tag"):
    return "MARKER"
  if name in ("cmd", "command"):
    return "echo Hello"
  if name.startswith("randv"):
    return "11"
  if name in ("timesec", "delay"):
    return 5
  if name == "http_request_method":
    return "GET"
  if name in ("OUTPUT_TEXTFILE", "filename"):
    return "out.txt"
  if name == "tags":
    return ["MARKER"]
  if name in ("condition", "expression"):
    return "1 -eq 1"
  if name == "operator":
    return "-eq"
  if name == "word":
    return "MARKER"
  if name == "qmarks":
    return 1
  return 1

"""
Every payload builder that takes the separator as its first argument.
"""
def builders():
  found = []
  for technique in TECHNIQUES:
    module = importlib.import_module("src.core.techniques." + technique)
    for name, function in inspect.getmembers(module, inspect.isfunction):
      if function.__module__ != module.__name__:
        continue
      parameters = list(inspect.signature(function).parameters)
      if parameters and parameters[0] == "separator":
        found.append((technique.split(".")[-1], name, function, parameters))
  return found

class PayloadSeparators(unittest.TestCase):
  """
  A payload exists to prove that one separator chains commands at the sink, so that is the only one
  it may carry - a target filtering some other operator would otherwise defeat a separator that
  works, and the separator is reported as not injectable.
  """
  def setUp(self):
    settings.TARGET_OS = settings.OS.UNIX
    settings.WHITESPACES = [settings.SINGLE_WHITESPACE]
    settings.TIME_RELATED_ATTACK = True

  # Builders that answer with nothing on a POSIX target, because that is not what they are for.
  INERT = ("windows_condition_check", "oracle_supported", "_supported", "_var_chain")

  def test_the_sweep_exercises_the_builders_it_found(self):
    """
    Counting what was found is not enough: a builder this cannot construct arguments for raises,
    is skipped, and takes its separators with it - so the sweep below would pass by never asking.
    """
    built, unexercised = 0, []
    for module_name, name, function, parameters in builders():
      answered = False
      for separator in SEPARATORS:
        try:
          payload = function(separator, *[argument_for(_) for _ in parameters[1:]])
        except Exception:
          continue
        if isinstance(payload, str) and payload.strip():
          answered, built = True, built + 1
      if not answered and name not in self.INERT:
        unexercised.append(module_name + "." + name)
    self.assertEqual([], unexercised)
    self.assertGreater(built, 100)

  def test_no_builder_carries_a_separator_it_is_not_proving(self):
    offenders = []
    for module_name, name, function, parameters in builders():
      if (module_name, name) in UNRESOLVED:
        continue
      for separator in SEPARATORS:
        try:
          payload = function(separator, *[argument_for(_) for _ in parameters[1:]])
        except Exception:
          continue
        if not isinstance(payload, str):
          continue
        counted = separators_in(payload)
        added = sorted(_ for _ in counted if counted[_] and _ != separator)
        if added:
          offenders.append(module_name + "." + name + " adds " +
                           ",".join(repr(_) for _ in added) + " under " + repr(separator))
    self.assertEqual([], offenders)

  def test_the_unresolved_list_names_builders_that_exist(self):
    known = set((module_name, name) for module_name, name, _, _ in builders())
    self.assertEqual(set(), UNRESOLVED - known)

  def test_the_unresolved_list_holds_nothing_already_compliant(self):
    # A builder that has been written clean must come off the list, or it stops being checked.
    still_offending = set()
    for module_name, name, function, parameters in builders():
      if (module_name, name) not in UNRESOLVED:
        continue
      for separator in SEPARATORS:
        try:
          payload = function(separator, *[argument_for(_) for _ in parameters[1:]])
        except Exception:
          continue
        if not isinstance(payload, str):
          continue
        counted = separators_in(payload)
        if any(counted[_] and _ != separator for _ in counted):
          still_offending.add((module_name, name))
    self.assertEqual(UNRESOLVED, still_offending)

class AwkExpressions(unittest.TestCase):
  """
  The measurements a payload makes when it cannot carry a variable from one command to the next.
  Each is handed to awk as an argument, so none of them needs a pipe - and each program is written
  so that it needs no separator of its own either.
  """
  def _programs(self):
    from src.core.techniques.time_based import tb_payloads
    from src.core.techniques.tempfile_based import tfb_payloads
    return {
      "length": tb_payloads._length_arg_expr("WORD"),
      "ordinal": tb_payloads._ordinal_arg_expr("WORD", 3),
      "flatten": tfb_payloads.flattened_trimmed_text("FILE"),
    }

  def test_none_of_them_pipes(self):
    # A pipe is what each of these exists to avoid; 'wc', 'rev' and 'tr' all read one.
    for name, program in self._programs().items():
      self.assertNotIn("|", program, name + " reaches for a pipe")

  def test_none_of_them_chains(self):
    for name, program in self._programs().items():
      for operator in ("&&", "||", "&", ";"):
        self.assertNotIn(operator, program, name + " carries " + repr(operator))

  def test_no_awk_program_holds_a_space_inside_its_own_quotes(self):
    """
    A space there is text to awk and a separator to the substitution that rewrites whitespace, so
    a run with a space2* script would rewrite the program itself into something awk cannot read.
    """
    for name, program in self._programs().items():
      # Only awk's own program, since the ordinal carries a lone quote of printf's beside it.
      programs = re.findall(r"awk '([^']*)'", program)
      self.assertTrue(programs, name + " has no awk program to check")
      for part in programs:
        self.assertNotIn(" ", part, name + " holds a space inside its quotes")

class ArithmeticConditions(unittest.TestCase):
  """
  A 'test' comparison, rewritten as arithmetic so the delay can be scaled by it instead of branching
  on it - and refused where it is not one, rather than mistranslated into something that always holds.
  """
  def test_a_numeric_comparison_translates(self):
    from src.core.techniques.time_based import tb_payloads
    for condition, expected in (("1 -eq 1", "1==1"), ("2 -ne 3", "2!=3"), ("4 -le 5", "4<=5"),
                                ("6 -lt 7", "6<7"), ("8 -ge 9", "8>=9"), ("1 -gt 0", "1>0")):
      self.assertEqual(expected, tb_payloads._arithmetic_condition(condition))

  def test_anything_else_is_refused(self):
    from src.core.techniques.time_based import tb_payloads
    for condition in ("-f /etc/passwd", "\"$x\" = \"y\"", "-n $VAR", "1 -eq $VAR"):
      self.assertIsNone(tb_payloads._arithmetic_condition(condition), condition + " was translated")

  def test_the_condition_payloads_use_it(self):
    # The separator count is the sweep's job; this is only that the arithmetic replaced the branch.
    from src.core.techniques.time_based import tb_payloads
    for separator in ("&", "&&"):
      payload = tb_payloads.condition_check(separator, "1 -eq 1", 5, "GET")
      self.assertIn("1==1", payload)
      self.assertNotIn("[ 1 -eq 1 ]", payload)

class BackticksFallback(unittest.TestCase):
  """
  The one-command forms nest one substitution inside another, which backticks cannot express - so
  a run using them keeps the older shape. It still has to produce a payload.
  """
  def test_a_payload_is_still_built_with_backticks(self):
    from src.core.techniques.time_based import tb_payloads
    settings.USE_BACKTICKS = True
    try:
      for separator in ("&", "&&"):
        payload = tb_payloads.decision(separator, "MARKER", 6, 5, "GET")
        self.assertTrue(payload.strip(), "no payload under " + repr(separator))
        self.assertNotIn("awk", payload, "the nested form was used with backticks")
    finally:
      settings.USE_BACKTICKS = False

class PayloadShape(unittest.TestCase):
  def setUp(self):
    settings.TARGET_OS = settings.OS.UNIX
    settings.WHITESPACES = [settings.SINGLE_WHITESPACE]
    settings.TIME_RELATED_ATTACK = True

  def test_every_builder_hands_back_a_payload(self):
    empty = []
    for module_name, name, function, parameters in builders():
      try:
        payload = function(";", *[argument_for(_) for _ in parameters[1:]])
      except Exception:
        continue
      if isinstance(payload, str) and not payload.strip():
        empty.append(module_name + "." + name)
    self.assertEqual([], empty)

  def test_an_interpreter_payload_separates_its_statements_without_a_semicolon(self):
    # A carriage return is a line break to the interpreter and not an operator to a filter.
    from src.core.techniques.time_based import tb_payloads
    payload = tb_payloads.decision_alter_interpreter(";", "MARKER", 1, 5, "GET")
    self.assertIn("import time" + settings.END_LINE.CR, payload)

if __name__ == "__main__":
  unittest.main()
