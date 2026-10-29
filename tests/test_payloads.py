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
import subprocess
import re
import inspect
import importlib
import unittest

from tests._testutils import SEPARATORS, separators_in, stage as stage_exploitation
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

class ByteSemantics(unittest.TestCase):
  """
  An ordinal is read off a raw byte, and a shell in a UTF-8 locale will not decode one on its own -
  'printf' answers 32767 instead of the byte's value, so every character past the first non-ASCII
  one is asked for at a position nothing is at. The locale is pinned where the byte is read, and
  where it is counted, so the length and the indexing agree on what a position means.
  """
  TECHNIQUES = ("time_based/tb_payloads.py", "boolean_based/bb_payloads.py",
                "tempfile_based/tfb_payloads.py", "file_based/fb_payloads.py",
                "results_based/rb_payloads.py")

  def _sources(self):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for name in self.TECHNIQUES:
      with open(os.path.join(root, "src", "core", "techniques", name)) as handle:
        yield name, handle.read()
    # Where the read itself lives, now that every technique asks for it through the one helper.
    with open(os.path.join(root, "src", "core", "controller", "checks.py")) as handle:
      yield "controller/checks.py", handle.read()

  def test_every_ordinal_read_pins_the_locale(self):
    from src.core.controller import checks
    self.assertIn(settings.BYTE_LOCALE + " printf '%d'", checks.byte_ordinal("${X}"))

  def test_no_technique_reads_an_ordinal_around_the_helper(self):
    """
    The pinned locale and the range the answer is brought back into are both the helper's doing,
    so a read built anywhere else gets neither.
    """
    loose = []
    for name, source in self._sources():
      if name.endswith("checks.py"):
        continue
      for line in source.splitlines():
        if "printf '%d'" in line:
          loose.append(name + ": " + line.strip()[:60])
    self.assertEqual([], loose)

  def test_the_scan_finds_the_reads_at_all(self):
    sources = dict(self._sources())
    self.assertEqual(len(self.TECHNIQUES) + 1, len(sources))
    self.assertEqual(1, sum(_.count("printf '%d'") for _ in sources.values()))
    # And the techniques do reach it, rather than having quietly stopped reading ordinals.
    callers = [_ for _ in self.TECHNIQUES if "byte_ordinal" in sources[_]]
    self.assertGreater(len(callers), 2, "only " + str(callers) + " call the helper")

  def test_an_ordinal_comes_back_as_the_byte_whichever_way_printf_signs_it(self):
    """
    'printf' hands a byte over as a plain char, signed on most builds - so bash answers -61 for the
    byte dash answers 195 for. Read as it arrives, every question about that byte is asked against
    the wrong number and the character is lost, which is what this brings back into range.
    """
    from src.core.controller import checks
    expression = checks.byte_ordinal("${X}")
    span = settings.HIGHEST_BYTE + 1
    self.assertIn("+ " + str(span) + " ) % " + str(span), expression)
    for byte in range(span):
      for answered in (byte, byte - span if byte > 127 else byte):
        self.assertEqual(byte, (answered + span) % span,
                         "byte " + str(byte) + " answered as " + str(answered))

  def test_a_shell_reads_a_high_byte_as_itself(self):
    """
    The table above is the arithmetic; this is the shells it has to hold on, bash among them -
    a shell whose 'printf' is unsigned agrees either way and would not notice the difference.
    """
    from src.core.controller import checks
    shells = [_ for _ in ("/bin/sh", "/bin/bash", "/bin/dash") if os.path.exists(_)]
    if not shells:
      self.skipTest("needs a POSIX shell")
    environment = {"LC_ALL": "C", "PATH": os.environ.get("PATH", "/bin:/usr/bin")}
    for octal, byte in (("\\303", 195), ("\\251", 169), ("\\101", 65), ("\\177", 127)):
      expression = checks.byte_ordinal("$(printf '" + octal + "')")
      for shell in shells:
        answer = subprocess.check_output([shell, "-c", "printf '%s' \"" + expression + "\""],
                                         env=environment).decode().strip()
        self.assertEqual(str(byte), answer, shell + " read byte " + str(byte) + " as " + answer)

  def test_the_piped_ordinal_parts_nothing_of_its_own(self):
    """
    Under a pipe the byte used to be read with a second statement after it, parted by a newline -
    an operator the payload is not proving, carried inside the substitution where it still counts.
    Counting the byte instead needs no second statement, and no sign either.
    """
    from src.core.techniques.time_based import tb_payloads
    settings.TARGET_OS = settings.OS.UNIX
    settings.WHITESPACES = [settings.SINGLE_WHITESPACE]
    settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX = "$(", ")"
    settings.TIME_RELATED_ATTACK = True
    settings.CHECKING_PARAMETER = "P"
    settings.EXPLOITATION_PHASE = True
    for separator in ("|", "||"):
      settings.CONFIRMED_BOUNDARY = {"P": ("", "", separator, settings.SINGLE_WHITESPACE)}
      payload = tb_payloads.get_char(separator, "id", 2, 126, 5, "GET")
      self.assertTrue(payload, "no payload under " + repr(separator))
      used = set(payload) & set(";&|\n\r")
      self.assertEqual(set(separator), used, "under " + repr(separator) + " it also uses " + str(sorted(used)))
      self.assertIn("-t u1", payload)

  def test_the_file_is_transformed_through_an_unsigned_reading(self):
    """
    The output file is rewritten as one number per byte, and those numbers are what the search then
    reads - digits and spaces, so a byte of any value is asked for out of the printable pool alone
    and the pool never has to widen. Signed, 'od' answers -61 where the byte is 195, which both puts
    a character outside that pool and spends the sign on nothing.
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "src", "core", "techniques", "tempfile_based", "tfb_payloads.py")) as handle:
      source = handle.read()
    self.assertGreater(source.count("-t u1"), 3, "the transform is not where it was")
    self.assertNotIn("-t d1", source)

  def test_the_locale_is_pinned_where_the_shell_does_the_counting(self):
    """
    A character-counting shell answers a length the byte beside it is not indexed by, so the measurement pins the locale itself.
    """
    from src.core.techniques.time_based import tb_payloads
    from src.core.techniques.tempfile_based import tfb_payloads
    from src.core.techniques.boolean_based import bb_payloads
    settings.TARGET_OS = settings.OS.UNIX
    settings.WHITESPACES = [settings.SINGLE_WHITESPACE]
    settings.TIME_RELATED_ATTACK = True
    settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX = "$(", ")"
    settings.CHECKING_PARAMETER = "P"
    settings.EXPLOITATION_PHASE = True
    for separator in (";", settings.END_LINE.LF):
      settings.CONFIRMED_BOUNDARY = {"P": ("", "", separator, settings.SINGLE_WHITESPACE)}
      # Every technique that measures a real output, counted the same way and read back the same way.
      for payload in (tb_payloads.get_length(separator, "id", 1, 5, "GET"),
                      tb_payloads.cmd_execution(separator, "id", 1, 5, "GET"),
                      tb_payloads.get_char(separator, "id", 2, 126, 5, "GET"),
                      tfb_payloads.cmd_execution(separator, "id", 1, "/tmp/out.txt", 5, "GET"),
                      bb_payloads.get_length(separator, "id", 1),
                      bb_payloads.get_char(separator, "id", 2, 126)):
        # Chained with the separator under test, so the pin brings in nothing new to filter.
        self.assertIn(separator + settings.BYTE_LOCALE_EXPORTED + separator, payload)
        used = set(payload) & set(";&|\n\r")
        self.assertEqual(set(separator), used, "under " + repr(separator) + " it also uses " + str(sorted(used)))
      # Detection measures a marker commix wrote itself, which is ASCII - nothing there can disagree.
      self.assertNotIn(settings.BYTE_LOCALE, tb_payloads.decision(separator, "MARKER", 6, 5, "GET"))
      self.assertNotIn(settings.BYTE_LOCALE, tfb_payloads.decision(separator, 6, "MARKER", "/tmp/out.txt", 5, "GET"))
    # Through backticks the counting is a command of its own, so the fallback pins an exported locale in place of the filler the "&&" needs.
    settings.CMD_SUB_PREFIX = settings.CMD_SUB_SUFFIX = settings.BACKTICK_SUBSTITUTION
    try:
      for separator in ("&", "&&"):
        settings.CONFIRMED_BOUNDARY = {"P": ("", "", separator, settings.SINGLE_WHITESPACE)}
        self.assertIn(settings.BYTE_LOCALE_EXPORTED, tb_payloads.get_length(separator, "id", 1, 5, "GET"))
        self.assertIn(settings.BYTE_LOCALE_EXPORTED, tb_payloads.cmd_execution(separator, "id", 1, 5, "GET"))
        self.assertIn(settings.BYTE_LOCALE_EXPORTED, tb_payloads.get_char(separator, "id", 2, 126, 5, "GET"))
        self.assertIn(settings.BYTE_LOCALE_EXPORTED, tfb_payloads.cmd_execution(separator, "id", 1, "/tmp/out.txt", 5, "GET"))
        # Detection measures an ASCII marker, so neither fallback pins anything there.
        self.assertNotIn(settings.BYTE_LOCALE, tb_payloads.decision(separator, "MARKER", 6, 5, "GET"))
      # Boolean-based refuses '&' outright rather than reach for a second operator to hold a variable.
      self.assertEqual("", bb_payloads.get_length("&", "id", 1))
    finally:
      settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX = settings.NESTING_SUBSTITUTION

  def test_a_windows_payload_is_left_alone(self):
    from src.core.techniques.time_based import tb_payloads
    was = settings.TARGET_OS
    try:
      settings.TARGET_OS = settings.OS.WINDOWS
      for separator in ("&", "&&"):
        payload = tb_payloads.decision(separator, "MARKER", 6, 5, "GET")
        self.assertNotIn(settings.BYTE_LOCALE, payload, repr(separator))
    finally:
      settings.TARGET_OS = was

  def test_every_awk_measurement_pins_the_locale(self):
    # 'length' and 'substr' count characters under gawk in a UTF-8 locale, and bytes under the C
    # one - the indexing beside them is bytes either way.
    unpinned = []
    for name, source in self._sources():
      for line in source.splitlines():
        if "awk 'BEGIN{" in line and "LC_ALL=C awk 'BEGIN{" not in line:
          unpinned.append(name + ": " + line.strip()[:60])
    self.assertEqual([], unpinned)

class PoolExpansion(unittest.TestCase):
  """
  A byte found to sit above the pool is looked for in the rest of the range a byte can be - but only
  while the pool is commix's own. A pool the user wrote out is a statement about this output, so a
  byte outside it is left unresolved instead of bought with the questions the search would cost.
  """

  def setUp(self):
    from src.core.parse import cmdline as menu
    self.menu = menu
    self.was = menu.options.charset

  def tearDown(self):
    self.menu.options.charset = self.was

  def test_commixs_own_pool_is_widened(self):
    from src.core.controller import checks
    self.menu.options.charset = None
    self.assertTrue(checks.char_pool_expands())

  def test_a_pool_the_user_wrote_out_is_not(self):
    from src.core.controller import checks
    self.menu.options.charset = "0123456789abcdef"
    self.assertFalse(checks.char_pool_expands())

  def test_that_pool_is_the_one_searched(self):
    from src.core.controller import checks
    self.menu.options.charset = "0123456789abcdef"
    self.assertEqual(sorted(ord(_) for _ in "0123456789abcdef"), sorted(checks.generate_char_pool(2)))

class CharacterPool(unittest.TestCase):
  """
  The pool the ordinal oracles search is printable ASCII, which is what output mostly is. A byte
  above it answers yes to every "is it at least N" the halving asks, so the search climbs to the
  pool's own last character - and that answer has to be checked rather than taken, or a wrong
  character is reported in the shape of a right one.
  """
  def test_the_pool_stops_at_printable_ascii(self):
    self.assertEqual(126, max(settings.CHAR_POOL_MULTI))
    self.assertEqual(126, max(settings.CHAR_POOL_SINGLE))
    self.assertIn(9, settings.CHAR_POOL_MULTI)
    self.assertIn(10, settings.CHAR_POOL_MULTI)

  def test_there_is_a_range_left_to_search_above_it(self):
    self.assertGreater(settings.HIGHEST_BYTE, max(settings.CHAR_POOL_MULTI))
    self.assertEqual(255, settings.HIGHEST_BYTE)

  def test_the_boolean_oracle_confirms_before_answering(self):
    """
    Its last step used to hand back whatever the halving settled on. A byte above the pool settles
    on the pool's top, so the answer needs asking for by name before it is believed.
    """
    import inspect
    from src.core.techniques.boolean_based import bb_handler
    source = inspect.getsource(bb_handler._byte_at)
    self.assertIn("_confirmed", source, "the span search answers without confirming")
    confirm = inspect.getsource(bb_handler._confirmed)
    self.assertIn("-eq", confirm)
    self.assertIn("HIGHEST_BYTE", confirm, "nothing searches above the pool")

  def test_the_time_based_oracle_checks_the_top_of_the_pool_from_above(self):
    import inspect
    from src.core.controller import injector
    source = inspect.getsource(injector.time_related_injection)
    self.assertIn("HIGHEST_BYTE", source, "the pool's top is accepted unchecked")

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

class WindowsPayloads(unittest.TestCase):
  """
  Nothing here can be run from this machine, so what is pinned is the shape: that a payload is
  built on the separators 'cmd.exe' chains with, that none is built on the ones it does not, and
  that what comes out carries no POSIX construct the shell it is written for cannot read.
  """
  CHAINS = ("&", "&&", "|", "||")
  DOES_NOT_CHAIN = (";", settings.END_LINE.LF, "\r\n")

  def setUp(self):
    self.was = settings.TARGET_OS
    settings.TARGET_OS = settings.OS.WINDOWS
    settings.WHITESPACES = [settings.SINGLE_WHITESPACE]
    settings.TIME_RELATED_ATTACK = True
    settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX = "$(", ")"

  def tearDown(self):
    settings.TARGET_OS = self.was

  def test_a_payload_is_built_on_what_cmd_chains_with(self):
    from src.core.techniques.time_based import tb_payloads
    for separator in self.CHAINS:
      payload = tb_payloads.decision(separator, "MARKER", 6, 5, "GET")
      self.assertTrue(payload and payload.strip(), "nothing built under " + repr(separator))

  def test_nothing_is_built_on_what_it_does_not(self):
    # A ';' is not a separator to 'cmd.exe', and a payload built on one would read as a single word.
    from src.core.techniques.time_based import tb_payloads
    for separator in self.DOES_NOT_CHAIN:
      payload = tb_payloads.decision(separator, "MARKER", 6, 5, "GET")
      self.assertFalse(payload and payload.strip(), "built under " + repr(separator))

  def test_no_posix_construct_reaches_a_windows_payload(self):
    from src.core.techniques.time_based import tb_payloads
    for separator in self.CHAINS:
      payload = tb_payloads.decision(separator, "MARKER", 6, 5, "GET")
      for construct in ("$(", "${", "awk ", "sleep ", "/bin/"):
        self.assertNotIn(construct, payload, construct + " under " + repr(separator))

class BackticksFallback(unittest.TestCase):
  """
  The one-command forms nest one substitution inside another, which backticks cannot express - so
  a run using them keeps the older shape. It still has to produce a payload.
  """
  def test_a_payload_is_still_built_with_backticks(self):
    from src.core.techniques.time_based import tb_payloads
    settings.CMD_SUB_PREFIX = settings.CMD_SUB_SUFFIX = settings.BACKTICK_SUBSTITUTION
    try:
      for separator in ("&", "&&"):
        payload = tb_payloads.decision(separator, "MARKER", 6, 5, "GET")
        self.assertTrue(payload.strip(), "no payload under " + repr(separator))
        self.assertNotIn("awk", payload, "the nested form was used with backticks")
    finally:
      settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX = "$(", ")"

  def test_what_the_rewrites_hand_back_closes_every_backtick_it_opens(self):
    """
    A backtick does not nest, so a rewrite that opens one and leaves it open runs the rest of the
    payload as the command inside it - and the shell answers nothing rather than erroring.
    """
    from src.tamper.obfuscation.posix import rev
    from src.tamper.obfuscation.generic import randomcase
    settings.CMD_SUB_PREFIX = settings.CMD_SUB_SUFFIX = settings.BACKTICK_SUBSTITUTION
    try:
      for separator in SEPARATORS:
        for script in (rev, randomcase):
          payload = stage_exploitation(separator)
          tampered = script.tamper(payload)
          self.assertEqual(tampered.count("`") % 2, 0,
                           script.__tamper__ + " left a backtick open under " + repr(separator))
    finally:
      settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX = "$(", ")"

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

class UnreadableBytes(unittest.TestCase):
  """
  Output is read off a page, and a page is read in whatever encoding it declares - so a byte that
  encoding cannot represent used to come back as the one replacement character every unreadable
  byte shares, which is not the byte the target sent and cannot be turned back into it.
  """

  def _response(self, charset):
    class Served(object):
      def info(self):
        return {"Content-Encoding": "", "Content-Type": "text/html; charset=" + charset}
    served = Served()
    served.info = lambda: {"Content-Encoding": "", "Content-Type": "text/html; charset=" + charset}
    return served

  def test_a_byte_the_page_cannot_read_is_kept(self):
    from src.core.controller import checks
    read = checks.decode_page_body(b"x\xc3y", self._response("utf-8"))
    self.assertNotIn("�", read)
    self.assertEqual("x\xc3y", checks.restored_unreadable_bytes(read))

  def test_a_page_it_can_read_is_left_as_it_is(self):
    from src.core.controller import checks
    self.assertEqual("caf\xe9", checks.decode_page_body(b"caf\xc3\xa9", self._response("utf-8")))

  def test_only_a_byte_past_ascii_is_read_back(self):
    """
    The escape stands for a byte no encoding could read, and only a byte past ASCII is ever one -
    so an escape the output itself printed spells a character the page read perfectly well.
    """
    from src.core.controller import checks
    self.assertEqual("printed \\x41 here", checks.restored_unreadable_bytes("printed \\x41 here"))
    self.assertEqual("x\xc3y", checks.restored_unreadable_bytes("x\\xc3y"))

# eof

class MaxlenTruncation(unittest.TestCase):
  """
  Landing on the ceiling says the output reaches it, not that it ends there - every length past it
  answers the same question the same way. Handed back without a word, a run that read four of ten
  characters is indistinguishable from one that read an output four characters long.
  """

  def _handler(self):
    from src.core.techniques.boolean_based import bb_handler
    return bb_handler

  def test_the_reading_limit_is_no_part_of_the_search(self):
    """
    The doubling runs on what is plausible, and the limit is applied to the length it settles on -
    so the length reported is the output's own, and how much of it was read is said separately.
    """
    import inspect
    source = inspect.getsource(self._handler().output_length)
    self.assertIn("MAX_INFERRED_LENGTH", source)
    self.assertIn("characters long, and this run reads", source)
    self.assertIn("INCOMPLETE_OUTPUT", source)

  def test_the_time_related_reading_says_so_too(self):
    """
    The limit now belongs to the reading, against a length already known in full - so what is said
    is how long the output is and how much of it was read, not that it is longer than some bound.
    """
    import inspect
    from src.core.controller import injector
    source = inspect.getsource(injector.time_related_injection)
    self.assertIn("characters long, and this run", source)
    self.assertIn("INCOMPLETE_OUTPUT", source)

# eof

class ResolvedOrdinal(unittest.TestCase):
  """
  The halving is never asked about its own upper bound, so the pool's last character is the one
  answer it cannot give: a byte that reaches it settles one below it, and so does every byte past
  the pool. Left there, '~' comes back as '}' and a byte of 195 as either.
  """
  POOL = [9, 10] + list(range(32, 127))

  def _asks(self, byte):
    self.asked = []
    def asks(candidate):
      self.asked.append(candidate)
      return candidate <= byte
    return asks

  def test_every_byte_resolves_to_itself(self):
    from src.core.controller import injector
    for byte in (9, 10, 32, 120, 125, 126, 127, 128, 169, 195, 254, 255):
      self.assertEqual(byte, injector.resolved_ordinal(self._asks(byte), self.POOL),
                       "byte " + str(byte))

  def test_the_pools_last_character_is_asked_about(self):
    from src.core.controller import injector
    injector.resolved_ordinal(self._asks(126), self.POOL)
    self.assertIn(max(self.POOL), self.asked, "the pool's top is never asked about")

  def test_a_pool_the_user_wrote_out_is_not_widened(self):
    from src.core.controller import injector
    self.assertEqual(max(self.POOL),
                     injector.resolved_ordinal(self._asks(195), self.POOL, expands=False))

  def test_nothing_answered_resolves_to_nothing(self):
    from src.core.controller import injector
    self.assertIsNone(injector.resolved_ordinal(lambda _: False, self.POOL))

  def test_the_range_past_the_pool_costs_only_the_bytes_that_need_it(self):
    from src.core.controller import injector
    injector.resolved_ordinal(self._asks(120), self.POOL)
    plain = len(self.asked)
    injector.resolved_ordinal(self._asks(195), self.POOL)
    self.assertLess(plain, len(self.asked))
    self.assertLess(len(self.asked), plain * 3, "a high byte costs more than twice an ASCII one")

# eof

class ResolvedLength(unittest.TestCase):
  """
  Nothing caps the length search but implausibility. Capped at what the run was willing to read, it
  had an upper bound nothing had answered for - an output exactly that long settled one character
  short of itself, and one longer settled there too rather than being known to be longer.
  """

  def _asks(self, length):
    self.asked = []
    def asks(candidate):
      self.asked.append(candidate)
      return candidate <= length
    return asks

  def test_an_output_is_found_whatever_its_length(self):
    from src.core.controller import injector
    for length in (1, 2, 3, 4, 5, 8, 9, 100, 255, 10000):
      self.assertEqual(length, injector.resolved_length(self._asks(length), 1),
                       "length " + str(length))

  def test_nothing_answered_resolves_to_nothing(self):
    from src.core.controller import injector
    self.assertIsNone(injector.resolved_length(lambda _: False, 1))

  def test_an_oracle_that_agrees_with_everything_is_disbelieved(self):
    """
    Yes all the way up is not a very long output, it is an oracle answering whatever it is asked.
    """
    from src.core.controller import injector
    self.assertIsNone(injector.resolved_length(lambda _: True, 1, sanity=4096))

  def test_what_the_run_reads_is_no_part_of_finding_the_length(self):
    from src.core.controller import injector
    import inspect
    source = inspect.getsource(injector.resolved_length)
    self.assertNotIn("maxlen", source, "the reading limit is back in the search")

  def test_a_large_length_is_reached_in_fewer_steps_than_doubling_would(self):
    """
    The bracket grows by more than two at a time, so a long output is reached in fewer steps - the
    reason being a numeric oracle answers a length question in one probe, unlike a character one,
    which is why reading the length's digits instead would cost commix more than it saved.
    """
    from src.core.controller import injector
    was = settings.LENGTH_SEARCH_BASE
    try:
      settings.LENGTH_SEARCH_BASE = 2
      injector.resolved_length(self._asks(100000), 1)
      doubling = len(self.asked)
      settings.LENGTH_SEARCH_BASE = 4
      injector.resolved_length(self._asks(100000), 1)
      self.assertLess(len(self.asked), doubling, "the wider bracket saved nothing")
    finally:
      settings.LENGTH_SEARCH_BASE = was

  def test_the_cost_stays_logarithmic(self):
    from src.core.controller import injector
    injector.resolved_length(self._asks(10000), 1)
    # Doubling to bracket it, then halving back: about twice the bits of the answer.
    self.assertLess(len(self.asked), 40, "asked " + str(len(self.asked)) + " times")

class BooleanThroughAPipe(unittest.TestCase):
  """
  A pipe carries a boolean answer either way one can be read, and neither way needs a second
  operator. Off the exit status, by leaving the pipeline unterminated - the no-operation that would
  close it answers 0 whatever the test said, which is the whole answer thrown away. Printed, by
  printing the marker through the pipe and taking it from the byte the comparison picks, since
  there is no ';' to put before an 'if' and '&&' would be a separator of its own.
  """
  SEP = "|"

  def _stage(self, printed):
    stage_exploitation(self.SEP)
    settings.BOOLEAN_PRINTED_STATE = printed
    settings.EXPLOITATION_PHASE = True
    from src.core.techniques.boolean_based import bb_payloads
    return bb_payloads

  def _built(self, payloads):
    return (("detect", payloads.condition_check(self.SEP, holds=True)),
            ("decision", payloads.decision(self.SEP, "TAG", 3)),
            ("length", payloads.get_length(self.SEP, "id", 5)),
            ("char", payloads.get_char(self.SEP, "id", 2, 126)))

  def test_a_pipe_is_answered_either_way(self):
    for printed in (False, True):
      payloads = self._stage(printed)
      for name, payload in self._built(payloads):
        self.assertTrue(payload, name + " under a pipe, printed=" + str(printed))

  def test_nothing_but_the_pipe_is_used(self):
    for printed in (False, True):
      payloads = self._stage(printed)
      for name, payload in self._built(payloads):
        used = set(payload) & set(";&|\n\r")
        self.assertEqual({"|"}, used, name + " printed=" + str(printed) + " uses " + str(sorted(used)))

  def test_the_status_is_not_closed_away(self):
    """
    'terminate_payload' ends a binary separator on a no-operation, whose status is the pipeline's.
    """
    payloads = self._stage(False)
    for name, payload in self._built(payloads):
      self.assertFalse(payload.rstrip().endswith("|" + settings.NO_OPERATION),
                       name + " ends on the no-operation, discarding the answer")

  def test_the_printed_answer_is_taken_from_the_marker(self):
    payloads = self._stage(True)
    for name, payload in self._built(payloads):
      self.assertIn(settings.BOOLEAN_MARKER, payload, name)
      self.assertIn("tail -c +$((", payload, name)
      # 'head -c 0' says the same thing and is refused outright by some builds.
      self.assertNotIn("head -c $((", payload, name)

  def test_the_byte_is_counted_unsigned(self):
    """
    No variable survives a pipe, so the byte is read where it is needed - counted rather than read
    as a character, which is the reading that holds on a build whose 'printf' signs it.
    """
    for printed in (False, True):
      payloads = self._stage(printed)
      self.assertIn("od -A n -t u1", payloads.get_char(self.SEP, "id", 2, 126))

# eof

class SubstitutionNesting(unittest.TestCase):
  """
  Whether a substitution can hold another one is a property of the substitution itself, so it is
  read off it rather than tracked beside it. Tracked, the two were two answers to one question: a
  run that set the flag without changing the substitution skipped the nesting form while still
  writing '$( )', which nests perfectly well.
  """

  def setUp(self):
    self.was = (settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX)

  def tearDown(self):
    settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX = self.was

  def test_it_is_read_off_the_substitution_in_use(self):
    from src.core.controller import checks
    settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX = "$(", ")"
    self.assertTrue(checks.substitution_nests())
    self.assertFalse(checks.using_backticks())
    settings.CMD_SUB_PREFIX = settings.CMD_SUB_SUFFIX = settings.BACKTICK_SUBSTITUTION
    self.assertFalse(checks.substitution_nests())
    self.assertTrue(checks.using_backticks())

  def test_the_branch_follows_the_substitution_and_nothing_else(self):
    from src.core.techniques.time_based import tb_payloads
    stage_exploitation("&")
    settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX = "$(", ")"
    nested = tb_payloads.get_length("&", "id", 1, 5, "GET")
    settings.CMD_SUB_PREFIX = settings.CMD_SUB_SUFFIX = settings.BACKTICK_SUBSTITUTION
    stage_exploitation("&")
    settings.CMD_SUB_PREFIX = settings.CMD_SUB_SUFFIX = settings.BACKTICK_SUBSTITUTION
    plain = tb_payloads.get_length("&", "id", 1, 5, "GET")
    self.assertNotEqual(nested, plain, "the substitution in use changes nothing")
    self.assertIn("$((", nested)
    self.assertNotIn("$((", plain)

  def test_no_second_answer_is_kept_anywhere(self):
    """
    The flag this replaced could be set on its own, and a caller reading it then disagreed with the
    payload actually being written.
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    stray = []
    for where, _, names in os.walk(os.path.join(root, "src")):
      if "thirdparty" in where.split(os.sep):
        continue
      for name in names:
        if not name.endswith(".py"):
          continue
        with open(os.path.join(where, name)) as handle:
          if "USE_BACKTICKS" in handle.read():
            stray.append(name)
    self.assertEqual([], stray)

# eof

class WindowsTargets(unittest.TestCase):
  """
  Stood in for rather than reached: nothing in this suite has a Windows target to ask, so what a
  Windows payload must and must not be made of is pinned here instead. A POSIX construct reaching
  'cmd.exe' is the failure that has no target to catch it.
  """
  POSIX_ONLY = ("$(", "${#", "od -A", "printf '%d'", "tail -c", "head -c", "sleep ",
                "LC_ALL=C", "[ ", " -le ", " -eq ")

  def _windows(self, separator):
    stage_exploitation(separator, target_os=settings.OS.WINDOWS)
    settings.TARGET_OS = settings.OS.WINDOWS
    settings.EXPLOITATION_PHASE = True

  def test_no_posix_construct_reaches_cmd_exe(self):
    from src.core.techniques.boolean_based import bb_payloads
    from src.core.techniques.time_based import tb_payloads
    from src.core.techniques.tempfile_based import tfb_payloads
    was = settings.TARGET_OS
    try:
      for separator in ("&", "&&", "|", "||"):
        self._windows(separator)
        settings.TIME_RELATED_ATTACK = False
        built = [("bb.get_char", bb_payloads.get_char(separator, "ver", 2, 126)),
                 ("bb.get_length", bb_payloads.get_length(separator, "ver", 5))]
        settings.TIME_RELATED_ATTACK = True
        built += [("tb.get_char", tb_payloads.get_char(separator, "ver", 2, 126, 5, "GET")),
                  ("tfb.get_char", tfb_payloads.get_char(separator, "C:\\\\t.txt", 2, 126, 5, "GET"))]
        for name, payload in built:
          if not payload:
            continue
          for construct in self.POSIX_ONLY:
            self.assertNotIn(construct, payload,
                             name + " under " + repr(separator) + " carries " + repr(construct))
    finally:
      settings.TARGET_OS = was

  def test_the_character_is_compared_as_a_number(self):
    """
    'cmd.exe' compares strings by locale collation, so only a number can be bisected on - and the number is a byte, which is what the pool it is searched in holds.
    """
    from src.core.techniques.boolean_based import bb_payloads
    was = settings.TARGET_OS
    try:
      self._windows("&")
      settings.TIME_RELATED_ATTACK = False
      payload = bb_payloads.get_char("&", "ver", 2, 126)
      self.assertIn("[int](", payload)
      self.assertIn("UTF8.GetBytes", payload)
      # A '[char]' answers the code point, which past Latin-1 is a number no byte can be.
      self.assertNotIn("[char]", payload)
      self.assertTrue("GEQ" in payload or "EQU" in payload, "no numeric comparison")
    finally:
      settings.TARGET_OS = was

  def test_a_byte_read_back_is_still_unsigned_there(self):
    """
    The reading a Windows target answers with is a .NET 'int' from a byte, unsigned already - so it needs no bringing back into range, and must not be given one.
    """
    from src.core.techniques.boolean_based import bb_payloads
    was = settings.TARGET_OS
    try:
      self._windows("&")
      settings.TIME_RELATED_ATTACK = False
      payload = bb_payloads.get_char("&", "ver", 2, 195)
      self.assertNotIn("% 256", payload)
      self.assertIn("195", payload)
    finally:
      settings.TARGET_OS = was


class OdIsAskedThePortableWay(unittest.TestCase):
  """
  Stood in for as well: the byte counts are read with 'od', and the only 'od' this suite can run is
  the one on the machine running it. What keeps the others answering is asking in the form POSIX
  defines, so that is what is pinned - a busybox or BSD 'od' refuses a spelling only GNU accepts.
  """
  # POSIX od: -A, -j, -N, -t, -v, with type specifiers a c d f o u x and an optional byte count.
  POSIX_TYPES = tuple("acdfoux")

  def _invocations(self):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    found = []
    for where, _, names in os.walk(os.path.join(root, "src")):
      if "thirdparty" in where.split(os.sep):
        continue
      for name in names:
        if not name.endswith(".py"):
          continue
        with open(os.path.join(where, name)) as handle:
          for line in handle:
            # Everything the invocation is given, not just its first flag: the options are
            # parted by operands ('-t u1'), which a run of flags alone stops at.
            for match in re.finditer(r"\bod(\s+-[^\"']*)", line):
              found.append((name, match.group(0)))
    return found

  def test_the_scan_finds_the_invocations(self):
    self.assertGreater(len(self._invocations()), 2, "nothing found to check")

  def test_every_option_is_one_posix_defines(self):
    strayed = []
    for name, invocation in self._invocations():
      for flag in re.findall(r"-([A-Za-z])", invocation):
        if flag not in ("A", "j", "N", "t", "v"):
          strayed.append(name + ": " + invocation)
    self.assertEqual([], strayed)

  def test_no_long_option_is_used(self):
    """
    '--format' and friends are GNU's own; a busybox or BSD 'od' takes the short forms alone.
    """
    for name, invocation in self._invocations():
      self.assertNotIn("--", invocation, name + ": " + invocation)

  def test_every_type_is_one_posix_defines(self):
    strayed = []
    for name, invocation in self._invocations():
      for spec in re.findall(r"-t\s*([A-Za-z])", invocation):
        if spec not in self.POSIX_TYPES:
          strayed.append(name + ": " + invocation)
    self.assertEqual([], strayed)

  def test_the_count_is_read_without_relying_on_its_padding(self):
    """
    busybox pads a byte count to a narrower width than GNU does, so the reading is taken by word
    splitting rather than by position - which a quoted substitution would take away.
    """
    from src.core.techniques.boolean_based import bb_payloads
    stage_exploitation(settings.PIPE_SEPARATOR)
    settings.EXPLOITATION_PHASE = True
    settings.BOOLEAN_PRINTED_STATE = False
    payload = bb_payloads.get_char(settings.PIPE_SEPARATOR, "id", 2, 126)
    self.assertIn("od -A n -t u1", payload)
    self.assertNotIn("\"$(printf '%s'", payload.replace("\"$(printf '%s' \\\"", ""))

# eof

class ArithmeticIsOpenedOnce(unittest.TestCase):
  """
  An arithmetic expansion holding another one is not parsed alike everywhere: a dash of the age
  shipped with older distributions stops at the first '))' and calls the rest a syntax error. From
  commix's side that is indistinguishable from a target that did not answer - the delay simply never
  arrives - so every character comes back unread with nothing to say why.
  """

  def test_the_reading_has_a_form_that_goes_inside_one(self):
    from src.core.controller import checks
    term = checks.byte_ordinal_term("${X}")
    self.assertTrue(term.startswith("("), term)
    self.assertNotIn("$((", term)
    # It is the same reading, only without an expansion of its own around it.
    self.assertIn(term, checks.byte_ordinal("${X}"))

  def test_no_delay_is_scaled_by_a_nested_expansion(self):
    from src.core.techniques.time_based import tb_payloads
    from src.core.techniques.tempfile_based import tfb_payloads
    nested = []
    for separator in SEPARATORS:
      stage_exploitation(separator)
      settings.EXPLOITATION_PHASE = True
      settings.TIME_RELATED_ATTACK = True
      for name, payload in (("tb.get_char", tb_payloads.get_char(separator, "id", 2, 126, 5, "GET")),
                            ("tb.get_length", tb_payloads.get_length(separator, "id", 1, 5, "GET")),
                            ("tfb.get_char", tfb_payloads.get_char(separator, "/tmp/f", 2, 126, 5, "GET"))):
        if not payload:
          continue
        depth = 0
        index = 0
        while index < len(payload):
          if payload.startswith("$((", index):
            depth += 1
            if depth > 1:
              nested.append(name + " under " + repr(separator))
              break
            index += 3
          elif payload.startswith("))", index) and depth:
            depth -= 1
            index += 2
          else:
            index += 1
    self.assertEqual([], nested)

# eof

class BytesAreReadByByte(unittest.TestCase):
  """
  A byte read off a file is read by byte position, not by character. 'cut -c' counts characters,
  and in a UTF-8 locale it errors outright on a byte that is not valid UTF-8 - returning nothing
  for every position at or after the first non-ASCII byte, which is exactly the output worth
  reading. 'cut -b' counts bytes, and reads it in any locale.
  """
  def _tfb_readers(self):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(root, "src", "core", "techniques", "tempfile_based", "tfb_payloads.py")
    with open(path) as handle:
      return [line for line in handle if "cut -" in line and "OUTPUT_TEXTFILE" in line]

  def test_the_file_is_indexed_by_byte(self):
    readers = self._tfb_readers()
    self.assertTrue(readers, "no byte reader found to check")
    for line in readers:
      self.assertIn("cut -b", line, "a file byte is read with 'cut -c': " + line.strip()[:70])
      self.assertNotIn("cut -c", line)

  @unittest.skipUnless(os.path.exists("/usr/bin/cut") or os.path.exists("/bin/cut"), "needs cut")
  def test_cut_b_reads_a_high_byte_a_utf8_locale_rejects(self):
    import subprocess, tempfile
    with tempfile.NamedTemporaryFile(delete=False) as handle:
      handle.write(b"x\xc3y")
      name = handle.name
    try:
      environment = {"LC_ALL": "en_US.UTF-8", "PATH": os.environ.get("PATH", "/bin:/usr/bin")}
      for position, expected in ((1, "120"), (2, "195"), (3, "121")):
        got = subprocess.run("cut -b%d %s | LC_ALL=C od -An -tu1" % (position, name),
                             shell=True, env=environment, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL).stdout.decode().split()
        # The byte at the position, bar the newline 'cut' puts after it.
        self.assertEqual(expected, got[0] if got else "none", "byte at position " + str(position))
    finally:
      os.unlink(name)

# eof

class FileOracleLengthIsBytes(unittest.TestCase):
  """
  The file oracle reads a character by byte position, so the length it searches has to be a byte
  count too. A shell counting characters makes the two disagree on where the output ends, and the
  trailing bytes of a non-ASCII output - counted as one character, read as two - go unread.
  """
  SEPARATORS = (";", "&&", "\n", "\r\n")

  def _length_payload(self, separator):
    stage_exploitation(separator)
    settings.BOOLEAN_PRINTED_STATE = False
    from src.core.techniques.tempfile_based import tfb_payloads
    return tfb_payloads.oracle_get_length(separator, "/tmp/F.txt", 5)

  def test_the_length_is_counted_in_bytes(self):
    for separator in self.SEPARATORS:
      payload = self._length_payload(separator)
      self.assertTrue(payload, "no length payload under " + repr(separator))
      self.assertIn(settings.BYTE_LOCALE, payload,
                    "length counted in the target's own locale under " + repr(separator))

  def test_pinning_the_locale_adds_no_foreign_separator(self):
    for separator in self.SEPARATORS:
      payload = self._length_payload(separator)
      used = set(payload) & set(";&|\n\r")
      self.assertEqual(set(separator) & set(";&|\n\r"), used,
                       repr(separator) + " also uses " + str(sorted(used)))

  @unittest.skipUnless(os.path.exists("/bin/bash"), "needs bash for the character-counting case")
  def test_a_non_ascii_length_is_counted_whole(self):
    import subprocess, tempfile
    # 'cafe' with an accent: four characters, five bytes - the reading needs the byte count.
    with tempfile.NamedTemporaryFile(delete=False) as handle:
      handle.write(b"caf\xc3\xa9\n")
      name = handle.name
    try:
      environment = {"LC_ALL": "en_US.UTF-8", "PATH": os.environ.get("PATH", "/bin:/usr/bin")}
      script = settings.BYTE_LOCALE + "; V=$(cat " + name + "); [ ${#V} -ge 5 ] && echo yes || echo no"
      got = subprocess.run(["/bin/bash", "-c", script], env=environment,
                           stdout=subprocess.PIPE).stdout.decode().strip()
      self.assertEqual("yes", got, "the fifth byte was not counted")
    finally:
      os.unlink(name)

# eof
