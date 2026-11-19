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
import inspect
import importlib
import unittest

from tests._testutils import SEPARATORS, stage, tamper_modules, separators_in
from src.utils import settings

# The scripts that cannot write their rewrite without an operator of their own, and why.
SMUGGLES_BY_DESIGN = {
                  # 'rev' reads from a pipe, and a filter stripping '|' has stripped '&' before it.
                  "rev": ("&", "&&"),
                  "randomcase": ("&", "&&"),
}

"""
A payload that measures its own output, as an extraction one does - the sweep's plain command gives
a script that only rewrites a measurement nothing to rewrite, and it passes by never acting.
"""
def _measuring_payload(separator, target_os):
  stage(separator, target_os=target_os)
  from src.core.techniques.time_based import tb_payloads
  return tb_payloads.get_length(separator, "id", 1, 5, "GET") or stage(separator, target_os=target_os)

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
          # A script the loader would refuse cannot smuggle anything, so it is not asked to: this
          # mirrors 'tamper_scripts()', which drops one whose dependencies() answers with a reason.
          settings.TARGET_OS = target_os
          if hasattr(module, "dependencies") and module.dependencies():
            continue
          # Two shapes, because a script that rewrites one leaves the other untouched: a plain
          # command, and one that measures its own output the way an extraction payload does.
          for payload in (stage(separator, target_os=target_os),
                          _measuring_payload(separator, target_os)):
            try:
              tampered = module.tamper(payload)
            except Exception:
              continue
            before, after = separators_in(payload), separators_in(tampered)
            added = [_ for _ in after if after[_] > before[_] and _ != separator]
            if added and separator not in SMUGGLES_BY_DESIGN.get(name, ()):
              offenders.append(name + " adds " + ",".join(added) + " under " + repr(separator))
    self.assertEqual([], offenders)

  def test_the_pinned_locale_is_still_an_assignment_after_a_rewrite(self):
    """
    Broken up between its letters the name is quoted, and a quoted name is a command name - so the locale a measuring payload pins would go unpinned.
    """
    offenders = []
    for separator in (";", settings.END_LINE.LF):
      for name, module in tamper_modules().items():
        if not hasattr(module, "tamper"):
          continue
        settings.TARGET_OS = settings.OS.UNIX
        if hasattr(module, "dependencies") and module.dependencies():
          continue
        payload = _measuring_payload(separator, settings.OS.UNIX)
        self.assertIn(settings.BYTE_LOCALE_EXPORTED, payload, "nothing to pin under " + repr(separator))
        try:
          tampered = module.tamper(payload)
        except Exception:
          continue
        if settings.BYTE_LOCALE not in tampered or "export" not in tampered:
          offenders.append(name + " under " + repr(separator))
    self.assertEqual([], offenders)

  def test_the_exported_pin_survives_a_rewrite_too(self):
    """
    Through backticks the counting is a command of its own, so the pin is exported - and 'export' is a builtin no glob of the same length can stand in for.
    """
    from src.core.techniques.time_based import tb_payloads
    offenders = []
    try:
      for separator in ("&", "&&"):
        for name, module in tamper_modules().items():
          if not hasattr(module, "tamper"):
            continue
          stage(separator)
          settings.CMD_SUB_PREFIX = settings.CMD_SUB_SUFFIX = settings.BACKTICK_SUBSTITUTION
          settings.TARGET_OS = settings.OS.UNIX
          if hasattr(module, "dependencies") and module.dependencies():
            continue
          payload = tb_payloads.get_length(separator, "id", 4, 5, "GET")
          self.assertIn(settings.BYTE_LOCALE_EXPORTED, payload, "nothing to pin under " + repr(separator))
          try:
            tampered = module.tamper(payload)
          except Exception:
            continue
          if settings.BYTE_LOCALE not in tampered or "export" not in tampered:
            offenders.append(name + " under " + repr(separator))
    finally:
      settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX = settings.NESTING_SUBSTITUTION
    self.assertEqual([], offenders)

  def test_fold_alone_carries_no_operator_at_all(self):
    from src.tamper.obfuscation.generic import randomcase
    for separator in SEPARATORS:
      payload = stage(separator, rev=False)
      tampered = randomcase.tamper(payload)
      before, after = separators_in(payload), separators_in(tampered)
      self.assertEqual(before, after, "randomcase changed the separator count under " + repr(separator))

class EvalTamperSeparators(unittest.TestCase):
  """
  A script that rewrites evaluated code is inert against a shell payload, so the sweep above never
  reaches one - which is how an '&&' sat in the PHP rewrite unnoticed. Each is run here against a
  payload shaped the way its own language's grammar writes them.

  No evaluated language chains on a shell operator (test_grammars pins that), so any '&', '&&',
  '|' or '||' a rewrite introduces is one the payload is not proving. A ';' is not counted: it
  terminates a statement in several of these grammars, and one of them appends a bare one.
  """
  SHAPES = {
                  "php": 'system("echo MARKER");',
                  "python": '__import__("os").system("echo MARKER")',
                  "ruby": 'system("echo MARKER")',
                  "javascript": 'require("child_process").execSync("echo MARKER")',
                  "lua": 'os.execute("echo MARKER")',
  }

  def _eval_scripts(self):
    return dict((name, module) for name, module in tamper_modules().items()
                if "/eval/" in (module.__file__ or "").replace(os.sep, "/"))

  def test_the_sweep_reaches_the_evaluated_language_scripts(self):
    acted = set()
    for language, shape in self.SHAPES.items():
      settings.EVAL_GRAMMAR = importlib.import_module("src.core.eval.grammars." + language)
      stage(";")
      settings.RAW_PAYLOAD = shape
      for name, module in self._eval_scripts().items():
        if module.tamper(shape) != shape:
          acted.add(name)
    # Short of this the assertion below passes by never rewriting anything at all.
    self.assertGreater(len(acted), 8)

  def test_no_evaluated_rewrite_introduces_a_shell_operator(self):
    offenders = []
    for language, shape in self.SHAPES.items():
      settings.EVAL_GRAMMAR = importlib.import_module("src.core.eval.grammars." + language)
      stage(";")
      settings.RAW_PAYLOAD = shape
      before = separators_in(shape)
      for name, module in self._eval_scripts().items():
        tampered = module.tamper(shape)
        after = separators_in(tampered)
        added = [_ for _ in ("&", "&&", "|", "||") if after[_] > before[_]]
        if added:
          offenders.append(language + "/" + name + " adds " + ",".join(added))
    self.assertEqual([], offenders)

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
        if start == -1:
          continue
        guarded = "TARGET_OS" in source[start:]
        # A script that settles something before any payload is built keeps the guard in 'declare()'
        # and calls it from 'tamper()', so the check is still made every time one is rewritten.
        if not guarded and "declare()" in source[start:]:
          declared = source.find("def declare():")
          guarded = declared != -1 and "TARGET_OS" in source[declared:start]
        if not guarded:
          unguarded.append(filename)
    self.assertEqual([], unguarded)

class TamperCommandIntegrity(unittest.TestCase):
  """
  What the user asked to run is what has to run: a rewrite may hide the command, never change it.
  """
  def test_arguments_keep_their_own_case(self):
    from src.tamper.obfuscation.generic import randomcase
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
    from src.tamper.obfuscation.generic import randomcase
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

class Printf2Echo(unittest.TestCase):
  """
  The script stands in for the reading an ordinal is taken with, so it has to go on matching the
  shape that reading is written in - it once went on being selected, and accepted, long after the
  payloads had stopped carrying the text it looked for, rewriting nothing at all.
  """
  TARGETS = (("boolean_based.bb_payloads", lambda m, s: m.get_char(s, "id", 2, 126)),
             ("tempfile_based.tfb_payloads", lambda m, s: m.get_char(s, "/tmp/f", 2, 126, 5, "GET")))

  def _payloads(self, separator):
    stage(separator)
    for name, build in self.TARGETS:
      module = importlib.import_module("src.core.techniques." + name)
      settings.EXPLOITATION_PHASE = True
      payload = build(module, separator)
      if payload:
        yield name, payload

  def _script(self):
    from src.tamper.obfuscation.posix import printf2echo
    return printf2echo

  def test_it_rewrites_the_reading_it_is_named_for(self):
    """
    Put to the script directly: no builder writes this reading under a pipe any more, where every technique reads a byte with 'od' already.
    """
    from src.core.controller import checks
    for separator in ("|", "||"):
      stage(separator)
      settings.EXPLOITATION_PHASE = True
      payload = separator + "[ 126 -gt " + checks.byte_ordinal("${" + settings.RANDOM_VAR_GENERATOR + "}") + " ]"
      self.assertIn("printf '%d'", payload)
      tampered = self._script().tamper(payload)
      self.assertNotEqual(payload, tampered, "under " + repr(separator))
      self.assertNotIn("printf '%d'", tampered)
      self.assertIn("od -An -tuC", tampered)

  def test_it_finds_the_reading_however_the_run_spells_a_gap(self):
    """
    The substitute is written in before any script runs, so a reading looked for with spaces in it
    is not the reading there is to find - and a script that looks for one rewrites nothing while
    going on being reported as applied.
    """
    from src.core.controller import checks
    kept = list(settings.WHITESPACES)
    try:
      for blank in ("\t", "${IFS}", "$IFS$9"):
        stage("|", whitespace=blank)
        settings.EXPLOITATION_PHASE = True
        plain = "|[ 126 -gt " + checks.byte_ordinal("${" + settings.RANDOM_VAR_GENERATOR + "}") + " ]"
        written = checks.tamper_outside_quoted_text(plain, lambda part: checks.tamper_blanks(part, blank))
        tampered = self._script().tamper(written)
        self.assertNotEqual(written, tampered, "rewrote nothing under " + repr(blank))
        self.assertNotIn("printf '%d'", tampered, "under " + repr(blank))
    finally:
      settings.WHITESPACES = kept

  def test_the_byte_reading_goes_out_without_the_name_the_target_refuses(self):
    """
    What this script is named for is a byte's ordinal, which is read with 'printf' - so with the
    printer traded away the comparison names the character instead, on every boundary, and the pool
    the search runs over is held to the characters that can be named.
    """
    from src.core.controller import checks
    from src.core.techniques.boolean_based import bb_payloads
    from src.core.techniques.time_based import tb_payloads
    kept = settings.PRINT_WITH_ECHO
    try:
      for separator in (";", "&&", settings.END_LINE.LF):
        stage(separator)
        settings.EXPLOITATION_PHASE = True
        self._script().declare()
        for built in (bb_payloads.get_char(separator, "id", 2, 100),
                      tb_payloads.get_char(separator, "id", 2, 100, 5, "GET")):
          if built:
            self.assertNotIn("printf", built, "under " + repr(separator))
        pool = checks.generate_char_pool(2)
        self.assertEqual([], [one for one in pool if checks.byte_literal(one) is None])
        # Left out only where the byte is asked for as one of a set, which is what a pipe gets:
        # alone between brackets a '^' negates the set rather than standing in it.
        self.assertEqual(separator not in ("|", "||"), ord("^") in pool, "under " + repr(separator))
        self.assertFalse(checks.char_pool_expands())
    finally:
      settings.PRINT_WITH_ECHO = kept

  def test_it_is_not_written_where_a_pipe_is_not_what_is_proving(self):
    for separator in (";", "&", "&&", settings.END_LINE.LF):
      for name, payload in self._payloads(separator):
        self.assertEqual(payload, self._script().tamper(payload),
                         name + " rewritten under " + repr(separator))

  def test_the_reading_it_leaves_behind_is_unsigned(self):
    """
    'od -tuC' answers 195 where the reading it replaces answers -61 on a shell signing its bytes,
    so the arithmetic bringing that answer back into range goes out with the reading it corrected.
    """
    for separator in ("|", "||"):
      for name, payload in self._payloads(separator):
        tampered = self._script().tamper(payload)
        if tampered == payload:
          continue
        self.assertNotIn("% " + str(settings.HIGHEST_BYTE + 1), tampered)

# eof

class DeclaredBeforeTheFirstPayload(unittest.TestCase):
  """
  A script that changes how a payload is put together, rather than how it reads, has to say so
  before any payload is built. Said when it first rewrites one, the choice arrives a payload late:
  the builders read it as they build, so the first payload of every boundary is put together the
  old way - and that is the payload a target is first judged on.
  """
  SETTLES = ("space2htab", "space2plus", "space2vtab", "space2ifs", "space2ifsraw",
             "multiplespaces", "backticks")

  def _module(self, name):
    modules = tamper_modules()
    self.assertIn(name, modules, "no tamper script named " + name)
    return modules[name]

  def test_every_construction_script_declares(self):
    for name in self.SETTLES:
      self.assertTrue(hasattr(self._module(name), "declare"),
                      name + " settles its choice only when it first rewrites a payload")

  def test_declaring_is_what_rewriting_would_have_done(self):
    """
    The rewrite still calls it, so a choice that has to follow a target settled later still does.
    """
    for name in self.SETTLES:
      module = self._module(name)
      source = inspect.getsource(module.tamper)
      self.assertIn("declare()", source, name + " no longer calls its own declaration")

  def test_the_choice_lands_before_a_payload_is_built(self):
    from src.tamper.whitespace.generic import space2htab
    settings.TARGET_OS = settings.OS.UNIX
    settings.WHITESPACES = [settings.SINGLE_WHITESPACE]
    space2htab.declare()
    self.assertNotEqual([settings.SINGLE_WHITESPACE], settings.WHITESPACES,
                        "declaring left the whitespace as it was")
    settings.WHITESPACES = [settings.SINGLE_WHITESPACE]

  def test_settling_the_scripts_is_what_declares_them(self):
    """
    The hook itself: a script selected for this run has its choice settled while the scripts are
    being settled, with no payload rewritten in between.
    """
    from src.core.controller import checks
    from src.core.parse import cmdline as menu
    was = (menu.options.tamper, list(settings.WHITESPACES), list(settings.MULTI_ENCODED_PAYLOAD))
    try:
      settings.TARGET_OS = settings.OS.UNIX
      settings.WHITESPACES = [settings.SINGLE_WHITESPACE]
      settings.MULTI_ENCODED_PAYLOAD = []
      menu.options.tamper = "space2htab"
      checks.tamper_scripts(stored_tamper_scripts=True)
      self.assertNotEqual([settings.SINGLE_WHITESPACE], settings.WHITESPACES,
                          "settling the scripts did not settle what they choose")
    finally:
      menu.options.tamper, settings.WHITESPACES, settings.MULTI_ENCODED_PAYLOAD = (
        was[0], was[1], was[2])

  def test_the_substitution_lands_before_a_payload_is_built(self):
    from src.tamper.quoting.posix import backticks
    was = (settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX)
    try:
      settings.TARGET_OS = settings.OS.UNIX
      from src.core.parse import cmdline as menu
      menu.options.interpreter = None
      settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX = "$(", ")"
      backticks.declare()
      self.assertEqual(settings.BACKTICK_SUBSTITUTION, settings.CMD_SUB_PREFIX)
    finally:
      settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX = was

# eof

class BackticksStayExpressible(unittest.TestCase):
  """
  A backtick cannot hold another backtick, so a payload written with them has to carry none nested.
  Where the substitution would have to nest, the builders keep a form that does not - and the parts
  that are written as '$( )' outright stay that way, which is what keeps them correct rather than an
  oversight: converted, 'printf %s "$(cmd)" | ...' would be a backtick inside a backtick.
  """

  def _payloads(self):
    from src.core.techniques.time_based import tb_payloads
    from src.core.techniques.boolean_based import bb_payloads
    from src.core.techniques.tempfile_based import tfb_payloads
    for separator in SEPARATORS:
      stage(separator)
      settings.EXPLOITATION_PHASE = True
      settings.TIME_RELATED_ATTACK = True
      yield "tb.get_char", separator, tb_payloads.get_char(separator, "id", 2, 126, 5, "GET")
      yield "tb.get_length", separator, tb_payloads.get_length(separator, "id", 1, 5, "GET")
      yield "tfb.get_char", separator, tfb_payloads.get_char(separator, "/tmp/f", 2, 126, 5, "GET")
      settings.TIME_RELATED_ATTACK = False
      yield "bb.get_char", separator, bb_payloads.get_char(separator, "id", 2, 126)

  @unittest.skipUnless(os.path.exists("/bin/sh"), "needs a POSIX shell")
  def test_a_payload_answers_the_same_whichever_substitution_is_written(self):
    """
    Counting backticks cannot tell nesting from adjacency - '`a``b`' and '`a`b``' read alike - so
    the payload is asked instead. A backtick holding another answers nothing rather than erroring,
    which is exactly the failure a textual check would miss.
    """
    import subprocess
    from src.core.techniques.boolean_based import bb_payloads
    from src.tamper.quoting.posix import backticks
    from src.core.parse import cmdline as menu
    was = (settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX)
    environment = {"LC_ALL": "C", "PATH": os.environ.get("PATH", "/bin:/usr/bin")}

    def answered(payload):
      # The pipe forms read the output down the pipe, so the payload stands on its own.
      body = payload.lstrip(settings.PIPE_SEPARATOR)
      done = subprocess.run(["/bin/sh", "-c", "/bin/echo up" + settings.PIPE_SEPARATOR + body],
                            env=environment, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
      return done.returncode

    try:
      menu.options.interpreter = None
      settings.TARGET_OS = settings.OS.UNIX
      for candidate, expected in ((126, 0), (196, 1)):
        stage(settings.PIPE_SEPARATOR)
        settings.EXPLOITATION_PHASE = True
        settings.BOOLEAN_PRINTED_STATE = False
        settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX = settings.NESTING_SUBSTITUTION
        nesting = bb_payloads.get_char(settings.PIPE_SEPARATOR, "printf 'x\\303y'", 2, candidate)
        backticks.declare()
        quoted = bb_payloads.get_char(settings.PIPE_SEPARATOR, "printf 'x\\303y'", 2, candidate)
        self.assertEqual(expected, answered(nesting), "the '$( )' form answered wrongly")
        self.assertEqual(answered(nesting), answered(quoted),
                         "the two substitutions disagree at " + str(candidate))
    finally:
      settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX = was

  def test_the_choice_is_withdrawn_where_it_stops_applying(self):
    """
    The comment in the script anticipated this: a target settled as Windows after the script was
    accepted would otherwise keep writing a backtick 'cmd.exe' has no meaning for.
    """
    from src.tamper.quoting.posix import backticks
    from src.core.parse import cmdline as menu
    was = (settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX, settings.TARGET_OS)
    try:
      menu.options.interpreter = None
      settings.TARGET_OS = settings.OS.UNIX
      backticks.declare()
      self.assertEqual(settings.BACKTICK_SUBSTITUTION, settings.CMD_SUB_PREFIX)
      settings.TARGET_OS = settings.OS.WINDOWS
      backticks.declare()
      self.assertEqual(settings.NESTING_SUBSTITUTION,
                       (settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX),
                       "the backtick was left standing for a target that has none")
    finally:
      settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX, settings.TARGET_OS = was

# eof

class NashornParsesWhatItIsSent(unittest.TestCase):
  """
  The engine behind '--tamper=nashornexec' stops at the ECMAScript version before arrow functions,
  so anything the grammar writes that postdates it has to be rewritten on the way out. A construct
  the engine cannot parse is worse than one it cannot run: the parse fails before the payload is
  evaluated at all, so every boundary comes back as the same error page and a technique reading one
  answer against another is told nothing by it.
  """
  def setUp(self):
    self.grammar = settings.EVAL_GRAMMAR
    settings.EVAL_GRAMMAR = importlib.import_module("src.core.eval.grammars.javascript")

  def tearDown(self):
    settings.EVAL_GRAMMAR = self.grammar

  def _tamper(self, payload):
    from src.tamper.eval.javascript import nashornexec
    return nashornexec.tamper(payload)

  def test_the_grammar_is_left_with_no_arrow_function(self):
    # Asked of the grammar rather than of a spelling written out here, so a payload that starts
    # carrying an arrow somewhere else is caught by this too.
    grammar = settings.EVAL_GRAMMAR
    written = [grammar.halt(grammar.length(grammar.run("id")) + "==2"),
               grammar.print_statement(";", ["id"]),
               grammar.delay(5, "1==1"),
               grammar.sequence(grammar.run("id"), grammar.read_file("/etc/passwd"))]
    for payload in written:
      self.assertNotIn("=>", self._tamper(payload), "an arrow reaches the engine in " + payload[:60])

  def test_the_rewrite_still_throws_where_the_condition_does_not_hold(self):
    grammar = settings.EVAL_GRAMMAR
    tampered = self._tamper(grammar.halt("1==2"))
    self.assertIn("function(){throw new Error()}", tampered)

class TheOperatorHandsOnTheCommandItWasGiven(unittest.TestCase):
  """
  Where a tamper script is in effect, the PHP and Ruby grammars run a command through the backtick
  operator, because every script rewriting such a payload is written around it. The operator reads
  its own string before the shell is handed anything, and what it reads it spends: 'printf \\141'
  reached the shell as 'printf a', a backtick of the command's own closed the operator early, and a
  '$' opened a variable that was never set. Each is written for that reading, and the scripts that
  take the command back out of the operator read it off again.
  """
  COMMAND = "printf '\\141\\045' $HOME `id`"

  def setUp(self):
    self.grammar = settings.EVAL_GRAMMAR
    self.scripts = dict(settings.TAMPER_SCRIPTS)
    settings.TAMPER_SCRIPTS["phpconcat"] = True

  def tearDown(self):
    settings.EVAL_GRAMMAR = self.grammar
    settings.TAMPER_SCRIPTS.clear()
    settings.TAMPER_SCRIPTS.update(self.scripts)

  def _grammar(self, language):
    settings.EVAL_GRAMMAR = importlib.import_module("src.core.eval.grammars." + language)
    return settings.EVAL_GRAMMAR

  def test_what_the_operator_reads_is_written_for_it(self):
    for language, interpolation in (("php", "$"), ("ruby", "#")):
      grammar = self._grammar(language)
      written = grammar.run(self.COMMAND)
      self.assertTrue(written.startswith("`") and written.endswith("`"), language)
      inside = written[1:-1]
      self.assertNotIn("\\141", inside.replace("\\\\141", ""), language + " left an escape unwritten")
      self.assertNotIn("`", inside.replace("\\`", ""), language + " left a backtick unwritten")
      self.assertEqual(self.COMMAND, grammar.backtick_command(inside),
                       language + " does not read back what it wrote")
      self.assertNotIn(interpolation, inside.replace("\\" + interpolation, ""),
                       language + " left its own interpolation unwritten")

  def test_a_script_taking_the_command_out_gets_it_as_it_was_written(self):
    grammar = self._grammar("php")
    payload = grammar.print_statement("", [self.COMMAND])
    for name, module in (("phpconcat", "src.tamper.eval.php.phpconcat"),
                         ("phphexname", "src.tamper.eval.php.phphexname")):
      tampered = importlib.import_module(module).tamper(payload)
      # The call carries the command as a single-quoted literal, where only the quote and the
      # backslash are spoken for - so what the operator was written for is off it again.
      self.assertIn("printf \\'\\\\141\\\\045\\' $HOME `id`", tampered,
                    name + " did not hand on the command as it was written")

class AReplacementStringCarriesWhatItWasGiven(unittest.TestCase):
  """
  A sink evaluated by preg_replace()'s "e" modifier fills in the backreferences its replacement is
  read as naming before it evaluates anything, and a pattern that captured nothing fills them in
  with nothing: a command written "printf '\\141\\142\\143'" reached the sink as "printf '123'",
  each backslash and the digit behind it spent on a group that was never there. What arrives has to
  be what was written, so the payload is written the way that reading puts it back.
  """
  # What is left of a replacement string once the backreferences in it have been filled in, with
  # nothing captured to fill them with - which is what the sink evaluates.
  READ_AS = r"\\\\|\\\$|\\\d{1,2}|\$\{?\d{1,2}\}?"

  def _as_the_sink_reads_it(self, replacement):
    def filled(match):
      return {"\\\\": "\\", "\\$": "$"}.get(match.group(0), "")
    return re.sub(self.READ_AS, filled, replacement)

  def _tamper(self, payload):
    from src.tamper.eval.php import phpregreplace
    return phpregreplace.tamper(payload)

  def test_a_payload_arrives_as_it_was_written(self):
    written = ["printf '\\141\\142\\143'",
               "shell_exec('printf \\'a\\\\b\\'')",
               "print(`echo $((5+7))`)",
               "`cat /tmp/x.txt`"]
    for payload in written:
      self.assertEqual(payload, self._as_the_sink_reads_it(self._tamper(payload)),
                       "did not arrive as written: " + payload)

  def test_a_dollar_sign_that_stands_before_a_digit_arrives_as_one(self):
    self.assertEqual("echo $1", self._as_the_sink_reads_it(self._tamper("echo $1")))
    self.assertEqual("echo ${12}", self._as_the_sink_reads_it(self._tamper("echo ${12}")))

  def test_a_payload_with_nothing_to_carry_is_left_as_it_is(self):
    for payload in ("print(`echo ABCDEF`)", "id", "echo $((1+2))"):
      self.assertEqual(payload, self._tamper(payload))

class DashlessByteReading(unittest.TestCase):
  """
  The reading 'dashlesstest' writes in place of 'tail -c'/'head -c'/'od' hands back the byte those
  three would have, a line break among them: a command's output carries one of those per line, and a
  reading that loses them answers with a wrong ordinal on every one of them.
  """
  # Two lines with an empty one between them, so a line break is asked for twice over - once where
  # another follows it, which is where a reading that takes the byte alone has nothing left to read.
  OUTPUT = "a\n\nb"

  def _shell(self, expression):
    done = subprocess.run(["/bin/sh", "-c", "printf %s " + expression], capture_output=True, text=True)
    return done.stdout.strip()

  @unittest.skipUnless(os.path.exists("/bin/sh"), "no POSIX shell to read the payload back with")
  def test_every_byte_reads_as_the_one_the_pipe_would_have_handed_back(self):
    stage("|")
    from src.core.techniques.time_based import tb_payloads
    from src.tamper.obfuscation.posix import dashlesstest
    word = "$(printf 'a\\n\\nb')"
    for at in range(1, len(self.OUTPUT) + 1):
      piped = tb_payloads._ordinal_expr(word, at)
      self.assertIn("od -A n -t u1", piped)
      expected = self._shell(piped)
      written = self._shell(dashlesstest.tamper(piped))
      self.assertEqual(str(ord(self.OUTPUT[at - 1])), written.strip(),
                       "byte " + str(at) + " of " + repr(self.OUTPUT) + " read as " + repr(written))
      self.assertEqual(expected.strip(), written.strip(), "byte " + str(at))

class DashlessReadingsOfAnAwkwardOutput(unittest.TestCase):
  """
  What the script measures and indexes is a command's own output, which a run is free to find
  anything in. An output that is one of 'expr's own words is read as that word rather than as the
  text being measured - refused by one build of it, answered with a wrong number by another - and a
  byte of a character written in two is a step of its own only where the byte locale is asked for.
  """
  # Each of 'expr's shapes: an operator, a parenthesis, and the words only some builds know.
  AWKWARD = ("|", "(", "match", "length", "index", "alpha\n\nbeta", "x")

  def _shell(self, script):
    done = subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True)
    return done.stdout.strip()

  def _printed(self, text):
    return "printf '" + "".join("\\%03o" % byte for byte in text.encode("utf-8")) + "'"

  @unittest.skipUnless(os.path.exists("/bin/sh"), "no POSIX shell to read the payload back with")
  def test_the_count_and_the_bytes_come_back_whatever_the_output_says(self):
    stage("|")
    from src.core.techniques.boolean_based import bb_payloads
    from src.core.techniques.time_based import tb_payloads
    from src.tamper.obfuscation.posix import dashlesstest
    for text in self.AWKWARD:
      word = "$(" + self._printed(text) + ")"
      counted = self._shell("printf %s " + dashlesstest.tamper(bb_payloads._piped_length(word)))
      self.assertEqual(str(len(text.encode("utf-8"))), counted, "length of " + repr(text))
      for at in range(1, len(text.encode("utf-8")) + 1):
        read = self._shell("printf %s " + dashlesstest.tamper(tb_payloads._ordinal_expr(word, at)))
        self.assertEqual(str(text.encode("utf-8")[at - 1]), read, "byte " + str(at) + " of " + repr(text))

  def test_both_readings_ask_for_the_locale_that_makes_a_character_a_byte(self):
    stage("|")
    from src.core.techniques.boolean_based import bb_payloads
    from src.core.techniques.time_based import tb_payloads
    from src.tamper.obfuscation.posix import dashlesstest
    word = "$(id)"
    for written in (dashlesstest.tamper(bb_payloads._piped_length(word)),
                    dashlesstest.tamper(tb_payloads._ordinal_expr(word, 2))):
      self.assertIn(settings.BYTE_LOCALE + " expr", written)
      self.assertNotIn("-", written)

class AWhitespaceSubstituteDoesNotDisarmAScript(unittest.TestCase):
  """
  The substitute is written in before any script runs - the request puts it there, and by then every
  space outside a quoted literal is gone - so a script that looks for a space finds none of what it
  was built to find, and goes on being reported as applied while rewriting nothing at all.

  Asked of every script that rewrites anything here: what it does to a payload written with a space
  it must still do to that same payload written the way the run spells a gap. The whitespace scripts
  themselves are left out, having no space of their own left to find once another one has run.
  """
  BLANKS = ("\t", "${IFS}", "$IFS$9")

  def setUp(self):
    # Every one of these is left as it was found: a substitute whitespace or a printer carried into
    # the next test is a payload built the way nothing else here expects.
    self._state = (list(settings.WHITESPACES), settings.PRINT_WITH_ECHO,
                   list(settings.MULTI_ENCODED_PAYLOAD), settings.EXPLOITATION_PHASE)

  def tearDown(self):
    settings.WHITESPACES, settings.PRINT_WITH_ECHO, settings.MULTI_ENCODED_PAYLOAD, settings.EXPLOITATION_PHASE = self._state

  def _substituted(self, payload, blank):
    from src.core.controller import checks
    rewrite = (checks.tamper_outside_single_quotes if blank in settings.DECODED_WHITESPACES
               else checks.tamper_outside_quoted_text)
    return rewrite(payload, lambda part: checks.tamper_blanks(part, blank))

  def _built(self, separator):
    from src.core.techniques.boolean_based import bb_payloads
    from src.core.techniques.time_based import tb_payloads
    if separator == "|":
      return bb_payloads.get_char("|", "id", 2, 100)
    return tb_payloads.get_length(separator, "id", 5, 5, "GET")

  def test_a_script_reads_the_payload_whichever_way_round_the_two_rewrites_went(self):
    """
    The substitute is written last, so what a script is handed carries spaces - and a script that
    only knew how to read a substitute would find nothing in it. Asked both ways round, since a
    script is also handed what another script wrote, and that may carry either.
    """
    stale = []
    for name, module in sorted(tamper_modules().items()):
      if not hasattr(module, "tamper") or os.sep + "whitespace" + os.sep in module.__file__:
        continue
      for separator in (";", "|"):
        for blank in self.BLANKS:
          stage(separator, whitespace=blank)
          settings.MULTI_ENCODED_PAYLOAD = [name]
          settings.EXPLOITATION_PHASE = True
          try:
            payload = self._built(separator)
            if not payload or module.tamper(payload) == payload:
              continue
          except Exception:
            continue
          # The same payload once the gap has been written in, which is what another script may hand on.
          swapped = self._substituted(self._built(separator), blank)
          try:
            if module.tamper(swapped) == swapped:
              stale.append(name + " under " + repr(blank) + " (" + repr(separator) + ")")
          except Exception as exc:
            stale.append(name + " raised " + type(exc).__name__ + " under " + repr(blank))
    self.assertEqual([], stale, "reads one spelling of a gap and not the other: " + ", ".join(stale))

  def test_what_a_script_rewrites_with_a_space_it_rewrites_with_a_substitute(self):
    disarmed = []
    for name, module in sorted(tamper_modules().items()):
      if not hasattr(module, "tamper") or os.sep + "whitespace" + os.sep in module.__file__:
        continue
      for separator in (";", "|"):
        stage(separator)
        settings.MULTI_ENCODED_PAYLOAD = [name]
        settings.EXPLOITATION_PHASE = True
        try:
          payload = self._built(separator)
          if not payload or module.tamper(payload) == payload:
            continue
        except Exception:
          continue
        for blank in self.BLANKS:
          stage(separator, whitespace=blank)
          settings.MULTI_ENCODED_PAYLOAD = [name]
          settings.EXPLOITATION_PHASE = True
          # Built again under this staging: a script reads the command the run was asked for out of
          # the payload, and a payload built under one staging does not hold the other's command.
          swapped = self._substituted(self._built(separator), blank)
          try:
            if module.tamper(swapped) == swapped:
              disarmed.append(name + " under " + repr(blank) + " (" + repr(separator) + ")")
          except Exception as exc:
            disarmed.append(name + " raised " + type(exc).__name__ + " under " + repr(blank))
    self.assertEqual([], disarmed, "rewrites nothing once the gap is a substitute: " + ", ".join(disarmed))

  def test_the_dashless_script_leaves_no_dash_whatever_the_gap_is_written_with(self):
    from src.tamper.obfuscation.posix import dashlesstest
    for blank in (settings.SINGLE_WHITESPACE,) + self.BLANKS:
      for separator in (";", "|"):
        for printer in (False, True):
          stage(separator, whitespace=blank)
          settings.MULTI_ENCODED_PAYLOAD = [settings.DASHLESS_TAMPER]
          settings.EXPLOITATION_PHASE = True
          settings.PRINT_WITH_ECHO = printer
          payload = self._built(separator)
          if not payload:
            continue
          given = payload if blank == settings.SINGLE_WHITESPACE else self._substituted(payload, blank)
          written = dashlesstest.tamper(given)
          self.assertNotIn("-", written,
                           "a '-' left under " + repr(blank) + " " + repr(separator) +
                           (" with echo" if printer else " with printf"))

class TheDashlessScriptReadsBeforeWhatRewritesWhatItReads(unittest.TestCase):
  """
  What it matches is the shape a payload builder wrote - a comparison, a count, a byte taken down a
  pipe. A script that breaks those up, a quote or a backslash or a letter at a time, leaves nothing
  to recognise, and this one then rewrites none of it while still being reported as applied. It is
  ordered ahead of them for that reason, so the only '-' a pairing can leave is one the other script
  writes itself and has no other spelling for.
  """
  # 'ping' has no other way of being told how many packets to send, 'awk' counts down with one, and
  # a defaulted expansion is written with one.
  WRITES_ITS_OWN = ("sleep2ping", "rev", "cmd2wildcard")

  def setUp(self):
    self._state = (list(settings.MULTI_ENCODED_PAYLOAD), settings.EXPLOITATION_PHASE)

  def tearDown(self):
    settings.MULTI_ENCODED_PAYLOAD, settings.EXPLOITATION_PHASE = self._state

  def test_a_pairing_leaves_a_dash_only_where_the_other_script_wrote_one(self):
    from src.core.techniques.time_based import tb_payloads
    modules = {name: module for name, module in tamper_modules().items()
               if hasattr(module, "tamper") and name != "xforwardedfor"
               and os.sep + "windows" + os.sep not in module.__file__
               and os.sep + "eval" + os.sep not in module.__file__}
    priority = {name: getattr(module, "__priority__", settings.PRIORITY.NORMAL)
                for name, module in modules.items()}
    left = []
    for separator in (";", "|"):
      for other in sorted(modules):
        if other == settings.DASHLESS_TAMPER or other in self.WRITES_ITS_OWN:
          continue
        pair = sorted((settings.DASHLESS_TAMPER, other), key=lambda name: -priority[name])
        stage(separator)
        settings.MULTI_ENCODED_PAYLOAD = list(pair)
        settings.EXPLOITATION_PHASE = True
        for name in pair:
          if hasattr(modules[name], "declare"):
            try: modules[name].declare()
            except Exception: pass
        payload = tb_payloads.get_length(separator, "id", 5, 5, "GET")
        if not payload:
          continue
        try:
          for name in pair:
            payload = modules[name].tamper(payload)
        except Exception:
          continue
        if "-" in payload:
          left.append(other + " on " + repr(separator))
    self.assertEqual([], left, "a '-' left in the payload beside: " + ", ".join(left))

class AScriptDoesNotReachBackPastTheOnesBeforeIt(unittest.TestCase):
  """
  The scripts run in order, each handed what the one before it wrote. One that cannot find the
  command in what it was handed - because the script before it hid the command, which is what that
  one was loaded to do - has nothing of its own to do, and going back to the payload the run started
  with would throw that work away and send a payload carrying only half of what was asked for.
  """
  def setUp(self):
    self._state = (list(settings.MULTI_ENCODED_PAYLOAD), settings.EXPLOITATION_PHASE,
                   settings.RAW_PAYLOAD, settings.USER_APPLIED_CMD)

  def tearDown(self):
    (settings.MULTI_ENCODED_PAYLOAD, settings.EXPLOITATION_PHASE,
     settings.RAW_PAYLOAD, settings.USER_APPLIED_CMD) = self._state

  def test_a_hidden_command_is_still_hidden_after_the_next_script(self):
    from src.core.techniques.time_based import tb_payloads
    modules = tamper_modules()
    stage(";", command="id")
    settings.MULTI_ENCODED_PAYLOAD = ["cmd2wildcard", "randomcase"]
    settings.EXPLOITATION_PHASE = True
    payload = tb_payloads.get_length(";", "id", 5, 5, "GET")
    settings.RAW_PAYLOAD = payload
    hidden = modules["cmd2wildcard"].tamper(payload)
    # What that script writes in place of the command, which is the thing that must survive.
    self.assertIn(":-", hidden, "the script under test rewrote nothing to begin with")
    self.assertIn(":-", modules["randomcase"].tamper(hidden),
                  "the rewrite before it was thrown away")

class ListedDescriptions(unittest.TestCase):
  """
  Whatever '--list-tampers' prints for a script has to be the whole sentence the script opens with,
  however many lines it was written over - a description listed cut off mid-sentence reads as a
  truncated answer from commix rather than as a description that happens to be long.
  """
  def _about(self, module):
    # Asked of the reader the listing itself uses, not of a second copy of it here - a test with its
    # own idea of where the description ends would pass while the listing printed something else.
    from src.core.controller import checks
    with open(module.__file__.replace(".pyc", ".py"), encoding="utf-8") as handle:
      return checks.tamper_description(handle.read())

  def test_every_script_says_what_it_does_in_the_line_that_is_printed(self):
    unfinished = []
    for name, module in sorted(tamper_modules().items()):
      about = self._about(module)
      if not about:
        unfinished.append(name + " (no 'About:' at all)")
      elif not about.endswith("."):
        unfinished.append(name + " (cut off: ..." + about[-40:] + ")")
    self.assertEqual([], unfinished,
                     "listed description is not a whole sentence: " + ", ".join(unfinished))
