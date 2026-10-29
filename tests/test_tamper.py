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
    rewritten = 0
    for separator in ("|", "||"):
      for name, payload in self._payloads(separator):
        if "printf '%d'" not in payload:
          continue
        tampered = self._script().tamper(payload)
        self.assertNotEqual(payload, tampered, name + " under " + repr(separator))
        self.assertNotIn("printf '%d'", tampered)
        self.assertIn("od -An -tuC", tampered)
        rewritten += 1
    self.assertGreater(rewritten, 0, "nothing left for this script to rewrite - it is inert")

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
