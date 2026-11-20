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
import shutil
import tempfile
import importlib
import subprocess
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

"""
How each language is asked to evaluate the payload left in the file named by 'COMMIX_PAYLOAD'.

Python is told which mode to read it in: an expression where the sink carried no terminator, a
statement where it did, which is the difference 'eval()' and 'exec()' make on the target itself.
"""
EVALUATORS = {
  "python": ["python3", "-c",
             "import os;src=open(os.environ['COMMIX_PAYLOAD']).read();"
             "exec(compile(src,'payload',os.environ['COMMIX_MODE']))"],
  "perl": ["perl", "-e",
           "open my $f,'<',$ENV{COMMIX_PAYLOAD} or die;my $c=do{local $/;<$f>};eval $c;die $@ if $@;"],
  "ruby": ["ruby", "-e", "eval(File.read(ENV['COMMIX_PAYLOAD']))"],
  "lua": ["lua", "-e", "local f=io.open(os.getenv('COMMIX_PAYLOAD'));local s=f:read('*a');"
                       "assert(load('return '..s) or load(s))()"],
  "php": ["php", "-r", "eval(file_get_contents(getenv('COMMIX_PAYLOAD')));"],
  "javascript": ["node", "-e",
                 "eval(require('fs').readFileSync(process.env.COMMIX_PAYLOAD,'utf8'))"],
  "powershell": ["pwsh", "-NoProfile", "-Command",
                 "Invoke-Expression (Get-Content -Raw $env:COMMIX_PAYLOAD)"],
}

class GrammarPayloads(unittest.TestCase):
  """
  What a grammar declares is one thing; what a technique builds out of it is another. The payload is
  assembled here and handed to the interpreter itself, which is the only thing that can say whether
  the language reads it - that the wrapping closes, that the terminator falls outside it, and that
  the two halves are of types the language will put together.

  A language with no interpreter on this host is passed over rather than failed.
  """
  def _evaluate(self, name, grammar, separator, work):
    from src.utils import settings
    from src.core.eval.payloads import tempfile_based as payloads
    settings.EVAL_GRAMMAR = grammar
    written = os.path.join(work, "output_" + name + ".txt")
    tag = "TAG" + name[:3].upper()
    # No delay at all: what is read here is whether the expression holds together, not how long for.
    payload = payloads.decision(separator, len(tag), tag, written, 0, "GET")
    path = os.path.join(work, "payload_" + name + ("_statement" if separator else "_expression"))
    with open(path, "w") as handle:
      handle.write(payload)
    environment = dict(os.environ, COMMIX_PAYLOAD=path,
                       COMMIX_MODE="exec" if separator else "eval")
    done = subprocess.run(EVALUATORS[name], capture_output=True, text=True,
                          timeout=60, env=environment)
    return done, written, tag

  def test_a_payload_is_something_its_own_language_can_read(self):
    from src.utils import settings
    previous = getattr(settings, "EVAL_GRAMMAR", None)
    offenders, reached = [], []
    try:
      with tempfile.TemporaryDirectory() as work:
        for name, grammar in sorted(grammars().items()):
          argv = EVALUATORS.get(name)
          if not argv or not shutil.which(argv[0]):
            continue
          reached.append(name)
          for separator in ("", grammar.TERMINATOR):
            shape = "statement" if separator else "expression"
            done, written, tag = self._evaluate(name, grammar, separator, work)
            if done.returncode != 0:
              complaint = (done.stderr or "").strip().splitlines()
              offenders.append(name + " (" + shape + "): " +
                               (complaint[0][:120] if complaint else "exited " + str(done.returncode)))
              continue
            landed = ""
            if os.path.isfile(written):
              with open(written) as handle:
                landed = handle.read()
            if tag not in landed:
              offenders.append(name + " (" + shape + "): the command never wrote its output")
    finally:
      settings.EVAL_GRAMMAR = previous
    if not reached:
      self.skipTest("none of the evaluated languages are installed on this host")
    self.assertEqual([], offenders)

class WhatAGrammarReadsBackOffAnOutput(unittest.TestCase):
  """
  A length and an ordinal are what the blind techniques have instead of the output itself, so what
  they read has to be the same thing the techniques reading a substitution hand back. A trim that
  took every kind of whitespace reported an output ending in a space shorter than it is, and an
  ordinal written without brackets of its own was read as one side of the comparison wrapped around
  it rather than as the byte - every comparison came back true, and the search for a byte converged
  on the top of its pool whatever the byte was.

  Asked of the interpreter rather than of a spelling written out here: each of these is a question
  about how the language reads what the grammar writes, which only the language can answer. One
  that is not installed on this host is passed over rather than failed.
  """
  PRINTERS = {
    "python": ["python3", "-c", "print(%s)"],
    "ruby": ["ruby", "-e", "print(%s)"],
    "perl": ["perl", "-e", "print(%s)"],
    "lua": ["lua", "-e", "print(%s)"],
    "php": ["php", "-r", "echo(%s);"],
    "javascript": ["node", "-e", "console.log(%s)"],
  }
  TRUE = ("1", "true", "True")
  FALSE = ("", "0", "false", "False")

  def _answer(self, name, expression):
    argv = list(self.PRINTERS[name])
    argv[-1] = argv[-1].replace("%s", expression)
    done = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    self.assertEqual(0, done.returncode,
                     name + " could not read '" + expression[:90] + "': " + (done.stderr or "").strip()[:160])
    return done.stdout.strip()

  def _installed(self):
    for name, grammar in sorted(grammars().items()):
      argv = self.PRINTERS.get(name)
      if argv and shutil.which(argv[0]):
        yield name, grammar

  def test_the_length_counts_the_whitespace_an_output_ends_with(self):
    reached = []
    for name, grammar in self._installed():
      reached.append(name)
      # 'AB' and two spaces, then two newlines: a substitution drops the newlines and keeps the
      # spaces, which is four characters.
      written = grammar.length(grammar.trim(grammar.run("printf 'AB  \\n\\n'")))
      self.assertEqual("4", self._answer(name, written), name + " counted it differently")
    if not reached:
      self.skipTest("none of the evaluated languages are installed on this host")

  def test_a_carriage_return_an_output_ends_with_is_counted_too(self):
    for name, grammar in self._installed():
      # A substitution stops at the first byte that is not a newline, and a carriage return is one
      # of those: 'AB' and a CRLF is three characters, not two.
      written = grammar.length(grammar.trim(grammar.run("printf 'AB\\r\\n'")))
      self.assertEqual("3", self._answer(name, written), name + " counted it differently")

  def test_a_length_and_an_ordinal_are_read_off_the_bytes(self):
    for name, grammar in self._installed():
      # Three Greek letters: six bytes, three of whatever a language calls a character. Counted the
      # second way, the search asks about half the output and the rest comes back as nothing.
      written = grammar.run("printf '\\316\\261\\316\\262\\316\\263'")
      self.assertEqual("6", self._answer(name, grammar.length(grammar.trim(written))),
                       name + " did not count the bytes")
      self.assertEqual("177", self._answer(name, grammar.ordinal(grammar.trim(written), 1)),
                       name + " did not read the second byte")
      self.assertEqual("0", self._answer(name, grammar.ordinal(grammar.trim(written), 99)),
                       name + " answered something for a byte that is not there")

  def test_an_ordinal_is_the_byte_and_not_the_comparison_around_it(self):
    for name, grammar in self._installed():
      byte = grammar.ordinal(grammar.trim(grammar.run("printf 'A'")), 0)
      self.assertEqual("65", self._answer(name, byte), name + " read the byte differently")
      # The comparison the blind techniques write around it - answered by the byte, not by a
      # fallback that took the comparison for its own right-hand side.
      above = byte + grammar.COMPARISON["-ge"] + "200"
      self.assertIn(self._answer(name, above), self.FALSE,
                    name + " read 'A' as standing at or above 200")
      below = byte + grammar.COMPARISON["-ge"] + "60"
      self.assertIn(self._answer(name, below), self.TRUE,
                    name + " read 'A' as standing below 60")

if __name__ == "__main__":
  unittest.main()

class StatementEnders(unittest.TestCase):
  """
  A value a sink reads as the whole statement has to be ended somehow, and the grammar's own
  terminator is not always available - a filter that rejects ';' takes it away while leaving the
  sink itself reachable. Where the language has a second way to end a statement, level 1 carries it
  beside the unwrapped prefix it belongs to, since the two are only useful together.
  """
  def test_php_can_end_a_statement_without_its_terminator(self):
    """
    PHP's close tag ends a statement exactly as ';' does. Without it the first level pairs an
    unwrapped value with nothing that ends one, and 'print(`cmd`)' reaches eval() half-written -
    which the interpreter refuses as readily as it refuses a payload that never closed its quote.
    """
    php = grammars()["php"]
    self.assertIn("", php.PREFIXES_LVL1, "the unwrapped value is a first-level prefix")
    enders = [s for s in php.SUFFIXES_LVL1 if s and php.TERMINATOR not in s]
    self.assertIn("?>", enders, "the close tag ends a statement where ';' cannot be written")

  def test_every_grammar_states_its_own_terminator(self):
    for name, grammar in sorted(grammars().items()):
      self.assertTrue(getattr(grammar, "TERMINATOR", ""), name + " declares no terminator")

class ACommandWithABacktickOrOddBytesIsCarried(unittest.TestCase):
  def test_the_perl_literal_leaves_a_backtick_to_the_interpreter(self):
    perl = grammars()["perl"]
    self.assertNotIn("`", perl._literal("printf 'a`echo b`c'"))
    if shutil.which("perl"):
      out = subprocess.check_output(["perl", "-e", "print " + perl.run("printf 'a`echo b`c'")]).decode()
      self.assertEqual("a`echo b`c", out)

  def test_the_python_grammar_decodes_without_stopping_at_a_byte_that_is_not_text(self):
    python = grammars()["python"]
    self.assertIn("\"utf-8\",\"replace\"", python.run("printf '\\xff'"))
    self.assertIn("\"utf-8\",\"replace\"", python.read_file("/etc/hostname"))

  def test_the_javascript_grammar_does_not_stop_at_a_command_that_exits_with_an_error(self):
    javascript = grammars()["javascript"]
    self.assertIn("spawnSync", javascript.run("ls /nonexistent"))
    self.assertNotIn("execSync", javascript.run("ls /nonexistent"))
