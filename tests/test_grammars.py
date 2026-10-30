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

if __name__ == "__main__":
  unittest.main()
