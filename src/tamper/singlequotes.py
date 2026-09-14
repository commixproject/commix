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
About: Adds single quotes (') between the characters in a given payload.
Notes: This tamper script works against target(s) with a POSIX shell.
"""

__tamper__ = "singlequotes"
__priority__ = settings.PRIORITY.BELOW_NORMAL

# Why this script cannot be applied to the target at hand, or nothing where it can.
def dependencies():
  return checks.tamper_dep_eval_incompatible(__tamper__) or checks.tamper_dep_unix_only(__tamper__)

if not settings.TAMPER_SCRIPTS[__tamper__]:
  obf_char = "''"
  settings.TAMPER_SCRIPTS[__tamper__] = True

# Put empty single quotes between the characters, which the shell drops.
def tamper(payload):
  return checks.interleave_char_tamper(payload, obf_char)

# eof
