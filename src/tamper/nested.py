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

from src.core.parse import cmdline as menu
from src.utils import settings
from src.core.controller import checks

"""
About: Adds double quotes (") around a given payload.
Notes: This tamper script works against target(s) with a POSIX shell.
"""

__tamper__ = "nested"
__priority__ = settings.PRIORITY.LOW

# Why this script cannot be applied to the target at hand, or nothing where it can.
def dependencies():
  return checks.tamper_dep_eval_incompatible(__tamper__) or checks.tamper_dep_unix_only(__tamper__)

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

# Wrap one command substitution around another, so the payload reads as nested work.
def nested():
  if menu.options.prefix:
    menu.options.prefix = "\"" + menu.options.prefix 
  else:
    menu.options.prefix = "\""
  if menu.options.suffix: 
    menu.options.suffix = menu.options.suffix + "\""
  else:
    menu.options.suffix = "\""

"""
Applied on the first payload rather than at import.

Importing a tamper script is what lets its dependencies be checked, and those run afterwards - so a
script rewriting the boundaries as it loaded had already done it by the time it was refused, and
left every payload for the rest of the run carrying a quote it never asked for.
"""
_applied = False

# Nest the payload's command substitutions inside one another.
def tamper(payload):
  global _applied
  if not _applied and settings.TARGET_OS != settings.OS.WINDOWS:
    _applied = True
    nested()
  return payload

# eof
