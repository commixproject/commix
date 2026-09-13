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

from src.utils import menu
from src.utils import settings
from src.core.injections.controller import checks

"""
About: Adds double quotes (") around a given payload.
Notes: This tamper script works against Unix-like target(s).
"""

__tamper__ = "nested"
__priority__ = settings.PRIORITY.LOW

def dependencies():
  return checks.tamper_dep_eval_incompatible(__tamper__) or checks.tamper_dep_unix_only(__tamper__)

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

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

def tamper(payload):
  global _applied
  if not _applied and settings.TARGET_OS != settings.OS.WINDOWS:
    _applied = True
    nested()
  return payload

# eof