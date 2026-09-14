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
from src.thirdparty.six.moves import urllib as _urllib
from src.core.injections.controller import checks

"""
About: Replaces space character (%20) with vertical tab (%0b) in a given payload.
Notes: This tamper script works against Windows targets.
"""

__tamper__ = "space2vtab"
__priority__ = settings.PRIORITY.LOWER
space2vtab = "\v"

def dependencies():
  return checks.tamper_dep_windows_only(__tamper__)

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

def tamper(payload):
  if len(settings.WHITESPACES) != 0:
    if settings.TARGET_OS == settings.OS.WINDOWS:
      if settings.WHITESPACES[0] == settings.SINGLE_WHITESPACE:
        settings.WHITESPACES[0] = space2vtab
      elif space2vtab not in settings.WHITESPACES:
        settings.WHITESPACES.append(space2vtab)
    else:
      if space2vtab in settings.WHITESPACES:
        settings.WHITESPACES.remove(space2vtab)
  return payload

# eof