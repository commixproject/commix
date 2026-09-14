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
from src.core.controller import checks

"""
About: Replaces space character (%20) with the internal field separator ($IFS) in a given payload.
The internal field separator refers to a variable which defines the character
or characters used to separate a pattern into tokens for some operations.
Notes: This tamper script works against target(s) with a POSIX shell.
"""

__tamper__ = "space2ifs"
__priority__ = settings.PRIORITY.LOWER
space2ifs = "${IFS}"

# Why this script cannot be applied to the target at hand, or nothing where it can.
def dependencies():
  return checks.tamper_dep_unix_only(__tamper__)

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

# Separate the payload's words with '${IFS}' instead of a space.
def tamper(payload):
  if len(settings.WHITESPACES) != 0:
    if space2ifs in settings.WHITESPACES[0] and settings.EVAL_BASED_STATE != False:
      settings.WHITESPACES[0] = space2ifs
    if settings.TARGET_OS != settings.OS.WINDOWS: 
      if settings.WHITESPACES[0] == settings.SINGLE_WHITESPACE:
        settings.WHITESPACES[0] = space2ifs
      elif space2ifs not in settings.WHITESPACES:
        settings.WHITESPACES.append(space2ifs)
    else:
      if space2ifs in settings.WHITESPACES:
        settings.WHITESPACES.remove(space2ifs)
  return payload

# eof
