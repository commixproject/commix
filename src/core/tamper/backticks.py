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

from src.utils import menu
from src.utils import settings


"""
About: Uses backticks (`) instead of "$()" for commands substitution in a given payload.
Notes: This tamper script works against Unix-like target(s).
"""

__tamper__ = "backticks"

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

def tamper(payload):
  if not menu.options.alter_shell and not settings.TARGET_OS == settings.OS.WINDOWS:
    settings.USE_BACKTICKS = True
    settings.CMD_SUB_PREFIX = settings.CMD_SUB_SUFFIX = "`"
    payload = payload.replace("${#" + settings.RANDOM_VAR_GENERATOR + "}", 
                              settings.CMD_SUB_PREFIX + "expr" + settings.WHITESPACES[0] + "length" + settings.WHITESPACES[0] + "\"$" + settings.RANDOM_VAR_GENERATOR + "\"" + settings.CMD_SUB_SUFFIX
                              )
  return payload

# eof