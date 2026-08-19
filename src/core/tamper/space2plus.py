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

"""
About: Replaces space character (%20) with plus (+) in a given payload.
Notes: This tamper script works against all targets.
"""

__tamper__ = "space2plus"
space2plus = _urllib.parse.quote_plus(settings.SINGLE_WHITESPACE)
_warned_once = False

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

def tamper(payload):
  global _warned_once

  if len(settings.WHITESPACES) != 0 and not settings.IS_JSON:
    if settings.WHITESPACES[0] == _urllib.parse.quote(settings.SINGLE_WHITESPACE):
      settings.WHITESPACES[0] = space2plus
    elif space2plus not in settings.WHITESPACES:
      settings.WHITESPACES.append(space2plus)

  else:
    if not _warned_once:
      warn_msg = "The tamper script '" + __tamper__ + "' is ineffective for JSON payloads. "
      warn_msg += "Skipping tamper script."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
      _warned_once = True

  return payload

# eof