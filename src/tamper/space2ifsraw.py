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
from src.core.controller import checks

"""
About: Replaces space character (%20) with '$IFS$9' (no braces, no quotes) in a given payload.
Notes: This tamper script works against target(s) with a POSIX shell, for a filter that also blocks
       curly braces and quotes - where 'space2ifs' ('${IFS}') and 'space2brace' both need a
       character this kind of filter takes away. '$9' is an empty positional parameter in an
       ordinary run, so it contributes nothing beyond ending the '$IFS' expansion cleanly: without
       it, '$IFS' run straight into a following letter, digit or underscore would be read as a
       longer, different (and empty) variable name instead. Safe wherever it lands, since nothing
       about what follows the space changes how it is used.
References: [1] https://www.yeswehack.com/dojo/dojo-ctf-challenge-winners
"""

__tamper__ = "space2ifsraw"
__priority__ = settings.PRIORITY.LOWER
space2ifsraw = "$IFS$9"

def dependencies():
  return checks.tamper_dep_unix_only(__tamper__)

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

# Separate the payload's words with '$IFS$9' instead of a space.
def tamper(payload):
  if settings.TARGET_OS != settings.OS.WINDOWS and len(settings.WHITESPACES) != 0:
    if settings.WHITESPACES[0] == settings.SINGLE_WHITESPACE:
      settings.WHITESPACES[0] = space2ifsraw
    elif space2ifsraw not in settings.WHITESPACES:
      settings.WHITESPACES.append(space2ifsraw)
  return payload

# eof
