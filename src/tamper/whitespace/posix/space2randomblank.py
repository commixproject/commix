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

import re
import random
from src.utils import settings
from src.core.controller import checks

"""
About: Replaces every occurrence of the payload's own whitespace with one drawn independently from a
       small set of equivalents, rather than the one substitute every other space2* script settles
       on for the whole payload.
Notes: This tamper script works against target(s) with a POSIX shell.
       Where one of the two expansions would not be read as the gap it stands for - beside a
       keyword, after a command's own assignments, or, for '$IFS$9', in front of a digit - the tab
       goes in instead, 'tamper_blank_allowed' being what settles which. A whitespace inside a
       double-quoted literal is left alone altogether: there it is a character of the string rather
       than the gap between two words, and none of these equivalents is that same one character.
"""

__tamper__ = "space2randomblank"
__priority__ = settings.PRIORITY.LOWER

_BLANKS = (checks.TAMPER_PARSED_BLANK, "${IFS}", "$IFS$9")

# Why this script cannot be applied to the target at hand, or nothing where it can.
def dependencies():
  return checks.tamper_dep_unix_only(__tamper__)

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

# Rules out whichever choices would misparse here, and picks randomly among what is left. Where
# that is none of them the tab goes in, which 'tamper_blank_allowed' never rules out.
def _blank_for(part, start, end):
  choices = tuple(blank for blank in _BLANKS if checks.tamper_blank_allowed(blank, part, start, end))
  return random.choice(choices or (checks.TAMPER_PARSED_BLANK,))

# Every occurrence of the current separator, each replaced with its own independent pick - so a
# signature over one consistent telltale substitute never sees the same one twice in a row.
def tamper(payload):
  # A target settled as Windows after this script was accepted: the blanks this draws from are not all separators to 'cmd.exe'.
  if settings.TARGET_OS == settings.OS.WINDOWS:
    return payload
  if len(settings.WHITESPACES) == 0:
    return payload
  current = settings.WHITESPACES[0]
  if not current:
    return payload
  pattern = re.escape(current)
  def _replace(part):
    return re.sub(pattern, lambda match: _blank_for(part, match.start(), match.end()), part)
  return checks.tamper_outside_quoted_text(payload, _replace)

# eof
