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
About: Replaces every occurrence of the payload's own whitespace with one drawn independently from
       a small set of equivalents, rather than the one substitute every other space2* script settles
       on for the whole payload.
Notes: This tamper script works against target(s) with a POSIX shell.
       'if'/'then'/'fi' and friends are recognised before '${IFS}' expands, so 'if${IFS}' is never
       read back as the keyword - a tab goes next to those instead. '$IFS$9' merges with a digit
       right after it into one (empty) parameter, so it is skipped there too. Picked once per call
       rather than once per occurrence, since a choice that breaks here would otherwise pass
       boolean-based verification's first check and fail its second, or the other way round.
"""

__tamper__ = "space2randomblank"
__priority__ = settings.PRIORITY.LOWER

_BLANKS = ("\t", "${IFS}", "$IFS$9")
_KEYWORDS = ("if", "then", "elif", "else", "fi", "for", "while", "until", "do", "done", "case", "esac", "in")

# Why this script cannot be applied to the target at hand, or nothing where it can.
def dependencies():
  return checks.tamper_dep_unix_only(__tamper__)

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

# Rules out whichever choices would misparse here, and picks randomly among what is left.
def _blank_for(part, start, end):
  before = re.search(r"(\w+)\Z", part[:start])
  after = re.match(r"\A(\w+)", part[end:])
  choices = _BLANKS
  if (before and before.group(1) in _KEYWORDS) or (after and after.group(1) in _KEYWORDS):
    choices = ("\t",)
  elif after and after.group(1)[:1].isdigit():
    choices = tuple(blank for blank in choices if blank != "$IFS$9")
  return random.choice(choices)

# Every occurrence of the current separator, each replaced with its own independent pick - so a
# signature over one consistent telltale substitute never sees the same one twice in a row.
def tamper(payload):
  if len(settings.WHITESPACES) == 0:
    return payload
  current = settings.WHITESPACES[0]
  if not current:
    return payload
  pattern = re.escape(current)
  def _replace(part):
    return re.sub(pattern, lambda match: _blank_for(part, match.start(), match.end()), part)
  return checks.tamper_outside_single_quotes(payload, _replace)

# eof
