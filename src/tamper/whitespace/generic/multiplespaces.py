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

import random
from src.utils import settings

"""
About: Adds multiple spaces around operating system commands in a given payload.
Notes: Useful to bypass very weak and bespoke web application firewalls that has poorly written permissive regular expressions.
"""

__tamper__ = "multiplespaces"
__priority__ = settings.PRIORITY.LOWER

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

# What each whitespace was before this script first multiplied it. Kept because the list is shared
# and this runs once per payload: multiplying what was already multiplied compounds, and by the
# eighth payload the substitute is millions of characters long rather than a handful.
_pristine = {}

# Pad the payload's own spaces out into runs of them.
def tamper(payload):
  for index, whitespace in enumerate(settings.WHITESPACES):
    base = _pristine.setdefault(index, whitespace)
    # A list rebuilt for another target, or one another script has changed, replaces what was kept.
    if not whitespace.startswith(base):
      base = _pristine[index] = whitespace
    settings.WHITESPACES[index] = base * random.randrange(3, 8)
  return payload

# eof
