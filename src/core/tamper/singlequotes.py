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

import re
from src.utils import settings

"""
About: Adds single quotes (') between the characters in a given payload.
Notes: This tamper script works against Unix-like target(s).
"""

__tamper__ = "singlequotes"

global obf_char

if not settings.TAMPER_SCRIPTS[__tamper__]:
  obf_char = "''"
  settings.TAMPER_SCRIPTS[__tamper__] = True

def tamper(payload):
  def add_single_quotes(payload): 
    payload = re.sub(settings.TAMPER_MODIFICATION_LETTERS, lambda x: obf_char + x[0], payload)
    for word in settings.IGNORE_TAMPER_TRANSFORMATION:
      _ = obf_char.join(word[i:i+1] for i in range(-1, len(word), 1))
      if _ in payload:
        payload = payload.replace(_,_.replace(obf_char, ""))
    return payload
  if settings.TARGET_OS != settings.OS.WINDOWS:
    return add_single_quotes(payload)
  else:
    return payload

# eof