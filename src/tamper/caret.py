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
from src.utils import settings
from src.core.controller import checks

"""
About: Adds caret symbol (^) between the characters in a given payload.
Notes: This tamper script works against windows targets.
"""

__tamper__ = "caret"
__priority__ = settings.PRIORITY.LOW

# Why this script cannot be applied to the target at hand, or nothing where it can.
def dependencies():
  return checks.tamper_dep_windows_only(__tamper__)

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

# Put a caret between the characters, which cmd.exe reads straight through.
def tamper(payload):
  # The carets themselves, kept out of the quoted words that must survive whole.
  def add_caret_symbol(payload):
    words = re.findall(r"\w+", payload)
    if words:
      longest_word = max(words, key=len)
      long_string = longest_word if len(longest_word) >= 5000 else ""
      rep = {
              "^^": "^",
              '"^t""^o""^k""^e""^n""^s"': '"t"^"o"^"k"^"e"^"n"^"s"',
              # "tokens" always appears quoted (e.g. "tokens=*") in this project's own for/f payloads -
              # the leading quote must be consumed here too, or it leaks through as a stray "".
              '"^t^o^k^e^n^s': '"t"^"o"^"k"^"e"^"n"^"s"',
              '^t^o^k^e^n^s': '"t"^"o"^"k"^"e"^"n"^"s"',
            }
      if long_string:
        rep[re.sub(settings.TAMPER_MODIFICATION_LETTERS, r'^\1', long_string)] = long_string.replace("^", "")
      payload = checks.tamper_modify_letters_outside_quotes(payload, r'^\1')
      rep = dict((re.escape(k), v) for k, v in rep.items())
      pattern = re.compile("|".join(rep.keys()))
      payload = pattern.sub(lambda m: rep[re.escape(m.group(0))], payload)
    return payload
  if settings.TARGET_OS == settings.OS.WINDOWS:
    return add_caret_symbol(payload)
  else:
    return payload

# eof
