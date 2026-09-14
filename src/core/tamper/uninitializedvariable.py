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
import string
from src.utils import settings
from src.core.injections.controller import checks

"""
About: Adds (randomly generated) uninitialized bash variables between the characters of each command in a given payload.
Notes: This tamper script works against target(s) with a POSIX shell.
Reference: https://www.secjuice.com/web-application-firewall-waf-evasion/
"""

__tamper__ = "uninitializedvariable"
__priority__ = settings.PRIORITY.LOW

def dependencies():
  return checks.tamper_dep_eval_incompatible(__tamper__) or checks.tamper_dep_unix_only(__tamper__)

if not settings.TAMPER_SCRIPTS[__tamper__]:
  num = 2
  obf_char = "${" + ''.join(random.choice(string.ascii_uppercase) for _ in range(num)) + "}"
  settings.TAMPER_SCRIPTS[__tamper__] = True


def tamper(payload):
  def add_uninitialized_variable(payload):
    def obfuscate(text):
      # Split into parts: already obfuscated (${XX}) and plain
      parts = re.split(r'(\$\{[A-Z]+\})', text)
      for i in range(len(parts)):
        if not re.match(r'\$\{[A-Z]+\}', parts[i]):
          parts[i] = re.sub(
            settings.TAMPER_MODIFICATION_LETTERS,
            lambda x: obf_char + x.group(0),
            parts[i]
          )
      return ''.join(parts)

    payload = checks.tamper_outside_single_quotes(payload, obfuscate)
    return checks.tamper_restore_ignored_words(payload, obf_char)

  # Only apply on non-Windows targets
  if settings.TARGET_OS != settings.OS.WINDOWS:
    return add_uninitialized_variable(payload)
  else:
    return payload

