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
import random
import string
from src.utils import settings

"""
About: Adds (randomly generated) uninitialized bash variables, between the characters of each command in a given payload.
Notes: This tamper script works against Unix-like target(s).
Reference: https://www.secjuice.com/web-application-firewall-waf-evasion/
"""

__tamper__ = "uninitializedvariable"

global obf_char

if not settings.TAMPER_SCRIPTS[__tamper__]:
  num = 2
  obf_char = "${" + ''.join(random.choice(string.ascii_uppercase) for x in range(num)) + "}"
  settings.TAMPER_SCRIPTS[__tamper__] = True

def tamper(payload):
  def add_uninitialized_variable(payload):
    if settings.TAMPER_SCRIPTS["backslashes"] or settings.TAMPER_SCRIPTS["dollaratsigns"]:
      err_msg = "Tamper script '" +  __tamper__  + "' is unlikely to work combined with the tamper scripts: 'backslashes' and/or 'dollaratsigns'."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()
    payload = re.sub(settings.TAMPER_MODIFICATION_LETTERS, lambda x: obf_char + x[0], payload)
    for word in settings.IGNORE_TAMPER_TRANSFORMATION:
      _ = obf_char.join(word[i:i+1] for i in range(-1, len(word), 1))
      if _ in payload:
        payload = payload.replace(_,_.replace(obf_char, ""))
    return payload

  if settings.TARGET_OS != settings.OS.WINDOWS:
    return add_uninitialized_variable(payload)
  else:
    return payload

# eof