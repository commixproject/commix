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
About: Replaces "sleep" with "usleep" command in a given payload.
Notes: This tamper script works against target(s) with a POSIX shell.
Reference: http://man7.org/linux/man-pages/man3/usleep.3.html
"""

__tamper__ = "sleep2usleep"
__priority__ = settings.PRIORITY.NORMAL

# Why this script cannot be applied to the target at hand, or nothing where it can.
def dependencies():
  return checks.tamper_dep_time_related_only(__tamper__) or checks.tamper_dep_unix_only(__tamper__)

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

# Wait with 'usleep' where the payload waited with 'sleep'.
def tamper(payload):
  # The rewrite itself, the delay restated in microseconds.
  def sleep_to_usleep(payload):
    whitespace = settings.WHITESPACES[0]
    # Arithmetic-gated delay ("sleep $((5*(cond)))") - scale its leading factor to microseconds.
    payload = re.sub(r"sleep" + re.escape(whitespace) + r"\$\(\((\d+)\*",
                     lambda x: "usleep" + whitespace + "$((" + x.group(1) + "000000*", payload)
    for match in re.finditer(r"sleep" + re.escape(whitespace) + r"([1-9]\d+|[0-9])", payload):
      sleep_to_usleep = "u" + match.group(0).split(settings.WHITESPACES[0])[0]
      if match.group(0).split(settings.WHITESPACES[0])[1] != "0":
        usleep_delay = match.group(0).split(settings.WHITESPACES[0])[1] + "0" * 6
      else:
        usleep_delay = match.group(0).split(settings.WHITESPACES[0])[1]
      payload = payload.replace(match.group(0), sleep_to_usleep + settings.WHITESPACES[0] + usleep_delay)
    return payload
  if settings.TARGET_OS != settings.OS.WINDOWS and settings.TIME_RELATED_ATTACK:
    return sleep_to_usleep(payload)
  return payload

# eof
