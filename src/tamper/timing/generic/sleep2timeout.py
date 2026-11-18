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
About: Replaces 'sleep' with 'timeout' command in a given payload.
  * Regarding Unix-like target(s), it replaces the 'sleep XX' command with 'timeout XX ping localhost'.
  * Regarding windows target(s), it replaces the 'powershell.exe -InputFormat none Start-Sleep -s XX' command with 'timeout XX'.
Notes: This tamper script works against all targets.
"""

__tamper__ = "sleep2timeout"
__priority__ = settings.PRIORITY.NORMAL

# Why this script cannot be applied to the target at hand, or nothing where it can.
def dependencies():
  return checks.tamper_dep_time_related_only(__tamper__)

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

# Wait with 'timeout' or 'ping' where the payload waited with 'sleep'.
def tamper(payload):
  # The rewrite itself, keeping the delay the payload asked for.
  def sleep_to_timeout_ping(payload):
    whitespace = checks.current_whitespace()
    # Matched however the gap is spelled where this reads it, and written with the run's own.
    gap = checks.tamper_blank_pattern()
    if settings.TARGET_OS != settings.OS.WINDOWS:
      payload = re.sub(r"sleep" + gap + r"(\$\(\(\d+\*\([^()]*\)\)\))",
                       lambda x: "timeout" + whitespace + x.group(1) + ".01" + whitespace + "ping" + whitespace + "localhost", payload)
      for match in re.finditer(r"sleep" + gap + r"([1-9]\d+|[0-9])", payload):
        # A delay of none has nothing to wait for, so nothing is given to wait on either.
        written = ("timeout" + whitespace + "0" if match.group(1) == "0" else
                   "timeout" + whitespace + match.group(1) + whitespace + "ping" + whitespace + "localhost")
        payload = payload.replace(match.group(0), written)
    else:
      payload = re.sub(r"powershell\.exe" + gap + r"-InputFormat" + gap + r"none" + gap + r"Start-Sleep" + gap + r"-s",
                       "timeout", payload)
    return payload
  if not settings.TIME_RELATED_ATTACK:
    return payload
  return sleep_to_timeout_ping(payload)

# eof
