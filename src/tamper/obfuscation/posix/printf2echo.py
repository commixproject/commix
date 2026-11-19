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
About: Prints with `echo` wherever a payload prints with `printf`, and reads a byte with `echo -n
       $char | od -An -tuC | xargs` instead of `printf '%d' "'$char"`.
Notes: This tamper script works against target(s) with a POSIX shell.
       It is for a target that refuses 'printf' by name. 'echo' is what every payload prints with
       here, so none of them carries the other name - at a cost: 'echo' reads the backslashes of
       what it prints as escapes on some shells ('dash' among them) and a leading '-n' as an option
       on all of them, so an output carrying either may come back changed.
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

# Every payload built from here on prints with 'echo' - said while the scripts are settled, since the
# builders read it as they build rather than having the result rewritten afterwards.
def declare():
  settings.PRINT_WITH_ECHO = True
  # An ordinal is what 'printf' reads, so without it a byte is compared as the character it is - and
  # only a printable one can be written into a comparison as itself.
  settings.print_once("The '" + __tamper__ + ".py' tamper script compares a byte against characters, "
                      "not ordinals, so one outside the printable range is left unread, as is a '" + "-" +
                      "' kept out of the payloads, or a '^' on a pipe.")

# Say with 'echo' what the payload said with 'printf'.
def tamper(payload):
  declare()
  # A target settled as Windows after this script was accepted: 'cmd.exe' has no 'od' to read with.
  if settings.TARGET_OS == settings.OS.WINDOWS:
    return payload
  # The byte is handed to 'od' down a pipe, so this rewrite is written where a pipe is what is
  # proving; on every other boundary the reading names the character instead, which the builders
  # write themselves once this script has declared the printer - see checks.byte_collation().
  if checks.current_separator() not in ("|", "||"):
    return payload
  space = checks.current_whitespace()
  prefix, suffix = checks.byte_ordinal_bounds()
  # Those two are spelled with spaces, and a payload reaching a script is not: whatever stands for a
  # gap this run went in before anything here was asked to find it.
  opening, closing = re.compile(checks.blank_tolerant(prefix)), re.compile(checks.blank_tolerant(suffix))
  # The reading is taken whole - from the text written around it rather than by looking for a
  # closing bracket, which the byte's own expression carries plenty of.
  while True:
    found = opening.search(payload)
    if not found:
      break
    ends = closing.search(payload, found.end())
    if not ends:
      break
    opened, closed = found.start(), ends.start()
    byte = payload[found.end():closed]
    counted = (settings.CMD_SUB_PREFIX + "echo" + space + "-n" + space + "\"" + byte + "\"" + space +
               "|" + space + "od" + space + "-An" + space + "-tuC" + space + "|" + space + "xargs" +
               settings.CMD_SUB_SUFFIX)
    payload = payload[:opened] + counted + payload[ends.end():]
  return payload

# eof
