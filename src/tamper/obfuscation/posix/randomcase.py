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

from random import choice
from src.utils import settings
from src.core.controller import checks

"""
About: Replaces each character in a user-supplied OS command with a random case.
Notes: This tamper script works against target(s) with a POSIX shell.
       The character ranges are quoted with "'", which is the one quote neither an
       evaluated string nor the shell inside it is already using.
"""

__tamper__ = "randomcase"
__priority__ = settings.PRIORITY.HIGH

# Why this script cannot be applied to the target at hand, or nothing where it can.
def dependencies():
  return checks.tamper_dep_unix_only(__tamper__)

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

"""
Every character's case chosen independently, so two letters - the shortest a real command ever
is - still come out matching the original's case throughout one time in two: a signature over the
literal, unmixed word is still caught as often as it is dodged. Retried until at least one letter
actually differs in case from the rest, the way the result is supposed to read in the first place -
skipped only where there are fewer than two letters to vary at all, since no retry would ever end.
"""
def _mixed_case(cmd):
  if sum(char.isalpha() for char in cmd) < 2:
    return ''.join(choice((str.upper, str.lower))(char) for char in cmd)
  while True:
    candidate = ''.join(choice((str.upper, str.lower))(char) for char in cmd)
    if candidate not in (candidate.lower(), candidate.upper()):
      return candidate

# Vary the case of the payload's letters, where the shell does not care about it.
def tamper(payload):
  # A target settled as Windows after this script was accepted: 'cmd.exe' has no command substitution to lower the case back through.
  if settings.TARGET_OS == settings.OS.WINDOWS:
    return payload
  mixed_case = _mixed_case(settings.USER_APPLIED_CMD)
  # An empty 'USER_APPLIED_CMD' is still "in" any string, so the replace below would otherwise
  # insert the obfuscated-empty-string construct between every character of the payload - a
  # verification litmus built after a finding confirms (and so after exploitation phase starts)
  # has no command of its own to case-randomize at all.
  if settings.EXPLOITATION_PHASE and settings.USER_APPLIED_CMD:
    if settings.TAMPER_SCRIPTS["rev"]:
      if settings.USE_BACKTICKS:
        mixed_case = mixed_case[::-1] + "|rev"
      else:
        mixed_case = "$(echo \"" + mixed_case[::-1] + "\"|rev)"
    source = payload if settings.USER_APPLIED_CMD in payload else settings.RAW_PAYLOAD
    if settings.USER_APPLIED_CMD in source:
      if settings.USE_BACKTICKS:
        random_case_cmd = "\\`echo " + mixed_case + "|tr '[A-Z]' '[a-z]'\\`"
      else:
        random_case_cmd = "$(echo " + mixed_case + "|tr '[A-Z]' '[a-z]')"
      # Applied to the payload as handed over, not to the untouched original: the scripts run in
      # order, and reaching back past the ones before would throw their work away.
      payload = source.replace(settings.USER_APPLIED_CMD, random_case_cmd)
      if len(settings.WHITESPACES) != 0:
        payload = payload.replace(settings.SINGLE_WHITESPACE, settings.WHITESPACES[0])
  return payload

# eof
