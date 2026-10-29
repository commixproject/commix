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

from src.core.parse import cmdline as menu
from src.utils import settings
from src.core.controller import checks


"""
About: Uses backticks (`) instead of '$()' for command substitution in a given payload.
Notes: This tamper script works against target(s) with a POSIX shell.
"""

__tamper__ = "backticks"
__priority__ = settings.PRIORITY.HIGHEST

# Why this script cannot be applied to the target at hand, or nothing where it can.
def dependencies():
  return checks.tamper_dep_unix_only(__tamper__) or checks.tamper_dep_interpreter_incompatible(__tamper__)

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

"""
The substitution this script writes, settled before any payload is built rather than when it first
rewrites one.

Settled then, the choice arrives one payload late: a builder reads it as it builds, so the first
payload of every boundary is written with '$( )' and only the ones after it carry this script at
all. 'tamper()' calls this too, for a target settled as Windows after the script was accepted.
"""
def declare():
  if not menu.options.interpreter and not settings.TARGET_OS == settings.OS.WINDOWS:
    settings.CMD_SUB_PREFIX = settings.CMD_SUB_SUFFIX = settings.BACKTICK_SUBSTITUTION
  elif checks.using_backticks():
    """
    A target settled as Windows, or an interpreter taken on, after this script was accepted.

    'cmd.exe' has no backtick and an interpreter is handed its program rather than a shell line, so
    what was chosen here no longer applies - and left standing it would go on being written into
    every payload built from here on, by a script that has itself stopped rewriting anything.
    """
    settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX = settings.NESTING_SUBSTITUTION

# Substitute the command through backticks rather than through '$()'.
def tamper(payload):
  declare()
  if not menu.options.interpreter and not settings.TARGET_OS == settings.OS.WINDOWS:
    whitespace = checks.current_whitespace()
    payload = payload.replace("${#" + settings.RANDOM_VAR_GENERATOR + "}",
                              settings.CMD_SUB_PREFIX + "expr" + whitespace + "length" + whitespace + "\"$" + settings.RANDOM_VAR_GENERATOR + "\"" + settings.CMD_SUB_SUFFIX
                              )
  return payload

# eof
