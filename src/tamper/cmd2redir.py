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
About: Rewrites a user-supplied "<command> <path>" as "<command><>path>", for a target that lets no
       whitespace at all through but leaves the redirection operators unfiltered.
Notes: This tamper script works against target(s) with a POSIX shell. '<>' opens the path for both
       reading and writing and attaches it as the command's own stdin, so a command given no
       positional argument at all reads it from there instead - removing the one space between the
       two without needing any whitespace substitute in its place. Only a command that already reads
       stdin when given no filename is any good for this, and the path must be writable by the
       process running it, not just readable, since '<>' opens it for both.
References: [1] https://dojo-yeswehack.com/challenge-of-the-month/Dojo-30
"""

__tamper__ = "cmd2redir"
__priority__ = settings.PRIORITY.HIGHER

# Why this script cannot be applied to the target at hand, or nothing where it can.
def dependencies():
  return checks.tamper_dep_unix_only(__tamper__)

# Commands that read stdin in place of a missing filename argument, across coreutils and BusyBox.
STDIN_FALLBACK_COMMANDS = (
              "cat", "tac", "rev", "sort", "uniq", "wc", "nl",
              "md5sum", "sha1sum", "sha256sum", "sha512sum", "base64", "od", "cksum", "sum"
)

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

# The command's one separating space folded into the redirection operator its argument arrives on.
def rewrite_command(command):
  parts = command.split(settings.SINGLE_WHITESPACE)
  if len(parts) != 2 or parts[0] not in STDIN_FALLBACK_COMMANDS:
    warn_msg = "The '" + __tamper__ + ".py' tamper script needs a single stdin-reading command "
    warn_msg += "(e.g. 'cat') and its one argument in the '" + command + "' command. Skipping tamper script."
    settings.print_once(warn_msg)
    return command
  return parts[0] + "<>" + parts[1]

# Hand the command over with its space folded away, alongside whatever else rewrites it.
def tamper(payload):
  # The exploitation phase reaches here before there is a command of the user's own to rewrite.
  if settings.EXPLOITATION_PHASE and settings.USER_APPLIED_CMD:
    return checks.tamper_rewrite_user_command(payload, __tamper__)
  return payload

# eof
