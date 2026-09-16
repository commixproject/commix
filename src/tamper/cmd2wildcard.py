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
About: Replaces the paths in the user-supplied operating system command with wildcards (/[b]in/[c]at).
Notes: This tamper script works against target(s) with a POSIX shell. Only a path the command reads
       is hidden, and only where it is written out in full - a bare command name is found on the
       PATH rather than by the filesystem, and a wildcard is not looked up there.
References: [1] https://www.secjuice.com/web-application-firewall-waf-evasion/
"""

__tamper__ = "cmd2wildcard"
__priority__ = settings.PRIORITY.HIGHER

# Why this script cannot be applied to the target at hand, or nothing where it can.
def dependencies():
  return checks.tamper_dep_unix_only(__tamper__)

# An absolute path written out in full, which is the only thing here a wildcard can stand in for.
WILDCARD_PATH = r"/[^\s/|;&<>()`'\"]+(?:/[^\s/|;&<>()`'\"]+)*"

# What a path already carrying a wildcard of its own is left alone for.
WILDCARD_ALREADY = r"[*?\[\]]"

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

def _wildcard_path(match):
  """
  One path with a bracket around the first character of each of its parts, or left as it was.

  A bracket rather than a '?', because the shell has to arrive back at the one file that was
  named: '/bin/c?t' is 'cat' and 'cut' both on a target that carries the two, and what the glob
  hands over then is a command with the other one as its argument. '/[c]at' can only ever be
  'cat', and a signature written against the path still does not see it.
  """
  path = match.group(0)
  if re.search(WILDCARD_ALREADY, path):
    return path
  parts = path.split("/")
  return "/".join(part if not part[:1].isalnum() else "[" + part[0] + "]" + part[1:] for part in parts)

# The command with its paths spelled as globs, for the target to match back to the file.
def rewrite_command(command):
  wildcard_cmd = re.sub(WILDCARD_PATH, _wildcard_path, command)
  # A command naming no path of its own has nothing here that a glob could stand in for, and
  # saying so once is worth more than leaving the script looking like it did something.
  if wildcard_cmd == command:
    warn_msg = "The '" + __tamper__ + ".py' tamper script found no path to hide in the '"
    warn_msg += command + "' command. Skipping tamper script."
    settings.print_once(warn_msg)
  return wildcard_cmd

# Hand the command over with its paths spelled as globs, alongside whatever else rewrites it.
def tamper(payload):
  # The exploitation phase reaches here before there is a command of the user's own to rewrite.
  if settings.EXPLOITATION_PHASE and settings.USER_APPLIED_CMD:
    return checks.tamper_rewrite_user_command(payload, __tamper__)
  return payload

# eof
