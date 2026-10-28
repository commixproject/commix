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

import os
import sys
import glob
import importlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.argv = ["commix.py"]

from src.utils import settings

# Every separator a payload can be built on, and the ones awk reads between its own statements.
SEPARATORS = (";", "&", "&&", settings.END_LINE.LF)

"""
Put the globals a tamper script reads into a known state, as a run reaches the exploitation phase
with a command of the user's own and one separator already proved.
"""
def stage(separator, command="echo Hello", target_os=None, rev=False, whitespace=None):
  settings.TARGET_OS = target_os or settings.OS.UNIX
  settings.WHITESPACES = [whitespace or settings.SINGLE_WHITESPACE]
  settings.EXPLOITATION_PHASE = True
  settings.TIME_RELATED_ATTACK = True
  settings.USE_BACKTICKS = False
  settings.USER_APPLIED_CMD = command
  settings.CHECKING_PARAMETER = "P"
  settings.CONFIRMED_BOUNDARY = {"P": ("", "", separator, settings.WHITESPACES[0])}
  settings.TAMPER_SCRIPTS["rev"] = rev
  payload = "AAA" + separator + command + separator
  settings.RAW_PAYLOAD = payload
  return payload

"""
Every tamper script, by the name it is asked for, paired with its imported module.
"""
def tamper_modules():
  modules = {}
  root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
  for script in sorted(glob.glob(os.path.join(root, "src", "tamper", "**", "*.py"), recursive=True)):
    name = os.path.basename(script)[:-len(".py")]
    if name == "__init__":
      continue
    relative = os.path.relpath(script, root)[:-len(".py")].replace(os.sep, ".")
    try:
      modules[name] = importlib.import_module(relative)
    except Exception:
      continue
  return modules

"""
The separators a string carries, counted so that '&&' is not read as two '&'.
"""
def separators_in(text):
  counts, rest = {}, text
  for separator in ("&&", "||"):
    counts[separator] = rest.count(separator)
    rest = rest.replace(separator, "")
  for separator in (";", "&", "|"):
    counts[separator] = rest.count(separator)
  return counts
