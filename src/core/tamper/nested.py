#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2025 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

import sys
import random
from src.utils import menu
from src.utils import settings

"""
About: Adds double quotes around of the generated payloads (nested).
Notes: This tamper script works against Unix-like target(s).
"""

__tamper__ = "nested"

def nested():
  if menu.options.prefix:
    menu.options.prefix = "\"" + menu.options.prefix 
  else:
    menu.options.prefix = "\""
  if menu.options.suffix: 
    menu.options.suffix = menu.options.suffix + "\""
  else:
    menu.options.suffix = "\""

if not settings.TAMPER_SCRIPTS[__tamper__]:
  if settings.TARGET_OS != settings.OS.WINDOWS:
    settings.TAMPER_SCRIPTS[__tamper__] = True
    nested()

def tamper(payload):
  return payload

# eof