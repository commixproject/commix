#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2023 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

from src.utils import settings

"""
About: Replaces space character ('%20') with plus ('+').
Notes: This tamper script works against all targets.
"""

__tamper__ = "space2plus"
space2plus = "+"

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

def tamper(payload):
  settings.TAMPER_SCRIPTS[__tamper__] = True
  if settings.WHITESPACES[0] == "%20":
    settings.WHITESPACES[0] = space2plus
  elif space2plus not in settings.WHITESPACES:
    settings.WHITESPACES.append(space2plus) 
  return payload 
  
# eof 