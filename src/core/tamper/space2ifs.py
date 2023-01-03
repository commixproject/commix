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
About: Replaces space character ('%20') with the internal field separator ('$IFS').
The internal field separator refers to a variable which defines the character 
or characters used to separate a pattern into tokens for some operations.
Notes: This tamper script works against Unix-like target(s).
"""

__tamper__ = "space2ifs"
space2ifs = "${IFS}"

def tamper(payload):
  if space2ifs in settings.WHITESPACES[0] and \
  settings.EVAL_BASED_STATE != False:
    settings.WHITESPACES[0] = "\${IFS}"
  if settings.TARGET_OS != "win":
    settings.TAMPER_SCRIPTS[__tamper__] = True
    if settings.WHITESPACES[0] == "%20":
      settings.WHITESPACES[0] = space2ifs
    elif space2ifs not in settings.WHITESPACES:
      settings.WHITESPACES.append(space2ifs) 
  else:
    if space2ifs in settings.WHITESPACES:
      settings.WHITESPACES.remove(space2ifs)
  return payload
  
# eof 
