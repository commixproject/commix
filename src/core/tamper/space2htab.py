#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (http://commixproject.com).
Copyright (c) 2014-2017 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

from src.utils import settings

"""
Replaces space character (' ') with horizontal tab ('%09')
Notes:
  * This tamper script works against all targets.
"""

script_name = "space2htab"
print settings.SUB_CONTENT_SIGN + script_name

settings.TAMPER_SCRIPTS[script_name] = True
if settings.WHITESPACE[0] == "%20" or settings.WHITESPACE[0] == " ":
  settings.WHITESPACE[0] = "%09"
else:
  settings.WHITESPACE.append("%09") 

#eof 