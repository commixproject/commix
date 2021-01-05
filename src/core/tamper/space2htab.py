#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2021 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

from src.utils import settings

"""
About: Replaces space character ('%20') with horizontal tab ('%09')
Notes: This tamper script works against all targets.
"""

__tamper__ = "space2htab"

settings.TAMPER_SCRIPTS[__tamper__] = True
if settings.WHITESPACE[0] == "%20":
  settings.WHITESPACE[0] = "%09"
else:
  settings.WHITESPACE.append("%09") 

# eof 