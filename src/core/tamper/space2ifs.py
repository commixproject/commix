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

import sys
from src.utils import settings

"""
About: Replaces space character ('%20') with the internal field separator ('$IFS').
The internal field separator refers to a variable which defines the character 
or characters used to separate a pattern into tokens for some operations.
Notes: This tamper script works against *nix targets.
"""

__tamper__ = "space2ifs"

if settings.TARGET_OS != "win":
  settings.TAMPER_SCRIPTS[__tamper__] = True
  if settings.WHITESPACE[0] == "%20":
    settings.WHITESPACE[0] = "${IFS}"
  else:
    settings.WHITESPACE.append("${IFS}") 
else:
  warn_msg = "Windows target host(s), does not support the '"+ __tamper__  +".py' tamper script."
  sys.stdout.write("\r" + settings.print_warning_msg(warn_msg))
  sys.stdout.flush() 
  print
  
# eof 