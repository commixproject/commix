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
Replaces space character (' ') with the internal field separator ('$IFS').
The internal field separator refers to a variable which defines the character 
or characters used to separate a pattern into tokens for some operations.
Notes:
  * This tamper script works against *nix targets.
"""

script_name = "space2ifs"
print settings.SUB_CONTENT_SIGN + script_name

if settings.TARGET_OS != "win":
  settings.TAMPER_SCRIPTS[script_name] = True
  if settings.WHITESPACE[0] == "%20" or settings.WHITESPACE[0] == " ":
    settings.WHITESPACE[0] = "${IFS}"
  else:
    settings.WHITESPACE.append("${IFS}") 
else:
  warn_msg = "Windows target host(s), does not support the (Bash) $IFS variable."
  print settings.print_warning_msg(warn_msg)

#eof 