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
Show version number and exit.
"""
def show_version():
  print(settings.VERSION)
  raise SystemExit()

"""
Check python version number.
"""
def python_version():
  PYTHON_VERSION = sys.version.split()[0]
  if PYTHON_VERSION >= "3" or PYTHON_VERSION < "2.7":
    warn_msg = "Python version " 
    warn_msg += PYTHON_VERSION + " detected. "
    warn_msg += "You are advised to use Python version 2.7.x."
    print("\n" + settings.print_bold_warning_msg(warn_msg))
    #raise SystemExit()
