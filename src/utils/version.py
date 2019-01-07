#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2019 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

import sys

"""
Show version number and exit.
"""
def show_version():
  from src.utils import settings
  print(settings.VERSION)
  raise SystemExit()

"""
Check python version number.
"""
def python_version():
  PYTHON_VERSION = sys.version.split()[0]
  if PYTHON_VERSION >= "3" or PYTHON_VERSION < "2.6":
    err_msg = "[x] Critical: Incompatible Python version (" 
    err_msg += PYTHON_VERSION + ") detected. "
    err_msg += "Use Python version 2.6.x or 2.7.x.\n"
    print(err_msg)
    raise SystemExit()
