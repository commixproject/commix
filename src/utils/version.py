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

import sys
from src.utils import settings
from src.thirdparty.colorama import Fore, Back, Style, init

# """
# Show version number and exit.
# """
def show_version():
  print("\n" + settings.VERSION)
  sys.exit(0)

"""
Check python version number.
"""
def python_version():
  if settings.PYTHON_VERSION >= "3" or settings.PYTHON_VERSION < "2.6":
    err_msg = "Incompatible Python version (" 
    err_msg += settings.PYTHON_VERSION + ") detected. "
    err_msg += "Use Python version 2.6.x or 2.7.x."
    print(settings.print_critical_msg(err_msg))
    sys.exit(0)
