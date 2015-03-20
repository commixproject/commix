#!/usr/bin/env python
# encoding: UTF-8

"""
 This file is part of commix tool.
 Copyright (c) 2014 Anastasios Stasinopoulos (@ancst).
 https://github.com/stasinopoulos/commix

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 For more see the file 'doc/COPYING' for copying permission.
"""

import sys
from src.utils import settings

"""
 Show version number and exit.
"""
def show_version():
  print settings.APPLICATION + " " + settings.VERSION + "\n"
  sys.exit(1)


"""
 Check python version number.
"""
def python_version():
  if settings.PYTHON_VERSION >= "3" or settings.PYTHON_VERSION < "2.6":
    print colors.RED + "(x) Error: Incompatible Python version (" + settings.PYTHON_VERSION + ") detected."
    sys.exit(1)