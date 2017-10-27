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

# Dummy check for missing module(s).
try:
  __import__("src.utils.version")
  from src.utils import version
  version.python_version()
except ImportError:
  err_msg = "Wrong installation detected (missing modules). "
  err_msg = "Visit 'https://github.com/commixproject/commix/' for further details. \n"
  print(settings.print_critical_msg(err_msg))
  sys.exit(0)

if __name__ == '__main__':
  import src.core.main

#eof