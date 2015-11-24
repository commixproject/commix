#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of commix (@commixproject) tool.
Copyright (c) 2014 Anastasios Stasinopoulos (@ancst).
https://github.com/stasinopoulos/commix

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'doc/COPYING' for copying permission.
"""

import subprocess

"""
Check for requirments.
"""
def do_check(requirment):
  try:
    # pipe output to /dev/null for silence
    null = open("/dev/null", "w")
    subprocess.Popen(requirment, stdout=null, stderr=null)
    null.close()
    return True

  except OSError:
    return False
    
# eof