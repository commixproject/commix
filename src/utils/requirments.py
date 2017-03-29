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
import os
import subprocess

"""
Check for requirments.
"""
def do_check(requirment):
  try:
    # Pipe output to the file path of the null device, for silence. 
    # i.e '/dev/null' for POSIX, 'nul' for Windows
    null = open(os.devnull,"w")
    subprocess.Popen(requirment, stdout=null, stderr=null)
    null.close()
    return True

  except OSError:
    return False
    
# eof