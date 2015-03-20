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

import os
import sys
import time

from src.utils import colors
from src.utils import settings
from src.utils import requirments

"""
 Check for updates (apply if any) and exit!
"""

def updater():
  	
  definepath = os.getcwd()
  time.sleep(1)
  
  # Check if git is installed
  requirment = "git"
  requirments.do_check(requirment)
  
  sys.stdout.write("(*) Updating "+ settings.APPLICATION + " (via Gihub) ... ")
  sys.stdout.flush()
  
  # Check if ".git" exists!
  if os.path.isfile("./.git"):
 
    sys.stdout.write("["+colors.GREEN+" OK "+ colors.RESET+"]\n")
    sys.stdout.flush()
    print "\n------"
    update = subprocess.Popen("git pull", shell=True).wait()
    print "------\n"
      
  else:
    print "["+ colors.RED + " FAILED " + colors.RESET +"]"
    print "(x) Download the latest version from: "
    print " --> https://github.com/stasinopoulos/"+ settings.APPLICATION +"/archive/master.zip\n"
    
  sys.exit(1)