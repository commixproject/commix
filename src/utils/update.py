#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of commix (@commixproject) tool.
Copyright (c) 2014-2016 Anastasios Stasinopoulos (@ancst).
https://github.com/stasinopoulos/commix

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

import os
import sys
import time
import subprocess

from src.utils import settings
from src.utils import requirments
from src.thirdparty.colorama import Fore, Back, Style, init

"""
Check for updates (apply if any) and exit!
"""

"""
The commix's updater.
"""
def updater():
  
  time.sleep(1)
  info_msg = "Checking requirements to update " 
  info_msg += settings.APPLICATION + " via GitHub... "
  sys.stdout.write(settings.print_info_msg(info_msg))
  sys.stdout.flush()
  # Check if windows
  if settings.IS_WINDOWS:
    print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
    err_msg = "For updating purposes on Windows platform, it's recommended "
    err_msg += "to use a GitHub client for Windows (http://windows.github.com/)."
    print settings.print_error_msg(err_msg)
    sys.exit(0)
  else:
    try:
      requirment = "git"
      # Check if 'git' is installed.
      requirments.do_check(requirment)
      if requirments.do_check(requirment) == True :
        # Check if ".git" exists!
        if os.path.isdir("./.git"):
          sys.stdout.write("[" + Fore.GREEN + " SUCCEED " + Style.RESET_ALL + "]\n")
          sys.stdout.flush()
          start = 0
          end = 0
          start = time.time()
          print "---"
          subprocess.Popen("git reset --hard HEAD && git pull", shell=True).wait()
          # Delete *.pyc files.
          subprocess.Popen("find . -name \"*.pyc\" -delete", shell=True).wait()
          # Delete empty directories and files.
          subprocess.Popen("find . -empty -type d -delete", shell=True).wait()
          print "---"
          end  = time.time()
          how_long = int(end - start)
          info_msg = "Finished in " + time.strftime('%H:%M:%S', time.gmtime(how_long)) + "."
          print settings.print_info_msg(info_msg)
        else:
          print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
          err_msg = "The '.git' directory not found. Do it manually: " 
          err_msg += Style.BRIGHT + "'git clone " + settings.GIT_URL 
          err_msg += " " + settings.APPLICATION + "' "
          print settings.print_error_msg(err_msg)    
          sys.exit(0)
      else:
          print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
          err_msg = requirment + " not found."
          print settings.print_error_msg(err_msg)
          sys.exit(0)

    except Exception as err_msg:
      print "\n" + settings.print_error_msg(err_msg)
    sys.exit(0)
