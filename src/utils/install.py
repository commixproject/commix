#!/usr/bin/env python
# encoding: UTF-8

"""
 This file is part of commix tool.
 Copyright (c) 2015 Anastasios Stasinopoulos (@ancst).
 https://github.com/stasinopoulos/commix

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 For more see the file 'doc/COPYING' for copying permission.
"""

import os
import sys
import platform
import subprocess

from src.utils import menu
from src.utils import colors
from src.utils import settings
from src.utils import requirments

"""
 Make a local installation of 'commix' on your system.
"""

def installer():
  packages = "build-essential python-dev"
  dependencies = "git python-pip"
  
  sys.stdout.write("(*) Starting installer ... ")
  sys.stdout.flush()
  
  # Check if OS is Linux.
  if platform.system() == "Linux":
    
    # You need to have root privileges to run this script
    if os.geteuid() != 0:
      print colors.RED + "\n(x) Error:  You need to have root privileges to run this option.\n" + colors.RESET
      sys.exit(0)
      
    # Check if commix is already installed.
    if os.path.isdir("/usr/share/"  + settings.APPLICATION + ""):
      print "[" + colors.RED + " FAILED " + colors.RESET + "]" 
      print colors.RED + "(x) Error: "  + settings.APPLICATION + " is already installed in /usr/share/"  + settings.APPLICATION + ", remove and start again." + colors.RESET
      print ""
      sys.exit(0)
      
    # Check for git.
    if not os.path.isfile("/usr/bin/git") or not os.path.isfile("/usr/bin/pip"):
      # Install requirment.
      if os.path.isfile("/etc/apt/sources.list"):
	sys.stdout.write("[" + colors.GREEN + " DONE " + colors.RESET + "]\n")
	sys.stdout.flush()
	# Check for dependencies.
	dependencies_items = dependencies.split()
	for item in dependencies_items:
	  requirments.do_check(item)
      else:
	print "[" + colors.RED + " FAILED " + colors.RESET + "]"
	print colors.RED + "(x) Error: The installer is not designed for any other Linux distro than Ubuntu / Debian." + colors.RESET
	print colors.RED + "    Please install manually: " + dependencies + colors.RESET
	print ""
	sys.exit(0)
	
    # Force install of necessary packages
    subprocess.Popen("apt-get --force-yes -y install " + packages + ">/dev/null 2>&1", shell=True).wait()
    sys.stdout.write("[" + colors.GREEN + " DONE " + colors.RESET + "]\n")
    sys.stdout.flush()
    
    sys.stdout.write("(*) Installing "  + settings.APPLICATION + " into the /usr/share/"  + settings.APPLICATION + " ... ")
    try:
      current_dir = os.getcwd()
      subprocess.Popen("cp -r " + current_dir + " /usr/share/" + settings.APPLICATION + " >/dev/null 2>&1", shell=True).wait()
      subprocess.Popen("chmod 775 /usr/share/"  + settings.APPLICATION + "/" + settings.APPLICATION + ".py >/dev/null 2>&1", shell=True).wait()
    except:
      print "[" + colors.RED + " FAILED " + colors.RESET + "]"
      sys.exit(0)
    sys.stdout.write("[" + colors.GREEN + " DONE " + colors.RESET + "]\n")
    sys.stdout.flush()
    
    sys.stdout.write("(*) Installing "  + settings.APPLICATION + " to /usr/bin/"  + settings.APPLICATION + " ... ")
    try:    
      with open('/usr/bin/commix', 'w') as f:
	f.write('#!/bin/bash\n')
	f.write('cd /usr/share/commix/ && ./commix.py "$@"')
	subprocess.Popen("chmod +x /usr/bin/"  + settings.APPLICATION + " >/dev/null 2>&1", shell=True).wait()
    except:
      print "[" + colors.RED + " FAILED " + colors.RESET + "]"
      sys.exit(0)
    sys.stdout.write("[" + colors.GREEN + " DONE " + colors.RESET + "]\n")
    sys.stdout.flush()
    
    print colors.BOLD + "(!) The installation is finished! Type '"  + settings.APPLICATION + "' to launch it." + colors.RESET

  else :
    print "[" + colors.RED + " FAILED " + colors.RESET + "]"
    print colors.RED + "(x) Error: The installer is not designed for any other system other than Linux." + colors.RESET
    print colors.RED + "    Please install manually: " + packages + dependencies + colors.RESET
    print ""
    sys.exit(0)

  #eof
