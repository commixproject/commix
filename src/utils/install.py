#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of commix (@commixproject) tool.
Copyright (c) 2014-2015 Anastasios Stasinopoulos (@ancst).
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

from src.utils import settings
from src.utils import requirments
from src.thirdparty.colorama import Fore, Back, Style, init

"""
Make a local installation of 'commix' on your system.
"""

"""
The un-installer.
"""
def uninstaller():
  sys.stdout.write("(*) Starting the uninstaller... ")
  sys.stdout.flush()
  try:
		subprocess.Popen("rm -rf /usr/bin/" + settings.APPLICATION + " >/dev/null 2>&1", shell=True).wait()
		subprocess.Popen("rm -rf /usr/share/" + settings.APPLICATION + " >/dev/null 2>&1", shell=True).wait()
  except:
    print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
    sys.exit(0)
  sys.stdout.write("[" + Fore.GREEN + " SUCCEED " + Style.RESET_ALL + "]\n")
  sys.stdout.flush()
  print Style.BRIGHT + "(!) The un-installation of commix has finished!" + Style.RESET_ALL
  
"""
The installer.
"""
def installer():
  packages = "build-essential python-dev"
  dependencies = "git python-pip"
  
  sys.stdout.write("(*) Starting the installer... ")
  sys.stdout.flush()
  
  # Check if OS is Linux.
  if platform.system() == "Linux":
    
    # You need to have root privileges to run this script
    if os.geteuid() != 0:
      print Back.RED + "\n(x) Error: You need to have root privileges to run this option!\n" + Style.RESET_ALL
      sys.exit(0)
      
    # Check if commix is already installed.
    if os.path.isdir("/usr/share/"  + settings.APPLICATION + ""):
      print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]" 
      print Fore.YELLOW + "(^) Warning: It seems that "  + settings.APPLICATION + " is already installed in your system." + Style.RESET_ALL
      while True:
        uninstall = raw_input("(?) Do you want to remove commix? [Y/n/q] > ").lower()
        if uninstall in settings.CHOISE_YES:
          uninstaller()
          sys.exit(0)
        elif uninstall in settings.CHOISE_NO or \
        uninstall in settings.CHOISE_QUIT: 
          sys.exit(0)
        else:
          if uninstall == "":
            uninstall = "enter"
          print Back.RED + "(x) Error: '" + uninstall + "' is not a valid answer." + Style.RESET_ALL
          pass
      
    # Check for git.
    if not os.path.isfile("/usr/bin/git") or not os.path.isfile("/usr/bin/pip"):
      # Install requirement.
      if os.path.isfile("/etc/apt/sources.list"):
        sys.stdout.write("[" + Fore.GREEN + " SUCCEED " + Style.RESET_ALL + "]\n")
        sys.stdout.flush()
        # Check for dependencies.
        dependencies_items = dependencies.split()
        for item in dependencies_items:
          requirments.do_check(item)
      else:
        print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
        print Back.RED + "(x) Error: The installer is not designed for any other Linux distro than Ubuntu / Debian." + Style.RESET_ALL
        print Back.RED + "    Please install manually: " + dependencies + Style.RESET_ALL
        print ""
        sys.exit(0)
        
    # Force install of necessary packages
    subprocess.Popen("apt-get --force-yes -y install " + packages + ">/dev/null 2>&1", shell=True).wait()
    sys.stdout.write("[" + Fore.GREEN + " SUCCEED " + Style.RESET_ALL + "]\n")
    sys.stdout.flush()
    
    sys.stdout.write("(*) Installing "  + settings.APPLICATION + " into the /usr/share/"  + settings.APPLICATION + "... ")
    try:
      current_dir = os.getcwd()
      subprocess.Popen("cp -r " + current_dir + " /usr/share/" + settings.APPLICATION + " >/dev/null 2>&1", shell=True).wait()
      subprocess.Popen("chmod 775 /usr/share/"  + settings.APPLICATION + "/" + settings.APPLICATION + ".py >/dev/null 2>&1", shell=True).wait()
    except:
      print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
      sys.exit(0)
    sys.stdout.write("[" + Fore.GREEN + " SUCCEED " + Style.RESET_ALL + "]\n")
    sys.stdout.flush()
    
    sys.stdout.write("(*) Installing "  + settings.APPLICATION + " to /usr/bin/"  + settings.APPLICATION + "... ")
    try:    
      with open("/usr/bin/" + settings.APPLICATION, 'w') as f:
        f.write('#!/bin/bash\n')
        f.write('cd /usr/share/commix/ && ./commix.py "$@"\n')
        subprocess.Popen("chmod +x /usr/bin/"  + settings.APPLICATION + " >/dev/null 2>&1", shell=True).wait()
    except:
      print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
      sys.exit(0)
    sys.stdout.write("[" + Fore.GREEN + " SUCCEED " + Style.RESET_ALL + "]\n")
    sys.stdout.flush()
    
    #Create the Output Directory
    OUTPUT_DIR = ".output/"
    try:
        os.stat(OUTPUT_DIR)
    except:
        os.mkdir(OUTPUT_DIR)  
    
    print Style.BRIGHT + "(!) The installation is finished! Type '"  + settings.APPLICATION + "' to launch it." + Style.RESET_ALL

  else :
    print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
    print Back.RED + "(x) Error: The installer is not designed for any other system other than Linux." + Style.RESET_ALL
    print Back.RED + "    Please install manually: " + packages + dependencies + Style.RESET_ALL
    print ""
    sys.exit(0)

  #eof
