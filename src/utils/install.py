#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2025 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

import os
import sys
import platform
import subprocess
from src.utils import menu
from src.utils import common
from src.utils import settings
from src.utils import requirements
from src.thirdparty.six.moves import input as _input
from src.thirdparty.colorama import Fore, Back, Style, init

"""
Make a local installation of 'commix' on your system.
"""

"""
The un-installer.
"""
def uninstaller():
  info_msg = "Starting the uninstaller. "
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  
  try:
    subprocess.Popen("rm -rf /usr/bin/" + settings.APPLICATION + " >/dev/null 2>&1", shell=True).wait()
    subprocess.Popen("rm -rf /usr/share/" + settings.APPLICATION + " >/dev/null 2>&1", shell=True).wait()
  except:
    settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
    raise SystemExit()

  settings.print_data_to_stdout(settings.SUCCESS_STATUS)
  
  info_msg = "The un-installation of commix has finished!"
  settings.print_data_to_stdout(settings.print_bold_info_msg(info_msg))

"""
The installer.
"""
def installer():
  packages = "build-essential python-dev"
  dependencies = "git python-pip"

  info_msg = "Starting the installer. "
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  

  # Check if OS is Linux.
  if settings.PLATFORM == "posix":
    # You need to have administrative privileges to run this script.
    if not common.running_as_admin():
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
      err_msg = "You need to have administrative privileges to run this option."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()

    # Check if commix is already installed.
    if os.path.isdir("/usr/share/"  + settings.APPLICATION + ""):
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
      warn_msg = "It seems that "  + settings.APPLICATION
      warn_msg += " is already installed in your system."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
      while True:
        message = "Do you want to remove commix? [Y/n] > "
        uninstall = common.read_input(message, default="Y", check_batch=True)
        if uninstall in settings.CHOICE_YES:
          uninstaller()
          raise SystemExit()
        elif uninstall in settings.CHOICE_NO or \
        uninstall in settings.CHOICE_QUIT:
          raise SystemExit()
        else:
          common.invalid_option(uninstall)
          pass

    # Check for git.
    if not os.path.isfile("/usr/bin/git") or not os.path.isfile("/usr/bin/pip"):
      # Install requirement.
      if os.path.isfile("/etc/apt/sources.list"):
        settings.print_data_to_stdout(settings.SUCCESS_STATUS)
        
        # Check for dependencies.
        dependencies_items = dependencies.split()
        for item in dependencies_items:
          requirements.do_check(item)
      else:
        settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
        err_msg = "The installer is not designed for any "
        err_msg += "other Linux distro than Ubuntu / Debian. "
        err_msg += "Please install manually: " + dependencies
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
        settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
        raise SystemExit()

    # Force install of necessary packages
    subprocess.Popen("apt-get --force-yes -y install " + packages + ">/dev/null 2>&1", shell=True).wait()
    settings.print_data_to_stdout(settings.SUCCESS_STATUS)
    

    info_msg =  "Installing " + settings.APPLICATION
    info_msg += " into the /usr/share/"  + settings.APPLICATION + ". "
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
    try:
      current_dir = os.getcwd()
      subprocess.Popen("cp -r " + current_dir + " /usr/share/" + settings.APPLICATION + " >/dev/null 2>&1", shell=True).wait()
      subprocess.Popen("chmod 775 /usr/share/"  + settings.APPLICATION + "/" + settings.APPLICATION + ".py >/dev/null 2>&1", shell=True).wait()
    except:
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
      raise SystemExit()
    settings.print_data_to_stdout(settings.SUCCESS_STATUS)
    

    info_msg = "Installing "  + settings.APPLICATION
    info_msg += " to /usr/bin/"  + settings.APPLICATION + ". "
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
    try:
      with open("/usr/bin/" + settings.APPLICATION, 'w') as f:
        f.write('#!/bin/bash\n')
        f.write('cd /usr/share/commix/ && ./commix.py "$@"\n')
        subprocess.Popen("chmod +x /usr/bin/"  + settings.APPLICATION + " >/dev/null 2>&1", shell=True).wait()
    except:
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
      raise SystemExit()
    settings.print_data_to_stdout(settings.SUCCESS_STATUS)
    

    #Create the Output Directory
    try:
      os.stat(settings.OUTPUT_DIR)
    except:
      try:
        os.mkdir(settings.OUTPUT_DIR)
      except OSError as err_msg:
        try:
          error_msg = str(err_msg).split("] ")[1] + "."
        except IndexError:
          error_msg = str(err_msg) + "."
        settings.print_data_to_stdout(settings.print_critical_msg(error_msg))
        raise SystemExit()

    info_msg = "The installation is finished! Type '"
    info_msg += settings.APPLICATION + "' to launch it."
    settings.print_data_to_stdout(settings.print_bold_info_msg(info_msg))

  else :
    settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
    err_msg = "The installer is not designed for any other system other than Linux. "
    err_msg += "Please install manually: " + packages + dependencies
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
    raise SystemExit()

  # eof