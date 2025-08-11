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
import subprocess
from src.utils import menu
from src.utils import common
from src.utils import settings
from src.utils import requirements
from src.thirdparty.six.moves import input as _input
from src.thirdparty.colorama import Fore, Back, Style, init

# Removal Function 
def remove():
  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Removing existing installation and performing cleanup..."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
  try:
    subprocess.call("rm -rf " + os.path.join(settings.WRAPPER_PATH, settings.APPLICATION) + settings.NO_OUTPUT, shell=True)
    subprocess.call("rm -rf " + os.path.join(settings.INSTALL_DIR, settings.APPLICATION) + settings.NO_OUTPUT, shell=True)
  except Exception as e:
    err_msg = "An error occurred while removing the application: " + str(e)
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  info_msg = settings.APPLICATION.capitalize() + " and all related components have been successfully removed."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))

# Abort for Unsupported Systems 
def abort_unsupported(packages, dependencies):
  err_msg = "This installer is designed specifically for Ubuntu and Debian-based Linux distributions. "
  err_msg += "To proceed on other systems, install the required packages (i.e. " + packages
  err_msg += ") and dependencies (i.e. " + dependencies + ") manually."
  settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
  raise SystemExit()

# Installer Function 
def installer():
  packages = "build-essential python-dev"
  dependencies = "git python-pip"

  info_msg = "Starting installation of " + settings.APPLICATION + " (" + settings.VERSION + ") on your system."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))

  if settings.PLATFORM != "posix":
    abort_unsupported(packages, dependencies)

  if not common.running_as_admin():
    err_msg = "Administrative privileges are required to run this option."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  app_install_path = os.path.join(settings.INSTALL_DIR, settings.APPLICATION)
  launcher_path = os.path.join(settings.WRAPPER_PATH, settings.APPLICATION)

  if os.path.isdir(app_install_path):
    warn_msg = "An existing installation of " + settings.APPLICATION + " was detected."
    settings.print_data_to_stdout(settings.print_bold_warning_msg(warn_msg))

    while True:
      message = "Do you want to remove the current installation? [Y/n] > "
      user_input = common.read_input(message, default="Y", check_batch=True)
      if user_input in settings.CHOICE_YES:
        remove()
        raise SystemExit()
      elif user_input in settings.CHOICE_NO or user_input in settings.CHOICE_QUIT:
        raise SystemExit()
      else:
        common.invalid_option(user_input)

  if not os.path.isfile("/usr/bin/git") or not os.path.isfile("/usr/bin/pip"):
    if os.path.isfile("/etc/apt/sources.list"):
      for dep in dependencies.split():
        requirements.do_check(dep)
    else:
      abort_unsupported(packages, dependencies)

  subprocess.call("apt-get --force-yes -y install " + packages + settings.NO_OUTPUT, shell=True)

  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Copying application files to '" + app_install_path + "'..."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

  try:
    current_dir = os.getcwd()
    subprocess.call("cp -r " + current_dir + " " + app_install_path + settings.NO_OUTPUT, shell=True)
    subprocess.call("chmod 775 " + os.path.join(app_install_path, settings.APPLICATION + ".py") + settings.NO_OUTPUT, shell=True)
  except Exception as e:
    settings.print_data_to_stdout(settings.print_critical_msg(str(e)))
    raise SystemExit()

  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Creating launcher script at '" + launcher_path + "'..."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

  try:
    with open(launcher_path, 'w') as f:
      f.write("#!/bin/bash\n")
      f.write("cd " + app_install_path + " && ./" + settings.APPLICATION + ".py \"$@\"\n")
    subprocess.call("chmod +x " + launcher_path + settings.NO_OUTPUT, shell=True)
  except Exception as e:
    err_msg = "Failed to create launcher: " + str(e)
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  try:
    if not os.path.exists(settings.OUTPUT_DIR):
      os.mkdir(settings.OUTPUT_DIR)
  except OSError as err_msg:
    try:
      error_msg = str(err_msg).split("] ")[1] + "."
    except IndexError:
      error_msg = str(err_msg) + "."
    settings.print_data_to_stdout(settings.print_critical_msg(error_msg))
    raise SystemExit()

  info_msg = "Installation has been completed."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))

# eof
