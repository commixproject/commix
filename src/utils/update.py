#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2023 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

import re
import os
import sys
import time
import subprocess
from src.utils import menu
from src.utils import settings
from src.utils import requirments
from src.utils import common
from src.thirdparty.six.moves import input as _input
from src.thirdparty.colorama import Fore, Back, Style, init

"""
Check for updates (apply if any) and exit!
"""

"""
Returns abbreviated commit hash number as retrieved with "git rev-parse --short HEAD"
"""
def revision_num():
  try:
    start = 0
    end = 0
    start = time.time()
    process = subprocess.Popen("git reset --hard HEAD && git clean -fd && git pull", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, _ = process.communicate()
    if settings.VERBOSITY_LEVEL == 0:
      info_msg = ('Updated to', 'Already at')["Already" in stdout]
      process = subprocess.Popen("git rev-parse --verify HEAD", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # Delete *.pyc files.
    subprocess.Popen("find . -name \"*.pyc\" -delete", shell=True).wait()
    # Delete empty directories and files.
    subprocess.Popen("find . -empty -type d -delete", shell=True).wait()
    if settings.VERBOSITY_LEVEL == 0: 
      stdout, _ = process.communicate()
      match = re.search(r"(?i)[0-9a-f]{32}", stdout or "")
      rev_num = match.group(0) if match else None
      info_msg += " the latest revision '" + str(rev_num[:7]) + "'."
      print(settings.SINGLE_WHITESPACE)
    else:
      sys.stdout.write(Fore.MAGENTA + "\n" + stdout + Style.RESET_ALL)
      end  = time.time()
      how_long = int(end - start)
      info_msg = "Finished in " + time.strftime('%H:%M:%S', time.gmtime(how_long)) + "."
    print(settings.print_info_msg(info_msg))
  except:
    print(settings.SINGLE_WHITESPACE) 
    raise SystemExit()

"""
The commix's updater.
"""
def updater():
  time.sleep(1)
  info_msg = "Checking requirements to update " 
  info_msg += settings.APPLICATION + " from GitHub repository. "
  sys.stdout.write(settings.print_info_msg(info_msg))
  sys.stdout.flush()
  if menu.options.offline:  
    print(settings.SINGLE_WHITESPACE)
    err_msg = "You cannot update commix via GitHub without access on the Internet."
    print(settings.print_critical_msg(err_msg))
    raise SystemExit()
  # Check if windows
  if settings.IS_WINDOWS:
    print(settings.SINGLE_WHITESPACE)
    err_msg = "For updating purposes on Windows platform, it's recommended "
    err_msg += "to use a GitHub client for Windows (http://windows.github.com/)."
    print(settings.print_critical_msg(err_msg))
    raise SystemExit()
  else:
    try:
      requirment = "git"
      # Check if 'git' is installed.
      requirments.do_check(requirment)
      if requirments.do_check(requirment) == True :
        if settings.VERBOSITY_LEVEL != 0:
          debug_msg = "commix will try to update itself using '" + requirment + "' command."
          print(settings.SINGLE_WHITESPACE)
          print(settings.print_debug_msg(debug_msg))
        # Check if ".git" exists!
        else:
          print(settings.SINGLE_WHITESPACE)
        if os.path.isdir("./.git"):
          info_msg = "Updating " + settings.APPLICATION + " to the latest (dev) " 
          info_msg += "version. "
          sys.stdout.write(settings.print_info_msg(info_msg))
          sys.stdout.flush()
          revision_num()
          print(settings.SINGLE_WHITESPACE)
          os._exit(0)
        else:
          print(settings.SINGLE_WHITESPACE)
          err_msg = "The '.git' directory not found. Do it manually: " 
          err_msg += Style.BRIGHT + "'git clone " + settings.GIT_URL 
          err_msg += " " + settings.APPLICATION + "' "
          print(settings.print_critical_msg(err_msg))    
          raise SystemExit()
      else:
          print(settings.SINGLE_WHITESPACE)
          err_msg = requirment + " not found."
          print(settings.print_critical_msg(err_msg))
          raise SystemExit()

    except Exception as err_msg:
      print("\n" + settings.print_critical_msg(err_msg))
    raise SystemExit()

"""
Check for new version of commix
"""
def check_for_update():
  try:
    response = _urllib.request.urlopen('https://raw.githubusercontent.com/commixproject/commix/master/src/utils/settings.py', timeout=settings.TIMEOUT)
    version_check = response.readlines()
    for line in version_check:
      line = line.rstrip()
      if "VERSION_NUM = " in line:
        update_version = line.replace("VERSION_NUM = ", "").replace("\"", "")
        break 
    if (int(settings.VERSION_NUM.replace(".","")[:2]) < int(update_version.replace(".","")[:2])) or \
       ((int(settings.VERSION_NUM.replace(".","")[:2]) == int(update_version.replace(".","")[:2])) and \
         int(settings.VERSION_NUM.replace(".","")[2:]) < int(update_version.replace(".","")[2:])):
      while True:
        message = "Do you want to update to the latest version now? [Y/n] > "
        do_update = common.read_input(message, default="Y", check_batch=True)
        if do_update in settings.CHOICE_YES:
          updater()
        elif do_update in settings.CHOICE_NO:
          break
        else:
          common.invalid_option(do_update)  
          pass
  except KeyboardInterrupt:
    raise
  except:
    pass

"""
The updater for the unicorn tool
"""
def unicorn_updater(current_version):
  APPLICATION_NAME = "TrustedSec's Magic Unicorn"
  info_msg = "Checking requirements to update " 
  info_msg += APPLICATION_NAME + " from GitHub repository. "
  sys.stdout.write(settings.print_info_msg(info_msg))
  sys.stdout.flush()
  if menu.options.offline:  
    print(settings.SINGLE_WHITESPACE)
    err_msg = "You cannot update TrustedSec's Magic Unicorn "
    err_msg += "via GitHub without access on the Internet."
    print(settings.print_critical_msg(err_msg))
    raise SystemExit()
  # Check if windows
  if settings.IS_WINDOWS:
    print(settings.SINGLE_WHITESPACE)
    err_msg = "For updating purposes on Windows platform, it's recommended "
    err_msg += "to use a GitHub client for Windows (http://windows.github.com/)."
    print(settings.print_critical_msg(err_msg))
    raise SystemExit()
  else:
    try:
      requirment = "git"
      # Check if 'git' is installed.
      requirments.do_check(requirment)
      if requirments.do_check(requirment) == True :
        sys.stdout.write(settings.SUCCESS_STATUS + "\n")
        sys.stdout.flush()
        if len(current_version) == 0:
          unicorn_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../', 'thirdparty/'))
          os.chdir(unicorn_path)
        else:
          os.chdir("../")
          subprocess.Popen("rm -rf unicorn", shell=True).wait()
        info_msg = "Updating " + APPLICATION_NAME + " to the latest (dev) " 
        info_msg += "version. "
        subprocess.Popen("git clone https://github.com/trustedsec/unicorn", shell=True).wait()
        os.chdir("unicorn")
        sys.stdout.write(settings.print_info_msg(info_msg))
        sys.stdout.flush()
        revision_num()
      else:
        print(settings.SINGLE_WHITESPACE)
        err_msg = requirment + " not found."
        print(settings.print_critical_msg(err_msg))
        raise SystemExit()

    except Exception as err_msg:
      print(settings.print_critical_msg(err_msg))
    raise SystemExit()

"""
Check the latest version of unicorn
"""
def check_unicorn_version(current_version):
  try:
    if len(current_version) != 0: 
      response = _urllib.request.urlopen('https://raw.githubusercontent.com/trustedsec/unicorn/master/unicorn.py', timeout=settings.TIMEOUT)
      latest_version = response.readlines()
      for line in latest_version:
        line = line.rstrip()
        if "Magic Unicorn Attack Vector v" in line:
          latest_version = line.replace("Magic Unicorn Attack Vector v", "").replace(settings.SINGLE_WHITESPACE, "").replace("-","").replace("\"","").replace(")","")
          break

    if len(current_version) == 0 or \
       (int(current_version.replace(".","")[:2]) < int(latest_version.replace(".","")[:2])) or \
       ((int(current_version.replace(".","")[:2]) == int(latest_version.replace(".","")[:2])) and \
         int(current_version.replace(".","")[2:]) < int(latest_version.replace(".","")[2:])):

      if len(current_version) != 0:
        warn_msg = "Current version of TrustedSec's Magic Unicorn (" + current_version + ") seems to be out-of-date."
        print(settings.print_warning_msg(warn_msg))
      else:
        warn_msg = "TrustedSec's Magic Unicorn seems to be not installed."
        print(settings.print_warning_msg(warn_msg)) 
      while True:
        if len(current_version) == 0:
          action = "install"
        else:
          action = "update to"
        message = "Do you want to " + action + " the latest version now? [Y/n] > "
        do_update = common.read_input(message, default="Y", check_batch=True)
        if do_update in settings.CHOICE_YES:
            unicorn_updater(current_version)
        elif do_update in settings.CHOICE_NO:
          break
        else:
          common.invalid_option(do_update)  
          pass

  except KeyboardInterrupt:
    raise
  except:
    pass

# eof