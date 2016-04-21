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

import re
import os
import sys
import urllib
import urlparse

from src.utils import menu
from src.utils import settings
from src.thirdparty.colorama import Fore, Back, Style, init

"""
Procced to the next attack vector.
"""
def next_attack_vector(technique, go_back):
  while True:
    next_attack_vector = raw_input(settings.QUESTION_SIGN + "Continue with testing the " + technique + "? [Y/n/q] > ").lower()
    if next_attack_vector in settings.CHOICE_YES:
      return True
    elif next_attack_vector in settings.CHOICE_NO:
      return  False
    elif next_attack_vector in settings.CHOICE_QUIT:
      sys.exit(0)
    else:
      if next_attack_vector == "":
        next_attack_vector = "enter"
      print Back.RED + settings.ERROR_SIGN + "'" + next_attack_vector + "' is not a valid answer." + Style.RESET_ALL + "\n"
      pass

"""
Fix single / double quote escaping.
"""
def escaped_cmd(cmd):
  if "\\\"" in cmd :
    cmd = cmd.replace("\\\"","\"")
  if "\'" in cmd :
    cmd = cmd.replace("\'","'")
  if "\$" in cmd :
    cmd = cmd.replace("\$","$")
  return cmd

"""
Check 'os_shell' options
"""
def check_os_shell_options(cmd, technique, go_back, no_result): 
  if cmd in settings.SHELL_OPTIONS:
    if cmd == "?":
      menu.shell_options()
    elif cmd == "back":
      go_back = True
      if next_attack_vector(technique, go_back) == True:
        return "back"
      else:
        return False
    else:
      return cmd

"""
Check 'reverse_tcp' options
"""
def check_reverse_tcp_options(reverse_tcp_option):
  if reverse_tcp_option == False:
    return 0
  elif reverse_tcp_option == "back":
    return 1
  elif reverse_tcp_option == "os_shell": 
    return 2

"""
Ignore error messages and continue the tests.
"""
def continue_tests(err):
  # If defined "--ignore-401" option, ignores HTTP Error 401 (Unauthorized) 
  # and continues tests without providing valid credentials.
  if menu.options.ignore_401:
    settings.WAF_ENABLED = True
    return True

  # Possible WAF/IPS/IDS
  if (str(err.code) == "403" or "406") and \
    not menu.options.skip_waf:
    # Check if "--skip-waf" option is defined 
    # that skips heuristic detection of WAF/IPS/IDS protection.
    settings.WAF_ENABLED = True
    print Fore.YELLOW + settings.WARNING_SIGN + "It seems that target is protected by some kind of WAF/IPS/IDS." + Style.RESET_ALL
  try:
    while True:
      continue_tests = raw_input(settings.QUESTION_SIGN + "Do you want to ignore the error (" + str(err.code) + ") message and continue the tests? [Y/n/q] > ").lower()
      if continue_tests in settings.CHOICE_YES:
        return True
      elif continue_tests in settings.CHOICE_NO:
        return False
      elif continue_tests in settings.CHOICE_QUIT:
        return False
      else:
        if continue_tests == "":
          continue_tests = "enter"
        print Back.RED + settings.ERROR_SIGN + "'" + continue_tests + "' is not a valid answer." + Style.RESET_ALL + "\n"
        pass
  except KeyboardInterrupt:
    print "\n" + Back.RED + settings.ABORTION_SIGN + "Ctrl-C was pressed!" + Style.RESET_ALL
    raise SystemExit()

"""
Check if option is unavailable
"""
def unavailable_option(check_option):
  print Fore.YELLOW + settings.WARNING_SIGN + "The '" +check_option+ "' option is not yet available for windows targets." + Style.RESET_ALL   

"""
Transformation of separators if time-based injection
"""
def time_based_separators(separator, http_request_method):
  if separator == "||"  or separator == "&&" :
    separator = separator[:1]
    if http_request_method == "POST":
      separator = urllib.quote(separator)
  return separator

"""
Information message if platform does not have 
GNU 'readline' module installed.
"""
def no_readline_module():
  info_msg =  settings.WARNING_SIGN + "It seems that your platform does not have GNU 'readline' module installed."
  info_msg += " For tab-completion support in your shell, download the"
  if settings.IS_WINDOWS:
    info_msg += " 'pyreadline' module (https://pypi.python.org/pypi/pyreadline).\n"
  else:  
    info_msg += " 'gnureadline' module (https://pypi.python.org/pypi/gnureadline).\n" 
  print Fore.YELLOW + info_msg + Style.RESET_ALL 

"""
Check if PowerShell is enabled.
"""
def ps_check():
  if settings.PS_ENABLED == None and menu.options.is_admin or menu.options.users or menu.options.passwords:
    info_msg = settings.WARNING_SIGN + "The payloads in some options that you have chosen, are requiring the use of PowerShell. "
    print Fore.YELLOW + info_msg + Style.RESET_ALL
    while True:
      ps_check = raw_input(settings.QUESTION_SIGN + "Do you want to use the \"--ps-version\" option so ensure that PowerShell is enabled? [Y/n/q] > ").lower()
      if ps_check in settings.CHOICE_YES:
        menu.options.ps_version = True
        break
      elif ps_check in settings.CHOICE_NO:
        break
      elif ps_check in settings.CHOICE_QUIT:
        print ""
        os._exit(0)
      else:  
        if ps_check == "":
          ps_check = "enter"
        print Back.RED + settings.ERROR_SIGN + "'" + ps_check + "' is not a valid answer." + Style.RESET_ALL + "\n"
        pass

"""
If PowerShell is disabled.
"""
def ps_check_failed():
  while True:
    ps_check = raw_input(settings.QUESTION_SIGN + "Do you want to ignore the above warning and continue the procedure? [Y/n] > ").lower()
    if ps_check in settings.CHOICE_YES:
      break
    elif ps_check in settings.CHOICE_NO:
      print ""
      os._exit(0)
    else:  
      if ps_check == "":
        ps_check = "enter"
      print Back.RED + settings.ERROR_SIGN + "'" + ps_check + "' is not a valid answer." + Style.RESET_ALL + "\n"
      pass

"""
Check if http / https.
"""
def check_http_s(url):
  if urlparse.urlparse(url).scheme:
    if menu.options.force_ssl and urlparse.urlparse(url).scheme != "https":
      url = re.sub("\Ahttp:", "https:", url, re.I)
  else:
    if menu.options.force_ssl:
      url = "https://" + url
    else:
      url = "http://" + url
  return url

"""
Force the user-defined operating system name.
"""
def user_defined_os():
  if menu.options.os:
    if menu.options.os.lower() == "windows" or \
       menu.options.os[:1].lower() == "w":
      settings.TARGET_OS = "win"
      return True
    elif menu.options.os.lower() == "unix" or \
       menu.options.os[:1].lower() == "u":
      return True
    else:
      error_msg = "You specified wrong value '" + menu.options.os + "' as an operation system. " \
                  "The value, must be (W)indows or (U)nix."
      print Back.RED + settings.ERROR_SIGN + error_msg + Style.RESET_ALL
      sys.exit(0)

"""
Decision if the user-defined operating system name, 
is different than the one identified by heuristics.
"""
def identified_os():
    warning_msg = "Heuristics have identified different operating system (" + \
                   settings.TARGET_OS + ") than that you have provided." 
    print Fore.YELLOW + settings.WARNING_SIGN + warning_msg + Style.RESET_ALL 
    proceed_option = raw_input(settings.QUESTION_SIGN + "How do you want to proceed? [(C)ontinue/(s)kip/(q)uit] > ").lower()
    if proceed_option.lower() in settings.CHOICE_PROCEED :
      if proceed_option.lower() == "s":
        return False
      elif proceed_option.lower() == "c":
        return True
      elif proceed_option.lower() == "q":
        raise SystemExit()
    else:
      if proceed_option == "":
        proceed_option = "enter"
      print Back.RED + settings.ERROR_SIGN + "'" + proceed_option + "' is not a valid answer." + Style.RESET_ALL + "\n"
      pass

"""
Check for third-party (non-core) libraries.
"""
def third_party_dependencies():
  sys.stdout.write(settings.INFO_SIGN + "Checking for third-party (non-core) libraries... ")
  sys.stdout.flush()
  
  try:
    import sqlite3
  except ImportError:
    print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
    error_msg = settings.APPLICATION + " requires 'sqlite3' third-party library "
    error_msg += "in order to store previous injection points and commands. "
    print Back.RED + settings.ERROR_SIGN + error_msg + Style.RESET_ALL
    sys.exit(0)

  try:
    import readline
  except ImportError:
    if settings.IS_WINDOWS:
      try:
        import pyreadline
      except ImportError:
        print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
        error_msg = settings.APPLICATION + " requires 'pyreadline' third-party library "
        error_msg += "in order to be able to take advantage of the TAB "
        error_msg += "completion and history support features. "
        print Back.RED + settings.ERROR_SIGN + error_msg + Style.RESET_ALL 
        sys.exit(0)
    else:
      try:
        import gnureadline
      except ImportError:
        print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
        error_msg = settings.APPLICATION + " requires 'gnureadline' third-party library "
        error_msg += "in order to be able to take advantage of the TAB "
        error_msg += "completion and history support features. "
        print Back.RED + settings.ERROR_SIGN + error_msg + Style.RESET_ALL
    pass

  print "[" + Fore.GREEN + " SUCCEED " + Style.RESET_ALL + "]"
  info_msg = "All required third-party (non-core) libraries are seems to be installed."
  print Style.BRIGHT + "(!) " + info_msg + Style.RESET_ALL

"""
Print the authentiation error message.
"""
def http_auth_error_msg():
  error_msg = "Use the '--auth-cred' option to provide a valid pair of " 
  error_msg += "HTTP authentication credentials (i.e --auth-cred=\"admin:admin\")" 
  error_msg += " or use the '--ignore-401' option to ignore HTTP error 401 (Unauthorized)" 
  error_msg += " and continue tests without providing valid credentials."
  print Back.RED + settings.ERROR_SIGN + error_msg + Style.RESET_ALL 
  sys.exit(0)

"""
Decision if the user-defined HTTP authenticatiob type, 
is different than the one identified by heuristics.
"""
def identified_http_auth_type(auth_type):
  warning_msg = "Heuristics have identified different HTTP authentication type (" 
  warning_msg += auth_type.lower() + ") than that you have provided ("
  warning_msg += menu.options.auth_type + ")." 
  print Fore.YELLOW + settings.WARNING_SIGN + warning_msg + Style.RESET_ALL 
  proceed_option = raw_input(settings.QUESTION_SIGN + "How do you want to proceed? [(C)ontinue/(s)kip/(q)uit] > ").lower()
  if proceed_option.lower() in settings.CHOICE_PROCEED :
    if proceed_option.lower() == "s":
      return False
    elif proceed_option.lower() == "c":
      return True
    elif proceed_option.lower() == "q":
      raise SystemExit()
  else:
    if proceed_option == "":
      proceed_option = "enter"
    print Back.RED + settings.ERROR_SIGN + "'" + proceed_option + "' is not a valid answer." + Style.RESET_ALL + "\n"
    pass

"""
Retrieve everything from the supported enumeration options.
"""
def enable_all_enumeration_options():
  # Retrieve current user name.
  menu.options.current_user = True
  # Retrieve current hostname.
  menu.options.hostname = True
  # Retrieve system information.
  menu.options.sys_info = True
  if settings.TARGET_OS == "win":
    # Check if the current user have admin privileges.
    menu.options.is_admin = True
    # Retrieve PowerShell's version number.
    menu.options.ps_version = True
  else:
    # Check if the current user have root privileges.
    menu.options.is_root = True
  # Retrieve system users.
  menu.options.users = True
  # Retrieve system users privileges.
  menu.options.privileges = True
  # Retrieve system users password hashes.
  menu.options.passwords = True

#eof