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
import urllib

from src.utils import menu
from src.utils import settings
from src.thirdparty.colorama import Fore, Back, Style, init

"""
Procced to the next attack vector.
"""
def next_attack_vector(technique, go_back):
  while True:
    next_attack_vector = raw_input(settings.QUESTION_SIGN + "Continue with testing the " + technique + "? [Y/n/q] > ").lower()
    if next_attack_vector in settings.CHOISE_YES:
      return True
    elif next_attack_vector in settings.CHOISE_NO:
      return  False
    elif next_attack_vector in settings.CHOISE_QUIT:
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
  try:
    while True:
      continue_tests = raw_input(settings.QUESTION_SIGN + "Do you want to ignore the error (" +str(err.code)+ ") message and continue the tests? [Y/n/q] > ").lower()
      if continue_tests in settings.CHOISE_YES:
        return True
      elif continue_tests in settings.CHOISE_NO:
        return False
      elif continue_tests in settings.CHOISE_QUIT:
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
Information message if platform does not have GNU 'readline' module installed
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
      if ps_check in settings.CHOISE_YES:
        menu.options.ps_version = True
        break
      elif ps_check in settings.CHOISE_NO:
        break
      elif ps_check in settings.CHOISE_QUIT:
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
    if ps_check in settings.CHOISE_YES:
      break
    elif ps_check in settings.CHOISE_NO:
      print ""
      os._exit(0)
    else:  
      if ps_check == "":
        ps_check = "enter"
      print Back.RED + settings.ERROR_SIGN + "'" + ps_check + "' is not a valid answer." + Style.RESET_ALL + "\n"
      pass

#eof