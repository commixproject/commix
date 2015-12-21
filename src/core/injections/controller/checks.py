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
    next_attack_vector = raw_input("(?) Continue with testing the " + technique + "? [Y/n/q] > ").lower()
    if next_attack_vector in settings.CHOISE_YES:
      return True
    elif next_attack_vector in settings.CHOISE_NO:
      return  False
    elif next_attack_vector in settings.CHOISE_QUIT:
      sys.exit(0)
    else:
      if next_attack_vector == "":
        next_attack_vector = "enter"
      print Back.RED + "(x) Error: '" + next_attack_vector + "' is not a valid answer." + Style.RESET_ALL + "\n"
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
      continue_tests = raw_input("(?) Do you want to ignore the error (" +str(err.code)+ ") message and continue the tests? [Y/n/q] > ").lower()
      if continue_tests in settings.CHOISE_YES:
        return True
      elif continue_tests in settings.CHOISE_NO:
        return False
      elif continue_tests in settings.CHOISE_QUIT:
        return False
      else:
        if continue_tests == "":
          continue_tests = "enter"
        print Back.RED + "(x) Error: '" + continue_tests + "' is not a valid answer." + Style.RESET_ALL + "\n"
        pass
  except KeyboardInterrupt:
    print "\n" + Back.RED + "(x) Aborted: Ctrl-C was pressed!" + Style.RESET_ALL
    raise SystemExit()

"""
Check if option is unavailable
"""
def unavailable_option(check_option):

  print Fore.YELLOW + "(^) Warning: The '" +check_option+ "' option is not yet available for windows targets." + Style.RESET_ALL   

"""
Transformation of separators if time-based injection
"""
def time_based_separators(separator, http_request_method):

  if separator == "||"  or separator == "&&" :
    separator = separator[:1]
    if http_request_method == "POST":
      separator = urllib.quote(separator)
  return separator

#eof