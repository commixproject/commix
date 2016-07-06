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
    question_msg = "Continue with testing the " + technique + "? [Y/n/q] > "
    sys.stdout.write(settings.print_question_msg(question_msg))
    next_attack_vector = sys.stdin.readline().replace("\n","").lower()
    if next_attack_vector in settings.CHOICE_YES:
      return True
    elif next_attack_vector in settings.CHOICE_NO:
      return  False
    elif next_attack_vector in settings.CHOICE_QUIT:
      sys.exit(0)
    else:
      if next_attack_vector == "":
        next_attack_vector = "enter"
      err_msg = "'" + next_attack_vector + "' is not a valid answer."  
      print settings.print_error_msg(err_msg)
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
  if (str(err.code) == settings.FORBIDDEN_ERROR or settings.NOT_ACCEPTABLE_ERROR) and \
    not menu.options.skip_waf:
    # Check if "--skip-waf" option is defined 
    # that skips heuristic detection of WAF/IPS/IDS protection.
    settings.WAF_ENABLED = True
    warn_msg = "It seems that target is protected by some kind of WAF/IPS/IDS."
    print settings.print_warning_msg(warn_msg)
  try:
    while True:
      question_msg = "Do you want to ignore the error (" + str(err.code) 
      question_msg += ") message and continue the tests? [Y/n/q] > "
      sys.stdout.write(settings.print_question_msg(question_msg))
      continue_tests = sys.stdin.readline().replace("\n","").lower()
      if continue_tests in settings.CHOICE_YES:
        return True
      elif continue_tests in settings.CHOICE_NO:
        return False
      elif continue_tests in settings.CHOICE_QUIT:
        return False
      else:
        if continue_tests == "":
          continue_tests = "enter"
        err_msg = "'" + continue_tests + "' is not a valid answer."  
        print settings.print_error_msg(err_msg)
        pass
  except KeyboardInterrupt:
    print "\n" + Back.RED + settings.ABORTION_SIGN + "Ctrl-C was pressed!" + Style.RESET_ALL
    raise SystemExit()

"""
Check if option is unavailable
"""
def unavailable_option(check_option):
  warn_msg = "The '" + check_option + "' option "
  warn_msg += "is not yet available for windows targets."
  print settings.print_warning_msg(warn_msg)  

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
  warn_msg =  "It seems that your platform does "
  warn_msg += "not have GNU 'readline' module installed."
  warn_msg += " For tab-completion support in your shell, download the"
  if settings.IS_WINDOWS:
    warn_msg += " 'pyreadline' module (https://pypi.python.org/pypi/pyreadline).\n"
  else:  
    warn_msg += " 'gnureadline' module (https://pypi.python.org/pypi/gnureadline).\n" 
  print settings.print_warning_msg(warn_msg) 

"""
Check if PowerShell is enabled.
"""
def ps_check():
  if settings.PS_ENABLED == None and menu.options.is_admin or menu.options.users or menu.options.passwords:
    if settings.VERBOSITY_LEVEL >= 1:
      print ""
    warn_msg = "The payloads in some options that you "
    warn_msg += "have chosen, are requiring the use of PowerShell. "
    print settings.print_warning_msg(warn_msg)
    while True:
      question_msg = "Do you want to use the \"--ps-version\" option "
      question_msg += "so ensure that PowerShell is enabled? [Y/n/q] > "
      sys.stdout.write(settings.print_question_msg(question_msg))
      ps_check = sys.stdin.readline().replace("\n","").lower()
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
        err_msg = "'" + ps_check + "' is not a valid answer."  
        print settings.print_error_msg(err_msg)
        pass

"""
If PowerShell is disabled.
"""
def ps_check_failed():
  while True:
    question_msg = "Do you want to ignore the above warning "
    question_msg += "and continue the procedure? [Y/n/q] > "
    sys.stdout.write(settings.print_question_msg(question_msg))
    ps_check = sys.stdin.readline().replace("\n","").lower()
    if ps_check in settings.CHOICE_YES:
      break
    elif ps_check in settings.CHOICE_NO:
      print ""
      os._exit(0)
    else:  
      if ps_check == "":
        ps_check = "enter"
      err_msg = "'" + ps_check + "' is not a valid answer."  
      print settings.print_error_msg(err_msg)
      pass


"""
Check if CGI scripts (shellshock injection).
"""
def check_CGI_scripts(url):

  try:
    CGI_SCRIPTS = []
    if not os.path.isfile(settings.CGI_SCRIPTS ):
      err_msg = "The pages / scripts list (" + settings.CGI_SCRIPTS  + ") is not found"
      print settings.print_critical_msg(err_msg)
      sys.exit(0) 
    if len(settings.CGI_SCRIPTS ) == 0:
      err_msg = "The " + settings.CGI_SCRIPTS  + " list is empty."
      print settings.print_critical_msg(err_msg)
      sys.exit(0)
    with open(settings.CGI_SCRIPTS , "r") as f: 
      for line in f:
        line = line.strip()
        CGI_SCRIPTS.append(line)
  except IOError: 
    err_msg = " Check if the " + settings.CGI_SCRIPTS  + " list is readable or corrupted."
    print settings.print_critical_msg(err_msg)
    sys.exit(0)

  for cgi_script in CGI_SCRIPTS:
    if cgi_script in url and menu.options.shellshock == False:
      warn_msg = "URL is probable to contain a script ('" + cgi_script + "') "
      warn_msg += "vulnerable to shellshock. "
      print settings.print_warning_msg(warn_msg)
      while True:
        question_msg = "Do you want to enable the shellshock injection module? [Y/n/q] > "
        sys.stdout.write(settings.print_question_msg(question_msg))
        shellshock_check = sys.stdin.readline().replace("\n","").lower()
        if shellshock_check in settings.CHOICE_YES:
          menu.options.shellshock = True
          break
        elif shellshock_check in settings.CHOICE_NO:
          menu.options.shellshock = False
          break
        elif shellshock_check in settings.CHOICE_QUIT:
          print ""
          os._exit(0)
        else:  
          if shellshock_check == "":
            shellshock_check = "enter"
          err_msg = "'" + shellshock_check + "' is not a valid answer."  
          print settings.print_error_msg(err_msg)
          pass

"""
Check if http / https.
"""
def check_http_s(url):
  if urlparse.urlparse(url).scheme:
    if menu.options.force_ssl and urlparse.urlparse(url).scheme != "https":
      url = re.sub("\Ahttp:", "https:", url, re.I)
      settings.PROXY_PROTOCOL = 'https'
  else:
    if menu.options.force_ssl:
      url = "https://" + url
      settings.PROXY_PROTOCOL = 'https'
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
      err_msg = "You specified wrong value '" + menu.options.os + "' "
      err_msg += "as an operation system. The value, must be (W)indows or (U)nix."
      print settings.print_error_msg(err_msg)
      sys.exit(0)

"""
Decision if the user-defined operating system name, 
is different than the one identified by heuristics.
"""
def identified_os():
    warn_msg = "Heuristics have identified different operating system (" 
    warn_msg += settings.TARGET_OS + ") than that you have provided." 
    print settings.print_warning_msg(warn_msg)
    question_msg = "How do you want to proceed? [(C)ontinue/(s)kip/(q)uit] > "
    sys.stdout.write(settings.print_question_msg(question_msg))
    proceed_option = sys.stdin.readline().replace("\n","").lower()
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
      err_msg = "'" + proceed_option + "' is not a valid answer."  
      print settings.print_error_msg(err_msg)
      pass

"""
Check for third-party (non-core) libraries.
"""
def third_party_dependencies():
  info_msg = "Checking for third-party (non-core) libraries... "
  sys.stdout.write(settings.print_info_msg(info_msg))
  sys.stdout.flush()
  
  try:
    import sqlite3
  except ImportError:
    print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
    err_msg = settings.APPLICATION + " requires 'sqlite3' third-party library "
    err_msg += "in order to store previous injection points and commands. "
    print settings.print_critical_msg(err_msg)
    sys.exit(0)

  try:
    import readline
  except ImportError:
    if settings.IS_WINDOWS:
      try:
        import pyreadline
      except ImportError:
        print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
        err_msg = settings.APPLICATION + " requires 'pyreadline' third-party library "
        err_msg += "in order to be able to take advantage of the TAB "
        err_msg += "completion and history support features. "
        print settings.print_critical_msg(err_msg) 
        sys.exit(0)
    else:
      try:
        import gnureadline
      except ImportError:
        print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
        err_msg = settings.APPLICATION + " requires 'gnureadline' third-party library "
        err_msg += "in order to be able to take advantage of the TAB "
        err_msg += "completion and history support features. "
        print settings.print_critical_msg(err_msg)
    pass

  print "[" + Fore.GREEN + " SUCCEED " + Style.RESET_ALL + "]"
  success_msg = "All required third-party (non-core) libraries are seems to be installed."
  print settings.print_success_msg(success_msg)

"""
Print the authentiation error message.
"""
def http_auth_err_msg():
  err_msg = "Use the '--auth-cred' option to provide a valid pair of " 
  err_msg += "HTTP authentication credentials (i.e --auth-cred=\"admin:admin\")" 
  err_msg += " or use the '--ignore-401' option to ignore HTTP error 401 (Unauthorized)" 
  err_msg += " and continue tests without providing valid credentials."
  print settings.print_critical_msg(err_msg) 
  sys.exit(0)

"""
Decision if the user-defined HTTP authenticatiob type, 
is different than the one identified by heuristics.
"""
def identified_http_auth_type(auth_type):
  warn_msg = "Heuristics have identified different HTTP authentication type (" 
  warn_msg += auth_type.lower() + ") than that you have provided ("
  warn_msg += menu.options.auth_type + ")." 
  print settings.print_warning_msg(warn_msg)
  question_msg = "How do you want to proceed? [(C)ontinue/(s)kip/(q)uit] > "
  sys.stdout.write(settings.print_question_msg(question_msg))
  proceed_option = sys.stdin.readline().replace("\n","").lower()
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
    err_msg = "'" + proceed_option + "' is not a valid answer." 
    print settings.print_error_msg(err_msg)
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

"""
Do replacement with the 'INJECT_HERE' tag, 
if the wildcard char is provided.
"""
def wildcard_character(data):
  if settings.WILDCARD_CHAR in data:
    if data.count(settings.WILDCARD_CHAR) > 1:
      err_msg = "You specified more than one testable parameters. " 
      err_msg += "Use the '-p' option to define them (i.e -p \"id1,id2\"). "
      print settings.print_critical_msg(err_msg) 
      sys.exit(0)
    else:  
      data = data.replace(settings.WILDCARD_CHAR, settings.INJECT_TAG)
  return data

"""
Print the non-listed parameters.
"""
def print_non_listed_params(check_parameters, http_request_method, header_name):
  if len(check_parameters) > 0:
    non_exist_param = list(set(settings.TEST_PARAMETER)-set(check_parameters))
    non_exist_param = ', '.join(non_exist_param)
    if not len(non_exist_param) == 0 :
      warn_msg = "The provided parameter" + "s"[len(non_exist_param) == 1:][::-1] + " '" 
      warn_msg += non_exist_param + "'" + (' are', ' is')[len(non_exist_param) == 1]
      if menu.options.level >= 2 and header_name != "":
        warn_msg += " not inside the "
        warn_msg +=  settings.HTTP_HEADER
      else:
        warn_msg += " not inside the "
        warn_msg += http_request_method   
      warn_msg += "."
      print settings.print_warning_msg(warn_msg) 

"""
Check for whitespaces
"""
def check_whitespaces():
  if settings.WHITESPACE[0] != "%20" and settings.WHITESPACE[0] != urllib.unquote("%20"):
    warn_msg = "Whitespaces are important for time-relative techniques, "
    warn_msg += "thus whitespace characters had been reset to default."
    print settings.print_warning_msg(warn_msg)
  if settings.WHITESPACE[0] != urllib.unquote("%20"):
    whitespace = " "
    return whitespace  

"""
Tamper script checker
"""
def tamper_scripts():

  info_msg = "Loading tamper script(s): "
  print settings.print_info_msg(info_msg)

  # Check the provided tamper script(s)
  tamper_script_counter = 0
  for tfile in re.split(settings.PARAMETER_SPLITTING_REGEX, menu.options.tamper.lower()):
    check_tfile = "src/core/tamper/" + tfile + ".py"

    if not os.path.exists(check_tfile.lower()):
      if not settings.LOAD_SESSION:
        err_msg = "The '" + tfile + "' tamper script does not exist."
        print settings.print_error_msg(err_msg)

    if os.path.isfile(check_tfile):
      tamper_script_counter =  tamper_script_counter + 1
      import importlib
      check_tfile = check_tfile.replace("/",".")
      importlib.import_module(check_tfile.split(".py")[0])
      print settings.SUB_CONTENT_SIGN + tfile 

  # info_msg = str(tamper_script_counter) + " tamper script" + "s"[tamper_script_counter == 1:] +  " enabled."
  # print settings.print_info_msg(info_msg)     

"""
Check if the payload output seems to be base64.
"""
def base64_output(payload):
  if (len(payload) % 4 == 0) and re.match(settings.BASE64_RECOGNITION_REGEX, payload):
    if not settings.TAMPER_SCRIPTS['base64encode']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",base64encode"
      else:
        menu.options.tamper = "base64encode"
      tamper_scripts()
  else:
    if settings.TAMPER_SCRIPTS['base64encode']:
      settings.TAMPER_SCRIPTS['base64encode'] = False
      warn_msg = "The resumed stored session is not in base64 format. "
      warn_msg += "Rerun with '--flush-session' option."
      print settings.print_warning_msg(warn_msg)

"""
Check for modified whitespaces 
"""
def whitespace_check(payload):
  if "${IFS}" in payload:
    settings.WHITESPACE[0] = "${IFS}"
    if not settings.TAMPER_SCRIPTS['space2ifs']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",space2ifs"
      else:
        menu.options.tamper = "space2ifs"
      tamper_scripts()
  else:
    count_plus = payload.count("+")
    if count_plus >= 2 and not "%20" in payload:
      if not settings.TAMPER_SCRIPTS['space2plus']:
        if menu.options.tamper:
          menu.options.tamper = menu.options.tamper + ",space2plus"
        else:
          menu.options.tamper = "space2plus"
        tamper_scripts()
    else:
      settings.WHITESPACE[0] = "%20" 

"""
Check for stored payloads and enable tamper scripts
"""
def check_for_stored_tamper(payload):
  whitespace_check(payload)
  base64_output(payload)

#eof