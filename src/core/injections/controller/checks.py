#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (http://commixproject.com).
Copyright (c) 2014-2017 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
 
For more see the file 'readme/COPYING' for copying permission.
"""

import re
import os
import sys
import base64
import urllib
import urlparse

from src.utils import menu
from src.utils import settings

from src.thirdparty.colorama import Fore, Back, Style, init

"""
Check current assessment phase.
"""
def assessment_phase():
  if settings.DETECTION_PHASE: 
    return "detection"
  else:
    return "exploitation"

"""
Check current assessment phase.
"""
def check_injection_level():
  # Checking testable parameters for cookies
  if menu.options.cookie:
    if settings.COOKIE_DELIMITER in menu.options.cookie:
      cookies = menu.options.cookie.split(settings.COOKIE_DELIMITER)
      for cookie in cookies:
        if cookie.split("=")[0].strip() in menu.options.test_parameter:
          menu.options.level = 2
    elif menu.options.cookie.split("=")[0] in menu.options.test_parameter:
      menu.options.level = 2

  # Checking testable parameters for user-agent / referer  
  if "user-agent" in menu.options.test_parameter or \
     "referer" in menu.options.test_parameter:
    menu.options.level = 3

"""
Procced to the next attack vector.
"""
def next_attack_vector(technique, go_back):
  while True:
    if not menu.options.batch:
      question_msg = "Continue with testing the " + technique + "? [Y/n] > "
      sys.stdout.write(settings.print_question_msg(question_msg))
      next_attack_vector = sys.stdin.readline().replace("\n","").lower()
    else:
      next_attack_vector = ""
    if len(next_attack_vector) == 0:
       next_attack_vector = "y"
    if next_attack_vector in settings.CHOICE_YES:
      # Check injection state
      assessment_phase()
      return True
    elif next_attack_vector in settings.CHOICE_NO:
      return  False
    elif next_attack_vector in settings.CHOICE_QUIT:
      sys.exit(0)
    else:
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
      menu.os_shell_options()
    elif cmd == "back":
      if next_attack_vector(technique, go_back) == True:
        return True
      else:
        return False
    else:
      return cmd

"""
Procced with file-based semiblind command injection technique,
once the user provides the path of web server's root directory.
"""
def procced_with_file_based_technique(): 
  while True:
    if not menu.options.batch:
      question_msg = "Do you want to procced with the (semi-blind) "
      question_msg += "file-based injection technique? [Y/n] > "
      sys.stdout.write(settings.print_question_msg(question_msg))
      enable_fb = sys.stdin.readline().replace("\n","").lower()
    else:
      enable_fb = ""
    if len(enable_fb) == 0:
       enable_fb = "y"
    if enable_fb in settings.CHOICE_YES:
      return True
    elif enable_fb in settings.CHOICE_NO:
      return False
    elif enable_fb in settings.CHOICE_QUIT:
      sys.exit(0)
    else:
      err_msg = "'" + enable_fb + "' is not a valid answer."  
      print settings.print_error_msg(err_msg)
      pass

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
  elif reverse_tcp_option == "bind_tcp": 
    return 3

"""
Check 'bind_tcp' options
"""
def check_bind_tcp_options(bind_tcp_option):
  if bind_tcp_option == False:
    return 0
  elif bind_tcp_option == "back":
    return 1
  elif bind_tcp_option == "os_shell": 
    return 2
  elif bind_tcp_option == "reverse_tcp": 
    return 3

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
      if not menu.options.batch:
        question_msg = "Do you want to ignore the error (" + str(err.code) 
        question_msg += ") message and continue the tests? [Y/n] > "
        sys.stdout.write(settings.print_question_msg(question_msg))
        continue_tests = sys.stdin.readline().replace("\n","").lower()
      else:
        continue_tests = ""
      if len(continue_tests) == 0:
         continue_tests = "y"
      if continue_tests in settings.CHOICE_YES:
        return True
      elif continue_tests in settings.CHOICE_NO:
        return False
      elif continue_tests in settings.CHOICE_QUIT:
        return False
      else:
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
  err_msg =  "It seems that your platform does "
  err_msg += "not have GNU 'readline' module installed."
  err_msg += " Download the"
  if settings.IS_WINDOWS:
    err_msg += " 'pyreadline' module (https://pypi.python.org/pypi/pyreadline)."
  else:  
    err_msg += " 'gnureadline' module (https://pypi.python.org/pypi/gnureadline)." 
  print settings.print_critical_msg(err_msg) 

"""
Check for incompatible OS (i.e Unix).
"""
def ps_incompatible_os():
  if not settings.TARGET_OS == "win":
    warn_msg = "The identified OS seems incompatible with the provided '--ps-version' switch."
    print settings.print_warning_msg(warn_msg)
    return True

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
      if not menu.options.batch:
        question_msg = "Do you want to use the \"--ps-version\" option "
        question_msg += "so ensure that PowerShell is enabled? [Y/n] > "
        sys.stdout.write(settings.print_question_msg(question_msg))
        ps_check = sys.stdin.readline().replace("\n","").lower()
      else:
        ps_check = ""
      if len(ps_check) == 0:
         ps_check = "y"
      if ps_check in settings.CHOICE_YES:
        menu.options.ps_version = True
        break
      elif ps_check in settings.CHOICE_NO:
        break
      elif ps_check in settings.CHOICE_QUIT:
        print ""
        os._exit(0)
      else:  
        err_msg = "'" + ps_check + "' is not a valid answer."  
        print settings.print_error_msg(err_msg)
        pass

"""
If PowerShell is disabled.
"""
def ps_check_failed():
  while True:
    if not menu.options.batch:
      question_msg = "Do you want to ignore the above warning "
      question_msg += "and continue the procedure? [Y/n] > "
      sys.stdout.write(settings.print_question_msg(question_msg))
      ps_check = sys.stdin.readline().replace("\n","").lower()
    else:
      ps_check = ""
    if len(ps_check) == 0:
       ps_check = "y"
    if ps_check in settings.CHOICE_YES:
      break
    elif ps_check in settings.CHOICE_NO:
      print ""
      os._exit(0)
    else:  
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
        if not menu.options.batch:
          question_msg = "Do you want to enable the shellshock injection module? [Y/n] > "
          sys.stdout.write(settings.print_question_msg(question_msg))
          shellshock_check = sys.stdin.readline().replace("\n","").lower()
        else:
          shellshock_check = ""   
        if len(shellshock_check) == 0:
           shellshock_check = "y"
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
          err_msg = "'" + shellshock_check + "' is not a valid answer."  
          print settings.print_error_msg(err_msg)
          pass

"""
Check if http / https.
"""
def check_http_s(url):
  if settings.CHECK_INTERNET:
    if "https" in url:
      url = "https://" + settings.CHECK_INTERNET_ADDRESS
    else:
      url = "http://" + settings.CHECK_INTERNET_ADDRESS
  else:
    if settings.PROXY_PROTOCOL in urlparse.urlparse(url).scheme:
      if menu.options.force_ssl and urlparse.urlparse(url).scheme != "https":
        url = re.sub("\Ahttp:", "https:", url, re.I)
        settings.PROXY_PROTOCOL = 'https'
      if urlparse.urlparse(url).scheme == "https":
        settings.PROXY_PROTOCOL = "https"
    else:
      if menu.options.force_ssl:
        url = "https://" + url
        settings.PROXY_PROTOCOL = "https"
      else:
        url = "http://" + url 
  return url
  
"""
Force the user-defined operating system name.
"""
def user_defined_os():
  if menu.options.os:
    if menu.options.os.lower() == "windows":
      settings.TARGET_OS = "win"
      return True
    elif menu.options.os.lower() == "unix":
      return True
    else:
      err_msg = "You specified wrong value '" + menu.options.os + "' "
      err_msg += "as an operation system. The value, must be 'Windows' or 'Unix'."
      print settings.print_critical_msg(err_msg)
      sys.exit(0)

"""
Decision if the user-defined operating system name, 
is different than the one identified by heuristics.
"""
def identified_os():
    if not menu.options.batch:
      warn_msg = "Heuristics have identified different operating system (" 
      warn_msg += settings.TARGET_OS + ") than that you have provided." 
      print settings.print_warning_msg(warn_msg)
      question_msg = "How do you want to proceed? [(C)ontinue/(s)kip/(q)uit] > "
      sys.stdout.write(settings.print_question_msg(question_msg))
      proceed_option = sys.stdin.readline().replace("\n","").lower()
    else:
      proceed_option = "" 
    if len(proceed_option) == 0:
       proceed_option = "c"
    if proceed_option.lower() in settings.CHOICE_PROCEED :
      if proceed_option.lower() == "s":
        return False
      elif proceed_option.lower() == "c":
        return True
      elif proceed_option.lower() == "q":
        raise SystemExit()
    else:
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
  if not menu.options.batch:
    warn_msg = "Heuristics have identified different HTTP authentication type (" 
    warn_msg += auth_type.lower() + ") than that you have provided ("
    warn_msg += menu.options.auth_type + ")." 
    print settings.print_warning_msg(warn_msg)
    question_msg = "How do you want to proceed? [(C)ontinue/(s)kip/(q)uit] > "
    sys.stdout.write(settings.print_question_msg(question_msg))
    proceed_option = sys.stdin.readline().replace("\n","").lower()
  else:
    proceed_option = ""  
  if len(proceed_option) == 0:
    proceed_option = "c"
  if proceed_option.lower() in settings.CHOICE_PROCEED :
    if proceed_option.lower() == "s":
      return False
    elif proceed_option.lower() == "c":
      return True
    elif proceed_option.lower() == "q":
      raise SystemExit()
  else:
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
Skip defined
"""
def check_skipped_params(check_parameters):

  settings.TEST_PARAMETER = [x + "," for x in settings.TEST_PARAMETER]
  settings.TEST_PARAMETER = [x for x in check_parameters if x not in ",".join(settings.TEST_PARAMETER).split(",")]
  settings.TEST_PARAMETER = ",".join(settings.TEST_PARAMETER)
  menu.options.test_parameter = True

"""
Print the non-listed parameters.
"""
def print_non_listed_params(check_parameters, http_request_method, header_name):
  
  if settings.TEST_PARAMETER:
    testable_parameters = ",".join(settings.TEST_PARAMETER).replace(" ","")
    testable_parameters = testable_parameters.split(",")
    non_exist_param = list(set(testable_parameters) - set(check_parameters))
    if non_exist_param:
      non_exist_param = ",".join(non_exist_param).replace(" ","")
      non_exist_param = non_exist_param.split(",")
      if menu.options.level >= 2:
        if settings.COOKIE_DELIMITER in menu.options.cookie:
          cookies = menu.options.cookie.split(settings.COOKIE_DELIMITER)
          for cookie in cookies:
            if cookie.split("=")[0].strip() in menu.options.test_parameter:
              try:
                non_exist_param.remove(cookie.split("=")[0].strip())
              except ValueError:
                pass 
        elif menu.options.cookie.split("=")[0] in menu.options.test_parameter:
          try:
            non_exist_param.remove(menu.options.cookie.split("=")[0])
          except ValueError:
            pass 
        for http_header in settings.HTTP_HEADERS:
          if http_header in non_exist_param: 
            non_exist_param.remove(http_header)

      if non_exist_param:
        non_exist_param_items = ",".join(non_exist_param)
        warn_msg = "Skipping tests for "
        warn_msg += "the provided parameter" + "s"[len(non_exist_param) == 1:][::-1] + " '" 
        warn_msg += non_exist_param_items + "' as" + (' they are', ' it is')[len(non_exist_param) == 1]
        if menu.options.level >= 2 and header_name != "":
          warn_msg += " not part of the "
          warn_msg +=  settings.HTTP_HEADER
        else:
          warn_msg += " not part of the "
          warn_msg += http_request_method   
          warn_msg += (' data', ' request')[http_request_method == "GET"] 
        warn_msg += "."
        print settings.print_warning_msg(warn_msg)

  if menu.options.skip_parameter != None:
    check_skipped_params(check_parameters)


# """
# Check for whitespaces
# """
# def check_whitespaces():
#   if settings.WHITESPACE[0] != "%20" and settings.WHITESPACE[0] != urllib.unquote("%20"):
#     warn_msg = "Whitespaces are important for time-relative techniques, "
#     warn_msg += "thus whitespace characters had been reset to default."
#     print settings.print_warning_msg(warn_msg)
#   if settings.WHITESPACE[0] != urllib.unquote("%20"):
#     whitespace = " "
#     return whitespace  

"""
Check for loaded tamper scripts
"""
# def loaded_tamper_scripts():
#   try:
#     menu.options.tamper.lower()
#     info_msg = "Loaded tamper script(s): "
#     print settings.print_info_msg(info_msg)
#     # Check the provided tamper script(s)
#     for tfile in re.split(settings.PARAMETER_SPLITTING_REGEX, menu.options.tamper.lower()):
#       print settings.SUB_CONTENT_SIGN + tfile
#   except:
#     pass

"""
Tamper script checker
"""
def tamper_scripts():
  if menu.options.tamper:
    info_msg = "Loading tamper script(s): "
    print settings.print_info_msg(info_msg)
    # Check the provided tamper script(s)
    tamper_script_counter = 0
    for tfile in re.split(settings.PARAMETER_SPLITTING_REGEX, menu.options.tamper.lower()):
      if "hexencode" or "base64encode" == tfile:
        settings.MULTI_ENCODED_PAYLOAD.append(tfile)

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

"""
Check if the payload output seems to be hex.
"""
def hex_output(payload):
  if not settings.TAMPER_SCRIPTS['hexencode']:
    if menu.options.tamper:
      menu.options.tamper = menu.options.tamper + ",hexencode"
    else:
      menu.options.tamper = "hexencode"

"""
Check if the payload output seems to be base64.
"""
def base64_output(payload):
  if not settings.TAMPER_SCRIPTS['base64encode']:
    if menu.options.tamper:
      menu.options.tamper = menu.options.tamper + ",base64encode"
    else:
      menu.options.tamper = "base64encode"

"""
Check for modified whitespaces.
"""
def whitespace_check(payload):
  if "${IFS}" in payload:
    settings.WHITESPACE[0] = "${IFS}"
    if not settings.TAMPER_SCRIPTS['space2ifs']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",space2ifs"
      else:
        menu.options.tamper = "space2ifs"
  else:
    count_plus = payload.count("+")
    if count_plus >= 2 and not "%20" in payload:
      if not settings.TAMPER_SCRIPTS['space2plus']:
        if menu.options.tamper:
          menu.options.tamper = menu.options.tamper + ",space2plus"
        else:
          menu.options.tamper = "space2plus"
    else:
      count_htabs = payload.count("%09")
      count_vtabs = payload.count("%0b")
      if count_htabs >= 1 and not "%20" in payload:
        if not settings.TAMPER_SCRIPTS['space2htab']:
          if menu.options.tamper:
            menu.options.tamper = menu.options.tamper + ",space2htab"
          else:
            menu.options.tamper = "space2htab"  
      elif count_vtabs >= 1 and not "%20" in payload:
        if not settings.TAMPER_SCRIPTS['space2vtab']:
          if menu.options.tamper:
            menu.options.tamper = menu.options.tamper + ",space2vtab"
          else:
            menu.options.tamper = "space2vtab"
      else:
        settings.WHITESPACE[0] = "%20" 

"""
Recognise the payload.
"""
def recognise_payload(payload):
  is_decoded = False
  if (len(payload) % 4 == 0) and \
    re.match(settings.BASE64_RECOGNITION_REGEX, payload) and \
    not re.match(settings.HEX_RECOGNITION_REGEX, payload):
      is_decoded = True
      settings.MULTI_ENCODED_PAYLOAD.append("base64encode")
      decoded_payload = base64.b64decode(payload)
      if re.match(settings.HEX_RECOGNITION_REGEX, payload):
        settings.MULTI_ENCODED_PAYLOAD.append("hexencode")
        decoded_payload = decoded_payload.decode("hex")

  elif re.match(settings.HEX_RECOGNITION_REGEX, payload):
    is_decoded = True
    settings.MULTI_ENCODED_PAYLOAD.append("hexencode")
    decoded_payload = payload.decode("hex")
    if (len(payload) % 4 == 0) and \
      re.match(settings.BASE64_RECOGNITION_REGEX, decoded_payload) and \
      not re.match(settings.HEX_RECOGNITION_REGEX, decoded_payload):
        settings.MULTI_ENCODED_PAYLOAD.append("base64encode")
        decoded_payload = base64.b64decode(decoded_payload)

  for encode_type in settings.MULTI_ENCODED_PAYLOAD:
    # Encode payload to base64 format.
    if encode_type == 'base64encode':
      base64_output(payload)
    # Encode payload to hex format.
    if encode_type == 'hexencode':
      hex_output(payload)

  if is_decoded:
    return urllib.quote(decoded_payload)  
  else:
    return payload

"""
Check for stored payloads and enable tamper scripts.
"""
def check_for_stored_tamper(payload):
  decoded_payload = recognise_payload(payload)
  whitespace_check(decoded_payload)
  tamper_scripts()


"""
Perform base64 / hex encoding in payload.
"""
def perform_payload_encoding(payload):
  for encode_type in settings.MULTI_ENCODED_PAYLOAD[::-1]:
    # Encode payload to hex format.    
    if encode_type == 'base64encode':
      from src.core.tamper import base64encode
      payload = base64encode.encode(payload)

    # Encode payload to hex format.
    if encode_type == 'hexencode':
      from src.core.tamper import hexencode
      payload = hexencode.encode(payload)

  return payload

#eof