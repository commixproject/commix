#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2021 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
 
For more see the file 'readme/COPYING' for copying permission.
"""

import io
import re
import os
import sys
import glob
import json
import socket
import random
import string
import base64
import gzip
import traceback
from src.utils import menu
from src.utils import settings
from src.utils import simple_http_server
from collections import OrderedDict 
from src.core.convert import hexdecode
from src.thirdparty.six.moves import input as _input
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.colorama import Fore, Back, Style, init
from src.thirdparty.flatten_json.flatten_json import flatten, unflatten_list

# If the value has boundaries.
def value_boundaries(value):
  if not menu.options.batch:
    question_msg =  "It appears that the value '" + value + "' has boundaries. "
    question_msg += "Do you want to inject inside? [Y/n] > "
    procced_option = _input(settings.print_question_msg(question_msg))
  else:
    procced_option = ""
  if procced_option in settings.CHOICE_YES or len(procced_option) == 0:
    value = value.replace(re.search(settings.VALUE_BOUNDARIES, value).group(0), "")
  elif procced_option in settings.CHOICE_NO:
    pass
  elif procced_option in settings.CHOICE_QUIT:
    raise SystemExit()
  else:
    err_msg = "'" + procced_option + "' is not a valid answer."  
    print(settings.print_error_msg(err_msg))
    pass
  return value

# Ignoring the anti-CSRF parameter(s).
def ignore_anticsrf_parameter(parameter):
  if any(parameter.lower().count(token) for token in settings.CSRF_TOKEN_PARAMETER_INFIXES):
    info_msg = "Ignoring the parameter '" + parameter.split("=")[0]
    info_msg += "' that appears to hold anti-CSRF token '" + parameter.split("=")[1] +  "'." 
    print(settings.print_info_msg(info_msg))
    return True

# Ignoring the Google analytics cookie parameter.
def ignore_google_analytics_cookie(cookie):
  if cookie.upper().startswith(settings.GOOGLE_ANALYTICS_COOKIE_PREFIX):
    info_msg = "Ignoring the Google analytics cookie parameter '" + cookie.split("=")[0] + "'."
    print(settings.print_info_msg(info_msg))
    return True

"""
Fix for %0a, %0d%0a separators
"""
def newline_fixation(payload):
  payload = _urllib.parse.unquote(payload)
  if "\n" in payload:
    #_ = payload.find("\n") + 1
    #payload = _urllib.parse.quote(payload[:_]) + payload[_:]
    payload = payload.replace("\n","%0a")
  if "\r" in payload:
    #_ = payload.find("\r\n") + 1
    #payload = _urllib.parse.quote(payload[:_]) + payload[_:]  
    payload = payload.replace("\r","%0d")
  return payload

"""
Page enc/decoding
"""
def page_encoding(response, action):
  _ = False
  if response.info().get('Content-Encoding') in ("gzip", "deflate"):
    if response.info().get('Content-Encoding') == 'deflate':
      data = io.BytesIO(zlib.decompress(response.read(), -15))
    elif response.info().get('Content-Encoding') == 'gzip':
      data = gzip.GzipFile("", "rb", 9, io.BytesIO(response.read()))
    page = data.read()
  else:
    page = response.read()
  try:
    if action == "encode" and type(page) == str:
      return page.encode(settings.UNICODE_ENCODING)
    else:
      return page.decode(settings.UNICODE_ENCODING)
  except (UnicodeEncodeError, UnicodeDecodeError) as err:
    err_msg = "The " + str(err).split(":")[0] + ". "
    _ = True
  except LookupError as err:
    err_msg = "The '" + settings.DEFAULT_PAGE_ENCODING + "' is " + str(err).split(":")[0] + ". "
    _ = True
  except AttributeError:
    pass
  if _:
    err_msg += "You are advised to rerun with"
    err_msg += ('out', '')[menu.options.encoding == None] + " the option '--encoding'."
    print(settings.print_critical_msg(str(err_msg)))
    raise SystemExit()

"""
Returns header value ignoring the letter case
"""
def get_header(headers, key):
  value = None
  for _ in (headers or {}):
    if _.upper() == key.upper():
      value = headers[_]
      break
  return value

"""
Checks regarding a recognition of generic "your ip has been blocked" messages.
"""
def blocked_ip(page):
  if re.search(settings.BLOCKED_IP_REGEX, page):
    warn_msg = "It appears that you have been blocked by the target server."
    print(settings.print_bold_warning_msg(warn_msg))

"""
Checks regarding a potential browser verification protection mechanism.
"""
def browser_verification(page):
  if not settings.BROWSER_VERIFICATION and re.search(r"(?i)browser.?verification", page or ""):
    settings.BROWSER_VERIFICATION = True
    warn_msg = "Potential browser verification protection mechanism detected"
    if re.search(r"(?i)CloudFlare", page):
      warn_msg += " (CloudFlare)."
    else:
      warn_msg += "."
    print(settings.print_bold_warning_msg(warn_msg))

"""
Checks regarding a potential CAPTCHA protection mechanism.
"""
def captcha_check(page):
  if not settings.CAPTCHA_DETECED and re.search(r"(?i)captcha", page or ""):
    for match in re.finditer(r"(?si)<form.+?</form>", page):
      if re.search(r"(?i)captcha", match.group(0)):
        settings.CAPTCHA_DETECED = True
        warn_msg = "Potential CAPTCHA protection mechanism detected"
        if re.search(r"(?i)<title>[^<]*CloudFlare", page):
          warn_msg += " (CloudFlare)."
        else:
          warn_msg += "."
        print(settings.print_bold_warning_msg(warn_msg))
        break
        
"""
Counting the total of HTTP(S) requests for the identified injection point(s), during the detection phase.
"""
def total_of_requests():
  debug_msg = "Identified the following injection point with "
  debug_msg += "a total of " + str(settings.TOTAL_OF_REQUESTS) + " HTTP(S) requests."
  print(settings.print_bold_debug_msg(debug_msg))

"""
Url decode specific chars of the provided payload.
"""
def url_decode(payload):
  rep = {
          "%20": " ", 
          "%2B": "+",
          "\n": "\\n"
        }
  rep = dict((re.escape(k), v) for k, v in rep.items())
  pattern = re.compile("|".join(rep.keys()))
  payload = pattern.sub(lambda m: rep[re.escape(m.group(0))], payload)
  return payload

"""
Checking connection (resolving hostname).
"""
def check_connection(url):
  hostname = _urllib.parse.urlparse(url).hostname or ''
  if not re.search(r"\A\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\Z", hostname):
    if not any((menu.options.proxy, menu.options.tor, menu.options.offline)):
      try:
        info_msg = "Resolving hostname '" + hostname + "'."
        print(settings.print_info_msg(info_msg))
        socket.getaddrinfo(hostname, None)
      except socket.gaierror:
        err_msg = "Host '" + hostname + "' does not exist."
        print(settings.print_critical_msg(err_msg))
        raise SystemExit()
      except socket.error as err:
        err_msg = "Problem occurred while "
        err_msg += "resolving a host name '" + hostname + "'"
        print(settings.print_critical_msg(err_msg))
        raise SystemExit()

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

  # Checking testable HTTP headers for user-agent / referer / host
  if "user-agent" in menu.options.test_parameter or \
     "referer" in menu.options.test_parameter or \
     "host" in menu.options.test_parameter:
    menu.options.level = 3

"""
Procced to the next attack vector.
"""
def next_attack_vector(technique, go_back):
  while True:
    if not menu.options.batch:
      question_msg = "Continue with testing the " + technique + "? [Y/n] > "
      next_attack_vector = _input(settings.print_question_msg(question_msg))
    else:
      next_attack_vector = ""
    if len(next_attack_vector) == 0:
       next_attack_vector = "Y"
    if next_attack_vector in settings.CHOICE_YES:
      # Check injection state
      assessment_phase()
      return True
    elif next_attack_vector in settings.CHOICE_NO:
      return  False
    elif next_attack_vector in settings.CHOICE_QUIT:
      raise SystemExit()
    else:
      err_msg = "'" + next_attack_vector + "' is not a valid answer."  
      print(settings.print_error_msg(err_msg))
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
Removing the first and/or last line of the html content (in case there are/is empty).
"""
def remove_empty_lines(content):
  try:
    if content[0] == "\n": 
      content = content[1:content.rfind("\n")]
    if content[-1] == "\n":
      content = content[:content.rfind("\n")]
  except IndexError:
    pass    
  return content

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
      enable_fb = _input(settings.print_question_msg(question_msg))
    else:
      enable_fb = ""
    if len(enable_fb) == 0:
       enable_fb = "Y"
    if enable_fb in settings.CHOICE_YES:
      return True
    elif enable_fb in settings.CHOICE_NO:
      return False
    elif enable_fb in settings.CHOICE_QUIT:
      raise SystemExit()
    else:
      err_msg = "'" + enable_fb + "' is not a valid answer."  
      print(settings.print_error_msg(err_msg))
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
  # Ignoring (problematic) HTTP error codes.
  if menu.options.ignore_code:
    for error_code in settings.HTTP_ERROR_CODES:
      if menu.options.ignore_code == error_code:
        settings.WAF_ENABLED = True
        return True

  # Possible WAF/IPS/IDS
  if (str(err.code) == settings.FORBIDDEN_ERROR or settings.NOT_ACCEPTABLE_ERROR) and \
    not menu.options.skip_waf and \
    not settings.HOST_INJECTION :
    # Check if "--skip-waf" option is defined 
    # that skips heuristic detection of WAF/IPS/IDS protection.
    settings.WAF_ENABLED = True
    warn_msg = "It seems that target is protected by some kind of WAF/IPS/IDS."
    print(settings.print_warning_msg(warn_msg))

  try:
    while True:
      if not menu.options.batch:
        question_msg = "Do you want to ignore the error (" + str(err.code) 
        question_msg += ") message and continue the tests? [Y/n] > "
        continue_tests = _input(settings.print_question_msg(question_msg))
      else:
        continue_tests = ""
      if len(continue_tests) == 0:
         continue_tests = "Y"
      if continue_tests in settings.CHOICE_YES:
        return True
      elif continue_tests in settings.CHOICE_NO:
        return False
      elif continue_tests in settings.CHOICE_QUIT:
        return False
      else:
        err_msg = "'" + continue_tests + "' is not a valid answer."  
        print(settings.print_error_msg(err_msg))
        pass
  except KeyboardInterrupt:
    print("\n") + Back.RED + settings.ABORTION_SIGN + "Ctrl-C was pressed!" + Style.RESET_ALL
    raise SystemExit()

"""
Check if option is unavailable
"""
def unavailable_option(check_option):
  warn_msg = "The '" + check_option + "' option "
  warn_msg += "is not yet available for windows targets."
  print(settings.print_warning_msg(warn_msg))  

"""
Transformation of separators if time-based injection
"""
def time_based_separators(separator, http_request_method):
  if separator == "||"  or separator == "&&" :
    separator = separator[:1]
    if http_request_method == "POST":
      separator = _urllib.parse.quote(separator)
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
  print(settings.print_critical_msg(err_msg)) 

"""
Check for incompatible OS (i.e Unix).
"""
def ps_incompatible_os():
  if not settings.TARGET_OS == "win":
    warn_msg = "The identified OS seems incompatible with the provided '--ps-version' switch."
    print(settings.print_warning_msg(warn_msg))
    return True

"""
Check if PowerShell is enabled.
"""
def ps_check():
  if settings.PS_ENABLED == None and menu.options.is_admin or menu.options.users or menu.options.passwords:
    if settings.VERBOSITY_LEVEL != 0:
      print("")
    warn_msg = "The payloads in some options that you "
    warn_msg += "have chosen, are requiring the use of PowerShell. "
    print(settings.print_warning_msg(warn_msg))
    while True:
      if not menu.options.batch:
        question_msg = "Do you want to use the \"--ps-version\" option "
        question_msg += "so ensure that PowerShell is enabled? [Y/n] > "
        ps_check = _input(settings.print_question_msg(question_msg))
      else:
        ps_check = ""
      if len(ps_check) == 0:
         ps_check = "Y"
      if ps_check in settings.CHOICE_YES:
        menu.options.ps_version = True
        break
      elif ps_check in settings.CHOICE_NO:
        break
      elif ps_check in settings.CHOICE_QUIT:
        print("")
        os._exit(0)
      else:  
        err_msg = "'" + ps_check + "' is not a valid answer."  
        print(settings.print_error_msg(err_msg))
        pass

"""
If PowerShell is disabled.
"""
def ps_check_failed():
  while True:
    if not menu.options.batch:
      question_msg = "Do you want to ignore the above warning "
      question_msg += "and continue the procedure? [Y/n] > "
      ps_check = _input(settings.print_question_msg(question_msg))
    else:
      ps_check = ""
    if len(ps_check) == 0:
       ps_check = "Y"
    if ps_check in settings.CHOICE_YES:
      break
    elif ps_check in settings.CHOICE_NO:
      print("")
      os._exit(0)
    else:  
      err_msg = "'" + ps_check + "' is not a valid answer."  
      print(settings.print_error_msg(err_msg))
      pass

"""
Check if CGI scripts (shellshock injection).
"""
def check_CGI_scripts(url):
  try:
    CGI_SCRIPTS = []
    if not os.path.isfile(settings.CGI_SCRIPTS ):
      err_msg = "The pages / scripts list (" + settings.CGI_SCRIPTS  + ") is not found"
      print(settings.print_critical_msg(err_msg))
      raise SystemExit() 
    if len(settings.CGI_SCRIPTS ) == 0:
      err_msg = "The " + settings.CGI_SCRIPTS  + " list is empty."
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()
    with open(settings.CGI_SCRIPTS , "r") as f: 
      for line in f:
        line = line.strip()
        CGI_SCRIPTS.append(line)
  except IOError: 
    err_msg = " Check if the " + settings.CGI_SCRIPTS  + " list is readable or corrupted."
    print(settings.print_critical_msg(err_msg))
    raise SystemExit()

  for cgi_script in CGI_SCRIPTS:
    if cgi_script in url and menu.options.shellshock == False:
      warn_msg = "URL is probable to contain a script ('" + cgi_script + "') "
      warn_msg += "vulnerable to shellshock. "
      print(settings.print_warning_msg(warn_msg))
      while True:
        if not menu.options.batch:
          question_msg = "Do you want to enable the shellshock injection module? [Y/n] > "
          shellshock_check = _input(settings.print_question_msg(question_msg))
        else:
          shellshock_check = ""   
        if len(shellshock_check) == 0:
           shellshock_check = "Y"
        if shellshock_check in settings.CHOICE_YES:
          menu.options.shellshock = True
          break
        elif shellshock_check in settings.CHOICE_NO:
          menu.options.shellshock = False
          break
        elif shellshock_check in settings.CHOICE_QUIT:
          print("")
          os._exit(0)
        else:  
          err_msg = "'" + shellshock_check + "' is not a valid answer."  
          print(settings.print_error_msg(err_msg))
          pass

"""
Check if http / https.
"""
def check_http_s(url):
  if settings.CHECK_INTERNET:
      url = settings.CHECK_INTERNET_ADDRESS
  else:
    try:
      if re.search(r'^(?:http)s?://', url, re.I):
        if not re.search(r"^https?://", url, re.I) and not re.search(r"^wss?://", url, re.I):
          if re.search(r":443\b", url):
            url = "https://" + url
          else:
            url = "http://" + url
        settings.SCHEME = (_urllib.parse.urlparse(url).scheme.lower() or "http") if not menu.options.force_ssl else "https"
        if menu.options.force_ssl and settings.VERBOSITY_LEVEL != 0:
          debug_msg = "Forcing usage of SSL/HTTPS requests."
          print(settings.print_debug_msg(debug_msg))
      else:
        err_msg = "Invalid target URL has been given." 
        print(settings.print_critical_msg(err_msg))
        raise SystemExit()
    except ValueError as err:
      err_msg = "Invalid target URL has been given." 
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()
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
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()

"""
Decision if the user-defined operating system name, 
is different than the one identified by heuristics.
"""
def identified_os():
    if not menu.options.batch:
      warn_msg = "Heuristics have identified different operating system (" 
      warn_msg += settings.TARGET_OS + ") than that you have provided." 
      print(settings.print_warning_msg(warn_msg))
      question_msg = "How do you want to proceed? [(C)ontinue/(s)kip/(q)uit] > "
      proceed_option = _input(settings.print_question_msg(question_msg))
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
      print(settings.print_error_msg(err_msg))
      pass

"""
Check for third-party (non-core) libraries.
"""
def third_party_dependencies():
  info_msg = "Checking for third-party (non-core) libraries. "
  sys.stdout.write(settings.print_info_msg(info_msg))
  sys.stdout.flush()
  
  try:
    import sqlite3
  except ImportError:
    print(settings.FAIL_STATUS)
    err_msg = settings.APPLICATION + " requires 'sqlite3' third-party library "
    err_msg += "in order to store previous injection points and commands. "
    print(settings.print_critical_msg(err_msg))
    raise SystemExit()

  try:
    import readline
  except ImportError:
    if settings.IS_WINDOWS:
      try:
        import pyreadline
      except ImportError:
        print(settings.FAIL_STATUS)
        err_msg = settings.APPLICATION + " requires 'pyreadline' third-party library "
        err_msg += "in order to be able to take advantage of the TAB "
        err_msg += "completion and history support features. "
        print(settings.print_critical_msg(err_msg)) 
        raise SystemExit()
    else:
      try:
        import gnureadline
      except ImportError:
        print(settings.FAIL_STATUS)
        err_msg = settings.APPLICATION + " requires 'gnureadline' third-party library "
        err_msg += "in order to be able to take advantage of the TAB "
        err_msg += "completion and history support features. "
        print(settings.print_critical_msg(err_msg))
    pass

  print(settings.SUCCESS_STATUS)
  info_msg = "All required third-party (non-core) libraries are seems to be installed."
  print(settings.print_bold_info_msg(info_msg))

"""
Print the authentiation error message.
"""
def http_auth_err_msg():
  err_msg = "Use the '--auth-cred' option to provide a valid pair of " 
  err_msg += "HTTP authentication credentials (i.e --auth-cred=\"admin:admin\")" 
  err_msg += " or use the '--ignore-code=401' option to ignore HTTP error 401 (Unauthorized)" 
  err_msg += " and continue tests without providing valid credentials."
  print(settings.print_critical_msg(err_msg)) 
  raise SystemExit()

"""
Decision if the user-defined HTTP authenticatiob type, 
is different than the one identified by heuristics.
"""
def identified_http_auth_type(auth_type):
  if not menu.options.batch:
    warn_msg = "Heuristics have identified different HTTP authentication type (" 
    warn_msg += auth_type.lower() + ") than that you have provided ("
    warn_msg += menu.options.auth_type + ")." 
    print(settings.print_warning_msg(warn_msg))
    question_msg = "How do you want to proceed? [(C)ontinue/(s)kip/(q)uit] > "
    proceed_option = _input(settings.print_question_msg(question_msg))
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
    print(settings.print_error_msg(err_msg))
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
  _ = ""
  for data in data.split("\\n"):
    # Ignore the Accept HTTP Header
    if not data.startswith("Accept: ") and settings.WILDCARD_CHAR in data :
      data = data.replace(settings.WILDCARD_CHAR, settings.INJECT_TAG)
    _ = _ + data + "\\n"
  data = _.rstrip("\\n")
  if data.count(settings.INJECT_TAG) > 1:
    err_msg = "You specified more than one injecton markers. " 
    err_msg += "Use the '-p' option to define them (i.e -p \"id1,id2\"). "
    print(settings.print_critical_msg(err_msg)) 
    raise SystemExit()
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
      if menu.options.level >= 2 and \
         menu.options.test_parameter != None:
        if menu.options.cookie != None: 
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
            
      # Remove the defined HTTP headers      
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
          warn_msg += ('', ' (JSON)')[settings.IS_JSON] + ('', ' (SOAP/XML)')[settings.IS_XML]  
          warn_msg += (' data', ' request')[http_request_method == "GET"] 
        warn_msg += "."
        print(settings.print_warning_msg(warn_msg))

  if menu.options.skip_parameter != None:
    check_skipped_params(check_parameters)

"""
Lists available tamper scripts
"""
def list_tamper_scripts():
  info_msg = "Listing available tamper scripts:"
  print(settings.print_info_msg(info_msg))
  if menu.options.list_tampers:
    for script in sorted(glob.glob(os.path.join(settings.TAMPER_SCRIPTS_PATH, "*.py"))):
      content = open(script, "rb").read().decode(settings.UNICODE_ENCODING)
      match = re.search(r"About:(.*)\n", content)
      if match:
        comment = match.group(1).strip()
        sub_content = Fore.MAGENTA + os.path.basename(script) + Style.RESET_ALL +  " - " + comment
        print(settings.print_sub_content(sub_content))

"""
Tamper script checker
"""
def tamper_scripts():
  if menu.options.tamper:
    # Check the provided tamper script(s)
    available_scripts = []
    provided_scripts = list(set(re.split(settings.PARAMETER_SPLITTING_REGEX, menu.options.tamper.lower())))
    for script in sorted(glob.glob(os.path.join(settings.TAMPER_SCRIPTS_PATH, "*.py"))):
      available_scripts.append(os.path.basename(script.split(".py")[0]))
    for script in provided_scripts:
      if script in available_scripts:
        pass
      else:
        err_msg = "The '" + script + "' tamper script does not exist. "
        err_msg += "Use the '--list-tampers' option for listing available tamper scripts."
        print(settings.print_critical_msg(err_msg))
        raise SystemExit()

    info_msg = "Loading tamper script" + ('s', '')[len(provided_scripts) == 1] + ": "
    print(settings.print_info_msg(info_msg))
    for script in provided_scripts:
      if "hexencode" or "base64encode" == script:
        settings.MULTI_ENCODED_PAYLOAD.append(script)
      import_script = str(settings.TAMPER_SCRIPTS_PATH + script + ".py").replace("/",".").split(".py")[0]
      print(settings.SUB_CONTENT_SIGN + import_script.split(".")[3])
      try:
        module = __import__(import_script, fromlist=[None])
        if not hasattr(module, "__tamper__"):
          err_msg = "Missing variable '__tamper__' "
          err_msg += "in tamper script '" + import_script.split(".")[0] + "'."
          print(settings.print_critical_msg(err_msg))
          raise SystemExit()
      except ImportError as err_msg:
        print(settings.print_error_msg(str(err_msg) + "."))
        pass

    # Using too many tamper scripts is usually not a good idea. :P
    _ = False
    if len(provided_scripts) >= 3 and not settings.LOAD_SESSION:
      warn_msg = "Using too many tamper scripts "
      _ = True
    elif len([x for x in provided_scripts if any(y in x for y in ["nested", "doublequotes"])]) == 2 and not settings.LOAD_SESSION:
      _ = True
      warn_msg = "The combination of the provided tamper scripts "
    if _:
      warn_msg += "is not a good idea (may cause false positive results)."
      print(settings.print_warning_msg(warn_msg))

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

  _ = []
  whitespaces = ["${IFS}", "+", "%09", "%0b", "%20"]
  for whitespace in whitespaces:
    if whitespace in payload:
      _.append(whitespace)

  # Enable the "space2ifs" tamper script.
  if "${IFS}" in _:
    if not settings.TAMPER_SCRIPTS['space2ifs']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",space2ifs"
      else:
        menu.options.tamper = "space2ifs"
    settings.WHITESPACE[0] = "${IFS}"  
  
  # Enable the "space2plus" tamper script.
  elif "+" in _ and payload.count("+") >= 2:
    if not settings.TAMPER_SCRIPTS['space2plus']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",space2plus"
      else:
        menu.options.tamper = "space2plus"
    settings.WHITESPACE[0] = "+"
  
  # Enable the "space2htab" tamper script.
  elif "%09" in _:
    if not settings.TAMPER_SCRIPTS['space2htab']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",space2htab"
      else:
        menu.options.tamper = "space2htab" 
    settings.WHITESPACE[0] = "%09"

  # Enable the "space2vtab" tamper script.
  elif "%0b" in _:
    if not settings.TAMPER_SCRIPTS['space2vtab']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",space2vtab"
      else:
        menu.options.tamper = "space2vtab"
    settings.WHITESPACE[0] = "%0b"
  
  # Default whitespace       
  else :
    settings.WHITESPACE[0] = "%20"

  # Enable the "multiplespaces" tamper script.
  count_spaces = payload.count(settings.WHITESPACE[0])
  if count_spaces >= 5:
    if menu.options.tamper:
      menu.options.tamper = menu.options.tamper + ",multiplespaces"
    else:
      menu.options.tamper = "multiplespaces" 
    settings.WHITESPACE[0] = settings.WHITESPACE[0] * int(count_spaces / 2)
      
"""
Check for added caret between the characters of the generated payloads.
"""
def other_symbols(payload):
  # Check for caret symbol
  if payload.count("^") >= 10:
    if not settings.TAMPER_SCRIPTS['caret']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",caret"
      else:
        menu.options.tamper = "caret"  
    from src.core.tamper import caret
    payload = caret.tamper(payload)

  # Check for dollar sign followed by an at-sign
  if payload.count("$@") >= 10:
    if not settings.TAMPER_SCRIPTS['dollaratsigns']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",dollaratsigns"
      else:
        menu.options.tamper = "dollaratsigns"  
    from src.core.tamper import dollaratsigns
    payload = dollaratsigns.tamper(payload)

  # Check for uninitialized variable
  if payload.count("$u") >= 2:
    if not settings.TAMPER_SCRIPTS['uninitializedvariable']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",uninitializedvariable"
      else:
        menu.options.tamper = "uninitializedvariable"  
    from src.core.tamper import uninitializedvariable
    payload = uninitializedvariable.tamper(payload)

"""
Check for (multiple) added back slashes between the characters of the generated payloads.
"""
def check_backslashes(payload):
  # Check for single quotes
  if payload.count("\\") >= 15:
    if not settings.TAMPER_SCRIPTS['backslashes']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",backslashes"
      else:
        menu.options.tamper = "backslashes"  
    from src.core.tamper import backslashes
    payload = backslashes.tamper(payload)

"""
Check for quotes in the generated payloads.
"""
def check_quotes(payload):
  # Check for double quotes around of the generated payloads.
  if payload.endswith("\""):
    if not settings.TAMPER_SCRIPTS['nested']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",nested"
      else:
        menu.options.tamper = "nested"  
    from src.core.tamper import nested
    payload = nested.tamper(payload)

  # Check for (multiple) added double-quotes between the characters of the generated payloads.
  if payload.count("\"") >= 10:
    if not settings.TAMPER_SCRIPTS['doublequotes']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",doublequotes"
      else:
        menu.options.tamper = "doublequotes"  
    from src.core.tamper import doublequotes
    payload = doublequotes.tamper(payload)

  # Check for (multiple) added single-quotes between the characters of the generated payloads.
  if payload.count("''") >= 10:
    if not settings.TAMPER_SCRIPTS['singlequotes']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",singlequotes"
      else:
        menu.options.tamper = "singlequotes"  
    from src.core.tamper import singlequotes
    payload = singlequotes.tamper(payload)

"""
Recognise the payload.
"""
def recognise_payload(payload):
  if "usleep" in payload:
    if not settings.TAMPER_SCRIPTS['sleep2usleep']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",sleep2usleep"
      else:
        menu.options.tamper = "sleep2usleep"  
    from src.core.tamper import sleep2usleep
    payload = sleep2usleep.tamper(payload)
  
  elif "timeout" in payload:
    if not settings.TAMPER_SCRIPTS['sleep2timeout']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",sleep2timeout"
      else:
        menu.options.tamper = "sleep2timeout"  
    from src.core.tamper import sleep2timeout
    payload = sleep2timeout.tamper(payload)
  
  is_decoded = False
  if (len(payload) % 4 == 0) and \
    re.match(settings.BASE64_RECOGNITION_REGEX, payload) and \
    not re.match(settings.HEX_RECOGNITION_REGEX, payload):
      is_decoded = True
      settings.MULTI_ENCODED_PAYLOAD.append("base64encode")
      decoded_payload = base64.b64decode(payload)
      if re.match(settings.HEX_RECOGNITION_REGEX, payload):
        settings.MULTI_ENCODED_PAYLOAD.append("hexencode")
        decoded_payload = hexdecode(decoded_payload)

  elif re.match(settings.HEX_RECOGNITION_REGEX, payload):
    is_decoded = True
    settings.MULTI_ENCODED_PAYLOAD.append("hexencode")
    decoded_payload = hexdecode(payload)
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
    return _urllib.parse.quote(decoded_payload)  
  else:
    return payload

"""
Check for stored payloads and enable tamper scripts.
"""
def check_for_stored_tamper(payload):
  decoded_payload = recognise_payload(payload)
  whitespace_check(decoded_payload)
  other_symbols(decoded_payload)
  check_quotes(decoded_payload)
  tamper_scripts()

"""
Perform payload modification
"""
def perform_payload_modification(payload):
  for encode_type in list(set(settings.MULTI_ENCODED_PAYLOAD[::-1])):
    # sleep to usleep
    if encode_type == 'sleep2timeout':
      from src.core.tamper import sleep2timeout
      payload = sleep2timeout.tamper(payload)
    # sleep to usleep
    if encode_type == 'sleep2usleep':
      from src.core.tamper import sleep2usleep
      payload = sleep2usleep.tamper(payload)
    # Add uninitialized variable.
    elif encode_type == 'uninitializedvariable':
      from src.core.tamper import uninitializedvariable
      payload = uninitializedvariable.tamper(payload) 
    # Add double-quotes.
    if encode_type == 'doublequotes':
      from src.core.tamper import doublequotes
      payload = doublequotes.tamper(payload)
    # Add single-quotes.
    if encode_type == 'singlequotes':
      from src.core.tamper import singlequotes
      payload = singlequotes.tamper(payload)
    # Add caret symbol.  
    elif encode_type == 'backslashes':
      from src.core.tamper import backslashes
      payload = backslashes.tamper(payload) 
    # Add caret symbol.  
    elif encode_type == 'caret':
      from src.core.tamper import caret
      payload = caret.tamper(payload) 
    # Transfomation to nested command
    elif encode_type == 'nested':
      from src.core.tamper import nested
      payload = nested.tamper(payload) 
    # Add dollar sign followed by an at-sign.
    elif encode_type == 'dollaratsigns':
      from src.core.tamper import dollaratsigns
      payload = dollaratsigns.tamper(payload) 

  for encode_type in list(set(settings.MULTI_ENCODED_PAYLOAD[::-1])):
    # Encode payload to hex format.    
    if encode_type == 'base64encode':
      from src.core.tamper import base64encode
      payload = base64encode.tamper(payload)
    # Encode payload to hex format.
    if encode_type == 'hexencode':
      from src.core.tamper import hexencode
      payload = hexencode.tamper(payload)

  return payload

"""
Skip parameters when the provided value is empty.
"""
def skip_empty(provided_value, http_request_method):
  warn_msg = "The " + http_request_method
  warn_msg += ('', ' (JSON)')[settings.IS_JSON] + ('', ' (SOAP/XML)')[settings.IS_XML]
  warn_msg += " parameter" + "s"[len(provided_value.split(",")) == 1:][::-1]
  warn_msg += " '" + provided_value + "'"
  warn_msg += (' have ', ' has ')[len(provided_value.split(",")) == 1]
  warn_msg += "been skipped from testing"
  warn_msg += " (the provided value" + "s"[len(provided_value.split(",")) == 1:][::-1]
  warn_msg += (' are ', ' is ')[len(provided_value.split(",")) == 1] + "empty). "
  print(settings.print_warning_msg(warn_msg))


"""
Parsing and unflattening json data.
"""
def json_data(data):
  data = json.loads(data, object_pairs_hook=OrderedDict)
  data = unflatten_list(data)
  data = json.dumps(data)
  return data

"""
Check if the provided value is empty.
"""
def is_empty(multi_parameters, http_request_method):
  # if settings.VERBOSITY_LEVEL != 0:
  #   info_msg = "Checking for empty values in provided data."  
  #   print(settings.print_info_msg(info_msg))
  provided_value = []
  multi_params = [s for s in multi_parameters]
  if settings.IS_JSON:
    multi_params = ','.join(multi_params)
    json_data = json.loads(multi_params, object_pairs_hook=OrderedDict)
    multi_params = flatten(json_data)
  for empty in multi_params:
    try:
      if settings.IS_JSON:
        if len(str(multi_params[empty])) == 0:
          provided_value.append(empty)
      elif settings.IS_XML:
        if re.findall(r'>(.*)<', empty)[0] == "" or \
           re.findall(r'>(.*)<', empty)[0] == " ":
          provided_value.append(re.findall(r'</(.*)>', empty)[0])  
      elif len(empty.split("=")[1]) == 0:
        provided_value.append(empty.split("=")[0])
    except IndexError:
      if not settings.IS_XML:
        err_msg = "No parameter(s) found for testing in the provided data."
        print(settings.print_critical_msg(err_msg))
        raise SystemExit() 
  provided_value = ", ".join(provided_value)
  if len(provided_value) > 0:
    if menu.options.skip_empty and len(multi_parameters) > 1:
      skip_empty(provided_value, http_request_method)
    else:
      warn_msg = "The provided value"+ "s"[len(provided_value.split(",")) == 1:][::-1]
      warn_msg += " for " + http_request_method 
      warn_msg += ('', ' (JSON)')[settings.IS_JSON] + ('', ' (SOAP/XML)')[settings.IS_XML] 
      warn_msg += " parameter" + "s"[len(provided_value.split(",")) == 1:][::-1]
      warn_msg += " '" + provided_value + "'"
      warn_msg += (' are ', ' is ')[len(provided_value.split(",")) == 1] + "empty. "
      warn_msg += "Use valid "
      warn_msg += "values to run properly."
      print(settings.print_warning_msg(warn_msg))
      return True

# Check if valid SOAP/XML
def is_XML_check(parameter):
  try:
    if re.search(settings.XML_RECOGNITION_REGEX, parameter):
      return True
  except ValueError as err_msg:
    return False

# Process with SOAP/XML data
def process_xml_data():
  while True:
    info_msg = "SOAP/XML data found in POST data."
    if not menu.options.batch:
      question_msg = info_msg
      question_msg += " Do you want to process it? [Y/n] > "
      xml_process = _input(settings.print_question_msg(question_msg))
    else:
      if settings.VERBOSITY_LEVEL != 0:
        print(settings.print_bold_info_msg(info_msg))
      xml_process = ""
    if len(xml_process) == 0:
       xml_process = "Y"              
    if xml_process in settings.CHOICE_YES:
      settings.IS_XML = True
      break
    elif xml_process in settings.CHOICE_NO:
      break 
    elif xml_process in settings.CHOICE_QUIT:
      raise SystemExit()
    else:
      err_msg = "'" + xml_process + "' is not a valid answer."  
      print(settings.print_error_msg(err_msg))
      pass

#Check if INJECT_TAG is enclosed in quotes (in json data)
def check_quotes_json_data(data):
  if not json.dumps(settings.INJECT_TAG) in data:
    data = data.replace(settings.INJECT_TAG, json.dumps(settings.INJECT_TAG))
  return data

# Check if valid JSON
def is_JSON_check(parameter):
  try:
    json_object = json.loads(parameter)
    if re.search(settings.JSON_RECOGNITION_REGEX, parameter) or \
       re.search(settings.JSON_LIKE_RECOGNITION_REGEX, parameter):
      return True
  except ValueError as err_msg:
    if not "No JSON object could be decoded" in str(err_msg) and \
       not "Expecting value" in str(err_msg):
      err_msg = "JSON " + str(err_msg) + ". "
      print(settings.print_critical_msg(err_msg) + "\n")
      raise SystemExit()
    return False

# Process with JSON data
def process_json_data():
  while True:
    info_msg = "JSON data found in POST data."
    if not menu.options.batch:
      question_msg = info_msg
      question_msg += " Do you want to process it? [Y/n] > "
      json_process = _input(settings.print_question_msg(question_msg))
    else:
      if settings.VERBOSITY_LEVEL != 0:
        print(settings.print_bold_info_msg(info_msg))
      json_process = ""
    if len(json_process) == 0:
       json_process = "Y"              
    if json_process in settings.CHOICE_YES:
      settings.IS_JSON = True
      break
    elif json_process in settings.CHOICE_NO:
      break 
    elif json_process in settings.CHOICE_QUIT:
      raise SystemExit()
    else:
      err_msg = "'" + json_process + "' is not a valid answer."  
      print(settings.print_error_msg(err_msg))
      pass

"""
Check if provided parameters are in inappropriate format.
"""
def inappropriate_format(multi_parameters):
  err_msg = "The provided parameter" + "s"[len(multi_parameters) == 1:][::-1]
  err_msg += (' are ', ' is ')[len(multi_parameters) == 1]
  err_msg += "not in appropriate format."
  print(settings.print_critical_msg(err_msg))
  raise SystemExit()

"""
Check for similarity in provided parameter name and value.
"""
def check_similarities(all_params):
  if settings.IS_JSON:
    all_params = ','.join(all_params)
    json_data = json.loads(all_params, object_pairs_hook=OrderedDict)
    all_params = flatten(json_data)
    for param in all_params:
      if param == all_params[param]:
        parameter_name = param
        all_params[param] = param + settings.RANDOM_TAG
    all_params = [x.replace(" ", "") for x in json.dumps(all_params).split(", ")]
  else:
    for param in range(0, len(all_params)):
      if settings.IS_XML:
        if re.findall(r'</(.*)>', all_params[param]) == re.findall(r'>(.*)</', all_params[param]):
          parameter_name = re.findall(r'>(.*)</', all_params[param])
          parameter_name = ''.join(parameter_name)
          all_params[param] = "<" + parameter_name + ">" + parameter_name + settings.RANDOM_TAG + "</" + parameter_name + ">"
      else:
        if re.findall(r'(.*)=', all_params[param]) == re.findall(r'=(.*)', all_params[param]):
          parameter_name = re.findall(r'=(.*)', all_params[param])
          parameter_name = ''.join(parameter_name)
          all_params[param] = parameter_name + "=" + parameter_name + settings.RANDOM_TAG
  return all_params

"""
Gererate characters pool (for blind command injections)
"""
def generate_char_pool(num_of_chars):
  if menu.options.charset:
    char_pool = [ord(c) for c in menu.options.charset]
  else:
    if num_of_chars == 1:
      # Checks {A..Z},{a..z},{0..9},{Symbols}
      char_pool = list(range(65, 90)) + list(range(96, 122))
    else:
      # Checks {a..z},{A..Z},{0..9},{Symbols}
      char_pool = list(range(96, 122)) + list(range(65, 90))
    char_pool = char_pool + list(range(48, 57)) + list(range(32, 48)) + list(range(90, 96)) + list(range(57, 65))  + list(range(122, 127))
  return char_pool

"""
Check if defined "--file-upload" option.
"""
def file_upload():
  if not re.match(settings.VALID_URL_FORMAT, menu.options.file_upload):
    if not menu.options.file_dest.endswith("/"):
      menu.options.file_dest = menu.options.file_dest + "/"
    # Check if not defined URL for upload.
    while True:
      if not menu.options.batch:
        question_msg = "Do you want to enable an HTTP server? [Y/n] > "
        enable_HTTP_server = _input(settings.print_question_msg(question_msg))
      else:
        enable_HTTP_server = ""
      if len(enable_HTTP_server) == 0:
         enable_HTTP_server = "Y"              
      if enable_HTTP_server in settings.CHOICE_YES:

        # Check if file exists
        if not os.path.isfile(menu.options.file_upload):
          err_msg = "The '" + menu.options.file_upload + "' file, does not exist."
          sys.stdout.write(settings.print_critical_msg(err_msg) + "\n")
          raise SystemExit()

        # Setting the local HTTP server.
        if settings.LOCAL_HTTP_IP == None:
          while True:
            question_msg = "Please enter your interface IP address > "
            ip_addr = _input(settings.print_question_msg(question_msg))
            # check if IP address is valid
            ip_check = simple_http_server.is_valid_ipv4(ip_addr)
            if ip_check == False:
              err_msg = "The provided IP address seems not valid."  
              print(settings.print_error_msg(err_msg))
              pass
            else:
              settings.LOCAL_HTTP_IP = ip_addr
              break

        # Check for invalid HTTP server's port.
        if settings.LOCAL_HTTP_PORT < 1 or settings.LOCAL_HTTP_PORT > 65535:
          err_msg = "Invalid HTTP server's port (" + str(settings.LOCAL_HTTP_PORT) + ")." 
          print(settings.print_critical_msg(err_msg))
          raise SystemExit()
        
        http_server = "http://" + str(settings.LOCAL_HTTP_IP) + ":" + str(settings.LOCAL_HTTP_PORT)
        info_msg = "Setting the HTTP server on '" + http_server + "/'. "  
        print(settings.print_info_msg(info_msg))
        menu.options.file_upload = http_server + "/" + menu.options.file_upload
        simple_http_server.main()
        break

      elif enable_HTTP_server in settings.CHOICE_NO:
        if not re.match(settings.VALID_URL_FORMAT, menu.options.file_upload):
          err_msg = "The '" + menu.options.file_upload + "' is not a valid URL. "
          print(settings.print_critical_msg(err_msg))
          raise SystemExit()
        break  
      elif enable_HTTP_server in settings.CHOICE_QUIT:
        raise SystemExit()
      else:
        err_msg = "'" + enable_HTTP_server + "' is not a valid answer."  
        print(settings.print_error_msg(err_msg))
        pass

"""
Check for wrong flags
"""
def check_wrong_flags():
  if settings.TARGET_OS == "win":
    if menu.options.is_root :
      warn_msg = "Swithing '--is-root' to '--is-admin' because the "
      warn_msg += "target has been identified as windows."
      print(settings.print_warning_msg(warn_msg))
    if menu.options.passwords:
      warn_msg = "The '--passwords' option, is not yet available for Windows targets."
      print(settings.print_warning_msg(warn_msg))  
    if menu.options.file_upload :
      warn_msg = "The '--file-upload' option, is not yet available for windows targets. "
      warn_msg += "Instead, use the '--file-write' option."
      print(settings.print_warning_msg(warn_msg))  
      raise SystemExit()
  else: 
    if menu.options.is_admin : 
      warn_msg = "Swithing the '--is-admin' to '--is-root' because "
      warn_msg += "the target has been identified as unix-like. "
      print(settings.print_warning_msg(warn_msg))

"""
Define python working dir (for windows targets)
"""
def define_py_working_dir():
  if settings.TARGET_OS == "win" and menu.options.alter_shell:
    while True:
      if not menu.options.batch:
        question_msg = "Do you want to use '" + settings.WIN_PYTHON_DIR 
        question_msg += "' as Python working directory on the target host? [Y/n] > "
        python_dir = _input(settings.print_question_msg(question_msg))
      else:
        python_dir = ""  
      if len(python_dir) == 0:
         python_dir = "Y" 
      if python_dir in settings.CHOICE_YES:
        break
      elif python_dir in settings.CHOICE_NO:
        question_msg = "Please provide a custom working directory for Python (e.g. '" 
        question_msg += settings.WIN_PYTHON_DIR + "') > "
        settings.WIN_PYTHON_DIR = _input(settings.print_question_msg(question_msg))
        break
      else:
        err_msg = "'" + python_dir + "' is not a valid answer."  
        print(settings.print_error_msg(err_msg))
        pass
    settings.USER_DEFINED_PYTHON_DIR = True

# eof