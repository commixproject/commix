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
from src.utils import menu
from src.utils import logs
from src.utils import settings
from src.utils import common
from src.utils import session_handler
from src.core.requests import headers
from src.core.requests import requests
from src.core.requests import parameters
from src.core.modules import modules_handler
from src.core.requests import authentication
from src.core.injections.controller import checks
from src.thirdparty.six.moves import input as _input
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.colorama import Fore, Back, Style, init
from src.core.injections.blind.techniques.time_based import tb_handler
from src.core.injections.semiblind.techniques.file_based import fb_handler
from src.core.injections.results_based.techniques.classic import cb_handler
from src.core.injections.results_based.techniques.eval_based import eb_handler

"""
Command Injection and exploitation controller.
Checks if the testable parameter is exploitable.
"""

"""
Check for previously stored sessions.
"""
def check_for_stored_sessions(url, http_request_method):
  if not menu.options.ignore_session:
    if os.path.isfile(settings.SESSION_FILE) and not settings.REQUIRED_AUTHENTICATION:
      if not menu.options.tech:
        settings.SESSION_APPLIED_TECHNIQUES = session_handler.applied_techniques(url, http_request_method)
        menu.options.tech = settings.SESSION_APPLIED_TECHNIQUES
      if session_handler.check_stored_parameter(url, http_request_method):
        if not settings.MULTI_TARGETS or not settings.STDIN_PARSING:
          settings.LOAD_SESSION = True
        return True    
        
"""
Check for previously stored injection level.
"""
def check_for_stored_levels(url, http_request_method):
  if not menu.options.ignore_session:
    if menu.options.level == settings.DEFAULT_INJECTION_LEVEL:
      menu.options.level = session_handler.applied_levels(url, http_request_method)
      if type(menu.options.level) is not int :
        menu.options.level = settings.DEFAULT_INJECTION_LEVEL

"""
Heuristic (basic) tests for command injection
"""
def command_injection_heuristic_basic(url, http_request_method, check_parameter, the_type, header_name, inject_http_headers):
  if menu.options.alter_shell:
    basic_payloads = settings.ALTER_SHELL_BASIC_COMMAND_INJECTION_PAYLOADS
  else:
    basic_payloads = settings.BASIC_COMMAND_INJECTION_PAYLOADS
  settings.CLASSIC_STATE = True
  try:
    whitespace = settings.WHITESPACES[0]
    if not settings.IDENTIFIED_COMMAND_INJECTION or settings.MULTI_TARGETS:  
      _ = 0
      for payload in basic_payloads:
        _ = _ + 1
        if not inject_http_headers or (inject_http_headers and "'Host'" in check_parameter):
          if not any((settings.IS_JSON, settings.IS_XML)) or settings.COOKIE_INJECTION:
            payload = _urllib.parse.quote(payload)
        payload = parameters.prefixes(payload, prefix="")
        payload = parameters.suffixes(payload, suffix="")
        payload = checks.perform_payload_modification(payload).replace(whitespace, settings.WHITESPACES[0])
        if settings.VERBOSITY_LEVEL >= 1:
          print(settings.print_payload(payload))
        data = None
        cookie = None
        tmp_url = url
        if menu.options.cookie and settings.INJECT_TAG in menu.options.cookie:
          cookie = menu.options.cookie.replace(settings.TESTABLE_VALUE + settings.INJECT_TAG, settings.INJECT_TAG).replace(settings.INJECT_TAG, payload).encode(settings.DEFAULT_CODEC)
        elif menu.options.data and http_request_method == settings.HTTPMETHOD.POST or \
             menu.options.data and settings.INJECT_TAG in menu.options.data:
          if inject_http_headers:
            data = menu.options.data.replace(settings.INJECT_TAG,"").encode(settings.DEFAULT_CODEC)
          else: 
            data = menu.options.data.replace(settings.TESTABLE_VALUE + settings.INJECT_TAG, settings.INJECT_TAG).replace(settings.INJECT_TAG, payload).encode(settings.DEFAULT_CODEC)
        else:
          if settings.INJECT_TAG in url:
            tmp_url = url.replace(settings.TESTABLE_VALUE + settings.INJECT_TAG, settings.INJECT_TAG).replace(settings.INJECT_TAG, payload)
        request = _urllib.request.Request(tmp_url, data)
        if cookie:
          request.add_header(settings.COOKIE, cookie)
        if inject_http_headers:
          request.add_header(check_parameter.replace("'","").strip(), (settings.CUSTOM_HEADER_VALUE + payload).encode(settings.DEFAULT_CODEC))
        headers.do_check(request)
        response = requests.get_request_response(request)

        if type(response) is not bool and response is not None:
          html_data = checks.page_encoding(response, action="decode")
          match = re.search(settings.BASIC_COMMAND_INJECTION_RESULT, html_data)
          if match:
            settings.IDENTIFIED_COMMAND_INJECTION = True
            info_msg = "Heuristic (basic) tests shows that "
            info_msg += settings.CHECKING_PARAMETER + " might be injectable (possible OS: '" + ('Unix-like', 'Windows')[_ != 1] + "')." 
            print(settings.print_bold_info_msg(info_msg))
            break

    settings.CLASSIC_STATE = False
    return url

  except (_urllib.error.URLError, _urllib.error.HTTPError) as err_msg:
    print(settings.print_critical_msg(err_msg))
    raise SystemExit()

"""
Heuristic (basic) tests for code injection warnings
"""
def code_injections_heuristic_basic(url, http_request_method, check_parameter, the_type, header_name, inject_http_headers):
  injection_type = "results-based dynamic code evaluation"
  technique = "dynamic code evaluation technique"
  technique = "(" + injection_type.split(settings.SINGLE_WHITESPACE)[0] + ") " + technique + ""
  settings.EVAL_BASED_STATE = True
  try:
    if (not settings.IDENTIFIED_WARNINGS and not settings.IDENTIFIED_PHPINFO) or settings.MULTI_TARGETS:  
      for payload in settings.PHPINFO_CHECK_PAYLOADS:
        if not inject_http_headers or (inject_http_headers and "'Host'" in check_parameter):
          if not any((settings.IS_JSON, settings.IS_XML)) or settings.COOKIE_INJECTION:
            payload = _urllib.parse.quote(payload)
        payload = parameters.prefixes(payload, prefix="")
        payload = parameters.suffixes(payload, suffix="")
        payload = checks.perform_payload_modification(payload)
        if settings.VERBOSITY_LEVEL >= 1:
          print(settings.print_payload(payload))
        data = None
        cookie = None
        tmp_url = url
        if menu.options.cookie and settings.INJECT_TAG in menu.options.cookie:
          cookie = menu.options.cookie.replace(settings.TESTABLE_VALUE + settings.INJECT_TAG, settings.INJECT_TAG).replace(settings.INJECT_TAG, payload).encode(settings.DEFAULT_CODEC)
        elif menu.options.data and http_request_method == settings.HTTPMETHOD.POST or \
             menu.options.data and settings.INJECT_TAG in menu.options.data:
          if inject_http_headers:
            data = menu.options.data.replace(settings.INJECT_TAG,"").encode(settings.DEFAULT_CODEC)
          else: 
            data = menu.options.data.replace(settings.TESTABLE_VALUE + settings.INJECT_TAG, settings.INJECT_TAG).replace(settings.INJECT_TAG, payload).encode(settings.DEFAULT_CODEC)
        else:
          if settings.INJECT_TAG in url:
            tmp_url = url.replace(settings.TESTABLE_VALUE + settings.INJECT_TAG, settings.INJECT_TAG).replace(settings.INJECT_TAG, payload)
        request = _urllib.request.Request(tmp_url, data)
        if cookie:
          request.add_header(settings.COOKIE, cookie)
        if inject_http_headers:
          request.add_header(check_parameter.replace("'","").strip(), (settings.CUSTOM_HEADER_VALUE + payload).encode(settings.DEFAULT_CODEC))
        headers.do_check(request)
        response = requests.get_request_response(request)

        if type(response) is not bool and response is not None:
          html_data = checks.page_encoding(response, action="decode")
          match = re.search(settings.CODE_INJECTION_PHPINFO, html_data)
          if match:
            technique = technique + " (possible PHP version: '" + match.group(1) + "')"
            settings.IDENTIFIED_PHPINFO = True
          else:
            for warning in settings.CODE_INJECTION_WARNINGS:
              if warning in html_data:
                settings.IDENTIFIED_WARNINGS = True
                break
          if settings.IDENTIFIED_WARNINGS or settings.IDENTIFIED_PHPINFO:
            info_msg = "Heuristic (basic) tests shows that "
            info_msg += settings.CHECKING_PARAMETER + " might be injectable via " + technique + "." 
            print(settings.print_bold_info_msg(info_msg))
            break

    settings.EVAL_BASED_STATE = False
    return url

  except (_urllib.error.URLError, _urllib.error.HTTPError) as err_msg:
    print(settings.print_critical_msg(err_msg))
    raise SystemExit()

# Check if it's exploitable via classic command injection technique.
def classic_command_injection_technique(url, timesec, filename, http_request_method):
  injection_type = "results-based OS command injection"
  technique = "classic command injection technique"
  if not settings.SKIP_COMMAND_INJECTIONS:
    if (len(menu.options.tech) == 0 or "c" in menu.options.tech):
      settings.CLASSIC_STATE = None
      if cb_handler.exploitation(url, timesec, filename, http_request_method, injection_type, technique) != False:
        if (len(menu.options.tech) == 0 or "e" in menu.options.tech):
          while True:
            settings.CLASSIC_STATE = True
            message = "Skipping of code injection tests is recommended. "
            message += "Do you agree? [Y/n] > "
            procced_option = common.read_input(message, default="Y", check_batch=True)
            if procced_option in settings.CHOICE_YES:
              settings.SKIP_CODE_INJECTIONS = True
              break
            elif procced_option in settings.CHOICE_NO:
              break
            elif procced_option in settings.CHOICE_QUIT:
              raise SystemExit()
            else:
              common.invalid_option(procced_option)  
              pass
      else:
        settings.CLASSIC_STATE = False
    else:
      if settings.VERBOSITY_LEVEL != 0:   
        debug_msg = "Skipping test the " + "(" + injection_type.split(settings.SINGLE_WHITESPACE)[0] + ") " + technique + ". "
        print(settings.print_debug_msg(debug_msg))

# Check if it's exploitable via dynamic code evaluation technique.   
def dynamic_code_evaluation_technique(url, timesec, filename, http_request_method):
  injection_type = "results-based dynamic code evaluation"
  technique = "dynamic code evaluation technique"
  if not settings.SKIP_CODE_INJECTIONS:
    if (len(menu.options.tech) == 0 or "e" in menu.options.tech) or settings.SKIP_COMMAND_INJECTIONS:
      settings.EVAL_BASED_STATE = None
      if eb_handler.exploitation(url, timesec, filename, http_request_method, injection_type, technique) != False:
        while True:
          settings.EVAL_BASED_STATE = True
          message = "Skipping of further command injection checks is recommended. "
          message += "Do you agree? [Y/n] > "
          procced_option = common.read_input(message, default="Y", check_batch=True)
          if procced_option in settings.CHOICE_YES:
            settings.SKIP_COMMAND_INJECTIONS = True
            break
          elif procced_option in settings.CHOICE_NO:
            if settings.SKIP_COMMAND_INJECTIONS:
              settings.SKIP_COMMAND_INJECTIONS = False
            break
          elif procced_option in settings.CHOICE_QUIT:
            raise SystemExit()
          else:
            common.invalid_option(procced_option)  
            pass
      else:
        settings.EVAL_BASED_STATE = False
    else:
      if settings.VERBOSITY_LEVEL != 0:   
        debug_msg = "Skipping test the " + "(" + injection_type.split(settings.SINGLE_WHITESPACE)[0] + ") " + technique + ". "
        print(settings.print_debug_msg(debug_msg))
  else:
    if settings.VERBOSITY_LEVEL != 0:   
      debug_msg = "Skipping test the " + "(" + injection_type.split(settings.SINGLE_WHITESPACE)[0] + ") " + technique + ". "
      print(settings.print_debug_msg(debug_msg))

# Check if it's exploitable via time-based command injection technique.
def timebased_command_injection_technique(url, timesec, filename, http_request_method, url_time_response):
  injection_type = "blind OS command injection"
  technique = "time-based command injection technique"
  if not settings.SKIP_COMMAND_INJECTIONS:
    if (len(menu.options.tech) == 0 or "t" in menu.options.tech):
      settings.TIME_BASED_STATE = None
      if tb_handler.exploitation(url, timesec, filename, http_request_method, url_time_response, injection_type, technique) != False:
        settings.TIME_BASED_STATE = True
      else:
        settings.TIME_BASED_STATE = False
    else:
      if settings.VERBOSITY_LEVEL != 0:   
        debug_msg = "Skipping test the " + "(" + injection_type.split(settings.SINGLE_WHITESPACE)[0] + ") " + technique + ". "
        print(settings.print_debug_msg(debug_msg))

# Check if it's exploitable via file-based command injection technique.
def filebased_command_injection_technique(url, timesec, filename, http_request_method, url_time_response):
  injection_type = "semi-blind command injection"
  technique = "file-based command injection technique"
  if not settings.SKIP_COMMAND_INJECTIONS:
    if (len(menu.options.tech) == 0 or "f" in menu.options.tech):
      settings.FILE_BASED_STATE = None
      if fb_handler.exploitation(url, timesec, filename, http_request_method, url_time_response, injection_type, technique) != False:
        settings.FILE_BASED_STATE = True
      else:
        settings.FILE_BASED_STATE = False
    else:
      if settings.VERBOSITY_LEVEL != 0:   
        debug_msg = "Skipping test the " + "(" + injection_type.split(settings.SINGLE_WHITESPACE)[0] + ") " + technique + ". "
        print(settings.print_debug_msg(debug_msg))

"""
Proceed to the injection process for the appropriate parameter.
"""
def injection_proccess(url, check_parameter, http_request_method, filename, timesec):
  inject_http_headers = False
  if (http_request_method == settings.HTTPMETHOD.GET and check_parameter.lower() not in url) or \
  (http_request_method == settings.HTTPMETHOD.POST and menu.options.data and check_parameter.lower() not in menu.options.data):
    if any(x in check_parameter.lower() for x in settings.HTTP_HEADERS) or \
       any(x in check_parameter.lower() for x in settings.CUSTOM_HEADER_NAME):
      inject_http_headers = True

  if menu.options.ignore_code: 
    info_msg = "Ignoring '" + str(menu.options.ignore_code) + "' HTTP error code. "
    print(settings.print_info_msg(info_msg))

  # User-Agent HTTP header / Referer HTTP header / 
  # Host HTTP header / Custom HTTP header Injection(s)
  if check_parameter.startswith(settings.SINGLE_WHITESPACE):
    header_name = ""
    the_type = "HTTP header"
    check_parameter = " '" + check_parameter.strip() + "'"
  else:
    if settings.COOKIE_INJECTION: 
      header_name = "Cookie"
    else:
      header_name = ""
    the_type = " parameter"
    check_parameter = " '" + check_parameter + "'"

  # Estimating the response time (in seconds)
  timesec, url_time_response = requests.estimate_response_time(url, timesec)

  # Load modules
  modules_handler.load_modules(url, http_request_method, filename)
  checks.tamper_scripts(stored_tamper_scripts=False)

  settings.CHECKING_PARAMETER = ""
  if not header_name == "Cookie" and not the_type == "HTTP header":
    settings.CHECKING_PARAMETER = str(http_request_method)
    settings.CHECKING_PARAMETER += ('', ' (JSON)')[settings.IS_JSON] + ('', ' (SOAP/XML)')[settings.IS_XML] 
  if header_name == "Cookie" :
     settings.CHECKING_PARAMETER += str(header_name) + str(the_type) + str(check_parameter)
  else:
     settings.CHECKING_PARAMETER += str(the_type) + str(header_name) + str(check_parameter)

  info_msg = "Setting " + settings.CHECKING_PARAMETER  + " for tests."
  print(settings.print_info_msg(info_msg))

  if menu.options.skip_heuristics:
    if settings.VERBOSITY_LEVEL != 0:   
      debug_msg = "Skipping heuristic (basic) tests to the target URL."
      print(settings.print_debug_msg(debug_msg))
  else:
    if not settings.LOAD_SESSION:
      checks.recognise_payload(payload=settings.TESTABLE_VALUE)
      if settings.VERBOSITY_LEVEL != 0:    
        debug_msg = "Performing heuristic (basic) tests to the target URL."
        print(settings.print_debug_msg(debug_msg))

      if not (len(menu.options.tech) == 1 and "e" in menu.options.tech):
        url = command_injection_heuristic_basic(url, http_request_method, check_parameter, the_type, header_name, inject_http_headers)

      if not settings.IDENTIFIED_COMMAND_INJECTION and "e" in menu.options.tech:
        # Check for identified warnings
        url = code_injections_heuristic_basic(url, http_request_method, check_parameter, the_type, header_name, inject_http_headers)
        if settings.IDENTIFIED_WARNINGS or settings.IDENTIFIED_PHPINFO:
          while True:
            message = "Skipping of further command injection tests is recommended. "
            message += "Do you agree? [Y/n] > "
            procced_option = common.read_input(message, default="Y", check_batch=True)
            if procced_option in settings.CHOICE_YES:
              settings.CLASSIC_STATE = settings.TIME_BASED_STATE = settings.FILE_BASED_STATE = False
              settings.EVAL_BASED_STATE = settings.SKIP_COMMAND_INJECTIONS = True
              break
            elif procced_option in settings.CHOICE_NO:
              break
            elif procced_option in settings.CHOICE_QUIT:
              raise SystemExit()
            else:
              common.invalid_option(procced_option)  
              pass

      if not settings.IDENTIFIED_COMMAND_INJECTION and not settings.IDENTIFIED_WARNINGS and not settings.IDENTIFIED_PHPINFO:
        warn_msg = "Heuristic (basic) tests shows that "
        warn_msg += settings.CHECKING_PARAMETER + " might not be injectable."
        print(settings.print_bold_warning_msg(warn_msg)) 

  if menu.options.failed_tries and \
     menu.options.tech and not "f" in menu.options.tech and not \
     menu.options.failed_tries:
    warn_msg = "Due to the provided (unsuitable) injection technique" 
    warn_msg += "s"[len(menu.options.tech) == 1:][::-1] + ", "
    warn_msg += "the option '--failed-tries' will be ignored."
    print(settings.print_warning_msg(warn_msg) + Style.RESET_ALL)

  # Procced with file-based semiblind command injection technique,
  # once the user provides the path of web server's root directory.
  if menu.options.web_root and \
     menu.options.tech and not "f" in menu.options.tech:
      if not menu.options.web_root.endswith("/"):
         menu.options.web_root =  menu.options.web_root + "/"
      if checks.procced_with_file_based_technique():
        menu.options.tech = "f"

  if settings.SKIP_COMMAND_INJECTIONS:
    dynamic_code_evaluation_technique(url, timesec, filename, http_request_method)
    classic_command_injection_technique(url, timesec, filename, http_request_method)
  else:
    classic_command_injection_technique(url, timesec, filename, http_request_method)
    if not settings.IDENTIFIED_COMMAND_INJECTION:
      dynamic_code_evaluation_technique(url, timesec, filename, http_request_method)
  timebased_command_injection_technique(url, timesec, filename, http_request_method, url_time_response)
  filebased_command_injection_technique(url, timesec, filename, http_request_method, url_time_response)

  # All injection techniques seems to be failed!
  if settings.CLASSIC_STATE == settings.EVAL_BASED_STATE == settings.TIME_BASED_STATE == settings.FILE_BASED_STATE == False :
    warn_msg = "The tested"
    if header_name != " cookie" and the_type != " HTTP header":
      warn_msg += " " + str(http_request_method) + ""
    warn_msg += str(the_type) + str(header_name) + str(check_parameter)
    warn_msg += " does not seem to be injectable."
    print(settings.print_bold_warning_msg(warn_msg))

"""
Inject HTTP headers (User-agent / Referer / Host) (if level > 2).
"""
def http_headers_injection(url, http_request_method, filename, timesec):
  # Disable Cookie Injection 
  settings.COOKIE_INJECTION = None

  def user_agent_injection(url, http_request_method, filename, timesec): 
    user_agent = menu.options.agent
    if not menu.options.shellshock:
      menu.options.agent = menu.options.agent + settings.INJECT_TAG
    settings.USER_AGENT_INJECTION = True
    if settings.USER_AGENT_INJECTION:
      check_parameter = header_name = " User-Agent"
      settings.HTTP_HEADER = header_name[1:].replace("-","").lower()
      check_for_stored_sessions(url, http_request_method)
      if not injection_proccess(url, check_parameter, http_request_method, filename, timesec):
        settings.USER_AGENT_INJECTION = None
    menu.options.agent = user_agent

  def referer_injection(url, http_request_method, filename, timesec):
    referer = menu.options.referer
    if not menu.options.shellshock:
      if menu.options.referer is None:
        menu.options.referer = ""
      menu.options.referer = menu.options.referer + settings.INJECT_TAG
    settings.REFERER_INJECTION = True
    if settings.REFERER_INJECTION:
      check_parameter = header_name = " Referer"
      settings.HTTP_HEADER = header_name[1:].lower()
      check_for_stored_sessions(url, http_request_method)
      if not injection_proccess(url, check_parameter, http_request_method, filename, timesec):
        settings.REFERER_INJECTION = False 
    menu.options.agent = referer

  def host_injection(url, http_request_method, filename, timesec):
    host = menu.options.host
    if menu.options.host is None:
      menu.options.host = ""
    menu.options.host = menu.options.host + settings.INJECT_TAG
    settings.HOST_INJECTION = True
    if settings.HOST_INJECTION:
      check_parameter = header_name = " Host"
      settings.HTTP_HEADER = header_name[1:].lower()
      check_for_stored_sessions(url, http_request_method)
      if not injection_proccess(url, check_parameter, http_request_method, filename, timesec):
        settings.HOST_INJECTION = False 
    menu.options.host = host

  # User-Agent HTTP header injection
  if menu.options.skip_parameter == None:
    if menu.options.test_parameter == None or "user-agent" in menu.options.test_parameter.lower():
      user_agent_injection(url, http_request_method, filename, timesec)
  else:
    if "user-agent" not in menu.options.skip_parameter.lower():
      user_agent_injection(url, http_request_method, filename, timesec)  

  # Referer HTTP header injection
  if menu.options.skip_parameter == None:
    if menu.options.test_parameter == None or "referer" in menu.options.test_parameter.lower():
      referer_injection(url, http_request_method, filename, timesec)
  else:
    if "referer" not in menu.options.skip_parameter.lower():
      referer_injection(url, http_request_method, filename, timesec)   

  # Host HTTP header injection
  if menu.options.skip_parameter == None:
    if menu.options.test_parameter == None or "host" in menu.options.test_parameter.lower():
      host_injection(url, http_request_method, filename, timesec)
  else:
    if "host" not in menu.options.skip_parameter.lower():
      host_injection(url, http_request_method, filename, timesec)   

"""
Check for stored injections on User-agent / Referer headers (if level > 2).
"""
def stored_http_header_injection(url, check_parameter, http_request_method, filename, timesec):

  for check_parameter in settings.HTTP_HEADERS:
    settings.HTTP_HEADER = check_parameter
    if check_for_stored_sessions(url, http_request_method):
      if check_parameter == "referer":
        menu.options.referer = settings.INJECT_TAG
        settings.REFERER_INJECTION = True
      elif check_parameter == "host":
        menu.options.host= settings.INJECT_TAG
        settings.HOST_INJECTION = True
      else:  
        menu.options.agent = settings.INJECT_TAG
        settings.USER_AGENT_INJECTION = True
      injection_proccess(url, check_parameter, http_request_method, filename, timesec)

  if not settings.LOAD_SESSION:
    http_headers_injection(url, http_request_method, filename, timesec)


"""
Cookie injection 
"""
def cookie_injection(url, http_request_method, filename, timesec):

  settings.COOKIE_INJECTION = True

  # Cookie Injection
  if settings.COOKIE_INJECTION == True:
    cookie_value = menu.options.cookie

    header_name = " cookie"
    settings.HTTP_HEADER = header_name[1:].lower()
    cookie_parameters = parameters.do_cookie_check(menu.options.cookie)
    if type(cookie_parameters) is str:
      cookie_parameters_list = []
      cookie_parameters_list.append(cookie_parameters)
      cookie_parameters = cookie_parameters_list

    # Remove whitespaces 
    cookie_parameters = [x.replace(settings.SINGLE_WHITESPACE, "") for x in cookie_parameters]

    check_parameters = []
    for i in range(0, len(cookie_parameters)):
      menu.options.cookie = cookie_parameters[i]
      check_parameter = parameters.specify_cookie_parameter(menu.options.cookie)
      check_parameters.append(check_parameter)

    checks.print_non_listed_params(check_parameters, http_request_method, header_name)

    for i in range(0, len(cookie_parameters)):
      parameter = menu.options.cookie = cookie_parameters[i]
      check_parameter = parameters.specify_cookie_parameter(parameter)
      if check_parameter != parameter:
        if len(check_parameter) > 0:
          settings.TESTABLE_PARAMETER = check_parameter
        # Check if testable parameter(s) are provided
        if len(settings.TEST_PARAMETER) > 0:
          if menu.options.test_parameter != None:
            param_counter = 0
            for check_parameter in check_parameters:
              if check_parameter in "".join(settings.TEST_PARAMETER).split(","):
                menu.options.cookie = cookie_parameters[param_counter]
                check_parameter = parameters.specify_cookie_parameter(menu.options.cookie)
                # Check for session file 
                check_for_stored_sessions(url, http_request_method)
                injection_proccess(url, check_parameter, http_request_method, filename, timesec) 
              param_counter += 1
            break  
        else:
          # Check for session file 
          check_for_stored_sessions(url, http_request_method)
          injection_proccess(url, check_parameter, http_request_method, filename, timesec) 
 
  if settings.COOKIE_INJECTION == True:
    # Restore cookie value
    menu.options.cookie = cookie_value
    # Disable cookie injection 
    settings.COOKIE_INJECTION = False

"""
Check if HTTP Method is GET.
""" 
def get_request(url, http_request_method, filename, timesec):

  found_url = parameters.do_GET_check(url, http_request_method)
  if found_url != False:

    check_parameters = []
    for i in range(0, len(found_url)):
      url = found_url[i]
      check_parameter = parameters.vuln_GET_param(url)
      check_parameters.append(check_parameter)

    header_name = ""
    checks.print_non_listed_params(check_parameters, http_request_method, header_name)

    for i in range(0, len(found_url)):
      url = found_url[i]
      check_parameter = parameters.vuln_GET_param(url)
      if check_parameter != url:
        if len(check_parameter) > 0:
          settings.TESTABLE_PARAMETER = check_parameter
        # Check if testable parameter(s) are provided
        if len(settings.TESTABLE_PARAMETER) > 0:
          if menu.options.test_parameter != None:
            url_counter = 0
            for check_parameter in check_parameters:
              if check_parameter in "".join(settings.TEST_PARAMETER).split(","):
                url = found_url[url_counter]
                check_parameter = parameters.vuln_GET_param(url)
                # Check for session file 
                check_for_stored_sessions(url, http_request_method)
                injection_proccess(url, check_parameter, http_request_method, filename, timesec)
              url_counter += 1
            break
          else:
            # Check for session file 
            check_for_stored_sessions(url, http_request_method)
            injection_proccess(url, check_parameter, http_request_method, filename, timesec)
        else:
          # Check for session file 
          check_for_stored_sessions(url, http_request_method)
          injection_proccess(url, check_parameter, http_request_method, filename, timesec)

"""
Check if HTTP Method is POST.
""" 
def post_request(url, http_request_method, filename, timesec):

  parameter = menu.options.data
  found_parameter = parameters.do_POST_check(parameter, http_request_method)

  # Check if singe entry parameter
  if type(found_parameter) is str:
    found_parameter_list = []
    found_parameter_list.append(found_parameter)
    found_parameter = found_parameter_list

  if settings.IS_XML:
    # Remove junk data
    found_parameter = [x for x in found_parameter if settings.INJECT_TAG in x]
  else:     
    # Remove whitespaces   
    found_parameter = [x.replace(settings.SINGLE_WHITESPACE, "") for x in found_parameter]

  # Check if multiple parameters
  check_parameters = []
  for i in range(0, len(found_parameter)):
    parameter = menu.options.data = found_parameter[i]
    check_parameter = parameters.vuln_POST_param(parameter, url)
    check_parameters.append(check_parameter)

  header_name = ""
  checks.print_non_listed_params(check_parameters, http_request_method, header_name)

  for i in range(0, len(found_parameter)):
    #if settings.INJECT_TAG in found_parameter[i]:
    parameter = menu.options.data = found_parameter[i]
    check_parameter = parameters.vuln_POST_param(parameter, url)
    if check_parameter != parameter:
      if len(check_parameter) > 0:
        settings.TESTABLE_PARAMETER = check_parameter
      # Check if testable parameter(s) are provided
      if len(settings.TESTABLE_PARAMETER) > 0:
        if menu.options.test_parameter != None:
          param_counter = 0
          for check_parameter in check_parameters:
            if check_parameter in "".join(settings.TEST_PARAMETER).split(","):
              menu.options.data = found_parameter[param_counter]
              check_parameter = parameters.vuln_POST_param(menu.options.data, url)
              # Check for session file 
              check_for_stored_sessions(url, http_request_method)
              injection_proccess(url, check_parameter, http_request_method, filename, timesec)
            param_counter += 1
          break
        else:
          # Check for session file 
          check_for_stored_sessions(url, http_request_method)
          injection_proccess(url, check_parameter, http_request_method, filename, timesec)
      else:
        # Check for session file 
        check_for_stored_sessions(url, http_request_method)
        injection_proccess(url, check_parameter, http_request_method, filename, timesec)

"""
Perform checks
"""
def perform_checks(url, http_request_method, filename):
  # Initiate whitespaces
  if settings.MULTI_TARGETS or settings.STDIN_PARSING and len(settings.WHITESPACES) > 1:
    settings.WHITESPACES = ["%20"]

  def basic_level_checks():
    if settings.MULTI_TARGETS or settings.STDIN_PARSING:
      settings.PERFORM_BASIC_SCANS = True
    else:
      settings.PERFORM_BASIC_SCANS = False
    settings.SKIP_CODE_INJECTIONS = False
    settings.SKIP_COMMAND_INJECTIONS = False
    settings.IDENTIFIED_COMMAND_INJECTION = False
    settings.IDENTIFIED_WARNINGS = False
    settings.IDENTIFIED_PHPINFO = False

  timesec = settings.TIMESEC
  # Check if authentication is needed.
  if menu.options.auth_url and menu.options.auth_data:
    # Do the authentication process.
    authentication.authentication_process()
    try:
      # Check if authentication page is the same with the next (injection) URL
      if _urllib.request.urlopen(url, timeout=settings.TIMEOUT).read() == _urllib.request.urlopen(menu.options.auth_url, timeout=settings.TIMEOUT).read():
        err_msg = "It seems that the authentication procedure has failed."
        print(settings.print_critical_msg(err_msg))
        raise SystemExit()
    except (_urllib.error.URLError, _urllib.error.HTTPError) as err_msg:
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()
  elif menu.options.auth_url or menu.options.auth_data: 
    err_msg = "You must specify both login panel URL and login parameters."
    print(settings.print_critical_msg(err_msg))
    raise SystemExit()
  else:
    pass

  if menu.options.shellshock:
    menu.options.level = settings.HTTP_HEADER_INJECTION_LEVEL
  else:
    if menu.options.level != settings.DEFAULT_INJECTION_LEVEL and settings.WILDCARD_CHAR_APPLIED != True:
      menu.options.level = settings.USER_SUPPLIED_LEVEL
    check_for_stored_levels(url, http_request_method)

  if settings.PERFORM_BASIC_SCANS:
    basic_level_checks()

  # Custom header Injection
  if settings.CUSTOM_HEADER_INJECTION == True:
    check_parameter = header_name = settings.SINGLE_WHITESPACE + settings.CUSTOM_HEADER_NAME
    settings.HTTP_HEADER = header_name[1:].lower()
    check_for_stored_sessions(url, http_request_method)
    injection_proccess(url, check_parameter, http_request_method, filename, timesec)
    settings.CUSTOM_HEADER_INJECTION = None
  
  # Check if defined POST data
  if not settings.COOKIE_INJECTION:
    if settings.USER_DEFINED_POST_DATA:
      post_request(url, http_request_method, filename, timesec)
    else:
      get_request(url, http_request_method, filename, timesec)  

  _ = menu.options.level
  if _ >= settings.COOKIE_INJECTION_LEVEL:
    menu.options.level = settings.COOKIE_INJECTION_LEVEL
    # Enable Cookie Injection
    if menu.options.cookie:
      cookie_injection(url, http_request_method, filename, timesec)
    else:
      warn_msg = "The HTTP Cookie header is not provided, "
      warn_msg += "so this test is going to be skipped."
      print(settings.print_warning_msg(warn_msg))
    if _ == settings.HTTP_HEADER_INJECTION_LEVEL:
      menu.options.level = settings.HTTP_HEADER_INJECTION_LEVEL
      if settings.INJECTED_HTTP_HEADER == False :
        check_parameter = ""
        # Check for stored injections on User-agent / Referer / Host HTTP headers (if level > 2).
        stored_http_header_injection(url, check_parameter, http_request_method, filename, timesec)
      else:
        http_headers_injection(url, http_request_method, filename, timesec)

  if settings.INJECTION_CHECKER == False:
    return False
  else:
    return True  

"""
General check on every injection technique.
"""
def do_check(url, http_request_method, filename):
  try:
    if settings.RECHECK_FILE_FOR_EXTRACTION:
      settings.RECHECK_FILE_FOR_EXTRACTION = False

    # Check for '--tor' option.
    if menu.options.tor: 
      if not menu.options.tech or "t" in menu.options.tech or "f" in menu.options.tech:
        warn_msg = "It is highly recommended to avoid usage of switch '--tor' for "
        warn_msg += "time-based injections because of inherent high latency time."
        print(settings.print_warning_msg(warn_msg))

    # Check for "backticks" tamper script.
    if settings.USE_BACKTICKS == True:
      if not menu.options.tech or "e" in menu.options.tech or "t" in menu.options.tech or "f" in menu.options.tech:
        warn_msg = "Commands substitution using backtics is only supported by the (results-based) classic command injection technique. "
        print(settings.print_warning_msg(warn_msg) + Style.RESET_ALL)

    # Check for "wizard" switch.
    if menu.options.wizard:
      if perform_checks(url, http_request_method, filename) == False:
        scan_level = menu.options.level
        while int(scan_level) < int(settings.HTTP_HEADER_INJECTION_LEVEL) and settings.LOAD_SESSION != True:
          while True:
            message = "Do you want to increase to '--level=" + str(scan_level + 1) 
            message += "' in order to perform more tests? [Y/n] > "
            next_level = common.read_input(message, default="Y", check_batch=True)
            if next_level in settings.CHOICE_YES:
              menu.options.level = int(menu.options.level + scan_level)
              if perform_checks(url, http_request_method, filename) == False and scan_level < settings.HTTP_HEADER_INJECTION_LEVEL :
                scan_level = scan_level + 1
              else:
                break  
            elif next_level in settings.CHOICE_NO:
              break
            elif next_level in settings.CHOICE_QUIT:
              raise SystemExit()
            else:
              common.invalid_option(next_level)  
              pass
    else:
      perform_checks(url, http_request_method, filename)
      
    # All injection techniques seems to be failed!
    if settings.CLASSIC_STATE == settings.EVAL_BASED_STATE == settings.TIME_BASED_STATE == settings.FILE_BASED_STATE == False :
      if settings.INJECTION_CHECKER == False and not settings.CHECK_BOTH_OS:
        err_msg = "All tested parameters "
        if menu.options.level > settings.COOKIE_INJECTION_LEVEL:
          err_msg += "and HTTP headers "
        err_msg += "appear to be not injectable."
        if menu.options.level < settings.HTTP_HEADER_INJECTION_LEVEL :
          err_msg += " Try to increase value for '--level' option"
        if menu.options.skip_empty:
          err_msg += " and/or remove option '--skip-empty'"
        err_msg += " if you wish to perform more tests."
        if settings.USER_SUPPLIED_TECHNIQUE or settings.SKIP_TECHNIQUES:
          err_msg += " Rerun without providing the option "
          if not settings.SKIP_TECHNIQUES :
            err_msg += "'--technique'."
          else:
            err_msg += "'--skip-technique'."  
        err_msg += " If you suspect that there is some kind of protection mechanism involved, maybe you could try to"
        if not menu.options.alter_shell :
          err_msg += " use option '--alter-shell'"
        else:
          err_msg += " remove option '--alter-shell'"
        if not menu.options.tamper:
          err_msg += " and/or use option '--tamper'"
        if not menu.options.random_agent:
          if not menu.options.tamper:
            err_msg += " and/or"
          err_msg += " switch '--random-agent'"
        err_msg += "."
        if settings.MULTI_TARGETS:
          err_msg += " Skipping to the next target."
        print(settings.print_error_msg(err_msg))
    else:    
      logs.print_logs_notification(filename, url)
    # if not settings.MULTI_TARGETS:
    #   print(settings.SINGLE_WHITESPACE)
    if not settings.CHECK_BOTH_OS and not settings.MULTI_TARGETS:
      common.show_http_error_codes()
      raise SystemExit()

  except KeyboardInterrupt:
    checks.user_aborted(filename, url)

# eof