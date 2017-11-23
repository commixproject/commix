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

import os
import sys
import urllib2

from src.utils import menu
from src.utils import logs
from src.utils import settings
from src.utils import session_handler

from src.thirdparty.colorama import Fore, Back, Style, init

from src.core.requests import headers
from src.core.requests import requests
from src.core.requests import parameters
from src.core.modules import modules_handler
from src.core.requests import authentication

from src.core.injections.controller import checks

from src.core.injections.results_based.techniques.classic import cb_handler
from src.core.injections.results_based.techniques.eval_based import eb_handler
from src.core.injections.blind.techniques.time_based import tb_handler
from src.core.injections.semiblind.techniques.file_based import fb_handler

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
Proceed to the injection process for the appropriate parameter.
"""
def injection_proccess(url, check_parameter, http_request_method, filename, timesec):

  # Skipping specific injection techniques.
  if settings.SKIP_TECHNIQUES:
    menu.options.tech = "".join(settings.AVAILABLE_TECHNIQUES)
    for skip_tech_name in settings.AVAILABLE_TECHNIQUES:
      if skip_tech_name in menu.options.skip_tech:
        menu.options.tech = menu.options.tech.replace(skip_tech_name,"")
    if len(menu.options.tech) == 0:
      err_msg = "Detection procedure was aborted due to skipping all injection techniques."
      print settings.print_critical_msg(err_msg)
      raise SystemExit

  # User-Agent Injection / Referer Injection / Custom header Injection 
  if check_parameter.startswith(" "):
    header_name = ""
    the_type = " HTTP header"
  else:
    if settings.COOKIE_INJECTION: 
      header_name = " cookie"
    else:
      header_name = ""
    the_type = " parameter"
    check_parameter = " '" + check_parameter + "'"

  # Load modules
  modules_handler.load_modules(url, http_request_method, filename)

  if not settings.LOAD_SESSION:
    info_msg = "Setting the" 
    if not header_name == " cookie" and not the_type == " HTTP header":
      info_msg += " " + http_request_method + ""
    info_msg += the_type + header_name + check_parameter + " for tests."
    print settings.print_info_msg(info_msg)

  # Estimating the response time (in seconds)
  timesec, url_time_response = requests.estimate_response_time(url, timesec)

  skip_code_injections = False
  skip_command_injections = False

  # Procced with file-based semiblind command injection technique,
  # once the user provides the path of web server's root directory.
  if menu.options.web_root and not "f" in menu.options.tech:
    if not menu.options.web_root.endswith("/"):
       menu.options.web_root =  menu.options.web_root + "/"
    if checks.procced_with_file_based_technique():
      menu.options.tech = "f"
  
  # Check if it is vulnerable to classic command injection technique.
  if not menu.options.tech or "c" in menu.options.tech:
    settings.CLASSIC_STATE = None
    if cb_handler.exploitation(url, timesec, filename, http_request_method) != False:
      if not menu.options.tech or "e" in menu.options.tech:
        if not menu.options.batch:
          settings.CLASSIC_STATE = True
          question_msg = "Due to results, "
          question_msg += "skipping of code injection checks is recommended. "
          question_msg += "Do you agree? [Y/n] > "
          sys.stdout.write(settings.print_question_msg(question_msg))
          procced_option = sys.stdin.readline().replace("\n","").lower()
        else:
          procced_option = ""
        if len(procced_option) == 0:
           procced_option = "y"
        if procced_option in settings.CHOICE_YES:
          skip_code_injections = True
        elif procced_option in settings.CHOICE_NO:
          pass
        elif procced_option in settings.CHOICE_QUIT:
          sys.exit(0)
        else:
          err_msg = "'" + procced_option + "' is not a valid answer."  
          print settings.print_error_msg(err_msg)
          pass
    else:
      settings.CLASSIC_STATE = False

  # Check if it is vulnerable to eval-based code injection technique.
  if not menu.options.tech or "e" in menu.options.tech:
    if not skip_code_injections:
      settings.EVAL_BASED_STATE = None
      if eb_handler.exploitation(url, timesec, filename, http_request_method) != False:
        if not menu.options.batch:
          settings.EVAL_BASED_STATE = True
          question_msg = "Due to results, "
          question_msg += "skipping of further command injection checks is recommended. "
          question_msg += "Do you agree? [Y/n] > "
          sys.stdout.write(settings.print_question_msg(question_msg))
          procced_option = sys.stdin.readline().replace("\n","").lower()
        else:
          procced_option = ""
        if len(procced_option) == 0:
           procced_option = "y"
        if procced_option in settings.CHOICE_YES:
          skip_command_injections = True
        elif procced_option in settings.CHOICE_NO:
          pass
        elif procced_option in settings.CHOICE_QUIT:
          sys.exit(0)
        else:
          err_msg = "'" + procced_option + "' is not a valid answer."  
          print settings.print_error_msg(err_msg)
          pass
      else:
        settings.EVAL_BASED_STATE = False
  
  if not skip_command_injections:
    # Check if it is vulnerable to time-based blind command injection technique.
    if not menu.options.tech or "t" in menu.options.tech:
      settings.TIME_BASED_STATE = None
      if tb_handler.exploitation(url, timesec, filename, http_request_method, url_time_response) != False:
        settings.TIME_BASED_STATE = True
      else:
        settings.TIME_BASED_STATE = False

    # Check if it is vulnerable to file-based semiblind command injection technique.
    if not menu.options.tech or "f" in menu.options.tech and not skip_command_injections:
      settings.FILE_BASED_STATE = None
      if fb_handler.exploitation(url, timesec, filename, http_request_method, url_time_response) != False:
        settings.FILE_BASED_STATE = True
      else:
        settings.FILE_BASED_STATE = False

  # All injection techniques seems to be failed!
  if settings.CLASSIC_STATE == settings.EVAL_BASED_STATE == settings.TIME_BASED_STATE == settings.FILE_BASED_STATE == False :
    warn_msg = "The tested"
    if not header_name == " cookie" and not the_type == " HTTP header":
      warn_msg += " " + http_request_method + ""
    warn_msg += the_type + header_name + check_parameter
    warn_msg += " seems to be not injectable."
    print settings.print_warning_msg(warn_msg) + Style.RESET_ALL

"""
Inject HTTP headers (User-agent / Referer) (if level > 2).
"""
def http_headers_injection(url, http_request_method, filename, timesec):
  # Disable Cookie Injection 
  settings.COOKIE_INJECTION = False

  def user_agent_injection(url, http_request_method, filename, timesec): 
    user_agent = menu.options.agent
    if not menu.options.shellshock:
      menu.options.agent = settings.INJECT_TAG
    settings.USER_AGENT_INJECTION = True
    if settings.USER_AGENT_INJECTION:
      check_parameter = header_name = " User-Agent"
      settings.HTTP_HEADER = header_name[1:].replace("-","").lower()
      check_for_stored_sessions(url, http_request_method)
      injection_proccess(url, check_parameter, http_request_method, filename, timesec)
    settings.USER_AGENT_INJECTION = False
    menu.options.agent = user_agent

  def referer_injection(url, http_request_method, filename, timesec):
    if not menu.options.shellshock:
      menu.options.referer = settings.INJECT_TAG
    settings.REFERER_INJECTION = True
    if settings.REFERER_INJECTION:
      check_parameter =  header_name = " Referer"
      settings.HTTP_HEADER = header_name[1:].lower()
      check_for_stored_sessions(url, http_request_method)
      injection_proccess(url, check_parameter, http_request_method, filename, timesec)
      settings.REFERER_INJECTION = False 

  # User-Agent header injection
  if menu.options.skip_parameter == None:
    if menu.options.test_parameter == None or "user-agent" in menu.options.test_parameter.lower():
      user_agent_injection(url, http_request_method, filename, timesec)
  else:
    if "user-agent" not in menu.options.skip_parameter.lower():
      user_agent_injection(url, http_request_method, filename, timesec)  

  # Referer header injection
  if menu.options.skip_parameter == None:
    if menu.options.test_parameter == None or "referer" in menu.options.test_parameter.lower():
      referer_injection(url, http_request_method, filename, timesec)
  else:
    if "referer" not in menu.options.skip_parameter.lower():
      referer_injection(url, http_request_method, filename, timesec)   

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
    cookie_parameters = [x.replace(" ", "") for x in cookie_parameters]

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

  #if not settings.COOKIE_INJECTION:
  found_url = parameters.do_GET_check(url)
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

  # Enable Cookie Injection
  if menu.options.level > settings.DEFAULT_INJECTION_LEVEL and menu.options.cookie:
    settings.COOKIE_INJECTION = True

"""
Check if HTTP Method is POST.
""" 
def post_request(url, http_request_method, filename, timesec):

  # Check if HTTP Method is POST.
  parameter = menu.options.data
  found_parameter = parameters.do_POST_check(parameter)

  # Check if singe entry parameter
  if type(found_parameter) is str:
    found_parameter_list = []
    found_parameter_list.append(found_parameter)
    found_parameter = found_parameter_list

  # Remove whitespaces   
  found_parameter = [x.replace(" ", "") for x in found_parameter]

  # Check if multiple parameters
  check_parameters = []
  for i in range(0, len(found_parameter)):
    parameter = menu.options.data = found_parameter[i]
    check_parameter = parameters.vuln_POST_param(parameter, url)
    check_parameters.append(check_parameter)

  header_name = ""
  checks.print_non_listed_params(check_parameters, http_request_method, header_name)

  for i in range(0, len(found_parameter)):
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

  # Enable Cookie Injection
  if menu.options.level > settings.DEFAULT_INJECTION_LEVEL and menu.options.cookie:
    settings.COOKIE_INJECTION = True

"""
Perform checks
"""
def perform_checks(url, filename):

  def basic_level_checks():
    settings.PERFORM_BASIC_SCANS = False
    # Check if HTTP Method is GET.
    if not menu.options.data:
      get_request(url, http_request_method, filename, timesec)
    # Check if HTTP Method is POST.      
    else:
      post_request(url, http_request_method, filename, timesec)

  timesec = settings.TIMESEC
  # Check if authentication is needed.
  if menu.options.auth_url and menu.options.auth_data:
    # Do the authentication process.
    authentication.authentication_process()

    # Check if authentication page is the same with the next (injection) URL
    if urllib2.urlopen(url).read() == urllib2.urlopen(menu.options.auth_url).read():
      err_msg = "It seems that the authentication procedure has failed."
      print settings.print_critical_msg(err_msg)
      sys.exit(0)
  elif menu.options.auth_url or menu.options.auth_data: 
    err_msg = "You must specify both login panel URL and login parameters."
    print settings.print_critical_msg(err_msg)
    sys.exit(0)
  else:
    pass

  # Check if HTTP Method is GET.
  if not menu.options.data:
    http_request_method = "GET"      
  else:
    http_request_method = "POST"

  if menu.options.shellshock:
    menu.options.level = settings.HTTP_HEADER_INJECTION_LEVEL
  else:
    check_for_stored_levels(url, http_request_method)

  if settings.PERFORM_BASIC_SCANS:
    basic_level_checks()

  # Check for stored injections on User-agent / Referer headers (if level > 2).
  if menu.options.level >= settings.HTTP_HEADER_INJECTION_LEVEL:
    if settings.INJECTED_HTTP_HEADER == False :
      check_parameter = ""
      stored_http_header_injection(url, check_parameter, http_request_method, filename, timesec)
  else:
    # Enable Cookie Injection
    if menu.options.level > settings.DEFAULT_INJECTION_LEVEL:
      if menu.options.cookie:
        cookie_injection(url, http_request_method, filename, timesec)
      else:
        warn_msg = "The HTTP Cookie header is not provided, "
        warn_msg += "so this test is going to be skipped."
        print settings.print_warning_msg(warn_msg)
    else:
      # Custom header Injection
      if settings.CUSTOM_HEADER_INJECTION == True:
        check_parameter =  header_name = " " + settings.CUSTOM_HEADER_NAME
        settings.HTTP_HEADER = header_name[1:].lower()
        check_for_stored_sessions(url, http_request_method)
        injection_proccess(url, check_parameter, http_request_method, filename, timesec)
        settings.CUSTOM_HEADER_INJECTION = None

  if settings.INJECTION_CHECKER == False:
    return False
  else:
    return True  

"""
General check on every injection technique.
"""
def do_check(url, filename):

  if menu.options.enable_backticks:
    if not menu.options.tech or "e" in menu.options.tech or "t" in menu.options.tech or "f" in menu.options.tech:
      warn_msg = "The '--backticks' switch is only supported by the classic command injection. "
      warn_msg += "It will be ignored for all other techniques."
      print settings.print_warning_msg(warn_msg) + Style.RESET_ALL

  if menu.options.wizard:
    if perform_checks(url,filename) == False:
      scan_level = menu.options.level
      while int(scan_level) < int(settings.HTTP_HEADER_INJECTION_LEVEL) and settings.LOAD_SESSION != True:
        if not menu.options.batch:
          question_msg = "Do you want to increase to '--level=" + str(scan_level + 1) 
          question_msg += "' in order to perform more tests? [Y/n] > "
          sys.stdout.write(settings.print_question_msg(question_msg))
          next_level = sys.stdin.readline().replace("\n","").lower()
        else:
          next_level = ""
        if len(next_level) == 0:
           next_level = "y"
        if next_level in settings.CHOICE_YES:
          menu.options.level = int(menu.options.level + scan_level)
          if perform_checks(url,filename) == False and scan_level < settings.HTTP_HEADER_INJECTION_LEVEL :
            scan_level = scan_level + 1
          else:
            break  
        elif next_level in settings.CHOICE_NO:
          break
        elif next_level in settings.CHOICE_QUIT:
          sys.exit(0)
        else:
          err_msg = "'" + next_level + "' is not a valid answer."  
          print settings.print_error_msg(err_msg)
          pass
  else:
    perform_checks(url,filename)
    
  # All injection techniques seems to be failed!
  if settings.CLASSIC_STATE == settings.EVAL_BASED_STATE == settings.TIME_BASED_STATE == settings.FILE_BASED_STATE == False :
    if settings.INJECTION_CHECKER == False:
      err_msg = "All tested parameters "
      if menu.options.level > 2:
        err_msg += "and headers "
      err_msg += "appear to be not injectable."
      if not menu.options.alter_shell :
        err_msg += " Try to use the option '--alter-shell'"
      else:
        err_msg += " Try to remove the option '--alter-shell'"
      if menu.options.level < settings.HTTP_HEADER_INJECTION_LEVEL :
        err_msg += " and/or try to increase '--level' values to perform"
        err_msg += " more tests (i.e 'User-Agent', 'Referer', 'Cookie' etc)"
      else:
        if menu.options.skip_empty:
          err_msg += " and/or try to remove the option '--skip-empty'"  
      err_msg += "."
      print settings.print_critical_msg(err_msg)

  logs.print_logs_notification(filename, url)
  if not menu.options.bulkfile or settings.EOF:
    print ""  
  #sys.exit(0)

#eof