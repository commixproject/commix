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

from src.core.injections.results_based.techniques.classic import cb_handler
from src.core.injections.results_based.techniques.eval_based import eb_handler
from src.core.injections.blind.techniques.time_based import tb_handler
from src.core.injections.semiblind.techniques.file_based import fb_handler

"""
Command Injection and exploitation controller.
Checks if the testable parameter is exploitable.
"""

"""
General check on every injection technique.
"""
def do_check(url, filename):
  
  classic_state = False
  eval_based_state = False
  time_based_state = False
  file_based_state = False

  # Check if defined "--delay" option.
  if menu.options.delay:
    delay = menu.options.delay
  else:
    delay = settings.DELAY

  # Check if authentication is needed.
  if menu.options.auth_url and menu.options.auth_data:
    # Do the authentication process.
    authentication.authentication_process()
    # Check if authentication page is the same with the next (injection) URL
    if urllib2.urlopen(url).read() == urllib2.urlopen(menu.options.auth_url).read():
      print Back.RED + settings.ERROR_SIGN + "It seems that the authentication procedure has failed." + Style.RESET_ALL
      sys.exit(0)
  elif menu.options.auth_url or menu.options.auth_data: 
    print Back.RED + settings.ERROR_SIGN + "You must specify both login panel URL and login parameters." + Style.RESET_ALL
    sys.exit(0)
  else:
    pass

  # Check if HTTP Method is GET or POST.
  header_name = ""
  if not menu.options.data:
    http_request_method = "GET"
    if not settings.COOKIE_INJECTION \
    and not settings.USER_AGENT_INJECTION \
    and not settings.REFERER_INJECTION \
    and not settings.CUSTOM_HEADER_INJECTION:
      url = parameters.do_GET_check(url)
    check_parameter = parameters.vuln_GET_param(url)
    the_type = " parameter "

  else:
    http_request_method = "POST"
    parameter = menu.options.data
    parameter = parameters.do_POST_check(parameter)
    check_parameter = parameters.vuln_POST_param(parameter, url)
    the_type = " parameter " 
  
  # Load modules
  modules_handler.load_modules(url, http_request_method, filename)

  # Cookie Injection
  if settings.COOKIE_INJECTION == True:
    header_name = " Cookie"
    settings.HTTP_HEADER = header_name[1:].lower()
    check_parameter  = parameters.specify_cookie_parameter(menu.options.cookie)
    the_type = " HTTP header "
            
  # User-Agent Injection
  elif settings.USER_AGENT_INJECTION == True:
    header_name = " User-Agent"
    settings.HTTP_HEADER = header_name[1:].replace("-","").lower()
    check_parameter  = ""
    the_type = " HTTP header "

  # Referer Injection
  elif settings.REFERER_INJECTION == True:
    header_name = " Referer"
    settings.HTTP_HEADER = header_name[1:].lower()
    check_parameter  = ""
    the_type = " HTTP header "

  # Custom header Injection
  elif settings.CUSTOM_HEADER_INJECTION == True:
    header_name = " " + settings.CUSTOM_HEADER_NAME
    settings.HTTP_HEADER = header_name[1:].lower()
    check_parameter  = ""
    the_type = " HTTP header "

  if len(check_parameter) > 0:
    settings.TESTABLE_PARAMETER = check_parameter

  # Check for session file 
  if not menu.options.ignore_session:
    if os.path.isfile(settings.SESSION_FILE) and not settings.REQUIRED_AUTHENTICATION:
      if not menu.options.tech:
        menu.options.tech = session_handler.applied_techniques(url, http_request_method)
      if session_handler.check_stored_parameter(url, http_request_method):
        settings.LOAD_SESSION = True
        
  if menu.options.flush_session:
    session_handler.flush(url)

  if len(check_parameter) != 0 :
    check_parameter = " '" + check_parameter + "'"

  print settings.INFO_SIGN + "Setting the " + "(" + http_request_method + ")" + check_parameter + header_name + the_type + "for tests."

  # Estimating the response time (in seconds)
  delay, url_time_response = requests.estimate_response_time(url, http_request_method, delay)

  # Check if it is vulnerable to classic command injection technique.
  if not menu.options.tech or "c" in menu.options.tech:
    if cb_handler.exploitation(url, delay, filename, http_request_method) != False:
      classic_state = True
  else:
    classic_state = False

  # Check if it is vulnerable to eval-based code injection technique.
  if not menu.options.tech or "e" in menu.options.tech:
    if eb_handler.exploitation(url, delay, filename, http_request_method) != False:
      eval_based_state = True
  else:
    eval_based_state = False

  # Check if it is vulnerable to time-based blind command injection technique.
  if not menu.options.tech or "t" in menu.options.tech:
    if tb_handler.exploitation(url, delay, filename, http_request_method, url_time_response) != False:
      time_based_state = True
  else:
    time_based_state = False

  # Check if it is vulnerable to file-based semiblind command injection technique.
  if not menu.options.tech or "f" in menu.options.tech:
    if fb_handler.exploitation(url, delay, filename, http_request_method, url_time_response) != False:
      file_based_state = True
  else:
    file_based_state = False

  if classic_state == eval_based_state == time_based_state == file_based_state == False :
    info_msg = settings.CRITICAL_SIGN + "The tested (" + http_request_method + ")" + check_parameter + " parameter appear to be not injectable."
    if not menu.options.alter_shell :
      info_msg += " Use the option '--alter-shell'"
    else:
      info_msg += " Remove the option '--alter-shell'"
    info_msg += " and/or try to audit the HTTP headers (i.e 'User-Agent', 'Referer', 'Cookie' etc)."
    print Back.RED + info_msg + Style.RESET_ALL  
  sys.exit(0)

#eof