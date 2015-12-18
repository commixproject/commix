#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of commix (@commixproject) tool.
Copyright (c) 2014-2015 Anastasios Stasinopoulos (@ancst).
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
      print Back.RED + "(x) Error: It seems that the authentication procedure has failed." + Style.RESET_ALL
      sys.exit(0)
  elif menu.options.auth_url or menu.options.auth_data: 
    print Back.RED + "(x) Error: You must specify both login panel URL and login parameters." + Style.RESET_ALL
    sys.exit(0)
  else:
    pass

  # Check if HTTP Method is GET or POST.
  header_name = ""
  if not menu.options.data:
    http_request_method = "GET"
    if not settings.COOKIE_INJECTION \
    and not settings.USER_AGENT_INJECTION \
    and not settings.REFERER_INJECTION:
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
    check_parameter  = parameters.specify_cookie_parameter(menu.options.cookie)
    the_type = " HTTP header "
            
  # User-Agent Injection
  elif settings.USER_AGENT_INJECTION == True:
    header_name = " User-Agent"
    check_parameter  = ""
    the_type = " HTTP header "

  # Referer Injection
  elif settings.REFERER_INJECTION == True:
    header_name = " Referer"
    check_parameter  = ""
    the_type = " HTTP header "

  else : 
    pass

  if len(check_parameter) != 0 :
    check_parameter = " '" + check_parameter + "'"

  print "(*) Setting the " + "(" + http_request_method + ")" + check_parameter + header_name + the_type + "for tests."

  # Estimating the response time (in seconds)
  delay, url_time_response = requests.estimate_response_time(url, http_request_method, delay)

  # Check all injection techniques
  if not menu.options.tech:
    # Check if it is vulnerable to classic command injection technique.
    if cb_handler.exploitation(url, delay, filename, http_request_method) != False:
      classic_state = True

    # Check if it is vulnerable to eval-based code injection technique.
    if eb_handler.exploitation(url, delay, filename, http_request_method) != False:
      eval_based_state = True

    # Check if it is vulnerable to time-based blind command injection technique.
    if tb_handler.exploitation(url, delay, filename, http_request_method, url_time_response) != False:
      time_based_state = True

    # Check if it is vulnerable to file-based semiblind command injection technique.
    if fb_handler.exploitation(url, delay, filename, http_request_method, url_time_response) != False:
      file_based_state = True

  else:
    # Check if it is vulnerable to classic command injection technique.
    if "classic" in menu.options.tech or len(menu.options.tech) <= 4 and "c" in menu.options.tech:
      # Check if classic results-based command injection technique succeeds.
      if cb_handler.exploitation(url, delay, filename, http_request_method) != False:
        classic_state = True
    elif menu.options.tech == "classic":
      cb_handler.exploitation(url, delay, filename, http_request_method)
    else:
      classic_state = False

    # Check if it is vulnerable to eval-based code injection technique.
    if "eval-based" in menu.options.tech or len(menu.options.tech) <= 4 and "e" in menu.options.tech:
      # Check if eval-based code injection technique succeeds.
      if eb_handler.exploitation(url, delay, filename, http_request_method) != False:
        eval_based_state = True
    elif menu.options.tech == "eval-based":
      eb_handler.exploitation(url, delay, filename, http_request_method)
    else:
      eval_based_state = False

    # Check if it is vulnerable to time-based blind command injection technique.
    if "time-based" in menu.options.tech or len(menu.options.tech) <= 4 and "t" in menu.options.tech:
      # Check if time-based blind command injection technique succeeds.
      if tb_handler.exploitation(url, delay, filename, http_request_method, url_time_response) != False:
        time_based_state = True
    elif menu.options.tech == "time-based":
      tb_handler.exploitation(url, delay, filename, http_request_method, url_time_response)
    else:
      time_based_state = False

    # Check if it is vulnerable to file-based semiblind command injection technique.
    if "file-based" in menu.options.tech or len(menu.options.tech) <= 4 and "f" in menu.options.tech:
       # Check if file-based semiblind command injection technique succeeds.
      if fb_handler.exploitation(url, delay, filename, http_request_method, url_time_response) != False:
        file_based_state = True
    elif menu.options.tech == "file-based":
      fb_handler.exploitation(url, delay, filename, http_request_method, url_time_response)
    else:
      file_based_state = False

  if classic_state == False and eval_based_state == False and time_based_state == False and file_based_state == False :
    info_msg = "(x) Critical: The tested (" + http_request_method + ")" + check_parameter + " parameter appear to be not injectable."
    if not menu.options.alter_shell :
      info_msg += " Use the option '--alter-shell'"
    else:
      info_msg += " Remove the option '--alter-shell'"
    info_msg += " and/or try to audit the HTTP headers (i.e 'User-Agent', 'Referer', 'Cookie' etc)."
    print Back.RED + info_msg + Style.RESET_ALL  
    
  # else:
  #   print ""
  sys.exit(0)

#eof
