#!/usr/bin/env python
# encoding: UTF-8

"""
 This file is part of commix (@commixproject) tool.
 Copyright (c) 2015 Anastasios Stasinopoulos (@ancst).
 https://github.com/stasinopoulos/commix

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 For more see the file 'readme/COPYING' for copying permission.
"""

import os
import sys

from src.utils import menu
from src.utils import logs
from src.utils import settings

from src.thirdparty.colorama import Fore, Back, Style, init

from src.core.requests import requests
from src.core.modules import modules_handler
from src.core.requests import authentication

from src.core.injections.results_based.techniques.classic import cb_handler
from src.core.injections.results_based.techniques.eval_based import eb_handler
from src.core.injections.blind_based.techniques.time_based import tb_handler
from src.core.injections.semiblind_based.techniques.file_based import fb_handler

"""
 Command Injection and exploitation controller.
 Checks if the testable parameter is exploitable.
"""

# ------------------------------------------
# Execute the classic injection technique.
# ------------------------------------------
def execute_classic_technique(url, delay, filename, http_request_method):
  if cb_handler.exploitation(url, delay, filename, http_request_method) == False:
    if http_request_method == "GET":
      print Back.RED + "(x) The url '"+ url +"' appear to be not injectable." + Style.RESET_ALL
    else:
      print Back.RED + "(x) The '"+ parameter +"' parameter appear to be not injectable." + Style.RESET_ALL
  if menu.options.verbose:
    print "\n"
  percent = colors.PURPLE + "FINISHED" + Style.RESET_ALL
  sys.stdout.write(Style.BRIGHT + "\r(!) The process of testing the "+ menu.options.tech + " injection technique... " + Style.RESET_ALL +  "[ " + percent + " ]")  
  sys.stdout.flush()
  logs.logs_notification(filename)
  sys.exit(0)


# --------------------------------------------
# Execute the eval-based injection technique.
# --------------------------------------------
def execute_eval_based_technique(url, delay, filename, http_request_method):
  if eb_handler.exploitation(url, delay, filename, http_request_method) == False:
    if http_request_method == "GET":
      print Back.RED + "(x) The url '"+ url +"' appear to be not injectable." + Style.RESET_ALL
    else:
      print Back.RED + "(x) The '"+ parameter +"' parameter appear to be not injectable via "+ menu.options.tech + "." + Style.RESET_ALL
  if menu.options.verbose:
    print "\n"
  percent = colors.PURPLE + "FINISHED" + Style.RESET_ALL
  sys.stdout.write(Style.BRIGHT + "\r(!) The process of testing the "+ menu.options.tech + " injection technique... " + Style.RESET_ALL +  "[ " + percent + " ]")  
  sys.stdout.flush()
  logs.logs_notification(filename)
  sys.exit(0)


# --------------------------------------------
# Execute the time-based injection technique.
# --------------------------------------------
def execute_time_based_technique(url, delay, filename, http_request_method, url_time_response):
  if tb_handler.exploitation(url, delay, filename, http_request_method, url_time_response) == False:
    if http_request_method == "GET":
      print Back.RED + "(x) The url '"+ url +"' appear to be not injectable." + Style.RESET_ALL
    else:
      print Back.RED + "(x) The '"+ parameter +"' parameter appear to be not injectable." + Style.RESET_ALL
  if menu.options.verbose:
    print "\n"
  percent = colors.PURPLE + "FINISHED" + Style.RESET_ALL
  sys.stdout.write(Style.BRIGHT + "\r(!) The process of testing the "+ menu.options.tech + " injection technique... " + Style.RESET_ALL +  "[ " + percent + " ]")  
  sys.stdout.flush()
  logs.logs_notification(filename)
  sys.exit(0)


# --------------------------------------------
# Execute the file-based injection technique.
# --------------------------------------------
def execute_file_based_technique(url, delay, filename, http_request_method, url_time_response):
  if fb_handler.exploitation(url, delay, filename, http_request_method, url_time_response) == False:
    if http_request_method == "GET":
      print Back.RED + "(x) The url '"+ url +"' appear to be not injectable." + Style.RESET_ALL
    else:
      print Back.RED + "(x) The '"+ parameter +"' parameter appear to be not injectable." + Style.RESET_ALL
  if menu.options.verbose:
    print "\n"
  percent = colors.PURPLE + "FINISHED" + Style.RESET_ALL
  sys.stdout.write(Style.BRIGHT + "\r(!) The process of testing the "+ menu.options.tech + " injection technique... " + Style.RESET_ALL +  "[ " + percent + " ]")  
  sys.stdout.flush()
  logs.logs_notification(filename)
  sys.exit(0)

# ---------------------------------------------
# General check on every injection technique.
# ---------------------------------------------
def do_check(url, filename):

  # Check if defined "--delay" option.
  if menu.options.delay:
    delay = menu.options.delay
  else:
    delay = settings.DELAY

  # Do authentication if needed.
  if menu.options.auth_url and menu.options.auth_data:
    authentication.auth_process()      
  elif menu.options.auth_url or menu.options.auth_data: 
    print Back.RED + "(x) Error: You must specify both login panel URL and login parameters.\n" + Style.RESET_ALL
    sys.exit(0)
  else:
    pass
  
  # Check if HTTP Method is POST.
  if not menu.options.data:
    http_request_method = "GET"
  else:
    http_request_method = "POST"
    parameter = menu.options.data
    
  # Load modules
  modules_handler.load_modules(url, http_request_method)

  # Estimating the response time (in seconds)
  delay, url_time_response = requests.estimate_response_time(url, delay)

  # Check all injection techniques
  if not menu.options.tech:
    # Check if it is vulnerable to classic command injection technique.
    if cb_handler.exploitation(url, delay, filename, http_request_method) == False:
      classic_state = False
    else:
      classic_state = True
    # Check if it is vulnerable to eval-based command injection technique.
    if eb_handler.exploitation(url, delay, filename, http_request_method) == False:
      eval_based_state = False
    else:
      eval_based_state = True
    # Check if it is vulnerable to time-based blind command injection technique.
    if tb_handler.exploitation(url, delay, filename, http_request_method, url_time_response) == False:
      time_based_state = False
    else:
      time_based_state = True
    # Check if it is vulnerable to file-based semiblind command injection technique.
    if fb_handler.exploitation(url, delay, filename, http_request_method, url_time_response) == False:
      file_based_state = False
    else:
      file_based_state = True

  else:
    # Check if it is vulnerable to classic command injection technique.
    if "classic" in menu.options.tech or len(menu.options.tech) <= 4 and "c" in menu.options.tech:
      # Check if classic results-based command injection technique succeeds.
      if cb_handler.exploitation(url, delay, filename, http_request_method) == False:
        classic_state = False
      else:
        classic_state = True
    elif menu.options.tech == "classic":
      execute_classic_technique(url, delay, filename, http_request_method)
    else:
      classic_state = False

    # Check if it is vulnerable to eval-based command injection technique.
    if "eval-based" in menu.options.tech or len(menu.options.tech) <= 4 and "e" in menu.options.tech:
      # Check if eval-based command injection technique succeeds.
      if eb_handler.exploitation(url, delay, filename, http_request_method) == False:
        eval_based_state = False
      else:
        eval_based_state = True
    elif menu.options.tech == "eval-based":
      execute_eval_based_technique(url, delay, filename, http_request_method)
    else:
      eval_based_state = False

    # Check if it is vulnerable to time-based blind command injection technique.
    if "time-based" in menu.options.tech or len(menu.options.tech) <= 4 and "t" in menu.options.tech:
      # Check if time-based blind command injection technique succeeds.
      if tb_handler.exploitation(url, delay, filename, http_request_method, url_time_response) == False:
        time_based_state = False
      else:
        time_based_state = True
    elif menu.options.tech == "time-based":
      execute_time_based_technique(url, delay, filename, http_request_method, url_time_response)
    else:
      time_based_state = False

    # Check if it is vulnerable to file-based semiblind command injection technique.
    if "file-based" in menu.options.tech or len(menu.options.tech) <= 4 and "f" in menu.options.tech:
       # Check if file-based semiblind command injection technique succeeds.
      if fb_handler.exploitation(url, delay, filename, http_request_method, url_time_response) == False:
        file_based_state = False
      else:
        file_based_state = True
    elif menu.options.tech == "file-based":
      execute_file_based_technique(url, delay, filename, http_request_method, url_time_response)
    else:
      file_based_state = False

  if classic_state == False and eval_based_state == False and time_based_state == False and file_based_state == False :
    if http_request_method == "GET":
      print Back.RED + "(x) The url '"+ url +"' appear to be not injectable." + Style.RESET_ALL
    else:
      print Back.RED + "(x) The '"+ parameter +"' parameter appear to be not injectable." + Style.RESET_ALL
  else:
    logs.logs_notification(filename)
  sys.exit(0)
  
#eof