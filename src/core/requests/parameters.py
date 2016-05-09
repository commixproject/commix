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

import re
import os
import sys
import json

from src.utils import menu
from src.utils import settings
from src.core.injections.controller import checks
from src.thirdparty.colorama import Fore, Back, Style, init

"""
Get the URL part of the defined URL.
"""
def get_url_part(url):
  
  # Find the host part
  url_part = url.split("?")[0]
  # Remove "/" if "/?" in url
  if url_part.endswith("/"):
    url_part = url_part[:-len("/")]

  return url_part

"""
Check if the 'INJECT_HERE' tag, is specified on GET Requests.
"""
def do_GET_check(url):

  # Do replacement with the 'INJECT_HERE' tag, if the wildcard char is provided.
  url = checks.wildcard_character(url)

  # Check for REST-ful URLs format. 
  if "?" not in url:
    if settings.INJECT_TAG not in url and not menu.options.shellshock:
      if menu.options.level == 3 or menu.options.headers:
        return False
      else:  
        err_msg = "No parameter(s) found for testing in the provided data. "
        err_msg += "You must specify the testable parameter or "
        err_msg += "try to increase '--level' values to perform more tests. " 
        print settings.print_error_msg(err_msg) + "\n"
        os._exit(0)   
    return url

  urls_list = []
  # Find the host part
  url_part = get_url_part(url)
  # Find the parameter part
  parameters = url.split("?")[1]
  # Split parameters
  multi_parameters = parameters.split(settings.PARAMETER_DELIMITER)
  # Check if single paramerter is supplied.
  if len(multi_parameters) == 1:
    # Check if defined the INJECT_TAG
    if settings.INJECT_TAG not in parameters:
      # Grab the value of parameter.
      value = re.findall(r'=(.*)', parameters)
      value = ''.join(value)
      # Replace the value of parameter with INJECT tag
      inject_value = value.replace(value, settings.INJECT_TAG)
      parameters = parameters.replace(value, inject_value) 
    else:
      # Grab the value of parameter.
      value = re.findall(r'=(.*)', parameters)
      value = ''.join(value)
      # Auto-recognize prefix / suffix
      if settings.INJECT_TAG in value:
        if len(value.rsplit(settings.INJECT_TAG, 0)[0]) > 0:
          menu.options.prefix = value.rsplit(settings.INJECT_TAG, 1)[0]
        if len(value.rsplit(settings.INJECT_TAG, 1)[1]) > 0:
          menu.options.suffix = value.rsplit(settings.INJECT_TAG, 1)[1]
      # Replace the value of parameter with INJECT tag
      inject_value = value.replace(value, settings.INJECT_TAG)
      parameters = parameters.replace(value, inject_value) 
    # Reconstruct the url
    url = url_part + "?" + parameters
    urls_list.append(url)
    return urls_list 

  else:
    # Check if multiple paramerters are supplied without the "INJECT_HERE" tag.
    all_params = settings.PARAMETER_DELIMITER.join(multi_parameters)
    # Check if defined the "INJECT_HERE" tag
    if settings.INJECT_TAG not in url:
      all_params = all_params.split(settings.PARAMETER_DELIMITER)
      for param in range(0,len(all_params)):
        if param == 0 :
          old = re.findall(r'=(.*)', all_params[param])
          old = ''.join(old)
        else :
          old = value
        # Grab the value of parameter.
        value = re.findall(r'=(.*)', all_params[param])
        value = ''.join(value)
        if not value == "":
          # Replace the value of parameter with INJECT tag
          inject_value = value.replace(value, settings.INJECT_TAG)
          all_params[param] = all_params[param].replace(value, inject_value)
          all_params[param-1] = all_params[param-1].replace(inject_value, old)
          parameter = settings.PARAMETER_DELIMITER.join(all_params)
          # Reconstruct the url
          url = url_part + "?" + parameter  
          urls_list.append(url)
        else:
          provided_value = re.findall(r'(.*)=', all_params[param])
          provided_value = ''.join(provided_value)
          warn_msg = "The '" + provided_value 
          warn_msg += "' parameter has been skipped from testing because the provided value is empty."
          print settings.print_warning_msg(warn_msg)
    else:
      for param in range(0,len(multi_parameters)):
        # Grab the value of parameter.
        value = re.findall(r'=(.*)', multi_parameters[param])
        value = ''.join(value)
        parameter = settings.PARAMETER_DELIMITER.join(multi_parameters)
      url = url_part + "?" + parameter  
      urls_list.append(url)
    return urls_list 

"""
Define the vulnerable GET parameter.
"""
def vuln_GET_param(url):

  urls_list = []
  # Define the vulnerable parameter
  if "?" not in url:
      #Grab the value of parameter.
      value = re.findall(r'/(.*)/' + settings.INJECT_TAG + "", url)
      value = ''.join(value)
      vuln_parameter = re.sub(r"/(.*)/", "", value)

  elif re.findall(r"" + settings.PARAMETER_DELIMITER + "(.*)=" + settings.INJECT_TAG + "", url):
    vuln_parameter = re.findall(r"" + settings.PARAMETER_DELIMITER + "(.*)=" + settings.INJECT_TAG + "", url)
    vuln_parameter = ''.join(vuln_parameter)
    vuln_parameter = re.sub(r"(.*)=(.*)" + settings.PARAMETER_DELIMITER, "", vuln_parameter)

  elif re.findall(r"\?(.*)=" + settings.INJECT_TAG + "", url):
    vuln_parameter = re.findall(r"\?(.*)=" + settings.INJECT_TAG + "", url)
    vuln_parameter = ''.join(vuln_parameter)

  elif re.findall(r"(.*)=" + settings.INJECT_TAG + "", url):
    vuln_parameter = re.findall(r"(.*)=" + settings.INJECT_TAG + "", url)
    vuln_parameter = ''.join(vuln_parameter)

  # Check if only one parameter supplied but, not defined the INJECT_TAG.
  elif settings.INJECT_TAG not in url:
      #Grab the value of parameter.
      value = re.findall(r'\?(.*)=', url)
      value = ''.join(value)
      vuln_parameter = value

  else:
    vuln_parameter = url
    
  return vuln_parameter 

"""
Check if the 'INJECT_HERE' tag, is specified on POST Requests.
"""
def do_POST_check(parameter):

    # Do replacement with the 'INJECT_HERE' tag, if the wildcard char is provided.
  parameter = checks.wildcard_character(parameter)

  # Check if valid JSON
  def is_JSON_check(parameter):
    try:
      json_object = json.loads(parameter)
    except ValueError, err_msg:
      if not "No JSON object could be decoded" in err_msg:
        err_msg = "JSON " + str(err_msg) + ". "
        print settings.print_error_msg(err_msg) + "\n"
        sys.exit(0)
      return False
    else:  
      return True

  if all(symbol in parameter for symbol in settings.JSON_SYMBOLS):
    parameter = parameter.replace("'", "\"")

  # Check if JSON Object.
  if is_JSON_check(parameter):
    settings.IS_JSON = True
  # Split parameters
  if settings.IS_JSON:
    settings.PARAMETER_DELIMITER = ","

  paramerters_list = []
  # Split multiple parameters
  multi_parameters = parameter.split(settings.PARAMETER_DELIMITER)

  # Check if single paramerter is supplied.
  if len(multi_parameters) == 1:
    #Grab the value of parameter.
    if settings.IS_JSON:
      #Grab the value of parameter.
      value = re.findall(r'\"(.*)\"', parameter)
      value = ''.join(value)
      if value != settings.INJECT_TAG:
        value = re.findall(r'\:\"(.*)\"', parameter)
        value = ''.join(value)
    else:  
      value = re.findall(r'=(.*)', parameter)
      value = ''.join(value)
    # Replace the value of parameter with INJECT tag
    inject_value = value.replace(value, settings.INJECT_TAG)
    parameter = parameter.replace(value, inject_value)
    return parameter

  # Check if multiple paramerters are supplied.
  else:
    all_params = settings.PARAMETER_DELIMITER.join(multi_parameters)
    all_params = all_params.split(settings.PARAMETER_DELIMITER)
    # Check if not defined the "INJECT_HERE" tag in parameter
    if settings.INJECT_TAG not in parameter:
      for param in range(0, len(all_params)):
        if param == 0 :
          if settings.IS_JSON:
            old = re.findall(r'\:\"(.*)\"', all_params[param])
            old = ''.join(old)
          else:  
            old = re.findall(r'=(.*)', all_params[param])
            old = ''.join(old)
        else :
          old = value
        # Grab the value of parameter.
        if settings.IS_JSON:
          #Grab the value of parameter.
          value = re.findall(r'\:\"(.*)\"', all_params[param])
          value = ''.join(value)
        else:  
          value = re.findall(r'=(.*)', all_params[param])
          value = ''.join(value)
        if not value == "":
          # Replace the value of parameter with INJECT tag
          inject_value = value.replace(value, settings.INJECT_TAG)
          all_params[param] = all_params[param].replace(value, inject_value)
          all_params[param-1] = all_params[param-1].replace(inject_value, old)
          parameter = settings.PARAMETER_DELIMITER.join(all_params)
          paramerters_list.append(parameter)
          parameter = paramerters_list
        else:
          if settings.IS_JSON:
            #Grab the value of parameter.
            provided_value = re.findall(r'\"(.*)\"\:', all_params[param])
            provided_value = ''.join(provided_value)
          else:  
            provided_value = re.findall(r'(.*)=', all_params[param])
            provided_value = ''.join(provided_value)
          warn_msg = "The '" + provided_value 
          warn_msg += "' parameter has been skipped from testing because the provided value is empty."
          print settings.print_warning_msg(warn_msg) 

    else:
      for param in range(0, len(multi_parameters)):
        # Grab the value of parameter.
        if settings.IS_JSON:
          value = re.findall(r'\"(.*)\"', multi_parameters[param])
          value = ''.join(value)
        else:  
          value = re.findall(r'=(.*)', multi_parameters[param])
          value = ''.join(value)
        parameter = settings.PARAMETER_DELIMITER.join(multi_parameters)
    return parameter

"""
Define the vulnerable POST parameter.
"""
def vuln_POST_param(parameter, url):

  # Define the vulnerable parameter
  if re.findall(r"" + settings.PARAMETER_DELIMITER + "(.*)=" + settings.INJECT_TAG + "", parameter):
    vuln_parameter = re.findall(r"" + settings.PARAMETER_DELIMITER + "(.*)=" + settings.INJECT_TAG + "", parameter)
    vuln_parameter = ''.join(vuln_parameter)
    vuln_parameter = re.sub(r"(.*)=(.*)" + settings.PARAMETER_DELIMITER, "", vuln_parameter)

  elif re.findall(r"(.*)=" + settings.INJECT_TAG + "", parameter):
    vuln_parameter = re.findall(r"(.*)=" + settings.INJECT_TAG + "", parameter)
    vuln_parameter = ''.join(vuln_parameter)

  # If JSON format
  elif re.findall(r"" + settings.PARAMETER_DELIMITER + "\"(.*)\"\:\"" + settings.INJECT_TAG + "\"", parameter):
    vuln_parameter = re.findall(r"" + settings.PARAMETER_DELIMITER + "\"(.*)\"\:\"" + settings.INJECT_TAG + "\"", parameter)
    vuln_parameter = ''.join(vuln_parameter)

  elif re.findall(r"\"(.*)\"\:\"" + settings.INJECT_TAG + "\"", parameter):
    vuln_parameter = re.findall(r"\"(.*)\"\:\"" + settings.INJECT_TAG + "\"", parameter)
    vuln_parameter = ''.join(vuln_parameter)

  else:
    vuln_parameter = parameter

  return vuln_parameter
 
"""
Define the injection prefixes.
"""
def prefixes(payload, prefix):

  # Check if defined "--prefix" option.
  if menu.options.prefix:
    payload = menu.options.prefix + prefix + payload
  else:
    payload = prefix + payload 

  return payload

"""
Define the injection suffixes.
"""
def suffixes(payload, suffix):

  # Check if defined "--suffix" option.
  if menu.options.suffix:
    payload = payload + suffix + menu.options.suffix
  else:
    payload = payload + suffix

  return payload

"""
The cookie based injection.
"""
def do_cookie_check(cookie):

  multi_parameters = cookie.split(settings.COOKIE_DELIMITER)
  # Check if single paramerter is supplied.
  if len(multi_parameters) == 1:
    # Check if defined the INJECT_TAG
    if settings.INJECT_TAG not in cookie:
      #Grab the value of parameter.
      value = re.findall(r'=(.*)', cookie)
      value = ''.join(value)
      # Replace the value of parameter with INJECT tag
      inject_value = value.replace(value, settings.INJECT_TAG)
      cookie = cookie.replace(value, inject_value)
    return cookie

  # Check if multiple paramerters are supplied.
  else:
    cookies_list = []
    all_params = settings.COOKIE_DELIMITER.join(multi_parameters)
    all_params = all_params.split(settings.COOKIE_DELIMITER)
    # Check if not defined the "INJECT_HERE" tag in parameter
    if settings.INJECT_TAG not in cookie:
      for param in range(0, len(all_params)):
        if param == 0 :
            old = re.findall(r'=(.*)', all_params[param])
            old = ''.join(old)
        else :
          old = value
        # Grab the value of cookie.
        value = re.findall(r'=(.*)', all_params[param])
        value = ''.join(value)
        if not value == "":        
          # Replace the value of cookie with INJECT tag
          inject_value = value.replace(value, settings.INJECT_TAG)
          all_params[param] = all_params[param].replace(value, inject_value)
          all_params[param-1] = all_params[param-1].replace(inject_value, old)
          cookie = settings.COOKIE_DELIMITER.join(all_params)
          cookies_list.append(cookie)
          cookie = cookies_list
        else:
          provided_value = re.findall(r'(.*)=', all_params[param])
          provided_value = ''.join(provided_value)
          warn_msg = "The '" + provided_value 
          warn_msg += "' parameter has been skipped from testing because the provided value is empty."
          print settings.print_warning_msg(warn_msg) 


    else:
      for param in range(0, len(multi_parameters)):
        # Grab the value of parameter.
        value = re.findall(r'=(.*)', multi_parameters[param])
        value = ''.join(value)
      cookie = settings.COOKIE_DELIMITER.join(multi_parameters) 
    return cookie

"""
Specify the cookie parameter(s).
"""
def specify_cookie_parameter(cookie):

  # Do replacement with the 'INJECT_HERE' tag, if the wildcard char is provided.
  cookie = checks.wildcard_character(cookie)
  
  # Specify the vulnerable cookie parameter
  if re.findall(r"" + settings.COOKIE_DELIMITER + "(.*)=" + settings.INJECT_TAG + "", cookie):
    inject_cookie = re.findall(r"" + settings.COOKIE_DELIMITER + "(.*)=" + settings.INJECT_TAG + "", cookie)
    inject_cookie = ''.join(inject_cookie)
    inject_cookie = re.sub(r"(.*)=(.*)" + settings.COOKIE_DELIMITER, "", inject_cookie)

  elif re.findall(r"(.*)=" + settings.INJECT_TAG + "", cookie):
    inject_cookie = re.findall(r"(.*)=" + settings.INJECT_TAG + "", cookie)
    inject_cookie = ''.join(inject_cookie)

  else:
    inject_cookie = cookie

  return inject_cookie 

"""
The user-agent based injection.
"""
def specify_user_agent_parameter(user_agent):

   # Specify the vulnerable user-agent parameter
   # Nothing to specify here! :)

  return user_agent
 
"""
The referer based injection.
"""
def specify_referer_parameter(referer):

   # Specify the vulnerable referer parameter.
   # Nothing to specify here! :)

  return referer

"""
The Custom http header based injection.
"""
def specify_custom_header_parameter(header_name):

   # Specify the vulnerable referer parameter.
   # Nothing to specify here! :)

  return header_name

#eof