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
import os
import sys
import json
import random
import string

from urlparse import urlparse

from src.utils import menu
from src.utils import settings
from src.core.injections.controller import checks
from src.thirdparty.colorama import Fore, Back, Style, init

"""
Check if provided parameters are in appropriate format.
"""
def inappropriate_format(multi_parameters):
  err_msg = "The provided parameter" + "s"[len(multi_parameters) == 1:][::-1]
  err_msg += (' are ', ' is ')[len(multi_parameters) == 1]
  err_msg += "not in appropriate format."
  print settings.print_critical_msg(err_msg)
  sys.exit(0)

"""
Skip parameters when the provided value is empty.
"""
def skip_empty(provided_value, http_request_method):
  warn_msg = "The " + http_request_method + " "
  warn_msg += "parameter" + "s"[len(provided_value.split(",")) == 1:][::-1]
  warn_msg += " '" + provided_value + "'"
  warn_msg += (' have ', ' has ')[len(provided_value.split(",")) == 1]
  warn_msg += "been skipped from testing"
  warn_msg += " (the provided value" + "s"[len(provided_value.split(",")) == 1:][::-1]
  warn_msg += (' are ', ' is ')[len(provided_value.split(",")) == 1] + "empty). "
  print settings.print_warning_msg(warn_msg)

"""
Check if the provided value is empty.
"""
def is_empty(multi_parameters, http_request_method):
  provided_value = []
  multi_params = [s for s in multi_parameters]
  for empty in multi_params:
    try:
      if len(empty.split("=")[1]) == 0:
        provided_value.append(empty.split("=")[0])
    except IndexError:
      err_msg = "No parameter(s) found for testing in the provided data."
      print settings.print_critical_msg(err_msg)
  provided_value = ", ".join(provided_value)
  if len(provided_value) > 0:
    if menu.options.skip_empty and len(multi_parameters) > 1:
      skip_empty(provided_value, http_request_method)
    else:
      warn_msg = "The provided value"+ "s"[len(provided_value.split(",")) == 1:][::-1]
      warn_msg += " for "+ http_request_method + " parameter" + "s"[len(provided_value.split(",")) == 1:][::-1]
      warn_msg += " '" + provided_value + "'"
      warn_msg += (' are ', ' is ')[len(provided_value.split(",")) == 1] + "empty. "
      warn_msg += "Use valid "
      warn_msg += "values to run properly."
      print settings.print_warning_msg(warn_msg) 

"""
Get the URL part of the defined URL.
"""
def get_url_part(url):
  
  # Find the URL part (scheme:[//host[:port]][/]path)
  o = urlparse(url)
  url_part = o.scheme + "://" + o.netloc + o.path

  return url_part

"""
Check for similarity in provided parameter name and value.
"""
def check_similarities(all_params):
  for param in range(0, len(all_params)):
    if settings.IS_JSON:
      if re.findall(r'\:\"(.*)\"', all_params[param]) == re.findall(r'\"(.*)\:\"', all_params[param]):
        parameter_name = re.findall(r'\:\"(.*)\"', all_params[param])
        parameter_name = ''.join(parameter_name)
        all_params[param] = parameter_name + ":" + parameter_name.lower() + ''.join([random.choice(string.ascii_letters) for n in xrange(2)]).lower()
    else:  
      if re.findall(r'(.*)=', all_params[param]) == re.findall(r'=(.*)', all_params[param]):
        parameter_name = re.findall(r'=(.*)', all_params[param])
        parameter_name = ''.join(parameter_name)
        all_params[param] = parameter_name + "=" + parameter_name.lower() + ''.join([random.choice(string.ascii_letters) for n in xrange(2)]).lower()

  return all_params


"""
Check if the 'INJECT_HERE' tag, is specified on GET Requests.
"""
def do_GET_check(url):
  http_request_method = "GET"
  # Do replacement with the 'INJECT_HERE' tag, if the wild card char is provided.
  url = checks.wildcard_character(url)

  # Check for REST-ful URLs format. 
  if "?" not in url:
    if settings.INJECT_TAG not in url and not menu.options.shellshock:
      if menu.options.level == 3 or menu.options.headers:
        return False
      if menu.options.level == 2 :
        return False
      else: 
        err_msg = "No parameter(s) found for testing in the provided data. "
        err_msg += "You must specify the testable parameter or "
        err_msg += "try to increase '--level' values to perform more tests." 
        print settings.print_critical_msg(err_msg)
        return False
    elif menu.options.shellshock:
      return False
    return url

  else:
    urls_list = []
    if menu.options.shellshock:
      urls_list.append(url)
    else:
      # Find the host part
      url_part = get_url_part(url)
      # Find the parameter part
      parameters = url.split("?")[1]
      # Split parameters
      multi_parameters = parameters.split(settings.PARAMETER_DELIMITER)
      # Check for inappropriate format in provided parameter(s).
      if len([s for s in multi_parameters if "=" in s]) != (len(multi_parameters)):
        inappropriate_format(multi_parameters)
      # Check for empty values (in provided parameters).
      is_empty(multi_parameters, http_request_method)
      # Grab the value of parameter.
      value = re.findall(r'=(.*)', parameters)
      value = ''.join(value)
      # Replace the value of parameter with INJECT tag
      inject_value = value.replace(value, settings.INJECT_TAG)
      # Check if single parameter is supplied.
      if len(multi_parameters) == 1:
        # Check if defined the INJECT_TAG
        if settings.INJECT_TAG not in parameters:
          if len(value) == 0:
            parameters = parameters + settings.INJECT_TAG
          else:
            parameters = parameters.replace(value, inject_value) 
        else:
          # Auto-recognize prefix / suffix
          if settings.INJECT_TAG in value:
            if len(value.rsplit(settings.INJECT_TAG, 0)[0]) > 0:
              menu.options.prefix = value.rsplit(settings.INJECT_TAG, 1)[0]
            if len(value.rsplit(settings.INJECT_TAG, 1)[1]) > 0:
              menu.options.suffix = value.rsplit(settings.INJECT_TAG, 1)[1]
          parameters = parameters.replace(value, inject_value) 
        # Reconstruct the URL
        url = url_part + "?" + parameters
        urls_list.append(url)
        return urls_list 

      else:
        # Check if multiple parameters are supplied without the "INJECT_HERE" tag.
        all_params = settings.PARAMETER_DELIMITER.join(multi_parameters)
        all_params = all_params.split(settings.PARAMETER_DELIMITER)
        # Check for similarity in provided parameter name and value.
        all_params = check_similarities(all_params)
        check_similarities(all_params)

        # Check if defined the "INJECT_HERE" tag
        if settings.INJECT_TAG not in url:
          for param in range(0,len(all_params)):
            if param == 0 :
              old = re.findall(r'=(.*)', all_params[param])
              old = ''.join(old)
            else :
              old = value

            # Grab the value of parameter.
            value = re.findall(r'=(.*)', all_params[param])
            value = ''.join(value)
            # Replace the value of parameter with INJECT tag
            inject_value = value.replace(value, settings.INJECT_TAG)
            # Skip testing the parameter(s) with empty value(s).
            if menu.options.skip_empty:
              if len(value) == 0:
                provided_value = re.findall(r'(.*)=', all_params[param])
                provided_value = ''.join(provided_value)
              else:
                all_params[param] = all_params[param].replace(value, inject_value)
                all_params[param-1] = all_params[param-1].replace(inject_value, old)
                parameter = settings.PARAMETER_DELIMITER.join(all_params)
                # Reconstruct the URL
                url = url_part + "?" + parameter  
                urls_list.append(url)
            else:
              if len(value) == 0:
                all_params[param] = all_params[param] + settings.INJECT_TAG
              else:
                all_params[param] = all_params[param].replace(value, inject_value)
              all_params[param-1] = all_params[param-1].replace(inject_value, old)
              parameter = settings.PARAMETER_DELIMITER.join(all_params)
              # Reconstruct the URL
              url = url_part + "?" + parameter  
              urls_list.append(url)

        else:
          for param in range(0,len(multi_parameters)):
            # Grab the value of parameter.
            value = re.findall(r'=(.*)', multi_parameters[param])
            value = ''.join(value)
            parameter = settings.PARAMETER_DELIMITER.join(multi_parameters)
          # Reconstruct the URL  
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
  http_request_method = "POST"
  # Check if valid JSON
  def is_JSON_check(parameter):
    try:
      json_object = json.loads(parameter)
      if re.search(settings.JSON_RECOGNITION_REGEX, parameter):
        if settings.VERBOSITY_LEVEL >= 1 and not settings.IS_JSON:
          success_msg = Style.BRIGHT +  "JSON data" 
          success_msg += Style.RESET_ALL + Style.BRIGHT
          success_msg += " found in POST data" 
          success_msg += Style.RESET_ALL + "."
          print settings.print_success_msg(success_msg)
    
    except ValueError, err_msg:
      if not "No JSON object could be decoded" in err_msg:
        err_msg = "JSON " + str(err_msg) + ". "
        print settings.print_critical_msg(err_msg) + "\n"
        sys.exit(0)
      return False
    else:  
      return True

  # Do replacement with the 'INJECT_HERE' tag, if the wild card char is provided.
  parameter = checks.wildcard_character(parameter).replace("'","\"")

  # Check if JSON Object.
  if is_JSON_check(parameter):
    settings.IS_JSON = True
    
  # Split parameters
  if settings.IS_JSON:
    settings.PARAMETER_DELIMITER = ","

  parameters_list = []
  # Split multiple parameters
  multi_parameters = parameter.split(settings.PARAMETER_DELIMITER)
  # Check for inappropriate format in provided parameter(s).
  if len([s for s in multi_parameters if "=" in s]) != (len(multi_parameters)) and \
     not settings.IS_JSON:
    inappropriate_format(multi_parameters)
  # Check for empty values (in provided parameters).
  # Check if single parameter is supplied.
  if len(multi_parameters) == 1:
    #Grab the value of parameter.
    if settings.IS_JSON:
      #Grab the value of parameter.
      value = re.findall(r'\"(.*)\"', parameter)
      value = ''.join(value)
      if value != settings.INJECT_TAG:
        value = re.findall(r'\s*\:\s*\"(.*)\"', parameter)
        value = ''.join(value)
    else:  
      value = re.findall(r'=(.*)', parameter)
      value = ''.join(value)
    is_empty(multi_parameters, http_request_method)  
    # Replace the value of parameter with INJECT tag
    inject_value = value.replace(value, settings.INJECT_TAG) 
    if len(value) == 0:
      parameter = parameter + settings.INJECT_TAG
    else:
      parameter = parameter.replace(value, inject_value)
    return parameter

  else:
    # Check if multiple parameters are supplied without the "INJECT_HERE" tag.
    all_params = settings.PARAMETER_DELIMITER.join(multi_parameters)
    all_params = all_params.split(settings.PARAMETER_DELIMITER)
    # Check for similarity in provided parameter name and value.
    all_params = check_similarities(all_params)
    check_similarities(all_params)

    # Check if not defined the "INJECT_HERE" tag in parameter
    if settings.INJECT_TAG not in parameter:
      is_empty(multi_parameters, http_request_method)
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

        # Replace the value of parameter with INJECT tag
        inject_value = value.replace(value, settings.INJECT_TAG)
        # Skip testing the parameter(s) with empty value(s).
        if menu.options.skip_empty:
          if len(value) == 0:
            if settings.IS_JSON:
              #Grab the value of parameter.
              provided_value = re.findall(r'\"(.*)\"\:', all_params[param])
              provided_value = ''.join(provided_value)
            else:  
              provided_value = re.findall(r'(.*)=', all_params[param])
              provided_value = ''.join(provided_value)
          else:
            all_params[param] = all_params[param].replace(value, inject_value)
            all_params[param-1] = all_params[param-1].replace(inject_value, old)
            parameter = settings.PARAMETER_DELIMITER.join(all_params)
            parameters_list.append(parameter)
            parameter = parameters_list
        else:
          if len(value) == 0:
            all_params[param] = all_params[param] + settings.INJECT_TAG
          else:
            all_params[param] = all_params[param].replace(value, inject_value)
          all_params[param-1] = all_params[param-1].replace(inject_value, old)
          parameter = settings.PARAMETER_DELIMITER.join(all_params)
          parameters_list.append(parameter)
          parameter = parameters_list
   
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
  http_request_method = "cookie"
  multi_parameters = cookie.split(settings.COOKIE_DELIMITER)
  # Check for inappropriate format in provided parameter(s).
  if len([s for s in multi_parameters if "=" in s]) != (len(multi_parameters)):
    inappropriate_format(multi_parameters)
  #Grab the value of parameter.
  value = re.findall(r'=(.*)', cookie)
  value = ''.join(value)
  # Replace the value of parameter with INJECT tag
  inject_value = value.replace(value, settings.INJECT_TAG)
  # Check if single paramerter is supplied.
  if len(multi_parameters) == 1:
    # Check for empty values (in provided parameters).
    is_empty(multi_parameters, http_request_method)
    # Check if defined the INJECT_TAG
    if settings.INJECT_TAG not in cookie:
      if len(value) == 0:
        cookie = cookie + settings.INJECT_TAG
      else:
        cookie = cookie.replace(value, inject_value)
    return cookie

  # Check if multiple parameters are supplied.
  else:
    cookies_list = []
    all_params = settings.COOKIE_DELIMITER.join(multi_parameters)
    all_params = all_params.split(settings.COOKIE_DELIMITER)
    # Check if not defined the "INJECT_HERE" tag in parameter
    if settings.INJECT_TAG not in cookie:
      # Check for empty values (in provided parameters).
      is_empty(multi_parameters, http_request_method)
      for param in range(0, len(all_params)):
        if param == 0 :
            old = re.findall(r'=(.*)', all_params[param])
            old = ''.join(old)
        else :
          old = value
        # Grab the value of cookie.
        value = re.findall(r'=(.*)', all_params[param])
        value = ''.join(value)
        # Replace the value of parameter with INJECT tag
        inject_value = value.replace(value, settings.INJECT_TAG)
        # Skip testing the parameter(s) with empty value(s).
        if menu.options.skip_empty:
          if len(value) == 0:   
            provided_value = re.findall(r'(.*)=', all_params[param])
            provided_value = ''.join(provided_value)
          else:
            all_params[param] = all_params[param].replace(value, inject_value)
            all_params[param-1] = all_params[param-1].replace(inject_value, old)
            cookie = settings.COOKIE_DELIMITER.join(all_params)
            cookies_list.append(cookie)
            cookie = cookies_list
        else:
          if len(value) == 0:        
            all_params[param] = all_params[param] + settings.INJECT_TAG
          else:
            all_params[param] = all_params[param].replace(value, inject_value)  
          all_params[param-1] = all_params[param-1].replace(inject_value, old)
          cookie = settings.COOKIE_DELIMITER.join(all_params)
          cookies_list.append(cookie)
          cookie = cookies_list

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