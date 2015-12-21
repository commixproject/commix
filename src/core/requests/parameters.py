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

import re
import os
import sys
import json

from src.utils import menu
from src.utils import settings
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

  # Check for REST-ful URLs format. 
  if "?" not in url:
    if settings.INJECT_TAG not in url and not menu.options.shellshock:
      print Back.RED + "(x) Error: You must set the \"INJECT_HERE\" tag to specify the testable parameter." + Style.RESET_ALL + "\n"
      os._exit(0)   
    return url

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

    # Reconstruct the url
    url = url_part + "?" + parameters
    return url

  # Check if multiple paramerters are supplied.
  else:
    # Check if defined the "INJECT_HERE" tag
    if settings.INJECT_TAG not in url:
      print Back.RED + "(x) Error: You must set the \"INJECT_HERE\" tag to specify the testable parameter." + Style.RESET_ALL + "\n"
      os._exit(0)

    all_params = settings.PARAMETER_DELIMITER.join(multi_parameters)

    for i in range(0,len(multi_parameters)):
      # Grab the value of parameter.
      value = re.findall(r'=(.*)', multi_parameters[i])
      value = ''.join(value)
      parameter = settings.PARAMETER_DELIMITER.join(multi_parameters)

    url = url_part + "?" + parameter  
    return url

      ## Multiple paramerters without the "INJECT_HERE" tag.
      #urls_list = []
      #for i in range(0,len(multi_parameters)):
        #if i == 0 :
          #old = re.findall(r'=(.*)', multi_parameters[i])
          #old = ''.join(old)
        #else :
          #old = value 
        ## Grab the value of parameter.
        #value = re.findall(r'=(.*)', multi_parameters[i])
        #value = ''.join(value)
        ##Replace the value of parameter with INJECT tag
        #inject_value = value.replace(value, settings.INJECT_TAG)
        #multi_parameters[i] = multi_parameters[i].replace(value, inject_value)
        #multi_parameters[i-1] = multi_parameters[i-1].replace(inject_value, old)
        #parameter = '&'.join(multi_parameters)
        ## Reconstruct the url
        #url = url_part + "?" + parameter
        ## Add all urls to url list.
        #urls_list.append(url)
      #return urls_list

"""
Define the vulnerable GET parameter.
"""
def vuln_GET_param(url):

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

  # Check if valid JSON
  def is_JSON_check(parameter):
    try:
      json_object = json.loads(parameter)
    except ValueError, err:
      if not "No JSON object could be decoded" in err:
        print Back.RED + "(x) Error: JSON " + str(err) + ". " + Style.RESET_ALL + "\n"
        sys.exit(0)
      return False
    else:  
      return True

  if all(symbol in parameter for symbol in settings.JSON_SYMBOLS):
    parameter = parameter.replace("'", "\"")

  # Check if JSON Object.
  if is_JSON_check(parameter):
    settings.IS_JSON = True
    #Split parameters 
    settings.PARAMETER_DELIMITER = ","
    multi_parameters = parameter.split(settings.PARAMETER_DELIMITER)

    # Check if single paramerter is supplied.
    if len(multi_parameters) == 1:

        # Check if defined the INJECT_TAG
        if settings.INJECT_TAG not in parameter:
          if settings.IS_JSON == True:
            #Grab the value of parameter.
            value = re.findall(r'\:\"(.*)\"', parameter)
            value = ''.join(value)
          else:
            #Grab the value of parameter.
            value = re.findall(r'\"(.*)\"', parameter)
            value = ''.join(value)

          # Replace the value of parameter with INJECT tag
          inject_value = value.replace(value, settings.INJECT_TAG)
          parameter = parameter.replace(value, inject_value)

        return parameter

    # Check if multiple paramerters are supplied.
    else:
      # Check if defined the "INJECT_HERE" tag
      if settings.INJECT_TAG not in parameter:
        print Back.RED + "(x) Error: You must set the \"INJECT_HERE\" tag to specify the testable parameter." + Style.RESET_ALL + "\n"
        os._exit(0)

      all_params = settings.PARAMETER_DELIMITER.join(multi_parameters)

      for i in range(0,len(multi_parameters)):
        # Grab the value of parameter.
        value = re.findall(r'\"(.*)\"', multi_parameters[i])
        value = ''.join(value)
        parameter = settings.PARAMETER_DELIMITER.join(multi_parameters)
      return parameter

  else:
    multi_parameters = parameter.split(settings.PARAMETER_DELIMITER)
    # Check if single paramerter is supplied.
    if len(multi_parameters) == 1:

        # Check if defined the INJECT_TAG
        if settings.INJECT_TAG not in parameter:

          #Grab the value of parameter.
          value = re.findall(r'=(.*)', parameter)
          value = ''.join(value)

          # Replace the value of parameter with INJECT tag
          inject_value = value.replace(value, settings.INJECT_TAG)
          parameter = parameter.replace(value, inject_value)
        return parameter

    # Check if multiple paramerters are supplied.
    else:
      # Check if defined the "INJECT_HERE" tag
      if settings.INJECT_TAG not in parameter:
        print Back.RED + "(x) Error: You must set the \"INJECT_HERE\" tag to specify the testable parameter." + Style.RESET_ALL + "\n"
        os._exit(0)

      all_params = settings.PARAMETER_DELIMITER.join(multi_parameters)

      for i in range(0,len(multi_parameters)):
        # Grab the value of parameter.
        value = re.findall(r'=(.*)', multi_parameters[i])
        value = ''.join(value)
        parameter = settings.PARAMETER_DELIMITER.join(multi_parameters)
      return parameter

      ## Multiple paramerters without the "INJECT_HERE" tag.
      #paramerters_list = []
      #for i in range(0,len(multi_parameters)):
        #if i == 0 :
          #old = re.findall(r'=(.*)', multi_parameters[i])
          #old = ''.join(old)
        #else :
          #old = value
        ## Grab the value of parameter.
        #value = re.findall(r'=(.*)', multi_parameters[i])
        #value = ''.join(value)
        ##Replace the value of parameter with INJECT tag
        #inject_value = value.replace(value, settings.INJECT_TAG)
        #multi_parameters[i] = multi_parameters[i].replace(value, inject_value)
        #multi_parameters[i-1] = multi_parameters[i-1].replace(inject_value, old)
        #parameter = '&'.join(multi_parameters)
        ## Reconstruct the paramerters
        ## Add all parameters to paramerters list.
        #paramerters_list.append(parameter)
      #return paramerters_list

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
    elif re.findall(r"" +settings.PARAMETER_DELIMITER + "\"(.*)\"\:\"" + settings.INJECT_TAG + "\"", parameter):
      vuln_parameter = re.findall(r"" +settings.PARAMETER_DELIMITER + "\"(.*)\"\:\"" + settings.INJECT_TAG + "\"", parameter)
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
def specify_cookie_parameter(cookie):

  # Specify the vulnerable cookie parameter
  if re.findall(r"" + settings.COOKIE_DELIMITER + "(.*)=" + settings.INJECT_TAG + "", cookie):
    inject_cookie = re.findall(r"" + settings.COOKIE_DELIMITER + "(.*)=" + settings.INJECT_TAG + "", cookie)
    inject_cookie = ''.join(inject_cookie)
    inject_cookie = re.sub(r"(.*)=(.*)" +settings.COOKIE_DELIMITER, "", inject_cookie)

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

#eof