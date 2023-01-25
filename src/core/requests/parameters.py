#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2023 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
 
For more see the file 'readme/COPYING' for copying permission.
"""

import re
import os
import sys
from src.utils import menu
from src.utils import settings
from src.core.injections.controller import checks
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.colorama import Fore, Back, Style, init

"""
Get the URL part of the defined URL.
"""
def get_url_part(url):
  # Find the URL part (scheme:[//host[:port]][/]path)
  o = _urllib.parse.urlparse(url)
  url_part = o.scheme + "://" + o.netloc + o.path

  return url_part

"""
Check if the 'INJECT_HERE' tag, is specified on GET Requests.
"""
def do_GET_check(url, http_request_method):
  """
  Grab the value of parameter.
  """
  def multi_params_get_value(parameter):
    value = re.findall(r'=(.*)', parameter)
    value = ''.join(value)
    return value
  
  # Do replacement with the 'INJECT_HERE' tag, if the wild card char is provided.
  url = checks.wildcard_character(url)

  # Check for REST-ful URLs format. 
  if "?" not in url:
    if settings.INJECT_TAG not in url and not menu.options.shellshock:
      checks.check_injection_level()
      if menu.options.level == settings.HTTP_HEADER_INJECTION_LEVEL or menu.options.header or menu.options.headers:
        return False
      if menu.options.level == settings.COOKIE_INJECTION_LEVEL:
        return False
      else: 
        err_msg = "No parameter(s) found for testing on the provided target URL. "
        if not menu.options.crawldepth:
          err_msg += "You are advised to rerun with '--crawl=2'."
        print(settings.print_critical_msg(err_msg))
        raise SystemExit()
    elif menu.options.shellshock:
      return False
    return [url]

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
        checks.inappropriate_format(multi_parameters)

      for param in range(len(multi_parameters)):
        multi_parameters[param] = checks.PCRE_e_modifier(multi_parameters[param], http_request_method)

      # Check for empty values (in provided parameters).
      if checks.is_empty(multi_parameters, http_request_method):
        return urls_list
      # Grab the value of parameter.
      _ = []
      _.append(parameters)
      parameters = ''.join(checks.check_similarities(_))
      value = multi_params_get_value(parameters)
      # Check if single parameter is supplied.
      if len(multi_parameters) == 1:
        if re.search(settings.VALUE_BOUNDARIES, value):
          value = checks.value_boundaries(parameters, value, http_request_method)
        # Check if defined the INJECT_TAG
        if settings.INJECT_TAG not in parameters:
          # Ignoring the anti-CSRF parameter(s).
          if checks.ignore_anticsrf_parameter(parameters):
            return urls_list
          if len(value) == 0:
            parameters = parameters + settings.INJECT_TAG
          else:
            parameters = parameters.replace(value, value + settings.INJECT_TAG) 
        # Reconstruct the URL
        url = url_part + "?" + parameters
        urls_list.append(url)
        return urls_list 
      else:
        # Check if multiple parameters are supplied without the "INJECT_HERE" tag.
        all_params = settings.PARAMETER_DELIMITER.join(multi_parameters)
        all_params = all_params.split(settings.PARAMETER_DELIMITER)
        # Check for similarity in provided parameter name and value.
        all_params = checks.check_similarities(all_params)
        # Check if defined the "INJECT_HERE" tag
        if settings.INJECT_TAG not in url:
          for param in range(0,len(all_params)):
            # Grab the value of parameter.
            value = multi_params_get_value(all_params[param])
          for param in range(0,len(all_params)):
            if param == 0 :
              old = multi_params_get_value(all_params[param])
            else :
              old = value
            # Grab the value of parameter.
            value = multi_params_get_value(all_params[param])
            if re.search(settings.VALUE_BOUNDARIES, value):
              value = checks.value_boundaries(all_params[param], value, http_request_method)
            # Ignoring the anti-CSRF parameter(s).
            if checks.ignore_anticsrf_parameter(all_params[param]):
              continue
            # Replace the value of parameter with INJECT_HERE tag
            if len(value) == 0:
              if not menu.options.skip_empty:
                all_params[param] = all_params[param] + settings.INJECT_TAG
            else:
              all_params[param] = all_params[param].replace(value, value + settings.INJECT_TAG)
            all_params[param - 1] = all_params[param - 1].replace(settings.INJECT_TAG, "")
            parameter = settings.PARAMETER_DELIMITER.join(all_params)
            # Reconstruct the URL
            url = url_part + "?" + parameter
            url = url.replace(settings.RANDOM_TAG,"")
            urls_list.append(url)
        else:
          for param in range(0,len(multi_parameters)):
            value = multi_params_get_value(multi_parameters[param])
            parameter = settings.PARAMETER_DELIMITER.join(multi_parameters)
          # Reconstruct the URL  
          url = url_part + "?" + parameter  
          urls_list.append(url)

    return urls_list 

"""
Define the vulnerable GET parameter.
"""
def vuln_GET_param(url):
  # Define the vulnerable parameter
  if "?" not in url:
    # Grab the value of parameter.
    value = re.findall(r'/(.*)/' + settings.INJECT_TAG + "", url)
    value = ''.join(value)
    vuln_parameter = re.sub(r"/(.*)/", "", value)

  elif re.search(r"" + settings.PARAMETER_DELIMITER + "(.*)=[\S*(\\/)]*" + settings.INJECT_TAG, url) or \
       re.search(r"\?(.*)=[\S*(\\/)]*" + settings.INJECT_TAG , url):
    pairs = url.split("?")[1].split(settings.PARAMETER_DELIMITER)
    for param in range(0,len(pairs)):
      if settings.INJECT_TAG in pairs[param]:
        vuln_parameter = pairs[param].split("=")[0]
        if settings.WILDCARD_CHAR_APPLIED:
          try:
            settings.POST_WILDCARD_CHAR = pairs[param].split("=")[1].split(settings.INJECT_TAG)[1]
          except Exception:
            pass
        settings.TESTABLE_VALUE = pairs[param].split("=")[1].replace(settings.INJECT_TAG,"")
        if re.search(settings.VALUE_BOUNDARIES, settings.TESTABLE_VALUE) and settings.INJECT_INSIDE_BOUNDARIES:
          settings.TESTABLE_VALUE  = checks.get_value_inside_boundaries(settings.TESTABLE_VALUE)
        if settings.BASE64_PADDING  in pairs[param]:
          settings.TESTABLE_VALUE = settings.TESTABLE_VALUE + settings.BASE64_PADDING  
        break
  else:
    vuln_parameter = url
  
  return vuln_parameter 

"""
Check if the 'INJECT_HERE' tag, is specified on POST Requests.
"""
def do_POST_check(parameter, http_request_method):
  """
  Grab the value of parameter.
  """
  def multi_params_get_value(param, all_params):
    if settings.IS_JSON:
      value = re.findall(r'\:(.*)', all_params[param])
      value = re.sub(settings.IGNORE_SPECIAL_CHAR_REGEX, '', ''.join(value))
    elif settings.IS_XML:
      value = re.findall(r'>(.*)</', all_params[param])
      value = ''.join(value)
    else:  
      value = re.findall(r'=(.*)', all_params[param])
      value = ''.join(value)
    return value

  # Do replacement with the 'INJECT_HERE' tag, if the wild card char is provided.
  parameter = checks.wildcard_character(parameter).replace("'","\"")
  checks.check_injection_level()
  # Check if JSON Object.
  if checks.is_JSON_check(parameter) or checks.is_JSON_check(checks.check_quotes_json_data(parameter)):
    if checks.is_JSON_check(checks.check_quotes_json_data(parameter)):
      parameter = checks.check_quotes_json_data(parameter)
    if not settings.IS_JSON:
      checks.process_json_data()
      settings.PARAMETER_DELIMITER = ","
  # Check if XML Object.
  elif checks.is_XML_check(parameter): 
    if not settings.IS_XML:
      checks.process_xml_data()
      settings.PARAMETER_DELIMITER = ""
  else:
    pass
  parameters_list = []
  # Split multiple parameters
  if settings.IS_XML:
    parameter = re.sub(r">\s*<", '>\n<', parameter).replace("\\n","\n")
    _ = []
    parameters = re.findall(r'(.*)', parameter)
    parameters = [param + "\n" for param in parameters if param]
    for value in range(0,len(parameters)):
      _.append(parameters[value])
    multi_parameters = _
  else: 
    try:
      multi_parameters = parameter.split(settings.PARAMETER_DELIMITER)
      multi_parameters = [x for x in multi_parameters if x]
    except ValueError as err_msg:
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()

  # Check for inappropriate format in provided parameter(s).
  if len([s for s in multi_parameters if "=" in s]) != (len(multi_parameters)) and \
     not settings.IS_JSON and \
     not settings.IS_XML:
    checks.inappropriate_format(multi_parameters)

  for param in range(len(multi_parameters)):
    multi_parameters[param] = checks.PCRE_e_modifier(multi_parameters[param], http_request_method)

  # Check if single parameter is supplied.
  if len(multi_parameters) == 1:
    if settings.INJECT_TAG not in multi_parameters[0]:
      # Grab the value of parameter.
      if settings.IS_JSON:
        # Grab the value of parameter.
        value = re.findall(r'\"(.*)\"', parameter)
        value = ''.join(value)
        if value != settings.INJECT_TAG:
          value = re.findall(r'\s*\:\s*\"(.*)\"', parameter)
          value = ''.join(value)
      elif settings.IS_XML:
        # Grab the value of parameter.
        value = re.findall(r'>(.*)</', parameter)
        value = ''.join(value)
      else:
        _ = []
        _.append(parameter)
        parameter = ''.join(checks.check_similarities(_))
        value = re.findall(r'=(.*)', parameter)
        value = ''.join(value)

      if checks.is_empty(multi_parameters, http_request_method):
        return parameter
      else:
        # Ignoring the anti-CSRF parameter(s).
        if checks.ignore_anticsrf_parameter(parameter):
          return parameter
        if re.search(settings.VALUE_BOUNDARIES, value):
          value = checks.value_boundaries(parameter, value, http_request_method)
        # Replace the value of parameter with INJECT_HERE tag
        if len(value) == 0:
          if settings.IS_JSON:
            parameter = parameter.replace(":\"\"", ":\"" + settings.INJECT_TAG + "\"")
          else:  
            parameter = parameter + settings.INJECT_TAG
        else:
          parameter = parameter.replace(value, value + settings.INJECT_TAG)
        return parameter
    else:
      return multi_parameters

  else:
    # Check if multiple parameters are supplied without the "INJECT_HERE" tag.
    if settings.IS_XML:
      all_params = multi_parameters
    else:
      all_params = settings.PARAMETER_DELIMITER.join(multi_parameters)
      # Check for similarity in provided parameter name and value.
      all_params = all_params.split(settings.PARAMETER_DELIMITER)
      all_params = checks.check_similarities(all_params)

    # Check if not defined the "INJECT_HERE" tag in parameter
    if settings.INJECT_TAG not in parameter:
      if checks.is_empty(multi_parameters, http_request_method):
        return parameter
      for param in range(0, len(all_params)):
        if param == 0 :
          old = multi_params_get_value(param, all_params)
        else :
          old = value
        # Grab the value of parameter.
        value = multi_params_get_value(param, all_params)
        if re.search(settings.VALUE_BOUNDARIES, value):
          value = checks.value_boundaries(all_params[param], value, http_request_method)
        # Ignoring the anti-CSRF parameter(s).
        if checks.ignore_anticsrf_parameter(all_params[param]):
          continue
        # Replace the value of parameter with INJECT_HERE tag  
        if len(value) == 0:
          if not menu.options.skip_empty:
            if settings.IS_JSON:
              all_params[param] = all_params[param].replace(":\"\"", ":\"" + settings.INJECT_TAG + "\"").replace(":\\\"\\\"", ":\\\"" + settings.INJECT_TAG + "\\\"")
            elif settings.IS_XML: 
              all_params[param] = all_params[param].replace("></", ">" + settings.INJECT_TAG + "</")
            else:  
              all_params[param] = all_params[param] + settings.INJECT_TAG
        else:
          all_params[param] = all_params[param].replace(value, value + settings.INJECT_TAG)
        all_params[param - 1] = all_params[param - 1].replace(settings.INJECT_TAG, "")
        parameter = settings.PARAMETER_DELIMITER.join(all_params)
        parameter = parameter.replace(settings.RANDOM_TAG,"")
        if type(parameter) != list:
          parameters_list.append(parameter)
        parameter = parameters_list

    else:
      for param in range(0, len(multi_parameters)):
        # Grab the value of parameter.
        value = multi_params_get_value(param, multi_parameters)
        parameter = settings.PARAMETER_DELIMITER.join(multi_parameters)

    return parameter

"""
Define the vulnerable POST parameter.
"""
def vuln_POST_param(parameter, url):
  if isinstance(parameter, list):
    parameter = " ".join(parameter)
  # JSON data format
  if settings.IS_JSON:
    param = re.sub(settings.IGNORE_SPECIAL_CHAR_REGEX, '', parameter.split(settings.INJECT_TAG)[0])
    if param:
      if "(" in param:
        param = param.split("(")[1]
      vuln_parameter = param.split(",")[-1:]
      if ":" in vuln_parameter[0]:
        settings.TESTABLE_VALUE = vuln_parameter[0].split(":")[1]
        vuln_parameter = vuln_parameter[0].split(":")[0]
      vuln_parameter = ''.join(vuln_parameter)

  # XML data format
  elif settings.IS_XML:
    if re.findall(r"" + settings.INJECT_TAG + "([^>]+)", parameter):
      vuln_parameter = re.findall(r"" + settings.INJECT_TAG + "([^>]+)", parameter)
      vuln_parameter = re.findall(r"" + "([^</]+)", vuln_parameter[0])
      if settings.WILDCARD_CHAR_APPLIED and len(vuln_parameter) != 1 :
        settings.POST_WILDCARD_CHAR = vuln_parameter[0]
        settings.TESTABLE_VALUE = vuln_parameter = vuln_parameter[1]
      else:  
        settings.TESTABLE_VALUE = re.findall(r"" + "([^>]+)" + settings.INJECT_TAG, parameter)[0]
      vuln_parameter = ''.join(vuln_parameter)
  
  # Regular POST data format.
  else:
    if re.search(r"" + settings.PARAMETER_DELIMITER + "(.*)=[\S*(\\/)]*" + settings.INJECT_TAG, parameter) or \
       re.search(r"(.*)=[\S*(\\/)]*" + settings.INJECT_TAG , parameter):
      pairs = parameter.split(settings.PARAMETER_DELIMITER)
      for param in range(0,len(pairs)):
        if settings.INJECT_TAG in pairs[param]:
          vuln_parameter = pairs[param].split("=")[0]
          if settings.WILDCARD_CHAR_APPLIED:
            try:
              settings.POST_WILDCARD_CHAR = pairs[param].split("=")[1].split(settings.INJECT_TAG)[1]
            except Exception:
              pass
          settings.TESTABLE_VALUE = pairs[param].split("=")[1].replace(settings.INJECT_TAG,"")
          if re.search(settings.VALUE_BOUNDARIES, settings.TESTABLE_VALUE) and settings.INJECT_INSIDE_BOUNDARIES:
            settings.TESTABLE_VALUE  = checks.get_value_inside_boundaries(settings.TESTABLE_VALUE)
          if settings.BASE64_PADDING  in pairs[param]:
            settings.TESTABLE_VALUE = settings.TESTABLE_VALUE + settings.BASE64_PADDING  
          break

  if 'vuln_parameter' not in locals():
    return parameter

  return vuln_parameter

"""
Define the injection prefixes.
"""
def prefixes(payload, prefix):
  if settings.COOKIE_INJECTION == True:
    specify_cookie_parameter(menu.options.cookie)
  elif settings.USER_AGENT_INJECTION == True:
    specify_user_agent_parameter(menu.options.agent)
  elif settings.REFERER_INJECTION == True:
    specify_referer_parameter(menu.options.referer)
  elif settings.HOST_INJECTION == True:
    specify_host_parameter(menu.options.host)

  # Check if defined "--prefix" option.
  testable_value = settings.TESTABLE_VALUE
  if settings.WILDCARD_CHAR_APPLIED and len(settings.POST_WILDCARD_CHAR) != 0:
    testable_value = ""
  if menu.options.prefix:
    payload = testable_value + menu.options.prefix + prefix + payload
  else:
    payload = testable_value + prefix + payload 

  return payload

"""
Define the injection suffixes.
"""
def suffixes(payload, suffix):
  # Check if defined "--suffix" option.
  if settings.COOKIE_INJECTION and suffix == settings.COOKIE_DELIMITER:
    suffix = ""
  if menu.options.suffix:
    payload = payload + suffix + menu.options.suffix
  else:
    payload = payload + suffix
    
  return payload

"""
The cookie based injection.
"""
def do_cookie_check(cookie):

  """
  Grab the value of parameter.
  """
  def multi_params_get_value(parameter):
    value = re.findall(r'=(.*)', parameter)
    value = ''.join(value)
    return value

  # Do replacement with the 'INJECT_HERE' tag, if the wild card char is provided.
  cookie = checks.wildcard_character(cookie)
  multi_parameters = cookie.split(settings.COOKIE_DELIMITER)
  # Check for inappropriate format in provided parameter(s).
  if len([s for s in multi_parameters if "=" in s]) != (len(multi_parameters)):
    checks.inappropriate_format(multi_parameters)
  # Grab the value of parameter.
  value = multi_params_get_value(cookie)
  # Replace the value of parameter with INJECT tag
  # Check if single paramerter is supplied.
  if len(multi_parameters) == 1:
    # Ignoring the anti-CSRF parameter(s).
    if checks.ignore_anticsrf_parameter(cookie):
      return cookie
    # Ignoring the Google analytics cookie parameter.
    if checks.ignore_google_analytics_cookie(cookie):
      return cookie
    # Check for empty values (in provided parameters).
    if checks.is_empty(multi_parameters, http_request_method = "cookie"):
      return cookie
    # Check if defined the INJECT_TAG
    if settings.INJECT_TAG not in cookie:
      if len(value) == 0:
        cookie = cookie + settings.INJECT_TAG
      else:
        cookie = cookie.replace(value, value + settings.INJECT_TAG)
    return cookie

  # Check if multiple parameters are supplied.
  else:
    cookies_list = []
    all_params = settings.COOKIE_DELIMITER.join(multi_parameters)
    all_params = all_params.split(settings.COOKIE_DELIMITER)
    # Check if not defined the "INJECT_HERE" tag in parameter
    if settings.INJECT_TAG not in cookie:
      # Check for empty values (in provided parameters).
      if checks.is_empty(multi_parameters, http_request_method = "cookie"):
        return cookie
      for param in range(0, len(all_params)):
        if param == 0 :
          old = multi_params_get_value(all_params[param])
        else :
          old = value
        # Grab the value of cookie.
        value = multi_params_get_value(all_params[param])
        # Ignoring the anti-CSRF parameter(s).
        if checks.ignore_anticsrf_parameter(all_params[param]):
          continue
        # Ignoring the Google analytics cookie parameter.
        if checks.ignore_google_analytics_cookie(all_params[param]):
          continue
        # Replace the value of parameter with INJECT tag
        if len(value) == 0:     
          if not menu.options.skip_empty:   
            all_params[param] = all_params[param] + settings.INJECT_TAG
        else:
          all_params[param] = all_params[param].replace(value, value + settings.INJECT_TAG)  
        all_params[param - 1] = all_params[param - 1].replace(settings.INJECT_TAG, "")
        cookie = settings.COOKIE_DELIMITER.join(all_params)
        if type(cookie) != list:
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

  # Specify the vulnerable cookie parameter
  if re.search(r"" + settings.COOKIE_DELIMITER + "(.*)=[\S*(\\/)]*" + settings.INJECT_TAG, cookie) or \
     re.search(r"(.*)=[\S*(\\/)]*" + settings.INJECT_TAG , cookie):
    pairs = cookie.split(settings.COOKIE_DELIMITER)
    for param in range(0,len(pairs)):
      if settings.INJECT_TAG in pairs[param]:
        inject_cookie = pairs[param].split("=")[0]
        if settings.WILDCARD_CHAR_APPLIED:
          try:
            settings.POST_WILDCARD_CHAR = pairs[param].split("=")[1].split(settings.INJECT_TAG)[1]
          except Exception:
            pass
        settings.TESTABLE_VALUE = pairs[param].split("=")[1].replace(settings.INJECT_TAG,"")
        break
  else:
    inject_cookie = cookie

  return inject_cookie 

"""
The user-agent based injection.
"""
def specify_user_agent_parameter(user_agent):
  settings.TESTABLE_VALUE = user_agent.replace(settings.INJECT_TAG,"")

  return user_agent
 
"""
The referer based injection.
"""
def specify_referer_parameter(referer):
  settings.TESTABLE_VALUE = referer.replace(settings.INJECT_TAG,"")

  return referer

"""
The host based injection.
"""
def specify_host_parameter(host):
  settings.TESTABLE_VALUE = host.replace(settings.INJECT_TAG,"")

  return host

"""
The Custom http header based injection.
"""
def specify_custom_header_parameter(header_name):
  header_name = settings.CUSTOM_HEADER_NAME

  return header_name

# eof