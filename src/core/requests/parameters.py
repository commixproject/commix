#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2024 Anastasios Stasinopoulos (@ancst).

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
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.colorama import Fore, Back, Style, init
from src.thirdparty.flatten_json.flatten_json import flatten, unflatten_list
from src.thirdparty.odict import OrderedDict

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

  if settings.CUSTOM_INJECTION_MARKER and settings.SKIP_NON_CUSTOM:
      return False
      
  if settings.USER_DEFINED_POST_DATA:
    if settings.CUSTOM_INJECTION_MARKER_CHAR in settings.USER_DEFINED_POST_DATA and settings.SKIP_NON_CUSTOM:
      return False
    if settings.INJECT_TAG in url:
      settings.IGNORE_USER_DEFINED_POST_DATA = True

  # Do replacement with the 'INJECT_HERE' tag, if the custom injection marker character is provided.
  url = checks.process_custom_injection_data(url)
  # Check for REST-ful URLs format.
  if "?" not in url:
    settings.USER_DEFINED_URL_DATA = False
    if settings.INJECT_TAG not in url and not menu.options.shellshock:
      if len(settings.TEST_PARAMETER) != 0 or \
         menu.options.level == settings.HTTP_HEADER_INJECTION_LEVEL or \
         menu.options.level == settings.COOKIE_INJECTION_LEVEL or \
         settings.USER_DEFINED_POST_DATA and not settings.IGNORE_USER_DEFINED_POST_DATA:
        return False
      else:
        err_msg = "No parameter(s) found for testing in the provided data. "
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
      try:
        multi_parameters = parameters.split(settings.PARAMETER_DELIMITER)
        multi_parameters = [x for x in multi_parameters if x]
      except ValueError as err_msg:
        print(settings.print_critical_msg(err_msg))
        raise SystemExit()
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
            if settings.CUSTOM_INJECTION_MARKER:
              if settings.ASTERISK_MARKER in value:
                parameters = parameters.replace(value, value.replace(settings.ASTERISK_MARKER, settings.INJECT_TAG))
            else:
              if not settings.ASTERISK_MARKER in value and not settings.CUSTOM_INJECTION_MARKER_CHAR in value:
                parameters = parameters.replace(value, value + settings.INJECT_TAG)
        # Reconstruct the URL
        url = url_part + "?" + parameters
        url = url.replace(settings.RANDOM_TAG, "").replace(settings.ASTERISK_MARKER,"")
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
              all_params[param - 1] = ''.join(all_params[param - 1]).replace(settings.INJECT_TAG, "")
              continue
            # Replace the value of parameter with INJECT_HERE tag
            if len(value) == 0:
              if not menu.options.skip_empty:
                all_params[param] = ''.join(all_params[param] + settings.INJECT_TAG)
            else:
              if settings.CUSTOM_INJECTION_MARKER:
                if settings.ASTERISK_MARKER in value:
                  all_params[param] = ''.join(all_params[param]).replace(value, value.replace(settings.ASTERISK_MARKER, settings.INJECT_TAG))
              else:
                if not settings.ASTERISK_MARKER in value and not settings.CUSTOM_INJECTION_MARKER_CHAR in value:
                  all_params[param] = ''.join(all_params[param]).replace(value, value + settings.INJECT_TAG)
            all_params[param - 1] = ''.join(all_params[param - 1]).replace(settings.INJECT_TAG, "")
            parameter = settings.PARAMETER_DELIMITER.join(all_params)
            # Reconstruct the URL
            url = url_part + "?" + parameter
            url = url.replace(settings.RANDOM_TAG, "").replace(settings.ASTERISK_MARKER,"")
            urls_list.append(url)
        else:
          for param in range(0,len(multi_parameters)):
            value = multi_params_get_value(multi_parameters[param])
            parameter = settings.PARAMETER_DELIMITER.join(multi_parameters)
          # Reconstruct the URL
          url = url_part + "?" + parameter
          url = url.replace(settings.RANDOM_TAG, "")
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

  elif re.search(r"" + settings.PARAMETER_DELIMITER + r"(.*)=[\S*(\\/)]*" + settings.INJECT_TAG, url) or \
       re.search(r"\?(.*)=[\S*(\\/)]*" + settings.INJECT_TAG , url):
    pairs = url.split("?")[1].split(settings.PARAMETER_DELIMITER)
    for param in range(0,len(pairs)):
      if settings.INJECT_TAG in pairs[param]:
        vuln_parameter = pairs[param].split("=")[0]
        if settings.CUSTOM_INJECTION_MARKER:
          try:
            settings.TEST_PARAMETER = vuln_parameter
            settings.PRE_CUSTOM_INJECTION_MARKER_CHAR = pairs[param].split("=")[1].split(settings.INJECT_TAG)[1]
          except Exception:
            pass
        settings.TESTABLE_VALUE = pairs[param].split("=")[1].replace(settings.INJECT_TAG, "")
        if re.search(settings.VALUE_BOUNDARIES, settings.TESTABLE_VALUE) and settings.INJECT_INSIDE_BOUNDARIES:
          settings.TESTABLE_VALUE  = checks.get_value_inside_boundaries(settings.TESTABLE_VALUE)
        if settings.BASE64_PADDING  in pairs[param]:
          settings.TESTABLE_VALUE = settings.TESTABLE_VALUE + settings.BASE64_PADDING
        break
  else:
    vuln_parameter = url

  if settings.USER_DEFINED_POST_DATA and vuln_parameter:
    settings.IGNORE_USER_DEFINED_POST_DATA = True

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
      if not value:
        value = all_params[param]
      value = ''.join(value) 
      if value.endswith("\"}"):
        value = (value[:-len("}")])
      if checks.quoted_value(value) and any(_ in "[]{}" for _ in value):
        value = value.replace("\"","")
      else:
        value = re.sub(settings.IGNORE_JSON_CHAR_REGEX, '', value)
    elif settings.IS_XML:
      value = re.findall(r'>(.*)</', all_params[param])
      value = ''.join(value)
    else:
      value = re.findall(r'=(.*)', all_params[param])
      value = ''.join(value)
    return value

  """
  Check for int value inside JSON objects.
  """
  def json_int_check(parameter, value):
    """
    Check JSON objects format.
    """
    def json_format(parameter):
      return json.loads(parameter, object_pairs_hook=OrderedDict)

    try:
      parameter = json_format(parameter)
    except:
      if not checks.quoted_value(value + settings.INJECT_TAG) in parameter:
        if any(_ in "[]{}" for _ in value):
          v = re.sub(settings.IGNORE_JSON_CHAR_REGEX, '', value.lstrip())
          parameter = parameter.replace(value + settings.INJECT_TAG, value.replace(v, checks.quoted_value(v + settings.INJECT_TAG)))
        else:
          parameter = parameter.replace(value + settings.INJECT_TAG, checks.quoted_value(value + settings.INJECT_TAG))        
      if settings.INJECT_TAG in value and not checks.quoted_value(value) in parameter:
        value = re.sub(settings.IGNORE_JSON_CHAR_REGEX, '', value.lstrip())
        parameter = parameter.replace(value, checks.quoted_value(value))
      parameter = json_format(parameter)

    _ = True
    if isinstance(parameter, list):
      parameter = parameter[(len(parameter) - 1)]

    if isinstance(parameter, OrderedDict):
      for keys,values in parameter.items():
        if settings.INJECT_TAG in keys:
          _ = False
          break

    if _ and isinstance(parameter, OrderedDict):
      parameter = unflatten_list(parameter)

    parameter = json.dumps(parameter)
    return parameter

  # Do replacement with the 'INJECT_HERE' tag, if the custom injection marker character is provided.
  parameter = checks.process_custom_injection_data(parameter).replace("'","\"").replace(", ",",").replace(",\"", ", \"")
  # Check if JSON Object.
  if checks.is_JSON_check(parameter) or checks.is_JSON_check(checks.check_quotes_json_data(parameter)):
    if checks.is_JSON_check(checks.check_quotes_json_data(parameter)):
      parameter = checks.check_quotes_json_data(parameter)
    if not settings.IS_JSON:
      data_type = "JSON"
      settings.IS_JSON = checks.process_data(data_type, http_request_method)
      settings.PARAMETER_DELIMITER = ","
  # Check if XML Object.
  elif checks.is_XML_check(parameter):
    if not settings.IS_XML:
      data_type = "XML/SOAP"
      settings.IS_XML = checks.process_data(data_type, http_request_method)
      settings.PARAMETER_DELIMITER = "\n"

  elif settings.TEST_PARAMETER and not any(ext in parameter for ext in settings.TEST_PARAMETER) and not settings.INJECT_TAG in parameter:
    if settings.SKIP_NON_CUSTOM:
      settings.IGNORE_USER_DEFINED_POST_DATA = True

  if settings.IGNORE_USER_DEFINED_POST_DATA and settings.SKIP_NON_CUSTOM:
    return ""

  parameters_list = []
  # Split multiple parameters
  if settings.IS_XML:
    parameter = re.sub(r">\s*<", ">" + settings.PARAMETER_DELIMITER + "<", parameter)
    _ = []
    parameters = re.findall(r'(.*)', parameter)
    parameters = [param for param in parameters if param]
    for value in range(0,len(parameters)):
      _.append(parameters[value])
    multi_parameters = _
  else:
    try:
      multi_parameters = parameter.split(settings.PARAMETER_DELIMITER)
    except ValueError as err_msg:
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()

  # Check for inappropriate format in provided parameter(s).
  if len([s for s in multi_parameters if "=" in s]) != (len(multi_parameters)) and \
     not settings.IS_JSON and \
     not settings.IS_XML:
    return ""

  for param in range(len(multi_parameters)):
    multi_parameters[param] = checks.PCRE_e_modifier(multi_parameters[param], http_request_method)

  _ = []
  _.append(parameter)
  parameter = ''.join(checks.check_similarities(_))
  # Check if single parameter is supplied.
  if len(multi_parameters) == 1:
    if settings.INJECT_TAG not in multi_parameters[0]:
      # Grab the value of parameter.
      if settings.IS_JSON:
        # Grab the value of parameter.
        value = multi_params_get_value(0, checks.check_similarities(_))
      elif settings.IS_XML:
        # Grab the value of parameter.
        value = re.findall(r'>(.*)</', parameter)
        value = ''.join(value)
      else:
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
          if settings.CUSTOM_INJECTION_MARKER:
            if settings.ASTERISK_MARKER in value:
              parameter = parameter.replace(value, value.replace(settings.ASTERISK_MARKER, settings.INJECT_TAG))
          else:
            if not settings.ASTERISK_MARKER in value and not settings.CUSTOM_INJECTION_MARKER_CHAR in value:
              parameter = parameter.replace(value, value + settings.INJECT_TAG)

        if settings.IS_JSON:
          parameter = json_int_check(parameter, value)
        parameter = parameter.replace(settings.RANDOM_TAG, "").replace(settings.ASTERISK_MARKER,"")
        return parameter
    else:
      for param in range(0, len(multi_parameters)):
        # Grab the value of parameter.
        value = multi_params_get_value(param, multi_parameters)
        parameter = settings.PARAMETER_DELIMITER.join(multi_parameters)
        parameter = parameter.replace(settings.RANDOM_TAG, "")
        if settings.IS_JSON and settings.INJECT_TAG in value:
          parameter = json_int_check(parameter, value)
          break
      return parameter

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
          all_params[param - 1] = ''.join(all_params[param - 1]).replace(settings.INJECT_TAG, "")
          continue
        # Replace the value of parameter with INJECT_HERE tag
        if len(value) == 0:
          if not menu.options.skip_empty:
            if settings.IS_JSON:
              all_params[param] = ''.join(all_params[param]).replace(":\"\"", ":\"" + settings.INJECT_TAG + "\"").replace(":\\\"\\\"", ":\\\"" + settings.INJECT_TAG + "\\\"")
            elif settings.IS_XML:
              all_params[param] = ''.join(all_params[param]).replace("></", ">" + settings.INJECT_TAG + "</")
            else:
              all_params[param] = ''.join(all_params[param] + settings.INJECT_TAG)
        else:
          if settings.CUSTOM_INJECTION_MARKER:
            if settings.ASTERISK_MARKER in value:
              all_params[param] = ''.join(all_params[param]).replace(value, value.replace(settings.ASTERISK_MARKER, settings.INJECT_TAG))
          else:
            if not settings.ASTERISK_MARKER in value and not settings.CUSTOM_INJECTION_MARKER_CHAR in value:
              all_params[param] = ''.join(all_params[param]).replace(value, value + settings.INJECT_TAG)
          if settings.IS_JSON and len(all_params[param].split("\":")) == 2:
            check_parameter = all_params[param].split("\":")[0] 
            if settings.INJECT_TAG in check_parameter:
              all_params[param] = all_params[param].replace(check_parameter, check_parameter.replace(settings.INJECT_TAG, ""))
              
        all_params[param - 1] = ''.join(all_params[param - 1]).replace(settings.INJECT_TAG, "")
        parameter = settings.PARAMETER_DELIMITER.join(all_params)
        parameter = parameter.replace(settings.RANDOM_TAG, "").replace(settings.ASTERISK_MARKER,"")
        if settings.IS_JSON:
          if (len(all_params)) == 1 and settings.INJECT_TAG not in all_params[param]:
            parameter = parameter.replace(value, value + settings.INJECT_TAG)
          parameter = json_int_check(parameter, value)
        if type(parameter) != list:
          parameters_list.append(parameter)
        parameter = parameters_list
    else:
      for param in range(0, len(multi_parameters)):
        # Grab the value of parameter.
        value = multi_params_get_value(param, multi_parameters)
        parameter = settings.PARAMETER_DELIMITER.join(multi_parameters)
        parameter = parameter.replace(settings.RANDOM_TAG, "")
        if settings.IS_JSON and settings.INJECT_TAG in multi_parameters[param]:
          parameter = json_int_check(parameter, value)
          break
    return parameter

"""
Define the vulnerable POST parameter.
"""
def vuln_POST_param(parameter, url):
  if isinstance(parameter, list):
    parameter = " ".join(parameter)

  # JSON data format.
  if settings.IS_JSON:
    parameter = json.loads(parameter, object_pairs_hook=OrderedDict)
    parameter = flatten(parameter)
    parameter = json.dumps(parameter)
    parameters = re.sub(settings.IGNORE_JSON_CHAR_REGEX, '', parameter.split(settings.INJECT_TAG)[0].replace(",\"", settings.RANDOM_TAG + "\""))
    parameters = ''.join(parameters.split(", ")[-1:]).strip()
    parameters = ''.join(parameters.split(":")[0]).strip()
    settings.TESTABLE_VALUE = vuln_parameter = ''.join(parameters.split(settings.RANDOM_TAG)[:1])
    if settings.CUSTOM_INJECTION_MARKER:
      settings.TEST_PARAMETER = vuln_parameter

  # XML data format.
  elif settings.IS_XML:
    parameters = list(parameter.replace("></",">" + settings.END_LINE[1] + "</").split(settings.END_LINE[1]))
    for item in parameters:
      if settings.INJECT_TAG in item:
        result = re.sub(re.compile('<.*?>'), '', item)
        if not settings.CUSTOM_INJECTION_MARKER and settings.CUSTOM_INJECTION_MARKER_CHAR in item:
          item = item.replace(settings.CUSTOM_INJECTION_MARKER_CHAR,"")
        _ = (re.search('<(.*)>' + result + '</(.*)>', item))
        if _ and (_.groups()[0]) == (_.groups()[1]):
          vuln_parameter = ''.join(_.groups()[0])
          if settings.CUSTOM_INJECTION_MARKER:
            try:
              settings.TEST_PARAMETER = vuln_parameter
              settings.PRE_CUSTOM_INJECTION_MARKER_CHAR = result.split(settings.INJECT_TAG)[1]
            except Exception:
              pass
          settings.TESTABLE_VALUE = result.split(settings.INJECT_TAG)[0]

  # Regular POST data format.
  else:
    if re.search(r"" + settings.PARAMETER_DELIMITER + r"(.*)=[\S*(\\/)]*" + settings.INJECT_TAG, parameter) or \
       re.search(r"(.*)=[\S*(\\/)]*" + settings.INJECT_TAG , parameter):
      pairs = parameter.split(settings.PARAMETER_DELIMITER)
      for param in range(0,len(pairs)):
        if settings.INJECT_TAG in pairs[param]:
          vuln_parameter = pairs[param].split("=")[0]
          if settings.CUSTOM_INJECTION_MARKER:
            try:
              settings.TEST_PARAMETER = vuln_parameter
              settings.PRE_CUSTOM_INJECTION_MARKER_CHAR = pairs[param].split("=")[1].split(settings.INJECT_TAG)[1]
            except Exception:
              pass
          settings.TESTABLE_VALUE = pairs[param].split("=")[1].replace(settings.INJECT_TAG, "")
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
  elif settings.CUSTOM_HEADER_INJECTION == True:
    specify_host_parameter("")

  # Check if defined "--prefix" option.
  testable_value = settings.TESTABLE_VALUE
  if settings.CUSTOM_INJECTION_MARKER and len(settings.PRE_CUSTOM_INJECTION_MARKER_CHAR) != 0:
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

  # Do replacement with the 'INJECT_HERE' tag, if the custom injection marker character is provided.
  cookie = checks.process_custom_injection_data(cookie)
  try:
    multi_parameters = cookie.split(settings.COOKIE_DELIMITER)
  except ValueError as err_msg:
    print(settings.print_critical_msg(err_msg))
    raise SystemExit()
  # Check for inappropriate format in provided parameter(s).
  if len([s for s in multi_parameters if "=" in s]) != (len(multi_parameters)):
    checks.inappropriate_format(multi_parameters)

  _ = []
  _.append(cookie)
  cookie = ''.join(checks.check_similarities(_))
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
    if checks.is_empty(multi_parameters, http_request_method=settings.COOKIE):
      return cookie
    # Check if defined the INJECT_TAG
    if settings.INJECT_TAG not in cookie:
      if len(value) == 0:
        cookie = cookie + settings.INJECT_TAG
      else:
        if settings.CUSTOM_INJECTION_MARKER:
          if settings.ASTERISK_MARKER in value:
            cookie = cookie.replace(value, value.replace(settings.ASTERISK_MARKER, settings.INJECT_TAG))
        else:
          if not settings.ASTERISK_MARKER in value and not settings.CUSTOM_INJECTION_MARKER_CHAR in value:
            cookie = cookie.replace(value, value + settings.INJECT_TAG)

    cookie = cookie.replace(settings.RANDOM_TAG, "").replace(settings.ASTERISK_MARKER,"")
    return cookie

  # Check if multiple parameters are supplied.
  else:
    cookies_list = []
    all_params = settings.COOKIE_DELIMITER.join(multi_parameters)
    all_params = all_params.split(settings.COOKIE_DELIMITER)
    all_params = checks.check_similarities(all_params)
    # Check if not defined the "INJECT_HERE" tag in parameter
    if settings.INJECT_TAG not in cookie:
      # Check for empty values (in provided parameters).
      if checks.is_empty(multi_parameters, http_request_method=settings.COOKIE):
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
          all_params[param - 1] = ''.join(all_params[param - 1]).replace(settings.INJECT_TAG, "")
          continue
        # Ignoring the Google analytics cookie parameter.
        if checks.ignore_google_analytics_cookie(all_params[param]):
          continue
        # Replace the value of parameter with INJECT tag
        if len(value) == 0:
          if not menu.options.skip_empty:
            all_params[param] = ''.join(all_params[param] + settings.INJECT_TAG)
        else:
          if settings.CUSTOM_INJECTION_MARKER:
            if settings.ASTERISK_MARKER in value:
              all_params[param] = ''.join(all_params[param]).replace(value, value.replace(settings.ASTERISK_MARKER, settings.INJECT_TAG))
          else:
            if not settings.ASTERISK_MARKER in value and not settings.CUSTOM_INJECTION_MARKER_CHAR in value:
              all_params[param] = ''.join(all_params[param]).replace(value, value + settings.INJECT_TAG)
        all_params[param - 1] = ''.join(all_params[param - 1]).replace(settings.INJECT_TAG, "")
        cookie = settings.COOKIE_DELIMITER.join(all_params)
        cookie = cookie.replace(settings.RANDOM_TAG, "").replace(settings.ASTERISK_MARKER,"")
        if type(cookie) != list:
          cookies_list.append(cookie)
        cookie = cookies_list
    else:
      for param in range(0, len(multi_parameters)):
        # Grab the value of parameter.
        value = re.findall(r'=(.*)', multi_parameters[param])
        value = ''.join(value)
      cookie = settings.COOKIE_DELIMITER.join(multi_parameters)
      cookie = cookie.replace(settings.RANDOM_TAG, "")

    return cookie

"""
Specify the cookie parameter(s).
"""
def specify_cookie_parameter(cookie):
  # Specify the vulnerable cookie parameter
  if re.search(r"" + settings.COOKIE_DELIMITER + r"(.*)=[\S*(\\/)]*" + settings.INJECT_TAG, cookie) or \
     re.search(r"(.*)=[\S*(\\/)]*" + settings.INJECT_TAG , cookie):
    pairs = cookie.split(settings.COOKIE_DELIMITER)
    for param in range(0,len(pairs)):
      if settings.INJECT_TAG in pairs[param]:
        inject_cookie = pairs[param].split("=")[0]
        if settings.CUSTOM_INJECTION_MARKER:
          try:
            settings.TEST_PARAMETER = inject_cookie
            settings.PRE_CUSTOM_INJECTION_MARKER_CHAR = pairs[param].split("=")[1].split(settings.INJECT_TAG)[1]
          except Exception:
            pass
        settings.TESTABLE_VALUE = pairs[param].split("=")[1].replace(settings.INJECT_TAG, "")
        break
  else:
    inject_cookie = cookie
  return inject_cookie

"""
The user-agent based injection.
"""
def specify_user_agent_parameter(user_agent):
  settings.TESTABLE_VALUE = user_agent.replace(settings.INJECT_TAG, "")
  return user_agent

"""
The referer based injection.
"""
def specify_referer_parameter(referer):
  settings.TESTABLE_VALUE = referer.replace(settings.INJECT_TAG, "")
  return referer

"""
The host based injection.
"""
def specify_host_parameter(host):
  settings.TESTABLE_VALUE = host.replace(settings.INJECT_TAG, "")
  return host

"""
The Custom http header based injection.
"""
def specify_custom_header_parameter(header_name):
  header_name = settings.CUSTOM_HEADER_NAME
  return header_name

# eof