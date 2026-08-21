#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2026 Anastasios Stasinopoulos (@ancst).

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
Grab the value out of a plain 'key=value' fragment.
"""
def get_kv_value(parameter):
  value = re.findall(r'=(.*)', parameter)
  value = ''.join(value)
  return value

"""
Unwrap a value that's a lone CDATA section, otherwise return it unchanged.
"""
def unwrap_cdata(value):
  cdata_only = re.match(r'\A<!\[CDATA\[(.*)\]\]>\Z', value, re.S)
  return cdata_only.group(1) if cdata_only else value

"""
Insert the INJECT_HERE tag right after 'value' inside 'text'.
"""
def apply_tag_to_value(text, value):
  if settings.CUSTOM_INJECTION_MARKER:
    if settings.ASTERISK_MARKER in value:
      text = text.replace(value, value.replace(settings.ASTERISK_MARKER, settings.INJECT_TAG))
  else:
    if not settings.ASTERISK_MARKER in value and not settings.CUSTOM_INJECTION_MARKER_CHAR in value:
      text = text.replace(value, value + settings.INJECT_TAG)
  return text

"""
Find the pair carrying the INJECT_TAG and register it as the vulnerable parameter.
"""
def extract_vuln_param_from_pairs(text, delimiter, strip_leading_space=False, check_base64_padding=False):
  pairs = text.split(delimiter)
  if strip_leading_space:
    pairs = [p.lstrip(settings.SINGLE_WHITESPACE) for p in pairs]
  pairs[:] = [p for p in pairs if "=" in p]
  for pair in pairs:
    if settings.INJECT_TAG in pair:
      vuln_parameter, param_value = pair.split("=", 1)
      if settings.CUSTOM_INJECTION_MARKER:
        register_custom_injection_marker(vuln_parameter, param_value)
      settings.TESTABLE_VALUE = param_value.replace(settings.INJECT_TAG, "")
      if check_base64_padding and settings.BASE64_PADDING in pair:
        settings.TESTABLE_VALUE = settings.TESTABLE_VALUE + settings.BASE64_PADDING
      return vuln_parameter
  return None

"""
Resolve the custom-marker component to prepend/append to a prefix or suffix.
"""
def resolve_marker_component(default_value, marker_char):
  if settings.CUSTOM_INJECTION_MARKER and len(settings.PRE_CUSTOM_INJECTION_MARKER_CHAR) != 0:
    return marker_char
  if settings.IS_JSON or (settings.LOAD_SESSION and not any((settings.COOKIE_INJECTION, settings.USER_AGENT_INJECTION,
                                                               settings.REFERER_INJECTION, settings.HOST_INJECTION,
                                                               settings.CUSTOM_HEADER_INJECTION))):
    return None
  return default_value

"""
Shield each leaf element behind a placeholder so a line/element split can't fragment it.
"""
def shield_xml_leaves(text):
  shielded = []
  def _shield(m):
    shielded.append(m.group(0))
    return "<\x00SHIELD%d\x00>" % (len(shielded) - 1)
  shielded_text = re.sub(r"<(\w[\w:.\-]*)((?:\s+[^<>]*)?)>((?:[^<]|<!\[CDATA\[.*?\]\]>)*)</\1>",
                          _shield, text, flags=re.S)
  return shielded_text, shielded

"""
Reverse shield_xml_leaves() on a string or a list of strings.
"""
def restore_xml_shields(text_or_list, shielded):
  def _restore_one(s):
    for index, value in enumerate(shielded):
      s = s.replace("<\x00SHIELD%d\x00>" % index, value)
    return s
  if isinstance(text_or_list, list):
    return [_restore_one(s) for s in text_or_list]
  return _restore_one(text_or_list)

"""
Check if the 'INJECT_HERE' tag, is specified on GET Requests.
"""
def do_GET_check(url, http_request_method):
  multi_params_get_value = get_kv_value

  if settings.CUSTOM_INJECTION_MARKER and settings.SKIP_NON_CUSTOM_PARAMS:
    return False
      
  if settings.USER_DEFINED_POST_DATA:
    if settings.CUSTOM_INJECTION_MARKER_CHAR in settings.USER_DEFINED_POST_DATA and settings.SKIP_NON_CUSTOM_PARAMS:
      return False
    if settings.INJECT_TAG in url:
      settings.IGNORE_USER_DEFINED_POST_DATA = True

  # Replace with INJECT_HERE, honoring the custom marker character.
  url = checks.process_custom_injection_data(url)
  # Check for REST-ful URLs format.
  if "?" not in url:
    if settings.INJECT_TAG not in url and not menu.options.shellshock:
      if len(settings.TESTABLE_PARAMETERS_LIST) != 0 or \
         len(settings.CUSTOM_INJECTION_MARKER_PARAMETERS_LIST) != 0 or \
         settings.INJECTION_LEVEL == settings.HTTP_HEADER_INJECTION_LEVEL or \
         (settings.INJECTION_LEVEL == settings.COOKIE_INJECTION_LEVEL and menu.options.cookie) or \
         settings.USER_DEFINED_POST_DATA and not settings.IGNORE_USER_DEFINED_POST_DATA:
        return False
      else:
        checks.no_parameters_found()
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
        multi_parameters = parameters.split(settings.URL_PARAM_DELIMITER)
        multi_parameters = [x for x in multi_parameters if x]
      except ValueError as err_msg:
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
        raise SystemExit()

      if len([s for s in multi_parameters if "=" in s]) == 0:
        checks.no_parameters_found()

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
        # Check if defined the INJECT_TAG
        if settings.INJECT_TAG not in parameters:
          # Ignoring the anti-CSRF parameter(s).
          if checks.ignore_anticsrf_parameter(parameters):
            return urls_list
          if len(value) == 0:
            parameters = parameters + settings.INJECT_TAG
          else:
            parameters = apply_tag_to_value(parameters, value)
        # Reconstruct the URL
        url = url_part + "?" + parameters
        url = url.replace(settings.RANDOM_TAG, "").replace(settings.ASTERISK_MARKER,"")
        urls_list.append(url)
        return urls_list
      else:
        # Multiple parameters without the INJECT_HERE tag.
        all_params = list(multi_parameters)
        # Check for similarity in provided parameter name and value.
        all_params = checks.check_similarities(all_params)
        # Check if defined the "INJECT_HERE" tag
        if settings.INJECT_TAG not in url:
          for param in range(0,len(all_params)):
            # Grab the value of parameter.
            value = multi_params_get_value(all_params[param])
            # Ignoring the anti-CSRF parameter(s).
            if checks.ignore_anticsrf_parameter(all_params[param]):
              if param > 0:
                all_params[param - 1] = ''.join(all_params[param - 1]).replace(settings.INJECT_TAG, "")
              continue
            # Replace the value of parameter with INJECT_HERE tag
            if len(value) == 0:
              if not menu.options.skip_empty:
                all_params[param] = ''.join(all_params[param] + settings.INJECT_TAG)
            else:
              all_params[param] = apply_tag_to_value(''.join(all_params[param]), value)
            if param > 0:
              all_params[param - 1] = ''.join(all_params[param - 1]).replace(settings.INJECT_TAG, "")
            parameter = settings.URL_PARAM_DELIMITER.join(all_params)
            # Reconstruct the URL
            url = url_part + "?" + parameter
            url = url.replace(settings.RANDOM_TAG, "").replace(settings.ASTERISK_MARKER,"")
            urls_list.append(url)
        else:
          parameter = settings.URL_PARAM_DELIMITER.join(multi_parameters)
          # Reconstruct the URL
          url = url_part + "?" + parameter
          url = url.replace(settings.RANDOM_TAG, "")
          urls_list.append(url)

    return urls_list

"""
Custom injection marker character bookkeeping.
"""
def register_custom_injection_marker(vuln_parameter, value_with_marker):
  try:
    settings.CUSTOM_INJECTION_MARKER_PARAMETERS_LIST.append(vuln_parameter) if vuln_parameter not in settings.CUSTOM_INJECTION_MARKER_PARAMETERS_LIST else settings.CUSTOM_INJECTION_MARKER_PARAMETERS_LIST
    settings.TESTABLE_PARAMETERS_LIST.append(vuln_parameter) if vuln_parameter not in settings.CUSTOM_INJECTION_MARKER_PARAMETERS_LIST else settings.TESTABLE_PARAMETERS_LIST
    settings.PRE_CUSTOM_INJECTION_MARKER_CHAR = value_with_marker.split(settings.INJECT_TAG)[0]
    settings.POST_CUSTOM_INJECTION_MARKER_CHAR = value_with_marker.split(settings.INJECT_TAG)[1]
  except Exception:
    pass

"""
Define the vulnerable GET parameter.
"""
def vuln_GET_param(url):
  # Define the vulnerable parameter
  vuln_parameter = None
  if "?" not in url:
    # Grab the value of parameter.
    value = re.findall(r'/(.*)/' + settings.INJECT_TAG + "", url)
    value = ''.join(value)
    vuln_parameter = re.sub(r"/(.*)/", "", value)

  # Allow a value with a space, and escape the delimiter (--pdel).
  elif re.search(re.escape(settings.URL_PARAM_DELIMITER) + r"(.*)=.*" + settings.INJECT_TAG, url) or \
       re.search(r"\?(.*)=.*" + settings.INJECT_TAG , url):
    vuln_parameter = extract_vuln_param_from_pairs(url.split("?")[1], settings.URL_PARAM_DELIMITER, check_base64_padding=True)
  else:
    vuln_parameter = url

  if vuln_parameter is None:
    return url

  if settings.USER_DEFINED_POST_DATA and vuln_parameter:
    settings.IGNORE_USER_DEFINED_POST_DATA = True

  return vuln_parameter

"""
Build one tagged candidate per leaf for a fragment whose value is itself a nested object.
"""
def json_nested_leaf_candidates(fragment, full_parameter):
  candidates = []
  key_match = re.match(r'\s*\{?\s*"([^"]+)"\s*:', fragment)
  if not key_match:
    return candidates
  try:
    full_json = json.loads(full_parameter, object_pairs_hook=OrderedDict)
  except Exception:
    return candidates
  nested_value = full_json.get(key_match.group(1)) if isinstance(full_json, dict) else None
  if not isinstance(nested_value, dict):
    return candidates
  for leaf_key, leaf_value in flatten(nested_value).items():
    last_key = leaf_key.split(settings.FLATTEN_JSON_SEPARATOR)[-1]
    dumped = json.dumps(leaf_value)
    anchor = "\"" + last_key + "\":" + settings.SINGLE_WHITESPACE + dumped
    if anchor not in full_parameter:
      anchor = "\"" + last_key + "\":" + dumped
      if anchor not in full_parameter:
        continue
    if isinstance(leaf_value, str):
      replacement = anchor[:-1] + settings.INJECT_TAG + "\""
    else:
      replacement = anchor[:anchor.rindex(dumped)] + "\"" + dumped + settings.INJECT_TAG + "\""
    candidates.append(full_parameter.replace(anchor, replacement, 1))
  return candidates

"""
Check if a JSON string is an empty object.
"""
def is_empty_json_object(s):
  try:
    return json.loads(s) == {}
  except Exception:
    return False

"""
Grab the value of a single POST parameter fragment.
"""
def multi_params_get_value(param, all_params):
  # Check if parameters are empty or meaningless
  if (len(all_params) == 0 or (len(all_params) == 1 and (all_params[0] == "{}" or is_empty_json_object(all_params[0])))):
      checks.no_parameters_found()

  if settings.IS_JSON:
    try:
      # Single-parameter case: flatten to get the leaf value.
      if len(all_params) != 1:
        raise ValueError
      flat = flatten(json.loads(all_params[param], object_pairs_hook=OrderedDict))
      value = json.dumps(list(flat.values())[0])
    except Exception:
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
    # Grab the value of parameter (unwrap CDATA).
    value = unwrap_cdata(''.join(re.findall(r'>(.*)</', all_params[param], re.S)))
  else:
    value = get_kv_value(all_params[param])
  return value

"""
Check JSON objects format.
"""
def json_format(parameter):
  return json.loads(parameter, object_pairs_hook=OrderedDict)

"""
Check for int value inside JSON objects.
"""
def json_int_check(parameter, value):
  try:
    parameter = json_format(parameter)
  except Exception:
    if not checks.quoted_value(value + settings.INJECT_TAG) in parameter:
      if any(_ in "[]{}" for _ in value):
        v = re.sub(settings.IGNORE_JSON_CHAR_REGEX, '', value.lstrip())
        parameter = parameter.replace(value + settings.INJECT_TAG, value.replace(v, checks.quoted_value(v + settings.INJECT_TAG)))
      else:
        parameter = parameter.replace(value + settings.INJECT_TAG, checks.quoted_value(value + settings.INJECT_TAG))
    if settings.INJECT_TAG in value and not checks.quoted_value(value) in parameter:
      value = re.sub(settings.IGNORE_JSON_CHAR_REGEX, '', value.lstrip())
      parameter = parameter.replace(value, checks.quoted_value(value))
    try:
      parameter = json_format(parameter)
    except Exception:
      # Fall back to the raw value if JSON formatting fails.
      return parameter

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

  parameter = checks.format_json(parameter)
  return parameter

"""
Detect the POST body's data format (JSON/XML/plain) and set the relevant settings.
"""
def configure_post_data_format(parameter, http_request_method):
  parameter = checks.process_custom_injection_data(parameter).replace("'","\"").replace(", ",",").replace(",\"", ", \"")
  # Check if JSON Object.
  if checks.is_JSON_check(parameter) or checks.is_JSON_check(checks.check_quotes_json_data(parameter)):
    if checks.is_JSON_check(checks.check_quotes_json_data(parameter)):
      parameter = checks.check_quotes_json_data(parameter)
    if not settings.IS_JSON:
      data_type = "JSON"
      settings.IS_JSON = checks.process_data(data_type, http_request_method)
      settings.POST_DATA_PARAM_DELIMITER = ","
  # Check if XML Object.
  elif checks.is_XML_check(parameter):
    if not settings.IS_XML:
      data_type = "XML/SOAP"
      settings.IS_XML = checks.process_data(data_type, http_request_method)
      settings.POST_DATA_PARAM_DELIMITER = settings.END_LINE.LF

  elif settings.TESTABLE_PARAMETERS_LIST and not any(ext in parameter for ext in settings.TESTABLE_PARAMETERS_LIST) and not settings.INJECT_TAG in parameter:
    if settings.SKIP_NON_CUSTOM_PARAMS:
      settings.IGNORE_USER_DEFINED_POST_DATA = True

  if settings.IGNORE_USER_DEFINED_POST_DATA and settings.SKIP_NON_CUSTOM_PARAMS:
    return None
  return parameter

"""
Split a POST body into its individual parameter fragments.
"""
def split_post_parameters(parameter):
  if settings.IS_XML:
    # Expand self-closing tags; keep menu.options.data in sync.
    expanded_parameter = re.sub(r"<([^\s/>]+)((?:[^>]*[^/>])?)\s*/>", r"<\1\2></\1>", parameter)
    if expanded_parameter != parameter:
      parameter = expanded_parameter
      menu.options.data = expanded_parameter
    # Shield leaf elements before the ">"/"<" split below.
    parameter, _shielded = shield_xml_leaves(parameter)
    parameter = re.sub(r">\s*<", ">" + settings.POST_DATA_PARAM_DELIMITER + "<", parameter)
    _ = []
    parameters = re.findall(r'(.*)', parameter)
    parameters = [param for param in parameters if param]
    for value in range(0,len(parameters)):
      _.append(parameters[value])
    multi_parameters = _
    # Restore per entry (elements may contain newlines).
    if _shielded:
      multi_parameters = restore_xml_shields(multi_parameters, _shielded)
      parameter = settings.POST_DATA_PARAM_DELIMITER.join(multi_parameters)
  else:
    try:
      multi_parameters = parameter.split(settings.POST_DATA_PARAM_DELIMITER)
    except ValueError as err_msg:
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()

  if len([s for s in multi_parameters if "=" in s]) == 0 and not any((settings.IS_JSON, settings.IS_XML)):
    checks.no_parameters_found()

  return multi_parameters, parameter

"""
Handle a POST body that split into exactly one parameter fragment.
"""
def handle_single_post_parameter(parameter, multi_parameters, http_request_method):
  if settings.INJECT_TAG not in multi_parameters[0]:
    # Grab the value of parameter.
    if settings.IS_JSON:
      value = multi_params_get_value(0, checks.check_similarities([multi_parameters[0]]))
    elif settings.IS_XML:
      # Grab the value of parameter (unwrap CDATA).
      value = unwrap_cdata(''.join(re.findall(r'>(.*)</', parameter, re.S)))
    else:
      value = get_kv_value(parameter)

    if checks.is_empty(multi_parameters, http_request_method):
      return parameter
    else:
      # Ignoring the anti-CSRF parameter(s).
      if checks.ignore_anticsrf_parameter(parameter):
        return parameter
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
            # Anchor on ":<value>" to avoid matching inside a key name.
            anchor = ":" + settings.SINGLE_WHITESPACE + value
            if settings.IS_JSON and anchor not in parameter:
              anchor = ":" + value
            if settings.IS_JSON and anchor in parameter:
              parameter = parameter.replace(anchor, anchor + settings.INJECT_TAG)
            else:
              parameter = parameter.replace(value, value + settings.INJECT_TAG)

      if settings.IS_JSON:
        parameter = json_int_check(parameter, value)
      parameter = parameter.replace(settings.RANDOM_TAG, "").replace(settings.ASTERISK_MARKER,"")
      return parameter
  else:
    for param in range(0, len(multi_parameters)):
      # Grab the value of parameter.
      value = multi_params_get_value(param, multi_parameters)
      parameter = settings.POST_DATA_PARAM_DELIMITER.join(multi_parameters)
      parameter = parameter.replace(settings.RANDOM_TAG, "")
      if settings.IS_JSON and settings.INJECT_TAG in value:
        parameter = json_int_check(parameter, value)
        break
    return parameter

"""
Handle a POST body that split into more than one parameter fragment.
"""
def handle_multiple_post_parameters(parameter, multi_parameters, http_request_method):
  parameters_list = []
  # Multiple parameters without the INJECT_HERE tag.
  if settings.IS_XML:
    all_params = multi_parameters
  else:
    # Check for similarity in provided parameter name and value.
    all_params = list(multi_parameters)
  all_params = checks.check_similarities(all_params)
  original_json_text = settings.POST_DATA_PARAM_DELIMITER.join(all_params) if settings.IS_JSON else None
  # Check if not defined the "INJECT_HERE" tag in parameter
  if settings.INJECT_TAG not in parameter:
    if checks.is_empty(multi_parameters, http_request_method):
      return parameter
    for param in range(0, len(all_params)):
      original_fragment = all_params[param]
      # Grab the value of parameter.
      value = multi_params_get_value(param, all_params)
      # Ignoring the anti-CSRF parameter(s).
      if checks.ignore_anticsrf_parameter(all_params[param]):
        if param > 0:
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
        all_params[param] = apply_tag_to_value(''.join(all_params[param]), value)
        if settings.IS_JSON and len(all_params[param].split("\":")) == 2:
          check_parameter = all_params[param].split("\":")[0]
          if settings.INJECT_TAG in check_parameter:
            all_params[param] = all_params[param].replace(check_parameter, check_parameter.replace(settings.INJECT_TAG, ""))

      if param > 0:
        all_params[param - 1] = ''.join(all_params[param - 1]).replace(settings.INJECT_TAG, "")
      parameter = settings.POST_DATA_PARAM_DELIMITER.join(all_params)
      parameter = parameter.replace(settings.RANDOM_TAG, "").replace(settings.ASTERISK_MARKER,"")
      if settings.IS_JSON:
        if (len(all_params)) == 1 and settings.INJECT_TAG not in all_params[param]:
          parameter = parameter.replace(value, value + settings.INJECT_TAG)
        parameter = json_int_check(parameter, value)
      # Skip candidates where no tag actually got placed (e.g. an XML
      # wrapper line, or a JSON fragment whose value is itself nested).
      if type(parameter) != list and settings.INJECT_TAG in parameter:
        parameters_list.append(parameter)
      elif settings.IS_JSON and original_json_text:
        parameters_list.extend(json_nested_leaf_candidates(original_fragment, original_json_text))
      parameter = parameters_list
  else:
    for param in range(0, len(multi_parameters)):
      # Grab the value of parameter.
      value = multi_params_get_value(param, multi_parameters)
      parameter = settings.POST_DATA_PARAM_DELIMITER.join(multi_parameters)
      parameter = parameter.replace(settings.RANDOM_TAG, "")
      if settings.IS_JSON and settings.INJECT_TAG in multi_parameters[param]:
        parameter = json_int_check(parameter, value)
        break
  return parameter

"""
Check if the 'INJECT_HERE' tag, is specified on POST Requests.
"""
def do_POST_check(parameter, http_request_method):
  parameter = configure_post_data_format(parameter, http_request_method)
  if parameter is None:
    return ""

  multi_parameters, parameter = split_post_parameters(parameter)

  _ = []
  _.append(parameter)
  parameter = ''.join(checks.check_similarities(_))
  # Check if single parameter is supplied.
  if len(multi_parameters) == 1:
    return handle_single_post_parameter(parameter, multi_parameters, http_request_method)
  else:
    return handle_multiple_post_parameters(parameter, multi_parameters, http_request_method)

"""
Define the vulnerable POST parameter.
"""
def vuln_POST_param(parameter, url):
  if isinstance(parameter, list):
    parameter = " ".join(parameter)
  vuln_parameter = None

  # JSON data format.
  if settings.IS_JSON:
    try:
      flat = flatten(json.loads(parameter, object_pairs_hook=OrderedDict))
    except Exception:
      # Return unchanged if the value is not valid JSON.
      return parameter
    vuln_key = None
    for key in flat:
      if settings.INJECT_TAG in str(flat[key]):
        vuln_key = key
        break
    if vuln_key is None:
      return parameter
    # Convert key to dot notation.
    key_parts = vuln_key.split(settings.FLATTEN_JSON_SEPARATOR)
    vuln_parameter = key_parts[0]
    for key_part in key_parts[1:]:
      vuln_parameter += "[" + key_part + "]" if key_part.isdigit() else "." + key_part
    settings.TESTABLE_VALUE = str(flat[vuln_key]).split(settings.INJECT_TAG)[0]
    if settings.CUSTOM_INJECTION_MARKER:
      settings.CUSTOM_INJECTION_MARKER_PARAMETERS_LIST.append(vuln_parameter) if vuln_parameter not in settings.CUSTOM_INJECTION_MARKER_PARAMETERS_LIST else settings.CUSTOM_INJECTION_MARKER_PARAMETERS_LIST
      settings.TESTABLE_PARAMETERS_LIST.append(vuln_parameter) if vuln_parameter not in settings.CUSTOM_INJECTION_MARKER_PARAMETERS_LIST else settings.TESTABLE_PARAMETERS_LIST

  # XML data format.
  elif settings.IS_XML:
    # Shield leaf elements before splitting into lines below.
    shielded_parameter, _shielded = shield_xml_leaves(parameter)
    # Split on element boundaries, but not inside "...]]></tag>".
    parameters = list(re.sub(r"(?<!\])></", ">" + settings.END_LINE.LF + "</", shielded_parameter).split(settings.END_LINE.LF))
    parameters = restore_xml_shields(parameters, _shielded)
    for item in parameters:
      if settings.INJECT_TAG in item:
        if not settings.CUSTOM_INJECTION_MARKER and settings.CUSTOM_INJECTION_MARKER_CHAR in item:
          item = item.replace(settings.CUSTOM_INJECTION_MARKER_CHAR,"")
        # Match tag name (tolerating attributes) against its closing tag.
        _ = re.search(r'<([^\s>/]+)[^>]*>(.*)</([^\s>]+)>', item, re.S)
        if _ and (_.groups()[0]) == (_.groups()[2]):
          vuln_parameter = ''.join(_.groups()[0])
          result = unwrap_cdata(_.groups()[1])
          if settings.CUSTOM_INJECTION_MARKER:
            register_custom_injection_marker(vuln_parameter, result)
          settings.TESTABLE_VALUE = result.split(settings.INJECT_TAG)[0]

  # Regular POST data format.
  else:
    # Allow a value with a space, and escape the delimiter (--pdel).
    if re.search(re.escape(settings.POST_DATA_PARAM_DELIMITER) + r"(.*)=.*" + settings.INJECT_TAG, parameter) or \
       re.search(r"(.*)=.*" + settings.INJECT_TAG , parameter):
      vuln_parameter = extract_vuln_param_from_pairs(parameter, settings.POST_DATA_PARAM_DELIMITER, check_base64_padding=True)

  if vuln_parameter is None:
    return parameter

  return vuln_parameter

"""
Define the injection prefixes.
"""
def prefixes(payload, prefix):
  parameter = ""
  if settings.COOKIE_INJECTION:
    if not settings.LOAD_SESSION:
      parameter = menu.options.cookie
    specify_cookie_parameter(parameter)
  if settings.CUSTOM_HEADER_INJECTION:
    if not settings.LOAD_SESSION:
      parameter = settings.CUSTOM_HEADER_VALUE
    specify_custom_header_parameter(parameter)
  elif settings.USER_AGENT_INJECTION:
    if not settings.LOAD_SESSION:
      parameter = menu.options.agent
    specify_user_agent_parameter(parameter)
  elif settings.REFERER_INJECTION:
    if not settings.LOAD_SESSION:
      parameter = menu.options.referer
    specify_referer_parameter(parameter)
  elif settings.HOST_INJECTION:
    if not settings.LOAD_SESSION:
      parameter = menu.options.host
    specify_host_parameter(parameter)

  pre_custom = resolve_marker_component(settings.TESTABLE_VALUE, settings.PRE_CUSTOM_INJECTION_MARKER_CHAR)
  if pre_custom is not None and pre_custom not in prefix:
    prefix = pre_custom + prefix
  # Check if defined "--prefix" option.
  if menu.options.prefix and not settings.LOAD_SESSION:
    if not menu.options.prefix in prefix:
      prefix = prefix + menu.options.prefix 

  payload = prefix + payload
  # Fixation for specific payload.
  if ")%3B" + ")}" in payload:
    payload = payload.replace(")%3B" + ")}", ")" + ")}")

  return payload, prefix

"""
Define the injection suffixes.
"""
def suffixes(payload, suffix):

  if settings.COOKIE_INJECTION and suffix == settings.COOKIE_PARAM_DELIMITER:
    suffix = ""

  post_custom = resolve_marker_component("", settings.POST_CUSTOM_INJECTION_MARKER_CHAR)
  if post_custom is not None and post_custom not in suffix:
    suffix = suffix + post_custom
  # Check if defined "--suffix" option.
  if menu.options.suffix and not settings.LOAD_SESSION:
    if not menu.options.suffix in suffix:
      suffix = menu.options.suffix + suffix

  payload = payload + suffix

  return payload, suffix

"""
The cookie based injection.
"""
def do_cookie_check(cookie):
  multi_params_get_value = get_kv_value

  # Replace with INJECT_HERE, honoring the custom marker character.
  cookie = checks.process_custom_injection_data(cookie)
  try:
    # Strip only the leading space left by the "; " convention.
    multi_parameters = [param.lstrip(settings.SINGLE_WHITESPACE) for param in cookie.split(settings.COOKIE_PARAM_DELIMITER)]
  except ValueError as err_msg:
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  if len([s for s in multi_parameters if "=" in s]) == 0:
    checks.no_parameters_found()

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
        cookie = apply_tag_to_value(cookie, value)

    cookie = cookie.replace(settings.RANDOM_TAG, "").replace(settings.ASTERISK_MARKER,"")
    return cookie

  # Check if multiple parameters are supplied.
  else:
    cookies_list = []
    all_params = list(multi_parameters)
    all_params = checks.check_similarities(all_params)
    # Check if not defined the "INJECT_HERE" tag in parameter
    if settings.INJECT_TAG not in cookie:
      # Check for empty values (in provided parameters).
      if checks.is_empty(multi_parameters, http_request_method=settings.COOKIE):
        return cookie
      for param in range(0, len(all_params)):
        # Grab the value of cookie.
        value = multi_params_get_value(all_params[param])
        # Ignoring the anti-CSRF parameter(s).
        if checks.ignore_anticsrf_parameter(all_params[param]):
          if param > 0:
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
          all_params[param] = apply_tag_to_value(''.join(all_params[param]), value)
        if param > 0:
          all_params[param - 1] = ''.join(all_params[param - 1]).replace(settings.INJECT_TAG, "")
        cookie = settings.COOKIE_PARAM_DELIMITER.join(all_params)
        cookie = cookie.replace(settings.RANDOM_TAG, "").replace(settings.ASTERISK_MARKER,"")
        if type(cookie) != list:
          cookies_list.append(cookie)
        cookie = cookies_list
    else:
      cookie = settings.COOKIE_PARAM_DELIMITER.join(multi_parameters)
      cookie = cookie.replace(settings.RANDOM_TAG, "")

    return cookie

"""
Specify the cookie parameter(s).
"""
def specify_cookie_parameter(cookie):
  # Specify the vulnerable cookie parameter
  vuln_parameter = None
  # Allow a value with a space, and escape the delimiter (--cdel).
  if re.search(re.escape(settings.COOKIE_PARAM_DELIMITER) + r"(.*)=.*" + settings.INJECT_TAG, cookie) or \
     re.search(r"(.*)=.*" + settings.INJECT_TAG , cookie):
    vuln_parameter = extract_vuln_param_from_pairs(cookie, settings.COOKIE_PARAM_DELIMITER, strip_leading_space=True)
  else:
    vuln_parameter = cookie

  if vuln_parameter is None:
    return cookie
    
  return vuln_parameter

"""
Process a given HTTP header value for custom injection.
"""
def specify_header_injection_parameter(header_value, header_name):
  try:
    settings.TESTABLE_VALUE = checks.process_custom_injection_data(header_value).replace(settings.ASTERISK_MARKER, settings.INJECT_TAG)

    if settings.CUSTOM_INJECTION_MARKER and settings.INJECT_TAG in settings.TESTABLE_VALUE:
      if header_name not in settings.CUSTOM_INJECTION_MARKER_PARAMETERS_LIST:
        settings.CUSTOM_INJECTION_MARKER_PARAMETERS_LIST.append(header_name)

      if header_value not in settings.TESTABLE_PARAMETERS_LIST:
        settings.TESTABLE_PARAMETERS_LIST.append(header_value)

      split_value = settings.TESTABLE_VALUE.split(settings.INJECT_TAG)
      settings.PRE_CUSTOM_INJECTION_MARKER_CHAR = split_value[0] if len(split_value) > 0 else ''
      settings.POST_CUSTOM_INJECTION_MARKER_CHAR = split_value[1] if len(split_value) > 1 else ''

  except (AttributeError, IndexError):
    pass

  return header_value

"""
Wrapper for processing User-Agent header injection.
"""
def specify_user_agent_parameter(user_agent):
  return specify_header_injection_parameter(user_agent, settings.USER_AGENT)

"""
Wrapper for processing Referer header injection.
"""
def specify_referer_parameter(referer):
  return specify_header_injection_parameter(referer, settings.REFERER)

"""
Wrapper for processing Host header injection.
"""
def specify_host_parameter(host):
  return specify_header_injection_parameter(host, settings.HOST)

"""
Wrapper for processing a custom-defined HTTP header injection.
"""
def specify_custom_header_parameter(custom_header_value):
  return specify_header_injection_parameter(custom_header_value, settings.CUSTOM_HEADER_NAME)

# eof