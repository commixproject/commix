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

import os
import re
import json
import base64
import binascii
from src.core.parse import cmdline as menu
from src.utils import settings
from src.thirdparty.odict import OrderedDict
from src.core.controller import checks
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.flatten_json.flatten_json import unflatten_list

"""
Extract a single header's value from a raw "Name: value" line, or None if it's a different header.
"""
def _extract_header_value(header_name, line):
  # Header names are case-insensitive, so match them as sent rather than reshaping them.
  match = re.findall(r"(?i)^" + header_name + ":" + " (.*)", line)
  return "".join([str(i) for i in match]) if match else None

"""
Error message for invalid data.
"""
def _invalid_data(request_file):
  err_msg = "Specified file "
  err_msg += "'" + os.path.split(request_file)[1] + "'"
  err_msg += " does not contain a valid HTTP request."
  settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
  raise SystemExit()

"""
Split the content of a request / proxy log file into the single requests it holds.
"""
def _split_requests(content):
  # A proxy log export delimits its entries with rows of '=', responses among them.
  if re.search(settings.PROXY_LOG_REQUEST_REGEX, content, re.I | re.S):
    # Only blocks opening on a method token are requests, which leaves the responses out.
    return [match.group(1) for match in re.finditer(settings.PROXY_LOG_REQUEST_REGEX, content, re.I | re.S)]

  # An XML history export keeps every request base64-encoded, with its port stored apart.
  if re.search(settings.PROXY_LOG_XML_REQUEST_REGEX, content, re.I | re.S):
    requests = []
    for port, encoded in re.findall(settings.PROXY_LOG_XML_REQUEST_REGEX, content, re.I | re.S):
      try:
        request = base64.b64decode(encoded).decode(settings.DEFAULT_CODEC)
      except (binascii.Error, TypeError, UnicodeDecodeError):
        continue
      # The host line carries no port, so put back the one the log kept beside it.
      match = re.search(r"(?im)^" + settings.HOST + r":.+", request)
      if match:
        host = match.group(0).strip()
        if not re.search(r":\d+\Z", host) and str(port) != "80":
          request = request.replace(host, host + ":" + str(port))
      requests.append(request)
    return requests

  return [content]

"""
Skip a request asking for a static file, which has nothing to inject into.
"""
def _is_static_request(http_method, request_url):
  if http_method != settings.HTTPMETHOD.GET or settings.INJECT_TAG in request_url:
    return False
  path = _urllib.parse.urlparse(request_url).path
  extension = os.path.splitext(path)[1].lstrip(".").lower()
  return bool(extension) and extension in [_.lower() for _ in settings.CRAWL_EXCLUDE_EXTENSIONS]

"""
Signature of a target, so the same endpoint logged again is not tested twice.
"""
def _target_signature(target):
  parsed = _urllib.parse.urlparse(target["url"])
  # The parameter names are what gets tested, so two requests differing only in values are one target.
  query_params = tuple(sorted(_urllib.parse.parse_qs(parsed.query, keep_blank_values=True)))
  try:
    data_params = tuple(sorted(_urllib.parse.parse_qs(target["data"] or "", keep_blank_values=True)))
  except (AttributeError, ValueError):
    data_params = ()
  return (target["method"], parsed.netloc, parsed.path, query_params, data_params)

"""
Parse a single raw HTTP request into the target it describes.
"""
def _parse_request(request, request_file):
  # Normalize CRLF line endings.
  request = request.replace(settings.END_LINE.CRLF, settings.END_LINE.LF)
  request = re.sub(r"\A[^\w]+", "", request)

  if "HTTP/" not in request:
    return None

  target = {
             "url" : "",
             "method" : "",
             "data" : "",
             "host" : None,
             "agent" : None,
             "cookie" : None,
             "referer" : None,
             "auth_type" : None,
             "auth_cred" : None,
             "headers" : "",
             "raw_headers" : ""
           }

  c = 1
  request_headers = []
  if menu.options.header:
    request_headers.append(menu.options.header)
  elif menu.options.headers:
    request_headers.extend(menu.options.headers.split(settings.END_LINE.ESCAPED_LF))
  request_lines = request.split(settings.END_LINE.LF)
  while c < len(request_lines) and len(request_lines[c]) > 0 and ':' in request_lines[c]:
    x = request_lines[c].find(':')
    # Keep the name as it was sent: a header the target matches case-sensitively would break.
    header_name = request_lines[c][:x]
    header_value = request_lines[c][x + 1:]
    request_headers.append(header_name + ":" + header_value)
    c += 1
  if c < len(request_lines) and len(request_lines[c]) == 0:
    c += 1
  # A body is line-based (multipart boundaries, XML, form data), so keep its line endings.
  target["data"] = settings.END_LINE.LF.join(request_lines[c:]).rstrip(settings.END_LINE.LF) if c < len(request_lines) else ""

  # Normalize a JSON body right away, so every request (including the first
  # connectivity check) uses the same pretty-printed form, not the raw file layout.
  if re.search(settings.JSON_RECOGNITION_REGEX, target["data"]) or re.search(settings.JSON_LIKE_RECOGNITION_REGEX, target["data"]):
    try:
      parsed = json.loads(target["data"], object_pairs_hook=OrderedDict)
      target["data"] = json.dumps(unflatten_list(parsed), indent=2, ensure_ascii=False)
    except Exception:
      pass
  target["raw_headers"] = settings.END_LINE.ESCAPED_LF.join(request_headers)

  # Safely determine HTTP method
  lines = request.strip().splitlines()
  if lines and len(lines[0].split()) >= 1:
    target["method"] = lines[0].split()[0]
  else:
    # fallback to default method if malformed/empty
    target["method"] = settings.HTTPMETHOD.GET

  # Safely extract request URL
  match = re.search(r"\s(.*?)\sHTTP/", request or "")
  request_url = match.group(1) if match else ""

  if not request_url:
    return None

  request_url = "".join([str(i) for i in request_url])
  # Check for other headers
  extra_headers = ""
  scheme = "http://"

  for line in request_headers:
    host_value = _extract_header_value(settings.HOST, line)
    if host_value is not None:
      target["host"] = host_value
    agent_value = _extract_header_value(settings.USER_AGENT, line)
    if agent_value is not None:
      target["agent"] = agent_value
    cookie_value = _extract_header_value(settings.COOKIE, line)
    if cookie_value is not None:
      target["cookie"] = cookie_value
    referer_value = _extract_header_value(settings.REFERER, line)
    if referer_value is not None:
      target["referer"] = referer_value
      if "https://" in referer_value:
        scheme = "https://"
    if re.findall(r"" + settings.AUTHORIZATION + ":" + " (.*)", line):
      auth_provided = "".join([str(i) for i in re.findall(r"" + settings.AUTHORIZATION + ":" + " (.*)", line)]).split()
      if auth_provided:
        target["auth_type"] = auth_provided[0].lower()
        if target["auth_type"].lower() == settings.AUTH_TYPE.BASIC:
          try:
            # Add base64 padding if missing
            b64_string = auth_provided[1]
            b64_string += '=' * (-len(b64_string) % 4)
            target["auth_cred"] = base64.b64decode(b64_string).decode()
          except (binascii.Error, UnicodeDecodeError) as e:
            err_msg = "Invalid base64-encoded credentials provided in Authorization header: " + format(str(e))
            settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
            raise SystemExit()

        elif target["auth_type"].lower() == settings.AUTH_TYPE.DIGEST:
          if not menu.options.auth_cred:
            err_msg = "Use the '--auth-cred' option to provide a valid pair of "
            err_msg += "HTTP authentication credentials (i.e. '--auth-cred=admin:admin') "
            settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
            raise SystemExit()

    # Add extra headers
    else:
      match = re.match(r"(.*): (.*)", line)
      # Ignore some headers.
      if match and match.group(1).lower() not in [_.lower() for _ in (settings.CONTENT_LENGTH, settings.ACCEPT_ENCODING, \
         settings.CONNECTION, settings.PROXY_CONNECTION, settings.IF_MODIFIED_SINCE, settings.IF_NONE_MATCH)]:
        extra_headers += match.group(1) + ":" + match.group(2) + settings.END_LINE.ESCAPED_LF

  # Extra headers
  target["headers"] = extra_headers

  # Target URL
  if not target["host"]:
    return None

  if len(_urllib.parse.urlparse(request_url).scheme) == 0:
    request_url = scheme + request_url
  if not target["host"] in request_url:
    request_url = request_url.replace(scheme, scheme + target["host"])
  target["url"] = checks.check_http_s(request_url)

  if _is_static_request(target["method"], target["url"]):
    return None

  return target

"""
Remember what was given on the command line, before any parsed request overwrites it.
"""
_command_line_options = {}

# Keep the options the command line gave, so a parsed request cannot overrule them.
def _keep_command_line_options():
  if not _command_line_options:
    for option in ("host", "agent", "cookie", "referer", "auth_type", "auth_cred"):
      _command_line_options[option] = getattr(menu.options, option, None)

"""
Apply a parsed target, so the scan that follows runs against that request.
"""
def apply_target(target):
  _keep_command_line_options()
  menu.options.url = target["url"]
  menu.options.data = target["data"]
  menu.options.headers = target["headers"]
  settings.RAW_HTTP_HEADERS = target["raw_headers"]
  settings.HTTP_METHOD = target["method"]
  # The request method follows the body, so a target without one must not inherit the previous body.
  settings.USER_DEFINED_POST_DATA = target["data"]
  settings.IGNORE_USER_DEFINED_POST_DATA = False
  # What a request does not carry falls back to the command line, never to the previous target.
  for option in ("host", "agent", "cookie", "referer", "auth_type", "auth_cred"):
    value = target[option] if target[option] is not None else _command_line_options.get(option)
    setattr(menu.options, option, value)

"""
Parse every target described by a request / proxy log file.
"""
def parse_requests(request_file):
  if not os.path.exists(request_file):
    err_msg = "It seems the '" + request_file + "' file does not exist."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  try:
    if os.stat(request_file).st_size == 0:
      _invalid_data(request_file)
    with open(request_file, encoding=settings.DEFAULT_CODEC) as file:
      content = file.read()
  except IOError as err_msg:
    error_msg = "The '" + request_file + "' "
    error_msg += str(err_msg.args[1]).lower() + "."
    settings.print_data_to_stdout(settings.print_critical_msg(error_msg))
    raise SystemExit()

  targets = []
  seen = set()
  for request in _split_requests(content):
    target = _parse_request(request, request_file)
    if target is None:
      continue
    if not checks.in_scope(target["url"]):
      continue
    signature = _target_signature(target)
    if signature in seen:
      continue
    seen.add(signature)
    targets.append(target)

  if not targets:
    # Saying the file is invalid would be wrong when it was the scope that emptied it.
    if menu.options.scope and settings.SKIPPED_OUT_OF_SCOPE:
      err_msg = "No target of the '" + os.path.split(request_file)[1] + "' file is within the given scope."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()
    _invalid_data(request_file)

  return targets

"""
Parse target and data from http proxy logs (i.e. Burp or WebScarab)
"""
def logfile_parser():
  if menu.options.requestfile:
    info_msg = "Parsing HTTP request "
    request_file = menu.options.requestfile
  elif menu.options.logfile:
    info_msg = "Parsing target "
    request_file = menu.options.logfile

  targets = parse_requests(request_file)

  info_msg += "using the '" + os.path.split(request_file)[1] + "' file. "
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))

  if len(targets) > 1:
    info_msg = "Found a total of " + str(len(targets)) + " targets in the provided file."
    if settings.SKIPPED_OUT_OF_SCOPE:
      info_msg += " Skipped " + str(len(settings.SKIPPED_OUT_OF_SCOPE)) + " target" + "s"[len(settings.SKIPPED_OUT_OF_SCOPE) == 1:] + " out of scope."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))

  settings.MULTI_REQUEST_TARGETS = targets
  apply_target(targets[0])

  return targets

# eof
