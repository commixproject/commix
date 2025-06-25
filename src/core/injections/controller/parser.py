#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2025 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

import os
import re
import sys
import time
import base64
import datetime
from src.utils import menu
from src.utils import settings
from src.core.injections.controller import checks
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.colorama import Fore, Back, Style, init

"""
Parse target and data from http proxy logs (i.e Burp or WebScarab)
"""
def logfile_parser():
  """
  Warning message for mutiple request in same log file.
  """
  def multi_requests():
    err_msg = "Multiple"
    if menu.options.requestfile:
      err_msg += " requests"
    elif menu.options.logfile:
      err_msg += " targets"
    err_msg += " are not supported, thus all coming"
    if menu.options.requestfile:
      err_msg += " requests "
    elif menu.options.logfile:
      err_msg += " targets "
    err_msg += "will be ignored."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    
    return False

  """
  Error message for invalid data.
  """
  def invalid_data(request):
    err_msg = "Specified file "
    err_msg += "'" + os.path.split(request_file)[1] + "'"
    err_msg += " does not contain a valid HTTP request."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  if menu.options.requestfile:
    info_msg = "Parsing HTTP request "
    request_file = menu.options.requestfile
    
  elif menu.options.logfile:
    info_msg = "Parsing target "
    request_file = menu.options.logfile

  if not os.path.exists(request_file):
    err_msg = "It seems the '" + request_file + "' file, does not exist."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  try:
    if os.stat(request_file).st_size != 0:
      with open(request_file, encoding=settings.DEFAULT_CODEC) as file:
        request = file.read()
    else:
      invalid_data(request_file)

    if menu.options.requestfile or menu.options.logfile:
      c = 1
      request_headers = []
      request_lines = request.split("\n")
      while c < len(request_lines) and len(request_lines[c]) > 0:
        x = request_lines[c].find(':')
        header_name = request_lines[c][:x].title()
        header_value = request_lines[c][x + 1:]
        if menu.options.header:
          request_headers.append(menu.options.header)
        elif menu.options.headers:
          request_headers.extend(menu.options.headers.split("\\n"))
        request_headers.append(header_name + ":" + header_value)
        c += 1
      c += 1  
      menu.options.data = "".join(request_lines[c:] if c < len(request_lines) else "")
      settings.RAW_HTTP_HEADERS = '\\n'.join(request_headers)

  except IOError as err_msg:
    error_msg = "The '" + request_file + "' "
    error_msg += str(err_msg.args[1]).lower() + "."
    settings.print_data_to_stdout(settings.print_critical_msg(error_msg))
    raise SystemExit()

  single_request = True
  pattern = r'HTTP/([\d.]+)'
  if len(re.findall(pattern, request)) > 1:
    single_request = multi_requests()

  if len(settings.HTTP_METHOD) == 0:
    http_method = request.strip().splitlines()[0].split()[0]
    settings.HTTP_METHOD = http_method
  else:
    http_method = settings.HTTP_METHOD

  request_url = re.findall(r"" + " (.*)" + " HTTP/", request)

  if not request_url:
    invalid_data(request_file)

  request_url = "".join([str(i) for i in request_url])
  # Check for other headers
  extra_headers = ""
  scheme = "http://"

  for line in request_headers:
    if re.findall(r"^" + settings.HOST + ":" + " (.*)", line):
      menu.options.host = "".join([str(i) for i in re.findall(r"" + settings.HOST + ":" + " (.*)", line)])
    # User-Agent Header
    if re.findall(r"" + settings.USER_AGENT + ":" + " (.*)", line):
      menu.options.agent = "".join([str(i) for i in re.findall(r"" + settings.USER_AGENT + ":" + " (.*)", line)])
    # Cookie Header
    if re.findall(r"" + settings.COOKIE + ":" + " (.*)", line):
      menu.options.cookie = "".join([str(i) for i in re.findall(r"" + settings.COOKIE + ":" + " (.*)", line)])
    # Referer Header
    if re.findall(r"" + settings.REFERER + ":" + " (.*)", line):
      menu.options.referer = "".join([str(i) for i in re.findall(r"" + settings.REFERER + ":" + " (.*)", line)])
      if menu.options.referer and "https://" in menu.options.referer:
        scheme = "https://"
    if re.findall(r"" + settings.AUTHORIZATION + ":" + " (.*)", line):
      auth_provided = "".join([str(i) for i in re.findall(r"" + settings.AUTHORIZATION + ":" + " (.*)", line)]).split()
      if auth_provided:
        menu.options.auth_type = auth_provided[0].lower()
        if menu.options.auth_type.lower() == settings.AUTH_TYPE.BASIC:
          # menu.options.auth_cred = base64.b64decode(auth_provided[1]).decode()
          try:
            # Add base64 padding if missing
            b64_string = auth_provided[1]
            b64_string += '=' * (-len(b64_string) % 4)
            menu.options.auth_cred = base64.b64decode(b64_string).decode()
          except (binascii.Error, UnicodeDecodeError) as e:
            err_msg = "Invalid base64-encoded credentials provided in Authorization header: " + format(str(e))
            settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
            raise SystemExit()

        elif menu.options.auth_type.lower() == settings.AUTH_TYPE.DIGEST:
          if not menu.options.auth_cred:
            err_msg = "Use the '--auth-cred' option to provide a valid pair of "
            err_msg += "HTTP authentication credentials (i.e --auth-cred=\"admin:admin\") "
            settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
            raise SystemExit()

    # Add extra headers
    else:
      match = re.findall(r"(.*): (.*)", line)
      match = "".join([str(i) for i in match]).replace("', '",":")
      match = match.replace("('", "")
      match = match.replace("')","\\n")
      # Ignore some header.
      if settings.CONTENT_LENGTH or settings.ACCEPT_ENCODING in match:
        extra_headers = extra_headers
      else:
        extra_headers = extra_headers + match

  # Extra headers
  menu.options.headers = extra_headers
  
  # Target URL
  if not menu.options.host:
    invalid_data(request_file)
  else:
    if len(_urllib.parse.urlparse(request_url).scheme) == 0:
      request_url = scheme + request_url
    if not menu.options.host in request_url:
      request_url = request_url.replace(scheme, scheme + menu.options.host)
    request_url = checks.check_http_s(request_url)
    info_msg += "using the '" + os.path.split(request_file)[1] + "' file. "
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
    
    menu.options.url = request_url
    if menu.options.logfile and settings.VERBOSITY_LEVEL != 0:
      sub_content = http_method + settings.SINGLE_WHITESPACE + menu.options.url
      settings.print_data_to_stdout(settings.print_sub_content(sub_content))
      if menu.options.cookie:
         sub_content = "Cookie: " + menu.options.cookie
         settings.print_data_to_stdout(settings.print_sub_content(sub_content))
      if menu.options.data:
         sub_content = "POST data: " + menu.options.data
         settings.print_data_to_stdout(settings.print_sub_content(sub_content))

# eof