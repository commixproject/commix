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
    print(settings.SUCCESS_STATUS)
    warn_msg = "Multiple"
    if menu.options.requestfile: 
      warn_msg += " requests"
    elif menu.options.logfile: 
      warn_msg += " targets"
    warn_msg += " are not supported, thus all coming"
    if menu.options.requestfile: 
      warn_msg += " requests "
    elif menu.options.logfile: 
      warn_msg += " targets "
    warn_msg += "will be ignored."
    sys.stdout.write(settings.print_warning_msg(warn_msg) + "\n")
    sys.stdout.flush()
    return False

  """
  Error message for invalid data.
  """
  def invalid_data(request, single_request):
    if single_request:
      print(settings.FAIL_STATUS)
    err_msg = "Specified file "
    err_msg += "'" + os.path.split(request_file)[1] + "'"
    err_msg += " does not contain a valid HTTP request."
    sys.stdout.write(settings.print_critical_msg(err_msg) + "\n")
    sys.stdout.flush()
    raise SystemExit()

  if menu.options.requestfile:
    info_msg = "Parsing HTTP request "
    request_file = menu.options.requestfile
  elif menu.options.logfile: 
    info_msg = "Parsing target "
    request_file = menu.options.logfile
    
  info_msg += "using the '" + os.path.split(request_file)[1] + "' file. "
  sys.stdout.write(settings.print_info_msg(info_msg))
  sys.stdout.flush()

  if not os.path.exists(request_file):
    print(settings.FAIL_STATUS)
    err_msg = "It seems that the '" + request_file + "' file, does not exist."
    sys.stdout.write(settings.print_critical_msg(err_msg) + "\n")
    sys.stdout.flush()
    raise SystemExit()

  else:
    try:
      if menu.options.requestfile:
        with open(request_file, 'r') as f:
          settings.RAW_HTTP_HEADERS = [line.strip() for line in f]
        settings.RAW_HTTP_HEADERS = [header for header in settings.RAW_HTTP_HEADERS if header]
        settings.RAW_HTTP_HEADERS = settings.RAW_HTTP_HEADERS[1:]
        settings.RAW_HTTP_HEADERS = settings.RAW_HTTP_HEADERS[:-1]
        settings.RAW_HTTP_HEADERS = '\\n'.join(settings.RAW_HTTP_HEADERS)
      request = open(request_file, 'r')
    except IOError as err_msg:
      error_msg = "The '" + request_file + "' "
      error_msg += str(err_msg.args[1]).lower() + "."
      print(settings.FAIL_STATUS)
      print(settings.print_critical_msg(error_msg))
      raise SystemExit()
        
    words_dict = {}
    for word in request.read().strip().splitlines():
      if word[:4].strip() == "GET" or word[:4].strip() == "POST":
        words_dict[word[:4].strip()] = words_dict.get(word[:4].strip(), 0) + 1

    # Check if same header appears more than once.
    single_request = True
    if len(words_dict.keys()) > 1:
      single_request = multi_requests()
    for key in words_dict.keys():
      if words_dict[key] > 1:
        single_request = multi_requests()

    # Check for GET / POST HTTP Header
    for http_header in ["GET","POST"]:
      request = open(request_file, "r")
      request = request.read()
      if "\\n" in request:
        request = request.replace("\\n","\n")
      request_url = re.findall(r"" + http_header + " (.*) ", request)

      if request_url:
        if not single_request:
          request_url = request_url[0]
        if http_header == "POST":
          # Check for POST Data.
          result = [item for item in request.splitlines() if item]
          multiple_xml = []
          for item in result:
            if checks.is_XML_check(item):
              multiple_xml.append(item)
          if len(multiple_xml) != 0:
            menu.options.data = '\n'.join([str(item) for item in multiple_xml]) 
          else:  
            menu.options.data = result[len(result)-1]
        else:
          try:
            # Check if url ends with "=".
            if request_url[0].endswith("="):
              request_url = request_url[0].replace("=","=" + settings.INJECT_TAG, 1)
          except IndexError:
            invalid_data(request_file, single_request) 
        break

    # Check if invalid data
    if not request_url:
      invalid_data(request_file, single_request)
    else:
      request_url = "".join([str(i) for i in request_url])       

    # Check for other headers
    extra_headers = ""
    prefix = "http://"
    for line in request.splitlines():
      if re.findall(r"Host: " + "(.*)", line):
        menu.options.host = "".join([str(i) for i in re.findall(r"Host: " + "(.*)", line)])
      # User-Agent Header
      elif re.findall(r"User-Agent: " + "(.*)", line) and not (menu.options.agent or menu.options.mobile):
        menu.options.agent = "".join([str(i) for i in re.findall(r"User-Agent: " + "(.*)", line)])
      # Cookie Header
      elif re.findall(r"Cookie: " + "(.*)", line):
        menu.options.cookie = "".join([str(i) for i in re.findall(r"Cookie: " + "(.*)", line)])
      # Referer Header
      elif re.findall(r"Referer: " + "(.*)", line):
        menu.options.referer = "".join([str(i) for i in re.findall(r"Referer: " + "(.*)", line)])
        if menu.options.referer and "https://" in menu.options.referer:
          prefix = "https://"
      elif re.findall(r"Authorization: " + "(.*)", line):
        auth_provided = "".join([str(i) for i in re.findall(r"Authorization: " + "(.*)", line)]).split()
        menu.options.auth_type = auth_provided[0].lower()
        if menu.options.auth_type == "basic":
          menu.options.auth_cred = base64.b64decode(auth_provided[1]).decode()
        elif menu.options.auth_type == "digest":
          if not menu.options.auth_cred:
            print(settings.FAIL_STATUS)
            err_msg = "Use the '--auth-cred' option to provide a valid pair of "
            err_msg += "HTTP authentication credentials (i.e --auth-cred=\"admin:admin\") "
            print(settings.print_critical_msg(err_msg))
            raise SystemExit()

      # Add extra headers
      else:
        match = re.findall(r"(.*): (.*)", line)
        match = "".join([str(i) for i in match]).replace("', '",":")
        match = match.replace("('","")
        match = match.replace("')","\\n")
        # Ignore some header.
        if "Content-Length" or "Accept-Encoding" in match: 
          extra_headers = extra_headers
        else:
          extra_headers = extra_headers + match
   
    # Extra headers   
    menu.options.headers = extra_headers

    # Target URL  
    if not menu.options.host:
      invalid_data(request_file, single_request)
    else:
      menu.options.url = prefix + menu.options.host + request_url
      if single_request:
        sys.stdout.write(settings.SUCCESS_STATUS + "\n")
        sys.stdout.flush()
      if menu.options.logfile:
        info_msg = "Parsed target from '" + os.path.split(request_file)[1] + "' for tests :"
        print(settings.print_info_msg(info_msg))
        sub_content = http_header + " " +  prefix + menu.options.host + request_url
        print(settings.print_sub_content(sub_content))
        if http_header == "POST":
           sub_content = "Data: " + menu.options.data
           print(settings.print_sub_content(sub_content))
# eof