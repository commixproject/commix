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

import os
import re
import sys
import time
import base64
import urllib
import datetime

from src.utils import menu
from src.utils import settings

from src.thirdparty.colorama import Fore, Back, Style, init

"""
Parse target and data from http proxy logs (i.e Burp or WebScarab)
"""
def logfile_parser():
  """
  Warning message for mutiple request in same log file.
  """
  def multi_requests():
    print "[" + Fore.GREEN + " SUCCEED " + Style.RESET_ALL + "]"
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
      print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
    err_msg = "Something seems to be wrong with "
    err_msg += "the '" + os.path.split(request_file)[1] + "' file. "
    sys.stdout.write(settings.print_critical_msg(err_msg) + "\n")
    sys.stdout.flush()
    sys.exit(0)

  if menu.options.requestfile: 
    request_file = menu.options.requestfile
    info_msg = "Parsing HTTP request "

  elif menu.options.logfile: 
    request_file = menu.options.logfile
    info_msg = "Parsing target "

  info_msg += "using the '" + os.path.split(request_file)[1] + "' file... "
  sys.stdout.write(settings.print_info_msg(info_msg))
  sys.stdout.flush()

  if not os.path.exists(request_file):
    print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
    err_msg = "It seems that the '" + request_file + "' file, does not exists."
    sys.stdout.write(settings.print_critical_msg(err_msg) + "\n")
    sys.stdout.flush()
    sys.exit(0)

  else:
    # Check for multiple hosts
    request = open(request_file, "r")
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
      elif re.findall(r"User-Agent: " + "(.*)", line):
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
          menu.options.auth_cred = base64.b64decode(auth_provided[1])
        elif menu.options.auth_type == "digest":
          if not menu.options.auth_cred:
            print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
            err_msg = "Use the '--auth-cred' option to provide a valid pair of "
            err_msg += "HTTP authentication credentials (i.e --auth-cred=\"admin:admin\") "
            print settings.print_critical_msg(err_msg)
            sys.exit(0)

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
        sys.stdout.write("[" + Fore.GREEN + " SUCCEED " + Style.RESET_ALL + "]\n")
        sys.stdout.flush()
      if menu.options.logfile:
        info_msg = "Parsed target from '" + os.path.split(request_file)[1] + "' for tests :"
        print settings.print_info_msg(info_msg)
        print settings.SUB_CONTENT_SIGN + http_header + " " +  prefix + menu.options.host + request_url
        if http_header == "POST":
           print settings.SUB_CONTENT_SIGN + "Data: " + menu.options.data
#eof