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
  Error message for mutiple request in same log file.
  """
  def multi_targets():
    print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
    error_msg = "Currently " + settings.APPLICATION + " doesn't support "
    error_msg += "multiple targets. Use only one request per log file."
    sys.stdout.write(Back.RED + settings.ERROR_SIGN + error_msg + Style.RESET_ALL + "\n")
    sys.stdout.flush()
    sys.exit(0)

  """
  Error message for invalid data.
  """
  def invalid_data():
    print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
    error_msg = "Something seems to be wrong with "
    error_msg += "the '" + menu.options.logfile + "' file. "
    sys.stdout.write(Back.RED + settings.ERROR_SIGN + error_msg + Style.RESET_ALL + "\n")
    sys.stdout.flush()
    sys.exit(0)

  proxy_log_file = menu.options.logfile
  sys.stdout.write(settings.INFO_SIGN + "Parsing target using the '" + os.path.split(proxy_log_file)[1] + "' file... ")
  sys.stdout.flush()
  if not os.path.exists(proxy_log_file):
    print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
    sys.stdout.write(Back.RED + settings.ERROR_SIGN + "It seems that the '" + proxy_log_file + "' file, does not exists." + Style.RESET_ALL + "\n")
    sys.stdout.flush()
    sys.exit(0)
  else:
    # Check for multiple hosts
    proxy_log_file = open(menu.options.logfile, "r")
    words_dict = {}
    for word in proxy_log_file.read().split():
      words_dict[word] = words_dict.get(word,0) + 1
    # Check if same header appears more than once.
    for key in words_dict.keys():
      if words_dict[key] > 1:
        multi_targets()

    # Check for GET / POST HTTP Header
    for http_header in ["GET", "POST"]:
      proxy_log_file = open(menu.options.logfile, "r")
      request_url = re.findall(r"" + http_header + " (.*) ", proxy_log_file.readline())

      if request_url:
        if http_header == "POST":
          # Check for POST Data.
          result = [item for item in proxy_log_file.read().splitlines() if item]
          if not any(settings.INJECT_TAG in s for s in result):
            print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
            print Back.RED + settings.ERROR_SIGN + "You must set the \"INJECT_HERE\" tag to specify the testable parameter in the '" + menu.options.logfile + "' file." + Style.RESET_ALL
            sys.exit(0)
          menu.options.data = result[len(result)-1]
        else:
          # Check if url ends with "=".
          if request_url[0].endswith("="):
            request_url = request_url[0].replace("=","=" + settings.INJECT_TAG, 1)
        break

    # Check if invalid data
    if not request_url:
      invalid_data()
    else:
      request_url = "".join([str(i) for i in request_url])       
    
    # Check for other headers
    proxy_log_file = open(menu.options.logfile, "r")
    extra_headers = ""
    prefix = "http://"
    for line in proxy_log_file:
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
            error_msg = "Use the '--auth-cred' option to provide a valid pair of "
            error_msg += "HTTP authentication credentials (i.e --auth-cred=\"admin:admin\") "
            print Back.RED + settings.ERROR_SIGN + error_msg + Style.RESET_ALL
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
      invalid_data()
    else:
      menu.options.url = prefix + menu.options.host + request_url
      sys.stdout.write("[" + Fore.GREEN + " SUCCEED " + Style.RESET_ALL + "]\n")
      sys.stdout.flush()
      
#eof
