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

For more see the file 'doc/COPYING' for copying permission.
"""

import os
import re
import time
import urllib
import datetime

from src.utils import menu
from src.utils import settings

from src.thirdparty.colorama import Fore, Back, Style, init

"""
1. Generate injection logs (logs.txt) in "./ouput" file.
2. Check for logs updates and apply if any!
"""

"""
Create log files
"""
def create_log_file(url, output_dir):
  if not output_dir.endswith("/"):
    output_dir = output_dir + "/"

  parts = url.split('//', 1)
  host = parts[1].split('/', 1)[0]

  # Check if port is defined to host.
  if ":" in host:
    host = host.replace(":","_")

  try:
      os.stat(output_dir + host + "/")
  except:
      os.mkdir(output_dir + host + "/") 

  # The logs filename construction.
  filename = output_dir + host + "/" + settings.OUTPUT_FILE
  output_file = open(filename, "a")
  output_file.write("\n---")
  output_file.write("\nTime : " + datetime.datetime.fromtimestamp(time.time()).strftime('%H:%M:%S'))
  output_file.write("\nDate : " + datetime.datetime.fromtimestamp(time.time()).strftime('%m/%d/%Y'))
  output_file.write("\n---")
  output_file.write("\nURL : " + url)
  output_file.write("\n---")
  output_file.close()

  return filename

"""
Add the injection type / technique in log files.
"""
def add_type_and_technique(export_injection_info, filename, injection_type, technique):

  if export_injection_info == False:
    settings.SHOW_LOGS_MSG = True
    output_file = open(filename, "a")
    output_file.write("\n(+) Type : " + injection_type)
    output_file.write("\n(+) Technique : " + technique.title())
    output_file.close()
    export_injection_info = True

  return export_injection_info

"""
Add the vulnerable parameter in log files.
"""
def add_parameter(vp_flag, filename, http_request_method, vuln_parameter, payload):

  if vp_flag == True:
    output_file = open(filename, "a")
    if settings.COOKIE_INJECTION == True:
      http_request_method = "cookie"
    if vuln_parameter == "HTTP Header" :
      output_file.write("\n(+) Parameter : " + http_request_method + " HTTP Header ")
    else :
      vp_flag = False
      output_file.write("\n(+) Parameter : " + vuln_parameter + "(" + http_request_method + ")")
    output_file.write("\n")
    output_file.close()

  return vp_flag

"""
Add any payload in log files.
"""
def update_payload(filename, counter, payload):

  output_file = open(filename, "a")
  if "\n" in payload:
    output_file.write("  (" +str(counter)+ ") Payload : " + re.sub("%20", " ", urllib.unquote_plus(payload.replace("\n", "\\n"))) + "\n")
  else:
    output_file.write("  (" +str(counter)+ ") Payload : " + re.sub("%20", " ", payload) + "\n")
  output_file.close()

"""
Log files cration notification
"""
def logs_notification(filename):
  print "\n" + Style.BRIGHT + "(!) The results can be found at '" + os.getcwd() + "/" + filename + "'" + Style.RESET_ALL


# eof
