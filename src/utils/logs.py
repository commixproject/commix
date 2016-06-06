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
import urllib
import sqlite3
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

  if menu.options.session_file is not None:
    if os.path.exists(menu.options.session_file):
      settings.SESSION_FILE = menu.options.session_file
    else:
       err_msg = "The provided session file ('" + \
                    menu.options.session_file + \
                    "') does not exists." 
       print settings.print_error_msg(err_msg)
       sys.exit(0)
  else:  
    settings.SESSION_FILE = output_dir + host + "/" + "session" + ".db"

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
def add_parameter(vp_flag, filename, the_type, header_name, http_request_method, vuln_parameter, payload):
  
  output_file = open(filename, "a")
  if header_name[1:] == "cookie":
    header_name = " ("+ header_name[1:] + ") " + vuln_parameter
  if header_name[1:] == "":
    header_name = " ("+ http_request_method + ") " + vuln_parameter
  output_file.write("\n(+) " + the_type[1:].title() + ": " + header_name[1:])
  vp_flag == False
  output_file.write("\n")
  output_file.close()

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
Log files cration notification.
"""
def logs_notification(filename):
  success_msg = "The results can be found at '" + os.getcwd() + "/" + filename + "'"
  print "\n" + settings.print_success_msg(success_msg)

# eof