#!/usr/bin/env python
# encoding: UTF-8

"""
 This file is part of commix (@commixproject) tool.
 Copyright (c) 2015 Anastasios Stasinopoulos (@ancst).
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
 1. Generate injection logs in "./ouput" file.
 2. Check for logs updates and apply if any!
"""

def create_log_file(url):

  parts = url.split('//', 1)
  host = parts[1].split('/', 1)[0]
  try:
      os.stat(settings.OUTPUT_DIR + host + "/")
  except:
      os.mkdir(settings.OUTPUT_DIR + host + "/") 
  # The logs filename construction.
  filename = settings.OUTPUT_DIR + host + "/" + settings.OUTPUT_FILE_NAME
  output_file = open(filename + ".txt", "a")
  output_file.write("\n---")
  output_file.write("\nTime : " + datetime.datetime.fromtimestamp(time.time()).strftime('%H:%M:%S'))
  output_file.write("\nDate : " + datetime.datetime.fromtimestamp(time.time()).strftime('%m/%d/%Y'))
  output_file.write("\n---")
  output_file.write("\nURL : " + url)
  output_file.write("\n---")
  output_file.close()

  return filename

def add_type_and_technique(export_injection_info, filename, injection_type, technique):

  if export_injection_info == False:
    output_file = open(filename + ".txt", "a")
    output_file.write("\n(+) Type : " + injection_type)
    output_file.write("\n(+) Technique : " + technique.title())
    output_file.close()
    export_injection_info = True

  return export_injection_info

def add_parameter(vp_flag, filename, http_request_method, vuln_parameter, payload):

  if vp_flag == True:
    output_file = open(filename + ".txt", "a")
    if settings.COOKIE_INJECTION == True:
      http_request_method = "cookie"
    output_file.write("\n(+) Parameter : " + vuln_parameter + " (" + http_request_method + ")")
    output_file.write("\n")
    vp_flag = False
    output_file.close()

  return vp_flag

def upload_payload(filename, counter, payload):

  output_file = open(filename + ".txt", "a")
  if "\n" in payload:
    output_file.write("  ("+str(counter)+") Payload : " + re.sub("%20", " ", urllib.unquote_plus(payload.replace("\n", "\\n"))) + "\n")
  else:
    output_file.write("  ("+str(counter)+") Payload : " + re.sub("%20", " ", payload) + "\n")
  output_file.close()