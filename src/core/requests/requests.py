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

import sys
import time
import socket
import urllib2

from src.utils import menu
from src.utils import settings
from src.core.requests import headers
from src.core.requests import parameters

from src.thirdparty.colorama import Fore, Back, Style, init

"""
Estimating the response time (in seconds).
"""
def estimate_response_time(url, http_request_method, delay):

  if http_request_method == "GET":
    # Find the host part.
    url = parameters.get_url_part(url)
  request = urllib2.Request(url)
  headers.do_check(request)
  start = time.time()
  try:
    response = urllib2.urlopen(request)
    response.read(1)
    response.close()
  except urllib2.HTTPError, e:
    pass
  except socket.timeout:
    err_msg = "The connection to target URL has timed out."
    print settings.print_error_msg(err_msg)+ "\n"
    sys.exit(0)     
  end = time.time()
  diff = end - start
  if int(diff) < 1:
    url_time_response = int(diff)
    if settings.TARGET_OS == "win":
      warn_msg = "Due to the relatively slow response of 'cmd.exe' in target "
      warn_msg += "host, there may be delays during the data extraction procedure."
      print settings.print_warning_msg(warn_msg)
  else:
    url_time_response = int(round(diff))
    warn_msg = "The estimated response time is " + str(url_time_response)
    warn_msg += " second" + "s"[url_time_response == 1:] + ". That may cause" 
    if url_time_response >= 3:
      warn_msg += " serious"
    warn_msg += " delays during the data extraction procedure" 
    if url_time_response >= 3:
      warn_msg += " and/or possible corruptions over the extracted data"
    warn_msg += "."
    print settings.print_warning_msg(warn_msg)
  delay = int(delay) + int(url_time_response)
  # Against windows targets (for more stability), add one extra second delay.
  if settings.TARGET_OS == "win" :
    delay = delay + 1

  return delay, url_time_response

"""
Target's charset detection
"""
def charset_detection(response):
  charset_detected = False
  if menu.options.verbose:
    info_msg = "Identifing the indicated web-page charset... " 
    sys.stdout.write(settings.print_info_msg(info_msg))
    sys.stdout.flush()
  try:
    # Detecting charset
    charset = response.headers.getparam('charset')
    if len(charset) != 0 :         
      charset_detected = True
    else:
      content = re.findall(r";charset=(.*)\"", html_data)
      if len(content) != 0 :
        charset = content
        charset_detected = True
      else:
         # Check if HTML5 format
        charset = re.findall(r"charset=['\"](.*?)['\"]", html_data) 
      if len(charset) != 0 :
        charset_detected = True
    # Check the identifyied charset
    if charset_detected :
      if menu.options.verbose:
        print "[ " + Fore.GREEN + "SUCCEED" + Style.RESET_ALL + " ]"
      settings.CHARSET = charset.lower()
      if settings.CHARSET.lower() not in settings.CHARSET_LIST:
        warn_msg = "The indicated web-page charset "  + settings.CHARSET + " seems unknown."
        print settings.print_warning_msg(warn_msg)
      else:
        if menu.options.verbose:
          success_msg = "The indicated web-page charset appears to be " 
          success_msg += Style.UNDERLINE + settings.CHARSET + Style.RESET_ALL + "."
          print settings.print_success_msg(success_msg)
    else:
      pass
  except:
    pass
  if charset_detected == False and menu.options.verbose:
    print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"

#eof