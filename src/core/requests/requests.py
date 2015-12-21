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
    print Back.RED + "(x) Error: The connection to target URL has timed out." + Style.RESET_ALL + "\n"
    sys.exit(0)     
  end = time.time()
  diff = end - start
  if int(diff) < 1:
    url_time_response = int(diff)
    if settings.TARGET_OS == "win":
      info_msg = "(^) Warning: Due to the relatively slow response of 'cmd.exe'"
      info_msg += " there may be delays during the data extraction procedure."
      print Fore.YELLOW + info_msg + Style.RESET_ALL
  else:
    url_time_response = int(round(diff))
    info_msg = "(^) Warning: The estimated response time is " + str(url_time_response)
    info_msg += " second" + "s"[url_time_response == 1:] + ". That may cause" 
    if url_time_response >= 3:
      info_msg += " serious"
    info_msg += " delays during the data extraction procedure" 
    if url_time_response >= 3:
      info_msg += " and/or possible corruptions over the extracted data"
    info_msg += "."
    print Fore.YELLOW + info_msg + Style.RESET_ALL
  delay = int(delay) + int(url_time_response)
  # Against windows targets (for more stability), add one extra second delay.
  if settings.TARGET_OS == "win" :
    delay = delay + 1

  return delay, url_time_response

#eof
