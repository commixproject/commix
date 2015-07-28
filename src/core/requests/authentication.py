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
 
 For more see the file 'readme/COPYING' for copying permission.
"""

import sys
import urllib2
import cookielib

from src.utils import menu

from src.core.requests import tor
from src.core.requests import proxy
from src.core.requests import headers

"""
  If a dashboard or an administration panel is found (auth_url),
  do the authentication process using the provided credentials (auth_data).
"""

def auth_process():
  auth_url = menu.options.auth_url
  auth_data = menu.options.auth_data
  cj = cookielib.CookieJar()
  opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
  urllib2.install_opener(opener)
  request = urllib2.Request(auth_url, auth_data)
  # Check if defined extra headers.
  headers.do_check(request)
  # Check if defined any HTTP Proxy.
  if menu.options.proxy:
    try:
      response = proxy.use_proxy(request)
    except urllib2.HTTPError, err:
      print "\n" + Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
      raise SystemExit() 

  # Check if defined Tor.
  elif menu.options.tor:
    try:
      response = tor.use_tor(request)
    except urllib2.HTTPError, err:
      print "\n" + Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
      raise SystemExit() 

  else:
    try:
      response = urllib2.urlopen(request)
    except urllib2.HTTPError, err:
      print "\n" + Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
      raise SystemExit() 


#eof