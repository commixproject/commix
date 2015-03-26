#!/usr/bin/env python
# encoding: UTF-8

"""
 This file is part of commix tool.
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
      proxy= urllib2.ProxyHandler({'http': menu.options.proxy})
      opener = urllib2.build_opener(proxy)
      urllib2.install_opener(opener)
      response = urllib2.urlopen(request)
    
    except urllib2.HTTPError, err:
      print "\n(x) Error : " + str(err)
      sys.exit(1) 

  else:
    response = urllib2.urlopen(request) 
    
#eof