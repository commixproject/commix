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

import sys
import urllib2

from src.utils import menu
from src.utils import settings

from src.core.requests import headers
from src.thirdparty.colorama import Fore, Back, Style, init

"""
 Check if HTTP Proxy is defined.
"""
def do_check(url):
  check_proxy = True
  try:
    # Check if defined POST data
    if menu.options.data:
      request = urllib2.Request(url, menu.options.data)
    else:
       request = urllib2.Request(url)
    # Check if defined extra headers.
    headers.do_check(request)
    request.set_proxy(menu.options.proxy,settings.PROXY_PROTOCOL)
    try:
      check = urllib2.urlopen(request)
    except urllib2.HTTPError, error:
      check = error
  except:
    check_proxy = False
    pass
  if check_proxy == True:
    pass
  else:
    err_msg = "Unable to connect to proxy ("
    err_msg += menu.options.proxy
    err_msg += ")."
    print settings.print_critical_msg(err_msg)
    sys.exit(0)
    
"""
Use the defined HTTP Proxy
"""
def use_proxy(request):
  headers.do_check(request)
  request.set_proxy(menu.options.proxy,settings.PROXY_PROTOCOL)
  response = urllib2.urlopen(request)
  return response  
