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
  sys.stdout.write("(*) Testing proxy " + menu.options.proxy + "... ")
  sys.stdout.flush()
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
    sys.stdout.write("[" + Fore.GREEN + "  SUCCEED " + Style.RESET_ALL + " ]\n")
    sys.stdout.flush()
  else:
    print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
    print Back.RED + "(x) Error: Could not connect to proxy." + Style.RESET_ALL
    sys.exit(0)
    
"""
Use the defined HTTP Proxy
"""
def use_proxy(request):
  proxy = urllib2.ProxyHandler({settings.PROXY_PROTOCOL: menu.options.proxy})
  opener = urllib2.build_opener(proxy)
  urllib2.install_opener(opener)
  response = urllib2.urlopen(request)

  return response