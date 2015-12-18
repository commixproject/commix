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
import cookielib

from src.utils import menu
from src.utils import settings

from src.core.requests import tor
from src.core.requests import proxy
from src.core.requests import headers

from src.core.injections.controller import checks
from src.thirdparty.colorama import Fore, Back, Style, init

"""
If a dashboard or an administration panel is found (auth_url),
do the authentication process using the provided credentials (auth_data).
"""

"""
The authentication process
"""
def authentication_process():
  auth_url = menu.options.auth_url
  auth_data = menu.options.auth_data
  cj = cookielib.CookieJar()
  opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
  request = opener.open(urllib2.Request(auth_url))

  cookies = ""
  for cookie in cj:
      cookie_values = cookie.name + "=" + cookie.value + "; "
      cookies += cookie_values

  if len(cookies) != 0 :
    menu.options.cookie = cookies.rstrip()
    if menu.options.verbose:
      print Style.BRIGHT + "(!) The received cookie is " + Style.UNDERLINE + menu.options.cookie + Style.RESET_ALL + "." + Style.RESET_ALL

  urllib2.install_opener(opener)
  request = urllib2.Request(auth_url, auth_data)

  # Check if defined extra headers.
  headers.do_check(request)

  # Check if defined any HTTP Proxy.
  if menu.options.proxy:
    try:
      response = proxy.use_proxy(request)
    except urllib2.HTTPError, err:
      if settings.IGNORE_ERR_MSG == False:
        print "\n" + Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
        continue_tests = checks.continue_tests(err)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 

  # Check if defined Tor.
  elif menu.options.tor:
    try:
      response = tor.use_tor(request)
    except urllib2.HTTPError, err:
      if settings.IGNORE_ERR_MSG == False:
        print "\n" + Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
        continue_tests = checks.continue_tests(err)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 

  else:
    try:
      response = urllib2.urlopen(request)
    except urllib2.HTTPError, err:
      if settings.IGNORE_ERR_MSG == False:
        print "\n" + Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
        continue_tests = checks.continue_tests(err)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 

  return response 

#eof