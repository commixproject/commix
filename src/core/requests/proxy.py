#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2020 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
 
For more see the file 'readme/COPYING' for copying permission.
"""

import sys
from src.utils import menu
from src.utils import settings
from src.core.requests import headers
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.colorama import Fore, Back, Style, init
from src.thirdparty.six.moves import http_client as _http_client

"""
 Check if HTTP Proxy is defined.
"""
def do_check(url):
  check_proxy = True
  try:
    if settings.VERBOSITY_LEVEL >= 1:
      info_msg = "Setting the HTTP proxy for all HTTP requests... "
      print(settings.print_info_msg(info_msg))
    # Check if defined POST data
    if menu.options.data:
      request = _urllib.request.Request(url, menu.options.data.encode(settings.UNICODE_ENCODING))
    else:
       request = _urllib.request.Request(url)
    # Check if defined extra headers.
    headers.do_check(request)
    request.set_proxy(menu.options.proxy,settings.PROXY_SCHEME)
    try:
      check = _urllib.request.urlopen(request)
    except _urllib.error.HTTPError as error:
      check = error
  except:
    check_proxy = False
    pass
  if check_proxy == True:
    pass
  else:
    err_msg = "Unable to connect to the target URL or proxy ("
    err_msg += str(menu.options.proxy)
    err_msg += ")."
    print(settings.print_critical_msg(err_msg))
    raise SystemExit()
    
"""
Use the defined HTTP Proxy
"""
def use_proxy(request):
  headers.do_check(request)
  request.set_proxy(menu.options.proxy,settings.PROXY_SCHEME)
  try:
    response = _urllib.request.urlopen(request)
    return response

  except _http_client.BadStatusLine as e:
    err_msg = "Unable to connect to the target URL or proxy ("
    err_msg += str(menu.options.proxy)
    err_msg += ")."
    print(settings.print_critical_msg(err_msg))
    raise SystemExit() 

  except Exception as err_msg:
    try:
      error_msg = str(err_msg.args[0]).split("] ")[1] + "."
    except IndexError:
      error_msg = str(err_msg).replace(": "," (") + ")."
    print(settings.print_critical_msg(error_msg))
    raise SystemExit()

# eof 