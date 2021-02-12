#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2021 Anastasios Stasinopoulos (@ancst).

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
  if settings.VERBOSITY_LEVEL != 0:
    info_msg = "Setting the HTTP proxy for all HTTP requests. "
    print(settings.print_info_msg(info_msg))
  if menu.options.data:
    request = _urllib.request.Request(url, menu.options.data.encode(settings.UNICODE_ENCODING))
  else:
     request = _urllib.request.Request(url)
  headers.do_check(request)
  request.set_proxy(menu.options.proxy, settings.PROXY_SCHEME)
  try:
    response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
    return response
  except Exception as err:
    if "Connection refused" in str(err):
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
  request.set_proxy(menu.options.proxy, settings.PROXY_SCHEME)
  try:
    response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
    return response
  except _http_client.BadStatusLine as err:
    err_msg = "Unable to connect to the target URL or proxy ("
    err_msg += str(menu.options.proxy)
    err_msg += ")."
    print(settings.print_critical_msg(err_msg))
    raise SystemExit() 
  except Exception as err:
    if settings.UNAUTHORIZED_ERROR in str(err).lower():
      pass
    elif "Connection refused" in str(err):
      err_msg = "Unable to connect to the target URL or proxy ("
      err_msg += str(menu.options.proxy)
      err_msg += ")."
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()
    else:
      try:
        err_msg = str(err.args[0]).split("] ")[1] + "."
      except IndexError:
        err_msg = str(err).replace(": "," (") + ")."
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()

# eof 