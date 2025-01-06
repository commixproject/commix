#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2025 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

import sys
import socket
from src.utils import menu
from src.utils import settings
from src.core.requests import headers
from src.core.requests import requests
from src.core.injections.controller import checks
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.colorama import Fore, Back, Style, init
from src.thirdparty.six.moves import http_client as _http_client

"""
Use the defined HTTP Proxy
"""
def use_proxy(request):
  try:
    if menu.options.ignore_proxy:
      proxy = _urllib.request.ProxyHandler({})
      opener = _urllib.request.build_opener(proxy)
      _urllib.request.install_opener(opener)
    elif menu.options.tor:
      proxy = _urllib.request.ProxyHandler({settings.TOR_HTTP_PROXY_SCHEME:menu.options.proxy})
      opener = _urllib.request.build_opener(proxy)
      _urllib.request.install_opener(opener)
    else:
      request.set_proxy(menu.options.proxy, settings.SCHEME)
    return _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
  except Exception as err_msg:
    return requests.request_failed(err_msg)

"""
 Check if HTTP Proxy is defined.
"""
def do_check():
  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Setting the HTTP proxy for all HTTP requests. "
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

# eof