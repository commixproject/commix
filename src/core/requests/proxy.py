#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2023 Anastasios Stasinopoulos (@ancst).

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
    request.set_proxy(menu.options.proxy, settings.PROXY_SCHEME)
    return _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
  except Exception as err_msg:
    return requests.request_failed(err_msg)

"""
 Check if HTTP Proxy is defined.
"""
def do_check():
  if settings.VERBOSITY_LEVEL != 0:
    info_msg = "Setting the HTTP proxy for all HTTP requests. "
    print(settings.print_info_msg(info_msg))

# eof 