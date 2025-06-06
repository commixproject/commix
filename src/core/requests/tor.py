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

import re
import sys
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.six.moves import http_client as _http_client
from src.utils import menu
from src.utils import settings
from src.utils import requirements
from src.core.requests import proxy
from src.core.requests import requests
from src.thirdparty.colorama import Fore, Back, Style, init

"""
Check if Tor HTTP proxy is defined.
"""

def tor_connection_error():
  err_msg = "It appears that Tor is not properly set. Please "
  if not menu.options.tor_port:
    err_msg += "try again using option '--tor-port'."
  else:
    err_msg += "check again the provided option '--tor-port'."
  settings.print_data_to_stdout(settings.print_error_msg(err_msg))
  raise SystemExit()

def do_check():
  info_msg = "Testing Tor HTTP proxy settings."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  if menu.options.offline:
    err_msg = "You cannot use Tor network while offline."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()
  try:
    request = _urllib.request.Request(settings.CHECK_TOR_PAGE, method=settings.HTTPMETHOD.GET)
    response = proxy.use_proxy(request)
    page = response.read().decode(settings.DEFAULT_CODEC)
  except Exception as err_msg:
    page = None
  if not page or "Congratulations" not in page:
    tor_connection_error()
  else:
    info_msg = "Connection with the Tor HTTP proxy is properly set. "
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))

# eof