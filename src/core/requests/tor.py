#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2026 Anastasios Stasinopoulos (@ancst).

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
  err_msg = "Tor connection could not be established. "
  err_msg += "Please ensure Tor is running and reachable"
  err_msg += " and that any provided options (e.g., '--tor-port') are correct."
  settings.print_data_to_stdout(settings.print_error_msg(err_msg))
  raise SystemExit()


def do_check():
  info_msg = "Testing connection to the Tor network."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))

  if menu.options.offline:
    err_msg = "You cannot use Tor network while offline."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  try:
    request = _urllib.request.Request(settings.CHECK_TOR_PAGE, method=settings.HTTPMETHOD.GET)
    response = proxy.use_proxy(request)
    page = response.read().decode(settings.DEFAULT_CODEC)
  except Exception:
    page = None

  if not page:
    tor_connection_error()

  ip_match = re.search(r'Your IP address appears to be:\s*<strong>(\d+\.\d+\.\d+\.\d+)</strong>', page)
  tor_ip = ip_match.group(1) if ip_match else "unknown"

  if tor_ip == "unknown":
    warn_msg = "Tor page fetched but no IP detected. Tor may not be routing traffic properly."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

  else:
    if settings.VERBOSITY_LEVEL >= 1:
      debug_msg = "Tor connection established and traffic is routing through exit node: IP: " + tor_ip
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))


# eof