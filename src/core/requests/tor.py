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

import re
import sys
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.six.moves import http_client as _http_client
from src.utils import menu
from src.utils import settings
from src.utils import requirments
from src.core.requests import requests
from src.thirdparty.colorama import Fore, Back, Style, init

def tor_bandle_error():
  print(settings.SINGLE_WHITESPACE)
  err_msg = "Can't establish connection with the Tor HTTP proxy. "  
  err_msg += "Please make sure that you have "
  err_msg += "Tor bundle (https://www.torproject.org/download/) or Tor and Privoxy installed and setup "
  err_msg += "so you could be able to successfully use switch '--tor'."
  print(settings.print_critical_msg(err_msg))
  raise SystemExit()

"""
Check if Tor HTTP proxy is defined.
"""
def do_check():
  if menu.options.tor_port:
    settings.TOR_HTTP_PROXY_PORT = menu.options.tor_port
  check_tor_http_proxy = True
  info_msg = "Testing Tor HTTP proxy settings ("
  info_msg += settings.TOR_HTTP_PROXY_SCHEME + "://" + settings.TOR_HTTP_PROXY_IP + ":" + settings.TOR_HTTP_PROXY_PORT 
  info_msg +=  "). "
  sys.stdout.write(settings.print_info_msg(info_msg))
  sys.stdout.flush()
  try:
    tor_http_proxy = _urllib.request.ProxyHandler({settings.TOR_HTTP_PROXY_SCHEME:settings.TOR_HTTP_PROXY_IP + ":" + settings.TOR_HTTP_PROXY_PORT})
    opener = _urllib.request.build_opener(tor_http_proxy)
    _urllib.request.install_opener(opener)
  except:
    check_tor_http_proxy = False
    pass

  if check_tor_http_proxy:
    try:
      check_tor_page = opener.open("https://check.torproject.org/").read().decode(settings.DEFAULT_CODEC)
      if not "You are not using Tor" in check_tor_page:
        sys.stdout.write(settings.SUCCESS_STATUS + "\n")
        sys.stdout.flush()
        if menu.options.tor_check:
          info_msg = "Connection with the Tor HTTP proxy is properly set. "
        else:
          info_msg = ""
        found_ip = re.findall(r":  <strong>" + "(.*)" + "</strong></p>", check_tor_page)
        info_msg += "Your ip address appears to be " + found_ip[0] + ".\n"
        sys.stdout.write(settings.print_bold_info_msg(info_msg))
        warn_msg = "Increasing default value for option '--time-sec' to"
        warn_msg += " " + str(settings.TIMESEC) + " because switch '--tor' was provided."
        print(settings.print_warning_msg(warn_msg))
      else:
        tor_bandle_error()

    except _urllib.error.URLError as err_msg:
      tor_bandle_error()

    except Exception as err_msg:
      return requests.request_failed(err_msg)


"""
Use the TOR HTTP Proxy.
"""
def use_tor(request):
  if menu.options.offline:
    err_msg = "You cannot use Tor network while offline."
    print(settings.print_critical_msg(err_msg))
    raise SystemExit()

  try:
    tor_http_proxy = _urllib.request.ProxyHandler({settings.TOR_HTTP_PROXY_SCHEME:settings.TOR_HTTP_PROXY_IP + ":" + settings.TOR_HTTP_PROXY_PORT})
    opener = _urllib.request.build_opener(tor_http_proxy)
    _urllib.request.install_opener(opener)
    response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
    return response

  except Exception as err_msg:
    return requests.request_failed(err_msg)

# eof