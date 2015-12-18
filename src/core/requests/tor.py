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
from src.utils import requirments
from src.thirdparty.colorama import Fore, Back, Style, init

"""
Check for TOR HTTP Proxy.
"""
if menu.options.tor_port:
  PRIVOXY_PORT = menu.options.tor_port
else:
  PRIVOXY_PORT = settings.PRIVOXY_PORT

"""
Check if HTTP Proxy (tor/privoxy) is defined.
"""
def do_check():
  # Check if 'tor' is installed.
  requirment = "tor"
  requirments.do_check(requirment)

  # Check if 'privoxy' is installed.
  requirment = "privoxy"
  requirments.do_check(requirment)
    
  check_privoxy_proxy = True
  sys.stdout.write("(*) Testing privoxy proxy settings " + settings.PRIVOXY_IP + ":" + PRIVOXY_PORT + "... ")
  sys.stdout.flush()

  try:
    privoxy_proxy = urllib2.ProxyHandler({settings.PROXY_PROTOCOL:settings.PRIVOXY_IP + ":" + PRIVOXY_PORT})
    opener = urllib2.build_opener(privoxy_proxy)
    urllib2.install_opener(opener)

  except:
    check_privoxy_proxy = False
    pass
    
  if check_privoxy_proxy:
    try:     
      new_ip = opener.open("http://icanhazip.com/").read()
      sys.stdout.write("[" + Fore.GREEN + " SUCCEED " + Style.RESET_ALL + "]\n")
      sys.stdout.flush()
      sys.stdout.write(Style.BRIGHT + "(!) Your ip address appears to be " + Style.UNDERLINE + new_ip + Style.RESET_ALL)

    except urllib2.URLError, err:
      print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
      print Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
      sys.exit(0)
      
    except urllib2.HTTPError, err:
      print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
      print Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
      sys.exit(0)

"""
Use the TOR HTTP Proxy.
"""
def use_tor(request):
  privoxy_proxy = urllib2.ProxyHandler({settings.PROXY_PROTOCOL:settings.PRIVOXY_IP + ":" + PRIVOXY_PORT})
  opener = urllib2.build_opener(privoxy_proxy)
  urllib2.install_opener(opener)
  response = urllib2.urlopen(request)
  
  return response
  
#eof 