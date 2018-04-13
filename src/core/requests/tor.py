#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (http://commixproject.com).
Copyright (c) 2014-2018 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

import re
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
  info_msg = "Testing Tor SOCKS proxy settings (" 
  info_msg += settings.PRIVOXY_IP + ":" + PRIVOXY_PORT 
  info_msg +=  ")... "
  sys.stdout.write(settings.print_info_msg(info_msg))
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
      check_tor_page = opener.open("https://check.torproject.org/").read()
      found_ip = re.findall(r":  <strong>" + "(.*)" + "</strong></p>", check_tor_page)
      if not "You are not using Tor" in check_tor_page:
        sys.stdout.write("[" + Fore.GREEN + " SUCCEED " + Style.RESET_ALL + "]\n")
        sys.stdout.flush()
        if menu.options.tor_check:
          success_msg = "Tor connection is properly set. "
        else:
          success_msg = ""
        success_msg += "Your ip address appears to be " + found_ip[0] + ".\n"
        sys.stdout.write(settings.print_success_msg(success_msg))
        warn_msg = "Increasing default value for option '--time-sec' to"
        warn_msg += " " + str(settings.TIMESEC) + " because switch '--tor' was provided."
        print settings.print_warning_msg(warn_msg)  

      else:
        print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
        if menu.options.tor_check:
          err_msg = "It seems that your Tor connection is not properly set. "
        else:
          err_msg = "" 
        err_msg += "Can't establish connection with the Tor SOCKS proxy. "
        err_msg += "Please make sure that you have "
        err_msg += "Tor installed and running so "
        err_msg += "you could successfully use "
        err_msg += "switch '--tor'."
        print settings.print_critical_msg(err_msg)  
        sys.exit(0)  

    except urllib2.URLError, err_msg:
      print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
      if menu.options.tor_check:
        warn_msg = "It seems that your Tor connection is not properly set. "
      else:
        warn_msg = ""
      warn_msg = "Please make sure that you have "
      warn_msg += "Tor installed and running so "
      warn_msg += "you could successfully use "
      warn_msg += "switch '--tor'."
      print settings.print_warning_msg(warn_msg)
      print settings.print_critical_msg(str(err_msg.args[0]).split("] ")[1] + ".")
      sys.exit(0)  

"""
Use the TOR HTTP Proxy.
"""
def use_tor(request):
  if menu.options.offline:  
    err_msg = "You cannot Tor network without access on the Internet."
    print settings.print_critical_msg(err_msg)
    sys.exit(0)

  privoxy_proxy = urllib2.ProxyHandler({settings.PROXY_PROTOCOL:settings.PRIVOXY_IP + ":" + PRIVOXY_PORT})
  opener = urllib2.build_opener(privoxy_proxy)
  urllib2.install_opener(opener)
  response = urllib2.urlopen(request)
  return response
  
# eof 