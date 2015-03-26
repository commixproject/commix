#!/usr/bin/env python
# encoding: UTF-8

"""
 This file is part of commix tool.
 Copyright (c) 2015 Anastasios Stasinopoulos (@ancst).
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
from src.utils import colors

from src.core.requests import headers

"""
 Check if HTTP Proxy.
"""

def do_check(url):

  check_proxy = True
  sys.stdout.write("(*) Testing proxy "+menu.options.proxy+" ... ")
  sys.stdout.flush()
  try:
    request = urllib2.Request(url)
    # Check if defined extra headers.
    headers.do_check(request)
    request.set_proxy(menu.options.proxy,"http")
    try:
      check = urllib2.urlopen(request)
      
    except urllib2.HTTPError, error:
      check = error
      
  except:
    check_proxy = False
    pass
  
  if check_proxy == True:
    sys.stdout.write("["+colors.GREEN+" OK "+colors.RESET+"]\n")
    sys.stdout.flush()
    
  else:
    print "[" + colors.RED+ " FAILED "+colors.RESET+"]\n"
    sys.exit(1)
    