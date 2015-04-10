#!/usr/bin/env python
# encoding: UTF-8

"""
 This file is part of commix (@commixproject) tool.
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
import httplib

from src.utils import menu
from src.utils import colors
from src.utils import update
from src.utils import version
from src.utils import install

from src.core.requests import proxy
from src.core.requests import headers
from src.core.injections import controller


"""
 The main function.
"""

def main():

  try:
    #Call the banner
    menu.banner()
        
    # Check python version number.
    version.python_version()
    
    #Check if defined "--version" option.
    if menu.options.version:
	version.show_version()
	sys.exit(0)
	
    #Check if defined "--update" option.	
    if menu.options.update:
	update.updater()
	sys.exit(0)
	
    #Check if defined "--install" option.	
    if menu.options.install:
	install.installer()
	sys.exit(0)
    
    # Check arguments
    if len(sys.argv) == 1:
	menu.parser.print_help()
	print ""
	sys.exit(0)

    if menu.options.url:

      print "(*) Initializing, please wait... "
      url = menu.options.url
      
      try:
	request = urllib2.Request(url)
	
	# Check if defined extra headers.
	headers.do_check(request)
	
	response = urllib2.urlopen(request)
	content = response.read()
	
      except urllib2.HTTPError, e:
	if e.getcode() == 500:
	  content = e.read()
	  sys.exit(0)

	elif e.getcode() == 401:
	  print colors.BGRED + "(x) Error: Authorization required!" + colors.RESET + "\n"
	  sys.exit(0)

	elif e.getcode() == 404:
	  print colors.BGRED + "(x) Error: The host seems to be down!" + colors.RESET + "\n"
	  sys.exit(0)

	else:
	  raise

      except urllib2.URLError, e:
	  print colors.BGRED + "(x) Error: The host seems to be down!" + colors.RESET + "\n"
	  sys.exit(0)
	
      except httplib.BadStatusLine, e:
	  print e.line, e.message
	  pass
	
    else:
      print colors.BGRED + "(x) Error: You must specify the target URL." + colors.RESET + "\n"
      sys.exit(0)
      
   #Check if defined "--proxy" option.
    if menu.options.proxy:
      proxy.do_check(url)

    # Launch injection and exploitation controller.
    controller.do_check(url)
    
  except (KeyboardInterrupt, SystemExit): 
    print ""
    sys.exit(0)
    
if __name__ == '__main__':
    main()
    
#eof
