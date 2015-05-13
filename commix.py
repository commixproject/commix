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
import random
import httplib
import urllib2
import urlparse

from src.utils import menu
from src.utils import colors
from src.utils import update
from src.utils import version
from src.utils import install
from src.utils import settings

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

    #Check if specified wrong injection technique
    if menu.options.tech and menu.options.tech not in settings.AVAILABLE_TECHNIQUES:
      print colors.BGRED + "(x) Error: Specified wrong injection technique!" + colors.RESET
      sys.exit(0)

    #Check if specified wrong alternative shell
    if menu.options.alter_shell.lower() not in settings.AVAILABLE_SHELLS:
      print colors.BGRED + "(x) Error: '" + menu.options.alter_shell + "' shell is not supported!" + colors.RESET
      sys.exit(0)

    #Check if defined "--random-agent" option.
    if menu.options.random_agent:
      menu.options.agent = random.choice(settings.USER_AGENT_LIST)
      
    #Check if defined "--url" option.
    if menu.options.url:
      sys.stdout.write("(*) Checking connection to the target URL... ")
      sys.stdout.flush()
      url = menu.options.url

      # If URL not starts with any URI scheme, add "http://"
      if not urlparse.urlparse(url).scheme:
	url = "http://" + url

      try:
	request = urllib2.Request(url)
	#Check if defined extra headers.
	headers.do_check(request)
	response = urllib2.urlopen(request)
	content = response.read()
	print "[ " + colors.GREEN + "SUCCEED" + colors.RESET + " ]"
	  
      except urllib2.HTTPError, e:
	print "[ " + colors.RED + "FAILED" + colors.RESET + " ]"
	if e.getcode() == 500:
	  content = e.read()
	  sys.exit(0)

	elif e.getcode() == 401:
	  if menu.options.auth_type != "basic":
	    print colors.BGRED + "(x) Error: Only 'Basic' Access Authentication is supported." + colors.RESET
	    sys.exit(0)
	  else:
	    print colors.BGRED + "(x) Error: Authorization required!" + colors.RESET + "\n"
	    sys.exit(0)
	  
	elif e.getcode() == 403:
	  print colors.BGRED + "(x) Error: You don't have permission to access this page." + colors.RESET + "\n"
	  sys.exit(0)
	  
	elif e.getcode() == 404:
	  print colors.BGRED + "(x) Error: The host seems to be down!" + colors.RESET + "\n"
	  sys.exit(0)

	else:
	  raise

      except urllib2.URLError, e:
	  print "[ " + colors.RED + "FAILED" + colors.RESET + " ]"
	  print colors.BGRED + "(x) Error: The host seems to be down!" + colors.RESET + "\n"
	  sys.exit(0)
	
      except httplib.BadStatusLine, e:
	  print "[ " + colors.RED + "FAILED" + colors.RESET + " ]"
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
