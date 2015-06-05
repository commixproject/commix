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

import os
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
      found_tech = False
      #Check if used the ',' separator
      if "," in menu.options.tech:
        split_techniques_names = menu.options.tech.split(",")
      else:
        split_techniques_names = menu.options.tech.split()
      if split_techniques_names:
        for i in range(0,len(split_techniques_names)):
          if len(menu.options.tech) <= 4:
            split_first_letter = list(menu.options.tech)
            for j in range(0,len(split_first_letter)):
              if split_first_letter[j] in settings.AVAILABLE_TECHNIQUES:
                found_tech = True
          if split_techniques_names[i].replace(' ', '') not in settings.AVAILABLE_TECHNIQUES and found_tech == False:
            print colors.BGRED + "(x) Error: You specified wrong '" + split_techniques_names[i] + "' injection technique." + colors.RESET
            print colors.BGRED + "(x) The available techniques are: classic,eval-based,time-based,file-based or c,e,t,f (with or without commas)." + colors.RESET
            sys.exit(0)

    #Check if specified wrong alternative shell
    if menu.options.alter_shell:
      if menu.options.alter_shell.lower() not in settings.AVAILABLE_SHELLS:
        print colors.BGRED + "(x) Error: '" + menu.options.alter_shell + "' shell is not supported!" + colors.RESET
        sys.exit(0)

    # Check if specified file-access options
    #Check if not defined "--file-dest" option.
    if menu.options.file_dest == None:
      
      # Check if defined "--file-write" option.
      if menu.options.file_write:
        file_name = os.path.split(menu.options.file_write)[1]
        menu.options.file_dest = settings.SRV_ROOT_DIR + file_name
        
      # Check if defined "--file-upload" option.
      if menu.options.file_upload:
        file_name = os.path.split(menu.options.file_upload)[1]
        menu.options.file_dest = settings.SRV_ROOT_DIR + file_name
        
    elif menu.options.file_dest and menu.options.file_write == None and menu.options.file_upload == None :
      print colors.BGRED + "(x) Error: You must enter the '--file-write' or '--file-upload' parameter." + colors.RESET
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

        # Check the codes of responses
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
