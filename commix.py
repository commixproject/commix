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

import re
import os
import sys
import random
import httplib
import urllib2
import urlparse
# Disable SSL verification.
# For python versions 2.7.9 or above.
import ssl
try:
  _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
  # Legacy Python that doesn't verify HTTPS certificates by default
  pass
else:
  # Handle target environment that doesn't support HTTPS verification
  ssl._create_default_https_context = _create_unverified_https_context

from src.utils import menu
from src.utils import logs
from src.utils import update
from src.utils import version
from src.utils import install
from src.utils import settings

from src.thirdparty.colorama import Fore, Back, Style, init

from src.core.requests import tor
from src.core.requests import proxy
from src.core.requests import headers
from src.core.injections import controller

"""
 The main function.
"""

# use Colorama to make Termcolor work on Windows too :)
if settings.IS_WINDOWS:
  init()



def main():

  try:
    # Checkall the banner
    menu.banner()
        
    # Check python version number.
    version.python_version()
    
    # Check if defined "--version" option.
    if menu.options.version:
      version.show_version()
      sys.exit(0)
        
    # Check if defined "--update" option.        
    if menu.options.update:
      update.updater()
      sys.exit(0)
        
    # Check if defined "--install" option.        
    if menu.options.install:
      install.installer()
      sys.exit(0)
    
    # Check arguments
    if len(sys.argv) == 1:
      menu.parser.print_help()
      print ""
      sys.exit(0)

    # Check if defined character used for splitting parameter values.
    if menu.options.pdel:
     settings.PARAMETER_DELIMITER = menu.options.pdel

    # Check if defined character used for splitting cookie values.
    if menu.options.cdel:
     settings.COOKIE_DELIMITER = menu.options.cdel

    # Check if specified wrong injection technique
    if menu.options.tech and menu.options.tech not in settings.AVAILABLE_TECHNIQUES:
      found_tech = False
      # Convert injection technique(s) to lowercase
      menu.options.tech = menu.options.tech.lower()
      # Check if used the ',' separator
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
            print Back.RED + "(x) Error: You specified wrong '" + split_techniques_names[i] + "' injection technique." + Style.RESET_ALL
            print Back.RED + "(x) The available techniques are: classic,eval-based,time-based,file-based or c,e,t,f (with or without commas)." + Style.RESET_ALL
            sys.exit(0)

    # Cookie Injection
    if menu.options.cookie and settings.INJECT_TAG in menu.options.cookie:
      settings.COOKIE_INJECTION = True

    # User-Agent Injection
    if menu.options.agent and settings.INJECT_TAG in menu.options.agent:
      settings.USER_AGENT_INJECTION = True

    # Referer Injection
    if menu.options.referer and settings.INJECT_TAG in menu.options.referer:
      settings.REFERER_INJECTION = True

    # Check if specified wrong alternative shell
    if menu.options.alter_shell:
      if menu.options.alter_shell.lower() not in settings.AVAILABLE_SHELLS:
        print Back.RED + "(x) Error: '" + menu.options.alter_shell + "' shell is not supported!" + Style.RESET_ALL
        sys.exit(0)

    # Check if defined "--file-upload" option.
    if menu.options.file_upload:

      # Check if not defined URL for upload.
      if not re.match(settings.VALID_URL_FORMAT, menu.options.file_upload):
        sys.stdout.write(Back.RED + "(x) Error: The '"+ menu.options.file_upload + "' is not a valid URL. " + Style.RESET_ALL + "\n")
        sys.stdout.flush()
        sys.exit(0)

    # Check if specified file-access options
    # Check if not defined "--file-dest" option.
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
      print Back.RED + "(x) Error: You must enter the '--file-write' or '--file-upload' parameter." + Style.RESET_ALL
      sys.exit(0)
        
    # Check if defined "--random-agent" option.
    if menu.options.random_agent:
      menu.options.agent = random.choice(settings.USER_AGENT_LIST)
            
    # Check if defined "--url" option.
    if menu.options.url:

      sys.stdout.write("(*) Checking connection to the target URL... ")
      sys.stdout.flush()
      url = menu.options.url
      
      # If URL not starts with any URI scheme, add "http://"
      if not urlparse.urlparse(url).scheme:
        url = "http://" + url

      if menu.options.output_dir:
        output_dir = menu.options.output_dir
      else:
        output_dir = settings.OUTPUT_DIR
      dir = os.path.dirname(output_dir)
      try:
        os.stat(output_dir)
      except:
        os.mkdir(output_dir)   

      # The logs filename construction.
      filename = logs.create_log_file(url, output_dir)

      try:
        request = urllib2.Request(url)
        # Check if defined extra headers.
        headers.do_check(request)
        response = urllib2.urlopen(request)
        html_data = response.read()

        content = response.read()
        print "[ " + Fore.GREEN + "SUCCEED" + Style.RESET_ALL + " ]"

        if response.info()['server'] :
          server_banner = response.info()['server']
        found_server_banner = False
        for i in range(0,len(settings.SERVER_BANNERS)):
          if settings.SERVER_BANNERS[i].lower() in server_banner.lower():
            if menu.options.verbose:
              print Style.BRIGHT + "(!) The server was identified as " + Style.UNDERLINE + server_banner + Style.RESET_ALL + "." + Style.RESET_ALL
            settings.SERVER_BANNER = server_banner
            found_server_banner = True
            break

        if found_server_banner != True:
          print  Fore.YELLOW + "(^) Warning: The server which was identified as " + server_banner + " seems unknown." + Style.RESET_ALL

        # Charset detection [1].
        # [1] http://www.w3schools.com/html/html_charset.asp
        # Check if HTML4 format
        content = re.findall(r";charset=(.*)\"", html_data)
        if len(content) != 0 :
          charset = content
        else:
           # Check if HTML5 format
          charset = re.findall(r"charset=['\"](.*)['\"]", html_data)
        if len(charset) != 0 :
          settings.CHARSET = charset[len(charset)-1]
          if settings.CHARSET.lower() not in settings.CHARSET_LIST:
            print  Fore.YELLOW + "(^) Warning: The indicated web-page charset "  + settings.CHARSET + " seems unknown." + Style.RESET_ALL
          else:
            if menu.options.verbose:
              print Style.BRIGHT + "(!) The indicated web-page charset appears to be "  + Style.UNDERLINE  + settings.CHARSET + Style.RESET_ALL + "." + Style.RESET_ALL

        # Check if defined "--tor" option.
        if menu.options.tor:
          tor.do_check()

      except urllib2.HTTPError, e:
        print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"

        # Check the codes of responses
        if e.getcode() == 500:
          content = e.read()
          sys.exit(0)

        elif e.getcode() == 401:
          if menu.options.auth_type != "basic":
            print Back.RED + "(x) Error: Only 'Basic' Access Authentication is supported." + Style.RESET_ALL
            sys.exit(0)
          else:
            print Back.RED + "(x) Error: Authorization required!" + Style.RESET_ALL + "\n"
            sys.exit(0)
          
        elif e.getcode() == 403:
          print Back.RED + "(x) Error: You don't have permission to access this page." + Style.RESET_ALL + "\n"
          sys.exit(0)
          
        elif e.getcode() == 404:
          print Back.RED + "(x) Error: The host seems to be down!" + Style.RESET_ALL + "\n"
          sys.exit(0)

        else:
          raise

      except urllib2.URLError, e:
          print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"
          print Back.RED + "(x) Error: The host seems to be down!" + Style.RESET_ALL + "\n"
          sys.exit(0)
        
      except httplib.BadStatusLine, e:
          print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"
          print e.line, e.message
          pass
        
    else:
      print Back.RED + "(x) Error: You must specify the target URL." + Style.RESET_ALL + "\n"
      sys.exit(0)

    # Check if defined "--proxy" option.
    if menu.options.proxy:
      proxy.do_check(url)

    # Launch injection and exploitation controller.
    controller.do_check(url, filename)

  except KeyboardInterrupt: 
    print "\n" + Back.RED + "(x) Aborted: Ctrl-C was pressed!" + Style.RESET_ALL
    if settings.SHOW_LOGS_MSG == True:
      logs.logs_notification(filename)
      print ""
    sys.exit(0)

  except SystemExit: 
    print ""
    sys.exit(0)
  
  # Accidental stop / restart of the target host server.
  except httplib.BadStatusLine, e:
    if e.line == "" or e.message == "":
      print "\n" + Back.RED + "(x) Error: The target host is not responding." + \
            " Ensure that host is up and running and try again." + Style.RESET_ALL + "\n"
    else: 
      print Back.RED + "(x) Error: " + e.line + e.message + Style.RESET_ALL
    sys.exit(0)

if __name__ == '__main__':
    main()
    
#eof
