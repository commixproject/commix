#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of commix (@commixproject) tool.
Copyright (c) 2014-2016 Anastasios Stasinopoulos (@ancst).
https://github.com/stasinopoulos/commix

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
 
For more see the file 'readme/COPYING' for copying permission.
"""

import os
import sys
import time
import base64
import urllib2
import cookielib

from src.utils import menu
from src.utils import settings
from src.utils import session_handler

from src.core.requests import tor
from src.core.requests import proxy
from src.core.requests import headers


from src.core.injections.controller import checks
from src.thirdparty.colorama import Fore, Back, Style, init

"""
If a dashboard or an administration panel is found (auth_url),
do the authentication process using the provided credentials (auth_data).
"""

"""
The authentication process
"""
def authentication_process():
  auth_url = menu.options.auth_url
  auth_data = menu.options.auth_data
  cj = cookielib.CookieJar()
  opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
  request = opener.open(urllib2.Request(auth_url))

  cookies = ""
  for cookie in cj:
      cookie_values = cookie.name + "=" + cookie.value + "; "
      cookies += cookie_values

  if len(cookies) != 0 :
    menu.options.cookie = cookies.rstrip()
    if menu.options.verbose:
      print Style.BRIGHT + "(!) The received cookie is " + Style.UNDERLINE + menu.options.cookie + Style.RESET_ALL + "." + Style.RESET_ALL

  urllib2.install_opener(opener)
  request = urllib2.Request(auth_url, auth_data)

  # Check if defined extra headers.
  headers.do_check(request)

  # Check if defined any HTTP Proxy.
  if menu.options.proxy:
    try:
      response = proxy.use_proxy(request)
    except urllib2.HTTPError, err:
      if settings.IGNORE_ERR_MSG == False:
        print "\n" + Back.RED + settings.ERROR_SIGN + str(err) + Style.RESET_ALL
        continue_tests = checks.continue_tests(err)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 

  # Check if defined Tor.
  elif menu.options.tor:
    try:
      response = tor.use_tor(request)
    except urllib2.HTTPError, err:
      if settings.IGNORE_ERR_MSG == False:
        print "\n" + Back.RED + settings.ERROR_SIGN + str(err) + Style.RESET_ALL
        continue_tests = checks.continue_tests(err)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 

  else:
    try:
      response = urllib2.urlopen(request)
    except urllib2.HTTPError, err:
      if settings.IGNORE_ERR_MSG == False:
        print "\n" + Back.RED + settings.ERROR_SIGN + str(err) + Style.RESET_ALL
        continue_tests = checks.continue_tests(err)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 

  return response 

"""
Simple "Basic" HTTP Authentication cracker.
"""
def http_basic(url):
    authentication_type = "basic"
    try:
      usernames = []
      if not os.path.isfile(settings.USERNAMES_TXT_FILE):
        print Back.RED + settings.ERROR_SIGN + "The username file (" + settings.USERNAMES_TXT_FILE + ") is not found" + Style.RESET_ALL
        sys.exit(0) 
      if len(settings.USERNAMES_TXT_FILE) == 0:
        print Back.RED + settings.ERROR_SIGN + "The " + settings.USERNAMES_TXT_FILE + " file is empty."
        sys.exit(0)
      with open(settings.USERNAMES_TXT_FILE, "r") as f: 
        for line in f:
          line = line.strip()
          usernames.append(line)
    except IOError: 
      print Back.RED + settings.ERROR_SIGN + " Check if the " + settings.USERNAMES_TXT_FILE + " file is readable or corrupted."
      sys.exit(0)

    try:
      passwords = []
      if not os.path.isfile(settings.PASSWORDS_TXT_FILE):
        print Back.RED + settings.ERROR_SIGN + "The password file (" + settings.PASSWORDS_TXT_FILE + ") is not found" + Style.RESET_ALL
        sys.exit(0) 
      if len(settings.PASSWORDS_TXT_FILE) == 0:
        print Back.RED + settings.ERROR_SIGN + "The " + settings.PASSWORDS_TXT_FILE + " file is empty."
        exit()
      with open(settings.PASSWORDS_TXT_FILE, "r") as f: 
        for line in f:
          line = line.strip()
          passwords.append(line)
    except IOError: 
      print Back.RED + settings.ERROR_SIGN + " Check if the " + settings.PASSWORDS_TXT_FILE + " file is readable or corrupted."
      sys.exit(0)

    i = 1 
    found = False
    total = len(usernames) * len(passwords)   
    for username in usernames:
      for password in passwords:
        float_percent = "{0:.1f}%".format(round(((i*100)/(total*1.0)),2))
        try:
          request = urllib2.Request(url)
          base64string = base64.encodestring(username + ":" + password)[:-1]
          request.add_header("Authorization", "Basic " + base64string)   
          result = urllib2.urlopen(request)
          # Store results to session 
          admin_panel = url 
          session_handler.import_valid_credentials(url, authentication_type, admin_panel, username, password)
          found = True
        except KeyboardInterrupt :
          raise 
        except:
          pass  
        if found:
          float_percent = Fore.GREEN + "SUCCEED" + Style.RESET_ALL
        else:
          if str(float_percent) == "100.0%":
            float_percent = Fore.RED + "FAILED" + Style.RESET_ALL
          else:  
            i = i + 1
        sys.stdout.write("\r\r" + settings.INFO_SIGN + "Checking for a valid pair of credentials... [ " +  float_percent + " ]")
        sys.stdout.flush()
        if found:
          valid_pair =  "" + username + ":" + password + ""
          print Style.BRIGHT + "\n(!) Identified a valid pair of credentials '" + Style.UNDERLINE  + valid_pair + Style.RESET_ALL + Style.BRIGHT  + "'." + Style.RESET_ALL
          return valid_pair

    error_msg = "Use the '--auth-cred' option to provide a valid pair of " 
    error_msg += "HTTP authentication credentials (i.e --auth-cred=\"admin:admin\") " 
    error_msg += "or place an other dictionary into '" + os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'txt')) + "/' directory."
    print "\n" + Back.RED + settings.ERROR_SIGN + error_msg + Style.RESET_ALL  
    return False  

#eof