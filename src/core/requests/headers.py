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

import re
import sys
import base64
import urllib2

from src.utils import menu
from src.utils import settings
from src.core.injections.controller import checks
from src.thirdparty.colorama import Fore, Back, Style, init

"""
 Check for added headers.
"""
def do_check(request):
  
  # Check if defined any HTTP Host header.
  if menu.options.host:
    Host = menu.options.host
    request.add_header('Host', Host)
    
  # Check if defined any HTTP Referer header.
  if menu.options.referer and settings.REFERER_INJECTION == False:
    Referer = menu.options.referer
    request.add_header('Referer', Referer)
    
  # Check if defined any HTTP User-Agent header.
  if menu.options.agent and settings.USER_AGENT_INJECTION == False:
    Agent = menu.options.agent
    request.add_header('User-Agent', Agent)
    
  # Check if defined any HTTP Cookie header.
  if menu.options.cookie and settings.COOKIE_INJECTION == False:
    Cookie = menu.options.cookie
    request.add_header('Cookie', Cookie)

  # Check if defined any HTTP Authentication credentials.
  # HTTP Authentication: Basic / Digest Access Authentication.
  if not menu.options.ignore_401:
    if menu.options.auth_cred and menu.options.auth_type:
      try:
        settings.SUPPORTED_HTTP_AUTH_TYPES.index(menu.options.auth_type)
        if menu.options.auth_type == "basic":
          b64_string = base64.encodestring(menu.options.auth_cred).replace('\n', '')
          request.add_header("Authorization", "Basic " + b64_string + "")
        elif menu.options.auth_type == "digest":
          try:
            url = menu.options.url
            try:
              response = urllib2.urlopen(url)
            except urllib2.HTTPError, e:
              try:
                authline = e.headers.get('www-authenticate', '')  
                authobj = re.match('''(\w*)\s+realm=(.*),''',authline).groups()
                realm = authobj[1].split(',')[0].replace("\"","")
                user_pass_pair = menu.options.auth_cred.split(":")
                username = user_pass_pair[0]
                password = user_pass_pair[1]
                authhandler = urllib2.HTTPDigestAuthHandler()
                authhandler.add_password(realm, url, username, password)
                opener = urllib2.build_opener(authhandler)
                urllib2.install_opener(opener)
                result = urllib2.urlopen(url)
              except AttributeError:
                pass
          except urllib2.HTTPError, e:
            pass
      except ValueError:
        err_msg = "Unsupported / Invalid HTTP authentication type '" + menu.options.auth_type + "'."
        err_msg += " Try basic or digest HTTP authentication type."
        print settings.print_error_msg(err_msg)
        sys.exit(0)   
    else:
      pass        
    
  # The MIME media type for JSON.
  if settings.IS_JSON:
  	request.add_header("Content-Type", "application/json")

  # Check if defined any extra HTTP headers.
  if menu.options.headers:
    # Do replacement with the 'INJECT_HERE' tag, if the wildcard char is provided.
    menu.options.headers = checks.wildcard_character(menu.options.headers)
    extra_headers = menu.options.headers
    extra_headers = extra_headers.split(":")
    extra_headers = ':'.join(extra_headers)
    extra_headers = extra_headers.split("\\n")
    # Remove empty strings
    extra_headers = [x for x in extra_headers if x]
    for extra_header in extra_headers:
      # Extra HTTP Header name 
      http_header_name = re.findall(r"(.*):", extra_header)
      http_header_name = ''.join(http_header_name)
      # Extra HTTP Header value
      http_header_value = re.findall(r":(.*)", extra_header)
      http_header_value = ''.join(http_header_value)
      # Check if it is a custom header injection.
      if not settings.CUSTOM_HEADER_INJECTION and \
         settings.INJECT_TAG in http_header_value:
        settings.CUSTOM_HEADER_INJECTION = True
        settings.CUSTOM_HEADER_NAME = http_header_name
      request.add_header(http_header_name, http_header_value)

#eof
