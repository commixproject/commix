#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of commix (@commixproject) tool.
Copyright (c) 2014-2015 Anastasios Stasinopoulos (@ancst).
https://github.com/stasinopoulos/commix

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
 
For more see the file 'readme/COPYING' for copying permission.
"""

import re
import base64
import urllib2
from src.utils import menu
from src.utils import settings
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
  # HTTP Authentication: Basic Access Authentication
  if menu.options.auth_type == "basic":
    if menu.options.auth_cred:
      b64_string = base64.encodestring(menu.options.auth_cred).replace('\n', '')
      request.add_header("Authorization", "Basic " + b64_string + "")
  
  # The MIME media type for JSON.
  if settings.IS_JSON:
  	request.add_header("Content-Type", "application/json")

  # Check if defined any extra HTTP headers.
  if menu.options.headers:
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
      request.add_header(http_header_name, http_header_value)

#eof