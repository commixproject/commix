#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2022 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
 
For more see the file 'readme/COPYING' for copying permission.
"""

import re
import sys
import errno
import base64
try:
  from base64 import encodebytes
except ImportError: 
  from base64 import encodestring as encodebytes
from src.utils import menu
from src.utils import settings
from src.utils import common
from socket import error as SocketError
from src.thirdparty.six.moves import http_client as _http_client
from src.core.injections.controller import checks
from src.thirdparty.six.moves import input as _input
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.colorama import Fore, Back, Style, init


def do_check(request, url):
  """
  This functinality is based on Filippo's Valsorda script [1].
  ---
  [1] https://gist.github.com/FiloSottile/2077115
  """
  class Request(_urllib.request.Request):
    def get_method(self):
        return settings.HTTPMETHOD.HEAD

  class RedirectHandler(_urllib.request.HTTPRedirectHandler, object):
    """
    Subclass the HTTPRedirectHandler to make it use our 
    Request also on the redirected URL
    """
    def redirect_request(self, request, fp, code, msg, headers, newurl): 
      if code in (301, 302, 303, 307):
        settings.REDIRECT_CODE = code
        return Request(newurl.replace(' ', '%20'), 
                       data=request.data, 
                       headers=request.headers
                       )
      else: 
        err_msg = str(_urllib.error.HTTPError(request.get_full_url(), code, msg, headers, fp)).replace(": "," (")
        print(settings.print_critical_msg(err_msg + ")."))
        raise SystemExit()
  
  opener = _urllib.request.build_opener(RedirectHandler())
  try:
    response = opener.open(request, timeout=settings.TIMEOUT)
    if url == response.geturl():
      return response.geturl()
    else:
      while True:
        if not settings.FOLLOW_REDIRECT:
          if settings.CRAWLED_URLS_NUM != 0 and settings.CRAWLED_SKIPPED_URLS_NUM != 0:
            print(settings.SINGLE_WHITESPACE)
          message = "Got a " + str(settings.REDIRECT_CODE) + " redirect to " + response.geturl() + "\n"
          message += "Do you want to follow the identified redirection? [Y/n] > "
          redirection_option = common.read_input(message, default="Y", check_batch=True) 
        if redirection_option in settings.CHOICE_YES:
          settings.FOLLOW_REDIRECT = True
          if not settings.CRAWLING:
            info_msg = "Following redirection to '" + response.geturl() + "'. "
            print(settings.print_info_msg(info_msg))
          return checks.check_http_s(response.geturl())
        elif redirection_option in settings.CHOICE_NO:
          return url  
        elif redirection_option in settings.CHOICE_QUIT:
          raise SystemExit()
        else:
          common.invalid_option(redirection_option)  
          pass

  except (SocketError, _urllib.error.HTTPError, _urllib.error.URLError, _http_client.BadStatusLine, _http_client.InvalidURL) as err_msg:
    if settings.VALID_URL: 
      checks.connection_exceptions(err_msg, request)
    else:
      pass

  except AttributeError:
    pass


# eof