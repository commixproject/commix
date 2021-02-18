#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2021 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
 
For more see the file 'readme/COPYING' for copying permission.
"""

import sys
import errno
import base64
try:
  from base64 import encodebytes
except ImportError: 
  from base64 import encodestring as encodebytes
from src.utils import menu
from src.utils import settings
from socket import error as SocketError
from src.thirdparty.six.moves import input as _input
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.colorama import Fore, Back, Style, init


def do_check(url):
  """
  This functinality is based on Filippo's Valsorda script [1].
  ---
  [1] https://gist.github.com/FiloSottile/2077115
  """
  class Request(_urllib.request.Request):
    def get_method(self):
        return "GET"

  class RedirectHandler(_urllib.request.HTTPRedirectHandler):
    """
    Subclass the HTTPRedirectHandler to make it use our 
    Request also on the redirected URL
    """
    def redirect_request(self, req, fp, code, msg, headers, redirected_url): 
      if code in (301, 302, 303, 307):
        redirected_url = redirected_url.replace(' ', '%20') 
        newheaders = dict((k,v) for k,v in req.headers.items() if k.lower() not in ("content-length", "content-type"))
        warn_msg = "Got a " + str(code) + " redirection (" + redirected_url + ")."
        print(settings.print_warning_msg(warn_msg))
        return Request(redirected_url, 
                           headers = newheaders,
                           # origin_req_host = req.get_origin_req_host(), 
                           unverifiable = True
                           ) 
      else: 
        err_msg = str(_urllib.error.HTTPError(req.get_full_url(), code, msg, headers, fp)).replace(": "," (")
        print(settings.print_critical_msg(err_msg + ")."))
        raise SystemExit()
              
  class HTTPMethodFallback(_urllib.request.BaseHandler):
    """
    """
    def http_error_405(self, req, fp, code, msg, headers): 
      fp.read()
      fp.close()
      newheaders = dict((k,v) for k,v in req.headers.items() if k.lower() not in ("content-length", "content-type"))
      return self.parent.open(_urllib.request.Request(req.get_full_url(), 
                              headers = newheaders, 
                              # origin_req_host = req.get_origin_req_host(), 
                              unverifiable = True)
                              )

  # Build our opener
  opener = _urllib.request.OpenerDirector() 
  # Check if defined any Host HTTP header.
  if menu.options.host and settings.HOST_INJECTION == False:
    opener.addheaders.append(('Host', menu.options.host))
  # Check if defined any User-Agent HTTP header.
  if menu.options.agent:
    opener.addheaders.append(('User-Agent', menu.options.agent))
  # Check if defined any Referer HTTP header.
  if menu.options.referer and settings.REFERER_INJECTION == False:
    opener.addheaders.append(('Referer', menu.options.referer))
  # Check if defined any Cookie HTTP header.
  if menu.options.cookie and settings.COOKIE_INJECTION == False:
    opener.addheaders.append(('Cookie', menu.options.cookie))
  # Check if defined any HTTP Authentication credentials.
  # HTTP Authentication: Basic / Digest Access Authentication.
  if menu.options.auth_cred and menu.options.auth_type:
    try:
      settings.SUPPORTED_HTTP_AUTH_TYPES.index(menu.options.auth_type)
      if menu.options.auth_type == "basic":
        b64_string = encodebytes(menu.options.auth_cred.encode(settings.UNICODE_ENCODING)).decode().replace('\n', '')
        opener.addheaders.append(("Authorization", "Basic " + b64_string + ""))
      elif menu.options.auth_type == "digest":
        try:
          url = menu.options.url
          try:
            response = _urllib.request.urlopen(url, timeout=settings.TIMEOUT)
          except _urllib.error.HTTPError as e:
            try:
              authline = e.headers.get('www-authenticate', '')  
              authobj = re.match('''(\w*)\s+realm=(.*),''',authline).groups()
              realm = authobj[1].split(',')[0].replace("\"","")
              user_pass_pair = menu.options.auth_cred.split(":")
              username = user_pass_pair[0]
              password = user_pass_pair[1]
              authhandler = _urllib.request.HTTPDigestAuthHandler()
              authhandler.add_password(realm, url, username, password)
              opener = _urllib.request.build_opener(authhandler)
              _urllib.request.install_opener(opener)
              result = _urllib.request.urlopen(url, timeout=settings.TIMEOUT)
            except AttributeError:
              pass
        except _urllib.error.HTTPError as e:
          pass
    except ValueError:
      err_msg = "Unsupported / Invalid HTTP authentication type '" + menu.options.auth_type + "'."
      err_msg += " Try basic or digest HTTP authentication type."
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()   
  else:
    pass  

  for handler in [_urllib.request.HTTPHandler,
                  HTTPMethodFallback,
                  RedirectHandler,
                  _urllib.request.HTTPErrorProcessor, 
                  _urllib.request.HTTPSHandler]:
      opener.add_handler(handler())   

  try:
    # Return a Request or None in response to a redirect.
    response = opener.open(Request(url))
    if response == None:
      return url
    else:
      redirected_url = response.geturl()
      if redirected_url != url:
        while True:
          if not menu.options.batch:
            question_msg = "Do you want to follow the identified redirection? [Y/n] > "
            redirection_option = _input(settings.print_question_msg(question_msg))
          else:
            redirection_option = ""  
          if len(redirection_option) == 0 or redirection_option in settings.CHOICE_YES:
            if menu.options.batch:
              info_msg = "Following redirection to '" + redirected_url + "'. "
              print(settings.print_info_msg(info_msg))
            return redirected_url
          elif redirection_option in settings.CHOICE_NO:
            return url  
          elif redirection_option in settings.CHOICE_QUIT:
            raise SystemExit()
          else:
            err_msg = "'" + redirection_option + "' is not a valid answer."  
            print(settings.print_error_msg(err_msg))
            pass
      else:
        return url

  except AttributeError:
    pass

  # Raise exception due to ValueError.
  except ValueError as err:
    err_msg = str(err).replace(": "," (")
    print(settings.print_critical_msg(err_msg + ")."))
    raise SystemExit()

  # Raise exception regarding urllib2 HTTPError.
  except _urllib.error.HTTPError as err:
    err_msg = str(err).replace(": "," (")
    print(settings.print_critical_msg(err_msg + ")."))
    raise SystemExit()

  # The target host seems to be down.
  except _urllib.error.URLError as err:
    err_msg = "The host seems to be down"
    try:
      err_msg += " (" + str(err.args[0]).split("] ")[-1] + ")."
    except IndexError:
      err_msg += "."
    print(settings.print_critical_msg(err_msg))
    raise SystemExit()

  # Raise exception regarding infinite loop.
  except RuntimeError:
    err_msg = "Infinite redirect loop detected." 
    err_msg += "Please check all provided parameters and/or provide missing ones."
    print(settings.print_critical_msg(err_msg))
    raise SystemExit() 

  # Raise exception regarding existing connection was forcibly closed by the remote host.
  except SocketError as err:
    if err.errno == errno.ECONNRESET:
      error_msg = "Connection reset by peer."
      print(settings.print_critical_msg(error_msg))
    elif err.errno == errno.ECONNREFUSED:
      error_msg = "Connection refused."
      print(settings.print_critical_msg(error_msg))
    raise SystemExit()

  # Raise exception regarding connection aborted.
  except Exception:
    err_msg = "Connection aborted."
    print(settings.print_critical_msg(err_msg))
    raise SystemExit()

# eof