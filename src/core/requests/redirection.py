#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2019 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
 
For more see the file 'readme/COPYING' for copying permission.
"""

import sys
import urllib2
from src.utils import menu
from src.utils import settings
from src.thirdparty.colorama import Fore, Back, Style, init

def do_check(url):
  """
  This functinality is based on Filippo's Valsorda script [1].
  ---
  [1] https://gist.github.com/FiloSottile/2077115
  """
  class Request(urllib2.Request):
    def get_method(self):
        return "GET"

  class RedirectHandler(urllib2.HTTPRedirectHandler):
    """
    Subclass the HTTPRedirectHandler to make it use our 
    Request also on the redirected URL
    """
    def redirect_request(self, req, fp, code, msg, headers, redirected_url): 
      if code in (301, 302, 303, 307):
        redirected_url = redirected_url.replace(' ', '%20') 
        newheaders = dict((k,v) for k,v in req.headers.items() if k.lower() not in ("content-length", "content-type"))
        warn_msg = "Got a " + str(code) + " redirection (" + redirected_url + ")."
        print settings.print_warning_msg(warn_msg)
        return Request(redirected_url, 
                           headers = newheaders,
                           origin_req_host = req.get_origin_req_host(), 
                           unverifiable = True
                           ) 
      else: 
        err_msg = str(urllib2.HTTPError(req.get_full_url(), code, msg, headers, fp)).replace(": "," (")
        print settings.print_critical_msg(err_msg + ").")
        raise SystemExit()
              
  class HTTPMethodFallback(urllib2.BaseHandler):
    """
    """
    def http_error_405(self, req, fp, code, msg, headers): 
      fp.read()
      fp.close()
      newheaders = dict((k,v) for k,v in req.headers.items() if k.lower() not in ("content-length", "content-type"))
      return self.parent.open(urllib2.Request(req.get_full_url(), 
                              headers = newheaders, 
                              origin_req_host = req.get_origin_req_host(), 
                              unverifiable = True)
                              )

  # Build our opener
  opener = urllib2.OpenerDirector() 
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

  for handler in [urllib2.HTTPHandler,
                  HTTPMethodFallback,
                  RedirectHandler,
                  urllib2.HTTPErrorProcessor, 
                  urllib2.HTTPSHandler]:
      opener.add_handler(handler())   

  try:
    response = opener.open(Request(url))
    redirected_url = response.geturl()
    if redirected_url != url:
      while True:
        if not menu.options.batch:
          question_msg = "Do you want to follow the identified redirection? [Y/n] > "
          sys.stdout.write(settings.print_question_msg(question_msg))
          redirection_option = sys.stdin.readline().replace("\n","").lower()
        else:
          redirection_option = ""  
        if len(redirection_option) == 0 or redirection_option in settings.CHOICE_YES:
          if menu.options.batch:
            info_msg = "Following redirection to '" + redirected_url + "'. "
            print settings.print_info_msg(info_msg)
          return redirected_url
        elif redirection_option in settings.CHOICE_NO:
          return url  
        elif redirection_option in settings.CHOICE_QUIT:
          raise SystemExit()
        else:
          err_msg = "'" + redirection_option + "' is not a valid answer."  
          print settings.print_error_msg(err_msg)
          pass
    else:
      return url

  except AttributeError:
    pass

  # Raise exception due to ValueError.
  except ValueError, err:
    err_msg = str(err).replace(": "," (")
    print settings.print_critical_msg(err_msg + ").")
    raise SystemExit()

  # Raise exception regarding urllib2 HTTPError.
  except urllib2.HTTPError, err:
    err_msg = str(err).replace(": "," (")
    print settings.print_critical_msg(err_msg + ").")
    raise SystemExit()

  # The target host seems to be down.
  except urllib2.URLError, err:
    err_msg = "The host seems to be down"
    try:
      err_msg += " (" + str(err.args[0]).split("] ")[1] + ")."
    except IndexError:
      err_msg += "."
    print settings.print_critical_msg(err_msg)
    raise SystemExit()

  # Raise exception regarding infinite loop.
  except RuntimeError:
    err_msg = "Infinite redirect loop detected." 
    err_msg += "Please check all provided parameters and/or provide missing ones."
    print settings.print_critical_msg(err_msg)
    raise SystemExit() 

  # Raise exception regarding connection aborted.
  except Exception:
    err_msg = "Connection aborted."
    print settings.print_critical_msg(err_msg)
    raise SystemExit()
  
# eof