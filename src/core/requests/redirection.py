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

from src.utils import settings
from src.utils import common
from src.core.controller import checks
from src.thirdparty.six.moves import urllib as _urllib

class Request(_urllib.request.Request):
  # A request that keeps the method it was made with, whatever a redirect asks for.
  def __init__(self, *args, method=None, **kwargs):
    self._method = method
    _urllib.request.Request.__init__(self, *args, **kwargs)

  # The method this request was made with.
  def get_method(self):
    return self._method or _urllib.request.Request.get_method(self)

class RedirectHandler(_urllib.request.HTTPRedirectHandler, object):
  """
  Subclass the HTTPRedirectHandler to make it use our
  Request also on the redirected URL
  """
  def redirect_request(self, request, fp, code, msg, headers, newurl):
    if code in (301, 302, 303, 307, 308):
      settings.REDIRECT_CODE = code
      if not settings.FOLLOW_REDIRECT:
        # Not following a redirect is our own decision to remember, not one the user asked for.
        settings.WARNED_HTTP_ERROR_CODES.add(int(code))
        return None
      target = newurl.replace(' ', '%20')
      carried = dict(request.headers)
      """
      Anything that authenticates the request to the host it was made to is dropped where the
      redirect leaves that host. A redirect is the target's to choose, so following one with the
      credentials still attached would hand them to whichever host it named.
      """
      if _urllib.parse.urlparse(target).netloc != _urllib.parse.urlparse(request.get_full_url()).netloc:
        for header in list(carried):
          if header.lower().replace("-", "") in ("authorization", "proxyauthorization", "cookie"):
            del carried[header]
      # Preserve the original method, not HEAD - except on 303, which asks for GET by definition.
      if code == 303 and request.get_method() != "HEAD":
        return Request(target, data=None, headers=carried, method="GET")
      return Request(target,
                     data=request.data,
                     headers=carried,
                     method=request.get_method()
                     )
    else:
      err_msg = str(_urllib.error.HTTPError(request.get_full_url(), code, msg, headers, fp)).replace(": "," (")
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg + ")."))
      raise SystemExit()

def do_check(url, redirect_url):
  """
  This functinality is based on Filippo's Valsorda script [1].
  ---
  [1] https://gist.github.com/FiloSottile/2077115
  """
  # settings.REDIRECT_CODE is already set by the caller's own request - no need to resend it here.
  try:
    if (not settings.REDIRECT_CODE) or (settings.CRAWLING and redirect_url in settings.HREF_SKIPPED):
      return redirect_url
    elif settings.CRAWLING and url in settings.HREF_SKIPPED:
      return url
    else:
      while True:
        if not settings.FOLLOW_REDIRECT:
          if settings.CRAWLED_URLS_NUM != 0 and settings.CRAWLED_SKIPPED_URLS_NUM != 0:
            settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
        message = "Got a " + str(settings.REDIRECT_CODE) + " redirect to '" + redirect_url
        message += "'. Do you want to follow? [Y/n] "
        redirection_option = common.read_input(message, default="Y", check_batch=True)
        if redirection_option in settings.CHOICE_YES:
          settings.FOLLOW_REDIRECT = True
          info_msg = "Following redirection to '" + redirect_url + "'. "
          settings.print_data_to_stdout(settings.print_info_msg(info_msg))
          if settings.CRAWLING:
            settings.HREF_SKIPPED.append(url)
          return checks.check_http_s(redirect_url)
        elif redirection_option in settings.CHOICE_NO:
          settings.FOLLOW_REDIRECT = False
          if settings.CRAWLING:
            settings.HREF_SKIPPED.append(url)
          return url
        elif redirection_option in settings.CHOICE_QUIT:
          raise SystemExit()
        else:
          common.invalid_option(redirection_option)
          pass

  except AttributeError:
    return url


# eof
