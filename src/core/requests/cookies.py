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
import re
import time
from src.core.parse import cmdline as menu
from src.utils import common
from src.utils import settings

"""
Read a cookies file, the way a browser or a helper tool leaves it behind.
"""
def _read_cookies_file(cookies_file):
  try:
    with open(cookies_file, encoding=settings.DEFAULT_CODEC, errors="replace") as file:
      return file.read()
  except IOError as err_msg:
    err_msg = "There was a problem reading the cookies file '" + cookies_file + "' (" + str(err_msg) + ")."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

"""
Turn the Netscape/wget cookie format into the value of a Cookie HTTP header. Every line holds seven
tab-separated fields, of which the last two are the name and the value that the target asked for.
"""
def _parse_netscape_format(content):
  cookies = []
  # The prefix marks a cookie the browser keeps from scripts, which says nothing about sending it.
  content = re.sub("(?im)^#httpOnly_", "", content)
  for line in content.splitlines():
    line = line.strip()
    if not line or line.startswith("#"):
      continue
    fields = line.split("\t")
    if len(fields) == 7 and fields[5]:
      cookies.append(fields[5] + "=" + fields[6])
  return (settings.COOKIE_PARAM_DELIMITER + settings.SINGLE_WHITESPACE).join(cookies)

"""
Load the cookies of a Netscape/wget file, as given with the '--load-cookies' option.
"""
def load_cookies():
  content = _read_cookies_file(menu.options.load_cookies)
  cookie = _parse_netscape_format(content)
  if not cookie:
    err_msg = "No valid cookies found in the '" + menu.options.load_cookies + "' file."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()
  info_msg = "Loading cookies from the '" + os.path.split(menu.options.load_cookies)[1] + "' file. "
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  return cookie

"""
Read the cookies as they stand right now, from the file that something else keeps up to date. A
file that is not there yet is waited for, since whatever writes it may still be logging back in.
"""
def live_cookies():
  cookies_file = menu.options.live_cookies
  if not os.path.isfile(cookies_file) or os.path.getsize(cookies_file) == 0:
    warn_msg = "The live cookies file '" + cookies_file + "' is empty or does not exist. "
    warn_msg += "Waiting up to " + str(settings.LIVE_COOKIES_TIMEOUT) + " seconds for it."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    for _ in range(settings.LIVE_COOKIES_TIMEOUT):
      if os.path.isfile(cookies_file) and os.path.getsize(cookies_file) != 0:
        break
      time.sleep(1)
    else:
      err_msg = "No cookies were provided in the '" + cookies_file + "' file."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()

  content = _read_cookies_file(cookies_file).strip()
  # Either the header as it would be sent, or the tab-separated file a browser exports.
  if "\t" in content:
    return _parse_netscape_format(content)
  return re.sub(r"(?i)\A" + settings.COOKIE + r":\s*", "", content)

"""
Handle server-set cookies.
"""
def handle_server_cookies(response):

  """
  Mask the middle part of long cookie values to avoid leaking sensitive data in prompts.
  """
  def mask_cookie_value(cookie_str):
      return re.sub(
          r"(=[^=;]{10}[^=;])[^=;]+([^=;]{10})",
          r"\g<1>...\g<2>",
          cookie_str
      )

  try:
    set_cookie_header = []
    declared_cookies = set(c.split('=')[0].strip() for c in menu.options.cookie.split(settings.COOKIE_PARAM_DELIMITER)) if menu.options.cookie else set()
    added_cookies = set()
    for header, value in response.getheaders():
      if header.lower() == settings.SET_COOKIE.lower():
        _ = re.search(r'^\s*([^=;\s]+=[^;]*)', value)
        if _:
          name_value = _.group(1)
          cookie_name = name_value.split("=")[0]
          if cookie_name not in declared_cookies and cookie_name not in added_cookies:
            set_cookie_header.append(name_value)
            added_cookies.add(cookie_name)

    candidate = settings.COOKIE_PARAM_DELIMITER.join(str(value) for value in set_cookie_header)

    if candidate and settings.DECLARED_COOKIES is not False and settings.CRAWLING is False:
      settings.DECLARED_COOKIES = True
      if settings.CRAWLED_SKIPPED_URLS_NUM != 0:
        settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
      if menu.options.cookie:
        user_cookies_set = set([c.split('=')[0] for c in menu.options.cookie.split(settings.COOKIE_PARAM_DELIMITER)])
        if user_cookies_set:
          while True:
            message = "You declared some cookie(s), "
            message += "but the server is setting additional ones ('"
            message += mask_cookie_value(candidate)
            message += "'). Do you want to merge them? [Y/n] "
            merge_option = common.read_input(message, default="Y", check_batch=True)
            if merge_option in settings.CHOICE_YES:
              menu.options.cookie += settings.COOKIE_PARAM_DELIMITER + candidate
              break
            elif merge_option in settings.CHOICE_NO:
              break
            elif merge_option in settings.CHOICE_QUIT:
              raise SystemExit()
            else:
              common.invalid_option(merge_option)
              pass
        else:
          menu.options.cookie += settings.COOKIE_PARAM_DELIMITER + candidate
        settings.DECLARED_COOKIES = False
      else:
        while True:
          message = "You have not declared any cookie(s), "
          message += "but the server wants to set its own ('"
          message += mask_cookie_value(candidate)
          message += "'). Do you want to use those? [Y/n] "
          set_cookies = common.read_input(message, default="Y", check_batch=True)
          if set_cookies in settings.CHOICE_YES:
            menu.options.cookie = candidate
            break
          elif set_cookies in settings.CHOICE_NO:
            settings.DECLARED_COOKIES = False
            break
          elif set_cookies in settings.CHOICE_QUIT:
            raise SystemExit()
          else:
            common.invalid_option(set_cookies)
            pass
  except (AttributeError, KeyError, TypeError):
    pass

"""
Ignoring the Google analytics cookie parameter.
"""
def ignore_google_analytics_cookie(cookie):
  if re.search(settings.GOOGLE_ANALYTICS_COOKIE_REGEX, cookie):
    if (len(cookie.split("="))) == 2:
      info_msg = "Ignoring the Google analytics cookie parameter '" + cookie.split("=")[0] + "'."
      settings.print_data_to_stdout(settings.print_info_msg(info_msg))
    return True

# eof
