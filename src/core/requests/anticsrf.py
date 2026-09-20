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

import re
from src.thirdparty.six.moves import urllib as _urllib
from src.core.parse import cmdline as menu
from src.utils import settings

"""
Anti-CSRF token handling.

A target that checks a token rejects every payload before it reaches a shell, and the rejection
looks exactly like a parameter that is not injectable. So the token is fetched again before each
request and written into the one that is about to be sent.
"""

"""
Where the token may be written, in the order it is looked for - the first shape that answers wins.
"""
def _token_patterns(name):
  return (
           r"(?i)<input[^>]+\bname=[\"']?(?P<name>" + name + r")\b[^>]*\bvalue=[\"']?(?P<value>[^>'\"]*)",
           r"(?i)<input[^>]+\bvalue=[\"']?(?P<value>[^>'\"]*)[\"']?[^>]*\bname=[\"']?(?P<name>" + name + r")\b",
           r"(?P<name>" + name + r")[\"']:[\"'](?P<value>[^\"']+)",
           r"\b(?P<name>" + name + r")\s*=\s*['\"]?(?P<value>[^;'\"]+)",
           r"<meta\s+name=[\"']?(?P<name>" + name + r")[\"']?[^>]+\b(value|content)=[\"']?(?P<value>[^>\"']+)"
         )

"""
Read the token out of a page, or out of the headers that came with it.
"""
def _find_token(page, response_headers):
  name = settings.CSRF_TOKEN
  page = _urllib.parse.unquote(page or "")
  for pattern in _token_patterns(name):
    match = re.search(pattern, page, re.I)
    if match:
      break
  else:
    # A token handed back in a header of its own, rather than written into the page.
    match = re.search(r"\b(?P<name>" + name + r")\s*[:=]\s*(?P<value>\w+)", str(response_headers or ""), re.I)
  if not match:
    return None, None
  token_name, token_value = match.group("name"), match.group("value")
  # A value the page assembles character by character, rather than writing out.
  assembled = re.search(r"String\.fromCharCode\(([\d+, ]+)\)", token_value)
  if assembled:
    token_value = "".join(chr(int(_)) for _ in assembled.group(1).replace(" ", "").split(","))
  return token_name, token_value.strip("'\"")

"""
Fetch the page the token is written on, as the options describe it.
"""
def _fetch_token_page(url, http_request_method):
  from src.core.requests import headers
  token_url = menu.options.csrf_url or url
  data = menu.options.csrf_data
  if not data and menu.options.csrf_url == url and (menu.options.csrf_method or "").upper() == settings.HTTPMETHOD.POST:
    data = menu.options.data
  method = menu.options.csrf_method or (http_request_method if menu.options.csrf_url == url else None)
  if not method:
    method = settings.HTTPMETHOD.POST if data else settings.HTTPMETHOD.GET
  request = _urllib.request.Request(token_url, data.encode(settings.DEFAULT_CODEC) if data else None, method=method.upper())
  headers.do_check(request)
  response = headers.check_http_traffic(request)
  if response is None:
    response = headers.resend(request)
  if response is None or isinstance(response, bool):
    return "", None, None
  try:
    page = response.read().decode(settings.DEFAULT_CODEC, errors="replace")
  except Exception:
    page = ""
  code = getattr(response, "code", None) or getattr(response, "status", None)
  return page, getattr(response, "headers", None), code

"""
Write the token into a string of parameters, whether they are written as pairs or as JSON.

Anchored at a parameter boundary, so that a token named 'token' does not rewrite the value of
'user_token' instead.
"""
def adjust_parameter(param_string, name, value):
  if not param_string:
    return param_string
  quoted = _urllib.parse.quote(name)
  if quoted in param_string:
    name = quoted
  match = re.search(r"(?i)(?:\A|(?<=&))" + re.escape(name) + r"=[^&]*", param_string)
  if match:
    return param_string[:match.start()] + name + "=" + value + param_string[match.end():]
  match = re.search(r"(?i)[\"']" + re.escape(name) + r"[\"']\s*:\s*[\"'](?P<value>[^\"']*)", param_string)
  if match:
    return param_string[:match.start("value")] + value + param_string[match.end("value"):]
  return param_string

"""
Put a freshly fetched token into the request that is about to be sent.

The value travels wherever the parameter does: the query string, the body, a header of its own, or
the cookie - which is also where it is read from, for a target that hands it back that way.
"""
def apply_token(request):
  if not settings.CSRF_TOKEN or settings.FETCHING_CSRF_TOKEN:
    return
  settings.FETCHING_CSRF_TOKEN = True
  try:
    url = request.get_full_url()
    method = request.get_method()
    token_name = token_value = None
    for attempt in range(menu.options.csrf_retries + 1):
      page, response_headers, code = _fetch_token_page(url, method)
      token_name, token_value = _find_token(page, response_headers)
      if token_name:
        break
      # A page of its own, answering with the token and nothing else.
      if menu.options.csrf_url and menu.options.csrf_url != url and code == settings.OK_RESPONSE_CODE:
        content_type = ""
        if response_headers is not None:
          content_type = response_headers.get(settings.CONTENT_TYPE, "") or ""
        if settings.PLAIN_TEXT_CONTENT_TYPE in content_type.lower():
          token_name, token_value = settings.CSRF_TOKEN_ORIGINAL, page.strip()
          break
      if attempt < menu.options.csrf_retries:
        warn_msg = "Unable to find the anti-CSRF token '" + str(settings.CSRF_TOKEN_ORIGINAL) + "' at '"
        warn_msg += str(menu.options.csrf_url or url) + "'. Retrying the request."
        settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

    if not token_name:
      # Carried in the cookie instead, which is a token the target keeps rather than one it prints.
      if menu.options.cookie:
        match = re.search(r"(?i)(?:\A|;\s*)(?P<name>[^=;\s]*" + settings.CSRF_TOKEN + r"[^=;\s]*)=(?P<value>[^;]*)", menu.options.cookie)
        if match:
          token_name, token_value = match.group("name"), match.group("value")

    if not token_name:
      err_msg = "The anti-CSRF token '" + str(settings.CSRF_TOKEN_ORIGINAL) + "' cannot be found at '"
      err_msg += str(menu.options.csrf_url or url) + "'."
      if not menu.options.csrf_url:
        err_msg += " You can try to re-run by providing a valid value for the option '--csrf-url'."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit(settings.EXIT_FAILURE)

    if settings.VERBOSITY_LEVEL >= 2:
      debug_msg = "Using '" + token_value + "' as the value of the anti-CSRF token '" + token_name + "'."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

    parts = request.full_url.split("?", 1)
    if len(parts) == 2 and parts[1]:
      request.full_url = parts[0] + "?" + adjust_parameter(parts[1], token_name, token_value)
    if request.data:
      body = request.data.decode(settings.DEFAULT_CODEC, errors="replace")
      request.data = adjust_parameter(body, token_name, token_value).encode(settings.DEFAULT_CODEC)
    if menu.options.cookie:
      menu.options.cookie = adjust_parameter(menu.options.cookie, token_name, token_value)
    # A token the target expects back as a header, under the name it was given.
    for header_name in list(request.headers) + list(request.unredirected_hdrs):
      if header_name.lower() == token_name.lower():
        request.add_unredirected_header(header_name, token_value)
  finally:
    settings.FETCHING_CSRF_TOKEN = False

# eof
