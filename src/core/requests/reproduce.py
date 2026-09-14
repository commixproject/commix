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
from src.core.parse import cmdline as menu
from src.utils import settings
from src.core.controller import checks
from src.thirdparty.six.moves import urllib as _urllib

"""
Wrap a value for a shell, so a payload full of quotes and dollar signs survives being pasted.
"""
def _quote(value):
  return "'" + str(value).replace("'", "'\\''") + "'"

"""
Split parameters into pairs and hand the payload to the one it was found on. The pairs are passed
to curl one by one, so the encoding of a payload full of '&' and '+' is curl's job, not a guess.
"""
def _parameter_arguments(data, vuln_parameter, payload):
  arguments = []
  replaced = False
  for pair in re.split(r"[" + re.escape(settings.URL_PARAM_DELIMITER + settings.POST_DATA_PARAM_DELIMITER) + r"]", data or ""):
    if not pair:
      continue
    name = pair.split("=")[0]
    if name == vuln_parameter and not replaced:
      replaced = True
      arguments += ["--data-urlencode", _quote(name + "=" + payload)]
    else:
      arguments += ["--data-urlencode", _quote(_urllib.parse.unquote(pair))]
  return arguments, replaced

"""
The header a payload was injected into, when it did not go into a parameter.
"""
def _injected_header():
  if settings.COOKIE_INJECTION:
    return settings.COOKIE
  if settings.USER_AGENT_INJECTION:
    return settings.USER_AGENT
  if settings.REFERER_INJECTION:
    return settings.REFERER
  if settings.HOST_INJECTION:
    return settings.HOST
  if settings.CUSTOM_HEADER_INJECTION:
    return settings.CUSTOM_HEADER_NAME
  return None

"""
Build the command that reproduces a finding, so it can be confirmed without running commix again.
"""
def curl_command(url, http_request_method, vuln_parameter, payload):
  try:
    url = url or menu.options.url
    if not url:
      return ""

    # Shown as it is built, not decoded: nothing here is URL-encoded until it meets the request,
    # and decoding it turned a per-cent sign in the command into the start of an escape.
    header_name = _injected_header()
    parts = _urllib.parse.urlsplit(url)
    parameters = []
    query_in_url = True
    headers = []

    if header_name:
      """
      The payload rode in a header, so every parameter stays as it was.

      A cookie header carries more than the one cookie the payload went into, and the real request
      sends all of them with only that one's value replaced - so the whole header is rebuilt the
      same way. Sending the payload on its own would drop the session cookie beside it, and the
      command would not reproduce the finding.
      """
      if header_name == settings.COOKIE and menu.options.cookie:
        headers.append(header_name + ": " + checks.process_injectable_value(payload, menu.options.cookie))
      else:
        headers.append(header_name + ": " + payload)
    elif settings.USER_DEFINED_POST_DATA and (settings.IS_JSON or settings.IS_XML):
      # A structured body is not a list of pairs: it goes over whole, with the payload written in.
      body = checks.process_injectable_value(payload, settings.USER_DEFINED_POST_DATA)
      parameters = ["--data-raw", _quote(body)]
      headers.append("Content-Type: " + ("application/json" if settings.IS_JSON else "application/xml"))
    elif settings.USER_DEFINED_POST_DATA:
      parameters, _ = _parameter_arguments(settings.USER_DEFINED_POST_DATA, vuln_parameter, payload)
    else:
      parameters, replaced = _parameter_arguments(parts.query, vuln_parameter, payload)
      if replaced:
        # curl rebuilds the query from the pairs, so the one already in the URL has to go.
        url = _urllib.parse.urlunsplit(parts._replace(query=""))
        query_in_url = False
      else:
        parameters = []

    for name, value in ((settings.COOKIE, menu.options.cookie), (settings.USER_AGENT, menu.options.agent), \
                        (settings.REFERER, menu.options.referer), (settings.HOST, menu.options.host)):
      if value and name != header_name:
        headers.append(name + ": " + value)

    if menu.options.headers:
      for header in menu.options.headers.split(settings.END_LINE.ESCAPED_LF):
        if header.strip() and header.strip() not in headers:
          headers.append(header.strip().replace(":", ": ", 1).replace(":  ", ": "))
    elif menu.options.header and menu.options.header.strip():
      headers.append(menu.options.header.strip())

    command = ["curl", "-i", "-s"]
    if parameters and query_in_url is False:
      # Without this the pairs would be sent as a body, turning the request into a POST.
      command.append("--get")
    if http_request_method and http_request_method != settings.HTTPMETHOD.GET:
      command += ["-X", http_request_method]
    for header in headers:
      command += ["-H", _quote(header)]
    command += parameters
    command.append(_quote(url))

    return settings.SINGLE_WHITESPACE.join(command)
  except Exception:
    # A command that cannot be built is not worth failing a finished scan over.
    return ""

"""
What the reproduction cannot carry over from the scan, so it is not read as an exact replay.
"""
def curl_command_caveats():
  caveats = []
  if menu.options.chunked:
    caveats.append("the request was sent chunked, which this command does not reproduce")
  if menu.options.live_cookies:
    caveats.append("the cookie was read live and may since have changed")
  return caveats

# eof
