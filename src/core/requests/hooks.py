#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2026 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

For more see the file 'readme/COPYING' for copying permission.
"""

import os
import re

from src.utils import settings
from src.core.parse import cmdline as menu
from src.thirdparty.six.moves import http_client as _http_client

"""
Scripts handed the whole request on its way out, and the whole answer on its way back.

A tamper script is handed the payload and hands one back, which is the right shape for what is done
to a payload and the wrong one for everything done around it. What is left over is the work that
belongs to the request rather than to what is being injected: signing it again once its body has
changed, recomputing a checksum header over it, or unwrapping the envelope an answer arrives in so
that what commix reads is the answer rather than the wrapper.
"""

"""
Load the scripts an option names, and hand back the functions they define.
"""
def _load(option, kind):
  functions = []
  if not option:
    return functions
  for path in (item.strip() for item in re.split(settings.PARAMETER_SPLITTING_REGEX, option) if item.strip()):
    if not path.endswith(".py"):
      err_msg = "The " + kind + " script '" + path + "' should have a '.py' extension."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit(settings.EXIT_FAILURE)
    if not os.path.isfile(path):
      err_msg = "The " + kind + " script '" + path + "' does not exist."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit(settings.EXIT_FAILURE)
    namespace = {}
    try:
      with open(path) as script_file:
        exec(compile(script_file.read(), path, "exec"), namespace)
    except Exception as err_msg:
      error_msg = "Unable to load the " + kind + " script '" + path + "' (" + str(err_msg) + ")."
      settings.print_data_to_stdout(settings.print_critical_msg(error_msg))
      raise SystemExit(settings.EXIT_FAILURE)
    if not callable(namespace.get(kind)):
      err_msg = "The " + kind + " script '" + path + "' does not define a '" + kind + "()' function."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit(settings.EXIT_FAILURE)
    functions.append((os.path.basename(path), namespace[kind]))
  return functions

"""
Read what '--preprocess' and '--postprocess' were given, before the target is touched.

For the same reason the tamper scripts are read there: a script that does not exist, or does not
define what it has to, is the user's to correct rather than something to find out mid-run.
"""
def load_scripts():
  settings.PREPROCESS_FUNCTIONS = _load(menu.options.preprocess, "preprocess")
  settings.POSTPROCESS_FUNCTIONS = _load(menu.options.postprocess, "postprocess")
  if settings.VERBOSITY_LEVEL != 0:
    for name, _ in settings.PREPROCESS_FUNCTIONS + settings.POSTPROCESS_FUNCTIONS:
      debug_msg = "Loaded the hook script '" + name + "'."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

"""
Report a script that raised, naming it rather than the line it died on.
"""
def _failed(kind, name, err_msg):
  error_msg = "The " + kind + " script '" + name + "' raised an unhandled error (" + str(err_msg) + ")."
  settings.print_data_to_stdout(settings.print_critical_msg(error_msg))
  raise SystemExit(settings.EXIT_FAILURE)

"""
Hand the request to every '--preprocess' script, in the order they were given.

The request itself is passed rather than a copy of its parts, so that a script can change the URL,
the body and the headers together - which is what signing one again amounts to.
"""
def preprocess(request):
  for name, function in settings.PREPROCESS_FUNCTIONS:
    try:
      function(request)
    except Exception as err_msg:
      _failed("preprocess", name, err_msg)
  return request

"""
Headers as the rest of the run expects them, whatever a script handed back.

A script is free to return a plain dictionary - it is the obvious thing to return - and what reads
them afterwards wants something that renders as headers rather than as a dictionary.
"""
def _as_headers(response_headers):
  if response_headers is None or hasattr(response_headers, "get_content_charset"):
    return response_headers
  if isinstance(response_headers, dict):
    message = _http_client.HTTPMessage()
    for key, value in response_headers.items():
      message[str(key)] = str(value)
    return message
  return response_headers

"""
Hand the answer to every '--postprocess' script, and keep what the last of them returns.

What comes back is what the rest of the run reads - the detection, the comparisons and the extracted
output all - so an answer unwrapped here is unwrapped everywhere, rather than only where it is shown.
"""
def postprocess(page, response_headers, code):
  for name, function in settings.POSTPROCESS_FUNCTIONS:
    try:
      page, response_headers, code = function(page, response_headers, code)
    except Exception as err_msg:
      _failed("postprocess", name, err_msg)
    response_headers = _as_headers(response_headers)
  if isinstance(page, bytes):
    page = page.decode(settings.DEFAULT_CODEC, errors="replace")
  return page, response_headers, code

# eof
