#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2025 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

import sys
import base64
from src.utils import settings
from src.thirdparty.six.moves import urllib as _urllib

"""
About: Base64 all characters in a given payload.
Notes: This tamper script works against all targets.
"""

__tamper__ = "base64encode"

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

def tamper(payload):
  if len(settings.WHITESPACES) != 0 and settings.WHITESPACES[0] == _urllib.parse.quote_plus(settings.SINGLE_WHITESPACE):
    err_msg = "Tamper script '" +  __tamper__  + "' is unlikely to work combined with the tamper script 'space2plus'."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()
  else:
    payload = _urllib.parse.unquote(payload)
    payload = base64.b64encode(payload.encode())
    payload = payload.decode(settings.DEFAULT_CODEC)
    return payload

# eof