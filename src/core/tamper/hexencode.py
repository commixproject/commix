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
from src.core.convert import hexencode
from src.thirdparty.six.moves import urllib as _urllib
from src.utils import settings

"""
About: Hex all characters in a given payload.
Notes: This tamper script works against all targets.
"""

__tamper__ = "hexencode"

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

def tamper(payload):
  if settings.WHITESPACE[0] == "+":
    err_msg = "Tamper script '" +  __tamper__  + "' is unlikely to work combined with the tamper script 'space2plus'."
    if settings.VERBOSITY_LEVEL == 0:
      print("")
    print(settings.print_critical_msg(err_msg)) 
    raise SystemExit()
    
  else:
    payload = _urllib.parse.unquote(payload)
    payload = hexencode(payload)
    return payload

# eof 