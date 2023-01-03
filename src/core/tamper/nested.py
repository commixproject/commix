#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2023 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

import sys
import random
from src.utils import menu
from src.utils import settings

"""
About: Adds double quotes around of the generated payloads (nested).
Notes: This tamper script works against Unix-like target(s).
"""

__tamper__ = "nested"
if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

double_quote = "\""
def tamper(payload):
  def nested(payload):
    if settings.TARGET_OS != "win":
      settings.TAMPER_SCRIPTS[__tamper__] = True
      if not menu.options.prefix and not menu.options.suffix:
        payload = double_quote + payload + double_quote
      else:
        if menu.options.prefix and menu.options.prefix != double_quote:
          menu.options.prefix = menu.options.prefix + double_quote
        else:
          menu.options.prefix = double_quote

        if menu.options.suffix and menu.options.suffix != double_quote:
          menu.options.suffix = menu.options.suffix + double_quote
        else:
          menu.options.suffix = double_quote
      return payload  
      
  if settings.TARGET_OS != "win":
    if settings.EVAL_BASED_STATE != False:
      return payload
    else:
      return nested(payload)
  else:
    return payload

# eof 