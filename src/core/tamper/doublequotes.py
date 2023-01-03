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

import re
import sys
from src.utils import menu
from src.utils import settings

"""
About: Adds double quotes (") between the characters of the generated payloads.
Notes: This tamper script works against Unix-like target(s).
"""

__tamper__ = "doublequotes"
if settings.TRANFROM_PAYLOAD != None:
  settings.TRANFROM_PAYLOAD = None

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

def tamper(payload):
  def add_double_quotes(payload):
    settings.TAMPER_SCRIPTS[__tamper__] = True
    rep = {
            '""I""F""S': 'IFS', 
            '""i""f': 'if', 
            '""t""h""e""n': 'then',
            '""e""l""s""e': 'else',
            '""f""i': 'fi',
            '""s""t""r': 'str',
            '""c""m""d': 'cmd',
            '""c""ha""r': 'char'
          }
    if settings.TARGET_OS != "win": 
      payload = re.sub(r'([b-zD-Z])', r'""\1', payload)
    else:
      payload = payload.replace("tokens","\"t\"\"o\"\"k\"\"e\"\"n\"\"s\"")
    rep = dict((re.escape(k), v) for k, v in rep.items())
    pattern = re.compile("|".join(rep.keys()))
    payload = pattern.sub(lambda m: rep[re.escape(m.group(0))], payload)
    return payload

  if settings.EVAL_BASED_STATE != False:
    return payload
  else:
    return add_double_quotes(payload)
  
# eof 