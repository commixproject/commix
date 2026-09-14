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
from src.core.injections.controller import checks

"""
About: Replaces slashes (/) with environment variable value "${PATH%%u*}".
Notes: This tamper script works against target(s) with a POSIX shell.
Reference: https://www.secjuice.com/bypass-strict-input-validation-with-remove-suffix-and-prefix-pattern/
"""

__tamper__ = "slash2env"
__priority__ = settings.PRIORITY.LOW

def dependencies():
  return checks.tamper_dep_eval_incompatible(__tamper__) or checks.tamper_dep_unix_only(__tamper__)

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

def tamper(payload):
  def add_slash2env(payload): 
    payload = payload.replace("/", "${PATH%%u*}")
    return payload
  if settings.TARGET_OS != settings.OS.WINDOWS:
    return add_slash2env(payload)
  else:
    return payload

# eof