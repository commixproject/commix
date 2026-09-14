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
from src.core.controller import checks

"""
About: Replaces slashes (/) with environment variable value "${PATH%%u*}".
Notes: This tamper script works against target(s) with a POSIX shell.
Reference: https://www.secjuice.com/bypass-strict-input-validation-with-remove-suffix-and-prefix-pattern/
"""

__tamper__ = "slash2env"
__priority__ = settings.PRIORITY.LOW

# Why this script cannot be applied to the target at hand, or nothing where it can.
def dependencies():
  return checks.tamper_dep_eval_incompatible(__tamper__) or checks.tamper_dep_unix_only(__tamper__)

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

# Say with an environment variable what the payload said with a slash.
def tamper(payload):
  # The substitution itself, over the slashes outside quoted words.
  def add_slash2env(payload): 
    payload = payload.replace("/", "${PATH%%u*}")
    return payload
  if settings.TARGET_OS != settings.OS.WINDOWS:
    return add_slash2env(payload)
  else:
    return payload

# eof
