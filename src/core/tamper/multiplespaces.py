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

import random
from src.utils import settings

"""
About: Adds multiple spaces around operating system commands in a given payload.
Notes: Useful to bypass very weak and bespoke web application firewalls that has poorly written permissive regular expressions.
"""

__tamper__ = "multiplespaces"

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

def tamper(payload):
  if settings.TAMPER_SCRIPTS[__tamper__]:
    for i in range(0, len(settings.WHITESPACES)):
      settings.WHITESPACES[i] = settings.WHITESPACES[i] * random.randrange(3, 8)
  return payload

# eof