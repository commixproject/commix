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

from random import sample
from src.utils import settings
from src.core.compat import xrange

"""
About: Appends a fake HTTP header 'X-Forwarded-For'.
"""

__tamper__ = "xforwardedfor"
settings.TAMPER_SCRIPTS[__tamper__] = True

def tamper(request):
  def randomIP():
    numbers = []
    while not numbers or numbers[0] in (10, 172, 192):
      numbers = sample(xrange(1, 255), 4)
    return '.'.join(str(_) for _ in numbers)

  request.add_header('X-Forwarded-For', randomIP())
  request.add_header('X-Client-Ip', randomIP())
  request.add_header('X-Real-Ip', randomIP())

# eof 