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

import random
from src.utils import settings
from src.core.compat import xrange

"""
About: Appends a fake HTTP header 'X-Forwarded-For' (and similar).
"""

__tamper__ = "xforwardedfor"
__priority__ = settings.PRIORITY.NORMAL

# An address the target would read as coming from inside its own network says the opposite of what
# this header is for, so an octet that begins one of those ranges is drawn again.
PRIVATE_FIRST_OCTETS = (10, 172, 192)
# The octets are sampled below this, which keeps them off the broadcast address as well as zero.
LAST_OCTET_VALUE = 255

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

# Add a spoofed client address, so the request appears to come from elsewhere.
def tamper(request):
  # An address from one of the ranges a proxy is believed for.
  def randomIP():
    numbers = []
    while not numbers or numbers[0] in PRIVATE_FIRST_OCTETS:
      numbers = random.sample(xrange(1, LAST_OCTET_VALUE), 4)
    return '.'.join(str(number) for number in numbers)
  request.add_header('X-Forwarded-For', randomIP())
  request.add_header('X-Client-Ip', randomIP())
  request.add_header('X-Real-Ip', randomIP())
  request.add_header('CF-Connecting-IP', randomIP())
  request.add_header('True-Client-IP', randomIP())
  # Reference: https://developer.chrome.com/multidevice/data-compression-for-isps#proxy-connection
  request.add_header('Via', '1.1 Chrome-Compression-Proxy')
  # Reference: https://wordpress.org/support/topic/blocked-country-gaining-access-via-cloudflare/#post-9812007
  request.add_header('CF-IPCountry', random.choice(('GB', 'US', 'FR', 'AU', 'CA', 'NZ', 'BE', 'DK', 'FI', 'IE', 'AT', 'IT', 'LU', 'NL', 'NO', 'PT', 'SE', 'ES', 'CH')))


# eof
