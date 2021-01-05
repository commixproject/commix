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

import codecs
from src.utils import settings 
from src.thirdparty import six

def hexdecode(value):
  try:
    value = codecs.decode(value, "hex")
  except LookupError:
    value = binascii.unhexlify(value)
  value = value.decode(settings.UNICODE_ENCODING)
  return value

def hexencode(value):
  if isinstance(value, six.text_type):
    value = value.encode(settings.UNICODE_ENCODING)
  try:
    value = codecs.encode(value, "hex")
  except LookupError:
    value = binascii.hexlify(value)
  value = value.decode(settings.UNICODE_ENCODING)
  return value

