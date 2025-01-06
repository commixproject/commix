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

import codecs
import binascii
from src.utils import settings
from src.thirdparty import six

"""
Decode string for hex
"""
def hexdecode(value):
  if value.lower().startswith("0x"):
    value = value[2:]
  try:
    value = codecs.decode(''.join(value.split()), "hex")
  except binascii.Error:
    _ = False
    return value, _
  except LookupError:
    value = binascii.unhexlify(value)
  try:
    value = value.decode(settings.DEFAULT_CODEC)
    _ = True
  except:
    _ = False
  return value, _

"""
Encode string to hex
"""
def hexencode(value):
  if isinstance(value, six.text_type):
    value = value.encode(settings.DEFAULT_CODEC)
  try:
    value = codecs.encode(value, "hex")
  except LookupError:
    value = binascii.hexlify(value)
  value = value.decode(settings.DEFAULT_CODEC)
  _ = True
  return value, _

