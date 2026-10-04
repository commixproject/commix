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

import re
import random
import string
from src.utils import settings

"""
Convert POST data to chunked transfer-encoded data.

The point of the split is that no chunk holds a whole token a filter could match on: the payload
only exists as a whole once the target has put the chunks back together.
"""
def split_post_data(data):
  if not data:
    return data

  length = len(data)
  chunked_data = []
  index = 0

  while index < length:
    chunk_size = random.randint(1, settings.MAX_CHUNK_SIZE)
    if index + chunk_size >= length:
      chunk_size = length - index

    while chunk_size > 1:
      candidate = data[index:index + chunk_size]
      # Cutting the chunk shorter moves the boundary inside the keyword, where a filter cannot see it.
      if re.search(settings.CHUNKED_SPLIT_KEYWORDS_REGEX, candidate, re.I):
        chunk_size -= 1
      else:
        break

    candidate = data[index:index + chunk_size]
    index += chunk_size

    # The extension is ignored by the target, but it is one more thing an inspecting device must parse.
    extension = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(5))
    chunked_data.append(hex(chunk_size)[2:] + ";" + extension + settings.END_LINE.CRLF)
    chunked_data.append(candidate + settings.END_LINE.CRLF)

  chunked_data.append("0" + settings.END_LINE.CRLF + settings.END_LINE.CRLF)

  return "".join(chunked_data)

# eof
