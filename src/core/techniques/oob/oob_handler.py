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

from src.core.controller import handler

"""
The out-of-band technique on OS command injection.
"""

"""
The out-of-band injection technique handler.
"""
def oob_injection_handler(url, timesec, filename, http_request_method, injection_type, technique):
  return handler.do_oob_process(url, timesec, filename, http_request_method, injection_type, technique)

"""
The exploitation function.
(call the injection handler)
"""
def exploitation(url, timesec, filename, http_request_method, injection_type, technique):
  return oob_injection_handler(url, timesec, filename, http_request_method, injection_type, technique)

# eof
