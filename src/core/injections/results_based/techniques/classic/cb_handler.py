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

from src.core.injections.controller import handler

"""
The "classic" technique on result-based OS command injection.
"""

"""
The "classic" injection technique handler.
"""
def cb_injection_handler(url, timesec, filename, http_request_method, injection_type, technique):
  return handler.do_results_based_proccess(url, timesec, filename, http_request_method, injection_type, technique)

"""
The exploitation function.
(call the injection handler)
"""
def exploitation(url, timesec, filename, http_request_method, injection_type, technique):
  return cb_injection_handler(url, timesec, filename, http_request_method, injection_type, technique)

# eof
