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
The dynamic code evaluation (aka eval-based) technique.
"""

"""
The "eval-based" injection technique handler.
"""
def eb_injection_handler(url, timesec, filename, http_request_method, injection_type, technique):
  return handler.do_results_based_proccess(url, timesec, filename, http_request_method, injection_type, technique)

"""
The exploitation function.
(call the injection handler)
"""
def exploitation(url, timesec, filename, http_request_method, injection_type, technique):
  return eb_injection_handler(url, timesec, filename, http_request_method, injection_type, technique)

# eof