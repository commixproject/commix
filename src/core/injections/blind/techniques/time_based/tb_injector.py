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

from src.core.injections.controller import injector

"""
 The "time-based" injection technique on Blind OS Command Injection.
"""

"""
The main command injection exploitation.
"""
def injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response, technique):
  OUTPUT_TEXTFILE = ""
  return injector.time_related_injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)

"""
False Positive check and evaluation.
"""
def false_positive_check(separator, TAG, cmd, whitespace, prefix, suffix, timesec, http_request_method, url, vuln_parameter, randvcalc, alter_shell, exec_time, url_time_response, false_positive_warning, technique):
  OUTPUT_TEXTFILE = ""
  return injector.false_positive_check(separator, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, randvcalc, alter_shell, exec_time, url_time_response, false_positive_warning, technique)

# eof