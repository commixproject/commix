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

from src.core.controller import injector

"""
 The "time-based" injection technique on Blind OS Command Injection.
"""

"""
The main command injection exploitation.
"""
def injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, interpreter, filename, url_time_response, technique):
  OUTPUT_TEXTFILE = ""
  return injector.time_related_injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique)

"""
False Positive check and evaluation.
"""
def false_positive_check(separator, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, randvcalc, interpreter, exec_time, url_time_response, false_positive_warning, technique, retry_attempt=None, retry_total=None, silent=False):
  # Named the way the caller calls it and the way the tempfile-based one beside it is named: taking
  # the boundary in another order and without the output file, every call raised before it arrived,
  # and the technique's own confirmation was thrown away with the exception.
  #
  # The technique has no output file of its own, so the empty one it is handed is what goes on.
  return injector.false_positive_check(separator, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, "", randvcalc, interpreter, exec_time, url_time_response, false_positive_warning, technique, retry_attempt, retry_total, silent)

# eof
