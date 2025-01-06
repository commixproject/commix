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
The "classic" technique on result-based OS command injection.
"""

"""
Evaluate test results.
"""
def injection_test_results(response, TAG, randvcalc, technique):
  return injector.injection_test_results(response, TAG, randvcalc, technique)

"""
The main command injection exploitation.
"""
def injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique):
  OUTPUT_TEXTFILE = ""
  return injector.results_based_injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique)

"""
The command execution results.
"""
def injection_results(response, TAG, cmd, technique, url, OUTPUT_TEXTFILE, timesec):
  url = OUTPUT_TEXTFILE = timesec = ""
  return injector.injection_results(response, TAG, cmd, technique, url, OUTPUT_TEXTFILE, timesec)
