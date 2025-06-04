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

from src.utils import settings
from src.core.injections.controller import checks
from src.core.injections.controller import handler

"""
The "tempfile-based" injection technique on semiblind OS command injection.
__Warning:__ This technique is still experimental, is not yet fully functional and may leads to false-positive results.
"""

"""
The "tempfile-based" injection technique handler
"""
def tfb_injection_handler(url, timesec, filename, http_request_method, url_time_response, injection_type, technique, tmp_path):
  return handler.do_time_related_proccess(url, timesec, filename, http_request_method, url_time_response, injection_type, technique, tmp_path)

"""
The exploitation function.
(call the injection handler)
"""
def exploitation(url, timesec, filename, tmp_path, http_request_method, url_time_response):
  settings.WEB_ROOT = ""
  # Check if attack is based on time delays.
  if not settings.TIME_RELATED_ATTACK :
    checks.time_related_attaks_msg()
    settings.TIME_RELATED_ATTACK = True

  injection_type = settings.INJECTION_TYPE.SEMI_BLIND
  technique = settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED

  if tfb_injection_handler(url, timesec, filename, http_request_method, url_time_response, injection_type, technique, tmp_path) == False:
    settings.TIME_RELATED_ATTACK = settings.TEMPFILE_BASED_STATE = False
    return False

# eof