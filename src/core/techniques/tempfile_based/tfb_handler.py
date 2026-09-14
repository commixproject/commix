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

from src.core.parse import cmdline as menu
from src.utils import settings
from src.core.controller import handler
from src.core.controller import checks

"""
The "tempfile-based" injection technique on semiblind OS command injection.
__Warning:__ This technique is still experimental, is not yet fully functional and may leads to false-positive results.
"""

"""
The "tempfile-based" injection technique handler
"""
def tfb_injection_handler(url, timesec, filename, http_request_method, url_time_response, injection_type, technique, tmp_path):
  return handler.do_time_related_process(url, timesec, filename, http_request_method, url_time_response, injection_type, technique, tmp_path)

"""
The exploitation function.
(call the injection handler)
"""
def exploitation(url, timesec, filename, tmp_path, http_request_method, url_time_response):
  settings.WEB_ROOT = ""
  # Check if attack is based on time delays.
  if not settings.TIME_RELATED_ATTACK :
    settings.TIME_RELATED_ATTACK = True

  # The temporary file proves execution either way - which sink filled it is what the type names.
  if menu.options.eval_sink:
    injection_type = settings.INJECTION_TYPE.SEMI_BLIND_CE
  else:
    injection_type = settings.INJECTION_TYPE.SEMI_BLIND
  technique = settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED
  settings.BASELINE_TARGET = (url, http_request_method)
  # Taken before the technique says what it is testing, rather than in the middle of it: the model
  # is what the first timing is read against, so filling it belongs with settling into '/tmp/'.
  checks.warm_up_response_baseline(url, http_request_method)

  if tfb_injection_handler(url, timesec, filename, http_request_method, url_time_response, injection_type, technique, tmp_path) == False:
    settings.TIME_RELATED_ATTACK = settings.TEMPFILE_BASED_STATE = False
    return False

# eof
