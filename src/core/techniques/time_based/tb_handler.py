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

from src.utils import common
from src.utils import settings
from src.core.controller import checks
from src.core.controller import handler

"""
The "time-based" injection technique on Blind OS Command Injection.
"""

"""
The "time-based" injection technique handler.
"""
def tb_injection_handler(url, timesec, filename, http_request_method, url_time_response, injection_type, technique, tmp_path):
  return handler.do_time_related_process(url, timesec, filename, http_request_method, url_time_response, injection_type, technique, tmp_path)

"""
The exploitation function.
(call the injection handler)
"""
def exploitation(url, timesec, filename, http_request_method, url_time_response, injection_type, technique):
  # Check if attack is based on time delays.
  if not settings.TIME_RELATED_ATTACK:
    settings.TIME_RELATED_ATTACK = True

  tmp_path = ""
  # Asked about how steadily the target answers, not about how long it takes: a slow target that
  # answers at the same speed every time is read as easily as a fast one, and the question was
  # being put - and the technique offered up - over nothing but its latency.
  if checks.response_times_unsteady():
    settings.RESPONSE_DELAYS = True
    # Lowering the delay again is read off the same times that are moving about, so it is
    # left where it is while they are.
    settings.ADJUST_TIME_DELAY_DISABLED = True
    while True:
      message = "Considerable lagging has been detected in the target's responses, which makes "
      message += "time-related techniques unreliable - a higher '--time-sec' (10 or more) stands "
      message += "clear of it. How do you want to proceed? [(C)ontinue/(s)kip] "
      proceed_option = common.read_input(message, default="C", check_batch=True)
      if proceed_option.lower() in settings.CHOICE_PROCEED :
        if proceed_option.lower() == "c":
          result = tb_injection_handler(url, timesec, filename, http_request_method, url_time_response, injection_type, technique, tmp_path)
          if result is False:
            return False
          # Return when a technique was resumed or found; only False should continue prompting.
          return result
        elif proceed_option.lower() == "s":
          from src.core.techniques.file_based import fb_handler
          fb_handler.exploitation(url, timesec, filename, http_request_method, url_time_response, injection_type, technique)
          return False
        elif proceed_option.lower() == "q":
          raise SystemExit()
      else:
        common.invalid_option(proceed_option)
        pass
  else:
    if tb_injection_handler(url, timesec, filename, http_request_method, url_time_response, injection_type, technique, tmp_path) is False:
      settings.TIME_RELATED_ATTACK = False
      return False
# eof
