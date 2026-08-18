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

from src.utils import settings

"""
Connection-level resilience: retry transient failures instead of aborting,
and detect retries that inflate timing measurements.
"""

"""
Reset the connection-error budget after a clean success.
"""
def reset_connection_error_budget():
  settings.CONNECTION_ERROR_RETRIES = 0

"""
True and warns if the connection-error budget allows another attempt; False once exhausted.
"""
def should_retry_connection_error(err):
  if settings.CONNECTION_ERROR_RETRIES < settings.MAX_CONNECTION_ERROR_RETRIES:
    settings.CONNECTION_ERROR_RETRIES = settings.CONNECTION_ERROR_RETRIES + 1
    warn_msg = "Connection dropped (" + str(err) + "), reconnecting (" + str(settings.CONNECTION_ERROR_RETRIES) + "/" + str(settings.MAX_CONNECTION_ERROR_RETRIES) + ")."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    settings.VISIBLE_CONNECTION_ERRORS += 1
    return True
  return False

"""
True once the connection-error budget is used up.
"""
def connection_error_budget_exhausted():
  return settings.CONNECTION_ERROR_RETRIES >= settings.MAX_CONNECTION_ERROR_RETRIES

"""
Retry delay in seconds; 0 during timing attacks to avoid inflating exec_time.
"""
def retry_delay_seconds():
  return 0 if settings.TIME_RELATED_ATTACK else settings.DELAY_RETRY

"""
True if a transport-level retry happened mid-measurement, making exec_time untrustworthy.
"""
def request_was_retried(requests_before):
  return settings.TOTAL_OF_REQUESTS - requests_before > 1

"""
True while the request loop should keep retrying: not succeeded, within budget, not unauthorized.
"""
def should_keep_retrying(succeeded, unauthorized):
  return not succeeded and settings.TOTAL_OF_REQUESTS <= settings.MAX_RETRIES and not unauthorized

"""
Grow the retry budget after progress.
"""
def expand_retry_budget():
  settings.MAX_RETRIES = settings.TOTAL_OF_REQUESTS * 2

"""
Stop growing the retry budget once retries won't help.
"""
def freeze_retry_budget():
  settings.MAX_RETRIES = settings.TOTAL_OF_REQUESTS

"""
Cut retries to one for clearly fatal errors.
"""
def disable_retries():
  settings.MAX_RETRIES = 1

"""
True once a single-target scan has exhausted retries and the connection-error budget.
"""
def should_abandon_target():
  return settings.TOTAL_OF_REQUESTS == settings.MAX_RETRIES and not settings.MULTI_TARGETS and connection_error_budget_exhausted()

"""
Mark the target URL unreachable.
"""
def mark_url_invalid():
  settings.VALID_URL = False

"""
Mark the target URL reachable.
"""
def mark_url_valid():
  settings.VALID_URL = True
