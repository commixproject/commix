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

import threading
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
"""
Back off when the target answers as if it has had enough of us, and creep back once it stops.
A time-related technique measures the very delay this changes, so it is left alone while one runs.
"""
def adapt_delay(blocked):
  if settings.ADAPTIVE_DELAY_FROZEN:
    return
  if settings.TIME_RELATED_ATTACK:
    # Freezing here, rather than skipping, keeps the baseline and the measurements comparable.
    settings.ADAPTIVE_DELAY_FROZEN = True
    return

  if blocked:
    settings.ADAPTIVE_DELAY_STREAK = 0
    if settings.ADAPTIVE_DELAY < settings.MAX_ADAPTIVE_DELAY:
      settings.ADAPTIVE_DELAY = min(settings.MAX_ADAPTIVE_DELAY, (settings.ADAPTIVE_DELAY * 2) or 1)
      warn_msg = "The target is answering as if it is rate-limiting, so waiting "
      warn_msg += str(settings.ADAPTIVE_DELAY) + " second" + "s"[settings.ADAPTIVE_DELAY == 1:] + " between requests."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
  elif settings.ADAPTIVE_DELAY:
    settings.ADAPTIVE_DELAY_STREAK += 1
    if settings.ADAPTIVE_DELAY_STREAK >= settings.ADAPTIVE_DELAY_RECOVERY:
      settings.ADAPTIVE_DELAY_STREAK = 0
      settings.ADAPTIVE_DELAY -= 1

# How long to wait before trying again, which a timed payload cannot afford at all.
def retry_delay_seconds():
  return 0 if settings.TIME_RELATED_ATTACK else settings.DELAY_RETRY

"""
Requests this thread has sent.

Counted per thread rather than off the run-wide total: several workers share that total, so a
thread asking whether its own request was retried would be answered with everyone else's traffic -
under '--threads' always "yes", and every measurement taken the maximum number of times.
"""
_thread_state = threading.local()

# Count one request against this thread's own tally.
def note_request_sent():
  _thread_state.sent = getattr(_thread_state, "sent", 0) + 1

# How many requests this thread has sent.
def requests_sent():
  return getattr(_thread_state, "sent", 0)

"""
True if a transport-level retry happened mid-measurement, making exec_time untrustworthy.
"""
def request_was_retried(requests_before):
  return requests_sent() - requests_before > 1

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
  # At or past it: the counter is raised from several places, so it can step over the budget
  # between two checks and an equality would never hold.
  return settings.TOTAL_OF_REQUESTS >= settings.MAX_RETRIES and not settings.MULTI_TARGETS and connection_error_budget_exhausted()

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
  # An answered request is the evidence that the backing off can start being given back.
  adapt_delay(blocked=False)

# eof
