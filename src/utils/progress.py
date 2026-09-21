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

import sys
import time
import shutil
from src.utils import settings

"""
A bar counting off what has been retrieved, and how long the rest of it is expected to take.
"""
class ProgressBar(object):

  def __init__(self, maxvalue=10, width=None):
    self._min = 0
    self._max = int(maxvalue)
    self._span = max(self._max - self._min, 0.001)
    self._width = width or progress_width()
    self._amount = 0
    # Timed from here, so the first item retrieved already gives an estimate.
    self._start = time.time()
    self._eta = None
    self._eta_at = None
    self._bar = "[]"
    self.update()

  # Seconds as the minutes and seconds they are shown in.
  def _as_clock(self, value):
    minutes = int(value) // 60
    return "%.2d:%.2d" % (minutes, int(value) - (minutes * 60))

  # Redraw the bar itself, for what has been retrieved so far.
  def update(self, amount=0):
    self._amount = min(max(amount, self._min), self._max)
    done = float(self._amount - self._min)
    percent = min(100, int(round((done / float(self._span)) * 100.0)))
    room = max(1, self._width - len("100%% [] %s/%s  (ETA 00:00)" % (self._max, self._max)))
    hashes = int(round((percent / 100.0) * room))
    if hashes == 0:
      self._bar = "[>" + (" " * (room - 1)) + "]"
    elif hashes >= room:
      self._bar = "[" + ("=" * room) + "]"
    else:
      self._bar = "[" + ("=" * (hashes - 1)) + ">" + (" " * (room - hashes)) + "]"
    self._bar = str(percent) + "% " + self._bar

  """
  Redraw with an estimate for what is left: the time each retrieved item took, over the ones still
  to come - eased into the estimate on screen, so a single slow character does not swing it.
  """
  def progress(self, amount):
    now = time.time()
    if amount > self._max:
      self._start = now
      self._eta = None
    done = amount - self._min
    elapsed = now - self._start
    target = (elapsed / done) * (self._max - amount) if (done > 0 and elapsed > 0) else None
    if target is None:
      self._eta = None
    elif self._eta is None:
      self._eta = target
    else:
      current = max(0, self._eta - (now - self._eta_at))
      self._eta = settings.ETA_DISPLAY_SMOOTHING * current + (1 - settings.ETA_DISPLAY_SMOOTHING) * target
    self._eta_at = now
    self.update(amount)
    self.draw(self._eta)

  # Redraw with the estimate counted down by the time that has passed, for a wait between items.
  def tick(self):
    eta = None if self._eta is None else max(0, self._eta - (time.time() - self._eta_at))
    self.draw(eta)

  # Drawn only where there is a terminal to animate, and wiped once there is nothing left to count.
  def draw(self, eta=None):
    if not is_tty():
      return
    settings.print_data_to_stdout("\r%s %d/%d  (ETA %s)" % (self._bar, self._amount, self._max,
                                                            self._as_clock(eta) if eta is not None else "??:??"))
    if self._amount >= self._max:
      settings.print_data_to_stdout("\r" + (" " * self._width) + "\r")
      # Wiped rather than ended, so what follows starts on this line instead of below a blank one.
      settings.PROGRESS_LINE_OPEN = False

  def __str__(self):
    return self._bar

# Whether there is a terminal to draw on, rather than a file or a pipe being written to.
def is_tty():
  try:
    return sys.stdout.isatty()
  except Exception:
    return False

# The room the bar is given: what is left of the line once the counter and the estimate are on it.
def progress_width():
  try:
    width = shutil.get_terminal_size().columns
  except Exception:
    width = settings.DEFAULT_CONSOLE_WIDTH
  return max(settings.MIN_PROGRESS_WIDTH, width - 26)

# eof
