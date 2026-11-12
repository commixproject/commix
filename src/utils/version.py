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

import os
import sys
import time
from src.utils import settings

"""
Show version number and exit.
"""
def show_version():
  settings.print_data_to_stdout(settings.VERSION)
  raise SystemExit()

"""
How long this install has gone without being updated, in whole days.

Taken from when the file holding the version was last written, which an update rewrites - so what
is measured is the install itself rather than anything a server would have to be asked for. None
where that cannot be read at all, which is a copy that says nothing about its own age rather than
one that is up to date.
"""
def days_since_update():
  try:
    return int(time.time() - os.path.getmtime(os.path.abspath(settings.__file__.replace(".pyc", ".py")))) // (3600 * 24)
  except (OSError, AttributeError, TypeError):
    return None

"""
Said at the end of the run, where what it is about is the install rather than the target.
"""
def announce_if_outdated():
  days = days_since_update()
  if days is None or days <= settings.LAST_UPDATE_NAGGING_DAYS:
    return
  warn_msg = "This copy of " + settings.APPLICATION + " was last updated " + str(days)
  warn_msg += " days ago. Run it with the '--update' switch to bring it up to date."
  settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Check python version number.
"""
def python_version():
  PYTHON_VERSION = sys.version.split()[0]
  if PYTHON_VERSION.split(".")[0] != "3":
    err_msg = "Unsupported Python version detected: "
    err_msg += PYTHON_VERSION + ". "
    err_msg += settings.APPLICATION + " requires Python 3.7 or later."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    # Exits non-zero: a caller that cannot tell this apart from a finished run - a CI job, or any
    # script around commix - would otherwise read the wrong interpreter as a successful one.
    raise SystemExit(1)

# eof
