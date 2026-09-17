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
import signal

from src.utils import common
from src.utils import settings
from src.utils import version
from src.core.parse import cmdline as menu
from src.core.testing import smoke_test

"""
What a run settles before it has a target: which version it is, how much it says, how long it is
allowed to take, and where its targets are going to come from.

Nothing here touches the network, so an option that cannot be acted on is refused while refusing
it still costs nothing.
"""
def bootstrap():
  # Check if defined "--version" option.
  if menu.options.version:
    version.show_version()
    raise SystemExit()

  # Print the legal disclaimer msg.
  settings.print_data_to_stdout(settings.print_legal_disclaimer_msg(settings.LEGAL_DISCLAIMER_MSG))

  # Get total number of days from last update
  if settings.STABLE_RELEASE is False:
    common.days_from_last_update()

  # Check if specified wrong alternative interpreter
  if menu.options.interpreter:
    # Resolved before it is checked, and kept resolved - what reads it later compares against the
    # name commix knows, so 'py' has to have become 'python' by now.
    menu.options.interpreter = settings.resolve_language(menu.options.interpreter)
    if menu.options.interpreter not in settings.AVAILABLE_INTERPRETERS:
      err_msg = "'" + menu.options.interpreter + "' interpreter is not supported!"
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()

  # Define the level of verbosity.
  if menu.options.verbose > 4:
    err_msg = "The value for option '-v' "
    err_msg += "must be an integer value from range [0, 4]."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()
  else:
    settings.VERBOSITY_LEVEL = menu.options.verbose

  # Hard '--time-limit' cutoff - a signal, immune to exception handling elsewhere.
  if menu.options.time_limit and hasattr(signal, "alarm"):
    # Stop the run where it has been going longer than '--time-limit' allows.
    def _time_limit_reached(signum, frame):
      err_msg = "Reached the specified time limit of " + str(menu.options.time_limit) + " second(s)."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      os._exit(0)
    signal.signal(signal.SIGALRM, _time_limit_reached)
    signal.alarm(max(1, int(round(menu.options.time_limit))))

  if settings.VERBOSITY_LEVEL != 0:
    settings.print_data_to_stdout(settings.execution("Starting"))

  if menu.options.smoke_test:
    smoke_test()

  try:
    # Treat non-interactive stdin as targets only without an explicit target; skip CI log pipes.
    if hasattr(sys.stdin, "fileno") and not any((os.isatty(sys.stdin.fileno()), menu.options.ignore_stdin,
                "CI" in os.environ,
                menu.options.url, menu.options.requestfile, menu.options.bulkfile, menu.options.logfile)):
      settings.STDIN_PARSING = True
  except Exception as ex:
    if "fileno" in str(ex) and settings.STDIN_PARSING:
      settings.STDIN_PARSING = False

  if settings.STDIN_PARSING or settings.CRAWLING or menu.options.bulkfile or menu.options.shellshock:
    settings.OS_CHECKS_NUM = 1

# eof
