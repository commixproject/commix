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

"""
A module should reuse the shared core building blocks (requests/checks/shell_options/handler) instead of reimplementing them - see shellshock.py as the reference implementation.
"""

"""
Registered modules: CLI flag name (matching the menu.options attribute) -> (import path, handler).
"""
MODULES = {
  "shellshock": ("src.core.modules.shellshock.shellshock", "shellshock_handler"),
}

"""
Load modules
"""
def load_modules(url, http_request_method, filename):
  for name, (module_path, handler_name) in MODULES.items():
    if getattr(menu.options, name, False):
      try:
        module = __import__(module_path, fromlist=[handler_name])
        getattr(module, handler_name)(url, http_request_method, filename)
      except ImportError as err_msg:
        settings.print_data_to_stdout(settings.END_LINE.LF + settings.print_critical_msg(err_msg))
        raise SystemExit()
      raise SystemExit()

# eof
