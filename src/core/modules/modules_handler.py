#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2025 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

import os
import sys

from src.utils import menu
from src.utils import settings
from src.thirdparty.colorama import Fore, Back, Style, init

"""
Load modules
"""
def load_modules(url, http_request_method, filename):

  # Check if defined the shellshock module
  if menu.options.shellshock :
    try:
      # The shellshock module
      from src.core.modules.shellshock import shellshock
      # The shellshock handler
      shellshock.shellshock_handler(url, http_request_method, filename)
    except ImportError as err_msg:
      settings.print_data_to_stdout("\n" + settings.print_critical_msg(err_msg))
      raise SystemExit()
    raise SystemExit()