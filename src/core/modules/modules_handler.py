#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of commix (@commixproject) tool.
Copyright (c) 2014-2015 Anastasios Stasinopoulos (@ancst).
https://github.com/stasinopoulos/commix

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

  # Check if defined the icmp exfiltration module
  if menu.options.ip_icmp_data :
    try:
      # The icmp exfiltration module
      from src.core.modules.icmp_exfiltration import icmp_exfiltration
      # The icmp exfiltration handler
      icmp_exfiltration.icmp_exfiltration_handler(url, http_request_method)
    except ImportError as e:
      print "\n" + Back.RED + "(x) Error: " + str(e) + Style.RESET_ALL
      sys.exit(0) 
    sys.exit(0)

  # Check if defined the icmp exfiltration module
  if menu.options.shellshock :
    try:
      # The Shellshock module
      from src.core.modules.shellshock import shellshock
      # The Shellshock handler
      shellshock.shellshock_handler(url, http_request_method, filename)
    except ImportError as e:
      print "\n" + Back.RED + "(x) Error: " + str(e) + Style.RESET_ALL
      sys.exit(0) 
    sys.exit(0) 