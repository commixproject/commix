#!/usr/bin/env python
# encoding: UTF-8

"""
 This file is part of commix (@commixproject) tool.
 Copyright (c) 2015 Anastasios Stasinopoulos (@ancst).
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
from src.utils import colors

try:
  from src.core.modules import ICMP_Exfiltration
except ImportError as e:
  print "\n" + colors.BGRED + "(x) Error:",e
  print colors.RESET
  sys.exit(1)

def load_modules(url,http_request_method):
  # Load the module ICMP_Exfiltration
  if menu.options.ip_icmp_data:
    # The ICMP Exfiltration handler
    ICMP_Exfiltration.icmp_exfiltration_handler(url,http_request_method)