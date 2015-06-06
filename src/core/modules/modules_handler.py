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
from src.utils import settings
from src.thirdparty.colorama import Fore, Back, Style, init
  
def load_modules(url,http_request_method):
  # Check if defined the ICMP exfiltration module
  if menu.options.ip_icmp_data :
    try:
      # The ICMP_Exfiltration module
      from src.core.modules import ICMP_Exfiltration
      # The ICMP Exfiltration handler
      ICMP_Exfiltration.icmp_exfiltration_handler(url,http_request_method)
    except ImportError as e:
      print "\n" + Back.RED + "(x) Error : " + str(e) + Style.RESET_ALL
      sys.exit(1) 