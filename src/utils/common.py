#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (http://commixproject.com).
Copyright (c) 2014-2018 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
 
For more see the file 'readme/COPYING' for copying permission.
"""

import re
import os
import sys
import traceback
from src.utils import settings
from src.thirdparty.colorama import Fore, Back, Style, init

"""
Returns detailed message about occurred unhandled exception
"""
def unhandled_exception():
  err_msg = "Unhandled exception occurred in '" + settings.VERSION[1:] + "'. It is recommended to retry your "
  err_msg += "run with the latest (dev) version from official GitHub "
  err_msg += "repository at '" + settings.GIT_URL + "'. If the exception persists, please open a new issue "
  err_msg += "at '" + settings.ISSUES_PAGE + "' "
  err_msg += "with the following text and any other information required to "
  err_msg += "reproduce the bug. The "
  err_msg += "developers will try to reproduce the bug, fix it accordingly "
  err_msg += "and get back to you.\n"
  err_msg += "Commix version: " + settings.VERSION[1:] + "\n"
  err_msg += "Python version: " + settings.PYTHON_VERSION + "\n"
  err_msg += "Operating system: " + os.name + "\n"
  err_msg += "Command line: " + re.sub(r".+?\bcommix\.py\b", "commix.py", " ".join(sys.argv)) + "\n"
  exc_msg = str(traceback.format_exc())
  print settings.print_critical_msg(err_msg + "\n" + exc_msg.rstrip()) 

# eof