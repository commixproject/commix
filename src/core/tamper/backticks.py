#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2023 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

import sys
from src.utils import settings

"""
About: Uses backticks instead of "$()" for commands substitution on the generated payloads.
Notes: This tamper script works against Unix-like target(s).
"""

__tamper__ = "backticks"

settings.TAMPER_SCRIPTS[__tamper__] = True
settings.USE_BACKTICKS = True
  
# eof 