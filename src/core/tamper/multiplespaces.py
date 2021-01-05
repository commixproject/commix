#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2021 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

import random
from src.utils import settings

"""
About: Adds multiple spaces around OS commands
Notes: Useful to bypass very weak and bespoke web application firewalls that has poorly written permissive regular expressions.
"""

__tamper__ = "multiplespaces"

settings.TAMPER_SCRIPTS[__tamper__] = True
settings.WHITESPACE[0] = settings.WHITESPACE[0] * random.randrange(2, 8)

# eof 