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

import re
from src.utils import settings
from src.core.controller import checks

r"""
About: Carries a payload through a replacement string, for a PHP sink evaluated by preg_replace().
Notes: This tamper script works against target(s) evaluating PHP (i.e. option '--eval=php').
References: [1] https://www.php.net/manual/en/function.preg-replace.php
"""

__tamper__ = "phpregreplace"

# Applied last, after every other script has finished shaping the payload: this is not another way
# of writing the payload but what carries whatever the payload ended up being, and a script running
# after it would write backslashes of its own that nothing is left to carry.
__priority__ = settings.PRIORITY.LOWEST

# Why this script cannot be applied to the target at hand, or nothing where it can.
def dependencies():
  return checks.tamper_dep_command_incompatible(__tamper__) or checks.tamper_dep_grammar_only(__tamper__, "php")

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

"""
A group the replacement string is read as naming, which the payload has to say it does not.

What preg_replace() evaluates is the replacement with its backreferences already filled in, and a
pattern that captured nothing fills them in with nothing: a command written '\141\142\143' reached
the sink as '123', each backslash and the two digits behind it spent on a group that was never
there. A backslash is written twice to arrive as the one character it was, and a dollar sign in
front of a digit - the other spelling of the same thing - is written behind one.
"""
BACKREFERENCE = r"\$(?=\{?\d)"

# Everything a replacement string is read for, written so it is read as itself instead.
def tamper(payload):
  return re.sub(BACKREFERENCE, lambda x: "\\$", payload.replace("\\", "\\\\"))

# eof
