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

"""
About: Runs 'test's numeric comparisons ('-eq'/'-ne'/'-le'/'-ge'/'-lt'/'-gt') without a '-' of their own, for a target that strips a bare '-' outright.
Notes: This tamper script works against target(s) with a POSIX shell. Equality is read as '='/'!=', which agrees with '-eq'/'-ne' exactly for the plain, unpadded decimal integers commix always compares this way - it would not for a value written with a leading zero. Ordering has no dash-free spelling of its own in 'test', so it is read instead from 'expr's own comparison, whose "<="/">="/"<"/">" need no '-' either - quoted, since unquoted they are shell redirections.
References: [1] https://github.com/digininja/DVWA/blob/master/vulnerabilities/exec/source/high.php
"""

__tamper__ = "dashlesstest"
__priority__ = settings.PRIORITY.LOWER

# Why this script cannot be applied to the target at hand, or nothing where it can.
def dependencies():
  return checks.tamper_dep_eval_incompatible(__tamper__) or checks.tamper_dep_unix_only(__tamper__)

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

# The ordering operators, spelled the way 'expr' reads them rather than 'test'.
_ORDER_OPERATORS = {"-le": "<=", "-ge": ">=", "-lt": "<", "-gt": ">"}

"""
A '[ LEFT OP RIGHT ]' ordering test, rewritten around 'expr' instead. Which side holds the plain
integer and which the longer expression is not the same from one caller to the next - a length is
compared against a variable on either side, depending on which payload built the check - so neither
side is assumed to be the simple one. What is assumed is that this bracket is flat: nothing commix
writes for this ever nests a second '[' inside the one being rewritten, so the nearest '[ ' before
the operator and the nearest ' ]' after it are this same test's own boundary, however long either
side runs.
"""
def _rewrite_ordering(payload):
  for operator, symbol in _ORDER_OPERATORS.items():
    token = " " + operator + " "
    search_from = 0
    while True:
      op_index = payload.find(token, search_from)
      if op_index == -1:
        break
      open_bracket = payload.rfind("[ ", 0, op_index)
      close_bracket = payload.find(" ]", op_index + len(token))
      if open_bracket == -1 or close_bracket == -1:
        search_from = op_index + len(token)
        continue
      left = payload[open_bracket + 2:op_index]
      right = payload[op_index + len(token):close_bracket]
      replacement = "[ $(expr " + left + " '" + symbol + "' " + right + ") = 1 ]"
      payload = payload[:open_bracket] + replacement + payload[close_bracket + 2:]
      search_from = open_bracket + len(replacement)
  return payload

# Read every comparison the way 'test' does without its own operators' '-'.
def tamper(payload):
  payload = _rewrite_ordering(payload)
  return payload.replace(" -eq ", " = ").replace(" -ne ", " != ")

# eof
