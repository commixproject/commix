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

from src.core.convert import hexencode
from src.thirdparty.six.moves import urllib as _urllib
from src.utils import settings
from src.core.controller import checks

"""
About: hex-encodes all characters in a given payload.
Notes: This tamper script works against all targets.
"""

__tamper__ = "hexencode"
__priority__ = settings.PRIORITY.LOWEST

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

"""
What this produces is a blob, not an expression - so an evaluated string has nothing to
evaluate, whichever language is doing the evaluating.
"""
def dependencies():
  return checks.tamper_dep_eval_incompatible(__tamper__)

# Hand the command over hex-encoded, for the target to decode and run.
def tamper(payload):
  checks.tamper_check_space2plus_conflict(__tamper__)
  payload = _urllib.parse.unquote(payload)
  encoded_payload, _ = hexencode(payload)
  if _:
    payload = encoded_payload
  return payload

# eof
