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

from src.utils import settings
from src.core.controller import checks

"""
About: Replaces single quotes (') with the fullwidth apostrophe (U+FF07, '＇') in a given payload.
Notes: This tamper script works against target(s) that strip or escape a literal quote before
       folding the value through a compatibility normalization (e.g. Python's
       'unicodedata.normalize("NFKC", ...)'). The fullwidth character is not the quote such a
       filter matches, so it passes through untouched, and the normalization applied afterwards
       folds it back into a real "'" - closing a quote the filter believed it had already removed.
References: [1] https://www.yeswehack.com/dojo/dojo-challenge-solution-46
"""

__tamper__ = "unicodequote"
__priority__ = settings.PRIORITY.LOWER

# Why this script cannot be applied to the target at hand, or nothing where it can.
def dependencies():
  return checks.tamper_dep_eval_incompatible(__tamper__) or checks.tamper_dep_unix_only(__tamper__)

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

# Fold every single quote into the fullwidth apostrophe a later normalization step reads as one.
def tamper(payload):
  return payload.replace("'", "＇")

# eof
