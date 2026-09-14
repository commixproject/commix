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

"""
What code injection looks like in each language commix can reach: how a payload breaks into a
string the application evaluates, how it closes again, and which of that language's own functions
run a command. It is the technique that decides how execution is proven, so none of this belongs
to one - a module here is used by whichever technique carries it.
"""

from src.core.eval.grammars import php
from src.core.eval.grammars import python

LANGUAGES = {php.NAME: php, python.NAME: python}

"""
The languages that can be named with '--eval'.
"""
def supported():
  return tuple(sorted(LANGUAGES))

"""
The grammar for one language, or the only one there is where none was named.
"""
def grammar(language=None):
  return LANGUAGES.get(language) or LANGUAGES[php.NAME]

# eof
