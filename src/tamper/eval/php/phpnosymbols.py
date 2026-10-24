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
About: Rewrites the three places a PHP eval-sink payload still carries a digit, a quote or a semicolon, for a target rejecting all three at once (along with '$' and '_', which the payload never needed in the first place).
Notes: This tamper script works against target(s) evaluating PHP (i.e. option '--eval=php').
       A literal integer becomes a parenthesised sum of 'true' added to itself, since a boolean is an
       integer the moment arithmetic or a comparison is done on it; the empty string a halted
       condition answers with becomes the keyword 'NULL', read back by '.' concatenation as the same
       nothing a quoted empty string would; a trailing statement terminator becomes a closing PHP tag,
       which ends a statement exactly as a semicolon would and needs none of its own. None of the
       three touches a backtick-run shell command - a digit or a space in there is that technique's
       own concern, left to a tamper such as 'space2htab' to answer for.
Reference: https://ctftime.org/writeup/40411
"""

__tamper__ = "phpnosymbols"
__priority__ = settings.PRIORITY.NORMAL

def dependencies():
  return checks.tamper_dep_command_incompatible(__tamper__) or checks.tamper_dep_grammar_only(__tamper__, "php")

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

# A literal integer, spelled as that many 'true's added together - still an integer the moment
# anything arithmetic or comparative is done with it, and never a digit on the way there.
def _digitless(match):
  return "(" + "+".join(["true"] * int(match.group(0))) + ")"

_INTEGER_LITERAL = re.compile(r"\d+")
_EMPTY_STRING = re.compile(r"\?(?:\"\"|'')\:exit\(\)")

# One run of PHP-level code - never what a backtick-quoted shell command is written in.
def _rewrite_php_span(span):
  span = _INTEGER_LITERAL.sub(_digitless, span)
  span = _EMPTY_STRING.sub("?NULL:exit()", span)
  return span

def tamper(payload):
  if settings.EVAL_GRAMMAR.NAME != "php":
    return payload
  # Backticks alternate PHP-level code with the shell command it runs - odd positions are the
  # commands themselves, left exactly as every other tamper script already left them.
  parts = payload.split("`")
  for index in range(0, len(parts), 2):
    parts[index] = _rewrite_php_span(parts[index])
  payload = "`".join(parts)
  # The grammar's own statement terminator, said only once and only at the very end - a closing
  # PHP tag ends the statement it follows exactly as that character would, and reopening it is
  # only needed where something is meant to run after it, which nothing here ever is.
  if payload.endswith(";"):
    payload = payload[:-1] + "?>"
  return payload

# eof
