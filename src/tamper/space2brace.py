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

"""
About: Replaces the space character (%20) with a brace expansion ({a,b}) in a given payload.
Notes: This tamper script works against target(s) whose shell expands '{a,b}' where a command is
       expected (e.g. 'bash', 'ksh'), which leaves the payload's commands with no whitespace.
References: [1] https://www.themiddleblue.com/2018/06/12/bypass-waf-using-brace-expansion/
"""

__tamper__ = "space2brace"
__priority__ = settings.PRIORITY.LOWER

# Why this script cannot be applied to the target at hand, or nothing where it can.
def dependencies():
  return checks.tamper_dep_unix_only(__tamper__)

# What a word may be made of and still come back out of the expansion as the word that went in.
BRACE_SAFE_WORD = r"^[A-Za-z0-9_.:=@%+~^/*?\[\]$(){}!,\x00-]+$"

"""
A run of words the shell would read as one command, and where such a run may begin and end.

Only a command is rewritten, never an argument list of the payload's own making: braces expand
wherever they are written, but only in command position does the result get read back as a command
and its arguments. A redirection ends the run rather than joining it - '> /tmp/x' is the shell's
own syntax and would come back out of the expansion as two arguments to the command. The space in
front of one goes all the same, since a single space left behind is all a filter needs: closing it
up is safe here and nowhere else, because what now ends the command is the '}' of a brace list,
where a digit would have turned '1 >file' into a redirection of the first file descriptor.

Where the payload itself begins is command position only inside a substitution. At the top level
that is the parameter's own value, still carrying whatever the target expects there, and a run
started on it would take that value into the command name.
"""
BRACE_RUN = r"(?P<lead>%s[ ]*)(?P<run>[^\s;&|`\n<>]+(?:[ ][^\s;&|`\n<>]+)+)(?P<gap>[ ]*)(?=$|[;&|`\n<>])"
BRACE_RUN_LEAD = r"[;&|`\n]"
BRACE_RUN_LEAD_NESTED = r"(?:^|[;&|`\n])"

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

def _brace_run(match):
  """
  One command written as a brace expansion, or left as it was where it cannot be.

  The shell splits '{a,b,c}' on the commas and on nothing else, so every word has to already be
  one word, and a single word would not expand at all. A word the shell has to read exactly as it
  was written is left alone, for the reason 'tamper_word_kept' gives.
  """
  words = match.group("run").split(settings.SINGLE_WHITESPACE)
  if len(words) < 2 or not all(re.match(BRACE_SAFE_WORD, word) for word in words):
    return match.group(0)
  if any(checks.tamper_word_kept(word) for word in words):
    return match.group(0)
  return match.group("lead") + "{" + ",".join(words) + "}"

# Every command in one span of shell code, written as a brace expansion.
def _brace_runs(text, nested):
  return re.sub(BRACE_RUN % (BRACE_RUN_LEAD_NESTED if nested else BRACE_RUN_LEAD), _brace_run, text)

# Hand each command over as a brace expansion, for the target's shell to split back on the commas.
def tamper(payload):
  # A target settled as Windows after this script was accepted: 'cmd.exe' has no brace expansion.
  if settings.TARGET_OS == settings.OS.WINDOWS:
    return payload
  return checks.tamper_shell_spans(payload, _brace_runs)

# eof
