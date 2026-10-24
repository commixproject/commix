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
About: Rewrites a bare command name in a given payload as a filename glob of the same length ('echo' -> '/???/????'), resolved by the shell against '/bin' rather than typed as a word.
Notes: This only reaches a target whose '/bin' holds exactly one file of that length - every POSIX
       shell keyword capable of trying more than one candidate ('for', 'while', 'case', 'set') is
       itself spelled in letters a filter blocking all of them also blocks, so an ambiguous match
       (several files sharing the word's length) is left as the glob and fails outright. Only a
       bare name is rewritten, the same restriction 'cmd2wildcard' documents for a path already
       written out in full - this script's own job starts where that one's leaves off.
Reference: https://www.secjuice.com/web-application-firewall-waf-evasion/
"""

__tamper__ = "noletters"
__priority__ = settings.PRIORITY.LOW

# Why this script cannot be applied to the target at hand, or nothing where it can.
def dependencies():
  # 'tamper_shell_spans' reads quoting the way a shell does, which an evaluated language's own
  # string/call syntax is not - a payload for '--eval' would come back with its own calls globbed.
  return checks.tamper_dep_eval_incompatible(__tamper__) or checks.tamper_dep_unix_only(__tamper__)

# A bare command name: letters only, not a path, not a variable or quoted word already.
NOLETTERS_WORD = r"(?<![\w$'\"\\{#=/.-])[A-Za-z]{2,}(?![\w=.'\"-])"

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

def _glob(match):
  """
  One word written as the glob the shell expands against '/bin' and runs, or left as it was.

  A word the shell has to read exactly as it was written is left alone, for the reason
  'tamper_word_kept' gives - it would no longer be itself once a glob stood in its place.
  """
  word = match.group(0)
  if checks.tamper_word_kept(word, match.string[:match.start()]):
    return word
  return "/???/" + "?" * len(word)

# Every bare command name in one span of shell code, written as a glob of the same length.
def _glob_words(text, nested):
  return re.sub(NOLETTERS_WORD, _glob, text)

# Hand the command name over as a glob, for the target's shell to resolve against '/bin'.
def tamper(payload):
  # A target settled as Windows after this script was accepted: 'cmd.exe' globs nothing on its own.
  if settings.TARGET_OS == settings.OS.WINDOWS:
    return payload
  return checks.tamper_shell_spans(payload, _glob_words)

# eof
