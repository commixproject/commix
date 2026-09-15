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
About: Rewrites the command names and paths in a given payload as ANSI-C quoted hex ($'\x63\x61\x74').
Notes: This tamper script works against target(s) whose shell reads ANSI-C quoting (e.g. 'bash',
       'ksh', 'zsh'), which leaves no command name or path spelled out in the payload.
References: [1] https://www.secjuice.com/web-application-firewall-waf-evasion/
"""

__tamper__ = "ansiquote"
__priority__ = settings.PRIORITY.HIGH

def dependencies():
  """
  Why this script cannot be applied to the target at hand, or nothing where it can.

  The escapes are the whole point of the script, and an evaluated string is read by the language
  doing the evaluating before ever reaching a shell - which spends '\\x63' itself, leaving the
  shell a payload that says something else.
  """
  return checks.tamper_dep_eval_incompatible(__tamper__) or checks.tamper_dep_unix_only(__tamper__)

# A word worth hiding: a command name or a path, which is what a signature is written against.
ANSI_QUOTE_WORD = r"(?<![\w$'\"\\{#=/.-])(/?[A-Za-z][\w.-]*(?:/[\w.-]+)*|/[\w.-]+(?:/[\w.-]+)*)(?![\w=.'\"-])"

# A name the shell assigns to rather than reads: it is spelled out or it is not a name at all. The
# separator is whatever the payload was built with, a held-aside '${IFS}' among it.
ANSI_QUOTE_ASSIGNED_NAME = r"\b(?:for|read)(?:\s|" + checks.SHELL_SPAN_HELD_REGEX + r")*$"

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

def _ansi_quote(match):
  """
  One word written as the hex the shell reads back as that word, or left as it was.

  A shell keyword is left alone for the reason 'IGNORE_TAMPER_TRANSFORMATION' exists: it stops
  being a keyword once it is quoted, and the payload loses the loop or the branch it was built
  around. Nothing else here needs to survive being spelled differently, because the shell spends
  the quoting before anything reads the word.
  """
  word = match.group(0)
  if word in settings.IGNORE_TAMPER_TRANSFORMATION:
    return word
  if re.search(ANSI_QUOTE_ASSIGNED_NAME, match.string[:match.start()]):
    return word
  return "$'" + "".join("\\x%02x" % ord(char) for char in word) + "'"

# Every command name and path in one span of shell code, written as hex.
def _ansi_quote_words(text, nested):
  return re.sub(ANSI_QUOTE_WORD, _ansi_quote, text)

# Hand the words over as hex, for the target's shell to read back as the words they were.
def tamper(payload):
  # A target settled as Windows after this script was accepted: 'cmd.exe' has no ANSI-C quoting.
  if settings.TARGET_OS == settings.OS.WINDOWS:
    return payload
  return checks.tamper_shell_spans(payload, _ansi_quote_words)

# eof
