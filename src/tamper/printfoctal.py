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
About: Rewrites the command names and paths in a given payload as a command substitution of printf's own octal escapes ($(printf '\143\141\164')).
Notes: Unlike 'ansiquote'/'ansiquoteoctal', this needs nothing a strict POSIX shell (e.g. 'dash',
       the '/bin/sh' of most Debian/Ubuntu targets) does not already have - no ANSI-C quoting, just
       "$()" and a "printf" whose octal escapes POSIX itself requires.
References: [1] https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Command%20Injection/README.md
"""

__tamper__ = "printfoctal"
__priority__ = settings.PRIORITY.HIGH

def dependencies():
  """
  Why this script cannot be applied to the target at hand, or nothing where it can.

  The escapes are the whole point of the script, and an evaluated string is read by the language
  doing the evaluating before ever reaching a shell - which spends '\\143' itself, leaving the
  shell (which never runs) a payload that says something else.
  """
  return checks.tamper_dep_eval_incompatible(__tamper__) or checks.tamper_dep_unix_only(__tamper__)

# A word worth hiding: a command name or a path, which is what a signature is written against.
PRINTF_OCTAL_WORD = r"(?<![\w$'\"\\{#=/.-])(/?[A-Za-z][\w.-]*(?:/[\w.-]+)*|/[\w.-]+(?:/[\w.-]+)*)(?![\w=.'\"-])"

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

def _printf_octal(match):
  """
  One word written as the "$(printf ...)" the shell runs and reads back as that word, or left as
  it was.

  A word the shell has to read exactly as it was written is left alone, for the reason
  'tamper_word_kept' gives. Nothing else here needs to survive being spelled differently, because
  the substitution runs and is replaced before anything reads the word.
  """
  word = match.group(0)
  if checks.tamper_word_kept(word, match.string[:match.start()]):
    return word
  return "$(printf '" + "".join("\\%03o" % ord(char) for char in word) + "')"

# Every command name and path in one span of shell code, written as a printf octal substitution.
def _printf_octal_words(text, nested):
  return re.sub(PRINTF_OCTAL_WORD, _printf_octal, text)

# Hand the words over as a printf substitution, for the target's shell to run and read back as the words they were.
def tamper(payload):
  # A target settled as Windows after this script was accepted: 'cmd.exe' has no command substitution of this kind.
  if settings.TARGET_OS == settings.OS.WINDOWS:
    return payload
  return checks.tamper_shell_spans(payload, _printf_octal_words)

# eof
