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

# The command's output, trailing whitespace dropped as a shell's own substitution drops it.
def _output(cmd):
  return settings.EVAL_GRAMMAR.trim(settings.EVAL_GRAMMAR.run(cmd))

# A statement terminator, where the boundary being tested can carry one.
def _end(separator):
  return settings.EVAL_GRAMMAR.TERMINATOR if separator else ""

# Stated in the shell's spelling by every caller, so it is rewritten into the language's here.
def _as_expression(condition):
  for shell_operator, operator in settings.EVAL_GRAMMAR.COMPARISON.items():
    condition = condition.replace(settings.SINGLE_WHITESPACE + shell_operator + settings.SINGLE_WHITESPACE, operator)
  return condition

"""
A question whose answer is known, for telling a target that answers at all from one that does not.
"""
def condition_check(separator, holds=True):
  condition = "1" + settings.EVAL_GRAMMAR.COMPARISON["-eq"] + ("1" if holds else "2")
  return settings.EVAL_GRAMMAR.halt(condition) + _end(separator)

"""
The decision payload, which asks the target to print something unguessable and measure it.
"""
def decision(separator, TAG, output_length, holds=True):
  expected = str(output_length if holds else output_length + 1)
  condition = settings.EVAL_GRAMMAR.length(_output("echo " + TAG)) + settings.EVAL_GRAMMAR.COMPARISON["-eq"] + expected
  return settings.EVAL_GRAMMAR.halt(condition) + _end(separator)

"""
How many bytes the command's output is, asked so that it can be bisected.
"""
def get_length(separator, cmd, candidate_length, operator="-eq"):
  settings.USER_APPLIED_CMD = cmd
  condition = settings.EVAL_GRAMMAR.length(_output(cmd)) + settings.EVAL_GRAMMAR.COMPARISON[operator] + str(candidate_length)
  return settings.EVAL_GRAMMAR.halt(condition) + _end(separator)

"""
Whether the ordinal of the output's Nth byte is at or above this one, which is what bisects it.
"""
def get_char(separator, cmd, num_of_chars, ascii_char, operator="-le"):
  settings.USER_APPLIED_CMD = cmd
  # Counted from zero by the grammar, and from one by every technique that asks.
  condition = str(ascii_char) + settings.EVAL_GRAMMAR.COMPARISON[operator] + settings.EVAL_GRAMMAR.ordinal(_output(cmd), num_of_chars - 1)
  return settings.EVAL_GRAMMAR.halt(condition) + _end(separator)

# eof
