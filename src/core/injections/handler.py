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

import os
import sys
import time
import datetime

from src.utils import menu
from src.utils import colors
from src.utils import settings

from src.core.requests import authentication

from src.core.injections.results_based.techniques import classic
from src.core.injections.results_based.techniques import eval_based
from src.core.injections.blind_based.techniques import time_based
from src.core.injections.blind_based.techniques import boolean_based

"""
 Command Injection and exploitation handler.
 Checks if the testable parameter is exploitable.
"""

def do_check(url):

  # Print the findings to log file.
  parts = url.split('//', 1)
  host = parts[1].split('/', 1)[0]
  try:
      os.stat(settings.OUTPUT_DIR + host + "/")
  except:
      os.mkdir(settings.OUTPUT_DIR + host + "/") 
  
  filename = datetime.datetime.fromtimestamp(time.time()).strftime('%Y_%m_%d_%H_%M_%S')
  filename = settings.OUTPUT_DIR + host + "/" + filename
  output_file = open(filename + ".txt", "a")
  output_file.write("\n(+) Host : " + host)
  output_file.write("\n(+) Date : " + datetime.datetime.fromtimestamp(time.time()).strftime('%m/%d/%Y'))
  output_file.write("\n(+) Time : " + datetime.datetime.fromtimestamp(time.time()).strftime('%H:%M:%S'))
  output_file.close()

  # Check if defined "--delay" option.
  if menu.options.delay:
    delay = menu.options.delay
  else:
    delay = settings.DELAY
      
  # Do authentication if needed.
  if menu.options.auth_url and menu.options.auth_data:
    authentication.auth_process()
	    
  elif menu.options.auth_url or menu.options.auth_data: 
    print colors.RED + "(x) Error: You must specify both login panel URL and login parameters.\n" + colors.RESET
    sys.exit(0)
    
  else:
    pass
  
  # Check if defined method is POST.
  parameter = menu.options.data

  # Check if it is vulnerable to classic command injection technique.
  if menu.options.tech == "classic":
    if classic.exploitation(url,delay,filename) == False:
      if menu.options.method == "GET":
	print colors.RED + "(x) The '"+ url +"' appear to be not injectable." + colors.RESET
      else:
	print colors.RED + "(x) The '"+ parameter +"' appear to be not injectable." + colors.RESET
	
  # Check if it is vulnerable to eval-based command injection technique.
  elif menu.options.tech == "eval-based":
    if eval_based.exploitation(url,delay,filename) == False:
      if menu.options.method == "GET":
	print colors.RED + "(x) The '"+ url +"' appear to be not injectable." + colors.RESET
      else:
	print colors.RED + "(x) The '"+ parameter +"' appear to be not injectable." + colors.RESET
	
  # Check if it is vulnerable to time-based command injection technique.
  elif menu.options.tech == "time-based":
    if time_based.exploitation(url,delay,filename) == False:
      if menu.options.method == "GET":
	print colors.RED + "(x) The '"+ url +"' appear to be not injectable." + colors.RESET
      else:
	print colors.RED + "(x) The '"+ parameter +"' appear to be not injectable." + colors.RESET
	
  # Check if it is vulnerable to boolean-based command injection technique.
  elif menu.options.tech == "boolean-based":
    if boolean_based.exploitation(url,delay,filename) == False:
      if menu.options.method == "GET":
	print colors.RED + "(x) The '"+ url +"' appear to be not injectable." + colors.RESET
      else:
	print colors.RED + "(x) The '"+ parameter +"' appear to be not injectable." + colors.RESET
    
  else:
    # Automated command injection and exploitation.
    if classic.exploitation(url,delay,filename) == False:
	classic_state = False
    else:
      classic_state = True
      
    if eval_based.exploitation(url,delay,filename) == False:
      eval_based_state = False
    else:
      eval_based_state = True
      
    if time_based.exploitation(url,delay,filename) == False:
      time_based_state = False
    else:
      time_based_state = True
      
    if boolean_based.exploitation(url,delay,filename) == False:
      boolean_based_state = False
    else:
      boolean_based_state = True

    if classic_state == False and eval_based_state == False and time_based_state == False and boolean_based_state == False :
      if menu.options.method == "GET":
	print colors.RED + "(x) The '"+ url +"' appear to be not injectable." + colors.RESET
      else:
	print colors.RED + "(x) The '"+ parameter +"' appear to be not injectable." + colors.RESET
	    
  print "\n(*) The scan has finished successfully!"
  print "(*) Results can be found at : '" + os.getcwd() + "/" + filename +".txt' \n"
  sys.exit(0)
  
#eof