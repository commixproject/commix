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
import random
import httplib
import urllib2

from socket import error as SocketError

# Disable SSL verification.
# For python versions 2.7.9 or above.
import ssl
try:
  _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
  # Legacy Python that doesn't verify HTTPS certificates by default
  pass
else:
  # Handle target environment that doesn't support HTTPS verification
  ssl._create_default_https_context = _create_unverified_https_context

from src.utils import menu
from src.utils import logs
from src.utils import update
from src.utils import version
from src.utils import install
from src.utils import settings
from src.utils import session_handler

from src.thirdparty.colorama import Fore, Back, Style, init

from src.core.requests import tor
from src.core.requests import proxy
from src.core.requests import headers
from src.core.requests import requests
from src.core.requests import authentication

from src.core.injections.controller import checks
from src.core.injections.controller import parser
from src.core.injections.controller import controller

# use Colorama to make Termcolor work on Windows too :)
if settings.IS_WINDOWS:
  init()

"""
The main function
"""
def main():
  try:
    # Check if defined "--version" option.
    if menu.options.version:
      version.show_version()
      sys.exit(0)

    # Checkall the banner
    menu.banner()
        
    # Check python version number.
    version.python_version()

    # Check if defined "--dependencies" option. 
    # For checking (non-core) third party dependenices.
    if menu.options.noncore_dependencies:
      checks.third_party_dependencies()
      sys.exit(0)
      
    # Check if defined "--update" option.        
    if menu.options.update:
      update.updater()
      sys.exit(0)
        
    # Check if defined "--install" option.        
    if menu.options.install:
      install.installer()
      sys.exit(0)
    
    # Check arguments
    if len(sys.argv) == 1:
      menu.parser.print_help()
      print ""
      sys.exit(0)

    # Define the level of verbosity.
    if menu.options.verbose > 1:
      err_msg = "The value for option '-v' "
      err_msg += "must be an integer value from range [0, 1]."
      print settings.print_critical_msg(err_msg)
      sys.exit(0)
    else:  
      settings.VERBOSITY_LEVEL = menu.options.verbose

    # Check if defined "--delay" option.
    if menu.options.delay:
      if menu.options.delay > "0":
        settings.DELAY = menu.options.delay

    # Define the level of tests to perform.
    if menu.options.level > 3:
      err_msg = "The value for option '--level' "
      err_msg += "must be an integer value from range [1, 3]."
      print settings.print_critical_msg(err_msg)
      sys.exit(0)

    # Parse target / data from HTTP proxy logs (i.e Burp / WebScarab).
    if menu.options.logfile:
      parser.logfile_parser()
 
    # Modification on payload
    if not menu.options.shellshock:
      #settings.CURRENT_USER = "echo $(" + settings.CURRENT_USER + ")"
      settings.SYS_USERS  = "echo $(" + settings.SYS_USERS + ")"
      settings.SYS_PASSES  = "echo $(" + settings.SYS_PASSES + ")"

    # Check provided parameters for tests
    if menu.options.test_parameter:
      if menu.options.test_parameter.startswith("="):
        menu.options.test_parameter = menu.options.test_parameter[1:]
      settings.TEST_PARAMETER = menu.options.test_parameter.split(settings.PARAMETER_SPLITTING_REGEX)
      for i in range(0,len(settings.TEST_PARAMETER)):
        if "=" in settings.TEST_PARAMETER[i]:
          settings.TEST_PARAMETER[i] = settings.TEST_PARAMETER[i].split("=")[0]

    # Check if defined character used for splitting parameter values.
    if menu.options.pdel:
     settings.PARAMETER_DELIMITER = menu.options.pdel

    # Check if defined character used for splitting cookie values.
    if menu.options.cdel:
     settings.COOKIE_DELIMITER = menu.options.cdel

    # Check if specified wrong injection technique
    if menu.options.tech and menu.options.tech not in settings.AVAILABLE_TECHNIQUES:
      found_tech = False
      # Convert injection technique(s) to lowercase
      menu.options.tech = menu.options.tech.lower()
      # Check if used the ',' separator
      if settings.PARAMETER_SPLITTING_REGEX in menu.options.tech:
        split_techniques_names = menu.options.tech.split(settings.PARAMETER_SPLITTING_REGEX)
      else:
        split_techniques_names = menu.options.tech.split()
      if split_techniques_names:
        for i in range(0,len(split_techniques_names)):
          if len(menu.options.tech) <= 4:
            split_first_letter = list(menu.options.tech)
            for j in range(0,len(split_first_letter)):
              if split_first_letter[j] in settings.AVAILABLE_TECHNIQUES:
                found_tech = True
              else:  
                found_tech = False  
                          
      if split_techniques_names[i].replace(' ', '') not in settings.AVAILABLE_TECHNIQUES and \
         found_tech == False:
        err_msg = "You specified wrong value '" + split_techniques_names[i] 
        err_msg += "' as injection technique. "
        err_msg += "The value, must be a string composed by the letters (C)lassic, (E)val-based, "
        err_msg += "(T)ime-based, (F)ile-based (with or without commas)."
        print settings.print_critical_msg(err_msg)
        sys.exit(0)

    # Check if specified wrong alternative shell
    if menu.options.alter_shell:
      if menu.options.alter_shell.lower() not in settings.AVAILABLE_SHELLS:
        err_msg = "'" + menu.options.alter_shell + "' shell is not supported!"
        print settings.print_critical_msg(err_msg)
        sys.exit(0)

    # Check the file-destination
    if menu.options.file_write and not menu.options.file_dest or \
    menu.options.file_upload  and not menu.options.file_dest:
      err_msg = "Host's absolute filepath to write and/or upload, must be specified (--file-dest)."
      print settings.print_critical_msg(err_msg)
      sys.exit(0)

    if menu.options.file_dest and menu.options.file_write == None and menu.options.file_upload == None :
      err_msg = "You must enter the '--file-write' or '--file-upload' parameter."
      print settings.print_critical_msg(err_msg)
      sys.exit(0)

    # Check if defined "--file-upload" option.
    if menu.options.file_upload:
      # Check if not defined URL for upload.
      if not re.match(settings.VALID_URL_FORMAT, menu.options.file_upload):
        err_msg = "The '" + menu.options.file_upload + "' is not a valid URL. "
        print settings.print_critical_msg(err_msg)
        sys.exit(0)
        
    # Check if defined "--random-agent" option.
    if menu.options.random_agent:
      menu.options.agent = random.choice(settings.USER_AGENT_LIST)
  
    # Check if defined "--url" option.
    if menu.options.url:
      url = menu.options.url
      
      # Check if http / https
      url = checks.check_http_s(url)

      if menu.options.output_dir:
        output_dir = menu.options.output_dir
      else:
        output_dir = settings.OUTPUT_DIR
      
      # One directory up, if Windows or if the script is being run under "/src".
      if settings.IS_WINDOWS or "/src" in os.path.dirname(os.path.abspath(__file__)):
        os.chdir("..")
        
      output_dir = os.path.dirname(output_dir)
     
      try:
        os.stat(output_dir)
      except:
        os.mkdir(output_dir)   

      # The logs filename construction.
      filename = logs.create_log_file(url, output_dir)
      try:
        
        # Check if defined POST data
        if menu.options.data:
          request = urllib2.Request(url, menu.options.data)
        else:
          request = urllib2.Request(url)

        headers.do_check(request)  
        
        # Check if defined any HTTP Proxy (--proxy option).
        if menu.options.proxy:
          proxy.do_check(url)
        
        # Check if defined Tor (--tor option).
        elif menu.options.tor:
          tor.do_check()
        info_msg = "Checking connection to the target URL... "  
        sys.stdout.write(settings.print_info_msg(info_msg))
        sys.stdout.flush()

        try:
          # Check if defined any HTTP Proxy (--proxy option).
          if menu.options.proxy:
            response = proxy.use_proxy(request)
          # Check if defined Tor (--tor option).  
          elif menu.options.tor:
            response = tor.use_tor(request)
          else:
            try:
              response = urllib2.urlopen(request)
            except ValueError:
              # Invalid format for the '--headers' option.
              print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"
              err_msg = "Use '--headers=\"HEADER_NAME:HEADER_VALUE\"' "
              err_msg += "to provide an HTTP header or"
              err_msg += " '--headers=\"HEADER_NAME:" + settings.WILDCARD_CHAR  + "\"' "
              err_msg += "if you want to try to exploit the provided HTTP header."
              print settings.print_critical_msg(err_msg)
              sys.exit(0)
        except:
          raise

        html_data = content = response.read()
        print "[ " + Fore.GREEN + "SUCCEED" + Style.RESET_ALL + " ]"

        # Check for CGI scripts on url
        checks.check_CGI_scripts(url)

        # Used a valid pair of valid credentials
        if menu.options.auth_cred:
          success_msg = Style.BRIGHT + "Identified a valid pair of credentials '" 
          success_msg += menu.options.auth_cred + Style.RESET_ALL 
          success_msg += Style.BRIGHT + "'." + Style.RESET_ALL
          print settings.print_success_msg(success_msg)

        try:
          if response.info()['server'] :
            server_banner = response.info()['server']
            found_os_server = False
            if menu.options.os and checks.user_defined_os():
              user_defined_os = settings.TARGET_OS

            for i in range(0,len(settings.SERVER_OS_BANNERS)):
              if settings.SERVER_OS_BANNERS[i].lower() in server_banner.lower():
                found_os_server = True
                settings.TARGET_OS = settings.SERVER_OS_BANNERS[i].lower()
                if settings.TARGET_OS == "win" or settings.TARGET_OS == "microsoft" :
                  identified_os = "Windows"
                  if menu.options.os and user_defined_os != "win":
                    if not checks.identified_os():
                      settings.TARGET_OS = user_defined_os

                  settings.TARGET_OS = identified_os[:3].lower()
                  if menu.options.shellshock:
                    err_msg = "The shellshock module is not available for " 
                    err_msg += identified_os + " targets."
                    print settings.print_critical_msg(err_msg)
                    raise SystemExit()
                else:
                  identified_os = "Unix-like (" + settings.TARGET_OS + ")"
                  if menu.options.os and user_defined_os == "win":
                    if not checks.identified_os():
                      settings.TARGET_OS = user_defined_os

            found_server_banner = False
            if settings.VERBOSITY_LEVEL >= 1:
              info_msg = "Identifying the target server... " 
              sys.stdout.write(settings.print_info_msg(info_msg))
              sys.stdout.flush()

            for i in range(0,len(settings.SERVER_BANNERS)):
              if settings.SERVER_BANNERS[i].lower() in server_banner.lower():
                if settings.VERBOSITY_LEVEL >= 1:
                  print "[ " + Fore.GREEN + "SUCCEED" + Style.RESET_ALL + " ]"
                if settings.VERBOSITY_LEVEL >= 1:
                  success_msg = "The server was identified as " 
                  success_msg += server_banner + Style.RESET_ALL + "."
                  print settings.print_success_msg(success_msg)
                settings.SERVER_BANNER = server_banner
                found_server_banner = True
                # Set up default root paths
                if settings.SERVER_BANNERS[i].lower() == "apache":
                  if settings.TARGET_OS == "win":
                    settings.SRV_ROOT_DIR = "\\htdocs"
                  else:
                    settings.SRV_ROOT_DIR = "/var/www"
                if settings.SERVER_BANNERS[i].lower() == "nginx": 
                  settings.SRV_ROOT_DIR = "/usr/share/nginx"
                if settings.SERVER_BANNERS[i].lower() == "microsoft-iis":
                  settings.SRV_ROOT_DIR = "\\inetpub\\wwwroot"
                break

            if not found_server_banner:
              if settings.VERBOSITY_LEVEL >= 1:
                print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"
              warn_msg = "Heuristics have failed to identify server."
              print settings.print_warning_msg(warn_msg)
            
            # Load tamper scripts
            if menu.options.tamper:
              checks.tamper_scripts()

            # Store the Server's root dir
            settings.DEFAULT_SRV_ROOT_DIR = settings.SRV_ROOT_DIR

            if menu.options.is_admin or menu.options.is_root and not menu.options.current_user:
              menu.options.current_user = True

            # Check for wrong flags.
            if settings.TARGET_OS == "win":
              if menu.options.is_root :
                warn_msg = "Swithing '--is-root' to '--is-admin' because the "
                warn_msg += "target has been identified as windows."
                print settings.print_warning_msg(warn_msg)
              if menu.options.passwords:
                warn_msg = "The '--passwords' option, is not yet available for Windows targets."
                print settings.print_warning_msg(warn_msg)  
              if menu.options.file_upload :
                warn_msg = "The '--file-upload' option, is not yet available for windows targets. "
                warn_msg += "Instead, use the '--file-write' option."
                print settings.print_warning_msg(warn_msg)  
                sys.exit(0)
            else: 
              if menu.options.is_admin : 
                warn_msg = "Swithing the '--is-admin' to '--is-root' because "
                warn_msg += "the target has been identified as unix-like. "
                print settings.print_warning_msg(warn_msg)  
            
            if found_os_server == False and \
               not menu.options.os:
              # If "--shellshock" option is provided then,
              # by default is a Linux/Unix operating system.
              if menu.options.shellshock:
                pass 
              else:
                warn_msg = "Heuristics have failed to identify server's operating system."
                print settings.print_warning_msg(warn_msg)
                while True:
                  question_msg = "Do you recognise the server's operating system? "
                  question_msg += "[(W)indows/(U)nix/(q)uit] > "
                  sys.stdout.write(settings.print_question_msg(question_msg))
                  got_os = sys.stdin.readline().replace("\n","").lower()
                  if got_os.lower() in settings.CHOICE_OS :
                    if got_os.lower() == "w":
                      settings.TARGET_OS = "win"
                      break
                    elif got_os.lower() == "u":
                      break
                    elif got_os.lower() == "q":
                      raise SystemExit()
                  else:
                    if got_os == "":
                      got_os = "enter"
                    err_msg = "'" + got_os + "' is not a valid answer."  
                    print settings.print_error_msg(err_msg)
                    pass

            if not menu.options.os:
              if found_server_banner == False:
                warn_msg = "The server which was identified as " 
                warn_msg += server_banner + " seems unknown."
                print settings.print_warning_msg(warn_msg)
          else:
            found_os_server = checks.user_defined_os()
        except KeyError:
          pass

        # Charset detection.
        requests.charset_detection(response)

      except urllib2.HTTPError, e:
        # Check the codes of responses
        if e.getcode() == 500:
          print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"
          content = e.read()
          sys.exit(0)

        # Check for HTTP Error 401 (Unauthorized).
        elif e.getcode() == 401:
          try:
            # Get the auth header value
            auth_line = e.headers.get('www-authenticate', '')
            # Checking for authentication type name.
            auth_type = auth_line.split()[0]
            settings.SUPPORTED_HTTP_AUTH_TYPES.index(auth_type.lower())
            # Checking for the realm attribute.
            try: 
              auth_obj = re.match('''(\w*)\s+realm=(.*)''', auth_line).groups()
              realm = auth_obj[1].split(',')[0].replace("\"", "")
            except:
              realm = False

          except ValueError:
            print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"
            err_msg = "The identified HTTP authentication type (" + auth_type + ") "
            err_msg += "is not yet supported."
            print settings.print_critical_msg(err_msg) + "\n"
            sys.exit(0)

          except IndexError:
            print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"
            err_msg = "The provided pair of " + menu.options.auth_type 
            err_msg += " HTTP authentication credentials '" + menu.options.auth_cred + "'"
            err_msg += " seems to be invalid."
            print settings.print_critical_msg(err_msg)
            sys.exit(0) 

          print "[ " + Fore.GREEN + "SUCCEED" + Style.RESET_ALL + " ]"
          if menu.options.auth_type and menu.options.auth_type != auth_type.lower():
            if checks.identified_http_auth_type(auth_type):
              menu.options.auth_type = auth_type.lower()
          else:
            menu.options.auth_type = auth_type.lower()

          # Check for stored auth credentials.
          if not menu.options.auth_cred:
            try:
              stored_auth_creds = session_handler.export_valid_credentials(url, auth_type.lower())
            except:
              stored_auth_creds = False
            if stored_auth_creds:
              menu.options.auth_cred = stored_auth_creds
              success_msg = "Identified a valid pair of credentials '"  
              success_msg += menu.options.auth_cred + Style.RESET_ALL + Style.BRIGHT  + "'."
              print settings.print_success_msg(success_msg)
            else:  
              # Basic authentication 
              if menu.options.auth_type == "basic":
                if not menu.options.ignore_401:
                  warn_msg = "(" + menu.options.auth_type.capitalize() + ") " 
                  warn_msg += "HTTP authentication credentials are required."
                  print settings.print_warning_msg(warn_msg)
                  while True:
                    question_msg = "Do you want to perform a dictionary-based attack? [Y/n/q] > "
                    sys.stdout.write(settings.print_question_msg(question_msg))
                    crack_creds = sys.stdin.readline().replace("\n","").lower()
                    if crack_creds in settings.CHOICE_YES:
                      auth_creds = authentication.http_auth_cracker(url, realm)
                      if auth_creds != False:
                        menu.options.auth_cred = auth_creds
                        settings.REQUIRED_AUTHENTICATION = True
                        break
                      else:
                        sys.exit(0)
                    elif crack_creds in settings.CHOICE_NO:
                      checks.http_auth_err_msg()
                    elif crack_creds in settings.CHOICE_QUIT:
                      sys.exit(0)
                    else:
                      if crack_creds == "":
                        crack_creds = "enter"
                      err_msg = "'" + crack_creds + "' is not a valid answer."  
                      print settings.print_error_msg(err_msg)
                      pass

              # Digest authentication         
              elif menu.options.auth_type == "digest":
                if not menu.options.ignore_401:
                  warn_msg = "(" + menu.options.auth_type.capitalize() + ") " 
                  warn_msg += "HTTP authentication credentials are required."
                  print settings.print_warning_msg(warn_msg)      
                  # Check if heuristics have failed to identify the realm attribute.
                  if not realm:
                    warn_msg = "Heuristics have failed to identify the realm attribute." 
                    print settings.print_warning_msg(warn_msg)
                  while True:
                    question_msg = "Do you want to perform a dictionary-based attack? [Y/n/q] > "
                    sys.stdout.write(settings.print_question_msg(question_msg))
                    crack_creds = sys.stdin.readline().replace("\n","").lower()
                    if crack_creds in settings.CHOICE_YES:
                      auth_creds = authentication.http_auth_cracker(url, realm)
                      if auth_creds != False:
                        menu.options.auth_cred = auth_creds
                        settings.REQUIRED_AUTHENTICATION = True
                        break
                      else:
                        sys.exit(0)
                    elif crack_creds in settings.CHOICE_NO:
                      checks.http_auth_err_msg()
                    elif crack_creds in settings.CHOICE_QUIT:
                      sys.exit(0)
                    else:
                      if crack_creds == "":
                        crack_creds = "enter"
                      err_msg = "'" + crack_creds + "' is not a valid answer."  
                      print settings.print_error_msg(err_msg)
                      pass
                  else:   
                    checks.http_auth_err_msg()      
          else:
            pass

        elif e.getcode() == 403:
          print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"
          err_msg = "You don't have permission to access this page."
          print settings.print_critical_msg(err_msg)
          sys.exit(0)
          
        elif e.getcode() == 404:
          print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"
          err_msg = "The host seems to be down!"
          print settings.print_critical_msg(err_msg)
          sys.exit(0)

        else:
          raise

      except urllib2.URLError, e:
        print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"
        err_msg = "The host seems to be down!"
        print settings.print_critical_msg(err_msg)
        sys.exit(0)
        
      except httplib.BadStatusLine, e:
        print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"
        if len(e.line) > 2 :
          print e.line, e.message
        pass

    else:
      err_msg = "You must specify the target URL."
      print settings.print_critical_msg(err_msg)
      sys.exit(0)

    # Retrieve everything from the supported enumeration options.
    if menu.options.enum_all:
      checks.enable_all_enumeration_options()

    # Launch injection and exploitation controller.
    controller.do_check(url, filename)

  except KeyboardInterrupt: 
    abort_msg = "Ctrl-C was pressed!"
    print "\n" + settings.print_abort_msg(abort_msg)
    if settings.SHOW_LOGS_MSG == True:
      logs.logs_notification(filename)
    print ""
    if menu.options.url:
      session_handler.clear(menu.options.url)
    sys.exit(0)

  except SystemExit: 
    if settings.SHOW_LOGS_MSG == True:
      logs.logs_notification(filename)
    print ""
    if menu.options.url:
      session_handler.clear(menu.options.url)
    sys.exit(0)
  
  # Accidental stop / restart of the target host server.
  except httplib.BadStatusLine, e:
    if e.line == "" or e.message == "":
      err_msg = "The target host is not responding."
      err_msg += " Please ensure that is up and try again."
      print "\n\n" + settings.print_critical_msg(err_msg) 
      if settings.SHOW_LOGS_MSG == True:
        logs.logs_notification(filename)
      print ""
      sys.exit(0)      
    else: 
      err_msg = e.line + e.message
      print settings.print_critical_msg(err_msg) + "\n"
    session_handler.clear(url)  
    sys.exit(0)

  # Connection reset by peer
  except SocketError, e:
    if settings.VERBOSITY_LEVEL >= 1:
      print ""
    err_msg = "The target host is not responding."
    err_msg += " Please ensure that is up and try again."
    print "\n" + settings.print_critical_msg(err_msg) 
    if settings.SHOW_LOGS_MSG == True:
      logs.logs_notification(filename)
    print ""
    session_handler.clear(url)
    sys.exit(0)
    
if __name__ == '__main__':
    main()
    
#eof