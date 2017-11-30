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
import random
import httplib
import urllib2

from socket import error as SocketError

from urlparse import urlparse
from os.path import splitext

from src.utils import menu
from src.utils import logs
from src.utils import purge
from src.utils import update
from src.utils import version
from src.utils import install
from src.utils import crawler
from src.utils import settings
from src.utils import session_handler
from src.utils import simple_http_server

from src.thirdparty.colorama import Fore, Back, Style, init

from src.core.requests import tor
from src.core.requests import proxy
from src.core.requests import headers
from src.core.requests import requests
from src.core.requests import redirection
from src.core.requests import authentication

from src.core.injections.controller import checks
from src.core.injections.controller import parser
from src.core.injections.controller import controller

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

# Use Colorama to make Termcolor work on Windows too :)
if settings.IS_WINDOWS:
  init()

"""
Define HTTP User-Agent header.
"""
def user_agent_header():
  # Check if defined "--random-agent" option.
  if menu.options.random_agent:
    if (menu.options.agent != settings.DEFAULT_USER_AGENT) or menu.options.mobile:
      err_msg = "The option '--random-agent' is incompatible with option '--user-agent' or switch '--mobile'."
      print settings.print_critical_msg(err_msg)
      sys.exit(0)
    else:
      info_msg = "Fetching random HTTP User-Agent header... "  
      sys.stdout.write(settings.print_info_msg(info_msg))
      sys.stdout.flush()
      try:
        menu.options.agent = random.choice(settings.USER_AGENT_LIST)
        print "[ " + Fore.GREEN + "SUCCEED" + Style.RESET_ALL + " ]"
        success_msg = "The fetched random HTTP User-Agent header is '" + menu.options.agent + "'."  
        print settings.print_success_msg(success_msg)
      except:
        print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"
          
"""
Examine the request
"""
def examine_request(request):
  try:
    headers.check_http_traffic(request)
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
        # Invalid format for the '--header' option.
        if settings.VERBOSITY_LEVEL < 2:
          print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"
        err_msg = "Use '--header=\"HEADER_NAME: HEADER_VALUE\"'"
        err_msg += "to provide an extra HTTP header or"
        err_msg += " '--header=\"HEADER_NAME: " + settings.WILDCARD_CHAR  + "\"' "
        err_msg += "if you want to try to exploit the provided HTTP header."
        print settings.print_critical_msg(err_msg)
        sys.exit(0)
    return response

  except urllib2.HTTPError, err_msg:
    error_description = ""
    if len(str(err_msg).split(": ")[1]) == 0:
      error_description = "Non-standard HTTP status code" 
    err_msg = str(err_msg).replace(": "," (") + error_description + ")." 
    if menu.options.bulkfile:
      warn_msg = "Skipping URL '" + url + "' - " + err_msg
      print settings.print_warning_msg(warn_msg)
      if settings.EOF:
        print "" 
      return False  
    else:
      print settings.print_critical_msg(err_msg)
      raise SystemExit 

  except urllib2.URLError, e:
    err_msg = "Unable to connect to the target URL "
    err_msg += "(" + str(e.args[0]).split("] ")[1] + ")." 
    if menu.options.bulkfile:
      warn_msg = "Skipping URL '" + url + "' - " + err_msg
      print settings.print_critical_msg(warn_msg)
      if settings.EOF:
        print "" 
      return False 
    else:
      print settings.print_critical_msg(err_msg)
      raise SystemExit  

"""
Check internet connection before assessing the target.
"""
def check_internet(url):

  settings.CHECK_INTERNET = True
  settings.CHECK_INTERNET_ADDRESS = checks.check_http_s(url)
  info_msg = "Checking for internet connection... "
  sys.stdout.write(settings.print_info_msg(info_msg))
  sys.stdout.flush()
  if settings.VERBOSITY_LEVEL > 1:
    print ""
  try:
    request = urllib2.Request(settings.CHECK_INTERNET_ADDRESS)
    headers.do_check(request)
    # Check if defined any HTTP Proxy (--proxy option).
    if menu.options.proxy:
      proxy.do_check(settings.CHECK_INTERNET_ADDRESS)
    examine_request(request)
  except:
    warn_msg = "No internet connection detected."
    print settings.print_warning_msg(warn_msg)

"""
The init (URL) request.
"""
def init_request(url):

  # Define HTTP User-Agent header
  user_agent_header()
  # Check the internet connection (--check-internet switch).
  if menu.options.check_internet:
    check_internet(url)
  # Check if defined POST data
  if menu.options.data:
    settings.USER_DEFINED_POST_DATA = menu.options.data
    request = urllib2.Request(url, menu.options.data)
  else:
    request = urllib2.Request(url)
  headers.do_check(request)
  # Check if defined any HTTP Proxy (--proxy option).
  if menu.options.proxy:
    proxy.do_check(url)
  return request

"""
Get the URL response.
"""
def url_response(url):

  # Check if http / https
  url = checks.check_http_s(url)
  # Check if defined Tor (--tor option).
  if menu.options.tor and settings.TOR_CHECK_AGAIN:
    tor.do_check()
  if menu.options.bulkfile:
    settings.TOR_CHECK_AGAIN = False
    info_msg = "Setting URL '" + url + "' for tests. "  
    print settings.print_info_msg(info_msg)
  request = init_request(url)
  if settings.CHECK_INTERNET:
    settings.CHECK_INTERNET = False
  if settings.INIT_TEST == True:
    info_msg = "Checking connection to the target URL... "
    sys.stdout.write(settings.print_info_msg(info_msg))
    sys.stdout.flush()
    if settings.VERBOSITY_LEVEL >= 2:
      print ""
  response = examine_request(request)
  return response, url

"""
Injection states initiation.
"""
def init_injection(url):
  # Initiate injection checker.
  if settings.INJECTION_CHECKER:
    settings.INJECTION_CHECKER = False
  # Initiate exploitation techniques states.
  if settings.INJECTION_CHECKER:
    settings.CLASSIC_STATE = False
  if settings.EVAL_BASED_STATE:
    settings.EVAL_BASED_STATE = False
  if settings.TIME_BASED_STATE:
    settings.TIME_BASED_STATE = False
  if settings.FILE_BASED_STATE:
    settings.FILE_BASED_STATE = False
  if settings.TEMPFILE_BASED_STATE:
    settings.TEMPFILE_BASED_STATE = False
  if settings.TIME_RELATIVE_ATTACK:
    settings.TIME_RELATIVE_ATTACK = False

"""
Logs filename creation.
"""
def logs_filename_creation():
  if menu.options.output_dir:
    output_dir = menu.options.output_dir
  else:
    output_dir = settings.OUTPUT_DIR
  
  # One directory up, if the script is being run under "/src".
  # if "/src" in os.path.dirname(os.path.abspath(__file__)):
  #   os.chdir("..")
  output_dir = os.path.dirname(output_dir)
 
  try:
    os.stat(output_dir)
  except:
    os.mkdir(output_dir)   

  # The logs filename construction.
  filename = logs.create_log_file(url, output_dir)
  return filename

"""
The main function.
"""
def main(filename, url):
  try:
    # Ignore the mathematic calculation part (Detection phase).
    if menu.options.skip_calc:
      settings.SKIP_CALC = True

    if menu.options.enable_backticks:
      settings.USE_BACKTICKS = True

    # Target URL reload.
    if menu.options.url_reload and menu.options.data:
      settings.URL_RELOAD = True

    if menu.options.test_parameter and menu.options.skip_parameter:
      err_msg = "The options '-p' and '--skip' cannot be used "
      err_msg += "simultaneously (i.e. only one option must be set)."
      print settings.print_critical_msg(err_msg)
      raise SystemExit

    # Check provided parameters for tests
    elif menu.options.test_parameter or menu.options.skip_parameter:     
      if menu.options.test_parameter != None :
        if menu.options.test_parameter.startswith("="):
          menu.options.test_parameter = menu.options.test_parameter[1:]
        settings.TEST_PARAMETER = menu.options.test_parameter.split(settings.PARAMETER_SPLITTING_REGEX)  
      
      elif menu.options.skip_parameter != None :
        if menu.options.skip_parameter.startswith("="):
          menu.options.skip_parameter = menu.options.skip_parameter[1:]
        settings.TEST_PARAMETER = menu.options.skip_parameter.split(settings.PARAMETER_SPLITTING_REGEX)

      for i in range(0,len(settings.TEST_PARAMETER)):
        if "=" in settings.TEST_PARAMETER[i]:
          settings.TEST_PARAMETER[i] = settings.TEST_PARAMETER[i].split("=")[0]

    # Check injection level, due to the provided testable parameters.
    if menu.options.level < 2 and menu.options.test_parameter != None:
      checks.check_injection_level()

    # Check if defined character used for splitting parameter values.
    if menu.options.pdel:
     settings.PARAMETER_DELIMITER = menu.options.pdel

    # Check if defined character used for splitting cookie values.
    if menu.options.cdel:
     settings.COOKIE_DELIMITER = menu.options.cdel

    # Check for skipping injection techniques.
    if menu.options.skip_tech:
      if menu.options.tech:
        err_msg = "The options '--technique' and '--skip-technique' cannot be used "
        err_msg += "simultaneously (i.e. only one option must be set)."
        print settings.print_critical_msg(err_msg)
        raise SystemExit

      settings.SKIP_TECHNIQUES = True
      menu.options.tech = menu.options.skip_tech

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
        err_msg += "The value for '"
        if not settings.SKIP_TECHNIQUES :
          err_msg += "--technique"
        else:
          err_msg += "--skip-technique"
          
        err_msg += "' must be a string composed by the letters C, E, T, F. "
        err_msg += "Refer to the official wiki for details."
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
      err_msg = "Host's absolute filepath to write and/or upload, must be specified (i.e. '--file-dest')."
      print settings.print_critical_msg(err_msg)
      sys.exit(0)

    if menu.options.file_dest and menu.options.file_write == None and menu.options.file_upload == None :
      err_msg = "You must enter the '--file-write' or '--file-upload' parameter."
      print settings.print_critical_msg(err_msg)
      sys.exit(0)
  
    # Check if defined "--url" or "-m" option.
    if url:

      # Load the crawler
      if menu.options.crawldepth > 0 or menu.options.sitemap_url:
        if menu.options.crawldepth > 0:
          menu.options.DEFAULT_CRAWLDEPTH_LEVEL = menu.options.crawldepth
        else:  
          if menu.options.sitemap_url:
            while True:
              if not menu.options.batch:
                question_msg = "Do you want to change the crawling depth level? [Y/n] > "
                sys.stdout.write(settings.print_question_msg(question_msg))
                change_depth_level = sys.stdin.readline().replace("\n","").lower()
              else:
                change_depth_level = ""
              if len(change_depth_level) == 0:
                 change_depth_level = "y"              
              if change_depth_level in settings.CHOICE_YES or change_depth_level in settings.CHOICE_NO:
                break  
              elif change_depth_level in settings.CHOICE_QUIT:
                sys.exit(0)
              else:
                err_msg = "'" + change_depth_level + "' is not a valid answer."  
                print settings.print_error_msg(err_msg)
                pass

            # Change the crawling depth level.
            if change_depth_level in settings.CHOICE_YES:
              while True:
                question_msg = "Please enter the crawling depth level (1-2) > "
                sys.stdout.write(settings.print_question_msg(question_msg))
                depth_level = sys.stdin.readline().replace("\n","").lower()
                if int(depth_level) >= 3:
                  err_msg = "Depth level '" + depth_level + "' is not a valid answer."  
                  print settings.print_error_msg(err_msg)
                  pass
                else: 
                  menu.options.DEFAULT_CRAWLDEPTH_LEVEL = depth_level
                  break

        # Crawl the url.        
        url = crawler.crawler(url)

      try:
        # Check for URL redirection
        if not menu.options.ignore_redirects:
          url = redirection.do_check(url)

        if menu.options.flush_session:
          session_handler.flush(url)

        # Check for CGI scripts on url
        checks.check_CGI_scripts(url)

        # Modification on payload
        if not menu.options.shellshock:
          if not settings.USE_BACKTICKS:
            settings.SYS_USERS  = "echo $(" + settings.SYS_USERS + ")"
            settings.SYS_PASSES  = "echo $(" + settings.SYS_PASSES + ")"

        # Load tamper scripts
        if menu.options.tamper:
          checks.tamper_scripts()

        # Check if defined "--file-upload" option.
        if menu.options.file_upload:
          if not re.match(settings.VALID_URL_FORMAT, menu.options.file_upload):

            # Check if not defined URL for upload.
            while True:
              if not menu.options.batch:
                question_msg = "Do you want to enable an HTTP server? [Y/n] > "
                sys.stdout.write(settings.print_question_msg(question_msg))
                enable_HTTP_server = sys.stdin.readline().replace("\n","").lower()
              else:
                enable_HTTP_server = ""
              if len(enable_HTTP_server) == 0:
                 enable_HTTP_server = "y"              
              if enable_HTTP_server in settings.CHOICE_YES:

                # Check if file exists
                if not os.path.isfile(menu.options.file_upload):
                  err_msg = "The '" + menu.options.file_upload + "' file, does not exists."
                  sys.stdout.write(settings.print_critical_msg(err_msg) + "\n")
                  sys.exit(0)

                # Setting the local HTTP server.
                if settings.LOCAL_HTTP_IP == None:
                  while True:
                    question_msg = "Please enter your interface IP address > "
                    sys.stdout.write(settings.print_question_msg(question_msg))
                    ip_addr = sys.stdin.readline().replace("\n","").lower()

                    # check if IP address is valid
                    ip_check = simple_http_server.is_valid_ipv4(ip_addr)
                    if ip_check == False:
                      err_msg = "The provided IP address seems not valid."  
                      print settings.print_error_msg(err_msg)
                      pass
                    else:
                      settings.LOCAL_HTTP_IP = ip_addr
                      break

                # Check for invalid HTTP server's port.
                if settings.LOCAL_HTTP_PORT < 1 or settings.LOCAL_HTTP_PORT > 65535:
                  err_msg = "Invalid HTTP server's port (" + str(settings.LOCAL_HTTP_PORT) + ")." 
                  print settings.print_critical_msg(err_msg)
                  sys.exit(0)
                
                http_server = "http://" + str(settings.LOCAL_HTTP_IP) + ":" + str(settings.LOCAL_HTTP_PORT) + "/"
                info_msg = "Setting the HTTP server on '" + http_server + "'. "  
                print settings.print_info_msg(info_msg)
                menu.options.file_upload = http_server + menu.options.file_upload
                simple_http_server.main()
                break

              elif enable_HTTP_server in settings.CHOICE_NO:
                if not re.match(settings.VALID_URL_FORMAT, menu.options.file_upload):
                  err_msg = "The '" + menu.options.file_upload + "' is not a valid URL. "
                  print settings.print_critical_msg(err_msg)
                  sys.exit(0)
                break  
              elif enable_HTTP_server in settings.CHOICE_QUIT:
                sys.exit(0)
              else:
                err_msg = "'" + enable_HTTP_server + "' is not a valid answer."  
                print settings.print_error_msg(err_msg)
                pass

          try:
            urllib2.urlopen(menu.options.file_upload)
          except urllib2.HTTPError, err_msg:
            print settings.print_critical_msg(str(err_msg.code))
            sys.exit(0)

          except urllib2.URLError, err_msg:
            print settings.print_critical_msg(str(err_msg.args[0]).split("] ")[1] + ".")
            sys.exit(0)

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

            if settings.VERBOSITY_LEVEL >= 1:
              info_msg = "Identifying the target operating system... " 
              sys.stdout.write(settings.print_info_msg(info_msg))
              sys.stdout.flush()

            # Procedure for target OS identification.
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

            if settings.VERBOSITY_LEVEL >= 1 :
              if found_os_server:
                print "[ " + Fore.GREEN + "SUCCEED" + Style.RESET_ALL + " ]"
                success_msg = "The target operating system appears to be " 
                success_msg += identified_os.title() + Style.RESET_ALL + "."
                print settings.print_success_msg(success_msg)
              else:
                print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"
                warn_msg = "Heuristics have failed to identify server's operating system."
                print settings.print_warning_msg(warn_msg)

            # Procedure for target server identification.
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
                  success_msg = "The target server was identified as " 
                  success_msg += server_banner + Style.RESET_ALL + "."
                  print settings.print_success_msg(success_msg)
                settings.SERVER_BANNER = server_banner
                found_server_banner = True

                # Set up default root paths
                if settings.SERVER_BANNERS[i].lower() == "apache":
                  if settings.TARGET_OS == "win":
                    settings.WEB_ROOT = "\\htdocs"
                  else:
                    settings.WEB_ROOT = "/var/www"
                if settings.SERVER_BANNERS[i].lower() == "nginx": 
                  settings.WEB_ROOT = "/usr/share/nginx"
                if settings.SERVER_BANNERS[i].lower() == "microsoft-iis":
                  settings.WEB_ROOT = "\\inetpub\\wwwroot"
                break

            if not found_server_banner:
              if settings.VERBOSITY_LEVEL >= 1:
                print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"
              warn_msg = "Heuristics have failed to identify target server."
              print settings.print_warning_msg(warn_msg)

            # Procedure for target application identification
            found_application_extension = False
            if settings.VERBOSITY_LEVEL >= 1:
              info_msg = "Identifying the target application ... " 
              sys.stdout.write(settings.print_info_msg(info_msg))
              sys.stdout.flush()
            root, application_extension = splitext(urlparse(url).path)
            settings.TARGET_APPLICATION = application_extension[1:].upper()
            
            if settings.TARGET_APPLICATION:
              found_application_extension = True
              if settings.VERBOSITY_LEVEL >= 1:
                print "[ " + Fore.GREEN + "SUCCEED" + Style.RESET_ALL + " ]"           
                success_msg = "The target application was identified as " 
                success_msg += settings.TARGET_APPLICATION + Style.RESET_ALL + "."
                print settings.print_success_msg(success_msg)

              # Check for unsupported target applications
              for i in range(0,len(settings.UNSUPPORTED_TARGET_APPLICATION)):
                if settings.TARGET_APPLICATION.lower() in settings.UNSUPPORTED_TARGET_APPLICATION[i].lower():
                  err_msg = settings.TARGET_APPLICATION + " exploitation is not yet supported."  
                  print settings.print_critical_msg(err_msg)
                  raise SystemExit()

            if not found_application_extension:
              if settings.VERBOSITY_LEVEL >= 1:
                print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"
              warn_msg = "Heuristics have failed to identify target application."
              print settings.print_warning_msg(warn_msg)

            # Store the Server's root dir
            settings.DEFAULT_WEB_ROOT= settings.WEB_ROOT

            if menu.options.is_admin or menu.options.is_root and not menu.options.current_user:
              menu.options.current_user = True

            # Define Python working directory.
            if settings.TARGET_OS == "win" and menu.options.alter_shell:
              while True:
                if not menu.options.batch:
                  question_msg = "Do you want to use '" + settings.WIN_PYTHON_DIR 
                  question_msg += "' as Python working directory on the target host? [Y/n] > "
                  sys.stdout.write(settings.print_question_msg(question_msg))
                  python_dir = sys.stdin.readline().replace("\n","").lower()
                else:
                  python_dir = ""  
                if len(python_dir) == 0:
                   python_dir = "y" 
                if python_dir in settings.CHOICE_YES:
                  break
                elif python_dir in settings.CHOICE_NO:
                  question_msg = "Please provide a custom working directory for Python (e.g. '" 
                  question_msg += settings.WIN_PYTHON_DIR + "') > "
                  sys.stdout.write(settings.print_question_msg(question_msg))
                  settings.WIN_PYTHON_DIR = sys.stdin.readline().replace("\n","").lower()
                  break
                else:
                  err_msg = "'" + python_dir + "' is not a valid answer."  
                  print settings.print_error_msg(err_msg)
                  pass
              settings.USER_DEFINED_PYTHON_DIR = True

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
            
            if found_os_server == False and not menu.options.os:
              # If "--shellshock" option is provided then,
              # by default is a Linux/Unix operating system.
              if menu.options.shellshock:
                pass 
              else:
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

      except urllib2.HTTPError, err_msg:

        # Check the codes of responses
        if str(err_msg.getcode()) == settings.INTERNAL_SERVER_ERROR:
          print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"
          content = err_msg.read()
          sys.exit(0)

        # Check for HTTP Error 401 (Unauthorized).
        elif str(err_msg.getcode()) == settings.UNAUTHORIZED_ERROR:
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
            
          if settings.VERBOSITY_LEVEL < 2:
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
                    if not menu.options.batch:
                      question_msg = "Do you want to perform a dictionary-based attack? [Y/n] > "
                      sys.stdout.write(settings.print_question_msg(question_msg))
                      do_update = sys.stdin.readline().replace("\n","").lower()
                    else:
                      do_update = ""  
                    if len(do_update) == 0:
                       do_update = "y" 
                    if do_update in settings.CHOICE_YES:
                      auth_creds = authentication.http_auth_cracker(url, realm)
                      if auth_creds != False:
                        menu.options.auth_cred = auth_creds
                        settings.REQUIRED_AUTHENTICATION = True
                        break
                      else:
                        sys.exit(0)
                    elif do_update in settings.CHOICE_NO:
                      checks.http_auth_err_msg()
                    elif do_update in settings.CHOICE_QUIT:
                      sys.exit(0)
                    else:
                      err_msg = "'" + do_update + "' is not a valid answer."  
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
                    if not menu.options.batch:
                      question_msg = "Do you want to perform a dictionary-based attack? [Y/n] > "
                      sys.stdout.write(settings.print_question_msg(question_msg))
                      do_update = sys.stdin.readline().replace("\n","").lower()
                    else:
                      do_update = ""
                    if len(do_update) == 0:
                       do_update = "y" 
                    if do_update in settings.CHOICE_YES:
                      auth_creds = authentication.http_auth_cracker(url, realm)
                      if auth_creds != False:
                        menu.options.auth_cred = auth_creds
                        settings.REQUIRED_AUTHENTICATION = True
                        break
                      else:
                        sys.exit(0)
                    elif do_update in settings.CHOICE_NO:
                      checks.http_auth_err_msg()
                    elif do_update in settings.CHOICE_QUIT:
                      sys.exit(0)
                    else:
                      err_msg = "'" + do_update + "' is not a valid answer."  
                      print settings.print_error_msg(err_msg)
                      pass
                  else:   
                    checks.http_auth_err_msg()      
          else:
            pass
        
        # Invalid permission to access target URL page.
        elif str(err_msg.getcode()) == settings.FORBIDDEN_ERROR:
          if settings.VERBOSITY_LEVEL < 2:
            print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"
          err_msg = "You don't have permission to access this page."
          print settings.print_critical_msg(err_msg)
          sys.exit(0)
        
        # The target host seems to be down!
        elif str(err_msg.getcode()) == settings.NOT_FOUND_ERROR:
          if settings.VERBOSITY_LEVEL < 2:
            print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"
          err_msg = "The host seems to be down!"
          print settings.print_critical_msg(err_msg)
          sys.exit(0)

        else:
          raise

      # The target host seems to be down!
      except urllib2.URLError, e:
        if settings.VERBOSITY_LEVEL < 2:
          print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"
        err_msg = "The host seems to be down! (" 
        err_msg += str(e.args[0]).split("] ")[1] 
        err_msg += ")."
        print settings.print_critical_msg(err_msg)
        sys.exit(0)
        
      except httplib.BadStatusLine, err_msg:
        if settings.VERBOSITY_LEVEL < 2:
          print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"
        if len(err_msg.line) > 2 :
          print err_msg.line, err_msg.message
        pass

      except AttributeError:
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
    return filename

  # Accidental stop / restart of the target host server.
  except httplib.BadStatusLine, err_msg:
    if err_msg.line == "" or err_msg.message == "":
      err_msg = "The target host is not responding."
      err_msg += " Please ensure that is up and try again."
      print "\n\n" + settings.print_critical_msg(err_msg) 
      logs.print_logs_notification(filename, url)      
    else: 
      err_msg = err_msg.line + err_msg.message
      print settings.print_critical_msg(err_msg) + "\n"
    session_handler.clear(url)  
    sys.exit(0)

  # Connection reset by peer
  except SocketError, err_msg:
    if settings.VERBOSITY_LEVEL >= 1:
      print ""
    err_msg = "The target host is not responding."
    err_msg += " Please ensure that is up and try again."
    print "\n" + settings.print_critical_msg(err_msg) 
    logs.print_logs_notification(filename, url)

try:
  # Check if defined "--version" option.
  if menu.options.version:
    version.show_version()
    sys.exit(0)

  # Check python version number.
  version.python_version()

  if readline_error :
    checks.no_readline_module()
    sys.exit(0)

  # Check if defined "--dependencies" option. 
  # For checking (non-core) third party dependenices.
  if menu.options.noncore_dependencies:
    checks.third_party_dependencies()
    sys.exit(0)
    
  # Check if defined "--update" option.        
  if menu.options.update:
    update.updater()
      
  # Check if defined "--install" option.        
  if menu.options.install:
    install.installer()
    sys.exit(0)

  # Check for missing mandatory option(s).
  if not any((menu.options.url, menu.options.logfile, menu.options.bulkfile, \
              menu.options.requestfile, menu.options.sitemap_url, menu.options.wizard, \
              menu.options.update, menu.options.purge_output, menu.options.noncore_dependencies)):
    err_msg = "Missing a mandatory option (-u, -l, -m, -r, -x, --wizard, --update, --purge-output or --dependencies). "
    err_msg += "Use -h for help."
    print settings.print_critical_msg(err_msg)
    sys.exit(0)

  # Check if defined "--purge-output" option.
  if menu.options.purge_output:
    purge.purge_output()

  # Check the user-defined OS.
  if menu.options.os:
    checks.user_defined_os()

  # Check if defined "--check-tor" option. 
  if menu.options.tor_check and not menu.options.tor:
    err_msg = "The '--check-tor' swich requires usage of switch '--tor'."
    print settings.print_critical_msg(err_msg)
    sys.exit(0)

  # Check if defined "--mobile" option.
  if menu.options.mobile:
    if (menu.options.agent != settings.DEFAULT_USER_AGENT) or menu.options.random_agent:
      err_msg = "The switch '--mobile' is incompatible with options '--user-agent', '--random-agent'."
      print settings.print_critical_msg(err_msg)
      sys.exit(0)
    else:
      menu.options.agent = menu.mobile_user_agents()

  if menu.options.wizard:
    if not menu.options.url:
      while True:
        question_msg = "Please enter full target URL (--url) > "
        sys.stdout.write(settings.print_question_msg(question_msg))
        menu.options.url = sys.stdin.readline().replace("\n","")
        if len(menu.options.url) == 0:
          pass
        else: 
          break
    if not menu.options.data:
      question_msg = "Please enter POST data (--data) [Enter for none] > "
      sys.stdout.write(settings.print_question_msg(question_msg))
      menu.options.data = sys.stdin.readline().replace("\n","")
      if len(menu.options.data) == 0:
        menu.options.data = False

  # Retries when the connection timeouts.
  if menu.options.retries:
    settings.MAX_RETRIES = menu.options.retries

  # Seconds to delay between each HTTP request.
  if menu.options.delay > "0":
    settings.DELAY = menu.options.delay

  # Check if defined "--timesec" option.
  if menu.options.timesec > "0":
    settings.TIMESEC = menu.options.timesec
  else:
    if menu.options.tor:
      settings.TIMESEC = 10
      warn_msg = "Increasing default value for option '--time-sec' to"
      warn_msg += " " + str(settings.TIMESEC) + " because switch '--tor' was provided."
      print settings.print_warning_msg(warn_msg)  

  # Local IP address
  if not menu.options.offline:
    settings.LOCAL_HTTP_IP = simple_http_server.grab_ip_addr()
  else:
    settings.LOCAL_HTTP_IP = None  

  # Check arguments
  if len(sys.argv) == 1:
    menu.parser.print_help()
    print ""
    sys.exit(0)

  # Define the level of verbosity.
  if menu.options.verbose > 4:
    err_msg = "The value for option '-v' "
    err_msg += "must be an integer value from range [0, 4]."
    print settings.print_critical_msg(err_msg)
    sys.exit(0)
  else:  
    settings.VERBOSITY_LEVEL = menu.options.verbose

  # Define the level of tests to perform.
  if menu.options.level > 3:
    err_msg = "The value for option '--level' "
    err_msg += "must be an integer value from range [1, 3]."
    print settings.print_critical_msg(err_msg)
    sys.exit(0)

  # Define the local path where Metasploit Framework is installed.
  if menu.options.msf_path:
    settings.METASPLOIT_PATH = menu.options.msf_path

  # Enable detection phase
  settings.DETECTION_PHASE = True

  # Parse target and data from HTTP proxy logs (i.e Burp / WebScarab).
  if menu.options.requestfile or menu.options.logfile:
    parser.logfile_parser()

  if menu.options.offline:
    settings.CHECK_FOR_UPDATES_ON_START = False
    
  # Check if ".git" exists and check for updated version!
  if os.path.isdir("./.git") and settings.CHECK_FOR_UPDATES_ON_START:
    update.check_for_update()

  # Check if option is "-m" for multiple urls test.
  if menu.options.bulkfile:
    bulkfile = menu.options.bulkfile
    info_msg = "Parsing targets using the '" + os.path.split(bulkfile)[1] + "' file... "
    sys.stdout.write(settings.print_info_msg(info_msg))
    sys.stdout.flush()
    if not os.path.exists(bulkfile):
      print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
      err_msg = "It seems that the '" + os.path.split(bulkfile)[1] + "' file, does not exists."
      sys.stdout.write(settings.print_critical_msg(err_msg) + "\n")
      sys.stdout.flush()
      sys.exit(0)
    elif os.stat(bulkfile).st_size == 0:
      print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
      err_msg = "It seems that the '" + os.path.split(bulkfile)[1] + "' file, is empty."
      sys.stdout.write(settings.print_critical_msg(err_msg) + "\n")
      sys.stdout.flush()
      sys.exit(0)
    else:
      print "[" + Fore.GREEN + " SUCCEED " + Style.RESET_ALL + "]"
      with open(menu.options.bulkfile) as f:
        bulkfile = [url.strip() for url in f]
      # Removing duplicates from list.
      clean_bulkfile = []
      [clean_bulkfile.append(x) for x in bulkfile if x not in clean_bulkfile]
      # Removing empty elements from list.
      clean_bulkfile = [x for x in clean_bulkfile if x]
      for url in clean_bulkfile:
        settings.INIT_TEST = True
        if url == clean_bulkfile[-1]:
          settings.EOF = True
        # Reset the injection level
        if menu.options.level > 3:
          menu.options.level = 1
        init_injection(url)
        try:
          response, url = url_response(url)
          if response != False:
            filename = logs_filename_creation()
            main(filename, url)

        except urllib2.HTTPError, err_msg:
          if settings.VERBOSITY_LEVEL < 2:
            print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"
          error_description = ""
          if len(str(err_msg).split(": ")[1]) == 0:
            error_description = "Non-standard HTTP status code" 
          err_msg = str(err_msg).replace(": "," (") + error_description + ")." 
          warn_msg = "Skipping URL '" + url + "' - " + err_msg
          print settings.print_warning_msg(warn_msg)
          if settings.EOF:
            print "" 

        except urllib2.URLError, err_msg:
          if settings.VERBOSITY_LEVEL < 2:
            print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"
          err_msg = str(err_msg.args[0]).split("] ")[1] + "." 
          warn_msg = "Skipping URL '" + url + "' - " + err_msg
          print settings.print_critical_msg(warn_msg)
          if settings.EOF:
            print "" 

  else:
    settings.INIT_TEST = True
    # Check if option is "--url" for single url test.
    if menu.options.sitemap_url:
      url = menu.options.sitemap_url
    else:  
      url = menu.options.url
    response, url = url_response(url)
    if response != False:
      filename = logs_filename_creation()
      main(filename, url)

except KeyboardInterrupt:
  abort_msg = "User aborted procedure "
  abort_msg += "during the " + checks.assessment_phase() 
  abort_msg += " phase (Ctrl-C was pressed)."
  new_line = "\n"
  if settings.FILE_BASED_STATE or \
     settings.TEMPFILE_BASED_STATE :
     if not settings.DETECTION_PHASE and \
        settings.EXPLOITATION_PHASE:
      if settings.VERBOSITY_LEVEL != 0: 
        new_line = ""
  print new_line + settings.print_abort_msg(abort_msg)
  try:
    logs.print_logs_notification(filename, url)
    print ""
  except NameError:
    sys.exit(0)

except SystemExit: 
  print ""
  sys.exit(0)

#eof