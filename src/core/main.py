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
import errno
import random
from src.thirdparty.six.moves import http_client as _http_client
# accept overly long result lines
_http_client._MAXLINE = 1 * 1024 * 1024
from socket import error as SocketError
from os.path import splitext
from src.thirdparty.six.moves import input as _input
from src.thirdparty.six.moves import urllib as _urllib
from src.utils import menu
from src.utils import logs
from src.utils import purge
from src.utils import update
from src.utils import common
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
from src.thirdparty.six.moves import reload_module as _reload_module

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

# Set default encoding
_reload_module(sys)
#sys.setdefaultencoding(settings.UNICODE_ENCODING)

if settings.IS_WINDOWS:
  import codecs
  # Reference: https://github.com/nodejs/node/issues/12786#issuecomment-298652440
  codecs.register(lambda name: codecs.lookup("utf-8") if name == "cp65001" else None)
  # Use Colorama to make Termcolor work on Windows too :)
  init()

"""
Define HTTP User-Agent header.
"""
def user_agent_header():
  # Check if defined "--mobile" option.
  if menu.options.mobile:
    if ((menu.options.agent != settings.DEFAULT_USER_AGENT) and not menu.options.requestfile) or menu.options.random_agent:
      err_msg = "The switch '--mobile' is incompatible with option '--user-agent' or switch '--random-agent'."
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()
    else:
      menu.options.agent = menu.mobile_user_agents()

  # Check if defined "--random-agent" option.
  if menu.options.random_agent:
    if ((menu.options.agent != settings.DEFAULT_USER_AGENT) and not menu.options.requestfile) or menu.options.mobile:
      err_msg = "The switch '--random-agent' is incompatible with option '--user-agent' or switch '--mobile'."
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()
    else:
      if settings.VERBOSITY_LEVEL != 0:
        debug_msg = "Fetching random HTTP User-Agent header. "  
        sys.stdout.write(settings.print_debug_msg(debug_msg))
        sys.stdout.flush()
      else:
        pass
      try:
        menu.options.agent = random.choice(settings.USER_AGENT_LIST)
        if settings.VERBOSITY_LEVEL != 0:
          print(settings.SUCCESS_STATUS)
        info_msg = "The fetched random HTTP User-Agent header value is '" + menu.options.agent + "'."  
        print(settings.print_info_msg(info_msg))
      except:
        print(settings.FAIL_STATUS)
  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Setting the HTTP User-Agent header."
    print(settings.print_debug_msg(debug_msg))

"""
Examine the request
"""
def examine_request(request):
  try:
    headers.check_http_traffic(request)
    # Check if defined any HTTP Proxy (--proxy option).
    if menu.options.proxy:
      return proxy.use_proxy(request)
    # Check if defined Tor (--tor option).  
    elif menu.options.tor:
      return tor.use_tor(request)
    else:
      try:
        response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
        return response

      except ValueError:
        # Invalid format for the '--header' option.
        if settings.VERBOSITY_LEVEL < 2:
          print(settings.FAIL_STATUS)
        err_msg = "Use '--header=\"HEADER_NAME: HEADER_VALUE\"'"
        err_msg += "to provide an extra HTTP header or"
        err_msg += " '--header=\"HEADER_NAME: " + settings.WILDCARD_CHAR  + "\"' "
        err_msg += "if you want to try to exploit the provided HTTP header."
        print(settings.print_critical_msg(err_msg))
        raise SystemExit()

      except Exception as err_msg:
        if settings.UNAUTHORIZED_ERROR in str(err_msg).lower():
          if menu.options.ignore_code == settings.UNAUTHORIZED_ERROR:
            pass
          elif menu.options.auth_type and menu.options.auth_cred:
            err_msg = "The provided pair of " + menu.options.auth_type 
            err_msg += " HTTP authentication credentials '" + menu.options.auth_cred + "'"
            err_msg += " seems to be invalid."
            err_msg += " Try to rerun without providing '--auth-cred' and '--auth-type' options,"
            err_msg += " in order to perform a dictionary-based attack."
            print(settings.print_critical_msg(err_msg))
            raise SystemExit()
          else:
            pass
        else:  
          try:
            error_msg = str(err_msg.args[0]).split("] ")[1] + "."
          except IndexError:
            error_msg = str(err_msg).replace(": "," (") + ")."
          print(settings.print_critical_msg(error_msg))
          raise SystemExit()

  except SocketError as e:
    if e.errno == errno.ECONNRESET:
      error_msg = "Connection reset by peer."
      print(settings.print_critical_msg(error_msg))
    elif e.errno == errno.ECONNREFUSED:
      error_msg = "Connection refused."
      print(settings.print_critical_msg(error_msg))
    raise SystemExit()

  except _urllib.error.HTTPError as err_msg:
    error_description = ""
    if len(str(err_msg).split(": ")[1]) == 0:
      error_description = "Non-standard HTTP status code"
    err_msg = str(err_msg).replace(": "," (") + error_description + ")." 
    if menu.options.bulkfile:
      warn_msg = "Skipping URL '" + url + "' - " + err_msg
      print(settings.print_warning_msg(warn_msg))
      if settings.EOF:
        print("") 
      return False  
    else:
      print(settings.print_critical_msg(err_msg))
      raise SystemExit 

  except _urllib.error.URLError as e:
    err_msg = "Unable to connect to the target URL"
    try:
      err_msg += " (" + str(e.args[0]).split("] ")[1] + ")."
    except IndexError:
      err_msg += "."
      pass
    if menu.options.bulkfile:
      err_msg = "Skipping URL '" + url + "' - " + err_msg
      print(settings.print_critical_msg(err_msg))
      if settings.EOF:
        print("") 
      return False 
    else:
      print(settings.print_critical_msg(err_msg))
      raise SystemExit  

"""
Check internet connection before assessing the target.
"""
def check_internet(url):
  settings.CHECK_INTERNET = True
  settings.CHECK_INTERNET_ADDRESS = checks.check_http_s(url)
  info_msg = "Checking for internet connection. "
  sys.stdout.write(settings.print_info_msg(info_msg))
  sys.stdout.flush()
  if settings.VERBOSITY_LEVEL >= 2:
    print("")
  try:
    request = _urllib.request.Request(settings.CHECK_INTERNET_ADDRESS)
    headers.do_check(request)
    # Check if defined any HTTP Proxy (--proxy option).
    if menu.options.proxy:
      proxy.do_check(settings.CHECK_INTERNET_ADDRESS)
    examine_request(request)
  except:
    print(settings.FAIL_STATUS)
    error_msg = "No internet connection detected."
    print(settings.print_critical_msg(error_msg))

"""
The init (URL) request.
"""
def init_request(url):
  # Number of seconds to wait before timeout connection
  if settings.VERBOSITY_LEVEL != 0:
      debug_msg = "Setting the HTTP timeout."
      print(settings.print_debug_msg(debug_msg))
  if menu.options.timeout:
    settings.TIMEOUT = menu.options.timeout
  # Check connection(s)
  checks.check_connection(url)
  # Define HTTP User-Agent header
  user_agent_header()
  # Check the internet connection (--check-internet switch).
  if menu.options.check_internet:
    check_internet(url)
  # Check if defined POST data
  if menu.options.data:
    settings.USER_DEFINED_POST_DATA = menu.options.data
    # Check if defined character used for splitting parameter values.
    if menu.options.pdel and menu.options.pdel in settings.USER_DEFINED_POST_DATA:
      settings.PARAMETER_DELIMITER = menu.options.pdel
    try:
      request = _urllib.request.Request(url, menu.options.data.encode())
    except SocketError as e:
      if e.errno == errno.ECONNRESET:
        error_msg = "Connection reset by peer."
        print(settings.print_critical_msg(error_msg))
      elif e.errno == errno.ECONNREFUSED:
        error_msg = "Connection refused."
        print(settings.print_critical_msg(error_msg))
      raise SystemExit()
  else:
    # Check if defined character used for splitting parameter values.
    if menu.options.pdel and menu.options.pdel in url:
      settings.PARAMETER_DELIMITER = menu.options.pdel
    try:
      request = _urllib.request.Request(url)
    except SocketError as e:
      if e.errno == errno.ECONNRESET:
        error_msg = "Connection reset by peer."
        print(settings.print_critical_msg(error_msg))
      elif e.errno == errno.ECONNREFUSED:
        error_msg = "Connection refused."
        print(settings.print_critical_msg(error_msg))
      raise SystemExit()

  headers.do_check(request)
  # Check if defined any HTTP Proxy (--proxy option).
  if menu.options.proxy:
    proxy.do_check(url)
  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Creating " + str(settings.SCHEME).upper() + " requests opener object."
    print(settings.print_debug_msg(debug_msg))
  # Used a valid pair of valid credentials
  if menu.options.auth_cred and menu.options.auth_type:
    info_msg = "Using '" + menu.options.auth_cred + "' pair of " + menu.options.auth_type 
    info_msg += " HTTP authentication credentials."
    print(settings.print_info_msg(info_msg))
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
    print(settings.print_info_msg(info_msg))
  request = init_request(url)
  if settings.CHECK_INTERNET:
    settings.CHECK_INTERNET = False
  if settings.INIT_TEST == True:
    info_msg = "Testing connection to the target URL. "
    sys.stdout.write(settings.print_info_msg(info_msg))
    sys.stdout.flush()
    if settings.VERBOSITY_LEVEL >= 2:
      print("")
  response = examine_request(request)
  # Check for URL redirection
  if not menu.options.ignore_redirects:
    url = redirection.do_check(url)
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
  output_dir = os.path.dirname(output_dir)
 
  try:
    os.stat(output_dir)
  except:
    try:
      os.mkdir(output_dir)   
    except OSError as err_msg:
      try:
        error_msg = str(err_msg.args[0]).split("] ")[1] + "."
      except IndexError:
        error_msg = str(err_msg.args[0]) + "."
      print(settings.print_critical_msg(error_msg))
      raise SystemExit()

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

    if menu.options.header is not None and settings.INJECT_TAG in menu.options.header or \
       menu.options.headers is not None and settings.INJECT_TAG in menu.options.headers:
      info_msg = "Injection marker found in option '--header(s)/--user-agent/--referer/--cookie'."
      print(settings.print_info_msg(info_msg))
      if menu.options.test_parameter:
        err_msg = "The options '-p' and the injection marker cannot be used "
        err_msg += "simultaneously (i.e. only one option must be set)."
        print(settings.print_critical_msg(err_msg))
        raise SystemExit

    if menu.options.test_parameter and menu.options.skip_parameter:
      if type(menu.options.test_parameter) is bool:
        menu.options.test_parameter = None
      else:
        err_msg = "The options '-p' and '--skip' cannot be used "
        err_msg += "simultaneously (i.e. only one option must be set)."
        print(settings.print_critical_msg(err_msg))
        raise SystemExit

    if menu.options.ignore_session:
      # Ignore session
      session_handler.ignore(url)      

    # Check provided parameters for tests
    if menu.options.test_parameter or menu.options.skip_parameter:     
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

    # Check if defined character used for splitting cookie values.
    if menu.options.cdel:
     settings.COOKIE_DELIMITER = menu.options.cdel

    # Check for skipping injection techniques.
    if menu.options.skip_tech:
      if menu.options.tech:
        err_msg = "The options '--technique' and '--skip-technique' cannot be used "
        err_msg += "simultaneously (i.e. only one option must be set)."
        print(settings.print_critical_msg(err_msg))
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
        print(settings.print_critical_msg(err_msg))
        raise SystemExit()

    # Check if specified wrong alternative shell
    if menu.options.alter_shell:
      if menu.options.alter_shell.lower() not in settings.AVAILABLE_SHELLS:
        err_msg = "'" + menu.options.alter_shell + "' shell is not supported!"
        print(settings.print_critical_msg(err_msg))
        raise SystemExit()

    # Check the file-destination
    if menu.options.file_write and not menu.options.file_dest or \
    menu.options.file_upload  and not menu.options.file_dest:
      err_msg = "Host's absolute filepath to write and/or upload, must be specified (i.e. '--file-dest')."
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()

    if menu.options.file_dest and menu.options.file_write == None and menu.options.file_upload == None:
      err_msg = "You must enter the '--file-write' or '--file-upload' parameter."
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()
  
    # Check if defined "--url" or "-m" option.
    if url:
      if menu.options.auth_cred and menu.options.auth_cred and settings.VERBOSITY_LEVEL != 0:
        info_msg = "Used a valid pair of " + menu.options.auth_type 
        info_msg += " HTTP authentication credentials '" + menu.options.auth_cred + "'." 
        print(settings.print_bold_info_msg(info_msg))
      # Load the crawler
      if menu.options.crawldepth > 0 or menu.options.sitemap_url:  
        url = crawler.crawler(url)
      try:
        if menu.options.flush_session:
          session_handler.flush(url)
        # Check for CGI scripts on url
        checks.check_CGI_scripts(url)
        # Modification on payload
        if not menu.options.shellshock:
          if not settings.USE_BACKTICKS:
            settings.SYS_USERS  = "echo $(" + settings.SYS_USERS + ")"
            settings.SYS_PASSES  = "echo $(" + settings.SYS_PASSES + ")"
        # Check if defined "--file-upload" option.
        if menu.options.file_upload:
          checks.file_upload()
          try:
            _urllib.request.urlopen(menu.options.file_upload, timeout=settings.TIMEOUT)
          except _urllib.error.HTTPError as err_msg:
            print(settings.print_critical_msg(str(err_msg.code)))
            raise SystemExit()
          except _urllib.error.URLError as err_msg:
            print(settings.print_critical_msg(str(err_msg.args[0]).split("] ")[1] + "."))
            raise SystemExit()
        try:
          # Webpage encoding detection.
          requests.encoding_detection(response)
          # Procedure for target application identification
          requests.application_identification(url)
          # Specifies the technology supporting the web application
          requests.technology_detection(response)
          if response.info()['server'] :
            server_banner = response.info()['server']
            # Procedure for target server's operating system identification.
            requests.check_target_os(server_banner)
            # Procedure for target server identification.
            requests.server_identification(server_banner)
            # Store the Server's root dir
            settings.DEFAULT_WEB_ROOT = settings.WEB_ROOT
            if menu.options.is_admin or menu.options.is_root and not menu.options.current_user:
              menu.options.current_user = True
            # Define Python working directory.
            checks.define_py_working_dir()
            # Check for wrong flags.
            checks.check_wrong_flags() 
          else:
            found_os_server = checks.user_defined_os()
        except KeyError:
          pass
        except AttributeError:
          pass
        # Load tamper scripts
        if menu.options.tamper:
          checks.tamper_scripts()
          
      except _urllib.error.HTTPError as err_msg:
        # Check the codes of responses
        if str(err_msg.getcode()) == settings.INTERNAL_SERVER_ERROR:
          print(settings.FAIL_STATUS)
          content = err_msg.read()
          raise SystemExit()
        
        # Invalid permission to access target URL page.
        elif str(err_msg.getcode()) == settings.FORBIDDEN_ERROR:
          if settings.VERBOSITY_LEVEL < 2:
            print(settings.FAIL_STATUS)
          err_msg = "You don't have permission to access this page."
          print(settings.print_critical_msg(err_msg))
          raise SystemExit()
        
        # The target host seems to be down!
        elif str(err_msg.getcode()) == settings.NOT_FOUND_ERROR:
          if settings.VERBOSITY_LEVEL < 2:
            print(settings.FAIL_STATUS)
          err_msg = "The host seems to be down!"
          print(settings.print_critical_msg(err_msg))
          raise SystemExit()

        else:
          raise

      # The target host seems to be down!
      except _urllib.error.URLError as e:
        if settings.VERBOSITY_LEVEL < 2:
          print(settings.FAIL_STATUS)
        err_msg = "The host seems to be down"
        try:
          err_msg += " (" + str(e.args[0]).split("] ")[1] + ")."
        except IndexError:
          err_msg += "."
          pass
        print(settings.print_critical_msg(err_msg))
        raise SystemExit()
        
      except _http_client.BadStatusLine as err_msg:
        if settings.VERBOSITY_LEVEL < 2:
          print(settings.FAIL_STATUS)
        if len(err_msg.line) > 2 :
          print(err_msg.line, err_msg.message)
        pass
  
      except _http_client.InvalidURL as err:
        print(settings.print_critical_msg(err_msg))
        raise SystemExit()

      except AttributeError:
        pass

    else:
      err_msg = "You must specify the target URL."
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()

    # Retrieve everything from the supported enumeration options.
    if menu.options.enum_all:
      checks.enable_all_enumeration_options()

    # Launch injection and exploitation controller.
    controller.do_check(url, filename)
    return filename

  # Accidental stop / restart of the target host server.
  except (_http_client.BadStatusLine, SocketError) as err_msg:
    if settings.VERBOSITY_LEVEL != 0:
      print("")
    err_msg = "The target host is not responding."
    err_msg += " Please ensure that is up and try again."
    print("\n" + settings.print_critical_msg(err_msg))
    logs.print_logs_notification(filename, url)      
    #session_handler.clear(url)  
    #raise SystemExit()

try:
  # Check if defined "--version" option.
  if menu.options.version:
    version.show_version()
    raise SystemExit()

  # Print the legal disclaimer msg.
  print(settings.print_legal_disclaimer_msg(settings.LEGAL_DISCLAIMER_MSG))

  # Get total number of days from last update 
  common.days_from_last_update()

  if not menu.options.batch:
    settings.OS_CHECKS_NUM = 1
  for os_checks_num in range(0, int(settings.OS_CHECKS_NUM)):

    # Check if defined "--list-tampers" option.
    if menu.options.list_tampers:
      checks.list_tamper_scripts()
      raise SystemExit()

    if readline_error :
      checks.no_readline_module()
      raise SystemExit()

    # Check if defined "--dependencies" option. 
    # For checking (non-core) third party dependenices.
    if menu.options.noncore_dependencies:
      checks.third_party_dependencies()
      raise SystemExit()
      
    # Check if defined "--update" option.        
    if menu.options.update:
      update.updater()
        
    # Check if defined "--install" option.        
    if menu.options.install:
      install.installer()
      raise SystemExit()

    # Check for missing mandatory option(s).
    if not any((menu.options.url, menu.options.logfile, menu.options.bulkfile, \
                menu.options.requestfile, menu.options.sitemap_url, menu.options.wizard, \
                menu.options.update, menu.options.list_tampers, menu.options.purge, menu.options.noncore_dependencies)):
      err_msg = "Missing a mandatory option (-u, -l, -m, -r, -x, --wizard, --update, --list-tampers, --purge or --dependencies). "
      err_msg += "Use -h for help."
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()

    if menu.options.encoding:
      if menu.options.encoding.lower() not in settings.ENCODING_LIST:
        err_msg = "The provided charset '"  + menu.options.encoding + "' is unknown. "
        err_msg += "Please visit 'http://docs.python.org/library/codecs.html#standard-encodings' "
        err_msg += "to get the full list of supported charsets."
        print(settings.print_critical_msg(err_msg))
        raise SystemExit()
      else:
        settings.DEFAULT_PAGE_ENCODING = menu.options.encoding.lower()

    if menu.options.header and len(menu.options.header.split("\\n"))> 1:
        warn_msg = "Swithing '--header' to '--headers' "
        warn_msg += "due to multiple extra HTTP headers."
        print(settings.print_warning_msg(warn_msg))

    # Check if defined "--proxy" option.
    if menu.options.proxy:
      for match in re.finditer(settings.PROXY_REGEX, menu.options.proxy):
        _, proxy_scheme, proxy_address, proxy_port = match.groups()
        if proxy_scheme:
          settings.PROXY_SCHEME = proxy_scheme
          menu.options.proxy = proxy_address + ":" + proxy_port
          break
      else:
        err_msg = "Proxy value must be in format '(http|https)://address:port'."
        print(settings.print_critical_msg(err_msg))
        raise SystemExit()

    if menu.options.ignore_session and menu.options.flush_session:
      err_msg = "The '--ignore-session' option is unlikely to work combined with the '--flush-session' option."
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()

    if int(menu.options.failed_tries) == 0:
      err_msg = "You must specify '--failed-tries' value, greater than zero."      
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()

    # Check if defined "--auth-cred" and/or '--auth-type'.
    if (menu.options.auth_type and not menu.options.auth_cred) or (menu.options.auth_cred and not menu.options.auth_type):
        err_msg = "You must specify both '--auth-cred' and '--auth-type' options."      
        print(settings.print_critical_msg(err_msg))
        raise SystemExit()

    if menu.options.requestfile and menu.options.url:
        err_msg = "The '-r' option is incompatible with option '-u' ('--url')."      
        print(settings.print_critical_msg(err_msg))
        raise SystemExit()

    # Check if defined "--purge" option.
    if menu.options.purge:
      purge.purge()
      if not any((menu.options.url, menu.options.logfile, menu.options.bulkfile, \
                  menu.options.requestfile, menu.options.sitemap_url, menu.options.wizard)):
        raise SystemExit()

    # Check the user-defined OS.
    if menu.options.os:
      checks.user_defined_os()

    # Check if defined "--check-tor" option. 
    if menu.options.tor_check and not menu.options.tor:
      err_msg = "The '--check-tor' swich requires usage of switch '--tor'."
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()

    # Check if defined "--ignore-code" option.
    if menu.options.ignore_code and "," in menu.options.ignore_code:
      err_msg = "Ignoring more than one HTTP error code, is not yet supported."
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()

    if menu.options.wizard:
      if not menu.options.url:
        while True:
          question_msg = "Please enter full target URL (-u) > "
          menu.options.url = _input(settings.print_question_msg(question_msg))
          if len(menu.options.url) == 0:
            pass
          else: 
            break
      if not menu.options.data:
        question_msg = "Please enter POST data (--data) [Enter for none] > "
        menu.options.data = _input(settings.print_question_msg(question_msg))
        if len(menu.options.data) == 0:
          menu.options.data = False

    # Retries when the connection timeouts.
    if menu.options.retries:
      settings.MAX_RETRIES = menu.options.retries

    # Seconds to delay between each HTTP request.
    if menu.options.delay > 0:
      settings.DELAY = menu.options.delay

    # Check if defined "--timesec" option.
    if menu.options.timesec > 0:
      settings.TIMESEC = menu.options.timesec
    else:
      if menu.options.tor:
        settings.TIMESEC = 10
        warn_msg = "Increasing default value for option '--time-sec' to"
        warn_msg += " " + str(settings.TIMESEC) + ", because switch '--tor' was provided."
        print(settings.print_warning_msg(warn_msg))  

    # Local IP address
    if not menu.options.offline:
      settings.LOCAL_HTTP_IP = simple_http_server.grab_ip_addr()
    else:
      settings.LOCAL_HTTP_IP = None  

    # Check arguments
    if len(sys.argv) == 1:
      menu.parser.print_help()
      print("")
      raise SystemExit()
    else:
      # Check for INJECT_HERE tag.
      inject_tag_regex_match = re.search(settings.INJECT_TAG_REGEX, ",".join(str(x) for x in sys.argv))
      if inject_tag_regex_match:
        settings.INJECT_TAG = inject_tag_regex_match.group(0)

    # Define the level of verbosity.
    if menu.options.verbose > 4:
      err_msg = "The value for option '-v' "
      err_msg += "must be an integer value from range [0, 4]."
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()
    else:  
      settings.VERBOSITY_LEVEL = menu.options.verbose

    # Define the level of tests to perform.
    if menu.options.level > 3:
      err_msg = "The value for option '--level' "
      err_msg += "must be an integer value from range [1, 3]."
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()

    # Define the local path where Metasploit Framework is installed.
    if menu.options.msf_path:
      settings.METASPLOIT_PATH = menu.options.msf_path

    # Enable detection phase
    settings.DETECTION_PHASE = True

    # Parse target and data from HTTP proxy logs (i.e Burp / WebScarab).
    if menu.options.requestfile and menu.options.logfile:
      err_msg = "The '-r' option is unlikely to work combined with the '-l' option."
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()
    elif menu.options.requestfile or menu.options.logfile:
      parser.logfile_parser()

    if menu.options.offline:
      settings.CHECK_FOR_UPDATES_ON_START = False
      
    # Check if ".git" exists and check for updated version!
    if os.path.isdir("./.git") and settings.CHECK_FOR_UPDATES_ON_START:
      update.check_for_update()

    # Check if option is "-m" for multiple urls test.
    if menu.options.bulkfile:
      bulkfile = menu.options.bulkfile
      info_msg = "Parsing targets using the '" + os.path.split(bulkfile)[1] + "' file. "
      sys.stdout.write(settings.print_info_msg(info_msg))
      sys.stdout.flush()
      if not os.path.exists(bulkfile):
        print(settings.FAIL_STATUS)
        err_msg = "It seems that the '" + os.path.split(bulkfile)[1] + "' file, does not exist."
        sys.stdout.write(settings.print_critical_msg(err_msg) + "\n")
        sys.stdout.flush()
        raise SystemExit()
      elif os.stat(bulkfile).st_size == 0:
        print(settings.FAIL_STATUS)
        err_msg = "It seems that the '" + os.path.split(bulkfile)[1] + "' file, is empty."
        sys.stdout.write(settings.print_critical_msg(err_msg) + "\n")
        sys.stdout.flush()
        raise SystemExit()
      else:
        print(settings.SUCCESS_STATUS)
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

          except _urllib.error.HTTPError as err_msg:
            if settings.VERBOSITY_LEVEL < 2:
              print(settings.FAIL_STATUS)
            error_description = ""
            if len(str(err_msg).split(": ")[1]) == 0:
              error_description = "Non-standard HTTP status code" 
            err_msg = str(err_msg).replace(": "," (") + error_description + ")." 
            warn_msg = "Skipping URL '" + url + "' - " + err_msg
            print(settings.print_warning_msg(warn_msg))
            if settings.EOF:
              print("") 

          except _urllib.error.URLError as err_msg:
            if settings.VERBOSITY_LEVEL < 2:
              print(settings.FAIL_STATUS)
            err_msg = str(err_msg.args[0]).split("] ")[1] + "." 
            err_msg = "Skipping URL '" + url + "' - " + err_msg
            print(settings.print_critical_msg(err_msg))
            if settings.EOF:
              print("") 

    else:
      if os_checks_num == 0:
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
  # if settings.FILE_BASED_STATE or \
  #    settings.TEMPFILE_BASED_STATE :
  #    if not settings.DETECTION_PHASE and \
  #       settings.EXPLOITATION_PHASE:
  #     if settings.VERBOSITY_LEVEL != 0: 
  #       new_line = ""
  print(new_line + settings.print_abort_msg(abort_msg))
  try:
    logs.print_logs_notification(filename, url)
    print("")
  except NameError:
    raise SystemExit()

except SystemExit: 
  print("")
  raise SystemExit()

except EOFError:
  err_msg = "Exiting, due to EOFError."
  print(settings.print_error_msg(err_msg))
  raise SystemExit()

# eof