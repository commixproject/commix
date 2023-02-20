#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2023 Anastasios Stasinopoulos (@ancst).

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
from src.core.requests import parameters
from src.utils import session_handler
from src.utils import simple_http_server
from src.thirdparty.colorama import Fore, Back, Style, init
from src.core.testing import smoke_test
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

# Set default encoding
_reload_module(sys)
#sys.setdefaultencoding(settings.DEFAULT_CODEC)

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
      if not settings.MULTI_TARGETS or not settings.STDIN_PARSING:
        err_msg = "The switch '--mobile' is incompatible with option '--user-agent' or switch '--random-agent'."
        print(settings.print_critical_msg(err_msg))
        raise SystemExit()
    else:
      menu.options.agent = checks.mobile_user_agents()

  # Check if defined "--random-agent" option.
  if menu.options.random_agent:
    if ((menu.options.agent != settings.DEFAULT_USER_AGENT) and not menu.options.requestfile) or menu.options.mobile:
      if not settings.MULTI_TARGETS or not settings.STDIN_PARSING:
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
          print(settings.SINGLE_WHITESPACE)
        info_msg = "The fetched random HTTP User-Agent header value is '" + menu.options.agent + "'."  
        print(settings.print_info_msg(info_msg))
      except:
        print(settings.SINGLE_WHITESPACE)

  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Setting the HTTP User-Agent header."
    print(settings.print_debug_msg(debug_msg))

"""
Examine the request
"""
def examine_request(request, url):
  # Retries when the connection timeouts.
  if menu.options.retries:
    settings.MAX_RETRIES = menu.options.retries
  else:
    if settings.MULTI_TARGETS:
      settings.MAX_RETRIES = 1
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
          print(settings.SINGLE_WHITESPACE)
        err_msg = "Use '--header=\"HEADER_NAME: HEADER_VALUE\"'"
        err_msg += "to provide an extra HTTP header or"
        err_msg += " '--header=\"HEADER_NAME: " + settings.WILDCARD_CHAR  + "\"' "
        err_msg += "if you want to try to exploit the provided HTTP header."
        print(settings.print_critical_msg(err_msg))
        raise SystemExit()

  except Exception as err_msg:
    requests.request_failed(err_msg)

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
    print(settings.SINGLE_WHITESPACE)
  try:
    request = _urllib.request.Request(settings.CHECK_INTERNET_ADDRESS)
    headers.do_check(request)
    examine_request(request, url)
  except:
    print(settings.SINGLE_WHITESPACE)
    error_msg = "No internet connection detected."
    print(settings.print_critical_msg(error_msg))

"""
The init (URL) request.
"""
def init_request(url):
  # Check connection(s)
  checks.check_connection(url)
  # Number of seconds to wait before timeout connection
  if settings.VERBOSITY_LEVEL != 0:
      debug_msg = "Setting the HTTP timeout."
      print(settings.print_debug_msg(debug_msg))
  if menu.options.timeout:
    settings.TIMEOUT = menu.options.timeout
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
    request = _urllib.request.Request(url, menu.options.data.encode())
  else:
    # Check if defined character used for splitting parameter values.
    if menu.options.pdel and menu.options.pdel in url:
      settings.PARAMETER_DELIMITER = menu.options.pdel
    request = _urllib.request.Request(url)
    # Check if defined any HTTP Proxy (--proxy option).
  headers.do_check(request)
  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Creating " + str(settings.SCHEME).upper() + " requests opener object."
    print(settings.print_debug_msg(debug_msg))
  # Used a valid pair of valid credentials
  if menu.options.auth_cred and menu.options.auth_type and settings.VERBOSITY_LEVEL != 0 :
    debug_msg = "Using '" + menu.options.auth_cred + "' pair of " + menu.options.auth_type 
    debug_msg += " HTTP authentication credentials."
    print(settings.print_debug_msg(debug_msg))
  if menu.options.proxy:
    proxy.do_check()
  return request

"""
Get the URL response.
"""
def url_response(url):
  if settings.INIT_TEST == True:
    info_msg = "Testing connection to the target URL. "
    print(settings.print_info_msg(info_msg))
  # Check if http / https
  url = checks.check_http_s(url)
  # Check if defined Tor (--tor option).
  if menu.options.tor and settings.TOR_CHECK_AGAIN:
    tor.do_check()
  if settings.MULTI_TARGETS or settings.CRAWLING:
    settings.TOR_CHECK_AGAIN = False
    # initiate total of requests
    settings.TOTAL_OF_REQUESTS = 0
  request = init_request(url)
  if settings.CHECK_INTERNET:
    settings.CHECK_INTERNET = False
  response = examine_request(request, url)
  # Check for URL redirection
  if type(response) is not bool and settings.FOLLOW_REDIRECT and response is not None:
    if response.geturl() != url:
      redirect_url = redirection.do_check(request, url, response.geturl())
      if redirect_url is not None:
        url = redirect_url
  return response, url

"""
Injection states initiation.
"""
def init_injection(url):
  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Initializing the knowledge base."
    print(settings.print_debug_msg(debug_msg))
  # Initiate heuristic checks.
  if not settings.FOLLOW_REDIRECT:
    settings.FOLLOW_REDIRECT = True
  if settings.SKIP_CODE_INJECTIONS:
    settings.SKIP_CODE_INJECTIONS = False
  if settings.SKIP_COMMAND_INJECTIONS:
    settings.SKIP_COMMAND_INJECTIONS = False
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
Using 'stdin' for parsing targets.
"""
def stdin_parsing_target(os_checks_num):
  _ = []
  if os_checks_num == 0:
    info_msg = "Using 'stdin' for parsing targets list."
    print(settings.print_info_msg(info_msg))
  menu.options.batch = True
  settings.MULTI_TARGETS = True
  for url in sys.stdin:
    if re.search(r"\b(https?://[^\s'\"]+|[\w.]+\.\w{2,3}[/\w+]*\?[^\s'\"]+)", url, re.I):
      url = url.replace(settings.SINGLE_WHITESPACE, _urllib.parse.quote_plus(settings.SINGLE_WHITESPACE)).strip()
      _.append(url.rstrip())
  return _

"""
Check if an injection point has already been detected against target.
"""
def check_for_injected_url(url):
  _ = True
  if _urllib.parse.urlparse(url).netloc not in settings.CRAWLED_URLS_INJECTED:
    _ = False
  return _

"""
The main function.
"""
def main(filename, url):
  try:
    if menu.options.alert:
      if menu.options.alert.startswith('-'):
        err_msg = "Value for option '--alert' must be valid operating system command(s)."
        print(settings.print_error_msg(err_msg))
      else:
        settings.ALERT = True

    if menu.options.offline:
      settings.CHECK_FOR_UPDATES_ON_START = False

    # Ignore the mathematic calculation part (Detection phase).
    if menu.options.skip_calc:
      settings.SKIP_CALC = True

    # Target URL reload.
    if menu.options.url_reload and menu.options.data:
      settings.URL_RELOAD = True

    if settings.WILDCARD_CHAR_APPLIED and settings.MULTI_TARGETS or settings.STDIN_PARSING:
      settings.WILDCARD_CHAR_APPLIED = False

    checks.check_custom_injection_marker(url)

    # Check injection level, due to the provided testable parameters.
    if menu.options.level == settings.DEFAULT_INJECTION_LEVEL and \
    menu.options.test_parameter != None:
      checks.check_injection_level()
    
    # Define the level of tests to perform.
    if menu.options.level == settings.DEFAULT_INJECTION_LEVEL:
      settings.SEPARATORS = sorted(set(settings.SEPARATORS_LVL1), key=settings.SEPARATORS_LVL1.index)
      settings.PREFIXES = sorted(set(settings.PREFIXES_LVL1), key=settings.PREFIXES_LVL1.index)
      settings.SUFFIXES = sorted(set(settings.SUFFIXES_LVL1), key=settings.SUFFIXES_LVL1.index)
      settings.EVAL_PREFIXES = sorted(set(settings.EVAL_PREFIXES_LVL1), key=settings.EVAL_PREFIXES_LVL1.index)
      settings.EVAL_SUFFIXES = sorted(set(settings.EVAL_SUFFIXES_LVL1), key=settings.EVAL_SUFFIXES_LVL1.index)
      settings.EVAL_SEPARATORS = sorted(set(settings.EVAL_SEPARATORS_LVL1), key=settings.EVAL_SEPARATORS_LVL1.index)
      settings.EXECUTION_FUNCTIONS = sorted(set(settings.EXECUTION_FUNCTIONS_LVL1), key=settings.EXECUTION_FUNCTIONS_LVL1.index)
    elif menu.options.level == settings.COOKIE_INJECTION_LEVEL:
      settings.SEPARATORS = sorted(set(settings.SEPARATORS_LVL2), key=settings.SEPARATORS_LVL2.index)
      settings.PREFIXES = sorted(set(settings.PREFIXES_LVL2), key=settings.PREFIXES_LVL2.index)
      settings.SUFFIXES = sorted(set(settings.SUFFIXES_LVL2), key=settings.SUFFIXES_LVL2.index)
      settings.EVAL_PREFIXES = sorted(set(settings.EVAL_PREFIXES_LVL2), key=settings.EVAL_PREFIXES_LVL2.index)
      settings.EVAL_SUFFIXES = sorted(set(settings.EVAL_SUFFIXES_LVL2), key=settings.EVAL_SUFFIXES_LVL2.index)
      settings.EVAL_SEPARATORS = sorted(set(settings.EVAL_SEPARATORS_LVL2), key=settings.EVAL_SEPARATORS_LVL2.index)
      settings.EXECUTION_FUNCTIONS = sorted(set(settings.EXECUTION_FUNCTIONS_LVL2), key=settings.EXECUTION_FUNCTIONS_LVL2.index)
    elif menu.options.level == settings.HTTP_HEADER_INJECTION_LEVEL:
      settings.SEPARATORS = sorted(set(settings.SEPARATORS_LVL3), key=settings.SEPARATORS_LVL3.index)
      settings.PREFIXES = sorted(set(settings.PREFIXES_LVL3), key=settings.PREFIXES_LVL3.index)
      settings.SUFFIXES = sorted(set(settings.SUFFIXES_LVL3), key=settings.SUFFIXES_LVL3.index)
      settings.EVAL_PREFIXES = sorted(set(settings.EVAL_PREFIXES_LVL3), key=settings.EVAL_PREFIXES_LVL3.index)
      settings.EVAL_SUFFIXES = sorted(set(settings.EVAL_SUFFIXES_LVL3), key=settings.EVAL_SUFFIXES_LVL3.index)
      settings.EVAL_SEPARATORS = sorted(set(settings.EVAL_SEPARATORS_LVL3), key=settings.EVAL_SEPARATORS_LVL3.index)
      settings.EXECUTION_FUNCTIONS = sorted(set(settings.EXECUTION_FUNCTIONS_LVL3), key=settings.EXECUTION_FUNCTIONS_LVL3.index)

    else:
      err_msg = "The value for option '--level' "
      err_msg += "must be an integer value from range [1, 3]."
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()

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
    checks.check_provided_parameters()
          
    # Check if defined character used for splitting cookie values.
    if menu.options.cdel:
     settings.COOKIE_DELIMITER = menu.options.cdel

    if not menu.options.ignore_session and not menu.options.flush_session:
      if session_handler.applied_techniques(url, http_request_method):
        if not menu.options.tech:
          menu.options.tech = session_handler.applied_techniques(url, http_request_method)
        else:
          settings.USER_SUPPLIED_TECHNIQUE = True
      else:
        menu.options.tech = list(menu.options.tech.lower())
        _ = {settings.AVAILABLE_TECHNIQUES[i] : i for i in range(len(settings.AVAILABLE_TECHNIQUES))}
        try:
          menu.options.tech.sort(key=lambda x:_[x])
        except KeyError:
          pass
        menu.options.tech = ''.join(menu.options.tech)
    else:
      menu.options.tech = ''.join([str(x) for x in settings.AVAILABLE_TECHNIQUES]) 

    # Check for skipping injection techniques.
    if menu.options.skip_tech:
      # Convert injection technique(s) to lowercase
      menu.options.skip_tech = menu.options.skip_tech.lower()
      settings.SKIP_TECHNIQUES = True
      if menu.options.tech:
        err_msg = "The options '--technique' and '--skip-technique' cannot be used "
        err_msg += "simultaneously (i.e. only one option must be set)."
        print(settings.print_critical_msg(err_msg))
        raise SystemExit
      else:
        menu.options.tech = "".join(settings.AVAILABLE_TECHNIQUES)
      for skip_tech_name in settings.AVAILABLE_TECHNIQUES:
        if skip_tech_name in menu.options.skip_tech:
          menu.options.tech = menu.options.tech.replace(skip_tech_name,"")
      if len(menu.options.tech) == 0:
        err_msg = "Detection procedure was aborted due to skipping all injection techniques."
        print(settings.print_critical_msg(err_msg))
        raise SystemExit

    # Check if specified wrong injection technique
    if menu.options.tech and menu.options.tech not in settings.AVAILABLE_TECHNIQUES:
      found_tech = False
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
        err_msg += "The value for option '"
        if not settings.SKIP_TECHNIQUES :
          err_msg += "--technique"
        else:
          err_msg += "--skip-technique"    
        err_msg += "' must be a string composed by the letters "
        err_msg += ', '.join(settings.AVAILABLE_TECHNIQUES).upper()
        err_msg += ". Refer to the official wiki for details."
        print(settings.print_critical_msg(err_msg))
        raise SystemExit()

    if not menu.options.tech:
      menu.options.tech = "".join(settings.AVAILABLE_TECHNIQUES)
    else:
      settings.USER_SUPPLIED_TECHNIQUE = True

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
      if menu.options.auth_cred and menu.options.auth_type:
        if settings.VERBOSITY_LEVEL != 0:
          debug_msg = "Used a valid pair of " + menu.options.auth_type 
          debug_msg += " HTTP authentication credentials '" + menu.options.auth_cred + "'." 
          print(settings.print_bold_debug_msg(debug_msg))
        session_handler.import_valid_credentials(url, authentication_type=menu.options.auth_type, \
                                                 admin_panel=url, username=menu.options.auth_cred.split(":")[0], \
                                                 password=menu.options.auth_cred.split(":")[1]
                                                 )
      try:
        if menu.options.flush_session:
          session_handler.flush(url)
        # Check for CGI scripts on url
        checks.check_CGI_scripts(url)
        # Check if defined "--file-upload" option.
        if menu.options.file_upload:
          checks.file_upload()
          try:
            _urllib.request.urlopen(menu.options.file_upload, timeout=settings.TIMEOUT)
          except _urllib.error.HTTPError as err_msg:
            print(settings.print_critical_msg(str(err_msg.code)))
            raise SystemExit()
          except _urllib.error.URLError as err_msg:
            print(settings.print_critical_msg(str(err_msg.reason) + "."))
            raise SystemExit()
        try:
          info_msg = "Performing identification checks to the target URL."
          print(settings.print_info_msg(info_msg))
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
        except (KeyError, AttributeError):
          pass
        # Load tamper scripts
        if menu.options.tamper:
          settings.USER_SUPPLIED_TAMPER = menu.options.tamper
          # checks.tamper_scripts(stored_tamper_scripts=False)
          
      except AttributeError:
        pass

    else:
      err_msg = "You must specify the target URL."
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()

    # Retrieve everything from the supported enumeration options.
    if menu.options.enum_all:
      checks.enable_all_enumeration_options()

    controller.do_check(url, http_request_method, filename)
    return filename

  # Accidental stop / restart of the target host server.
  except (_http_client.BadStatusLine, SocketError) as err_msg:
    if settings.VERBOSITY_LEVEL != 0:
      print(settings.SINGLE_WHITESPACE)
    err_msg = "The target host is not responding."
    err_msg += " Please ensure that is up and try again."
    print("\n" + settings.print_critical_msg(err_msg))
    logs.print_logs_notification(filename, url)      

try:
  filename = ""

  # Check if defined "--version" option.
  if menu.options.version:
    version.show_version()
    raise SystemExit()

  # Print the legal disclaimer msg.
  print(settings.print_legal_disclaimer_msg(settings.LEGAL_DISCLAIMER_MSG))

  # Get total number of days from last update
  if os.path.isfile(settings.SETTINGS_PATH):
    if settings.STABLE_RELEASE == False:
      common.days_from_last_update()

  # Check if specified wrong alternative shell
  if menu.options.alter_shell:
    if menu.options.alter_shell.lower() not in settings.AVAILABLE_SHELLS:
      err_msg = "'" + menu.options.alter_shell + "' shell is not supported!"
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()

  # Define the level of verbosity.
  if menu.options.verbose > 4:
    err_msg = "The value for option '-v' "
    err_msg += "must be an integer value from range [0, 4]."
    print(settings.print_critical_msg(err_msg))
    raise SystemExit()
  else:  
    settings.VERBOSITY_LEVEL = menu.options.verbose

  if menu.options.smoke_test:
    smoke_test()

  if menu.options.ignore_redirects:
    settings.FOLLOW_REDIRECT = False

  if settings.STDIN_PARSING or settings.CRAWLING or menu.options.bulkfile or menu.options.shellshock:
    settings.OS_CHECKS_NUM = 1

  for os_checks_num in range(0, int(settings.OS_CHECKS_NUM)):
    # Check if defined "--list-tampers" option.
    if menu.options.list_tampers:
      checks.list_tamper_scripts()
      raise SystemExit()

    if settings.READLINE_ERROR :
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

    # Check if defined "--purge" option.
    if menu.options.purge:
      purge.purge()

    # Check for missing mandatory option(s).
    if not settings.STDIN_PARSING and not any((menu.options.url, menu.options.logfile, menu.options.bulkfile, \
                menu.options.requestfile, menu.options.sitemap_url, menu.options.wizard, \
                menu.options.update, menu.options.list_tampers, menu.options.noncore_dependencies)):
      if not menu.options.purge:
        err_msg = "Missing a mandatory option (-u, -l, -m, -r, -x, --wizard, --update, --list-tampers, --purge or --dependencies). "
        err_msg += "Use -h for help."
        print(settings.print_critical_msg(err_msg))
      raise SystemExit()

    if menu.options.codec:
      if menu.options.codec.lower() not in settings.ENCODING_LIST:
        err_msg = "The provided charset '"  + menu.options.codec + "' is unknown. "
        err_msg += "Please visit 'http://docs.python.org/library/codecs.html#standard-encodings' "
        err_msg += "to get the full list of supported charsets."
        print(settings.print_critical_msg(err_msg))
        raise SystemExit()
      else:
        settings.DEFAULT_CODEC  = menu.options.codec.lower()

    if menu.options.header and len(menu.options.header.split("\\n"))> 1:
        warn_msg = "Swithing '--header' to '--headers' "
        warn_msg += "due to multiple extra HTTP headers."
        print(settings.print_warning_msg(warn_msg))

    if menu.options.method:
      settings.HTTP_METHOD = menu.options.method

    if menu.options.answers:
      settings.ANSWERS = menu.options.answers

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

    if menu.options.failed_tries == 0:
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

    # Check the user-defined OS.
    if menu.options.os:
      checks.user_defined_os()

    # Check if defined "--check-tor" option. 
    if menu.options.tor_check and not menu.options.tor:
      err_msg = "The '--check-tor' swich requires usage of '--tor' switch."
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()

    # Check if defined "--ignore-code" option.
    if menu.options.ignore_code and "," in menu.options.ignore_code:
      err_msg = "Ignoring more than one HTTP error code, is not yet supported."
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()

    # Check if defined "--wizard" option.
    if menu.options.wizard:
      if not menu.options.url and not settings.STDIN_PARSING:
        while True:
          message = "Enter full target URL (-u) > "
          menu.options.url = common.read_input(message, default=None, check_batch=True)
          if menu.options.url is None or len(menu.options.url) == 0:
            pass
          else:
            break
      message = "Enter POST data (--data) [Enter for none] > "
      if settings.STDIN_PARSING or menu.options.data:
        print(settings.print_message(message + menu.options.data))
      else:
        menu.options.data = common.read_input(message, default=None, check_batch=True)
        if menu.options.data is not None and len(menu.options.data) == 0:
          menu.options.data = False
      while True:
        message = "Enter injection level (--level) [1-3, Default: 1] > "
        if settings.STDIN_PARSING:
          print(settings.print_message(message + str(menu.options.level)))
          break
        try:
          menu.options.level = int(common.read_input(message, default=settings.DEFAULT_INJECTION_LEVEL, check_batch=True))
          if menu.options.level > int(settings.HTTP_HEADER_INJECTION_LEVEL):
            pass
          else:
            break
        except ValueError:
          pass

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

    if menu.options.sitemap_url:
      settings.SITEMAP_CHECK = True

    if menu.options.crawldepth > 0 or settings.SITEMAP_CHECK:
      settings.CRAWLING = True

    if menu.options.crawl_exclude:
      if not settings.CRAWLING:
        err_msg = "The '--crawl-exclude' option requires usage of '--crawl' option."
        print(settings.print_critical_msg(err_msg))
        raise SystemExit()
      try:
        re.compile(menu.options.crawl_exclude)
      except Exception as e:
        err_msg = "invalid regular expression '" + menu.options.crawl_exclude + "' (" + str(e) + ")."
        print(settings.print_critical_msg(err_msg))
        raise SystemExit()

    # Check arguments
    if len(sys.argv) == 1 and not settings.STDIN_PARSING:
      menu.parser.print_help()
      print(settings.SINGLE_WHITESPACE)
      raise SystemExit()
    else:
      # Check for INJECT_HERE tag.
      inject_tag_regex_match = re.search(settings.INJECT_TAG_REGEX, ",".join(str(x) for x in sys.argv))
      if inject_tag_regex_match:
        settings.INJECT_TAG = inject_tag_regex_match.group(0)

    # Check provided parameters for tests
    checks.check_provided_parameters()

    if menu.options.level != settings.DEFAULT_INJECTION_LEVEL:
      settings.USER_SUPPLIED_LEVEL = menu.options.level
      
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

    # Check if ".git" exists and check for updated version!
    if os.path.isdir("./.git") and settings.CHECK_FOR_UPDATES_ON_START:
      update.check_for_update()

    # Check if option is "--url" for single url test.
    if menu.options.sitemap_url:
      url = menu.options.sitemap_url
    else:  
      url = menu.options.url

    if not settings.STDIN_PARSING and not menu.options.bulkfile and not settings.CRAWLING:
      http_request_method  = checks.check_http_method(url)
      if os_checks_num == 0:
        settings.INIT_TEST = True
      response, url = url_response(url)
      if response != False:
        filename = logs.logs_filename_creation(url)
        main(filename, url)

    else:
      output_href = []
      # Check if option is "-m" for multiple urls test.
      if menu.options.bulkfile:
        bulkfile = menu.options.bulkfile
        if os_checks_num == 0:
          info_msg = "Parsing targets using the '" + os.path.split(bulkfile)[1] + "' file. "
          sys.stdout.write(settings.print_info_msg(info_msg))
          sys.stdout.flush()
        if not os.path.exists(bulkfile):
          print(settings.SINGLE_WHITESPACE)
          err_msg = "It seems that the '" + os.path.split(bulkfile)[1] + "' file, does not exist."
          sys.stdout.write(settings.print_critical_msg(err_msg) + "\n")
          sys.stdout.flush()
          raise SystemExit()
        elif os.stat(bulkfile).st_size == 0:
          print(settings.SINGLE_WHITESPACE)
          err_msg = "It seems that the '" + os.path.split(bulkfile)[1] + "' file, is empty."
          sys.stdout.write(settings.print_critical_msg(err_msg) + "\n")
          sys.stdout.flush()
          raise SystemExit()
        else:
          settings.MULTI_TARGETS = True
          print(settings.SINGLE_WHITESPACE)
          with open(menu.options.bulkfile) as f:
            bulkfile = [url.replace(settings.SINGLE_WHITESPACE, _urllib.parse.quote_plus(settings.SINGLE_WHITESPACE)).strip() for url in f]
      
      # Check if option "--crawl" is enabled.
      if settings.CRAWLING:
        settings.CRAWLING_PHASE = True
        url_num = 1
        if not menu.options.bulkfile and not settings.STDIN_PARSING:
          crawling_list = 1
          output_href = crawler.crawler(url, url_num, crawling_list)
          output_href.append(url)
        else:
          if settings.STDIN_PARSING:
            bulkfile = stdin_parsing_target(os_checks_num)
          crawling_list = len(bulkfile)
          for url in bulkfile:
            output_href += (crawler.crawler(url, url_num, crawling_list))
            url_num += 1
          output_href = output_href + bulkfile
          output_href = [x for x in output_href if x not in settings.HREF_SKIPPED]
        if not menu.options.shellshock:
          output_href = crawler.normalize_results(output_href)
        settings.CRAWLING_PHASE = False
      else:
        filename = None
        if not settings.STDIN_PARSING:
          output_href = output_href + bulkfile
        else:
          output_href = stdin_parsing_target(os_checks_num)

      # Removing duplicates from list.
      clean_output_href = []
      [clean_output_href.append(x) for x in output_href if x not in clean_output_href]
      # Removing empty elements from list.
      clean_output_href = [x for x in clean_output_href if x]
      if len(output_href) != 0 and not settings.STDIN_PARSING:
        if filename is not None:
          filename = crawler.store_crawling(output_href)
        info_msg = "Found a total of " + str(len(clean_output_href)) + " target"+ "s"[len(clean_output_href) == 1:] + "."
        print(settings.print_info_msg(info_msg))
      url_num = 0
      for url in clean_output_href:
        if check_for_injected_url(url):
          if settings.SKIP_VULNERABLE_HOST is None:
            while True:
              message = "An injection point has already been detected against '" + _urllib.parse.urlparse(url).netloc + "'. "
              message += "Do you want to skip further tests involving it? [Y/n] > "
              skip_host = common.read_input(message, default="Y", check_batch=True)
              if skip_host in settings.CHOICE_YES:
                settings.SKIP_VULNERABLE_HOST = True
                break
              elif skip_host in settings.CHOICE_NO:
                settings.SKIP_VULNERABLE_HOST = False
                break
              elif skip_host in settings.CHOICE_QUIT:
                raise SystemExit()
              else:
                common.invalid_option(skip_host)  
                pass

          if settings.SKIP_VULNERABLE_HOST:
            url_num += 1
            info_msg = "Skipping URL '" + url + "' (" + str(url_num) + "/" + str(len(clean_output_href)) + ")."
            print(settings.print_info_msg(info_msg))   

        if not check_for_injected_url(url) or settings.SKIP_VULNERABLE_HOST is False:
          if not check_for_injected_url(url):
            settings.SKIP_VULNERABLE_HOST = None
          http_request_method = checks.check_http_method(url)
          if (settings.CRAWLING and re.search(r"(.*?)\?(.+)", url) or menu.options.shellshock) or settings.MULTI_TARGETS:    
            url_num += 1
            perform_check = True
            while True:
              print(settings.print_message("[" + str(url_num) + "/" + str(len(clean_output_href)) + "] URL - " + url))
              message = "Do you want to use URL #" + str(url_num) + " to perform tests? [Y/n] > "
              next_url = common.read_input(message, default="Y", check_batch=True)
              if next_url in settings.CHOICE_YES:
                break
              elif next_url in settings.CHOICE_NO:
                perform_check = False
                if url_num == len(clean_output_href):
                  raise SystemExit()
                else:
                  break
              elif next_url in settings.CHOICE_QUIT:
                raise SystemExit()
              else:
                common.invalid_option(next_url)  
                pass
            if perform_check:
              if os_checks_num == 0:
                settings.INIT_TEST = True
              if url == clean_output_href[-1]:
                settings.EOF = True
              # Reset the injection level
              if menu.options.level > settings.HTTP_HEADER_INJECTION_LEVEL:
                menu.options.level = 1
              init_injection(url)
              try:
                response, url = url_response(url)
                if response != False:
                  filename = logs.logs_filename_creation(url)
                  main(filename, url)
              except:
                pass 
          else:
            url_num += 1
            print(settings.print_message("[" + str(url_num) + "/" + str(len(clean_output_href)) + "] Skipping URL - " + url))

        if url_num == len(clean_output_href):
          raise SystemExit()

except KeyboardInterrupt:
  try:
    checks.user_aborted(filename, url)
  except NameError:
    abort_msg = "User quit (Ctrl-C was pressed)."
    print(settings.print_abort_msg(abort_msg))
    raise SystemExit()

except SystemExit: 
  raise SystemExit()

except EOFError:
  err_msg = "Exiting, due to EOFError."
  print(settings.print_error_msg(err_msg))
  raise SystemExit()

# eof