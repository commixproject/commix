#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2026 Anastasios Stasinopoulos (@ancst).

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
import random
import signal
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

if settings.IS_WINDOWS:
  import codecs
  # Reference: https://github.com/nodejs/node/issues/12786#issuecomment-298652440
  codecs.register(lambda name: codecs.lookup("utf-8") if name == "cp65001" else None)
  # Use Colorama to make Termcolor work on Windows too :)
  init()


"""
Define HTTP User-Agent header.
"""
def defined_http_headers(url):
  def extra_headers():
    if any((menu.options.header, menu.options.headers)):
      settings.EXTRA_HTTP_HEADERS = True
      if settings.VERBOSITY_LEVEL != 0:
        debug_msg = "Setting extra HTTP headers."
        settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))  

  def cookie():
    if menu.options.cookie and settings.VERBOSITY_LEVEL != 0:
      debug_msg = "Setting the HTTP " + settings.COOKIE + " header."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))  

  def referer(url):
    if menu.options.referer is None:
      if menu.options.level and int(menu.options.level) == settings.HTTP_HEADER_INJECTION_LEVEL:
        menu.options.referer = _urllib.parse.urljoin(url, _urllib.parse.urlparse(url).path)
    if menu.options.referer and settings.VERBOSITY_LEVEL != 0:
      debug_msg = "Setting the HTTP " + settings.REFERER + " header."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg)) 

  def host(url):
    if menu.options.host is None:
      menu.options.host = _urllib.parse.urlparse(url).netloc
    if menu.options.host and settings.VERBOSITY_LEVEL != 0:
      debug_msg = "Setting the HTTP " + settings.HOST + " header."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg)) 

  def user_agent():
    # Determine which option is enabled
    mobile_agent = menu.options.mobile
    random_agent = menu.options.random_agent
    custom_agent = menu.options.agent != settings.DEFAULT_USER_AGENT and not menu.options.requestfile

    # Final debug message
    if settings.VERBOSITY_LEVEL != 0:
      debug_msg = "Setting the HTTP User-Agent header."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

    # Combined check for incompatible combinations
    if (mobile_agent and (custom_agent or random_agent)) or (random_agent and (custom_agent or mobile_agent)):
      if not any([settings.MULTI_TARGETS, settings.STDIN_PARSING]):
        if mobile_agent:
          err_msg = "The switch '--mobile' is incompatible with option '--user-agent' or switch '--random-agent'."
        else:
          err_msg = "The switch '--random-agent' is incompatible with option '--user-agent' or switch '--mobile'."
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
        raise SystemExit()

    # Set the User-Agent
    if mobile_agent:
      menu.options.agent = checks.mobile_user_agents()
    elif random_agent:
      if settings.VERBOSITY_LEVEL != 0:
        debug_msg = "Fetching random HTTP User-Agent header. "
        settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
      user_agents = common.load_list_from_file(settings.USER_AGENT_LIST, "user-agent list")
      menu.options.agent = random.choice(user_agents)
      info_msg = "The fetched random HTTP User-Agent header value is '" + menu.options.agent + "'."
      settings.print_data_to_stdout(settings.print_info_msg(info_msg))

  extra_headers()
  cookie()
  referer(url)
  host(url)
  user_agent()

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
    # Reuse check_http_traffic()'s own fetch instead of requesting twice.
    response = headers.check_http_traffic(request)
    if response is not None:
      return response
    # Check if defined any HTTP Proxy (--proxy option).
    if menu.options.proxy or menu.options.ignore_proxy:
      return proxy.use_proxy(request)
    else:
      try:
        response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
        return response

      except ValueError:
        # Invalid format for the '--header' option.
        if settings.VERBOSITY_LEVEL < 2:
          settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
        err_msg = "Use '--header=\"HEADER_NAME: HEADER_VALUE\"'"
        err_msg += "to provide an extra HTTP header or"
        err_msg += " '--header=\"HEADER_NAME: " + settings.CUSTOM_INJECTION_MARKER_CHAR  + "\"' "
        err_msg += "if you want to try to exploit the provided HTTP header."
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
        raise SystemExit()

  except Exception as err_msg:
    requests.request_failed(err_msg)

"""
Check internet connection before assessing the target.
"""
def check_internet(url):
  settings.CHECK_INTERNET = True
  settings.CHECK_INTERNET_ADDRESS = checks.check_http_s(url)
  info_msg = "Checking for internet connection."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  
  if settings.VERBOSITY_LEVEL >= 2:
    settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
  try:
    request = _urllib.request.Request(settings.CHECK_INTERNET_ADDRESS, method=settings.HTTPMETHOD.GET)
    headers.do_check(request)
    examine_request(request, url)
  except (Exception, SystemExit):
    settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
    error_msg = "No internet connection detected."
    settings.print_data_to_stdout(settings.print_critical_msg(error_msg))

"""
The init (URL) request.
"""
def init_request(url, http_request_method):

  def perform_init_request(url, http_request_method):
    if settings.USER_DEFINED_POST_DATA:
      request = _urllib.request.Request(url, settings.USER_DEFINED_POST_DATA.encode(), method=http_request_method)
    else:
      request = _urllib.request.Request(url, method=http_request_method)
    headers.do_check(request)
    return request

  def redirect_probe_request(url, http_request_method):
    # Redirect detection doesn't need the (possibly slow) POST body.
    request = _urllib.request.Request(url, method=http_request_method)
    headers.do_check(request)
    return request

  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Setting the HTTP timeout."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
  if menu.options.timeout:
    settings.TIMEOUT = menu.options.timeout

  if menu.options.proxy: 
    proxy.do_check()

  if menu.options.auth_cred and menu.options.auth_type and settings.VERBOSITY_LEVEL != 0 :
    debug_msg = "Setting the HTTP authentication type and credentials."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

  _ = None
  response = None
  redirect_url = None

  try:
    if settings.VERBOSITY_LEVEL != 0:
      debug_msg = "Creating " + str(settings.SCHEME).upper() + " requests opener object."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
    opener = _urllib.request.build_opener(redirection.RedirectHandler())
    # Install globally so later bare urlopen() calls respect it too.
    _urllib.request.install_opener(opener)
    probe_request = redirect_probe_request(url, http_request_method)
    response = opener.open(probe_request, timeout=settings.TIMEOUT)
    if response.geturl() != url:
      redirect_url = response.geturl()

  except _urllib.error.HTTPError as e:
    _ = True
    redirect_url = e.geturl()

  except Exception as err_msg:
    requests.request_failed(err_msg)

  if redirect_url and redirect_url != url and settings.FOLLOW_REDIRECT:
    redirect_url = redirection.do_check(probe_request, url, redirect_url, http_request_method)
    if redirect_url is not None and settings.FOLLOW_REDIRECT:
      if _:
        url = redirect_url

  # Build the real request (full data) now that the final URL is known.
  request = perform_init_request(url, http_request_method)

  # Define HTTP headers
  defined_http_headers(url)
  # Check the internet connection (--check-internet switch).
  if menu.options.check_internet:
    check_internet(url)

  checks.check_connection(url)
  settings.CUSTOM_INJECTION_MARKER = checks.custom_injection_marker_character(url, http_request_method)

  return request, url
  
"""
Get the URL response.
"""
def url_response(url, http_request_method):
  if settings.CHECK_INTERNET:
    settings.CHECK_INTERNET = False
  if settings.INIT_TEST == True:
    info_msg = "Testing connection to the target URL. "
    settings.print_data_to_stdout(settings.print_bold_info_msg(info_msg))

  # Check if http / https
  url = checks.check_http_s(url)
  request, url = init_request(url, http_request_method)
  # Set early so WAF detection can persist the finding.
  settings.TARGET_URL = _urllib.parse.urlparse(url).hostname
  settings.TARGET_NETLOC = _urllib.parse.urlparse(url).netloc
  # Cache clean-request timing to avoid repeating the measurement, resetting it first to prevent stale values.
  settings.INIT_CONNECTION_TIME = None
  settings.INIT_CONNECTION_FETCH_TIME = None
  settings.INIT_CONNECTION_URL = None

  # Piggyback the WAF probe on the same request to avoid an extra round-trip.
  conn_request, conn_url = request, url
  do_waf = not menu.options.skip_waf
  if do_waf:
    settings.COOKIE_INJECTION = None
    conn_request, conn_url = checks.check_waf(url, http_request_method)
    settings.WAF_DETECTION_PHASE = True

  _conn_start = time.time()
  response = examine_request(conn_request, conn_url)
  if do_waf:
    settings.WAF_DETECTION_PHASE = False
  if response is not False and response is not None:
    _conn_end = time.time()
    settings.INIT_CONNECTION_TIME = _conn_end - _conn_start
    settings.INIT_CONNECTION_FETCH_TIME = _conn_end
    settings.INIT_CONNECTION_URL = conn_url
  if settings.MULTI_TARGETS or settings.CRAWLING:
    # initiate total of requests
    settings.TOTAL_OF_REQUESTS = 0

  return response, url

"""
Initialize injection-related settings and state.
"""
def init_injection(url):
  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Initializing the knowledge base."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

  # Ensure redirection is followed (unless ignored) and core injection paths are enabled
  settings.FOLLOW_REDIRECT = not menu.options.ignore_redirects
  settings.SKIP_CODE_INJECTIONS = False
  settings.SKIP_COMMAND_INJECTIONS = False

  # Reset injection checker and technique flags
  settings.INJECTION_CHECKER = False
  settings.CLASSIC_STATE = False
  settings.EVAL_BASED_STATE = False
  settings.TIME_BASED_STATE = False
  settings.FILE_BASED_STATE = False
  settings.TEMPFILE_BASED_STATE = False
  settings.TIME_RELATED_ATTACK = False

  # Reset custom and temporary settings
  settings.TESTED_PARAMETERS_LIST = []
  settings.METHODS_WITH_NON_LISTED_PARAMS = []
  settings.SKIP_NON_CUSTOM_PARAMS = None
  settings.CUSTOM_INJECTION_MARKER = None
  settings.CUSTOM_FILENAME = ""

  # Reset web-root state
  settings.WEB_ROOT = ""
  settings.DEFAULT_WEB_ROOT = ""
  settings.CUSTOM_WEB_ROOT = False
  if not settings.USER_APPLIED_WEB_ROOT:
    menu.options.web_root = False
  
"""
Validate and normalize a target line, returning the cleaned URL or None.
"""
def parse_target_line(line):
  if re.search(r"\b(https?://[^\s'\"]+|[\w.]+\.\w{2,3}[/\w+]*\?[^\s'\"]+)", line, re.I):
    line = line.replace(settings.SINGLE_WHITESPACE, _urllib.parse.quote_plus(settings.SINGLE_WHITESPACE)).strip()
    return line.rstrip()
  return None

"""
Using 'stdin' for parsing targets.
"""
def stdin_parsing_target(os_checks_num):
  _ = []
  if os_checks_num == 0:
    info_msg = "Using 'stdin' for parsing targets list."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  menu.options.batch = True
  settings.MULTI_TARGETS = True
  for url in sys.stdin:
    target = parse_target_line(url)
    if target:
      _.append(target)
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
Check if value is inside boundaries
"""
def check_value_inside_boundaries(url, http_request_method):
  url = checks.value_inside_boundaries(url, http_request_method)
  settings.USER_DEFINED_POST_DATA = checks.value_inside_boundaries(settings.USER_DEFINED_POST_DATA, http_request_method)
  return url

"""
The main function.
"""
def main(filename, url, http_request_method):
  try:
    # Reset per-target state so file access isn't silently skipped for later targets.
    settings.FILE_ACCESS_DONE = False

    if menu.options.alert:
      if menu.options.alert.startswith('-'):
        err_msg = "Value for option '--alert' must be valid operating system command(s)."
        settings.print_data_to_stdout(settings.print_error_msg(err_msg))
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
    elif menu.options.url_reload:
      warn_msg = "The '--url-reload' option has no effect without '--data'."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

    if menu.options.flush_session:
      session_handler.flush(url)

    url = check_value_inside_boundaries(url, http_request_method)

    if menu.options.level is not None and menu.options.level is not False:
      settings.INJECTION_LEVEL = int(menu.options.level)
      if settings.INJECTION_LEVEL not in (settings.DEFAULT_INJECTION_LEVEL, settings.COOKIE_INJECTION_LEVEL, settings.HTTP_HEADER_INJECTION_LEVEL):
        err_msg = "The value for option '--level' must be an integer value from range [1, 3]."
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
        raise SystemExit()
    else:
      settings.INJECTION_LEVEL = settings.DEFAULT_INJECTION_LEVEL

    if menu.options.level and settings.INJECTION_LEVEL >= settings.DEFAULT_INJECTION_LEVEL:
        settings.USER_APPLIED_LEVEL = settings.INJECTION_LEVEL

    if not settings.USER_APPLIED_LEVEL :
      settings.INJECTION_LEVEL = settings.USER_APPLIED_LEVEL = session_handler.applied_levels(url, http_request_method)

    # Define the level of tests to perform.
    if settings.INJECTION_LEVEL == settings.DEFAULT_INJECTION_LEVEL:
      settings.SEPARATORS = sorted(set(settings.SEPARATORS_LVL1), key=settings.SEPARATORS_LVL1.index)
      settings.PREFIXES = sorted(set(settings.PREFIXES_LVL1), key=settings.PREFIXES_LVL1.index)
      settings.SUFFIXES = sorted(set(settings.SUFFIXES_LVL1), key=settings.SUFFIXES_LVL1.index)
      settings.EVAL_PREFIXES = sorted(set(settings.EVAL_PREFIXES_LVL1), key=settings.EVAL_PREFIXES_LVL1.index)
      settings.EVAL_SUFFIXES = sorted(set(settings.EVAL_SUFFIXES_LVL1), key=settings.EVAL_SUFFIXES_LVL1.index)
      settings.EVAL_SEPARATORS = sorted(set(settings.EVAL_SEPARATORS_LVL1), key=settings.EVAL_SEPARATORS_LVL1.index)
      settings.EXECUTION_FUNCTIONS = sorted(set(settings.EXECUTION_FUNCTIONS_LVL1), key=settings.EXECUTION_FUNCTIONS_LVL1.index)
    elif settings.INJECTION_LEVEL == settings.COOKIE_INJECTION_LEVEL:
      settings.SEPARATORS = sorted(set(settings.SEPARATORS_LVL2), key=settings.SEPARATORS_LVL2.index)
      settings.PREFIXES = sorted(set(settings.PREFIXES_LVL2), key=settings.PREFIXES_LVL2.index)
      settings.SUFFIXES = sorted(set(settings.SUFFIXES_LVL2), key=settings.SUFFIXES_LVL2.index)
      settings.EVAL_PREFIXES = sorted(set(settings.EVAL_PREFIXES_LVL2), key=settings.EVAL_PREFIXES_LVL2.index)
      settings.EVAL_SUFFIXES = sorted(set(settings.EVAL_SUFFIXES_LVL2), key=settings.EVAL_SUFFIXES_LVL2.index)
      settings.EVAL_SEPARATORS = sorted(set(settings.EVAL_SEPARATORS_LVL2), key=settings.EVAL_SEPARATORS_LVL2.index)
      settings.EXECUTION_FUNCTIONS = sorted(set(settings.EXECUTION_FUNCTIONS_LVL2), key=settings.EXECUTION_FUNCTIONS_LVL2.index)
    elif settings.INJECTION_LEVEL == settings.HTTP_HEADER_INJECTION_LEVEL:
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
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()

    if menu.options.test_parameter and menu.options.skip_parameter:
      if type(menu.options.test_parameter) is bool:
        menu.options.test_parameter = None
      else:
        err_msg = "The options '-p' and '--skip' cannot be used "
        err_msg += "simultaneously (i.e. only one option must be set)."
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
        raise SystemExit()

    if menu.options.ignore_session:
      # Ignore session
      session_handler.ignore(url)

    # Check provided parameters for tests
    checks.check_provided_parameters()

    # Check if defined character used for splitting cookie values.
    if menu.options.cdel:
     settings.COOKIE_PARAM_DELIMITER = menu.options.cdel

    if menu.options.tech and settings.USER_APPLIED_TECHNIQUE != None:
      settings.USER_APPLIED_TECHNIQUE = True
    else:
      settings.USER_APPLIED_TECHNIQUE = None
      if len(session_handler.applied_techniques(url, http_request_method)) != 0:
        settings.SESSION_APPLIED_TECHNIQUES = session_handler.applied_techniques(url, http_request_method)
        menu.options.tech = settings.SESSION_APPLIED_TECHNIQUES
      else:
        menu.options.tech = ''.join([str(x) for x in settings.AVAILABLE_TECHNIQUES])

    menu.options.tech = menu.options.tech.lower()
    # Check for skipping injection techniques.
    if menu.options.skip_tech:
      # Convert injection technique(s) to lowercase
      menu.options.skip_tech = menu.options.skip_tech.lower()
      settings.SKIP_TECHNIQUES = True
      if settings.USER_APPLIED_TECHNIQUE:
        err_msg = "The options '--technique' and '--skip-technique' cannot be used "
        err_msg += "simultaneously (i.e. only one option must be set)."
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
        raise SystemExit()
      else:
        menu.options.tech = "".join(settings.AVAILABLE_TECHNIQUES)
      for skip_tech_name in settings.AVAILABLE_TECHNIQUES:
        if skip_tech_name in menu.options.skip_tech:
          menu.options.tech = menu.options.tech.replace(skip_tech_name, "")
      if len(menu.options.tech) == 0:
        err_msg = "Aborted the detection procedure due to skipping all injection techniques."
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
        raise SystemExit()

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
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
        raise SystemExit()

    # Check the file-destination
    if menu.options.file_write is not None and not menu.options.file_dest:
      err_msg = "You must specify the host's absolute filepath to write (i.e. '--file-dest')."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()

    if menu.options.file_dest and menu.options.file_write == None:
      err_msg = "You must enter the '--file-write' parameter."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()

    # The remote destination must be an absolute filepath (Unix-style, Windows drive-letter, or UNC).
    if menu.options.file_dest and not (menu.options.file_dest.startswith(("/", "\\")) or \
       re.match(r"^[A-Za-z]:[\\/]", menu.options.file_dest)):
      err_msg = "The value for option '--file-dest' must be an absolute filepath "
      err_msg += "(e.g. '/tmp/file' or 'C:\\Windows\\Temp\\file')."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()

    # Check the local file to write, before any tests are performed.
    if menu.options.file_write is not None:
      if not os.path.exists(menu.options.file_write):
        err_msg = "The specified local file '" + menu.options.file_write + "' does not exist."
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
        raise SystemExit()
      if not os.path.isfile(menu.options.file_write):
        err_msg = "The specified path '" + menu.options.file_write + "' is not a file."
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
        raise SystemExit()

    # Check if defined "--url" or "-m" option.
    if url:
      if menu.options.auth_cred and menu.options.auth_type:
        username, password = menu.options.auth_cred.split(":", 1)
        if not settings.LOAD_SESSION:
          session_handler.import_valid_credentials(url, authentication_type=menu.options.auth_type, \
                                                   admin_panel=url, username=username, \
                                                   password=password
                                                   )
      try:
        try:
          # Skip stability probing on resume unless content-reflection techniques ('c'/'e') are in scope.
          if not settings.LIKELY_RESUME and (not menu.options.tech or "c" in menu.options.tech or "e" in menu.options.tech):
            requests.is_url_content_stable(settings.INIT_CONNECTION_URL or url, response, settings.INIT_CONNECTION_FETCH_TIME, http_request_method)
            info_msg = "Performing heuristic (passive) tests on the target URL."
            settings.print_data_to_stdout(settings.print_info_msg(info_msg))
          # Webpage encoding detection.
          requests.encoding_detection(response)
          # Procedure for target server identification.
          requests.server_identification(response)
          # Procedure for target application identification
          requests.application_identification(url, response)
          # Specifies the technology supporting the web application
          requests.technology_identification(response)
          # Procedure for target server's operating system identification.
          if not settings.IDENTIFIED_TARGET_OS:
            requests.os_identification(response)
          if settings.IDENTIFIED_TARGET_OS:
            # Store the Server's root dir
            settings.DEFAULT_WEB_ROOT = settings.WEB_ROOT
            if menu.options.is_admin or menu.options.is_root and not menu.options.current_user:
              menu.options.current_user = True
            # Define Python working directory.
            checks.define_py_working_dir()
            # Check for wrong flags.
            checks.check_wrong_flags()
          else:
            checks.user_defined_os()
        except (KeyError, AttributeError):
          pass
        # Load tamper scripts
        if menu.options.tamper:
          settings.USER_APPLIED_TAMPER = menu.options.tamper
          checks.tamper_scripts(stored_tamper_scripts=False)
      except AttributeError:
        pass

    else:
      err_msg = "You must specify the target URL."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()

    # Retrieve everything from the supported enumeration options.
    if menu.options.enum_all:
      checks.enable_all_enumeration_options()
    controller.do_check(url, http_request_method, filename)
    return filename

  # Accidental stop / restart of the target host server.
  except (_http_client.BadStatusLine, SocketError) as err_msg:
    if any((settings.REVERSE_TCP, settings.BIND_TCP)):
      err_msg = "Failed to establish a connection."
    else:
      err_msg = "The target host is not responding."
      err_msg += " Please ensure it is up and try again."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    logs.print_logs_notification(filename, url)
    if any((settings.REVERSE_TCP, settings.BIND_TCP)):
      raise SystemExit()

  # Ctrl-C before controller.do_check() even starts (rare - do_check() has
  # its own handling for everything inside it).
  except KeyboardInterrupt:
    checks.handle_early_interrupt(filename, url)
    return

try:
  filename = ""

  # Check if defined "--version" option.
  if menu.options.version:
    version.show_version()
    raise SystemExit()

  # Print the legal disclaimer msg.
  settings.print_data_to_stdout(settings.print_legal_disclaimer_msg(settings.LEGAL_DISCLAIMER_MSG))

  # Get total number of days from last update
  if os.path.isfile(settings.SETTINGS_PATH):
    if settings.STABLE_RELEASE == False:
      common.days_from_last_update()

  # Check if specified wrong alternative shell
  if menu.options.alter_shell:
    if menu.options.alter_shell.lower() not in settings.AVAILABLE_SHELLS:
      err_msg = "'" + menu.options.alter_shell + "' shell is not supported!"
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()

  # Define the level of verbosity.
  if menu.options.verbose > 4:
    err_msg = "The value for option '-v' "
    err_msg += "must be an integer value from range [0, 4]."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()
  else:
    settings.VERBOSITY_LEVEL = menu.options.verbose

  # Hard '--time-limit' cutoff - a signal, immune to exception handling elsewhere.
  if menu.options.time_limit and hasattr(signal, "alarm"):
    def _time_limit_reached(signum, frame):
      err_msg = "Reached the specified time limit of " + str(menu.options.time_limit) + " second(s)."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      os._exit(0)
    signal.signal(signal.SIGALRM, _time_limit_reached)
    signal.alarm(max(1, int(round(menu.options.time_limit))))

  if settings.VERBOSITY_LEVEL != 0:
    settings.print_data_to_stdout(settings.execution("Starting"))

  if menu.options.smoke_test:
    smoke_test()

  try:
    # Treat non-interactive stdin as targets only when no explicit target was given.
    if hasattr(sys.stdin, "fileno") and not any((os.isatty(sys.stdin.fileno()), menu.options.ignore_stdin,
                menu.options.url, menu.options.requestfile, menu.options.bulkfile, menu.options.logfile)):
      settings.STDIN_PARSING = True
  except Exception as ex:
    if "fileno" in str(ex) and settings.STDIN_PARSING:
      settings.STDIN_PARSING = False

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

    # Check if defined "--ignore-dependencies" option.
    if not menu.options.ignore_dependencies:
      checks.third_party_dependencies()

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
                menu.options.update, menu.options.list_tampers)):
      if not menu.options.purge:
        err_msg = "Missing a mandatory option (-u, -l, -m, -r, -x, --wizard, --update, --list-tampers or --purge). "
        err_msg += "Use -h for help."
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()

    if menu.options.codec:
      if menu.options.codec.lower() not in settings.ENCODING_LIST:
        err_msg = "The provided charset '"  + menu.options.codec + "' is unknown. "
        err_msg += "Please visit 'http://docs.python.org/library/codecs.html#standard-encodings' "
        err_msg += "to get the full list of supported charsets."
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
        raise SystemExit()
      else:
        settings.DEFAULT_CODEC  = menu.options.codec.lower()

    if menu.options.header and len(menu.options.header.split(settings.END_LINE.ESCAPED_LF))> 1:
        warn_msg = "Due to multiple provided HTTP headers, switching '--header' to '--headers'."
        settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

    if menu.options.method:
      settings.HTTP_METHOD = menu.options.method

    if menu.options.answers:
      settings.ANSWERS = menu.options.answers

    # Check if defined "--proxy" option.
    if menu.options.proxy:
      if menu.options.tor:
        err_msg = "The switch '--tor' is incompatible with option '--proxy'."
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
        raise SystemExit()

      if menu.options.ignore_proxy:
        err_msg = "The option '--proxy' is incompatible with switch '--ignore-proxy'."
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
        raise SystemExit()

      for match in re.finditer(settings.PROXY_REGEX, menu.options.proxy):
        _, proxy_scheme, proxy_address, proxy_port = match.groups()
        if settings.SCHEME or proxy_scheme:
          if not settings.SCHEME:
            settings.SCHEME = proxy_scheme
          menu.options.proxy = proxy_address + ":" + proxy_port
          break
      else:
        err_msg = "Proxy value must be in format '(http|https)://address:port'."
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
        raise SystemExit()

    if not menu.options.proxy:
      # Check if defined Tor (--tor option).
      if menu.options.tor:
        if menu.options.tor_port:
          settings.TOR_HTTP_PROXY_PORT = menu.options.tor_port
        menu.options.proxy = settings.TOR_HTTP_PROXY_IP + ":" + settings.TOR_HTTP_PROXY_PORT
        tor.do_check()

    if menu.options.ignore_session and menu.options.flush_session:
      err_msg = "The '--ignore-session' option is unlikely to work combined with the '--flush-session' option."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()

    if menu.options.failed_tries == 0:
      err_msg = "You must specify '--failed-tries' value, greater than zero."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()

    # Check if defined "--auth-cred" and/or '--auth-type'.
    if (menu.options.auth_type and not menu.options.auth_cred) or (menu.options.auth_cred and not menu.options.auth_type):
      err_msg = "You must specify both '--auth-cred' and '--auth-type' options."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()

    if menu.options.auth_cred and menu.options.auth_type:
      if menu.options.auth_type.lower() in (settings.AUTH_TYPE.BASIC, settings.AUTH_TYPE.DIGEST) and not re.search(settings.AUTH_CRED_REGEX, menu.options.auth_cred):
        error_msg = "HTTP " + str(menu.options.auth_type)
        error_msg += " authentication credentials value must be in format 'username:password'."
        settings.print_data_to_stdout(settings.print_critical_msg(error_msg))
        raise SystemExit()

    if menu.options.requestfile and menu.options.url:
      err_msg = "The '-r' option is incompatible with option '-u' ('--url')."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()

    if menu.options.bulkfile and menu.options.url:
      err_msg = "The '-m' option is incompatible with option '-u' ('--url')."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()

    # Check the user-defined OS.
    if menu.options.os:
      checks.user_defined_os()

    # Check if defined "--abort-code" option.
    if menu.options.abort_code:
      try:
        settings.ABORT_CODE = [int(_) for _ in re.split(settings.PARAMETER_SPLITTING_REGEX, menu.options.abort_code)]
      except ValueError:
        err_msg = "The option '--abort-code' should contain a list of integer values."
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
        raise SystemExit()

    # Check if defined "--ignore-code" option.
    if menu.options.ignore_code:
      try:
        settings.IGNORE_CODE = [int(_) for _ in re.split(settings.PARAMETER_SPLITTING_REGEX, menu.options.ignore_code)]
        if settings.VERBOSITY_LEVEL != 0:
          debug_msg = "Ignoring '" + str(', '.join(str(x) for x in settings.IGNORE_CODE)) + "' HTTP error code"+('', 's')[len(settings.IGNORE_CODE) > 1]+ "."
          settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
      except ValueError:
        err_msg = "The option '--ignore-code' should contain a list of integer values."
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
        raise SystemExit()

    # Check if defined "--wizard" option.
    if menu.options.wizard:
      info_msg = "Starting wizard interface."
      settings.print_data_to_stdout(settings.print_info_msg(info_msg))
      message = "Please enter full target URL (-u) "
      if menu.options.url:
        settings.print_data_to_stdout(settings.print_message(message + str(menu.options.url)))
      elif not menu.options.url and not settings.STDIN_PARSING:
        while True:
          menu.options.url = common.read_input(message, default=None, check_batch=True)
          if menu.options.url is None or len(menu.options.url) == 0:
            pass
          else:
            break
      message = "POST data (--data) [Enter for None] "
      if settings.STDIN_PARSING or menu.options.data:
        settings.print_data_to_stdout(settings.print_message(message + str(menu.options.data)))
      else:
        menu.options.data = common.read_input(message, default=None, check_batch=True)
        if menu.options.data is not None and len(menu.options.data) == 0:
          menu.options.data = False
      while True:
        message = "Injection difficulty (--level) [1-3, Default: 1] "
        if settings.STDIN_PARSING:
          settings.print_data_to_stdout(settings.print_message(message + str(settings.INJECTION_LEVEL)))
          break
        try:
          settings.INJECTION_LEVEL = int(common.read_input(message, default=settings.DEFAULT_INJECTION_LEVEL, check_batch=True))
          if settings.INJECTION_LEVEL > int(settings.HTTP_HEADER_INJECTION_LEVEL):
            pass
          else:
            break
        except ValueError:
          pass

    # Seconds to delay between each HTTP request.
    if menu.options.delay != 0:
      settings.DELAY = menu.options.delay

    # Check if defined "--timesec" option.
    if menu.options.timesec != 0:
      settings.TIMESEC = menu.options.timesec

    # Check if defined "--threads" option.
    if menu.options.threads > 1:
      try:
        import concurrent.futures
        threads_supported = True
      except ImportError:
        threads_supported = False
      if not threads_supported:
        warn_msg = "'--threads' needs Python 3.2+; continuing with a single thread."
        settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
      elif menu.options.threads > settings.MAX_THREADS:
        settings.THREADS = settings.MAX_THREADS
        warn_msg = "Setting '--threads' to the maximum of " + str(settings.MAX_THREADS) + " concurrent HTTP requests."
        settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
      else:
        settings.THREADS = menu.options.threads
      if settings.THREADS > 1 and settings.VERBOSITY_LEVEL != 0:
        debug_msg = "Setting " + str(settings.THREADS) + " concurrent HTTP requests."
        settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

    if menu.options.tor:
      settings.TIMESEC = settings.TIMESEC * 2
      warn_msg = "Increasing default value for option '--time-sec' to"
      warn_msg += " " + str(settings.TIMESEC) + ", because you provided switch '--tor'."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

    if menu.options.sitemap_url:
      settings.SITEMAP_CHECK = True

    if menu.options.crawldepth > 0 or settings.SITEMAP_CHECK:
      settings.CRAWLING = True

    if menu.options.crawl_exclude:
      if not settings.CRAWLING:
        err_msg = "The '--crawl-exclude' option requires usage of the '--crawl' option."
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
        raise SystemExit()
      try:
        re.compile(menu.options.crawl_exclude)
      except Exception as e:
        err_msg = "invalid regular expression '" + menu.options.crawl_exclude + "' (" + str(e) + ")."
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
        raise SystemExit()

    if menu.options.forms and not settings.CRAWLING:
      err_msg = "The '--forms' switch requires the '--crawl' option."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()

    # Check arguments
    if len(sys.argv) == 1 and not settings.STDIN_PARSING:
      menu.parser.print_help()
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
      raise SystemExit()
    else:
      # Check for INJECT_HERE tag.
      inject_tag_regex_match = re.search(settings.INJECT_TAG_REGEX, ",".join(str(x) for x in sys.argv))
      if inject_tag_regex_match:
        settings.INJECT_TAG = inject_tag_regex_match.group(0)

    # Check provided parameters for tests
    checks.check_provided_parameters()

    # Define the local path where Metasploit Framework is installed.
    if menu.options.msf_path:
      settings.METASPLOIT_PATH = menu.options.msf_path

    # Enable detection phase
    settings.DETECTION_PHASE = True

    # Parse target and data from HTTP proxy logs (i.e Burp / WebScarab).
    if menu.options.requestfile and menu.options.logfile:
      err_msg = "The '-r' option is unlikely to work combined with the '-l' option."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
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

    if menu.options.data and not settings.CRAWLING:
      settings.USER_DEFINED_POST_DATA = menu.options.data
      # Check if defined character used for splitting parameter values.
      if menu.options.pdel and menu.options.pdel in settings.USER_DEFINED_POST_DATA:
        settings.POST_DATA_PARAM_DELIMITER = menu.options.pdel
    else:
      # Check if defined character used for splitting parameter values.
      if menu.options.pdel and menu.options.pdel in url:
        settings.URL_PARAM_DELIMITER = menu.options.pdel
        
    http_request_method  = checks.check_http_method(url)
    if not settings.STDIN_PARSING and not menu.options.bulkfile and not settings.CRAWLING:
      if os_checks_num == 0:
        settings.INIT_TEST = True
      # Skip upfront detection-only probes below when a stored technique already exists.
      settings.LIKELY_RESUME = session_handler.has_any_stored_technique(url, http_request_method)
      response, url = url_response(url, http_request_method)
      if response != False:
        filename = logs.logs_filename_creation(url)
        session_handler.restore_waf_status(url)
        main(filename, url, http_request_method)

    else:
      output_href = []
      output_forms = []
      # Check if option is "-m" for multiple urls test.
      if menu.options.bulkfile:
        bulkfile = menu.options.bulkfile
        if os_checks_num == 0:
          info_msg = "Parsing targets using the '" + os.path.split(bulkfile)[1] + "' file. "
          settings.print_data_to_stdout(settings.print_info_msg(info_msg))
          
        if not os.path.exists(bulkfile):
          err_msg = "It seems the '" + os.path.split(bulkfile)[1] + "' file does not exist."
          settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
          raise SystemExit()

        elif os.stat(bulkfile).st_size == 0:
          err_msg = "It seems the '" + os.path.split(bulkfile)[1] + "' file is empty."
          settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
          raise SystemExit()

        else:
          settings.MULTI_TARGETS = True
          menu.options.batch = True
          with open(menu.options.bulkfile, encoding="utf-8-sig") as f:
            bulkfile = [x for x in (parse_target_line(url) for url in f) if x]

      # Check if option "--crawl" is enabled.
      if settings.CRAWLING:
        settings.CRAWLING_PHASE = True
        url_num = 1
        if not menu.options.bulkfile and not settings.STDIN_PARSING:
          crawling_list = 1
          output_href = crawler.crawler(url, url_num, crawling_list, http_request_method)
          output_href.append(url)
          output_forms += crawler.crawled_forms
        else:
          if settings.STDIN_PARSING:
            bulkfile = stdin_parsing_target(os_checks_num)
          crawling_list = len(bulkfile)
          for url in bulkfile:
            output_href += (crawler.crawler(url, url_num, crawling_list, http_request_method))
            output_forms += crawler.crawled_forms
            url_num += 1
          output_href = output_href + bulkfile
          output_href = [x for x in output_href if x not in settings.HREF_SKIPPED]
        if not menu.options.shellshock:
          try:
            output_href = crawler.normalize_results(output_href)
          except SystemExit:
            # No GET links; continue if crawled POST forms are available.
            if not output_forms:
              raise
            output_href = []
        settings.CRAWLING_PHASE = False
      else:
        filename = None
        if not settings.STDIN_PARSING:
          output_href = output_href + bulkfile
        else:
          output_href = stdin_parsing_target(os_checks_num)

      # Removing duplicates from list (order-preserving, O(n)).
      clean_output_href = []
      seen_href = set()
      for x in output_href:
        if x not in seen_href:
          seen_href.add(x)
          clean_output_href.append(x)
      # Removing empty elements from list.
      clean_output_href = [x for x in clean_output_href if x]
      if len(output_href) != 0:
        if filename is not None:
          filename = crawler.store_crawling(output_href)
        info_msg = "Found a total of " + str(len(clean_output_href)) + " target"+ "s"[len(clean_output_href) == 1:] + "."
        settings.print_data_to_stdout(settings.print_info_msg(info_msg))

      # Removing duplicates from the identified (crawled) forms (order-preserving, O(n)).
      clean_output_forms = []
      seen_forms = set()
      for x in output_forms:
        if x not in seen_forms:
          seen_forms.add(x)
          clean_output_forms.append(x)
      if len(clean_output_forms) != 0:
        info_msg = "Found a total of " + str(len(clean_output_forms)) + " form" + "s"[len(clean_output_forms) == 1:] + "."
        settings.print_data_to_stdout(settings.print_info_msg(info_msg))

      # Test crawled POST forms first; their method/data are handled separately.
      form_num = 0
      orig_data = menu.options.data
      orig_user_defined_post_data = settings.USER_DEFINED_POST_DATA
      for form_url, form_data in clean_output_forms:
        if check_for_injected_url(form_url):
          if settings.SKIP_VULNERABLE_HOST is None:
            while True:
              message = "An injection point has already been detected against '" + _urllib.parse.urlparse(form_url).netloc + "'. "
              message += "Do you want to skip further tests involving it? [Y/n] "
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
          form_num += 1
          info_msg = "Skipping form URL '" + form_url + "' (" + str(form_num) + "/" + str(len(clean_output_forms)) + ")."
          settings.print_data_to_stdout(settings.print_info_msg(info_msg))
          continue

        if not check_for_injected_url(form_url):
          settings.SKIP_VULNERABLE_HOST = None
        form_num += 1
        perform_check = True
        while True:
          settings.print_data_to_stdout(settings.print_message("[" + str(form_num) + "/" + str(len(clean_output_forms)) + "] FORM - POST " + form_url + " - " + form_data))
          message = "Do you want to use form #" + str(form_num) + " for testing? [Y/n] "
          next_form = common.read_input(message, default="Y", check_batch=True)
          if next_form in settings.CHOICE_YES:
            info_msg = "Testing form '" + form_url + "'."
            settings.print_data_to_stdout(settings.print_info_msg(info_msg))
            break
          elif next_form in settings.CHOICE_NO:
            perform_check = False
            break
          elif next_form in settings.CHOICE_QUIT:
            raise SystemExit()
          else:
            common.invalid_option(next_form)
            pass
        if perform_check:
          if os_checks_num == 0:
            settings.INIT_TEST = True
          # Reset the injection level
          if settings.INJECTION_LEVEL > settings.HTTP_HEADER_INJECTION_LEVEL:
            settings.INJECTION_LEVEL = 1
          menu.options.url = form_url
          menu.options.data = form_data
          settings.USER_DEFINED_POST_DATA = form_data
          settings.IGNORE_USER_DEFINED_POST_DATA = False
          init_injection(form_url)
          try:
            response, form_url = url_response(form_url, settings.HTTPMETHOD.POST)
            if response != False:
              filename = logs.logs_filename_creation(form_url)
              session_handler.restore_waf_status(form_url)
              main(filename, form_url, settings.HTTPMETHOD.POST)
          except KeyboardInterrupt:
            checks.handle_early_interrupt(filename, form_url)
          except (Exception, SystemExit):
            pass
          menu.options.data = orig_data
          settings.USER_DEFINED_POST_DATA = orig_user_defined_post_data

      url_num = 0
      for url in clean_output_href:
        if check_for_injected_url(url):
          if settings.SKIP_VULNERABLE_HOST is None:
            while True:
              message = "An injection point has already been detected against '" + _urllib.parse.urlparse(url).netloc + "'. "
              message += "Do you want to skip further tests involving it? [Y/n] "
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
            settings.print_data_to_stdout(settings.print_info_msg(info_msg))

        if not check_for_injected_url(url) or settings.SKIP_VULNERABLE_HOST is False:
          if not check_for_injected_url(url):
            settings.SKIP_VULNERABLE_HOST = None
          http_request_method = checks.check_http_method(url)
          if (settings.CRAWLING and re.search(r"(.*?)\?(.+)", url) or menu.options.shellshock) or settings.MULTI_TARGETS:
            url_num += 1
            perform_check = True
            while True:
              settings.print_data_to_stdout(settings.print_message("[" + str(url_num) + "/" + str(len(clean_output_href)) + "] URL - " + http_request_method + " " + url))
              message = "Do you want to use URL #" + str(url_num) + " for testing? [Y/n] "
              next_url = common.read_input(message, default="Y", check_batch=True)
              if next_url in settings.CHOICE_YES:
                info_msg = "Testing URL '" + url + "'."
                settings.print_data_to_stdout(settings.print_info_msg(info_msg))
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
              # Reset the injection level
              if settings.INJECTION_LEVEL > settings.HTTP_HEADER_INJECTION_LEVEL:
                settings.INJECTION_LEVEL = 1
              menu.options.url = url
              init_injection(url)
              try:
                response, url = url_response(url, http_request_method)
                if response != False:
                  filename = logs.logs_filename_creation(url)
                  session_handler.restore_waf_status(url)
                  main(filename, url, http_request_method)
              except KeyboardInterrupt:
                checks.handle_early_interrupt(filename, url)
              except (Exception, SystemExit):
                pass
          else:
            url_num += 1
            settings.print_data_to_stdout(settings.print_message("[" + str(url_num) + "/" + str(len(clean_output_href)) + "] Skipping URL - " + http_request_method + " " + url))

        if url_num == len(clean_output_href):
          raise SystemExit()

except KeyboardInterrupt:
  try:
    checks.user_aborted(filename, url)
  except NameError:
    abort_msg = "User quit (Ctrl-C pressed)."
    settings.print_data_to_stdout(settings.print_abort_msg(abort_msg))
  raise checks.exit()

except EOFError:
  err_msg = "Exiting, due to EOFError."
  settings.print_data_to_stdout(settings.print_error_msg(err_msg))
  raise checks.exit()

except SystemExit:
  raise checks.exit()

# eof