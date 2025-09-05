#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2025 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

import re
import sys
import time
import socket
from socket import error as SocketError
from src.utils import menu
from os.path import splitext
from src.utils import settings
from src.utils import session_handler
from src.thirdparty.six.moves import http_client as _http_client
# accept overly long result lines
_http_client._MAXLINE = 1 * 1024 * 1024
from src.utils import common
from src.utils import crawler
from src.core.requests import proxy
from src.core.requests import headers
from src.core.requests import requests
from src.core.requests import parameters
from src.core.requests import redirection
from src.core.requests import authentication
from src.core.injections.controller import checks
from src.thirdparty.six.moves import input as _input
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.six.moves import http_client as _http_client
from src.thirdparty.colorama import Fore, Back, Style, init

"""
Check if the content of the given URL is stable over time.
"""
def is_url_content_stable(url, delay=5):
  status = "stable"
  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Testing if the target URL content remains consistent between requests."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
  try:
    first_response_content = _urllib.request.urlopen(url, timeout=settings.TIMEOUT).read().strip()
    time.sleep(delay)
    second_response_content = _urllib.request.urlopen(url, timeout=settings.TIMEOUT).read().strip()
    if first_response_content != second_response_content:
      status = "dynamic"
  except Exception:
    msg = "Unable to determine target URL content stability due to retrieval errors."
    settings.print_data_to_stdout(settings.print_warning_msg(msg))
    return

  if settings.VERBOSITY_LEVEL != 0:
    msg = "Target URL content is " + status + "."
    settings.print_data_to_stdout(settings.print_bold_debug_msg(msg))


"""
Do a request to target URL.
"""
def crawler_request(url, http_request_method):
  try:
    # Check if defined POST data
    if settings.USER_DEFINED_POST_DATA:
      data = settings.USER_DEFINED_POST_DATA.encode(settings.DEFAULT_CODEC)
    else:
      data = None
    request = _urllib.request.Request(url, data, method=http_request_method)
    headers.do_check(request)
    headers.check_http_traffic(request)
    if menu.options.proxy or menu.options.ignore_proxy or menu.options.tor: 
      response = proxy.use_proxy(request)
    else:
      response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
    if type(response) is not bool and settings.FOLLOW_REDIRECT and response is not None:
      if response.geturl() != url:
        href = redirection.do_check(request, url, response.geturl())
        if href != url:
          crawler.store_hrefs(href, identified_hrefs=True, redirection=True)
    return response
  except (SocketError, _urllib.error.HTTPError, _urllib.error.URLError, _http_client.BadStatusLine, _http_client.IncompleteRead, _http_client.InvalidURL, Exception) as err_msg:
    if url not in settings.HREF_SKIPPED:
      settings.HREF_SKIPPED.append(url)
      settings.CRAWLED_SKIPPED_URLS_NUM += 1
      if settings.SITEMAP_XML_FILE in url and settings.NOT_FOUND_ERROR in str(err_msg):
        warn_msg = "'" + settings.SITEMAP_XML_FILE + "' not found."
        settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
      else:
        request_failed(err_msg)

"""
Estimating the response time (in seconds).
"""
def estimate_response_time(url, timesec, http_request_method):
  stored_auth_creds = False
  _ = False
  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Estimating the target URL response time. "
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
    
  # Check if defined POST data
  if menu.options.data:
    request = _urllib.request.Request(url, menu.options.data.replace(settings.TESTABLE_VALUE + settings.INJECT_TAG, settings.TESTABLE_VALUE).encode(settings.DEFAULT_CODEC), method=http_request_method)
  else:
    request = _urllib.request.Request(url.replace(settings.TESTABLE_VALUE + settings.INJECT_TAG, settings.TESTABLE_VALUE), method=http_request_method)

  headers.do_check(request)
  start = time.time()
  try:
    response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
    response.read(1)
    response.close()
    _ = True
  except _http_client.InvalidURL as err_msg:
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()
    
  except (_urllib.error.HTTPError, _urllib.error.URLError) as err:
    ignore_start = time.time()
    if settings.UNAUTHORIZED_ERROR in str(err) and int(settings.UNAUTHORIZED_ERROR) in settings.IGNORE_CODE:
      pass
    else:
      err_msg = "Unable to connect to the target URL"
      try:
        err_msg += " (Reason: " + str(err.args[0]).split("] ")[-1].lower() + ")."
      except IndexError:
        err_msg += " (" + str(err) + ")."

      # Use getattr to safely get the error code (HTTPError has it, URLError doesn't)
      err_code = getattr(err, "code", None)
      if str(err_code) != settings.UNAUTHORIZED_ERROR:
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      else:
        try:
          # Safely get auth header if present
          auth_line = ''
          if hasattr(err, 'headers') and err.headers:
            auth_line = err.headers.get('www-authenticate', '')
          auth_type = auth_line.split()[0] if auth_line else ''
          
          try:
            auth_obj = re.match(r'''(\w*)\s+realm=(.*)''', auth_line).groups()
            realm = auth_obj[1].split(',')[0].replace("\"", "")
          except (AttributeError, IndexError, TypeError):
            realm = False

        except ValueError:
          err_msg = "The identified HTTP authentication type (" + str(auth_type) + ") "
          err_msg += "is not yet supported."
          settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
          raise SystemExit()

        except IndexError:
          err_msg = "The provided pair of " + str(menu.options.auth_type)
          err_msg += " HTTP authentication credentials '" + str(menu.options.auth_cred) + "'"
          err_msg += " seems to be invalid."
          settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
          raise SystemExit()


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
          if stored_auth_creds and not menu.options.ignore_session:
            menu.options.auth_cred = stored_auth_creds
            info_msg = "Restoring credentials '"
            info_msg += menu.options.auth_cred + "' from previous stored session."
            settings.print_data_to_stdout(settings.print_info_msg(info_msg))
          else:
            # Basic authentication
            if menu.options.auth_type.lower() == settings.AUTH_TYPE.BASIC:
              if not int(settings.UNAUTHORIZED_ERROR) in settings.IGNORE_CODE:
                warn_msg = menu.options.auth_type.capitalize() + " "
                warn_msg += "HTTP authentication credentials are required."
                settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
                while True:
                  message = "Do you want to perform a dictionary-based attack? [Y/n] > "
                  do_update = common.read_input(message, default="Y", check_batch=True)
                  if do_update in settings.CHOICE_YES:
                    auth_creds = authentication.http_auth_cracker(url, realm, http_request_method)
                    if auth_creds != False:
                      # menu.options.auth_cred = auth_creds
                      settings.REQUIRED_AUTHENTICATION = True
                      break
                    else:
                      raise SystemExit()
                  elif do_update in settings.CHOICE_NO:
                    checks.http_auth_err_msg()
                  elif do_update in settings.CHOICE_QUIT:
                    raise SystemExit()
                  else:
                    common.invalid_option(do_update)
                    pass

            # Digest authentication
            elif menu.options.auth_type.lower() == settings.AUTH_TYPE.DIGEST:
              if not int(settings.UNAUTHORIZED_ERROR) in settings.IGNORE_CODE:
                warn_msg = menu.options.auth_type.capitalize() + " "
                warn_msg += "HTTP authentication credentials are required."
                settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
                # Check if failed to identify the realm attribute.
                if not realm:
                  warn_msg = "Failed to identify the realm attribute."
                  settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
                while True:
                  message = "Do you want to perform a dictionary-based attack? [Y/n] > "
                  do_update = common.read_input(message, default="Y", check_batch=True)
                  if do_update in settings.CHOICE_YES:
                    auth_creds = authentication.http_auth_cracker(url, realm, http_request_method)
                    if auth_creds != False:
                      # menu.options.auth_cred = auth_creds
                      settings.REQUIRED_AUTHENTICATION = True
                      break
                    else:
                      raise SystemExit()
                  elif do_update in settings.CHOICE_NO:
                    checks.http_auth_err_msg()
                  elif do_update in settings.CHOICE_QUIT:
                    raise SystemExit()
                  else:
                    common.invalid_option(do_update)
                    pass
                else:
                  checks.http_auth_err_msg()
        else:
          raise SystemExit()

    ignore_end = time.time()
    start = start - (ignore_start - ignore_end)


  except ValueError as err_msg:
    settings.print_data_to_stdout(settings.print_critical_msg(str(err_msg) + "."))
    raise SystemExit()

  except Exception as err_msg:
    request_failed(err_msg)

  end = time.time()
  diff = end - start
    
  if int(diff) < 1:
    url_time_response = int(diff)
  else:
    if settings.TARGET_OS == settings.OS.WINDOWS:
      warn_msg = "Due to the relatively slow response of 'cmd.exe' in target "
      warn_msg += "host, there might be delays during the data extraction procedure."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    url_time_response = int(round(diff))
    warn_msg = "Target's estimated response time is " + str(url_time_response)
    warn_msg += " second" + "s"[url_time_response == 1:] + ". That may cause"
    if url_time_response >= 3:
      warn_msg += " serious"
    warn_msg += " delays during the data extraction procedure"
    if url_time_response >= 3:
      warn_msg += " and/or possible corruptions over the extracted data"
    warn_msg += "."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

  if int(timesec) == int(url_time_response):
    timesec = int(timesec) + int(url_time_response)
  else:
    timesec = int(timesec)

  # Against windows targets (for more stability), add one extra second delay.
  # if settings.TARGET_OS == settings.OS.WINDOWS :
  #   timesec = timesec + 1
  return timesec, url_time_response

"""
Exceptions regarding requests failure(s)
"""
def request_failed(err_msg):

  settings.VALID_URL = False

  try:
    error_msg = str(err_msg.args[0]).split("] ")[1]
  except IndexError:
    try:
      error_msg = str(err_msg.args[0])
    except IndexError:
      error_msg = str(err_msg)

  if "Tunnel connection failed" in str(error_msg) and menu.options.tor:
      err_msg = "Can't establish connection with the Tor network. "  
      err_msg += "Please make sure that you have "
      err_msg += "Tor bundle (https://www.torproject.org/download/) or Tor and Privoxy installed and setup "
      err_msg += "so you could be able to successfully use switch '--tor'."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()

  elif any(x in str(error_msg).lower() for x in ["wrong version number", "ssl", "https"]):
    settings.MAX_RETRIES = 1
    error_msg = "Can't establish SSL connection. "
    if settings.MULTI_TARGETS or settings.CRAWLING:
      error_msg = error_msg + "Skipping to the next target."
    settings.print_data_to_stdout(settings.print_critical_msg(error_msg))
    if not settings.CRAWLING:
      raise SystemExit()
    else:
      return False

  elif re.search(r"(connection\s*refused|timed?\s*out)", str(error_msg), re.IGNORECASE):
    settings.MAX_RETRIES = 1
    err = "Unable to connect to the target URL"
    if menu.options.tor:
      err += " or Tor HTTP proxy."
    elif menu.options.proxy or menu.options.ignore_proxy: 
      err += " or proxy"
    err = err + " (Reason: " + str(error_msg)  + "). "
    if menu.options.tor:
      err += "Please make sure that you have "
      err += "Tor bundle (https://www.torproject.org/download/) or Tor and Privoxy installed and setup "
      err += "so you could be able to successfully use switch '--tor'."
    if settings.MULTI_TARGETS or settings.CRAWLING:
      err = err + "Skipping to the next target."
    error_msg = err
    settings.print_data_to_stdout(settings.print_critical_msg(error_msg))
    if not settings.CRAWLING:
      raise SystemExit()
    else:
      return False

  elif settings.UNAUTHORIZED_ERROR in str(err_msg).lower():
    if int(settings.UNAUTHORIZED_ERROR) in settings.IGNORE_CODE or \
       settings.PERFORM_CRACKING or \
       settings.WAF_DETECTION_PHASE:
      return False
    else:
      err_msg = "Not authorized (" + settings.UNAUTHORIZED_ERROR + "). "
      err_msg += "Try to provide right HTTP authentication type ('--auth-type') and valid credentials ('--auth-cred')"
      if menu.options.auth_type and menu.options.auth_cred:
        if settings.MULTI_TARGETS or settings.CRAWLING:
          err_msg += ". "
        else:
          err_msg += " or rerun without providing them, in order to perform a dictionary-based attack. "
      else:
        err_msg += " or rerun by providing option '--ignore-code=" + settings.UNAUTHORIZED_ERROR +"'. "
      if settings.CRAWLING:
        err_msg += "Skipping to the next target."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    if not settings.CRAWLING:
      if menu.options.auth_type and menu.options.auth_cred:
        raise SystemExit()

  elif settings.TOTAL_OF_REQUESTS == 1:
    if "IncompleteRead" in str(error_msg):
      error_msg = "There was an incomplete read error while retrieving data "
      error_msg += "from the target URL."
    elif "infinite loop" in str(error_msg):
      error_msg = "Infinite redirect loop detected. "
      error_msg += "Please check all provided parameters and/or provide missing ones."
    elif "BadStatusLine" in str(error_msg):
      error_msg = "Connection dropped or unknown HTTP "
      error_msg += "status code received."
    elif "forcibly closed" in str(error_msg) or "Connection is already closed" in str(error_msg):
      error_msg = "Connection was forcibly closed by the target URL."
    elif [True for err_code in settings.HTTP_ERROR_CODES if err_code in str(error_msg)]:
      status_code = [err_code for err_code in settings.HTTP_ERROR_CODES if err_code in str(error_msg)]
      warn_msg = "The web server responded with an HTTP error code '" + str(status_code[0]) 
      warn_msg += "' which could interfere with the results of the tests."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
      if not settings.NOT_FOUND_ERROR in str(err_msg).lower():
        return False
      return True
    else:
      error_msg = "The provided target URL seems not reachable. "
      items = []
      if not menu.options.random_agent:
          items.append("'--random-agent' switch")
      if not any((menu.options.proxy, menu.options.ignore_proxy, menu.options.tor)):
        items.append("proxy switches ('--proxy', '--ignore-proxy'...).")
      if items:
        error_msg += "In case that it is, "
        error_msg += "you can try to rerun with "
        error_msg += " and/or ".join(items)
    settings.print_data_to_stdout(settings.print_critical_msg(error_msg))
    if not settings.CRAWLING:
      raise SystemExit()
    else:
      return False

  elif settings.IDENTIFIED_WARNINGS or settings.IDENTIFIED_PHPINFO or settings.IDENTIFIED_COMMAND_INJECTION or \
  (len(settings.IGNORE_CODE) != 0 and any(str(x) in str(error_msg).lower() for x in settings.IGNORE_CODE)):
    return False

  elif settings.IGNORE_ERR_MSG == False:
    continue_tests = checks.continue_tests(err_msg)
    if continue_tests:
      settings.IGNORE_ERR_MSG = True
    else:
      if not settings.CRAWLING:
        raise SystemExit()
    return False

  else:
    if settings.VERBOSITY_LEVEL >= 1:
      if [True for err_code in settings.HTTP_ERROR_CODES if err_code in str(error_msg)]:
        debug_msg = "Got " + str(err_msg)
        settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
      else:
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    return False

"""
Get the response of the request
"""
def get_request_response(request):

  headers.check_http_traffic(request)
  if menu.options.proxy or menu.options.ignore_proxy or menu.options.tor: 
    try:
      response = proxy.use_proxy(request)
    except Exception as err_msg:
      response = request_failed(err_msg)
  else:
    try:
      response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
    except Exception as err_msg:
      response = request_failed(err_msg)
  
  return response

"""
Check if target host is vulnerable.
"""
def init_injection(payload, http_request_method, url):
  if settings.TIME_RELATED_ATTACK:
    start = 0
    end = 0
    start = time.time()

  if settings.INJECT_TAG in url:
    payload = payload.replace("#","%23")
    vuln_parameter = parameters.vuln_GET_param(url)
    target = checks.process_injectable_value(payload, url)
    if settings.USER_DEFINED_POST_DATA and not settings.IGNORE_USER_DEFINED_POST_DATA:
      request = _urllib.request.Request(target, settings.USER_DEFINED_POST_DATA.encode(settings.DEFAULT_CODEC), method=http_request_method)
    else:
      request = _urllib.request.Request(target, method=http_request_method)
  else:
    parameter = menu.options.data
    parameter = parameters.do_POST_check(parameter, http_request_method)
    parameter = ''.join(str(e) for e in parameter).replace("+","%2B")
    vuln_parameter = parameters.vuln_POST_param(parameter, url)
    if settings.IS_JSON:
      data = checks.process_injectable_value(_urllib.parse.unquote(payload.replace("\"", "\\\"")), menu.options.data)
      try:
        data = checks.json_data(data)
      except ValueError:
        pass
    elif settings.IS_XML:
      data = checks.process_injectable_value(_urllib.parse.unquote(payload), menu.options.data)
    else:
      data = checks.process_injectable_value(payload, menu.options.data)
    request = _urllib.request.Request(url, data.encode(settings.DEFAULT_CODEC), method=http_request_method)
  headers.do_check(request)
  response = get_request_response(request)

  if settings.TIME_RELATED_ATTACK:
    end = time.time()
    response = int(end - start)
  else:
    exec_time = response

  return response, vuln_parameter

"""
Check if target host is vulnerable. (Cookie-based injection)
"""
def cookie_injection(url, vuln_parameter, payload, http_request_method):

  def inject_cookie(url, vuln_parameter, payload, http_request_method):

    # Check if defined POST data
    if settings.USER_DEFINED_POST_DATA:
      data = settings.USER_DEFINED_POST_DATA.encode(settings.DEFAULT_CODEC)
    else:
      data = None
    request = _urllib.request.Request(url, data, method=http_request_method)
    #Check if defined extra headers.
    headers.do_check(request)
    payload = checks.newline_fixation(payload)
    payload = checks.payload_fixation(payload)
    # payload = payload.replace("+", "%2B")
    if settings.INJECT_TAG in menu.options.cookie:
      cookie = checks.process_injectable_value(payload, menu.options.cookie)
      # if settings.TESTABLE_VALUE in menu.options.cookie.replace(settings.INJECT_TAG, ""):
      #   request.add_header(settings.COOKIE, menu.options.cookie.replace(settings.INJECT_TAG, "").replace(settings.TESTABLE_VALUE, payload))
      # else:
      request.add_header(settings.COOKIE, cookie)
    try:
      headers.check_http_traffic(request)
      if menu.options.proxy or menu.options.ignore_proxy or menu.options.tor: 
        response = proxy.use_proxy(request)
      else:
        response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
      return response
    except ValueError:
      pass

  if settings.TIME_RELATED_ATTACK :
    start = 0
    end = 0
    start = time.time()

  try:
    response = inject_cookie(url, vuln_parameter, payload, http_request_method)
  except Exception as err_msg:
    response = request_failed(err_msg)

  if settings.TIME_RELATED_ATTACK :
    end  = time.time()
    exec_time = int(end - start)
    return exec_time
  else:
    return response

"""
Check if target host is vulnerable. (User-Agent-based injection)
"""
def user_agent_injection(url, vuln_parameter, payload, http_request_method):

  def inject_user_agent(url, vuln_parameter, payload, http_request_method):
    # Check if defined POST data
    if settings.USER_DEFINED_POST_DATA:
      data = settings.USER_DEFINED_POST_DATA.encode(settings.DEFAULT_CODEC)
    else:
      data = None
    request = _urllib.request.Request(url, data, method=http_request_method)
    #Check if defined extra headers.
    headers.do_check(request)
    payload = checks.newline_fixation(payload)
    request.add_header(settings.USER_AGENT, payload)
    try:
      headers.check_http_traffic(request)
      if menu.options.proxy or menu.options.ignore_proxy or menu.options.tor: 
        response = proxy.use_proxy(request)
      else:
        response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
      return response
    except ValueError:
      pass

  if settings.TIME_RELATED_ATTACK :
    start = 0
    end = 0
    start = time.time()

  try:
    response = inject_user_agent(url, vuln_parameter, payload, http_request_method)
  except Exception as err_msg:
    response = request_failed(err_msg)

  if settings.TIME_RELATED_ATTACK :
    end = time.time()
    exec_time = int(end - start)
    return exec_time
  else:
    return response

"""
Check if target host is vulnerable. (Referer-based injection)
"""
def referer_injection(url, vuln_parameter, payload, http_request_method):

  def inject_referer(url, vuln_parameter, payload, http_request_method):
    # Check if defined POST data
    if settings.USER_DEFINED_POST_DATA:
      data = settings.USER_DEFINED_POST_DATA.encode(settings.DEFAULT_CODEC)
    else:
      data = None
    request = _urllib.request.Request(url, data, method=http_request_method)
    #Check if defined extra headers.
    headers.do_check(request)
    payload = checks.newline_fixation(payload)
    request.add_header(settings.REFERER, payload)
    try:
      headers.check_http_traffic(request)
      if menu.options.proxy or menu.options.ignore_proxy or menu.options.tor: 
        response = proxy.use_proxy(request)
      else:
        response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
      return response
    except ValueError:
      pass

  if settings.TIME_RELATED_ATTACK :
    start = 0
    end = 0
    start = time.time()

  try:
    response = inject_referer(url, vuln_parameter, payload, http_request_method)
  except Exception as err_msg:
    response = request_failed(err_msg)

  if settings.TIME_RELATED_ATTACK :
    end  = time.time()
    exec_time = int(end - start)
    return exec_time
  else:
    return response

"""
Check if target host is vulnerable. (Host-based injection)
"""
def host_injection(url, vuln_parameter, payload, http_request_method):

  def inject_host(url, vuln_parameter, payload, http_request_method):
    # Check if defined POST data
    if settings.USER_DEFINED_POST_DATA:
      data = settings.USER_DEFINED_POST_DATA.encode(settings.DEFAULT_CODEC)
    else:
      data = None
    request = _urllib.request.Request(url, data, method=http_request_method)
    #Check if defined extra headers.
    headers.do_check(request)
    payload = checks.newline_fixation(payload)
    request.add_header(settings.HOST, payload)
    try:
      headers.check_http_traffic(request)
      if menu.options.proxy or menu.options.ignore_proxy or menu.options.tor: 
        response = proxy.use_proxy(request)
      else:
        response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
      return response
    except ValueError:
      pass

  if settings.TIME_RELATED_ATTACK :
    start = 0
    end = 0
    start = time.time()

  try:
    response = inject_host(url, vuln_parameter, payload, http_request_method)
  except Exception as err_msg:
    response = request_failed(err_msg)

  if settings.TIME_RELATED_ATTACK :
    end  = time.time()
    exec_time = int(end - start)
    return exec_time
  else:
    return response

"""
Check if target host is vulnerable. (Custom header injection)
"""
def custom_header_injection(url, vuln_parameter, payload, http_request_method):

  def inject_custom_header(url, vuln_parameter, payload, http_request_method):
    # Check if defined POST data
    if settings.USER_DEFINED_POST_DATA:
      data = settings.USER_DEFINED_POST_DATA.encode(settings.DEFAULT_CODEC)
    else:
      data = None
    request = _urllib.request.Request(url, data, method=http_request_method)
    #Check if defined extra headers.
    headers.do_check(request)
    payload = checks.newline_fixation(payload)
    # if settings.CUSTOM_HEADER_VALUE in settings.CUSTOM_HEADER_VALUE.replace(settings.INJECT_TAG, ""):
    #   request.add_header(settings.CUSTOM_HEADER_NAME, settings.CUSTOM_HEADER_VALUE.replace(settings.INJECT_TAG, "").replace(settings.CUSTOM_HEADER_VALUE, payload))
    # else:
    request.add_header(settings.CUSTOM_HEADER_NAME, payload)
    try:
      headers.check_http_traffic(request)
      if menu.options.proxy or menu.options.ignore_proxy or menu.options.tor: 
        response = proxy.use_proxy(request)
      else:
        response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
      return response
    except ValueError:
      pass

  if settings.TIME_RELATED_ATTACK :
    start = 0
    end = 0
    start = time.time()

  try:
    response = inject_custom_header(url, vuln_parameter, payload, http_request_method)
  except Exception as err_msg:
    response = request_failed(err_msg)

  if settings.TIME_RELATED_ATTACK :
    end  = time.time()
    exec_time = int(end - start)
    return exec_time
  else:
    return response

"""
Detect the character encoding of the target web page.
"""
def encoding_detection(response):
  charset_detected = False
  charset = None

  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Detecting the character encoding declared by the web page."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

  try:
    # Read once
    content_bytes = response.read()
    try:
      content_text = content_bytes.decode("utf-8", errors="ignore")
    except:
      content_text = ""

    # 1. Get charset from HTTP header (may be None)
    try:
      header_charset = response.headers.getparam('charset')  # Python 2
    except AttributeError:
      try:
        header_charset = response.headers.get_content_charset()  # Python 3
      except:
        header_charset = None

    if header_charset:
      header_charset = header_charset.strip().lower()

    # 2. Find all meta charset declarations

    # HTML5 <meta charset="...">
    meta_charset_match = re.search(r'<meta\s+charset=["\']?([a-zA-Z0-9\-_]+)["\']?', content_text, re.I)

    # HTML4 <meta http-equiv="Content-Type" content="text/html; charset=...">
    meta_http_equiv_match = re.search(
      r'<meta\s+http-equiv=["\']Content-Type["\']\s+content=["\'][^"\']*charset=([a-zA-Z0-9\-_]+)',
      content_text, re.I)

    # Decide priority: prefer meta charset, then meta http-equiv, then header
    if meta_charset_match:
      charset = meta_charset_match.group(1).strip().lower()
    elif meta_http_equiv_match:
      charset = meta_http_equiv_match.group(1).strip().lower()
    elif header_charset:
      charset = header_charset
    else:
      charset = None

    # 3. If no charset yet, default to utf-8
    if not charset:
      charset = 'utf-8'

    charset_detected = True
    settings.DEFAULT_PAGE_ENCODING = charset

    # 4. Logging
    msg = "The web page declares the character encoding as '"

    if charset in settings.ENCODING_LIST:
      if settings.VERBOSITY_LEVEL != 0:
        debug_msg = msg + charset + "'."
        settings.print_data_to_stdout(settings.print_bold_debug_msg(debug_msg))
    else:
      warn_msg = msg + charset + "', which is not recognized."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

  except Exception as e:
    pass

  if not charset_detected and settings.VERBOSITY_LEVEL != 0:
    warn_msg = "Failed to identify the web page charset."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Identify the target application's type based on the URL extension.
"""
def application_identification(url):
  found_application_extension = False

  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Detecting the type of target application based on URL and headers."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

  root, application_extension = splitext(_urllib.parse.urlparse(url).path)
  settings.TARGET_APPLICATION = application_extension[1:].upper()

  if settings.TARGET_APPLICATION:
    found_application_extension = True

    if settings.VERBOSITY_LEVEL != 0:
      debug_msg = "Target application identified as " + settings.TARGET_APPLICATION + "."
      settings.print_data_to_stdout(settings.print_bold_debug_msg(debug_msg))

    for unsupported in settings.UNSUPPORTED_TARGET_APPLICATION:
      if settings.TARGET_APPLICATION.lower() in unsupported.lower():
        err_msg = settings.TARGET_APPLICATION + " exploitation is not yet supported."
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
        raise SystemExit()

  if not found_application_extension and settings.VERBOSITY_LEVEL != 0:
    warn_msg = "Failed to identify the target application's type from the URL."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Detect the underlying operating system of the target server based on server headers.
"""
def check_os(server_header):
  identified_os = "unknown"
  user_defined_os = None

  if menu.options.os and checks.user_defined_os():
    user_defined_os = settings.TARGET_OS

  for banner in settings.SERVER_OS_BANNERS:
    match = re.search(banner.lower(), server_header.lower())
    if match:
      if settings.VERBOSITY_LEVEL != 0:
        debug_msg = "Detecting the operating system hosting the target server."
        settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

      settings.IDENTIFIED_TARGET_OS = True
      settings.TARGET_OS = match.group(0)

      if re.search(r"microsoft|win", settings.TARGET_OS, re.IGNORECASE):
        identified_os = settings.OS.WINDOWS
        settings.TARGET_OS = identified_os

        if menu.options.os and user_defined_os != settings.OS.WINDOWS:
          if checks.identified_os():
            settings.TARGET_OS = user_defined_os

        if menu.options.shellshock:
          err_msg = "The shellshock module ('--shellshock') is not available for Windows targets."
          settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
          raise SystemExit()
      else:
        identified_os = "Unix-like (" + settings.TARGET_OS + ")"

        if menu.options.os and user_defined_os == settings.OS.WINDOWS:
          if checks.identified_os():
            settings.TARGET_OS = user_defined_os
      break

  if settings.VERBOSITY_LEVEL != 0:
    if settings.IDENTIFIED_TARGET_OS:
      debug_msg = "Underlying operating system identified as " + identified_os + "."
      settings.print_data_to_stdout(settings.print_bold_debug_msg(debug_msg))


"""
Identify the underlying technology or framework powering the target application.
"""
def technology_identification(response):
  try:
    x_powered_by = response.info().get(settings.X_POWERED_BY, "").strip()

    if settings.VERBOSITY_LEVEL != 0:
      debug_msg = "Detecting the underlying technology or framework powering the target application."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

      if x_powered_by:
        debug_msg = "Target application technology detected as " + x_powered_by + "."
        settings.print_data_to_stdout(settings.print_bold_debug_msg(debug_msg))
        check_os(x_powered_by)
      else:
        warn_msg = "Failed to identify the technology supporting the target application."
        settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

  except Exception:
    if settings.VERBOSITY_LEVEL != 0:
      warn_msg = "Failed to identify the technology supporting the target application."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))


"""
Identify the software running on the target web server.
"""
def server_identification(response):
  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Detecting the software running on the target web server."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

  server_banner = response.info().get(settings.SERVER, "").strip()
  for banner in settings.SERVER_BANNERS:
    match = re.search(banner.lower(), server_banner.lower())
    if match:
      settings.SERVER_BANNER = match.group(0)

      # Set up default document root paths
      if "apache" in settings.SERVER_BANNER.lower():
        if settings.TARGET_OS == settings.OS.WINDOWS:
          settings.WEB_ROOT = settings.WINDOWS_DEFAULT_DOC_ROOTS[1]
        else:
          settings.WEB_ROOT = settings.LINUX_DEFAULT_DOC_ROOTS[0].replace(
            settings.DOC_ROOT_TARGET_MARK, settings.TARGET_URL)
      elif "nginx" in settings.SERVER_BANNER.lower():
        settings.WEB_ROOT = settings.LINUX_DEFAULT_DOC_ROOTS[6]
      elif "microsoft-iis" in settings.SERVER_BANNER.lower():
        settings.WEB_ROOT = settings.WINDOWS_DEFAULT_DOC_ROOTS[0]
      break

  if server_banner and settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Target server software identified as " + server_banner + "."
    settings.print_data_to_stdout(settings.print_bold_debug_msg(debug_msg))


"""
Identify the underlying operating system based on the server banner.
"""
def os_identification(response):
  if not settings.IGNORE_IDENTIFIED_OS:
    server_banner = response.info().get(settings.SERVER, "")
    check_os(server_banner)

  if not settings.IDENTIFIED_TARGET_OS and not menu.options.os:
    warn_msg = "Failed to identify the server's underlying operating system."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    checks.define_target_os()


"""
Perform a target page reload after a specified delay (minimum 5 seconds).
"""
def url_reload(url, delay_seconds):
  # Ensure a minimum delay of 5 seconds before reloading
  if int(delay_seconds) < 5:
    delay_seconds = 5
  time.sleep(delay_seconds)

  # Perform the URL request and return the response
  response = _urllib.request.urlopen(url, timeout=settings.TIMEOUT)
  return response

"""
Calculate the time related execution time
"""
def perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url):
  # Fix prefixes / suffixes
  payload, prefix = parameters.prefixes(payload, prefix)
  payload, suffix = parameters.suffixes(payload, suffix)
  
  payload = payload.replace(settings.SINGLE_WHITESPACE, whitespace)
  payload = checks.perform_payload_modification(payload)
  
  # Check if defined "--verbose" option.
  if settings.VERBOSITY_LEVEL != 0:
    payload_msg = payload.replace("\n", "\\n")
    settings.print_data_to_stdout(settings.print_payload(payload_msg))

  # Check if defined cookie with "INJECT_HERE" tag
  if menu.options.cookie and settings.INJECT_TAG in menu.options.cookie or settings.COOKIE_INJECTION:
    if not vuln_parameter:
      vuln_parameter = parameters.specify_cookie_parameter(menu.options.cookie)
    exec_time = cookie_injection(url, vuln_parameter, payload, http_request_method)
  # Check if defined custom header with "INJECT_HERE" tag
  elif settings.CUSTOM_HEADER_INJECTION:
    if not vuln_parameter:
      vuln_parameter = parameters.specify_custom_header_parameter("")
    exec_time = custom_header_injection(url, vuln_parameter, payload, http_request_method)
  # Check if defined user-agent with "INJECT_HERE" tag
  elif (menu.options.agent and settings.INJECT_TAG in menu.options.agent) or settings.USER_AGENT_INJECTION:
    if not vuln_parameter:
      vuln_parameter = parameters.specify_user_agent_parameter(settings.USER_AGENT.lower())
    exec_time = user_agent_injection(url, vuln_parameter, payload, http_request_method)
  # Check if defined referer with "INJECT_HERE" tag
  elif (menu.options.referer and settings.INJECT_TAG in menu.options.referer) or settings.REFERER_INJECTION:
    if not vuln_parameter:
      vuln_parameter = parameters.specify_referer_parameter(settings.REFERER.lower())
    exec_time = referer_injection(url, vuln_parameter, payload, http_request_method)
  # Check if defined host with "INJECT_HERE" tag
  elif (menu.options.host and settings.INJECT_TAG in menu.options.host) or settings.HOST_INJECTION:
    if not vuln_parameter:
      vuln_parameter = parameters.specify_host_parameter(settings.HOST.lower())
    exec_time = host_injection(url, vuln_parameter, payload, http_request_method)
  else:
    exec_time, vuln_parameter = init_injection(payload, http_request_method, url)

  return exec_time, vuln_parameter, payload, prefix, suffix
  
# eof