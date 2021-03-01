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
import sys
import time
import socket
from src.utils import menu
from os.path import splitext
from src.utils import settings
from src.utils import session_handler
from src.core.requests import tor
from src.core.requests import proxy
from src.core.requests import headers
from src.core.requests import parameters
from src.core.requests import authentication
from src.core.injections.controller import checks
from src.thirdparty.six.moves import input as _input
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.colorama import Fore, Back, Style, init

"""
Estimating the response time (in seconds).
"""
def estimate_response_time(url, timesec):
  stored_auth_creds = False
  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Estimating the target URL response time. "
    sys.stdout.write(settings.print_debug_msg(debug_msg))
    sys.stdout.flush()
  # Check if defined POST data
  if menu.options.data:
    request = _urllib.request.Request(url, menu.options.data.encode(settings.UNICODE_ENCODING))
  else:
    url = parameters.get_url_part(url)
    request = _urllib.request.Request(url)
  headers.do_check(request) 
  start = time.time()
  try:
    response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
    response.read(1)
    response.close()
    
  except _urllib.error.HTTPError as err:
    ignore_start = time.time()
    if settings.UNAUTHORIZED_ERROR in str(err) and menu.options.ignore_code == settings.UNAUTHORIZED_ERROR:
      pass
    else:
      if settings.VERBOSITY_LEVEL != 0:
        print(settings.FAIL_STATUS)
      err_msg = "Unable to connect to the target URL"
      try:
        err_msg += " (" + str(err.args[0]).split("] ")[-1] + ")."
      except IndexError:
        err_msg += " (" + str(err) + ")."
      print(settings.print_critical_msg(err_msg))
      # Check for HTTP Error 401 (Unauthorized).
      if str(err.getcode()) == settings.UNAUTHORIZED_ERROR:
        try:
          # Get the auth header value
          auth_line = err.headers.get('www-authenticate', '')
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
          err_msg = "The identified HTTP authentication type (" + str(auth_type) + ") "
          err_msg += "is not yet supported."
          print(settings.print_critical_msg(err_msg) + "\n")
          raise SystemExit()

        except IndexError:
          err_msg = "The provided pair of " + str(menu.options.auth_type) 
          err_msg += " HTTP authentication credentials '" + str(menu.options.auth_cred) + "'"
          err_msg += " seems to be invalid."
          print(settings.print_critical_msg(err_msg))
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
          if stored_auth_creds:
            menu.options.auth_cred = stored_auth_creds
            info_msg = "Identified a (stored) valid pair of credentials '"  
            info_msg += menu.options.auth_cred + Style.RESET_ALL + Style.BRIGHT  + "'."
            print(settings.print_bold_info_msg(info_msg))
          else:  
            # Basic authentication 
            if menu.options.auth_type == "basic":
              if not menu.options.ignore_code == settings.UNAUTHORIZED_ERROR:
                warn_msg = menu.options.auth_type.capitalize() + " " 
                warn_msg += "HTTP authentication credentials are required."
                print(settings.print_warning_msg(warn_msg))
                while True:
                  if not menu.options.batch:
                    question_msg = "Do you want to perform a dictionary-based attack? [Y/n] > "
                    do_update = _input(settings.print_question_msg(question_msg))
                  else:
                    do_update = ""  
                  if len(do_update) == 0:
                     do_update = "Y" 
                  if do_update in settings.CHOICE_YES:
                    auth_creds = authentication.http_auth_cracker(url, realm)
                    if auth_creds != False:
                      menu.options.auth_cred = auth_creds
                      settings.REQUIRED_AUTHENTICATION = True
                      break
                    else:
                      raise SystemExit()
                  elif do_update in settings.CHOICE_NO:
                    checks.http_auth_err_msg()
                  elif do_update in settings.CHOICE_QUIT:
                    raise SystemExit()
                  else:
                    err_msg = "'" + do_update + "' is not a valid answer."  
                    print(settings.print_error_msg(err_msg))
                    pass

            # Digest authentication         
            elif menu.options.auth_type == "digest":
              if not menu.options.ignore_code == settings.UNAUTHORIZED_ERROR:
                warn_msg = menu.options.auth_type.capitalize() + " " 
                warn_msg += "HTTP authentication credentials are required."
                print(settings.print_warning_msg(warn_msg))      
                # Check if heuristics have failed to identify the realm attribute.
                if not realm:
                  warn_msg = "Heuristics have failed to identify the realm attribute." 
                  print(settings.print_warning_msg(warn_msg))
                while True:
                  if not menu.options.batch:
                    question_msg = "Do you want to perform a dictionary-based attack? [Y/n] > "
                    do_update = _input(settings.print_question_msg(question_msg))
                  else:
                    do_update = ""
                  if len(do_update) == 0:
                     do_update = "Y" 
                  if do_update in settings.CHOICE_YES:
                    auth_creds = authentication.http_auth_cracker(url, realm)
                    if auth_creds != False:
                      menu.options.auth_cred = auth_creds
                      settings.REQUIRED_AUTHENTICATION = True
                      break
                    else:
                      raise SystemExit()
                  elif do_update in settings.CHOICE_NO:
                    checks.http_auth_err_msg()
                  elif do_update in settings.CHOICE_QUIT:
                    raise SystemExit()
                  else:
                    err_msg = "'" + do_update + "' is not a valid answer."  
                    print(settings.print_error_msg(err_msg))
                    pass
                else:   
                  checks.http_auth_err_msg()      
        else:
          raise SystemExit()
   
    ignore_end = time.time()
    start = start - (ignore_start - ignore_end)

  except socket.timeout:
    if settings.VERBOSITY_LEVEL != 0:
      print(settings.FAIL_STATUS)
    err_msg = "The connection to target URL has timed out."
    print(settings.print_critical_msg(err_msg) + "\n")
    raise SystemExit()

  except _urllib.error.URLError as err_msg:
    if settings.VERBOSITY_LEVEL != 0:
      print(settings.FAIL_STATUS)
    print(settings.print_critical_msg(str(err_msg.args[0]).split("] ")[1] + "."))
    raise SystemExit()

  except ValueError as err_msg:
    if settings.VERBOSITY_LEVEL != 0:
      print(settings.FAIL_STATUS)
    print(settings.print_critical_msg(str(err_msg) + "."))
    raise SystemExit()

  end = time.time()
  diff = end - start 
  
  if int(diff) < 1:
    if settings.VERBOSITY_LEVEL != 0 and stored_auth_creds == False:
      print(settings.SUCCESS_STATUS)
    url_time_response = int(diff)
    if settings.TARGET_OS == "win":
      warn_msg = "Due to the relatively slow response of 'cmd.exe' in target "
      warn_msg += "host, there may be delays during the data extraction procedure."
      print(settings.print_warning_msg(warn_msg))
  else:
    if settings.VERBOSITY_LEVEL != 0:
      print(settings.SUCCESS_STATUS)
    url_time_response = int(round(diff))
    warn_msg = "The estimated response time is " + str(url_time_response)
    warn_msg += " second" + "s"[url_time_response == 1:] + ". That may cause" 
    if url_time_response >= 3:
      warn_msg += " serious"
    warn_msg += " delays during the data extraction procedure" 
    if url_time_response >= 3:
      warn_msg += " and/or possible corruptions over the extracted data"
    warn_msg += "."
    print(settings.print_bold_warning_msg(warn_msg))

  if int(timesec) == int(url_time_response):
    timesec = int(timesec) + int(url_time_response)
  else:
    timesec = int(timesec)

  # Against windows targets (for more stability), add one extra second delay.
  if settings.TARGET_OS == "win" :
    timesec = timesec + 1

  return timesec, url_time_response

"""
Get the response of the request
"""
def get_request_response(request):

  headers.check_http_traffic(request)
  # Check if defined any HTTP Proxy.
  if menu.options.proxy:
    try:
      response = proxy.use_proxy(request)
    except _urllib.error.HTTPError as err_msg:
      if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
        response = False  
      elif settings.IGNORE_ERR_MSG == False:
        err = str(err_msg) + "."
        if not settings.VERBOSITY_LEVEL != 0 and settings.TIME_BASED_STATE == False or \
          settings.VERBOSITY_LEVEL != 0 and settings.EVAL_BASED_STATE == None:
          print("")
        if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
          print("") 
        print(settings.print_critical_msg(err))
        continue_tests = checks.continue_tests(err_msg)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except _urllib.error.URLError as err_msg:
      if "Connection refused" in err_msg.reason:
        err_msg =  "The target host is not responding. "
        err_msg += "Please ensure that is up and try again."
        if not settings.VERBOSITY_LEVEL != 0 and settings.TIME_BASED_STATE == False or \
           settings.VERBOSITY_LEVEL != 0 and settings.EVAL_BASED_STATE == None:
          print("")
        if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
          print("")
        print(settings.print_critical_msg(err_msg))
      raise SystemExit()

  # Check if defined Tor.
  elif menu.options.tor:
    try:
      response = tor.use_tor(request)
    except _urllib.error.HTTPError as err_msg:
      if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
        response = False  
      elif settings.IGNORE_ERR_MSG == False:
        err = str(err_msg) + "."
        if not settings.VERBOSITY_LEVEL != 0 and settings.TIME_BASED_STATE == False or \
          settings.VERBOSITY_LEVEL != 0 and settings.EVAL_BASED_STATE == None:
          print("")
        if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
          print("") 
        print(settings.print_critical_msg(err))
        continue_tests = checks.continue_tests(err_msg)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except _urllib.error.URLError as err_msg:
      err_msg = str(err_msg.reason).split(" ")[2:]
      err_msg = ' '.join(err_msg)+ "."
      if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
        print("")
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()

  else:
    try:
      response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
    except _urllib.error.HTTPError as err_msg:
      if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
        response = False  
      elif settings.IGNORE_ERR_MSG == False:
        if not str(err_msg.code) == str(menu.options.ignore_code):
          err = str(err_msg) + "."
          if settings.VERBOSITY_LEVEL < 2:
            print("\r" + settings.print_critical_msg(err) + 30 * " ")

        continue_tests = checks.continue_tests(err_msg)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False  
    except _urllib.error.URLError as err_msg:
      err_msg = str(err_msg.reason).split(" ")[2:]
      err_msg = ' '.join(err_msg)+ "."
      if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
        print("")
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()
  return response

"""
Check if target host is vulnerable. (Cookie-based injection)
"""
def cookie_injection(url, vuln_parameter, payload):

  def inject_cookie(url, vuln_parameter, payload, proxy):
    if proxy == None:
      opener = _urllib.request.build_opener()
    else:
      opener = _urllib.request.build_opener(proxy)

    if settings.TIME_RELATIVE_ATTACK :
      payload = _urllib.parse.quote(payload)

    # Check if defined POST data
    if menu.options.data:
      menu.options.data = settings.USER_DEFINED_POST_DATA
      request = _urllib.request.Request(url, menu.options.data.encode(settings.UNICODE_ENCODING))
    else:
      url = parameters.get_url_part(url)
      request = _urllib.request.Request(url)
    #Check if defined extra headers.
    headers.do_check(request)
    payload = checks.newline_fixation(payload)
    request.add_header('Cookie', menu.options.cookie.replace(settings.INJECT_TAG, payload))
    try:
      headers.check_http_traffic(request)
      response = opener.open(request)
      return response
    except ValueError:
      pass

  if settings.TIME_RELATIVE_ATTACK :
    start = 0
    end = 0
    start = time.time()

  proxy = None 
  #response = inject_cookie(url, vuln_parameter, payload, proxy)

  # Check if defined any HTTP Proxy.
  if menu.options.proxy:
    try:
      proxy = _urllib.request.ProxyHandler({settings.SCHEME : menu.options.proxy})
      response = inject_cookie(url, vuln_parameter, payload, proxy)
    except _urllib.error.HTTPError as err_msg:
      if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
        response = False  
      elif settings.IGNORE_ERR_MSG == False:
        err_msg = str(err_msg) + "."
        print("\n" + settings.print_critical_msg(err_msg))
        continue_tests = checks.continue_tests(err)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False  
    except _urllib.error.URLError as err_msg:
      err_msg = str(err_msg.reason).split(" ")[2:]
      err_msg = ' '.join(err_msg)+ "."
      if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
        print("")
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()

  # Check if defined Tor.
  elif menu.options.tor:
    try:
      proxy = _urllib.request.ProxyHandler({settings.SCHEME:settings.PRIVOXY_IP + ":" + settings.PRIVOXY_PORT})
      response = inject_cookie(url, vuln_parameter, payload, proxy)
    except _urllib.error.HTTPError as err_msg:
      if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
        response = False  
      elif settings.IGNORE_ERR_MSG == False:
        err = str(err_msg) + "."
        if not settings.VERBOSITY_LEVEL != 0 and settings.TIME_BASED_STATE == False or \
          settings.VERBOSITY_LEVEL != 0 and settings.EVAL_BASED_STATE == None:
          print("")
        if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
          print("") 
        print(settings.print_critical_msg(err))
        continue_tests = checks.continue_tests(err_msg)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except _urllib.error.URLError as err_msg:
      err_msg = str(err_msg.reason).split(" ")[2:]
      err_msg = ' '.join(err_msg)+ "."
      if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
        print("")
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()

  else:
    try:
      response = inject_cookie(url, vuln_parameter, payload, proxy)
    except _urllib.error.HTTPError as err_msg:
      if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
        response = False  
      elif settings.IGNORE_ERR_MSG == False:
        err = str(err_msg) + "."
        if not settings.VERBOSITY_LEVEL != 0 and settings.TIME_BASED_STATE == False or \
          settings.VERBOSITY_LEVEL != 0 and settings.EVAL_BASED_STATE == None:
          print("")
        if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
          print("") 
        print(settings.print_critical_msg(err))
        continue_tests = checks.continue_tests(err_msg)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 

    except _urllib.error.URLError as err_msg:
      err_msg = str(err_msg.reason).split(" ")[2:]
      err_msg = ' '.join(err_msg)+ "."
      if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
        print("")
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()

  if settings.TIME_RELATIVE_ATTACK :
    end  = time.time()
    how_long = int(end - start)
    return how_long
  else:
    return response

"""
Check if target host is vulnerable. (User-Agent-based injection)
"""
def user_agent_injection(url, vuln_parameter, payload):

  def inject_user_agent(url, vuln_parameter, payload, proxy):
    if proxy == None:
      opener = _urllib.request.build_opener()
    else:
      opener = _urllib.request.build_opener(proxy)

    # Check if defined POST data
    if menu.options.data:
      menu.options.data = settings.USER_DEFINED_POST_DATA
      request = _urllib.request.Request(url, menu.options.data.encode(settings.UNICODE_ENCODING))
    else:
      url = parameters.get_url_part(url)
      request = _urllib.request.Request(url)
    #Check if defined extra headers.
    headers.do_check(request)
    payload = checks.newline_fixation(payload)
    request.add_header('User-Agent', payload)
    try:
      headers.check_http_traffic(request)
      response = opener.open(request)
      return response
    except ValueError:
      pass

  if settings.TIME_RELATIVE_ATTACK :
    start = 0
    end = 0
    start = time.time()

  proxy = None 
  #response = inject_user_agent(url, vuln_parameter, payload, proxy)
  # Check if defined any HTTP Proxy.
  if menu.options.proxy:
    try:
      proxy = _urllib.request.ProxyHandler({settings.SCHEME : menu.options.proxy})
      response = inject_user_agent(url, vuln_parameter, payload, proxy)
    except _urllib.error.HTTPError as err_msg:
      if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
        response = False  
      elif settings.IGNORE_ERR_MSG == False:
        err = str(err_msg) + "."
        if not settings.VERBOSITY_LEVEL != 0 and settings.TIME_BASED_STATE == False or \
          settings.VERBOSITY_LEVEL != 0 and settings.EVAL_BASED_STATE == None:
          print("")
        if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
          print("") 
        print(settings.print_critical_msg(err))
        continue_tests = checks.continue_tests(err_msg)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except _urllib.error.URLError as err_msg:
      err_msg = str(err_msg.reason).split(" ")[2:]
      err_msg = ' '.join(err_msg)+ "."
      if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
        print("")
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()

  # Check if defined Tor.
  elif menu.options.tor:
    try:
      proxy = _urllib.request.ProxyHandler({settings.SCHEME:settings.PRIVOXY_IP + ":" + settings.PRIVOXY_PORT})
      response = inject_user_agent(url, vuln_parameter, payload, proxy)
    except _urllib.error.HTTPError as err_msg:
      if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
        response = False  
      elif settings.IGNORE_ERR_MSG == False:
        err = str(err_msg) + "."
        if not settings.VERBOSITY_LEVEL != 0 and settings.TIME_BASED_STATE == False or \
          settings.VERBOSITY_LEVEL != 0 and settings.EVAL_BASED_STATE == None:
          print("")
        if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
          print("") 
        print(settings.print_critical_msg(err))
        continue_tests = checks.continue_tests(err_msg)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except _urllib.error.URLError as err_msg:
      err_msg = str(err_msg.reason).split(" ")[2:]
      err_msg = ' '.join(err_msg)+ "."
      if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
        print("")
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()

  else:
    try:
      response = inject_user_agent(url, vuln_parameter, payload, proxy)
    except _urllib.error.HTTPError as err_msg:
      if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
        response = False  
      elif settings.IGNORE_ERR_MSG == False:
        err = str(err_msg) + "."
        if not settings.VERBOSITY_LEVEL != 0 and settings.TIME_BASED_STATE == False or \
          settings.VERBOSITY_LEVEL != 0 and settings.EVAL_BASED_STATE == None:
          print("")
        if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
          print("") 
        print(settings.print_critical_msg(err))
        continue_tests = checks.continue_tests(err_msg)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except _urllib.error.URLError as err_msg:
      err_msg = str(err_msg.reason).split(" ")[2:]
      err_msg = ' '.join(err_msg)+ "."
      if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
        print("")
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()

  if settings.TIME_RELATIVE_ATTACK :
    end = time.time()
    how_long = int(end - start)
    return how_long
  else:
    return response

"""
Check if target host is vulnerable. (Referer-based injection)
"""
def referer_injection(url, vuln_parameter, payload):

  def inject_referer(url, vuln_parameter, payload, proxy):

    if proxy == None:
      opener = _urllib.request.build_opener()
    else:
      opener = _urllib.request.build_opener(proxy)

    # Check if defined POST data
    if menu.options.data:
      menu.options.data = settings.USER_DEFINED_POST_DATA
      request = _urllib.request.Request(url, menu.options.data.encode(settings.UNICODE_ENCODING))
    else:
      url = parameters.get_url_part(url)
      request = _urllib.request.Request(url)
    #Check if defined extra headers.
    headers.do_check(request)
    payload = checks.newline_fixation(payload)
    request.add_header('Referer', payload)
    try:
      headers.check_http_traffic(request)
      response = opener.open(request)
      return response
    except ValueError:
      pass

  if settings.TIME_RELATIVE_ATTACK :
    start = 0
    end = 0
    start = time.time()

  proxy = None 
  #response = inject_referer(url, vuln_parameter, payload, proxy)
  # Check if defined any HTTP Proxy.
  if menu.options.proxy:
    try:
      proxy = _urllib.request.ProxyHandler({settings.SCHEME : menu.options.proxy})
      response = inject_referer(url, vuln_parameter, payload, proxy)
    except _urllib.error.HTTPError as err_msg:
      if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
        response = False  
      elif settings.IGNORE_ERR_MSG == False:
        err = str(err_msg) + "."
        if not settings.VERBOSITY_LEVEL != 0 and settings.TIME_BASED_STATE == False or \
          settings.VERBOSITY_LEVEL != 0 and settings.EVAL_BASED_STATE == None:
          print("")
        if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
          print("") 
        print(settings.print_critical_msg(err))
        continue_tests = checks.continue_tests(err_msg)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except _urllib.error.URLError as err_msg:
      err_msg = str(err_msg.reason).split(" ")[2:]
      err_msg = ' '.join(err_msg)+ "."
      if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
        print("")
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()
          
  # Check if defined Tor.
  elif menu.options.tor:
    try:
      proxy = _urllib.request.ProxyHandler({settings.SCHEME:settings.PRIVOXY_IP + ":" + settings.PRIVOXY_PORT})
      response = inject_referer(url, vuln_parameter, payload, proxy)
    except _urllib.error.HTTPError as err_msg:
      if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
        response = False  
      elif settings.IGNORE_ERR_MSG == False:
        err = str(err_msg) + "."
        if not settings.VERBOSITY_LEVEL != 0 and settings.TIME_BASED_STATE == False or \
          settings.VERBOSITY_LEVEL != 0 and settings.EVAL_BASED_STATE == None:
          print("")
        if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
          print("") 
        print(settings.print_critical_msg(err))
        continue_tests = checks.continue_tests(err_msg)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except _urllib.error.URLError as err_msg:
      err_msg = str(err_msg.reason).split(" ")[2:]
      err_msg = ' '.join(err_msg)+ "."
      if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
        print("")
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()
          
  else:
    try:
      response = inject_referer(url, vuln_parameter, payload, proxy)

    except _urllib.error.HTTPError as err_msg:
      if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
        response = False  
      elif settings.IGNORE_ERR_MSG == False:
        err = str(err_msg) + "."
        if not settings.VERBOSITY_LEVEL != 0 and settings.TIME_BASED_STATE == False or \
          settings.VERBOSITY_LEVEL != 0 and settings.EVAL_BASED_STATE == None:
          print("")
        if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
          print("") 
        print(settings.print_critical_msg(err))
        continue_tests = checks.continue_tests(err_msg)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except _urllib.error.URLError as err_msg:
      err_msg = str(err_msg.reason).split(" ")[2:]
      err_msg = ' '.join(err_msg)+ "."
      if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
        print("")
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()
          
  if settings.TIME_RELATIVE_ATTACK :
    end  = time.time()
    how_long = int(end - start)
    return how_long
  else:
    return response

"""
Check if target host is vulnerable. (Host-based injection)
"""
def host_injection(url, vuln_parameter, payload):
  
  payload = _urllib.parse.urlparse(url).netloc + payload

  def inject_host(url, vuln_parameter, payload, proxy):

    if proxy == None:
      opener = _urllib.request.build_opener()
    else:
      opener = _urllib.request.build_opener(proxy)

    # Check if defined POST data
    if menu.options.data:
      menu.options.data = settings.USER_DEFINED_POST_DATA
      request = _urllib.request.Request(url, menu.options.data.encode(settings.UNICODE_ENCODING))
    else:
      url = parameters.get_url_part(url)
      request = _urllib.request.Request(url)
    #Check if defined extra headers.
    headers.do_check(request)
    payload = checks.newline_fixation(payload)  
    request.add_header('Host', payload)
    try:
      headers.check_http_traffic(request)
      response = opener.open(request)
      return response
    except ValueError:
      pass

  if settings.TIME_RELATIVE_ATTACK :
    start = 0
    end = 0
    start = time.time()

  proxy = None 
  #response = inject_host(url, vuln_parameter, payload, proxy)
  # Check if defined any HTTP Proxy.
  if menu.options.proxy:
    try:
      proxy = _urllib.request.ProxyHandler({settings.SCHEME : menu.options.proxy})
      response = inject_host(url, vuln_parameter, payload, proxy)
    except _urllib.error.HTTPError as err_msg:
      if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
        response = False  
      elif settings.IGNORE_ERR_MSG == False:
        err = str(err_msg) + "."
        if not settings.VERBOSITY_LEVEL != 0 and settings.TIME_BASED_STATE == False or \
          settings.VERBOSITY_LEVEL != 0 and settings.EVAL_BASED_STATE == None:
          print("")
        if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
          print("") 
        print(settings.print_critical_msg(err))
        continue_tests = checks.continue_tests(err_msg)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except _urllib.error.URLError as err_msg:
      err_msg = str(err_msg.reason).split(" ")[2:]
      err_msg = ' '.join(err_msg)+ "."
      if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
        print("")
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()
          
  # Check if defined Tor.
  elif menu.options.tor:
    try:
      proxy = _urllib.request.ProxyHandler({settings.SCHEME:settings.PRIVOXY_IP + ":" + settings.PRIVOXY_PORT})
      response = inject_host(url, vuln_parameter, payload, proxy)
    except _urllib.error.HTTPError as err_msg:
      if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
        response = False  
      elif settings.IGNORE_ERR_MSG == False:
        err = str(err_msg) + "."
        if not settings.VERBOSITY_LEVEL != 0 and settings.TIME_BASED_STATE == False or \
          settings.VERBOSITY_LEVEL != 0 and settings.EVAL_BASED_STATE == None:
          print("")
        if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
          print("") 
        print(settings.print_critical_msg(err))
        continue_tests = checks.continue_tests(err_msg)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except _urllib.error.URLError as err_msg:
      err_msg = str(err_msg.reason).split(" ")[2:]
      err_msg = ' '.join(err_msg)+ "."
      if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
        print("")
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()
          
  else:
    try:
      response = inject_host(url, vuln_parameter, payload, proxy)

    except _urllib.error.HTTPError as err_msg:
      if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
        response = False  
      elif settings.IGNORE_ERR_MSG == False:
        err = str(err_msg) + "."
        if not settings.VERBOSITY_LEVEL != 0 and settings.TIME_BASED_STATE == False or \
          settings.VERBOSITY_LEVEL != 0 and settings.EVAL_BASED_STATE == None:
          print("")
        if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
          print("") 
        print(settings.print_critical_msg(err))
        continue_tests = checks.continue_tests(err_msg)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except _urllib.error.URLError as err_msg:
      err_msg = str(err_msg.reason).split(" ")[2:]
      err_msg = ' '.join(err_msg)+ "."
      if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
        print("")
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()
          
  if settings.TIME_RELATIVE_ATTACK :
    end  = time.time()
    how_long = int(end - start)
    return how_long
  else:
    return response


"""
Check if target host is vulnerable. (Custom header injection)
"""
def custom_header_injection(url, vuln_parameter, payload):

  def inject_custom_header(url, vuln_parameter, payload, proxy):

    if proxy == None:
      opener = _urllib.request.build_opener()
    else:
      opener = _urllib.request.build_opener(proxy)

    # Check if defined POST data
    if menu.options.data:
      menu.options.data = settings.USER_DEFINED_POST_DATA
      request = _urllib.request.Request(url, menu.options.data.encode(settings.UNICODE_ENCODING))
    else:
      url = parameters.get_url_part(url)
      request = _urllib.request.Request(url)
    #Check if defined extra headers.
    headers.do_check(request)
    payload = checks.newline_fixation(payload) 
    request.add_header(settings.CUSTOM_HEADER_NAME, payload)
    try:
      headers.check_http_traffic(request)
      response = opener.open(request)
      return response
    except ValueError:
      pass

  if settings.TIME_RELATIVE_ATTACK :
    start = 0
    end = 0
    start = time.time()

  proxy = None  
  #response = inject_custom_header(url, vuln_parameter, payload, proxy)

  # Check if defined any HTTP Proxy.
  if menu.options.proxy:
    try:
      proxy = _urllib.request.ProxyHandler({settings.SCHEME : menu.options.proxy})
      response = inject_custom_header(url, vuln_parameter, payload, proxy)
    except _urllib.error.HTTPError as err_msg:
      if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
        response = False  
      elif settings.IGNORE_ERR_MSG == False:
        err = str(err_msg) + "."
        if not settings.VERBOSITY_LEVEL != 0 and settings.TIME_BASED_STATE == False or \
          settings.VERBOSITY_LEVEL != 0 and settings.EVAL_BASED_STATE == None:
          print("")
        if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
          print("") 
        print(settings.print_critical_msg(err))
        continue_tests = checks.continue_tests(err_msg)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except _urllib.error.URLError as err_msg:
      err_msg = str(err_msg.reason).split(" ")[2:]
      err_msg = ' '.join(err_msg)+ "."
      if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
        print("")
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()
          
  # Check if defined Tor.
  elif menu.options.tor:
    try:
      proxy = _urllib.request.ProxyHandler({settings.SCHEME:settings.PRIVOXY_IP + ":" + settings.PRIVOXY_PORT})
      response = inject_custom_header(url, vuln_parameter, payload, proxy)
    except _urllib.error.HTTPError as err_msg:
      if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
        response = False  
      elif settings.IGNORE_ERR_MSG == False:
        err = str(err_msg) + "."
        if not settings.VERBOSITY_LEVEL != 0 and settings.TIME_BASED_STATE == False or \
          settings.VERBOSITY_LEVEL != 0 and settings.EVAL_BASED_STATE == None:
          print("")
        if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
          print("") 
        print(settings.print_critical_msg(err))
        continue_tests = checks.continue_tests(err_msg)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except _urllib.error.URLError as err_msg:
      err_msg = str(err_msg.reason).split(" ")[2:]
      err_msg = ' '.join(err_msg)+ "."
      if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
        print("")
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()
          
  else:
    try:
      response = inject_custom_header(url, vuln_parameter, payload, proxy)
    except _urllib.error.HTTPError as err_msg:
      if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
        response = False  
      elif settings.IGNORE_ERR_MSG == False:
        err = str(err_msg) + "."
        if not settings.VERBOSITY_LEVEL != 0 and settings.TIME_BASED_STATE == False or \
          settings.VERBOSITY_LEVEL != 0 and settings.EVAL_BASED_STATE == None:
          print("")
        if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
          print("") 
        print(settings.print_critical_msg(err))
        continue_tests = checks.continue_tests(err_msg)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except _urllib.error.URLError as err_msg:
      err_msg = str(err_msg.reason).split(" ")[2:]
      err_msg = ' '.join(err_msg)+ "."
      if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
        print("")
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()
          
  if settings.TIME_RELATIVE_ATTACK :
    end  = time.time()
    how_long = int(end - start)
    return how_long
  else:
    return response

"""
Target's encoding detection
"""
def encoding_detection(response):
  if not menu.options.encoding:
    charset_detected = False
    if settings.VERBOSITY_LEVEL != 0:
      debug_msg = "Identifying the indicated web-page charset. " 
      sys.stdout.write(settings.print_debug_msg(debug_msg))
      sys.stdout.flush()
    try:
      # Detecting charset
      try:
        # Support for python 2.7.x
        charset = response.headers.getparam('charset')
      except AttributeError:
        # Support for python 3.x
        charset = response.headers.get_content_charset()
      if charset != None and len(charset) != 0 :        
        charset_detected = True
      else:
        content = re.findall(r"charset=['\"](.*)['\"]", response.read())[0]
        if len(content) != 0 :
          charset = content
          charset_detected = True
        else:
           # Check if HTML5 format
          charset = re.findall(r"charset=['\"](.*?)['\"]", response.read())[0]
        if len(charset) != 0 :
          charset_detected = True
      # Check the identifyied charset
      if charset_detected :
        settings.DEFAULT_PAGE_ENCODING = charset
        if settings.VERBOSITY_LEVEL != 0:
          print(settings.SUCCESS_STATUS)
        if settings.DEFAULT_PAGE_ENCODING.lower() not in settings.ENCODING_LIST:
          warn_msg = "The indicated web-page charset "  + settings.DEFAULT_PAGE_ENCODING + " seems unknown."
          print(settings.print_warning_msg(warn_msg))
        else:
          if settings.VERBOSITY_LEVEL != 0:
            debug_msg = "The indicated web-page charset appears to be " 
            debug_msg += settings.DEFAULT_PAGE_ENCODING + Style.RESET_ALL + "."
            print(settings.print_bold_debug_msg(debug_msg))
      else:
        pass
    except:
      pass
    if charset_detected == False and settings.VERBOSITY_LEVEL != 0:
      print(settings.FAIL_STATUS)
      warn_msg = "Heuristics have failed to identify indicated web-page charset."
      print(settings.print_warning_msg(warn_msg))

"""
Procedure for target application identification
"""
def technology_detection(response):
  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Identifying the technology supporting the target application. " 
    sys.stdout.write(settings.print_debug_msg(debug_msg))
    sys.stdout.flush()
    print(settings.SUCCESS_STATUS) 
    if response.info()['X-Powered-By']:         
      debug_msg = "The target application is powered by " 
      debug_msg += response.info()['X-Powered-By'] + Style.RESET_ALL + "."
      print(settings.print_bold_debug_msg(debug_msg))
    else:
      warn_msg = "Heuristics have failed to identify the technology supporting the target application."
      print(settings.print_warning_msg(warn_msg))

"""
Procedure for target application identification
"""
def application_identification(url):
  found_application_extension = False
  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Identifying the target application." 
    sys.stdout.write(settings.print_debug_msg(debug_msg))
    sys.stdout.flush()
  root, application_extension = splitext(_urllib.parse.urlparse(url).path)
  settings.TARGET_APPLICATION = application_extension[1:].upper()
  
  if settings.TARGET_APPLICATION:
    found_application_extension = True
    if settings.VERBOSITY_LEVEL != 0:
      print(settings.SUCCESS_STATUS)           
      debug_msg = "The target application identified as " 
      debug_msg += settings.TARGET_APPLICATION + Style.RESET_ALL + "."
      print(settings.print_bold_debug_msg(debug_msg))

    # Check for unsupported target applications
    for i in range(0,len(settings.UNSUPPORTED_TARGET_APPLICATION)):
      if settings.TARGET_APPLICATION.lower() in settings.UNSUPPORTED_TARGET_APPLICATION[i].lower():
        err_msg = settings.TARGET_APPLICATION + " exploitation is not yet supported."  
        print(settings.print_critical_msg(err_msg))
        raise SystemExit()

  if not found_application_extension:
    if settings.VERBOSITY_LEVEL != 0:
      print(settings.FAIL_STATUS)
      warn_msg = "Heuristics have failed to identify target application."
      print(settings.print_warning_msg(warn_msg))

"""
Procedure for target server's identification.
"""
def server_identification(server_banner):
  found_server_banner = False
  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Identifying the target server. " 
    sys.stdout.write(settings.print_debug_msg(debug_msg))
    sys.stdout.flush()

  for i in range(0,len(settings.SERVER_BANNERS)):
    match = re.search(settings.SERVER_BANNERS[i].lower(), server_banner.lower())
    if match:
      if settings.VERBOSITY_LEVEL != 0:
        print(settings.SUCCESS_STATUS)
      if settings.VERBOSITY_LEVEL != 0:
        debug_msg = "The target server identified as " 
        debug_msg += server_banner + Style.RESET_ALL + "."
        print(settings.print_bold_debug_msg(debug_msg))
      settings.SERVER_BANNER = match.group(0)
      found_server_banner = True
      # Set up default root paths
      if "apache" in settings.SERVER_BANNER.lower():
        if settings.TARGET_OS == "win":
          settings.WEB_ROOT = "\\htdocs"
        else:
          settings.WEB_ROOT = "/var/www"
      elif "nginx" in settings.SERVER_BANNER.lower(): 
        settings.WEB_ROOT = "/usr/share/nginx"
      elif "microsoft-iis" in settings.SERVER_BANNER.lower():
        settings.WEB_ROOT = "\\inetpub\\wwwroot"
      break
  else:
    if settings.VERBOSITY_LEVEL != 0:
      print(settings.FAIL_STATUS)
      warn_msg = "The server which identified as '" 
      warn_msg += server_banner + "' seems unknown."
      print(settings.print_warning_msg(warn_msg))

"""
Procedure for target server's operating system identification.
"""
def check_target_os(server_banner):
  found_os_server = False
  if menu.options.os and checks.user_defined_os():
    user_defined_os = settings.TARGET_OS

  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Identifying the target operating system. " 
    sys.stdout.write(settings.print_debug_msg(debug_msg))
    sys.stdout.flush()

  # Procedure for target OS identification.
  for i in range(0,len(settings.SERVER_OS_BANNERS)):
    match = re.search(settings.SERVER_OS_BANNERS[i].lower(), server_banner.lower())
    if match:
      found_os_server = True
      settings.TARGET_OS = match.group(0)
      match = re.search(r"microsoft|win", settings.TARGET_OS)
      if match:
        identified_os = "Windows"
        if menu.options.os and user_defined_os != "win":
          if not checks.identified_os():
            settings.TARGET_OS = user_defined_os

        settings.TARGET_OS = identified_os[:3].lower()
        if menu.options.shellshock:
          err_msg = "The shellshock module is not available for " 
          err_msg += identified_os + " targets."
          print(settings.print_critical_msg(err_msg))
          raise SystemExit()
      else:
        identified_os = "Unix-like (" + settings.TARGET_OS + ")"
        if menu.options.os and user_defined_os == "win":
          if not checks.identified_os():
            settings.TARGET_OS = user_defined_os

  if settings.VERBOSITY_LEVEL != 0 :
    if found_os_server:
      print(settings.SUCCESS_STATUS)
      debug_msg = "The target operating system appears to be " 
      debug_msg += identified_os.title() + Style.RESET_ALL + "."
      print(settings.print_bold_debug_msg(debug_msg))
    else:
      print(settings.FAIL_STATUS)
      warn_msg = "Heuristics have failed to identify server's operating system."
      print(settings.print_warning_msg(warn_msg))

  if found_os_server == False and not menu.options.os:
    # If "--shellshock" option is provided then,
    # by default is a Linux/Unix operating system.
    if menu.options.shellshock:
      pass 
    else:
      if menu.options.batch:
        if not settings.CHECK_BOTH_OS:
          settings.CHECK_BOTH_OS = True
          check_type = "unix-based"
        elif settings.CHECK_BOTH_OS:
          settings.TARGET_OS = "win"
          settings.CHECK_BOTH_OS = False
          settings.PERFORM_BASIC_SCANS = True
          check_type = "windows-based"
        info_msg = "Setting the " + check_type + " payloads."
        print(settings.print_info_msg(info_msg))
      else:
        while True:
          question_msg = "Do you recognise the server's operating system? "
          question_msg += "[(W)indows/(U)nix/(q)uit] > "
          got_os = _input(settings.print_question_msg(question_msg))
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
            print(settings.print_error_msg(err_msg))
            pass

"""
Perform target page reload (if it is required).
"""
def url_reload(url, timesec):
  if timesec <= "5":
    timesec = 5
    time.sleep(timesec)
  response = urllib.urlopen(url)
  return response

# eof