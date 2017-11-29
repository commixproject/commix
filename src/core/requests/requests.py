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

import sys
import time
import socket
import urllib
import urllib2

from src.utils import menu
from src.utils import settings
from src.thirdparty.colorama import Fore, Back, Style, init

from src.core.requests import tor
from src.core.requests import proxy
from src.core.requests import headers
from src.core.requests import parameters

from src.core.injections.controller import checks

"""
Estimating the response time (in seconds).
"""
def estimate_response_time(url, timesec):
  if settings.VERBOSITY_LEVEL >= 1:
    info_msg = "Estimating the target URL response time... "
    sys.stdout.write(settings.print_info_msg(info_msg))
    sys.stdout.flush()
  # Check if defined POST data
  if menu.options.data:
    request = urllib2.Request(url, menu.options.data)
  else:
    url = parameters.get_url_part(url)
    request = urllib2.Request(url)
  headers.do_check(request)
  start = time.time()
  try:
    response = urllib2.urlopen(request)
    response.read(1)
    response.close()
  except urllib2.HTTPError, e:
    pass
  except socket.timeout:
    if settings.VERBOSITY_LEVEL >= 1:
      print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"
    err_msg = "The connection to target URL has timed out."
    print settings.print_critical_msg(err_msg)+ "\n"
    sys.exit(0)     
  end = time.time()
  diff = end - start
  if int(diff) < 1:
    if settings.VERBOSITY_LEVEL >= 1:
      print "[ " + Fore.GREEN + "SUCCEED" + Style.RESET_ALL + " ]"
    url_time_response = int(diff)
    if settings.TARGET_OS == "win":
      warn_msg = "Due to the relatively slow response of 'cmd.exe' in target "
      warn_msg += "host, there may be delays during the data extraction procedure."
      print settings.print_warning_msg(warn_msg)
  else:
    if settings.VERBOSITY_LEVEL >= 1:
      print "[ " + Fore.GREEN + "SUCCEED" + Style.RESET_ALL + " ]"
    url_time_response = int(round(diff))
    warn_msg = "The estimated response time is " + str(url_time_response)
    warn_msg += " second" + "s"[url_time_response == 1:] + ". That may cause" 
    if url_time_response >= 3:
      warn_msg += " serious"
    warn_msg += " delays during the data extraction procedure" 
    if url_time_response >= 3:
      warn_msg += " and/or possible corruptions over the extracted data"
    warn_msg += "."
    print settings.print_warning_msg(warn_msg)
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

  if settings.REVERSE_TCP == False and settings.BIND_TCP == False:
    headers.check_http_traffic(request)
    # Check if defined any HTTP Proxy.
    if menu.options.proxy:
      try:
        response = proxy.use_proxy(request)
      except urllib2.HTTPError, err_msg:
        if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
          response = False  
        elif settings.IGNORE_ERR_MSG == False:
          err = str(err_msg) + "."
          if not settings.VERBOSITY_LEVEL >= 1 and settings.TIME_BASED_STATE == False or \
            settings.VERBOSITY_LEVEL >= 1 and settings.EVAL_BASED_STATE == None:
            print ""
          if settings.VERBOSITY_LEVEL >= 1 and settings.LOAD_SESSION == False:
            print "" 
          print settings.print_critical_msg(err)
          continue_tests = checks.continue_tests(err_msg)
          if continue_tests == True:
            settings.IGNORE_ERR_MSG = True
          else:
            raise SystemExit()
        response = False 
      except urllib2.URLError, err_msg:
        if "Connection refused" in err_msg.reason:
          err_msg =  "The target host is not responding. "
          err_msg += "Please ensure that is up and try again."
          if not settings.VERBOSITY_LEVEL >= 1 and settings.TIME_BASED_STATE == False or \
             settings.VERBOSITY_LEVEL >= 1 and settings.EVAL_BASED_STATE == None:
            print ""
          if settings.VERBOSITY_LEVEL >= 1 and settings.LOAD_SESSION == False:
            print ""
          print settings.print_critical_msg(err_msg)
        raise SystemExit()

    # Check if defined Tor.
    elif menu.options.tor:
      try:
        response = tor.use_tor(request)
      except urllib2.HTTPError, err_msg:
        if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
          response = False  
        elif settings.IGNORE_ERR_MSG == False:
          err = str(err_msg) + "."
          if not settings.VERBOSITY_LEVEL >= 1 and settings.TIME_BASED_STATE == False or \
            settings.VERBOSITY_LEVEL >= 1 and settings.EVAL_BASED_STATE == None:
            print ""
          if settings.VERBOSITY_LEVEL >= 1 and settings.LOAD_SESSION == False:
            print "" 
          print settings.print_critical_msg(err)
          continue_tests = checks.continue_tests(err_msg)
          if continue_tests == True:
            settings.IGNORE_ERR_MSG = True
          else:
            raise SystemExit()
        response = False 
      except urllib2.URLError, err_msg:
        err_msg = str(err_msg.reason).split(" ")[2:]
        err_msg = ' '.join(err_msg)+ "."
        if settings.VERBOSITY_LEVEL >= 1 and settings.LOAD_SESSION == False:
          print ""
        print settings.print_critical_msg(err_msg)
        raise SystemExit()

    else:
      try:
        response = urllib2.urlopen(request)
      except urllib2.HTTPError, err_msg:
        if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
          response = False  
        elif settings.IGNORE_ERR_MSG == False:
          err = str(err_msg) + "."
          if not settings.VERBOSITY_LEVEL >= 1 and settings.TIME_BASED_STATE == False or \
            settings.VERBOSITY_LEVEL >= 1 and settings.EVAL_BASED_STATE == None:
            print ""
          if settings.VERBOSITY_LEVEL >= 1 and settings.LOAD_SESSION == False:
            print "" 
          print settings.print_critical_msg(err)
          continue_tests = checks.continue_tests(err_msg)
          if continue_tests == True:
            settings.IGNORE_ERR_MSG = True
          else:
            raise SystemExit()
        response = False  
      except urllib2.URLError, err_msg:
        err_msg = str(err_msg.reason).split(" ")[2:]
        err_msg = ' '.join(err_msg)+ "."
        if settings.VERBOSITY_LEVEL >= 1 and settings.LOAD_SESSION == False:
          print ""
        print settings.print_critical_msg(err_msg)
        raise SystemExit()
  else:
    response = headers.check_http_traffic(request)
  return response

"""
Check if target host is vulnerable. (Cookie-based injection)
"""
def cookie_injection(url, vuln_parameter, payload):

  def inject_cookie(url, vuln_parameter, payload, proxy):
    if proxy == None:
      opener = urllib2.build_opener()
    else:
      opener = urllib2.build_opener(proxy)

    if settings.TIME_RELATIVE_ATTACK :
      payload = urllib.quote(payload)

    # Check if defined POST data
    if menu.options.data:
      menu.options.data = settings.USER_DEFINED_POST_DATA
      request = urllib2.Request(url, menu.options.data)
    else:
      url = parameters.get_url_part(url)
      request = urllib2.Request(url)
    #Check if defined extra headers.
    headers.do_check(request)
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
      proxy = urllib2.ProxyHandler({settings.PROXY_PROTOCOL : menu.options.proxy})
      response = inject_cookie(url, vuln_parameter, payload, proxy)
    except urllib2.HTTPError, err_msg:
      if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
        response = False  
      elif settings.IGNORE_ERR_MSG == False:
        err_msg = str(err_msg) + "."
        print "\n" + settings.print_critical_msg(err_msg)
        continue_tests = checks.continue_tests(err)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False  
    except urllib2.URLError, err_msg:
      err_msg = str(err_msg.reason).split(" ")[2:]
      err_msg = ' '.join(err_msg)+ "."
      if settings.VERBOSITY_LEVEL >= 1 and settings.LOAD_SESSION == False:
        print ""
      print settings.print_critical_msg(err_msg)
      raise SystemExit()

  # Check if defined Tor.
  elif menu.options.tor:
    try:
      proxy = urllib2.ProxyHandler({settings.PROXY_PROTOCOL:settings.PRIVOXY_IP + ":" + PRIVOXY_PORT})
      response = inject_cookie(url, vuln_parameter, payload, proxy)
    except urllib2.HTTPError, err_msg:
      if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
        response = False  
      elif settings.IGNORE_ERR_MSG == False:
        err = str(err_msg) + "."
        if not settings.VERBOSITY_LEVEL >= 1 and settings.TIME_BASED_STATE == False or \
          settings.VERBOSITY_LEVEL >= 1 and settings.EVAL_BASED_STATE == None:
          print ""
        if settings.VERBOSITY_LEVEL >= 1 and settings.LOAD_SESSION == False:
          print "" 
        print settings.print_critical_msg(err)
        continue_tests = checks.continue_tests(err_msg)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except urllib2.URLError, err_msg:
      err_msg = str(err_msg.reason).split(" ")[2:]
      err_msg = ' '.join(err_msg)+ "."
      if settings.VERBOSITY_LEVEL >= 1 and settings.LOAD_SESSION == False:
        print ""
      print settings.print_critical_msg(err_msg)
      raise SystemExit()

  else:
    try:
      response = inject_cookie(url, vuln_parameter, payload, proxy)
    except urllib2.HTTPError, err_msg:
      if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
        response = False  
      elif settings.IGNORE_ERR_MSG == False:
        err = str(err_msg) + "."
        if not settings.VERBOSITY_LEVEL >= 1 and settings.TIME_BASED_STATE == False or \
          settings.VERBOSITY_LEVEL >= 1 and settings.EVAL_BASED_STATE == None:
          print ""
        if settings.VERBOSITY_LEVEL >= 1 and settings.LOAD_SESSION == False:
          print "" 
        print settings.print_critical_msg(err)
        continue_tests = checks.continue_tests(err_msg)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 

    except urllib2.URLError, err_msg:
      err_msg = str(err_msg.reason).split(" ")[2:]
      err_msg = ' '.join(err_msg)+ "."
      if settings.VERBOSITY_LEVEL >= 1 and settings.LOAD_SESSION == False:
        print ""
      print settings.print_critical_msg(err_msg)
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
      opener = urllib2.build_opener()
    else:
      opener = urllib2.build_opener(proxy)

    # Check if defined POST data
    if menu.options.data:
      menu.options.data = settings.USER_DEFINED_POST_DATA
      request = urllib2.Request(url, menu.options.data)
    else:
      url = parameters.get_url_part(url)
      request = urllib2.Request(url)
    #Check if defined extra headers.
    headers.do_check(request)
    request.add_header('User-Agent', urllib.unquote(payload))
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
      proxy = urllib2.ProxyHandler({settings.PROXY_PROTOCOL : menu.options.proxy})
      response = inject_user_agent(url, vuln_parameter, payload, proxy)
    except urllib2.HTTPError, err_msg:
      if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
        response = False  
      elif settings.IGNORE_ERR_MSG == False:
        err = str(err_msg) + "."
        if not settings.VERBOSITY_LEVEL >= 1 and settings.TIME_BASED_STATE == False or \
          settings.VERBOSITY_LEVEL >= 1 and settings.EVAL_BASED_STATE == None:
          print ""
        if settings.VERBOSITY_LEVEL >= 1 and settings.LOAD_SESSION == False:
          print "" 
        print settings.print_critical_msg(err)
        continue_tests = checks.continue_tests(err_msg)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except urllib2.URLError, err_msg:
      err_msg = str(err_msg.reason).split(" ")[2:]
      err_msg = ' '.join(err_msg)+ "."
      if settings.VERBOSITY_LEVEL >= 1 and settings.LOAD_SESSION == False:
        print ""
      print settings.print_critical_msg(err_msg)
      raise SystemExit()

  # Check if defined Tor.
  elif menu.options.tor:
    try:
      proxy = urllib2.ProxyHandler({settings.PROXY_PROTOCOL:settings.PRIVOXY_IP + ":" + PRIVOXY_PORT})
      response = inject_user_agent(url, vuln_parameter, payload, proxy)
    except urllib2.HTTPError, err_msg:
      if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
        response = False  
      elif settings.IGNORE_ERR_MSG == False:
        err = str(err_msg) + "."
        if not settings.VERBOSITY_LEVEL >= 1 and settings.TIME_BASED_STATE == False or \
          settings.VERBOSITY_LEVEL >= 1 and settings.EVAL_BASED_STATE == None:
          print ""
        if settings.VERBOSITY_LEVEL >= 1 and settings.LOAD_SESSION == False:
          print "" 
        print settings.print_critical_msg(err)
        continue_tests = checks.continue_tests(err_msg)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except urllib2.URLError, err_msg:
      err_msg = str(err_msg.reason).split(" ")[2:]
      err_msg = ' '.join(err_msg)+ "."
      if settings.VERBOSITY_LEVEL >= 1 and settings.LOAD_SESSION == False:
        print ""
      print settings.print_critical_msg(err_msg)
      raise SystemExit()

  else:
    try:
      response = inject_user_agent(url, vuln_parameter, payload, proxy)
    except urllib2.HTTPError, err_msg:
      if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
        response = False  
      elif settings.IGNORE_ERR_MSG == False:
        err = str(err_msg) + "."
        if not settings.VERBOSITY_LEVEL >= 1 and settings.TIME_BASED_STATE == False or \
          settings.VERBOSITY_LEVEL >= 1 and settings.EVAL_BASED_STATE == None:
          print ""
        if settings.VERBOSITY_LEVEL >= 1 and settings.LOAD_SESSION == False:
          print "" 
        print settings.print_critical_msg(err)
        continue_tests = checks.continue_tests(err_msg)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except urllib2.URLError, err_msg:
      err_msg = str(err_msg.reason).split(" ")[2:]
      err_msg = ' '.join(err_msg)+ "."
      if settings.VERBOSITY_LEVEL >= 1 and settings.LOAD_SESSION == False:
        print ""
      print settings.print_critical_msg(err_msg)
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
      opener = urllib2.build_opener()
    else:
      opener = urllib2.build_opener(proxy)

    # Check if defined POST data
    if menu.options.data:
      menu.options.data = settings.USER_DEFINED_POST_DATA
      request = urllib2.Request(url, menu.options.data)
    else:
      url = parameters.get_url_part(url)
      request = urllib2.Request(url)
    #Check if defined extra headers.
    headers.do_check(request)
    request.add_header('Referer', urllib.unquote(payload))
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
      proxy = urllib2.ProxyHandler({settings.PROXY_PROTOCOL : menu.options.proxy})
      response = inject_referer(url, vuln_parameter, payload, proxy)
    except urllib2.HTTPError, err_msg:
      if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
        response = False  
      elif settings.IGNORE_ERR_MSG == False:
        err = str(err_msg) + "."
        if not settings.VERBOSITY_LEVEL >= 1 and settings.TIME_BASED_STATE == False or \
          settings.VERBOSITY_LEVEL >= 1 and settings.EVAL_BASED_STATE == None:
          print ""
        if settings.VERBOSITY_LEVEL >= 1 and settings.LOAD_SESSION == False:
          print "" 
        print settings.print_critical_msg(err)
        continue_tests = checks.continue_tests(err_msg)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except urllib2.URLError, err_msg:
      err_msg = str(err_msg.reason).split(" ")[2:]
      err_msg = ' '.join(err_msg)+ "."
      if settings.VERBOSITY_LEVEL >= 1 and settings.LOAD_SESSION == False:
        print ""
      print settings.print_critical_msg(err_msg)
      raise SystemExit()
          
  # Check if defined Tor.
  elif menu.options.tor:
    try:
      proxy = urllib2.ProxyHandler({settings.PROXY_PROTOCOL:settings.PRIVOXY_IP + ":" + PRIVOXY_PORT})
      response = inject_referer(url, vuln_parameter, payload, proxy)
    except urllib2.HTTPError, err_msg:
      if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
        response = False  
      elif settings.IGNORE_ERR_MSG == False:
        err = str(err_msg) + "."
        if not settings.VERBOSITY_LEVEL >= 1 and settings.TIME_BASED_STATE == False or \
          settings.VERBOSITY_LEVEL >= 1 and settings.EVAL_BASED_STATE == None:
          print ""
        if settings.VERBOSITY_LEVEL >= 1 and settings.LOAD_SESSION == False:
          print "" 
        print settings.print_critical_msg(err)
        continue_tests = checks.continue_tests(err_msg)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except urllib2.URLError, err_msg:
      err_msg = str(err_msg.reason).split(" ")[2:]
      err_msg = ' '.join(err_msg)+ "."
      if settings.VERBOSITY_LEVEL >= 1 and settings.LOAD_SESSION == False:
        print ""
      print settings.print_critical_msg(err_msg)
      raise SystemExit()
          
  else:
    try:
      response = inject_referer(url, vuln_parameter, payload, proxy)

    except urllib2.HTTPError, err_msg:
      if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
        response = False  
      elif settings.IGNORE_ERR_MSG == False:
        err = str(err_msg) + "."
        if not settings.VERBOSITY_LEVEL >= 1 and settings.TIME_BASED_STATE == False or \
          settings.VERBOSITY_LEVEL >= 1 and settings.EVAL_BASED_STATE == None:
          print ""
        if settings.VERBOSITY_LEVEL >= 1 and settings.LOAD_SESSION == False:
          print "" 
        print settings.print_critical_msg(err)
        continue_tests = checks.continue_tests(err_msg)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except urllib2.URLError, err_msg:
      err_msg = str(err_msg.reason).split(" ")[2:]
      err_msg = ' '.join(err_msg)+ "."
      if settings.VERBOSITY_LEVEL >= 1 and settings.LOAD_SESSION == False:
        print ""
      print settings.print_critical_msg(err_msg)
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
      opener = urllib2.build_opener()
    else:
      opener = urllib2.build_opener(proxy)

    # Check if defined POST data
    if menu.options.data:
      menu.options.data = settings.USER_DEFINED_POST_DATA
      request = urllib2.Request(url, menu.options.data)
    else:
      url = parameters.get_url_part(url)
      request = urllib2.Request(url)
    #Check if defined extra headers.
    headers.do_check(request)
    request.add_header(settings.CUSTOM_HEADER_NAME, urllib.unquote(payload))
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
      proxy = urllib2.ProxyHandler({settings.PROXY_PROTOCOL : menu.options.proxy})
      response = inject_custom_header(url, vuln_parameter, payload, proxy)
    except urllib2.HTTPError, err_msg:
      if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
        response = False  
      elif settings.IGNORE_ERR_MSG == False:
        err = str(err_msg) + "."
        if not settings.VERBOSITY_LEVEL >= 1 and settings.TIME_BASED_STATE == False or \
          settings.VERBOSITY_LEVEL >= 1 and settings.EVAL_BASED_STATE == None:
          print ""
        if settings.VERBOSITY_LEVEL >= 1 and settings.LOAD_SESSION == False:
          print "" 
        print settings.print_critical_msg(err)
        continue_tests = checks.continue_tests(err_msg)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except urllib2.URLError, err_msg:
      err_msg = str(err_msg.reason).split(" ")[2:]
      err_msg = ' '.join(err_msg)+ "."
      if settings.VERBOSITY_LEVEL >= 1 and settings.LOAD_SESSION == False:
        print ""
      print settings.print_critical_msg(err_msg)
      raise SystemExit()
          
  # Check if defined Tor.
  elif menu.options.tor:
    try:
      proxy = urllib2.ProxyHandler({settings.PROXY_PROTOCOL:settings.PRIVOXY_IP + ":" + PRIVOXY_PORT})
      response = inject_custom_header(url, vuln_parameter, payload, proxy)
    except urllib2.HTTPError, err_msg:
      if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
        response = False  
      elif settings.IGNORE_ERR_MSG == False:
        err = str(err_msg) + "."
        if not settings.VERBOSITY_LEVEL >= 1 and settings.TIME_BASED_STATE == False or \
          settings.VERBOSITY_LEVEL >= 1 and settings.EVAL_BASED_STATE == None:
          print ""
        if settings.VERBOSITY_LEVEL >= 1 and settings.LOAD_SESSION == False:
          print "" 
        print settings.print_critical_msg(err)
        continue_tests = checks.continue_tests(err_msg)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except urllib2.URLError, err_msg:
      err_msg = str(err_msg.reason).split(" ")[2:]
      err_msg = ' '.join(err_msg)+ "."
      if settings.VERBOSITY_LEVEL >= 1 and settings.LOAD_SESSION == False:
        print ""
      print settings.print_critical_msg(err_msg)
      raise SystemExit()
          
  else:
    try:
      response = inject_custom_header(url, vuln_parameter, payload, proxy)
    except urllib2.HTTPError, err_msg:
      if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
        response = False  
      elif settings.IGNORE_ERR_MSG == False:
        err = str(err_msg) + "."
        if not settings.VERBOSITY_LEVEL >= 1 and settings.TIME_BASED_STATE == False or \
          settings.VERBOSITY_LEVEL >= 1 and settings.EVAL_BASED_STATE == None:
          print ""
        if settings.VERBOSITY_LEVEL >= 1 and settings.LOAD_SESSION == False:
          print "" 
        print settings.print_critical_msg(err)
        continue_tests = checks.continue_tests(err_msg)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except urllib2.URLError, err_msg:
      err_msg = str(err_msg.reason).split(" ")[2:]
      err_msg = ' '.join(err_msg)+ "."
      if settings.VERBOSITY_LEVEL >= 1 and settings.LOAD_SESSION == False:
        print ""
      print settings.print_critical_msg(err_msg)
      raise SystemExit()
          
  if settings.TIME_RELATIVE_ATTACK :
    end  = time.time()
    how_long = int(end - start)
    return how_long
  else:
    return response

"""
Target's charset detection
"""
def charset_detection(response):
  if not menu.options.charset:
    charset_detected = False
    if settings.VERBOSITY_LEVEL >= 1:
      info_msg = "Identifing the indicated web-page charset... " 
      sys.stdout.write(settings.print_info_msg(info_msg))
      sys.stdout.flush()
    try:
      # Detecting charset
      charset = response.headers.getparam('charset')
      if len(charset) != 0 :         
        charset_detected = True
      else:
        content = re.findall(r";charset=(.*)\"", html_data)
        if len(content) != 0 :
          charset = content
          charset_detected = True
        else:
           # Check if HTML5 format
          charset = re.findall(r"charset=['\"](.*?)['\"]", html_data) 
        if len(charset) != 0 :
          charset_detected = True
      # Check the identifyied charset
      if charset_detected :
        settings.DEFAULT_CHARSET = charset
        if settings.VERBOSITY_LEVEL >= 1:
          print "[ " + Fore.GREEN + "SUCCEED" + Style.RESET_ALL + " ]"
        settings.CHARSET = charset.lower()
        if settings.CHARSET.lower() not in settings.CHARSET_LIST:
          warn_msg = "The indicated web-page charset "  + settings.CHARSET + " seems unknown."
          print settings.print_warning_msg(warn_msg)
        else:
          if settings.VERBOSITY_LEVEL >= 1:
            success_msg = "The indicated web-page charset appears to be " 
            success_msg += settings.CHARSET + Style.RESET_ALL + "."
            print settings.print_success_msg(success_msg)
      else:
        pass
    except:
      pass
    if charset_detected == False and settings.VERBOSITY_LEVEL >= 1:
      print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"
  else:
    settings.CHARSET = menu.options.charset
    if settings.CHARSET.lower() not in settings.CHARSET_LIST:
      err_msg = "The user-defined charset '"  + settings.CHARSET + "' seems unknown. "
      err_msg += "Please visit 'http://docs.python.org/library/codecs.html#standard-encodings' "
      err_msg += "to get the full list of supported charsets."
      print settings.print_critical_msg(err_msg)
      sys.exit(0)

# Perform target page reload (if it is required).
def url_reload(url, timesec):
  if timesec <= "5":
    timesec = 5
    time.sleep(timesec)
  response = urllib.urlopen(url)
  return response

#eof