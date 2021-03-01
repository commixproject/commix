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
import ssl
try:
  _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
  # Legacy Python that doesn't verify HTTPS certificates by default
  pass
else:
  # Handle target environment that doesn't support HTTPS verification
  ssl._create_default_https_context = _create_unverified_https_context
import sys

import time
import errno
import base64
try:
  from base64 import encodebytes
except ImportError: 
  from base64 import encodestring as encodebytes
import socket
from socket import error as SocketError
from src.thirdparty.six.moves import http_client as _http_client
from src.utils import logs
from src.utils import menu
from src.utils import settings
from src.core.injections.controller import checks
from src.thirdparty.colorama import Fore, Back, Style, init
from src.thirdparty.six.moves import urllib as _urllib

"""
Checking the HTTP response content.
"""
def http_response_content(content):
  if settings.VERBOSITY_LEVEL >= 4:
    content = checks.remove_empty_lines(content)
    print(settings.print_http_response_content(content))
  if menu.options.traffic_file:
    logs.log_traffic(content)
    logs.log_traffic("\n\n" + "#" * 77 + "\n\n")

"""
Checking the HTTP response headers.
"""
def http_response(headers, code):
  response_http_headers = str(headers).split("\n")
  for header in response_http_headers:
    if len(header) > 1: 
      if settings.VERBOSITY_LEVEL >= 3:
        print(settings.print_traffic(header))
      if menu.options.traffic_file:
        logs.log_traffic("\n" + header)
  if menu.options.traffic_file:
    logs.log_traffic("\n\n")    

"""
Print HTTP response headers / Body.
"""
def print_http_response(response_headers, code, page):
  if settings.VERBOSITY_LEVEL >= 3 or menu.options.traffic_file:
    if settings.VERBOSITY_LEVEL >= 3:
      resp_msg = "HTTP response [" + settings.print_request_num(settings.TOTAL_OF_REQUESTS) + "] (" + str(code) + "):"
      print(settings.print_response_msg(resp_msg))
    if menu.options.traffic_file:
      resp_msg = "HTTP response [#" + str(settings.TOTAL_OF_REQUESTS) + "] (" + str(code) + "):"
      logs.log_traffic("\n" + resp_msg)
    http_response(response_headers, code)
  if settings.VERBOSITY_LEVEL >= 4 or menu.options.traffic_file:
    if settings.VERBOSITY_LEVEL >= 4:
      print("")
    try:
      http_response_content(page)
    except AttributeError:
      http_response_content(page.decode(settings.UNICODE_ENCODING))

"""
Checking the HTTP Headers & HTTP/S Request.
"""
def check_http_traffic(request):
  settings.TOTAL_OF_REQUESTS = settings.TOTAL_OF_REQUESTS + 1
  # Delay in seconds between each HTTP request
  time.sleep(int(settings.DELAY))
  if settings.SCHEME == 'https':
    http_client = _http_client.HTTPSConnection
  else:
    http_client = _http_client.HTTPConnection

  class connection(http_client):
    def send(self, req):
      headers = req.decode()
      request_http_headers = str(headers).split("\r\n")
      unique_request_http_headers = []
      [unique_request_http_headers.append(item) for item in request_http_headers if item not in unique_request_http_headers]
      request_http_headers = unique_request_http_headers
      for header in request_http_headers:
        if settings.VERBOSITY_LEVEL >= 2:
          print(settings.print_traffic(header))
        if menu.options.traffic_file:
          logs.log_traffic("\n" + header)
      http_client.send(self, req)

  class connection_handler(_urllib.request.HTTPSHandler, _urllib.request.HTTPHandler, object):
    def http_open(self, req):
      try:
        self.do_open(connection, req)
        return super(connection_handler, self).http_open(req)
      except (_urllib.error.HTTPError, _urllib.error.URLError) as err_msg:
        try:
          error_msg = str(err_msg.args[0]).split("] ")[1] + "."
        except IndexError:
          error_msg = str(err_msg.args[0]) + "."
          error_msg = "Connection to the target URL " + error_msg
      except _http_client.InvalidURL as err_msg:
        settings.VALID_URL = False
        error_msg = err_msg 
      if current_attempt == 0 and settings.VERBOSITY_LEVEL < 2:
        print("")
      print(settings.print_critical_msg(error_msg))
      if not settings.VALID_URL:
        raise SystemExit()


    def https_open(self, req):
      try:
        self.do_open(connection, req)
        return super(connection_handler, self).https_open(req)
      except (_urllib.error.HTTPError, _urllib.error.URLError) as err_msg:
        try:
          error_msg = str(err_msg.args[0]).split("] ")[1] + "."
        except IndexError:
          error_msg = str(err_msg.args[0]) + "."
          error_msg = "Connection to the target URL " + error_msg
      except _http_client.InvalidURL as err_msg:
        settings.VALID_URL = False
        error_msg = err_msg 
      if current_attempt == 0 and settings.VERBOSITY_LEVEL < 2:
        print("")
      print(settings.print_critical_msg(error_msg))
      if not settings.VALID_URL:
        raise SystemExit()
        
  opener = _urllib.request.build_opener(connection_handler())
  _ = False
  current_attempt = 0
  unauthorized = False
  while not _ and current_attempt <= settings.MAX_RETRIES and unauthorized is False:
    if settings.VERBOSITY_LEVEL >= 2 or menu.options.traffic_file:
      if settings.VERBOSITY_LEVEL >= 2:
        req_msg = "HTTP request [" + settings.print_request_num(settings.TOTAL_OF_REQUESTS) + "]:"
        print(settings.print_request_msg(req_msg))
      if menu.options.traffic_file:
        req_msg = "HTTP request [#" + str(settings.TOTAL_OF_REQUESTS) + "]:"
        logs.log_traffic(req_msg)
    try:
      response = opener.open(request, timeout=settings.TIMEOUT)
      page = checks.page_encoding(response, action="encode")
      _ = True
      if settings.VERBOSITY_LEVEL < 2:
        if current_attempt != 0:
          info_msg = "Testing connection to the target URL."
          sys.stdout.write(settings.print_info_msg(info_msg))
          sys.stdout.flush()
        if settings.INIT_TEST == True and not settings.UNAUTHORIZED:
          print(settings.SUCCESS_STATUS)
          if not settings.CHECK_INTERNET:
            settings.INIT_TEST = False

    except _urllib.error.HTTPError as err_msg:
      if settings.UNAUTHORIZED_ERROR in str(err_msg):
        if settings.VERBOSITY_LEVEL < 2 and not settings.UNAUTHORIZED:
          print(settings.FAIL_STATUS)
        settings.UNAUTHORIZED = unauthorized = True
      http_errors = [settings.BAD_REQUEST, settings.FORBIDDEN_ERROR, settings.NOT_FOUND_ERROR,\
                     settings.NOT_ACCEPTABLE_ERROR, settings.INTERNAL_SERVER_ERROR]
      if [True for err_code in http_errors if err_code in str(err_msg)]:
        if settings.VERBOSITY_LEVEL < 2:
          break

    except _urllib.error.URLError as err_msg: 
      if current_attempt == 0:
        warn_msg = "The provided target URL seems not reachable. "
        warn_msg += "In case that it is, please try to re-run using "
        if not menu.options.random_agent:
            warn_msg += "'--random-agent' switch and/or "
        warn_msg += "'--proxy' option."
        print(settings.print_warning_msg(warn_msg))
      if settings.VERBOSITY_LEVEL != 0:
        debug_msg = settings.APPLICATION + " is going to retry the request(s)."
        print(settings.print_debug_msg(debug_msg))
      current_attempt = current_attempt + 1
      time.sleep(3)
      
    except _http_client.BadStatusLine as err_msg:
      if settings.VERBOSITY_LEVEL < 2:
        print(settings.FAIL_STATUS)
      if len(err_msg.line) > 2 :
        print(err_msg.line, err_msg.message)
      raise SystemExit()

    except ValueError as err:
      if settings.VERBOSITY_LEVEL < 2:
        print(settings.FAIL_STATUS)
      err_msg = "Invalid target URL has been given." 
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()

    except AttributeError:
      raise SystemExit() 
      
  try:
    response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
    code = response.getcode()
    response_headers = response.info()
    page = checks.page_encoding(response, action="encode")
    response_headers[settings.URI_HTTP_HEADER] = response.geturl()
    response_headers = str(response_headers).strip("\n")
    if settings.VERBOSITY_LEVEL > 2 or menu.options.traffic_file:
      print_http_response(response_headers, code, page)
    # Checks regarding a potential CAPTCHA protection mechanism.
    checks.captcha_check(page)
    # Checks regarding a potential browser verification protection mechanism.
    checks.browser_verification(page)
    # Checks regarding recognition of generic "your ip has been blocked" messages.
    checks.blocked_ip(page) 

  # This is useful when handling exotic HTTP errors (i.e requests for authentication).
  except _urllib.error.HTTPError as err:
    if settings.VERBOSITY_LEVEL > 2:
      print_http_response(err.info(), err.code, err.read())
    error_msg = "Got " + str(err).replace(": "," (")
    # Check for 3xx, 4xx, 5xx HTTP error codes.
    if str(err.code).startswith(('3', '4', '5')):
      if settings.VERBOSITY_LEVEL >= 2:
        if len(str(err).split(": ")[1]) == 0:
          error_msg = error_msg + "Non-standard HTTP status code" 
        warn_msg = error_msg
        print(settings.print_warning_msg(warn_msg + ")."))
      pass
    else:
      error_msg = str(err).replace(": "," (")
      if len(str(err).split(": ")[1]) == 0:
        err_msg = error_msg + "Non-standard HTTP status code" 
      else:
        err_msg = error_msg
      print(settings.print_critical_msg(err_msg + ")."))
      raise SystemExit()
    
  # The handlers raise this exception when they run into a problem.
  except (_http_client.HTTPException, _urllib.error.URLError, _http_client.IncompleteRead) as err:
    if any(_ in str(err) for _ in ("timed out", "IncompleteRead", "Interrupted system call")):
      pass
    else:  
      err_msg = "Unable to connect to the target URL"
      try:
        err_msg += " (" + str(err.args[0]).split("] ")[-1] + ")."
      except IndexError:
        err_msg += "."
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()

  # Raise exception regarding existing connection was forcibly closed by the remote host.
  except SocketError as err:
    if err.errno == errno.ECONNRESET:
      error_msg = "Connection reset by peer."
      print(settings.print_critical_msg(error_msg))
    elif err.errno == errno.ECONNREFUSED:
      error_msg = "Connection refused."
      print(settings.print_critical_msg(error_msg))
    raise SystemExit()
    
"""
Check for added headers.
"""
def do_check(request):

  # Check if defined any Host HTTP header.
  if menu.options.host and settings.HOST_INJECTION == None:
    request.add_header(settings.HOST, menu.options.host)

  # Check if defined any User-Agent HTTP header.
  if menu.options.agent:
    request.add_header(settings.USER_AGENT, menu.options.agent)

  # Check if defined any Referer HTTP header.
  if menu.options.referer and settings.REFERER_INJECTION == None:
    request.add_header(settings.REFERER, menu.options.referer)
   
  # Check if defined any Cookie HTTP header.
  if menu.options.cookie and settings.COOKIE_INJECTION == False:
    request.add_header(settings.COOKIE, menu.options.cookie)
  
  if not checks.get_header(request.headers, settings.HTTP_ACCEPT_HEADER):
    request.add_header(settings.HTTP_ACCEPT_HEADER, settings.HTTP_ACCEPT_HEADER_VALUE)

  # Appends a fake HTTP header 'X-Forwarded-For'
  if settings.TAMPER_SCRIPTS["xforwardedfor"]:
    from src.core.tamper import xforwardedfor
    xforwardedfor.tamper(request)
  
  # Default value for "Accept-Encoding" HTTP header
  request.add_header('Accept-Encoding', settings.HTTP_ACCEPT_ENCODING_HEADER_VALUE)

  # Check if defined any HTTP Authentication credentials.
  # HTTP Authentication: Basic / Digest Access Authentication.
  if menu.options.auth_cred and menu.options.auth_type:
    try:
      settings.SUPPORTED_HTTP_AUTH_TYPES.index(menu.options.auth_type)
      if menu.options.auth_type == "basic":
        b64_string = encodebytes(menu.options.auth_cred.encode(settings.UNICODE_ENCODING)).decode().replace('\n', '')
        request.add_header("Authorization", "Basic " + b64_string + "")
      elif menu.options.auth_type == "digest":
        try:
          url = menu.options.url
          try:
            response = _urllib.request.urlopen(url, timeout=settings.TIMEOUT)
          except _urllib.error.HTTPError as e:
            try:
              authline = e.headers.get('www-authenticate', '')  
              authobj = re.match('''(\w*)\s+realm=(.*),''',authline).groups()
              realm = authobj[1].split(',')[0].replace("\"","")
              user_pass_pair = menu.options.auth_cred.split(":")
              username = user_pass_pair[0]
              password = user_pass_pair[1]
              authhandler = _urllib.request.HTTPDigestAuthHandler()
              authhandler.add_password(realm, url, username, password)
              opener = _urllib.request.build_opener(authhandler)
              _urllib.request.install_opener(opener)
              result = _urllib.request.urlopen(url, timeout=settings.TIMEOUT)
            except AttributeError:
              pass
        except _urllib.error.HTTPError as e:
          pass
    except ValueError:
      err_msg = "Unsupported / Invalid HTTP authentication type '" + menu.options.auth_type + "'."
      err_msg += " Try basic or digest HTTP authentication type."
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()   
  else:
    pass        
  
  # The MIME media type for JSON.
  if settings.IS_JSON:
    request.add_header("Content-Type", "application/json")

  # Check if defined any extra HTTP headers.
  if menu.options.headers or menu.options.header or len(settings.RAW_HTTP_HEADERS) >= 1:
    if len(settings.RAW_HTTP_HEADERS) >= 1:
      menu.options.headers = settings.RAW_HTTP_HEADERS
    # Do replacement with the 'INJECT_HERE' tag, if the wildcard char is provided.
    if menu.options.headers:
      menu.options.headers = checks.wildcard_character(menu.options.headers)
      extra_headers = menu.options.headers 
    else:
      menu.options.header = checks.wildcard_character(menu.options.header) 
      extra_headers = menu.options.header
  
    extra_headers = extra_headers.replace(":",": ")
    if ": //" in extra_headers:
      extra_headers = extra_headers.replace(": //" ,"://")

    if "\\n" in extra_headers:
      extra_headers = extra_headers.split("\\n")
      # Remove empty strings and "Content-Length"
      extra_headers = [x for x in extra_headers if "Content-Length" not in x]
    else:
      tmp_extra_header = []
      tmp_extra_header.append(extra_headers)
      extra_headers = tmp_extra_header

    # Remove empty strings
    extra_headers = [x for x in extra_headers if x]
    
    for extra_header in extra_headers:
      try:
        # Extra HTTP Header name 
        http_header_name = extra_header.split(':', 1)[0]
        http_header_name = ''.join(http_header_name).strip()
        # Extra HTTP Header value
        http_header_value = extra_header.split(':', 1)[1]
        http_header_value = ''.join(http_header_value).strip().replace(": ",":")
        # Check if it is a custom header injection.
        if settings.CUSTOM_HEADER_INJECTION == False and \
           settings.INJECT_TAG in http_header_value:
          settings.CUSTOM_HEADER_INJECTION = True
          settings.CUSTOM_HEADER_NAME = http_header_name
        # Add HTTP Header name / value to the HTTP request
        if http_header_name not in [settings.HOST, settings.USER_AGENT, settings.REFERER, settings.COOKIE]:
          request.add_header(http_header_name, http_header_value)
      except:
        pass
        
# eof