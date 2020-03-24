#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2020 Anastasios Stasinopoulos (@ancst).

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
import gzip
import time
import errno
import base64
import socket
from socket import error as SocketError
from src.thirdparty.six.moves import http_client as _http_client
from src.utils import logs
from src.utils import menu
from src.utils import settings
#from StringIO import StringIO
import io
from src.core.injections.controller import checks
from src.thirdparty.colorama import Fore, Back, Style, init
from src.thirdparty.six.moves import urllib as _urllib

"""
Checking the HTTP response content.
"""
def http_response_content(content):
  if menu.options.traffic_file: 
    logs.log_traffic("-" * 42 + "\n" + info_msg + "\n" + "-" * 42)  
  if settings.VERBOSITY_LEVEL >= 4:
    content = checks.remove_empty_lines(content)
    print(settings.print_http_response_content(content))
  if menu.options.traffic_file:
    logs.log_traffic("\n" + content)
  if menu.options.traffic_file:
    logs.log_traffic("\n\n" + "#" * 77 + "\n\n")

"""
Checking the HTTP response headers.
"""
def http_response(headers, code):
  if menu.options.traffic_file: 
    logs.log_traffic("-" * 37 + "\n" + info_msg + "\n" + "-" * 37)  
  response_http_headers = str(headers).split("\n")
  for header in response_http_headers:
    if len(header) > 1: 
      if settings.VERBOSITY_LEVEL >= 3:
        print(settings.print_traffic(header))
      if menu.options.traffic_file:
        logs.log_traffic("\n" + header)
  if menu.options.traffic_file:
    if settings.VERBOSITY_LEVEL <= 3: 
      logs.log_traffic("\n\n" + "#" * 77 + "\n\n")
    else:
      logs.log_traffic("\n\n")    

"""
Checking the HTTP Headers & HTTP/S Request.
"""
def check_http_traffic(request):
  settings.TOTAL_OF_REQUESTS = settings.TOTAL_OF_REQUESTS + 1
  # Delay in seconds between each HTTP request
  time.sleep(int(settings.DELAY))
  
  class do_connection(_http_client.HTTPConnection):
    def send(self, req):
      headers = req.decode()
      if menu.options.traffic_file: 
        logs.log_traffic("-" * 37 + "\n" + info_msg + "\n" + "-" * 37)  
      request_http_headers = str(headers).split("\r\n")
      for header in request_http_headers:
        if len(header) > 1: 
          if settings.VERBOSITY_LEVEL >= 2:
            print(settings.print_traffic(header))
          if menu.options.traffic_file:
            logs.log_traffic("\n" + header)
      if menu.options.traffic_file:
        if settings.VERBOSITY_LEVEL <= 2: 
          logs.log_traffic("\n\n" + "#" * 77 + "\n\n")
        else:
          logs.log_traffic("\n\n") 
      _http_client.HTTPConnection.send(self, req)

  class connection_handler(_urllib.request.HTTPHandler, _urllib.request.HTTPSHandler):
    if settings.SCHEME == 'https':
      def https_open(self, req):
        try:
          return self.do_open(do_connection, req)
        except Exception as err_msg:
          try:
            error_msg = str(err_msg.args[0]).split("] ")[1] + "."
          except IndexError:
            error_msg = str(err_msg.args[0]) + "."
          if settings.INIT_TEST == True:
            if settings.VERBOSITY_LEVEL < 2:
              print("[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]")
          else:
            if settings.VERBOSITY_LEVEL < 1:
              print("")   
          print(settings.print_critical_msg(error_msg))
          raise SystemExit()
    else:      
      def http_open(self, req):
        try:
          return self.do_open(do_connection, req)
        except Exception as err_msg:
          try:
            error_msg = str(err_msg.args[0]).split("] ")[1] + "."
          except IndexError:
            error_msg = str(err_msg.args[0]) + "."
          if settings.INIT_TEST == True:
            if settings.VERBOSITY_LEVEL < 2:
              print("[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]")
          else:
            if settings.VERBOSITY_LEVEL < 1:
              print("")  
          print(settings.print_critical_msg(error_msg))
          raise SystemExit()

  if settings.REVERSE_TCP == False and settings.BIND_TCP == False:
    opener = _urllib.request.build_opener(connection_handler())
    response = False
    current_attempt = 0
    while not response and current_attempt <= settings.MAX_RETRIES and not settings.UNAUTHORIZED:
      try:
        if settings.VERBOSITY_LEVEL >= 2:
          info_msg = "The target's request HTTP headers:"
          print(settings.print_info_msg(info_msg))
        opener.open(request)
        response = True
        if settings.VERBOSITY_LEVEL < 2:
          if current_attempt != 0:
            info_msg = "Checking connection to the target URL... "
            sys.stdout.write(settings.print_info_msg(info_msg))
            sys.stdout.flush()
          if settings.INIT_TEST == True:
            print("[ " + Fore.GREEN + "SUCCEED" + Style.RESET_ALL + " ]")
            if not settings.CHECK_INTERNET:
              settings.INIT_TEST = False

      except _urllib.error.HTTPError as err_msg:
        if "Unauthorized" in str(err_msg):
          if settings.VERBOSITY_LEVEL < 2 and not settings.UNAUTHORIZED:
            print("[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]")
          settings.UNAUTHORIZED = True

      except _urllib.error.URLError as err_msg: 
        if current_attempt == 0:
          if settings.VERBOSITY_LEVEL < 2:
            print("[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]")
          try:
            error_msg = str(err_msg.args[0]).split("] ")[1] + ". "
          except IndexError:
            error_msg = ""
          error_msg += "Please wait while retring the request(s)."
          print(settings.print_critical_msg(error_msg))
          warn_msg = "In case the provided target URL is valid, try to rerun with"
          warn_msg += " the switch '--random-agent' and/or proxy switch."
          print(settings.print_warning_msg(warn_msg))
        if settings.VERBOSITY_LEVEL >= 2 or current_attempt == 1:
          info_msg = "Please wait while retring the request(s)."
          print(settings.print_info_msg(info_msg))
        current_attempt = current_attempt + 1
        time.sleep(3)
        
      except _http_client.BadStatusLine as err_msg:
        if settings.VERBOSITY_LEVEL < 2:
          print("[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]")
        if len(err_msg.line) > 2 :
          print(err_msg.line, err_msg.message)
        raise SystemExit()

      except ValueError as err:
        if settings.VERBOSITY_LEVEL < 2:
          print("[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]")
        err_msg = "Invalid target URL has been given." 
        print(settings.print_critical_msg(err_msg))
        raise SystemExit()

      except AttributeError:
        raise SystemExit() 
      
  try:
    response = _urllib.request.urlopen(request)
    code = response.getcode()
    # Check the HTTP response headers.
    response_headers = response.info()
    page = response.read()
    try:
      # Fix for Python 2.7
      page = page.encode(settings.DEFAULT_ENCODING)
    except AttributeError:
      pass
    if response_headers.get('Content-Encoding') == 'gzip':
      page = gzip.GzipFile("", "rb", 9, io.BytesIO(page)).read()
      request.add_header('Accept-Encoding', 'deflate')
    if len(settings.ENCODING) != 0:
      page = page.decode(settings.ENCODING)
    else:
      if type(page) != str:
        page = page.decode(settings.DEFAULT_ENCODING)
    response_headers[settings.URI_HTTP_HEADER] = response.geturl()
    response_headers = str(response_headers).strip("\n")
    if settings.VERBOSITY_LEVEL >= 3:
      info_msg = "The target's response HTTP headers (" + str(code) + "):"
      print(settings.print_info_msg(info_msg))
      http_response(response_headers, code)
    if settings.VERBOSITY_LEVEL >= 4:
      info_msg = "The target's HTTP response page content:"
      print(settings.print_info_msg(info_msg))
      http_response_content(page)
    # Checks regarding a potential CAPTCHA protection mechanism.
    checks.captcha_check(page)
    # Checks regarding a potential browser verification protection mechanism.
    checks.browser_verification(page)
    # Checks regarding recognition of generic "your ip has been blocked" messages.
    checks.blocked_ip(page) 

  # This is useful when handling exotic HTTP errors (i.e requests for authentication).
  except _urllib.error.HTTPError as err:
    error_msg = "Got " + str(err).replace(": "," (")
    # Check for 4xx and/or 5xx HTTP error codes.
    if str(err.code).startswith('4') or \
       str(err.code).startswith('5'):
      if settings.VERBOSITY_LEVEL > 1:
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
  except (socket.error, _http_client.HTTPException, _urllib.error.URLError) as err:
    err_msg = "Unable to connect to the target URL"
    try:
      err_msg += " (" + str(err.args[0]).split("] ")[1] + ")."
    except IndexError:
      err_msg += "."
    print(settings.print_critical_msg(err_msg))
    raise SystemExit()

  except _http_client.IncompleteRead as err_msg:
    print(settings.print_critical_msg(str(err_msg)))
    raise SystemExit()

  except UnicodeDecodeError as err_msg:
    print(settings.print_critical_msg(str(err_msg)))
    raise SystemExit()

  except LookupError as err_msg:
    print(settings.print_critical_msg(str(err_msg)))
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

  # Check if defined any HTTP Authentication credentials.
  # HTTP Authentication: Basic / Digest Access Authentication.
  if menu.options.auth_cred and menu.options.auth_type:
    try:
      settings.SUPPORTED_HTTP_AUTH_TYPES.index(menu.options.auth_type)
      if menu.options.auth_type == "basic":
        b64_string = base64.encodestring(menu.options.auth_cred.encode(settings.UNICODE_ENCODING)).decode().replace('\n', '')
        request.add_header("Authorization", "Basic " + b64_string + "")
      elif menu.options.auth_type == "digest":
        try:
          url = menu.options.url
          try:
            response = _urllib.request.urlopen(url)
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
              result = _urllib.request.urlopen(url)
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
        request.add_header(http_header_name, http_header_value)
      except:
        pass
        
# eof