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
Encoding non-ASCII characters (in URL path and query).
"""
def encode_non_ascii_url(request):
  url = request.get_full_url()
  parts = _urllib.parse.urlsplit(url)
  # Encode path, preserving '/', '*', and '%' to avoid over-encoding
  path = _urllib.parse.quote(parts.path, safe="*%/")
  # Encode query string, preserving delimiters and configured parameter delimiter
  query = _urllib.parse.quote(parts.query, safe="*=?/%" + settings.URL_PARAM_DELIMITER)
  # Reconstruct the full URL with encoded path and query
  request.full_url = _urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, query, parts.fragment))

  return request
  
"""
Checking the HTTP response content.
"""
def http_response_content(content):
  if type(content) is bytes:
    content = content.decode(settings.DEFAULT_CODEC)
  if settings.VERBOSITY_LEVEL >= 4:
    content = checks.remove_empty_lines(content)
    settings.print_data_to_stdout(settings.print_http_response_content(content))
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
        settings.print_data_to_stdout(settings.print_traffic(header))
      if menu.options.traffic_file:
        logs.log_traffic("\n" + header)
  if menu.options.traffic_file:
    logs.log_traffic("\n\n")

"""
Print HTTP response headers / Body.
"""
def print_http_response(response_headers, code, page):
  try:
    if int(code) in settings.ABORT_CODE:
      err_msg = "Aborting due to detected HTTP code '" + str(code) + "'. "
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()
  except (ValueError, TypeError):
    warn_msg = "Skipping abort check due to invalid (or missing) HTTP response code '" + str(code) + "'"
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

  if settings.VERBOSITY_LEVEL >= 3 or menu.options.traffic_file:
    if settings.VERBOSITY_LEVEL >= 3:
      resp_msg = "HTTP response [" + settings.print_request_num(settings.TOTAL_OF_REQUESTS) + "] (" + str(code) + "):"
      settings.print_data_to_stdout(settings.print_response_msg(resp_msg))
    if menu.options.traffic_file:
      resp_msg = "HTTP response [#" + str(settings.TOTAL_OF_REQUESTS) + "] (" + str(code) + "):"
      logs.log_traffic("\n" + resp_msg)
    http_response(response_headers, code)
  if settings.VERBOSITY_LEVEL >= 4 or menu.options.traffic_file:
    if settings.VERBOSITY_LEVEL >= 4:
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
    try:
      http_response_content(page)
    except AttributeError:
      http_response_content(page.decode(settings.DEFAULT_CODEC))

"""
Checking the HTTP Headers & HTTP/S Request.
"""
def check_http_traffic(request):
  # Delay in seconds between each HTTP request
  time.sleep(int(settings.DELAY))
  if settings.SCHEME == 'https':
    http_client = _http_client.HTTPSConnection
  else:
    http_client = _http_client.HTTPConnection

  if menu.options.http10:
    _http_client.HTTPConnection._http_vsn = 10
    _http_client.HTTPConnection._http_vsn_str = 'HTTP/1.0'

  class connection(http_client):
    def send(self, req):
      headers = req.decode()
      request_http_headers = str(headers).split("\r\n")
      unique_request_http_headers = []
      [unique_request_http_headers.append(item) for item in request_http_headers if item not in unique_request_http_headers]
      request_http_headers = [x for x in unique_request_http_headers if x]
      if settings.USER_DEFINED_POST_DATA and \
         len(request_http_headers) == 1 and \
         settings.VERBOSITY_LEVEL >= 2:
        settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
      for header in request_http_headers:
        if settings.VERBOSITY_LEVEL >= 2:
          settings.print_data_to_stdout(settings.print_traffic(header))
        if menu.options.traffic_file:
          logs.log_traffic("\n" + header)
      http_client.send(self, req)

  class connection_handler(_urllib.request.HTTPSHandler, _urllib.request.HTTPHandler, object):
    """
    Print HTTP request headers.
    """
    def print_http_response(self):
      settings.TOTAL_OF_REQUESTS = settings.TOTAL_OF_REQUESTS + 1
      if settings.VERBOSITY_LEVEL >= 2 or menu.options.traffic_file:
        if settings.VERBOSITY_LEVEL >= 2:
          req_msg = "HTTP request [" + settings.print_request_num(settings.TOTAL_OF_REQUESTS) + "]:"
          settings.print_data_to_stdout(settings.print_request_msg(req_msg))
        if menu.options.traffic_file:
          req_msg = "HTTP request [#" + str(settings.TOTAL_OF_REQUESTS) + "]:"
          logs.log_traffic(req_msg)

    def http_open(self, req):
      try:
        self.print_http_response()
        self.do_open(connection, req)
        return super(connection_handler, self).http_open(req)
      except (SocketError, _urllib.error.HTTPError, _urllib.error.URLError, _http_client.BadStatusLine, _http_client.RemoteDisconnected, _http_client.IncompleteRead, _http_client.InvalidURL, Exception) as err_msg:
        checks.connection_exceptions(err_msg)

    def https_open(self, req):
      try:
        self.print_http_response()
        self.do_open(connection, req)
        return super(connection_handler, self).https_open(req)
      except (SocketError, _urllib.error.HTTPError, _urllib.error.URLError, _http_client.BadStatusLine, _http_client.RemoteDisconnected, _http_client.IncompleteRead, _http_client.InvalidURL, Exception) as err_msg:
        checks.connection_exceptions(err_msg)

  opener = _urllib.request.build_opener(connection_handler())

  # Time limit mechanism.
  if menu.options.time_limit and (time.time() - settings.START_TIME > menu.options.time_limit):
    raise SystemExit()

  _ = False
  response = False
  unauthorized = False
  while not _ and settings.TOTAL_OF_REQUESTS <= settings.MAX_RETRIES and unauthorized is False:
    if any((settings.REVERSE_TCP, settings.BIND_TCP)):
      _ = True
    if settings.MULTI_TARGETS:
      if settings.INIT_TEST == True and len(settings.MULTI_ENCODED_PAYLOAD) != 0:
        settings.MULTI_ENCODED_PAYLOAD = []
        menu.options.tamper = settings.USER_APPLIED_TAMPER
    try:
      request = encode_non_ascii_url(request)
      response = opener.open(request, timeout=settings.TIMEOUT)
      _ = True
      settings.MAX_RETRIES = settings.TOTAL_OF_REQUESTS * 2
      if (settings.INIT_TEST == True and not settings.UNAUTHORIZED) or \
         (settings.INIT_TEST == True and settings.MULTI_TARGETS):
        if settings.VALID_URL == False:
          settings.VALID_URL = True
        if not settings.CHECK_INTERNET:
          settings.INIT_TEST = False

    except ValueError as err:
      if settings.VERBOSITY_LEVEL < 2:
        settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
      err_msg = "Invalid target URL has been given."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()

    except AttributeError:
      raise SystemExit()

    except (_urllib.error.HTTPError, _urllib.error.URLError) as err_msg:
      if settings.UNAUTHORIZED_ERROR in str(err_msg):
        settings.UNAUTHORIZED = unauthorized = True
        settings.MAX_RETRIES = settings.TOTAL_OF_REQUESTS
      else:
        settings.MAX_RETRIES = settings.TOTAL_OF_REQUESTS * 2
      if [True for err_code in settings.HTTP_ERROR_CODES if err_code in str(err_msg)]:
        break

    except (SocketError, _urllib.error.HTTPError, _urllib.error.URLError, _http_client.BadStatusLine, _http_client.RemoteDisconnected, _http_client.IncompleteRead, _http_client.InvalidURL, Exception) as err_msg:
      if not settings.MULTI_TARGETS and not settings.CRAWLING:
        pass
      else:
        if not settings.INIT_TEST:
          checks.connection_exceptions(err_msg)
        break

  try:
    if response is False:
      response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
    code = response.getcode()
    response_headers = response.info()
    page = checks.page_encoding(response, action="encode")
    response_headers[settings.URI_HTTP_HEADER] = response.geturl()
    response_headers = str(response_headers).strip("\n")
    # Handle server-set cookies.
    if not menu.options.drop_set_cookie:
      checks.handle_server_cookies(response)
    print_http_response(response_headers, code, page)
    # Checks regarding a potential CAPTCHA protection mechanism.
    checks.captcha_check(page)
    # Checks regarding a potential browser verification protection mechanism.
    checks.browser_verification(page)
    # Checks regarding recognition of generic "your ip has been blocked" messages.
    checks.blocked_ip(page)

  # This is useful when handling exotic HTTP errors (i.e requests for authentication).
  except _urllib.error.HTTPError as err:
    if not menu.options.drop_set_cookie:
      checks.handle_server_cookies(err)
    try:
      if getattr(err, 'fp', None) is None:
        raise AttributeError
      page = checks.page_encoding(err, action="encode")
    except Exception:
      page = ''
    response_headers = err.info()
    code = err.code
    print_http_response(response_headers, code, page)

    if (not settings.PERFORM_CRACKING and \
    not settings.IS_JSON and \
    not settings.IS_XML and \
    not str(err.code) == settings.INTERNAL_SERVER_ERROR and \
    not str(err.code) == settings.BAD_REQUEST and \
    not settings.CRAWLED_URLS_NUM != 0 and \
    not settings.MULTI_TARGETS) and settings.CRAWLED_SKIPPED_URLS_NUM != 0:
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
    # Check for 3xx, 4xx, 5xx HTTP error codes.
    if str(err.code).startswith(('3', '4', '5')):
      settings.HTTP_ERROR_CODES_SUM.append(err.code)
      if settings.VERBOSITY_LEVEL >= 2:
        parts = str(err).split(": ")
        if len(parts) > 1 and len(parts[1]) == 0:
          error_msg = "Non-standard HTTP status code"
      pass
    else:
      error_msg = str(err).replace(": ", " (")
      parts = str(err).split(": ")
      if len(parts) > 1 and len(parts[1]) == 0:
        err_msg = error_msg + "Non-standard HTTP status code"
      else:
        err_msg = error_msg

      settings.print_data_to_stdout(settings.print_critical_msg(err_msg + ")."))
      raise SystemExit()

  except _urllib.error.URLError as err:
    if not menu.options.drop_set_cookie:
      checks.handle_server_cookies(err)
    reason = str(getattr(err, 'reason', 'Unknown error'))
    reason_parts = reason.split(settings.SINGLE_WHITESPACE)
    if len(reason_parts) > 2:
      response_headers = settings.SINGLE_WHITESPACE.join(reason_parts[2:]) + "."
    else:
      response_headers = reason
    if not response_headers.endswith("."):
      response_headers += "."
    code = ""
    page = ""
    print_http_response(response_headers, code, page)
    settings.print_data_to_stdout(settings.print_critical_msg("URL Error: " + reason))
    raise SystemExit()

"""
Check for added headers.
"""
def do_check(request):

  # Check if defined any Cookie HTTP header.
  if menu.options.cookie and not settings.COOKIE_INJECTION:
    request.add_header(settings.COOKIE, checks.remove_tags(menu.options.cookie))

  # Check if defined any User-Agent HTTP header.
  if menu.options.agent and not settings.USER_AGENT_INJECTION:
    request.add_header(settings.USER_AGENT, checks.remove_tags(menu.options.agent))

  # Check if defined any Referer HTTP header.
  if menu.options.referer and not settings.REFERER_INJECTION:
    request.add_header(settings.REFERER, checks.remove_tags(menu.options.referer))

  # Check if defined any Host HTTP header.
  if menu.options.host and not settings.HOST_INJECTION:
    request.add_header(settings.HOST, checks.remove_tags(menu.options.host))

  if not checks.get_header(request.headers, settings.ACCEPT):
    request.add_header(settings.ACCEPT, settings.ACCEPT_VALUE)

  if not checks.get_header(request.headers, settings.CONTENT_TYPE):
    request.add_unredirected_header(settings.CONTENT_TYPE, settings.DEFAULT_HTTP_CONTENT_TYPE_VALUE)

  # The MIME media type for JSON.
  if menu.options.data and not (menu.options.requestfile or menu.options.logfile):
    if re.search(settings.JSON_RECOGNITION_REGEX, menu.options.data) or \
       re.search(settings.JSON_LIKE_RECOGNITION_REGEX, menu.options.data):
      request.add_unredirected_header(settings.CONTENT_TYPE, settings.HTTP_CONTENT_TYPE_JSON_HEADER_VALUE)
    elif re.search(settings.XML_RECOGNITION_REGEX, menu.options.data):
      request.add_unredirected_header(settings.CONTENT_TYPE, settings.HTTP_CONTENT_TYPE_XML_HEADER_VALUE)

  # Default value for "Accept-Encoding" HTTP header
  if not (menu.options.requestfile or menu.options.logfile):
    request.add_header(settings.ACCEPT_ENCODING, settings.HTTP_ACCEPT_ENCODING_HEADER_VALUE)

  # Appends a fake HTTP header 'X-Forwarded-For' (and alike)
  if settings.TAMPER_SCRIPTS["xforwardedfor"]:
    from src.core.tamper import xforwardedfor
    xforwardedfor.tamper(request)

  # Check if defined any HTTP Authentication credentials.
  # HTTP Authentication: Basic, Digest, Bearer Access Authentication.
  if menu.options.auth_cred and menu.options.auth_type:
    if menu.options.auth_type.lower() not in (settings.AUTH_TYPE.BASIC, settings.AUTH_TYPE.DIGEST, settings.AUTH_TYPE.BEARER):
      err_msg = "HTTP authentication type value must be Basic, Digest or Bearer."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()
    if menu.options.auth_type.lower() == settings.AUTH_TYPE.BEARER:
      request.add_header(settings.AUTHORIZATION, "Bearer " + menu.options.auth_cred.strip())
    elif menu.options.auth_type.lower() == settings.AUTH_TYPE.BASIC:
      b64_string = encodebytes(menu.options.auth_cred.encode(settings.DEFAULT_CODEC)).decode().replace('\n', '')
      request.add_header(settings.AUTHORIZATION, "Basic " + b64_string)
    elif menu.options.auth_type.lower() == settings.AUTH_TYPE.DIGEST:
      try:
        url = menu.options.url
        try:
          response = _urllib.request.urlopen(url, timeout=settings.TIMEOUT)
        except (_urllib.error.HTTPError, _urllib.error.URLError) as e:
          try:
            authline = e.headers.get('www-authenticate', '')
            authobj = re.match(r'''(\w*)\s+realm=(.*),''',authline).groups()
            realm = authobj[1].split(',')[0].replace("\"", "")
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
      except (_urllib.error.HTTPError, _urllib.error.URLError) as e:
        pass

  else:
    pass

  # Check if defined any extra HTTP headers.
  if settings.EXTRA_HTTP_HEADERS or settings.RAW_HTTP_HEADERS:
    if settings.RAW_HTTP_HEADERS:
      menu.options.headers = settings.RAW_HTTP_HEADERS
    # Do replacement with the 'INJECT_HERE' tag, if the custom injection marker character is provided.
    if menu.options.headers:
      extra_headers = checks.process_custom_injection_data(menu.options.headers)
    elif menu.options.header:
      extra_headers = checks.process_custom_injection_data(menu.options.header)

    extra_headers = extra_headers.replace(":",": ")
    if ": //" in extra_headers:
      extra_headers = extra_headers.replace(": //" ,"://")

    if "\\n" in extra_headers:
      extra_headers = extra_headers.split("\\n")
      # Remove empty strings and "Content-Length"
      extra_headers = [x for x in extra_headers if settings.CONTENT_LENGTH not in x]
    else:
      tmp_extra_header = []
      tmp_extra_header.append(extra_headers)
      extra_headers = tmp_extra_header

    # Remove empty strings and/or duplicates
    _ = [x for x in extra_headers if x]
    extra_headers = (list(dict.fromkeys(_)))

    if menu.options.data:
      # The MIME media type for JSON.
      if re.search(settings.JSON_RECOGNITION_REGEX, menu.options.data) or \
         re.search(settings.JSON_LIKE_RECOGNITION_REGEX, menu.options.data):
         if settings.CONTENT_TYPE not in str(extra_headers):
          request.add_header(settings.CONTENT_TYPE, settings.HTTP_CONTENT_TYPE_JSON_HEADER_VALUE)
      elif re.search(settings.XML_RECOGNITION_REGEX, menu.options.data):
         if settings.CONTENT_TYPE not in str(extra_headers):
          request.add_header(settings.CONTENT_TYPE, settings.HTTP_CONTENT_TYPE_XML_HEADER_VALUE)
    if settings.ACCEPT_ENCODING not in str(extra_headers):
      request.add_header(settings.ACCEPT_ENCODING, settings.HTTP_ACCEPT_ENCODING_HEADER_VALUE)

    for extra_header in extra_headers:
      try:
        # Extra HTTP Header name
        http_header_name = extra_header.split(':', 1)[0]
        http_header_name = ''.join(http_header_name).strip()
        # Extra HTTP Header value
        http_header_value = extra_header.split(':', 1)[1]
        http_header_value = ''.join(http_header_value).strip().replace(": ",":")
        # Check if it is a custom header injection.
        if http_header_name not in [settings.ACCEPT, settings.HOST, settings.USER_AGENT, settings.REFERER, settings.COOKIE]:
          if not settings.CUSTOM_HEADER_INJECTION:
            if settings.CUSTOM_INJECTION_MARKER_CHAR in http_header_value:
              settings.CUSTOM_INJECTION_MARKER = True
              settings.CUSTOM_HEADER_CHECK = http_header_name
              
            if settings.CUSTOM_INJECTION_MARKER_CHAR in http_header_value or \
               http_header_name in settings.TESTABLE_PARAMETERS_LIST or \
               settings.INJECT_TAG in http_header_value or \
               settings.ASTERISK_MARKER in http_header_value:

              settings.INJECTION_MARKER_LOCATION.CUSTOM_HTTP_HEADERS = True
              settings.CUSTOM_HEADER_CHECK = http_header_name
              if len(http_header_name) != 0 and \
                http_header_name + ": " + http_header_value not in [settings.ACCEPT, settings.HOST, settings.USER_AGENT, settings.REFERER, settings.COOKIE] and \
                http_header_name + ": " + http_header_value not in settings.CUSTOM_HEADERS_NAMES:
                settings.CUSTOM_INJECTION_MARKER_PARAMETERS_LIST.append(http_header_name) if http_header_name not in settings.CUSTOM_INJECTION_MARKER_PARAMETERS_LIST else settings.CUSTOM_INJECTION_MARKER_PARAMETERS_LIST
                settings.CUSTOM_HEADERS_NAMES.append(http_header_name + ": " + http_header_value)
              http_header_value = checks.remove_tags(http_header_value)
              request.add_header(http_header_name, http_header_value)
              
        # Normalize for comparison
        excluded_headers = [
          settings.HOST,
          settings.USER_AGENT,
          settings.REFERER,
          settings.COOKIE,
          settings.CUSTOM_HEADER_NAME
        ]
        excluded_headers = [h.lower() for h in excluded_headers if h]
        
        # Check and apply Title-Case for final header name
        if http_header_name.lower() not in excluded_headers:
          normalized_name = '-'.join([part.capitalize() for part in http_header_name.split('-')])
          request.add_header(normalized_name, http_header_value)

      except:
        pass

# eof