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
import time
import random
import string
try:
  from base64 import encodebytes
except ImportError:
  from base64 import encodestring as encodebytes
from socket import error as SocketError
from src.thirdparty.six.moves import http_client as _http_client
from src.utils import logs
from src.core.parse import cmdline as menu
from src.utils import settings
from src.core.controller import checks
from src.core.requests import proxy
from src.core.requests import cookies
from src.core.requests import chunked
from src.core.requests import anticsrf
from src.core.requests import redirection
from src.core.requests import keepalive
from src.core.requests import stability
from src.thirdparty.six.moves import urllib as _urllib

"""
The query string, encoded - and shortened by giving characters back where it runs long.

Only while it is over the limit, and only characters that are legal in a query unencoded, so what
the target reads is unchanged and a query of ordinary length is encoded exactly as it would be.
"""
def encoded_query(query):
  safe = settings.query_safe_chars() + settings.URL_PARAM_DELIMITER
  given_back = 0
  while True:
    encoded = _urllib.parse.quote(query, safe=safe)
    if len(encoded) <= settings.URLENCODE_CHAR_LIMIT or given_back >= len(settings.URLENCODE_FAILSAFE_CHARS):
      return encoded
    # One at a time, and only ones the query actually contains - handing back a character it does
    # not have shortens nothing and widens the set for no reason.
    while given_back < len(settings.URLENCODE_FAILSAFE_CHARS):
      safe += settings.URLENCODE_FAILSAFE_CHARS[given_back]
      given_back += 1
      if safe[-1] in query:
        break

"""
Encoding non-ASCII characters (in URL path and query).
"""
def encode_non_ascii_url(request):
  url = request.get_full_url()
  parts = _urllib.parse.urlsplit(url)
  path = _urllib.parse.quote(parts.path, safe=settings.SAFE_PATH)
  # Encode query string, preserving delimiters and the parameter delimiter
  query = encoded_query(parts.query)
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
    logs.log_traffic(settings.END_LINE.LF * 2 + "#" * 77 + settings.END_LINE.LF * 2)

"""
Checking the HTTP response headers.
"""
def http_response(headers, code):
  response_http_headers = str(headers).split(settings.END_LINE.LF)
  for header in response_http_headers:
    if len(header) > 1:
      if settings.VERBOSITY_LEVEL >= 3:
        settings.print_data_to_stdout(settings.print_traffic(header))
      if menu.options.traffic_file:
        logs.log_traffic(settings.END_LINE.LF + header)
  if menu.options.traffic_file:
    logs.log_traffic(settings.END_LINE.LF * 2)

"""
Print HTTP response headers / Body.
"""
def print_http_response(response_headers, code, page):
  try:
    if int(code) in settings.ABORT_CODE:
      err_msg = "Aborting due to detected HTTP code '" + str(code) + "'. "
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit(settings.EXIT_FAILURE)
  except (ValueError, TypeError):
    warn_msg = "Skipping abort check due to invalid (or missing) HTTP response code '" + str(code) + "'"
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

  if settings.VERBOSITY_LEVEL >= 3 or menu.options.traffic_file:
    if settings.VERBOSITY_LEVEL >= 3:
      # Blank line separating this response block from the request block printed before it.
      settings.print_data_to_stdout("")
      resp_msg = "HTTP response [" + settings.print_request_num(settings.TOTAL_OF_REQUESTS) + "] (" + str(code) + "):"
      settings.print_data_to_stdout(settings.print_response_msg(resp_msg))
    if menu.options.traffic_file:
      resp_msg = "HTTP response [#" + str(settings.TOTAL_OF_REQUESTS) + "] (" + str(code) + "):"
      logs.log_traffic(settings.END_LINE.LF + resp_msg)
    http_response(response_headers, code)
  if settings.VERBOSITY_LEVEL >= 4 or menu.options.traffic_file:
    if settings.VERBOSITY_LEVEL >= 4:
      # Blank line separating response headers from the response body below.
      settings.print_data_to_stdout("")
    try:
      http_response_content(page)
    except AttributeError:
      http_response_content(page.decode(settings.DEFAULT_CODEC))

  if settings.VERBOSITY_LEVEL >= 3:
    # Blank line closing out this traffic block before whatever's printed next.
    settings.print_data_to_stdout("")

"""
Probe once to read the realm off the target's own WWW-Authenticate challenge.
"""
def discover_digest_realm(url):
  try:
    _urllib.request.urlopen(url, timeout=settings.TIMEOUT)
  except _urllib.error.HTTPError as e:
    authline = e.headers.get('www-authenticate', '')
    match = re.match(r'''(\w*)\s+realm=(.*)''', authline)
    if match:
      return match.group(2).split(',')[0].strip().strip('"')
  except Exception:
    pass
  return ""

"""
A fresh value for a parameter named with '--randomize', shaped like the one it replaces - digits
stay digits and letters keep their case, so a target that validates the format still accepts it.
"""
def random_pool():
  """
  The values the target's own '<select>' menus offer, read once from the page the run started on.

  A parameter that is a menu has an answer the target already accepts: inventing one of the right
  shape would be refused by anything that validates the choice.
  """
  if not settings.RANDOM_POOL_READ:
    settings.RANDOM_POOL_READ = True
    for match in re.finditer(r"(?si)<select[^>]+\bname\s*=\s*[\"']?([^\"'\s>]+)[\"']?(.+?)</select>", settings.ORIGINAL_PAGE or ""):
      name, body = match.groups()
      options = tuple(re.findall(r"(?i)<option[^>]+\bvalue\s*=\s*[\"']?([^\"'\s>]*)", body))
      if options:
        settings.RANDOM_POOL[name] = options
    if settings.RANDOM_POOL and settings.VERBOSITY_LEVEL >= 2:
      debug_msg = "Read the values offered for " + ", ".join("'" + _ + "'" for _ in sorted(settings.RANDOM_POOL)) + " from the target's own page."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
  return settings.RANDOM_POOL

def randomized_value(value, name=None):
  # A menu is answered with one of its own options, rather than with a value of the same shape.
  pool = random_pool().get(name) if name else None
  if pool:
    candidates = [_ for _ in pool if _ != value] or list(pool)
    return random.choice(candidates)

  def _swap(match):
    original = match.group()
    if original.isdigit():
      pool = string.digits
    elif original.isupper():
      pool = string.ascii_uppercase
    else:
      pool = string.ascii_lowercase
    while True:
      candidate = "".join(random.choice(pool) for _ in original)
      if candidate != original:
        return candidate
  return re.sub(r"[0-9]+|[A-Z]+|[a-z]+", _swap, value)

"""
Give every parameter named with '--randomize' a new value, wherever it travels - the query string
of the URL and the body alike.
"""
def randomize_parameters(request):
  if not settings.RANDOMIZE_PARAMETERS_LIST:
    return request

  def _rewrite(text):
    def _pair(match):
      name, value = match.group("name").strip(), match.group("value")
      if name not in settings.RANDOMIZE_PARAMETERS_LIST:
        return match.group()
      return match.group().replace(name + "=" + value, name + "=" + randomized_value(value, name), 1)
    # Both delimiters, so a cookie's pairs are read the way a query string's are.
    return re.sub(r"(?P<name>[^=&;?]+)=(?P<value>[^&;]*)", _pair, text)

  parts = request.full_url.split("?", 1)
  # A parameter written into the path is bounded by its own slashes, not by the '&' a query uses.
  path = "/".join(_rewrite(segment) for segment in parts[0].split("/"))
  request.full_url = path + ("?" + _rewrite(parts[1]) if len(parts) == 2 and parts[1] else "")
  if request.data:
    body = request.data.decode(settings.DEFAULT_CODEC, errors="replace")
    request.data = _rewrite(body).encode(settings.DEFAULT_CODEC)
  # The cookie is added further down from the option it was given in, so it is randomized there.
  if menu.options.cookie:
    menu.options.cookie = _rewrite(menu.options.cookie)
  return request

"""
Count one request, and do what the options ask for every so many of them: change the proxy the run
goes out through, and visit the URL that keeps the session alive.

The safe request is sent through the same path as any other, so it is counted out here rather than
inside it - a request made to keep the session alive is not one of the requests being paced.
"""
def count_request():
  with settings.REQUESTS_LOCK:
    settings.REQUEST_COUNTER += 1
    counter = settings.REQUEST_COUNTER
    if settings.SENDING_SAFE_REQUEST:
      return

  if menu.options.proxy_freq and counter % menu.options.proxy_freq == 0:
    proxy.rotate_proxy()

  if menu.options.safe_freq and counter % menu.options.safe_freq == 0:
    send_safe_request()

"""
Visit the URL that has nothing to do with the test, at the frequency asked for.

What it is for is the session: a target that logs out, locks an account or expires a token after so
many odd-looking requests sees an ordinary one in between them.
"""
def send_safe_request():
  if settings.SENDING_SAFE_REQUEST:
    return
  settings.SENDING_SAFE_REQUEST = True
  try:
    if settings.SAFE_REQUEST:
      safe = settings.SAFE_REQUEST
      data = safe["data"].encode(settings.DEFAULT_CODEC) if safe["data"] else None
      request = _urllib.request.Request(safe["url"], data, method=safe["method"] or settings.HTTPMETHOD.GET)
      for header_name, header_value in safe["headers"]:
        request.add_header(header_name, header_value)
    else:
      data = menu.options.safe_post.encode(settings.DEFAULT_CODEC) if menu.options.safe_post else None
      method = settings.HTTPMETHOD.POST if menu.options.safe_post else settings.HTTPMETHOD.GET
      request = _urllib.request.Request(menu.options.safe_url, data, method=method)
      do_check(request)
    if settings.VERBOSITY_LEVEL >= 2:
      debug_msg = "Visiting the safe URL '" + request.get_full_url() + "'."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
    response = check_http_traffic(request)
    if response is None:
      response = resend(request)
    if response is not None and not isinstance(response, bool):
      try:
        response.close()
      except Exception:
        pass
  except Exception:
    # A safe visit that fails is not the run's business: nothing is read from it, and the request
    # it was sent between is the one that matters.
    pass
  finally:
    settings.SENDING_SAFE_REQUEST = False

"""
What holds for a request whatever it was sent for: the pacing that was asked for, the count it is
part of, and the proxy rotation and safe visit that go by that count.
"""
def apply_request_policy():
  settings.LAST_HTTP_ERROR = None
  count_request()
  # Delay in seconds between each HTTP request, plus whatever backing off the target has earned -
  # and, where '--jitter' was given, a different fraction of a second on top of every one of them.
  time.sleep(int(settings.DELAY) + settings.ADAPTIVE_DELAY + (random.uniform(0, menu.options.jitter) if menu.options.jitter else 0))

"""
Send a request the caller reads or times itself, rather than through the opener the rest of the run
goes out over - and have it paced and counted like any other request all the same.

A caller that measures the answer applies the policy first and starts its clock afterwards, so that
what it times is the target rather than the delay this run was told to keep.
"""
def send_raw(request, timeout=None, policy=True):
  if policy:
    apply_request_policy()
  with settings.REQUESTS_LOCK:
    settings.TOTAL_OF_REQUESTS = settings.TOTAL_OF_REQUESTS + 1
  return _urllib.request.urlopen(request, timeout=timeout or settings.TIMEOUT)

"""
Checking the HTTP Headers & HTTP/S Request.
"""
def check_http_traffic(request):
  apply_request_policy()
  if request.type == 'https':
    http_client = _http_client.HTTPSConnection
  else:
    http_client = _http_client.HTTPConnection

  if menu.options.http10:
    _http_client.HTTPConnection._http_vsn = 10
    _http_client.HTTPConnection._http_vsn_str = 'HTTP/1.0'

  class connection(http_client):
    # Build the request, letting chunked bodies be framed by hand rather than by the client.
    def request(self, method, url, body=None, headers={}, **kwargs):
      # The body is framed as chunks already, so the client must not frame it a second time.
      if menu.options.chunked:
        kwargs["encode_chunked"] = False
      return http_client.request(self, method, url, body, headers, **kwargs)

    # Write the request out, printing it first where the traffic is being shown.
    def send(self, req):
      # Decode request output safely, replacing non-UTF8 bytes instead of crashing.
      headers = req.decode(settings.DEFAULT_CODEC, errors="replace")
      # Headers end with a blank line, so the next send() starts the body.

      ends_with_blank_line = headers.endswith(settings.END_LINE.CRLF + settings.END_LINE.CRLF)
      request_http_headers = str(headers).split(settings.END_LINE.CRLF)
      unique_request_http_headers = []
      [unique_request_http_headers.append(item) for item in request_http_headers if item not in unique_request_http_headers]
      request_http_headers = [x for x in unique_request_http_headers if x]
      for header in request_http_headers:
        if settings.VERBOSITY_LEVEL >= 2:
          settings.print_data_to_stdout(settings.print_traffic(header))
        if menu.options.traffic_file:
          logs.log_traffic(settings.END_LINE.LF + header)
      if ends_with_blank_line and settings.USER_DEFINED_POST_DATA and settings.VERBOSITY_LEVEL >= 2:
        settings.print_data_to_stdout("")
      elif not ends_with_blank_line and settings.USER_DEFINED_POST_DATA and settings.VERBOSITY_LEVEL == 2:
        settings.print_data_to_stdout("")
      http_client.send(self, req)

  class connection_handler(_urllib.request.HTTPSHandler, _urllib.request.HTTPHandler, object):
    """
    Print HTTP request headers.
    """
    def print_http_response(self):
      with settings.REQUESTS_LOCK:
        settings.TOTAL_OF_REQUESTS = settings.TOTAL_OF_REQUESTS + 1
        stability.note_request_sent()
      if settings.VERBOSITY_LEVEL >= 2 or menu.options.traffic_file:
        if settings.VERBOSITY_LEVEL >= 2:
          req_msg = "HTTP request [" + settings.print_request_num(settings.TOTAL_OF_REQUESTS) + "]:"
          settings.print_data_to_stdout(settings.print_request_msg(req_msg))
        if menu.options.traffic_file:
          req_msg = "HTTP request [#" + str(settings.TOTAL_OF_REQUESTS) + "]:"
          logs.log_traffic(req_msg)

    """
    Reuse a pooled connection, when enabled.
    """
    def do_open(self, http_class, req, **http_conn_args):
      if settings.KEEP_ALIVE:
        return keepalive.do_open(self, http_class, req, **http_conn_args)
      return super(connection_handler, self).do_open(http_class, req, **http_conn_args)

    # Open the connection, and show the response where the traffic is being shown.
    def http_open(self, req):
      try:
        self.print_http_response()
        return self.do_open(connection, req)
      except (SocketError, _urllib.error.HTTPError, _urllib.error.URLError, _http_client.BadStatusLine, _http_client.RemoteDisconnected, _http_client.IncompleteRead, _http_client.InvalidURL, Exception) as err_msg:
        checks.connection_exceptions(err_msg)

    # Open the TLS connection, and show the response where the traffic is being shown.
    def https_open(self, req):
      try:
        self.print_http_response()
        return self.do_open(connection, req, context=self._context)
      except (SocketError, _urllib.error.HTTPError, _urllib.error.URLError, _http_client.BadStatusLine, _http_client.RemoteDisconnected, _http_client.IncompleteRead, _http_client.InvalidURL, Exception) as err_msg:
        checks.connection_exceptions(err_msg)

  # Digest needs a handler on the sending opener, unlike Basic/Bearer's static header.
  extra_handlers = []
  if menu.options.auth_cred and menu.options.auth_type and menu.options.auth_type.lower() == settings.AUTH_TYPE.DIGEST:
    if settings.DIGEST_AUTH_REALM is None:
      settings.DIGEST_AUTH_REALM = discover_digest_realm(menu.options.url)
    digest_handler = _urllib.request.HTTPDigestAuthHandler()
    username, _, password = menu.options.auth_cred.partition(":")
    digest_handler.add_password(settings.DIGEST_AUTH_REALM, menu.options.url, username, password)
    extra_handlers.append(digest_handler)

  request = encode_non_ascii_url(request)

  # Also route through the configured proxy/Tor, so this fetch is reusable.
  if menu.options.ignore_proxy:
    opener = _urllib.request.build_opener(_urllib.request.ProxyHandler({}), connection_handler(context=settings.unverified_context()), redirection.RedirectHandler(), *extra_handlers)
  elif menu.options.tor and menu.options.tor_type == settings.PROXY_TYPE.HTTP:
    opener = _urllib.request.build_opener(_urllib.request.ProxyHandler({settings.SCHEME: menu.options.proxy}), connection_handler(context=settings.unverified_context()), redirection.RedirectHandler(), *extra_handlers)
  else:
    proxy.apply_to_request(request)
    opener = _urllib.request.build_opener(connection_handler(context=settings.unverified_context()), redirection.RedirectHandler(), *extra_handlers)

  # Time limit mechanism.
  if menu.options.time_limit and (time.time() - settings.START_TIME > menu.options.time_limit):
    raise SystemExit()

  succeeded = False
  response = False
  unauthorized = False
  pending_error = None
  while stability.should_keep_retrying(succeeded, unauthorized):
    if any((settings.REVERSE_TCP, settings.BIND_TCP)):
      succeeded = True
    if settings.MULTI_TARGETS or settings.CRAWLING:
      if settings.INIT_TEST is True and len(settings.MULTI_ENCODED_PAYLOAD) != 0:
        # A per-parameter auto-detected tamper (e.g. hexencode from check_encoders()) must not
        # leak into the next target/form - reset back to only what the user actually gave.
        settings.MULTI_ENCODED_PAYLOAD = []
        menu.options.tamper = settings.USER_APPLIED_TAMPER
    try:
      response = opener.open(request, timeout=settings.TIMEOUT)
      succeeded = True
      with settings.REQUESTS_LOCK:
        stability.expand_retry_budget()
      if (settings.INIT_TEST is True and not settings.UNAUTHORIZED) or \
         (settings.INIT_TEST is True and settings.MULTI_TARGETS):
        if not settings.VALID_URL:
          stability.mark_url_valid()
        if not settings.CHECK_INTERNET:
          settings.INIT_TEST = False

    except ValueError:
      if settings.VERBOSITY_LEVEL < 2:
        settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
      err_msg = "You provided an invalid target URL."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit(settings.EXIT_FAILURE)

    except AttributeError:
      raise SystemExit(settings.EXIT_FAILURE)

    except (_urllib.error.HTTPError, _urllib.error.URLError) as err_msg:
      # A deliberately unfollowed redirect - retrying won't help.
      if not settings.FOLLOW_REDIRECT and getattr(err_msg, "code", None) in (301, 302, 303, 307):
        break
      if settings.UNAUTHORIZED_ERROR in str(err_msg):
        settings.UNAUTHORIZED = unauthorized = True
        with settings.REQUESTS_LOCK:
          stability.freeze_retry_budget()
      else:
        with settings.REQUESTS_LOCK:
          stability.expand_retry_budget()
      if [True for err_code in settings.HTTP_ERROR_CODES if err_code in str(err_msg)]:
        pending_error = err_msg
        break
      # A status the list does not name is still an answer rather than a transport failure, and
      # retrying cannot change it. Left to the loop it would never stop: the budget is re-doubled
      # on every attempt, so it outgrows the count of attempts made against it.
      if isinstance(err_msg, _urllib.error.HTTPError):
        pending_error = err_msg
        break

    except (SocketError, _urllib.error.HTTPError, _urllib.error.URLError, _http_client.BadStatusLine, _http_client.RemoteDisconnected, _http_client.IncompleteRead, _http_client.InvalidURL, Exception) as err_msg:
      if not settings.MULTI_TARGETS and not settings.CRAWLING:
        pass
      else:
        if not settings.INIT_TEST:
          checks.connection_exceptions(err_msg)
        if isinstance(err_msg, (_urllib.error.HTTPError, _urllib.error.URLError, SocketError, _http_client.BadStatusLine, _http_client.RemoteDisconnected, _http_client.IncompleteRead)):
          pending_error = err_msg
        break

  while True:
    try:
      if response is False:
        if pending_error is not None:
          raise pending_error
        response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
      # Make .read() idempotent so callers can safely reuse this response.
      _raw_body = response.read()
      response.read = (lambda _b: lambda *a, **kw: _b)(_raw_body)
      code = response.getcode()
      response_headers = response.info()
      page = checks.process_page_content(response, action="encode")
      response_headers[settings.URI_HTTP_HEADER] = response.geturl()
      response_headers = str(response_headers).strip(settings.END_LINE.LF)
      # Handle server-set cookies.
      if not menu.options.drop_set_cookie:
        cookies.handle_server_cookies(response)
      print_http_response(response_headers, code, page)
      # Checks regarding a potential CAPTCHA protection mechanism.
      checks.captcha_check(page)
      # Checks regarding a potential browser verification protection mechanism.
      checks.browser_verification(page)
      # Checks regarding recognition of generic "your ip has been blocked" messages.
      checks.blocked_ip(page)
      # Whatever shell or interpreter the page is reporting an error from.
      checks.parse_errors(page)
      stability.reset_connection_error_budget()
      return response

    # This is useful when handling exotic HTTP errors (i.e. requests for authentication).
    except _urllib.error.HTTPError as err:
      if not menu.options.drop_set_cookie:
        cookies.handle_server_cookies(err)
      try:
        if getattr(err, 'fp', None) is None:
          raise AttributeError
        page = checks.process_page_content(err, action="encode")
      except Exception:
        page = ''
      response_headers = err.info()
      code = err.code
      print_http_response(response_headers, code, page)
      # WAF/CAPTCHA/block pages are usually served as error codes - check the body here too.
      checks.captcha_check(page)
      checks.browser_verification(page)
      checks.blocked_ip(page)
      # A shell error is at least as likely to come back as a 500 as it is with a 200.
      checks.parse_errors(page)

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
        # Nothing is returned for it, so this is what tells a caller the request did reach the target.
        settings.LAST_HTTP_ERROR = err
        if settings.VERBOSITY_LEVEL >= 2:
          parts = str(err).split(": ")
          if len(parts) > 1 and len(parts[1]) == 0:
            error_msg = "Non-standard HTTP status code"
        return None
      else:
        error_msg = str(err).replace(": ", " (")
        parts = str(err).split(": ")
        if len(parts) > 1 and len(parts[1]) == 0:
          err_msg = error_msg + "Non-standard HTTP status code"
        else:
          err_msg = error_msg

        settings.print_data_to_stdout(settings.print_critical_msg(err_msg + ")."))
        raise SystemExit(settings.EXIT_FAILURE)

    except _urllib.error.URLError as err:
      if not menu.options.drop_set_cookie:
        cookies.handle_server_cookies(err)
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
      raise SystemExit(settings.EXIT_FAILURE)

    # A raw connection-level error - retry it like any other transient failure.
    except (SocketError, _http_client.BadStatusLine, _http_client.RemoteDisconnected, _http_client.IncompleteRead) as err:
      if stability.should_retry_connection_error(err):
        response = False
        continue
      err_msg = "The target host is not responding. Please ensure it is up and try again."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit(settings.EXIT_FAILURE)

"""
Send again a request check_http_traffic() came back from empty-handed - which it does both when nothing answered and when the answer was a 3xx/4xx/5xx already read off the wire, and only the first is worth repeating.
"""
def resend(request):
  error = settings.LAST_HTTP_ERROR
  if error is not None and str(getattr(error, "code", "")) not in settings.TRANSIENT_HTTP_ERROR_CODES:
    raise error
  # A long enough delay can push the target into erroring out, and that error arrives at the delay asked for - which is the measurement, so repeating it only pays the delay twice.
  if error is not None and settings.TIME_RELATED_ATTACK:
    raise error
  if error is not None and settings.VERBOSITY_LEVEL >= 2:
    debug_msg = "Retrying the request due to HTTP error code '" + str(error.code) + "'."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
  if menu.options.proxy or menu.options.ignore_proxy or menu.options.tor:
    return proxy.use_proxy(request)
  return _urllib.request.urlopen(request, timeout=settings.TIMEOUT)

"""
Send a request, falling back to proxy/urlopen only if check_http_traffic() found no response.
"""
def send_request(request):
  do_check(request)
  response = check_http_traffic(request)
  if response is None:
    response = resend(request)
  return response

"""
Check for added headers.
"""
def do_check(request):

  request = encode_non_ascii_url(request)
  randomize_parameters(request)
  anticsrf.apply_token(request)

  # Frame the body as chunks, so a filter inspecting it never sees the payload in one piece.
  if menu.options.chunked and request.data and not request.has_header(settings.TRANSFER_ENCODING):
    request.data = chunked.split_post_data(request.data.decode(settings.DEFAULT_CODEC, errors="replace")).encode(settings.DEFAULT_CODEC)
    request.add_unredirected_header(settings.TRANSFER_ENCODING, "chunked")

  # Check if defined any Cookie HTTP header.
  # Whatever keeps the file up to date knows better than the value this run started with.
  if menu.options.live_cookies and not settings.COOKIE_INJECTION:
    menu.options.cookie = cookies.live_cookies()

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
    request.add_header(settings.ACCEPT_ENCODING, settings.HTTP_ACCEPT_ENCODING_HEADER_VALUE if settings.PAGE_COMPRESSION else settings.HTTP_ACCEPT_ENCODING_IDENTITY)

  # Appends a fake HTTP header 'X-Forwarded-For' (and similar)
  if settings.TAMPER_SCRIPTS["xforwardedfor"]:
    from src.tamper import xforwardedfor
    xforwardedfor.tamper(request)

  # Check if defined any HTTP Authentication credentials.
  # HTTP Authentication: Basic, Digest, Bearer Access Authentication.
  if menu.options.auth_cred and menu.options.auth_type:
    if menu.options.auth_type.lower() not in (settings.AUTH_TYPE.BASIC, settings.AUTH_TYPE.DIGEST, settings.AUTH_TYPE.BEARER):
      err_msg = "HTTP authentication type value must be Basic, Digest or Bearer."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit(settings.EXIT_FAILURE)
    if menu.options.auth_type.lower() == settings.AUTH_TYPE.BEARER:
      request.add_header(settings.AUTHORIZATION, "Bearer " + menu.options.auth_cred.strip())
    elif menu.options.auth_type.lower() == settings.AUTH_TYPE.BASIC:
      b64_string = encodebytes(menu.options.auth_cred.encode(settings.DEFAULT_CODEC)).decode().replace(settings.END_LINE.LF, '')
      request.add_header(settings.AUTHORIZATION, "Basic " + b64_string)
    # Digest is handled in check_http_traffic()'s opener, not here.

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

    if settings.END_LINE.ESCAPED_LF in extra_headers:
      extra_headers = extra_headers.split(settings.END_LINE.ESCAPED_LF)
      # Remove empty strings and "Content-Length"
      extra_headers = [x for x in extra_headers if settings.CONTENT_LENGTH not in x]
    else:
      tmp_extra_header = []
      tmp_extra_header.append(extra_headers)
      extra_headers = tmp_extra_header

    # Remove empty strings and/or duplicates
    non_empty = [x for x in extra_headers if x]
    extra_headers = (list(dict.fromkeys(non_empty)))

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
      request.add_header(settings.ACCEPT_ENCODING, settings.HTTP_ACCEPT_ENCODING_HEADER_VALUE if settings.PAGE_COMPRESSION else settings.HTTP_ACCEPT_ENCODING_IDENTITY)

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
            benign_value = re.sub(settings.PROBLEMATIC_CUSTOM_INJECTION_PATTERNS, "", http_header_value)
            if settings.CUSTOM_INJECTION_MARKER_CHAR in benign_value:
              settings.CUSTOM_INJECTION_MARKER = True
              settings.CUSTOM_HEADER_CHECK = http_header_name

            if settings.CUSTOM_INJECTION_MARKER_CHAR in benign_value or \
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

      except Exception:
        pass

# eof
