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

import io
import re
import time
import calendar
import email.utils
import threading
import difflib
import statistics
from socket import error as SocketError
from src.core.parse import cmdline as menu
from os.path import splitext
from src.utils import settings
from src.utils import session_handler
from src.thirdparty.six.moves import http_client as _http_client
# accept overly long result lines
_http_client._MAXLINE = 1 * 1024 * 1024
from src.utils import common
from src.utils import crawler
from src.core.requests import headers
from src.core.requests import parameters
from src.core.requests import redirection
from src.core.requests import authentication
from src.core.requests import stability
from src.core.controller import checks
from src.thirdparty.six.moves import urllib as _urllib

"""
Keep the page the target answered with, off the response already in hand.

Read once and handed back for whatever reads it next: what a parameter is compared against, what the
forms are parsed out of, and what the proof is written from all want the same page, and none of them
is worth a second request.
"""
def capture_original_page(response):
  if response is None or isinstance(response, bool):
    return None
  try:
    raw_body = response.read()
  except Exception:
    return None
  response.read = (lambda _b: lambda *a, **kw: _b)(raw_body)
  settings.ORIGINAL_PAGE = checks.decode_page_body(raw_body, response)
  return raw_body

"""
Check if the content of the given URL is stable over time.
"""
def is_url_content_stable(url, response=None, fetch_time=None, http_request_method=None):
  status = "stable"
  info_msg = "Checking if the target URL content is stable."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))

  # One request for the stability check, built the way the run's own requests are.
  def _build_request():
    method = http_request_method or settings.HTTPMETHOD.GET
    if settings.USER_DEFINED_POST_DATA:
      request = _urllib.request.Request(url, settings.USER_DEFINED_POST_DATA.encode(settings.DEFAULT_CODEC), method=method)
    else:
      request = _urllib.request.Request(url, method=method)
    headers.do_check(request)
    return request

  # Retried here too: what differs between the samples is set aside as the page moving on its own.
  def _sample(request=None, response=None):
    if request is None:
      request = _build_request()
    if response is None:
      response = headers.send_raw(request)
    return with_retry_on(request, response)

  try:
    if response is not None:
      response = _sample(response=response)
      raw_body = capture_original_page(response)
      first_response_content = raw_body.strip()
    else:
      first_response = _sample()
      try:
        raw_body = first_response.read()
        first_response_content = raw_body.strip()
        settings.ORIGINAL_PAGE = checks.decode_page_body(raw_body, first_response)
      finally:
        first_response.close()
      fetch_time = time.time()

    remaining = settings.STABILITY_CHECK_DELAY
    if fetch_time is not None:
      remaining = max(0, min(settings.STABILITY_CHECK_DELAY, settings.STABILITY_CHECK_DELAY - (time.time() - fetch_time)))
    if remaining:
      time.sleep(remaining)

    second_response = _sample()
    try:
      raw_second_body = second_response.read()
      second_response_content = raw_second_body.strip()
      second_page = checks.decode_page_body(raw_second_body, second_response)
    finally:
      second_response.close()

    if first_response_content != second_response_content:
      ratio = difflib.SequenceMatcher(None, first_response_content, second_response_content).ratio()
      if settings.VERBOSITY_LEVEL != 0:
        debug_msg = "Content similarity ratio between the two samples: " + str(round(ratio, 4))
        debug_msg += " (threshold: " + str(settings.STABILITY_SIMILARITY_THRESHOLD) + ")."
        settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
      if ratio < settings.STABILITY_SIMILARITY_THRESHOLD:
        status = "dynamic"
    settings.PAGE_STABLE = status == "stable"

    # Said before the work it decides, so the answer is given with the reason for it still on screen.
    if not settings.PAGE_STABLE and not settings.UNSTABLE_PROMPTED:
      settings.UNSTABLE_PROMPTED = True
      # What happened, what is done about it, and what to reach for when the results read wrong.
      warn_msg = "Target URL content is not stable (i.e. content differs). Page comparison is based "
      warn_msg += "on a sequence matcher, with the parts that move on their own left out. If no "
      warn_msg += "dynamic nor injectable parameter is detected, or in case of junk results, give "
      warn_msg += "it a go with the switch '--text-only'."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
      message = "How do you want to proceed? [(C)ontinue/(q)uit] "
      if common.read_input(message, default="C", check_batch=True) in settings.CHOICE_QUIT:
        raise SystemExit(settings.EXIT_FAILURE)

    """
    The two samples are of the same request, so whatever differs between them is the page moving on
    its own. Noted as regions to leave out, and the pair compared again without them and without
    the layout around the text - which is the comparison every later one is read against.
    """
    checks.find_dynamic_content(settings.ORIGINAL_PAGE, second_page)
    settings.ORIGINAL_PAGE_COMPARABLE = checks.comparable_page(settings.ORIGINAL_PAGE)
    settings.PAGE_NOISE_RATIO = difflib.SequenceMatcher(None, settings.ORIGINAL_PAGE_COMPARABLE,
                                                        checks.comparable_page(second_page)).ratio()
    if settings.VERBOSITY_LEVEL != 0 and settings.DYNAMIC_MARKINGS:
      debug_msg = "Marked " + str(len(settings.DYNAMIC_MARKINGS)) + " region"
      debug_msg += "s"[len(settings.DYNAMIC_MARKINGS) == 1:] + " of the page as moving on its own."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

  except Exception:
    msg = "Unable to determine target URL content stability due to retrieval errors."
    settings.print_data_to_stdout(settings.print_warning_msg(msg))
    return

  # Only where it is: the other answer was already given, with what it costs, by the warning above.
  if settings.PAGE_STABLE:
    msg = "Target URL content is stable."
    settings.print_data_to_stdout(settings.print_info_msg(msg))


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
    response = headers.check_http_traffic(request)
    if response is None:
      response = headers.resend(request)
    response = with_retry_on(request, response)
    if type(response) is not bool and settings.FOLLOW_REDIRECT and response is not None:
      if response.geturl() != url:
        href = redirection.do_check(url, response.geturl())
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
Attach a harmless (tag-stripped) version of the cookie/header under test - do_check() skips it, but timing samples need the same target-side cost as real requests.
"""
def _attach_injection_point_placeholder(request):
  if settings.COOKIE_INJECTION and menu.options.cookie:
    request.add_header(settings.COOKIE, checks.remove_tags(menu.options.cookie))
  elif settings.USER_AGENT_INJECTION and menu.options.agent:
    request.add_header(settings.USER_AGENT, checks.remove_tags(menu.options.agent))
  elif settings.REFERER_INJECTION and menu.options.referer:
    request.add_header(settings.REFERER, checks.remove_tags(menu.options.referer))
  elif settings.HOST_INJECTION and menu.options.host:
    request.add_header(settings.HOST, checks.remove_tags(menu.options.host))
  elif settings.CUSTOM_HEADER_INJECTION and settings.CUSTOM_HEADER_VALUE:
    request.add_header(settings.CUSTOM_HEADER_NAME, checks.remove_tags(settings.CUSTOM_HEADER_VALUE))

"""
A single, best-effort clean response-time sample; returns None on failure instead of raising.
"""
def quick_response_time_sample(url, http_request_method):
  try:
    if menu.options.data:
      request = _urllib.request.Request(url, menu.options.data.replace(settings.TESTABLE_VALUE + settings.INJECT_TAG, settings.TESTABLE_VALUE).encode(settings.DEFAULT_CODEC), method=http_request_method)
    else:
      request = _urllib.request.Request(url.replace(settings.TESTABLE_VALUE + settings.INJECT_TAG, settings.TESTABLE_VALUE), method=http_request_method)
    headers.do_check(request)
    _attach_injection_point_placeholder(request)
    # Paced before the clock starts, so the delay this run keeps is not measured as the target's.
    headers.apply_request_policy()
    start = time.time()
    response = headers.send_raw(request, policy=False)
    response.read(1)
    response.close()
    return time.time() - start
  except Exception:
    return None

"""
Sends one clean request and times it, with full auth-error handling - the authoritative first sample for estimate_response_time() below.
"""
def _measure_response_time_with_auth_handling(url, http_request_method):
  stored_auth_creds = False

  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Estimating the target URL response time. "
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

  # Check if defined POST data
  if menu.options.data:
    request = _urllib.request.Request(url, menu.options.data.replace(settings.TESTABLE_VALUE + settings.INJECT_TAG, settings.TESTABLE_VALUE).encode(settings.DEFAULT_CODEC), method=http_request_method)
  else:
    request = _urllib.request.Request(url.replace(settings.TESTABLE_VALUE + settings.INJECT_TAG, settings.TESTABLE_VALUE), method=http_request_method)

  headers.do_check(request)
  _attach_injection_point_placeholder(request)
  # Paced before the clock starts, so the delay this run keeps is not measured as the target's.
  headers.apply_request_policy()
  start = time.time()
  try:
    response = headers.send_raw(request, policy=False)
    response.read(1)
    response.close()
  except _http_client.InvalidURL as err_msg:
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit(settings.EXIT_FAILURE)
    
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
          raise SystemExit(settings.EXIT_FAILURE)

        except IndexError:
          err_msg = "The provided pair of " + str(menu.options.auth_type)
          err_msg += " HTTP authentication credentials '" + str(menu.options.auth_cred) + "'"
          err_msg += " seems to be invalid."
          settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
          raise SystemExit(settings.EXIT_FAILURE)


        if menu.options.auth_type and menu.options.auth_type != auth_type.lower():
          if checks.identified_http_auth_type(auth_type):
            menu.options.auth_type = auth_type.lower()
        else:
          menu.options.auth_type = auth_type.lower()

        # Check for stored auth credentials.
        if not menu.options.auth_cred:
          try:
            stored_auth_creds = session_handler.export_valid_credentials(url, auth_type.lower())
          except (Exception, SystemExit):
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
                warn_msg = "This target requires " + menu.options.auth_type.lower() + " "
                warn_msg += "HTTP authentication credentials."
                settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
                while True:
                  message = "Do you want to perform a dictionary-based attack? [Y/n] "
                  do_update = common.read_input(message, default="Y", check_batch=True)
                  if do_update in settings.CHOICE_YES:
                    auth_creds = authentication.http_auth_cracker(url, realm, http_request_method)
                    if auth_creds is not False:
                      # Put to use, not only announced: what builds the Authorization header for
                      # every request after this is the option, so a pair found and left there
                      # would have the run carry on unauthenticated against a target that just
                      # said it needs credentials.
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
                    common.invalid_option(do_update)
                    pass

            # Digest authentication
            elif menu.options.auth_type.lower() == settings.AUTH_TYPE.DIGEST:
              if not int(settings.UNAUTHORIZED_ERROR) in settings.IGNORE_CODE:
                warn_msg = "This target requires " + menu.options.auth_type.lower() + " "
                warn_msg += "HTTP authentication credentials."
                settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
                # Check if failed to identify the realm attribute.
                if not realm:
                  warn_msg = "Failed to identify the realm attribute."
                  settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
                while True:
                  message = "Do you want to perform a dictionary-based attack? [Y/n] "
                  do_update = common.read_input(message, default="Y", check_batch=True)
                  if do_update in settings.CHOICE_YES:
                    auth_creds = authentication.http_auth_cracker(url, realm, http_request_method)
                    if auth_creds is not False:
                      # Put to use, not only announced: what builds the Authorization header for
                      # every request after this is the option, so a pair found and left there
                      # would have the run carry on unauthenticated against a target that just
                      # said it needs credentials.
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
                    common.invalid_option(do_update)
                    pass
        else:
          raise SystemExit()

    ignore_end = time.time()
    start = start - (ignore_start - ignore_end)


  except ValueError as err_msg:
    settings.print_data_to_stdout(settings.print_critical_msg(str(err_msg) + "."))
    raise SystemExit(settings.EXIT_FAILURE)

  except Exception as err_msg:
    request_failed(err_msg)

  end = time.time()
  diff = end - start
  return diff

"""
Estimating the response time (in seconds) - median of several samples, since one alone is too noisy to trust for the slow-target decision.
"""
def estimate_response_time(url, timesec, http_request_method):
  samples = []

  if settings.INIT_CONNECTION_TIME is not None:
    samples.append(settings.INIT_CONNECTION_TIME)
    settings.INIT_CONNECTION_TIME = None
  else:
    samples.append(_measure_response_time_with_auth_handling(url, http_request_method))

  for _ in range(settings.RESPONSE_TIME_SAMPLES - len(samples)):
    extra = quick_response_time_sample(url, http_request_method)
    if extra is not None:
      samples.append(extra)

  diff = statistics.median(samples)
  return _finish_response_time_estimate(diff, timesec)

"""
Convert the measured round-trip time into the slow-target warning and adjusted timesec.
"""
def _finish_response_time_estimate(diff, timesec):
  if int(diff) < 1:
    url_time_response = int(diff)
  else:
    url_time_response = int(round(diff))
    warn_msg = "Target's estimated response time is " + str(url_time_response)
    warn_msg += " second" + "s"[url_time_response == 1:]
    if settings.TARGET_OS == settings.OS.WINDOWS:
      warn_msg += " (a relatively slow 'cmd.exe' on the target host adds to it)"
    warn_msg += ". This may delay"
    if url_time_response >= 3:
      warn_msg += " and/or corrupt"
    warn_msg += " data extraction."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

  # The payloads count the delay in whole seconds, so a fractional one cannot be used as given -
  # rounded rather than dropped, and said out loud instead of quietly becoming a shorter delay.
  if timesec != int(timesec):
    rounded = int(round(timesec)) or 1
    warn_msg = "The delay given with '--time-sec' (i.e. '" + str(timesec) + "') is counted in whole "
    warn_msg += "seconds by the payloads, so '" + str(rounded) + "' is used instead."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    timesec = rounded
  else:
    timesec = int(timesec)

  settings.URL_TIME_RESPONSE = url_time_response
  return timesec, url_time_response

"""
Seconds to wait, read from a 'Retry-After' header given either as a number of them or as a date.
None where the target sent no such header, or sent one that cannot be read.
"""
def retry_after_seconds(err):
  try:
    value = (err.headers.get("Retry-After") or "").strip()
  except Exception:
    return None
  if not value:
    return None
  if value.isdigit():
    return float(value)
  try:
    parsed = email.utils.parsedate(value)
    return max(0.0, calendar.timegm(parsed) - time.time()) if parsed else None
  except Exception:
    return None

"""
What a status says about the target rather than about the request. Returns what request_failed()
should answer, or None where the status is nothing more than the interference it warns about.
"""
def _answered_with_status(code, err):
  code = str(code)

  # The first answer being '404' is a wrong URL far more often than a target worth testing.
  if code == settings.NOT_FOUND_ERROR and settings.INIT_TEST is True:
    return checks.page_not_found(err)

  # The payload is in the request line and the target will not take one that long. Where it can be
  # moved into a body instead, that is the way past it - shortening what is sent is the other.
  if code == settings.REQUEST_URI_TOO_LONG and int(code) not in settings.WARNED_HTTP_ERROR_CODES:
    settings.WARNED_HTTP_ERROR_CODES.add(int(code))
    warn_msg = "The target answered '" + checks.http_error_code_label(code, err) + "', so the "
    warn_msg += "request line is longer than it accepts. "
    if not settings.USER_DEFINED_POST_DATA:
      warn_msg += "Try sending the parameters in the body ('--data'), or a tamper script that "
      warn_msg += "shortens the payload ('--tamper')."
    else:
      warn_msg += "Try a tamper script that shortens the payload ('--tamper')."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    return None

  # A body the target will not read is worth sending again the way it will.
  if menu.options.chunked and not settings.CHUNKED_UNSUPPORTED and \
     code in (settings.NOT_ALLOWED, settings.LENGTH_REQUIRED):
    settings.CHUNKED_UNSUPPORTED = True
    menu.options.chunked = False
    warn_msg = "Turning off HTTP chunked transfer encoding, as the target answered '"
    warn_msg += checks.http_error_code_label(code, err) + "' to a chunked body."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    return True

  return None

"""
Exceptions regarding requests failure(s)
"""
def request_failed(err_msg):

  # Asked for with '--ignore-timeouts': the request is given up on and the run carries on without
  # it, so a target that answers late neither reads as unreachable nor spends the error budget.
  if menu.options.ignore_timeouts and re.search(r"timed?\s*out", str(err_msg), re.IGNORECASE):
    settings.IGNORED_TIMEOUTS += 1
    if settings.IGNORED_TIMEOUTS == 1 or settings.VERBOSITY_LEVEL != 0:
      warn_msg = "The target did not answer in time, so the request is skipped ('--ignore-timeouts')"
      warn_msg += " - " + str(settings.IGNORED_TIMEOUTS) + " so far." if settings.IGNORED_TIMEOUTS > 1 else "."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    return False

  stability.mark_url_invalid()

  # Pacing is answered on its own: being told to slow down holds whether or not a WAF is looked for.
  if str(getattr(err_msg, "code", None)) in settings.WAF_BLOCK_HTTP_CODES:
    stability.adapt_delay(blocked=True)
    # Where the target said how long to wait, that beats guessing at it - waited out once here,
    # while the delay between requests is what keeps the pace afterwards.
    requested = retry_after_seconds(err_msg)
    if requested is not None and not settings.TIME_RELATED_ATTACK:
      waited = min(requested, settings.RATE_LIMIT_MAX_DELAY)
      if settings.VERBOSITY_LEVEL != 0:
        debug_msg = "Waiting the " + str(round(waited, 1)) + " second"
        debug_msg += "s"[waited == 1:] + " the target asked for ('Retry-After')."
        settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
      time.sleep(waited)

  if not settings.FOLLOW_REDIRECT and getattr(err_msg, "code", None) in (301, 302, 303, 307):
    stability.mark_url_valid()
    return False

  try:
    error_msg = str(err_msg.args[0]).split("] ")[1]
  except IndexError:
    try:
      error_msg = str(err_msg.args[0])
    except IndexError:
      error_msg = str(err_msg)

  if any(x in str(error_msg).lower() for x in ["wrong version number", "ssl", "https"]):
    stability.disable_retries()
    error_msg = "Cannot establish SSL connection. "
    if settings.MULTI_TARGETS or settings.CRAWLING:
      error_msg = error_msg + "Skipping to the next target."
    settings.print_data_to_stdout(settings.print_critical_msg(error_msg))
    if not settings.CRAWLING:
      raise SystemExit(settings.EXIT_FAILURE)
    else:
      return False

  elif re.search(r"(connection\s*refused|timed?\s*out|no\s*route|unreachable|tunnel)", str(error_msg), re.IGNORECASE):
    stability.disable_retries()
    if any((settings.BIND_TCP, settings.REVERSE_TCP)) and re.search(r"timed?\s*out", str(error_msg), re.IGNORECASE):
      raise SystemExit()
    if settings.OOB_IGNORE_TIMEOUT and re.search(r"timed?\s*out", str(error_msg), re.IGNORECASE):
      # Nothing is read from the response here, and some clients on the target take tens of
      # seconds to return, so waiting in vain is expected rather than fatal.
      if settings.VERBOSITY_LEVEL >= 2:
        debug_msg = "The target did not answer in time, which an out-of-band payload does not need."
        settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
      return False
    err = "Unable to connect to the target URL"
    if menu.options.tor:
      err += " using the Tor network"
    elif menu.options.proxy: 
      err += " using the defined HTTP proxy"
    err = err + " (Reason: " + str(error_msg)  + "). "
    if menu.options.tor:
      err += "Please make sure that the Tor service is running and "
      err += "that Privoxy is properly configured to forward traffic to Tor. "
      err += "This is required in order to use the '--tor' switch."
    if settings.MULTI_TARGETS or settings.CRAWLING:
      err = err + "Skipping to the next target."
    error_msg = err
    settings.print_data_to_stdout(settings.print_critical_msg(error_msg))
    if not settings.CRAWLING:
      raise SystemExit(settings.EXIT_FAILURE)
    else:
      return False

  elif settings.UNAUTHORIZED_ERROR in str(err_msg).lower():
    if int(settings.UNAUTHORIZED_ERROR) in settings.IGNORE_CODE or \
       settings.PERFORM_CRACKING:
      return False
    else:
      err_msg = "Not authorized (" + settings.UNAUTHORIZED_ERROR + "). "
      err_msg += "Try to provide right HTTP authentication type ('--auth-type') and valid credentials ('--auth-cred')"
      if menu.options.auth_type and menu.options.auth_cred:
        if settings.MULTI_TARGETS or settings.CRAWLING:
          err_msg += ". "
        else:
          err_msg += " or re-run without providing them, in order to perform a dictionary-based attack. "
      else:
        err_msg += " or re-run by providing option '--ignore-code=" + settings.UNAUTHORIZED_ERROR +"'. "
      if settings.CRAWLING:
        err_msg += "Skipping to the next target."
      # Said once: every request that follows is answered the same way, and repeating it buries
      # whatever else the run has to report.
      if int(settings.UNAUTHORIZED_ERROR) not in settings.WARNED_HTTP_ERROR_CODES:
        settings.WARNED_HTTP_ERROR_CODES.add(int(settings.UNAUTHORIZED_ERROR))
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    if not settings.CRAWLING:
      if menu.options.auth_type and menu.options.auth_cred:
        raise SystemExit(settings.EXIT_FAILURE)

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
    elif checks.detect_waf(getattr(err_msg, "code", None)):
      if not settings.NOT_FOUND_ERROR in str(err_msg).lower():
        return False
      return True
    elif [True for err_code in settings.HTTP_ERROR_CODES if err_code in str(error_msg)]:
      status_code = [err_code for err_code in settings.HTTP_ERROR_CODES if err_code in str(error_msg)]
      code = status_code[0]
      if not checks.ignored_http_error_code(code):
        # What the code says about the target, before it is written off as interference.
        handled = _answered_with_status(code, err_msg)
        if handled is not None:
          return handled
      if not checks.ignored_http_error_code(code) and int(code) not in settings.WARNED_HTTP_ERROR_CODES:
        warn_msg = "The web server responded with an HTTP error code '" + checks.http_error_code_label(code, err_msg)
        warn_msg += "' which could interfere with the results of the tests."
        settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
        settings.WARNED_HTTP_ERROR_CODES.add(int(code))
      if not settings.NOT_FOUND_ERROR in str(err_msg).lower():
        return False
      return True
    elif stability.should_retry_connection_error(error_msg):
      return True
    else:
      error_msg = "The provided target URL does not seem reachable. "
      items = []
      if not menu.options.random_agent:
          items.append("'--random-agent' switch")
      if not any((menu.options.proxy, menu.options.ignore_proxy, menu.options.tor)):
        items.append("proxy switches ('--proxy', '--ignore-proxy'...).")
      if items:
        error_msg += "It might still be reachable. Try re-running with "
        error_msg += " and/or ".join(items)
    settings.print_data_to_stdout(settings.print_critical_msg(error_msg))
    if not settings.CRAWLING:
      raise SystemExit(settings.EXIT_FAILURE)
    else:
      return False

  elif settings.IDENTIFIED_WARNINGS or settings.IDENTIFIED_EVAL_PROBE or settings.IDENTIFIED_COMMAND_INJECTION or \
  any(checks.ignored_http_error_code(_) for _ in settings.HTTP_ERROR_CODES if _ in str(error_msg)):
    return False

  elif settings.IGNORE_ERR_MSG is False:
    continue_tests = checks.continue_tests(err_msg)
    if continue_tests:
      settings.IGNORE_ERR_MSG = True
    else:
      if not settings.CRAWLING:
        raise SystemExit()
    return False

  else:
    if settings.VERBOSITY_LEVEL >= 1:
      status_code = [err_code for err_code in settings.HTTP_ERROR_CODES if err_code in str(error_msg)]
      if status_code:
        # The warning above already named the code; repeating it for every request that meets it does not.
        if int(status_code[0]) not in settings.WARNED_HTTP_ERROR_CODES:
          debug_msg = "Got " + str(err_msg)
          settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
      else:
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    return False

"""
Get the response of the request
"""
class ReReadableResponse(object):
  """
  A response whose body has already been read, handed on as though it had not been.

  Everything else about it is the response itself: the status, the headers and the URL are asked
  of the original, and only the reading is answered from what was kept.
  """
  def __init__(self, response, body):
    self._response = response
    self._body = io.BytesIO(body)

  def read(self, *args, **kwargs):
    return self._body.read(*args, **kwargs)

  def readlines(self, *args, **kwargs):
    return self._body.readlines(*args, **kwargs)

  def close(self):
    try:
      self._response.close()
    except Exception:
      pass

  def __getattr__(self, name):
    return getattr(self._response, name)

"""
Send the request again while its answer is a page the run was told to retry on.

What it is for is a target that answers something other than what it was asked - a rate limit, a
'try again later', an interstitial - where the response is a valid one and only its content says
that nothing was tested.
"""
def retry_on_undesired_content(request, response):
  attempts = 0
  while True:
    try:
      body = response.read()
    except Exception:
      return response
    content = checks.decode_page_body(body, response)
    # Bounded by the retries the run was given, not by the budget the connection layer keeps
    # raising as requests are spent: a page that always asks to be retried would otherwise be
    # asked again for as long as the run lasts.
    if not re.search(menu.options.retry_on, content, re.I) or attempts >= menu.options.retries:
      # Nothing left to retry with, so this page is what everything downstream reads as the answer.
      if attempts and not settings.RETRY_ON_EXHAUSTED and re.search(menu.options.retry_on, content, re.I):
        settings.RETRY_ON_EXHAUSTED = True
        warn_msg = "The target still answers with a page matching '" + menu.options.retry_on + "', after the retries were spent."
        settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
      return ReReadableResponse(response, body)
    attempts += 1
    warn_msg = "Forced retry of the request, because of undesired page content."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    retried = headers.check_http_traffic(request)
    if retried is None:
      try:
        retried = headers.resend(request)
      except Exception:
        return ReReadableResponse(response, body)
    if retried is None or isinstance(retried, bool):
      return ReReadableResponse(response, body)
    response = retried

"""
The answer, retried while it says what '--retry-on' names - whichever path the request went out over.
"""
def with_retry_on(request, response):
  if menu.options.retry_on and response is not None and not isinstance(response, bool):
    return retry_on_undesired_content(request, response)
  return response

def get_request_response(request):

  response = headers.check_http_traffic(request)
  if response is None:
    try:
      response = headers.resend(request)
    except Exception as err_msg:
      response = request_failed(err_msg)

  return with_retry_on(request, response)

"""
The page a second-order injection shows up on, which is not the page the payload was sent to.

A target that stores what it is given and runs it somewhere else - a queue, a log viewer, an admin
page - answers the injected request with nothing at all. So that answer is set aside and the page
named by '--second-url'/'--second-req' is fetched in its place, and read for the result instead.
"""
def second_order_response(payload=None):
  if settings.FETCHING_SECOND_ORDER:
    return None
  if not menu.options.second_url and not settings.SECOND_ORDER_REQUEST:
    return None
  # Looking for a protection in the way is not an injection, so its answer is not looked for
  # anywhere else either.
  if payload and settings.WAF_CHECK_PAYLOAD in str(payload):
    return None

  settings.FETCHING_SECOND_ORDER = True
  try:
    # The stored request may say where the payload goes, the way the target's own parameters do.
    def _with_payload(value):
      if value and settings.INJECT_TAG in value:
        return checks.process_injectable_value(checks.encode_payload(payload or ""), value)
      return value

    if menu.options.second_url:
      request = _urllib.request.Request(_with_payload(menu.options.second_url), method=settings.HTTPMETHOD.GET)
      headers.do_check(request)
    else:
      stored = settings.SECOND_ORDER_REQUEST
      data = _with_payload(stored["data"])
      request = _urllib.request.Request(_with_payload(stored["url"]), data.encode(settings.DEFAULT_CODEC) if data else None, method=stored["method"] or settings.HTTPMETHOD.GET)
      for header_name, header_value in stored["headers"]:
        request.add_header(header_name, _with_payload(header_value))
    if settings.VERBOSITY_LEVEL >= 2:
      debug_msg = "Reading the result from '" + request.get_full_url() + "', where the output of a second-order injection shows up."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
    return get_request_response(request)
  except Exception:
    return None
  finally:
    settings.FETCHING_SECOND_ORDER = False

"""
Check if target host is vulnerable.
"""
def init_injection(payload, http_request_method, url):
  if settings.TIME_RELATED_ATTACK:
    start = 0
    end = 0
    start = time.time()

  """
  Encoded as the last thing before it is spliced into a carrier that is URL-encoded.

  A payload arrives with its boundaries, its whitespace and its tamper scripts already applied, and
  it is full of characters that end a parameter where it is going: an '&' or an '=' out of the
  user's own command split the query or the body in two and truncated the payload. What the payload
  wrote for itself survives, '%' being the one character left alone - and the carrier is encoded
  separately, keeping the '&' and '=' that do its own separating.

  A JSON or XML body is not URL-encoded and the target never decodes one, so those carry the
  payload as it is and do their own escaping below.
  """
  def encoded_for_url(value):
    return checks.encode_payload(value)

  if settings.INJECT_TAG in url:
    vuln_parameter = parameters.vuln_GET_param(url)
    target = checks.process_injectable_value(encoded_for_url(payload), url)
    if settings.USER_DEFINED_POST_DATA and not settings.IGNORE_USER_DEFINED_POST_DATA:
      request = _urllib.request.Request(target, settings.USER_DEFINED_POST_DATA.encode(settings.DEFAULT_CODEC), method=http_request_method)
    else:
      request = _urllib.request.Request(target, method=http_request_method)
  else:
    parameter = menu.options.data
    parameter = parameters.do_POST_check(parameter, http_request_method)
    # Joined only to find which parameter carries the tag, so nothing here is encoded for a
    # wire it never reaches - the '+' this escaped was in a value being read for its name.
    parameter = ''.join(str(e) for e in parameter)
    vuln_parameter = parameters.vuln_POST_param(parameter, url)
    if settings.IS_JSON:
      # Escaped for the string it is going into, not decoded: a payload is not URL-encoded by the
      # time it gets here, so unquoting it only ever damaged one that held a per-cent sign.
      data = checks.process_injectable_value(checks.escape_json_value(payload), menu.options.data)
      try:
        data = checks.json_data(data)
      except ValueError:
        pass
    elif settings.IS_XML:
      # Likewise here: nothing to decode, and the characters XML cannot carry at all are dropped.
      data = checks.restore_xml_layout(checks.process_injectable_value(checks.xml_encode_payload(checks.strip_xml_forbidden(payload)), menu.options.data))
    else:
      data = checks.process_injectable_value(encoded_for_url(payload), menu.options.data)
    request = _urllib.request.Request(url, data.encode(settings.DEFAULT_CODEC), method=http_request_method)

  headers.do_check(request)
  response = get_request_response(request)
  # Sent before the clock is stopped: a delay asked for by the payload is paid on the request
  # above, and what is read below is the page it shows up on.
  second_order = second_order_response(payload)
  if second_order is not None:
    response = second_order

  if settings.TIME_RELATED_ATTACK:
    failed_attempts = 0
    # Only a request that never reached the target is worth sending again: an error status is still an answer, and asking for it again both pays the delay a second time and reads as a retried measurement, which discards the finding.
    while response is False and not stability.answered_with_http_error() and failed_attempts < settings.TIME_RELATED_ATTACK_RETRIES:
      failed_attempts += 1
      start = time.time()
      response = get_request_response(request)
    end = time.time()
    response = end - start

  return response, vuln_parameter

"""
Check if target host is vulnerable, injecting payload via the given set_header(request, payload) callback.
"""
def header_injection(url, payload, http_request_method, set_header):

  # Send the payload in an HTTP header rather than in a parameter.
  def inject_header(url, payload, http_request_method):
    # Check if defined POST data
    if settings.USER_DEFINED_POST_DATA:
      data = settings.USER_DEFINED_POST_DATA.encode(settings.DEFAULT_CODEC)
    else:
      data = None
    request = _urllib.request.Request(url, data, method=http_request_method)
    payload = checks.normalize_newlines(payload)
    set_header(request, payload)
    try:
      return with_retry_on(request, headers.send_request(request))
    except ValueError:
      pass

  if settings.TIME_RELATED_ATTACK :
    start = 0
    end = 0
    start = time.time()

  try:
    response = inject_header(url, payload, http_request_method)
  except Exception as err_msg:
    response = request_failed(err_msg)
  second_order = second_order_response(payload)
  if second_order is not None:
    response = second_order

  if settings.TIME_RELATED_ATTACK :
    failed_attempts = 0
    while response is False and not stability.answered_with_http_error() and failed_attempts < settings.TIME_RELATED_ATTACK_RETRIES:
      failed_attempts += 1
      start = time.time()
      try:
        response = inject_header(url, payload, http_request_method)
      except Exception as err_msg:
        response = request_failed(err_msg)
    end  = time.time()
    exec_time = end - start
    return exec_time
  else:
    return response

"""
Check if target host is vulnerable. (Cookie-based injection)
"""
def cookie_injection(url, payload, http_request_method):
  # Put the payload into the cookie, in place of the marker that says where it goes.
  def set_cookie(request, payload):
    if settings.INJECT_TAG in menu.options.cookie:
      encoded_payload = checks.encode_payload(payload)
      cookie = checks.process_injectable_value(encoded_payload, menu.options.cookie)
      request.add_header(settings.COOKIE, cookie)
  return header_injection(url, payload, http_request_method, set_cookie)

"""
Check if target host is vulnerable. (User-Agent-based injection)
"""
def user_agent_injection(url, payload, http_request_method):
  return header_injection(url, payload, http_request_method, lambda request, payload: request.add_header(settings.USER_AGENT, payload))

"""
Check if target host is vulnerable. (Referer-based injection)
"""
def referer_injection(url, payload, http_request_method):
  return header_injection(url, payload, http_request_method, lambda request, payload: request.add_header(settings.REFERER, payload))

"""
Check if target host is vulnerable. (Host-based injection)
"""
def host_injection(url, payload, http_request_method):
  return header_injection(url, payload, http_request_method, lambda request, payload: request.add_header(settings.HOST, payload))

"""
Check if target host is vulnerable. (Custom header injection)
"""
def custom_header_injection(url, payload, http_request_method):
  return header_injection(url, payload, http_request_method, lambda request, payload: request.add_header(settings.CUSTOM_HEADER_NAME, payload))

"""
Detect the character encoding of the target web page.
"""
def encoding_detection(response):
  charset = None

  try:
    # Read once
    content_bytes = response.read()
    try:
      content_text = content_bytes[:1024].decode("utf-8", errors="ignore")
    except (Exception, SystemExit):
      content_text = ""

    # 1. Get charset from HTTP header (may be None)
    try:
      header_charset = response.headers.getparam('charset')  # Python 2
    except AttributeError:
      try:
        header_charset = response.headers.get_content_charset()  # Python 3
      except (Exception, SystemExit):
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

    # 3. Nothing declared, so what the pages are read with stays what it already was.
    if not charset:
      return

    # 4. Kept only where it can actually be decoded with, so a page is never read through an
    # encoding the platform does not have.
    if settings.known_encoding(charset) and settings.ascii_transparent_encoding(charset):
      settings.DEFAULT_PAGE_ENCODING = charset
    else:
      settings.DEFAULT_PAGE_ENCODING = settings.DEFAULT_CODEC
      warn_msg = "The web page declares the character encoding as '" + charset + "', which is not recognized."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

  except Exception:
    pass

"""
Identify the target application's type based on the URL extension.
"""
def application_identification(url, response=None):
  root, application_extension = splitext(_urllib.parse.urlparse(url).path)
  settings.TARGET_APPLICATION = application_extension[1:].upper()

  x_powered_by = response.info().get(settings.X_POWERED_BY, "") if response is not None else ""
  if not settings.TARGET_APPLICATION and x_powered_by:
    match = re.search(r"PHP|ASP\.NET|JSP", x_powered_by, re.IGNORECASE)
    if match:
      settings.TARGET_APPLICATION = match.group(0).upper()

  if settings.TARGET_APPLICATION:
    # The version, where the header names one. Read as digits and dots only: a packaged build writes
    # its packaging after the version ("5.5.9-1ubuntu4.6"), which is the distribution's and not the
    # application's.
    version = re.search(re.escape(settings.TARGET_APPLICATION) + r"[\-\_\/\ ]([\d\.]+)", x_powered_by, re.IGNORECASE)
    if version:
      settings.TARGET_APPLICATION_VERSION = version.group(1).rstrip(".")

    # The application and the language an evaluated string is tried in are the same question, so
    # they are answered once and said once, rather than naming the same language twice over.
    checks.note_evaluated_language(settings.TARGET_APPLICATION, x_powered_by)
    if settings.VERBOSITY_LEVEL != 0:
      debug_msg = "The web application technology is '" + settings.TARGET_APPLICATION + "'."
      settings.print_data_to_stdout(settings.print_bold_debug_msg(debug_msg))

    for unsupported in settings.UNSUPPORTED_TARGET_APPLICATION:
      if settings.TARGET_APPLICATION.lower() in unsupported.lower():
        err_msg = settings.TARGET_APPLICATION + " exploitation is not yet supported."
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
        raise SystemExit(settings.EXIT_FAILURE)

"""
Detect the underlying operating system of the target server based on server headers.
"""
def check_os(server_header):
  if menu.options.os:
    checks.user_defined_os()

  named = ""
  for banner in settings.SERVER_OS_BANNERS:
    match = re.search(banner, server_header, re.IGNORECASE)
    if match:
      # What the banner spells out, rather than the family it puts the target in.
      named = match.group(0)
      settings.IDENTIFIED_SERVER_OS = named
      checks.set_target_os(named)

      if settings.TARGET_OS == settings.OS.WINDOWS and menu.options.shellshock:
        err_msg = "The 'shellshock' module is not available for Windows targets."
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
        raise SystemExit(settings.EXIT_FAILURE)
      break

  if named and settings.VERBOSITY_LEVEL != 0:
    debug_msg = "The web server operating system is '" + named + "'"
    debug_msg += " (" + checks.target_os_label() + ")."
    settings.print_data_to_stdout(settings.print_bold_debug_msg(debug_msg))


"""
Identify the underlying technology or framework powering the target application.
"""
def technology_identification(response):
  try:
    x_powered_by = response.info().get(settings.X_POWERED_BY, "").strip()

    # Not reported on its own: what it settles - the operating system, and the language an
    # evaluated string is tried in - is each said where it is settled.
    if x_powered_by:
      check_os(x_powered_by)

  except Exception:
    pass


"""
Identify the software running on the target web server.
"""
def server_identification(response):
  server_banner = response.info().get(settings.SERVER, "").strip()
  for banner in settings.SERVER_BANNERS:
    match = re.search(banner, server_banner, re.IGNORECASE)
    if match:
      settings.SERVER_BANNER = match.group(0)
      # The version, where the banner names one - the matched name carries it only for the servers
      # whose pattern asks for it, so it is read off the banner itself.
      version = re.search(re.escape(settings.SERVER_BANNER.split("/")[0]) + r"[\-\_\/\ ]([\d\.]+)", server_banner, re.IGNORECASE)
      if version:
        settings.SERVER_VERSION = version.group(1).rstrip(".")

      # Which document root this server keeps. It runs on the first connection, before the target's
      # operating system has been worked out, so the banner itself has to answer for it - an Apache
      # build reports "(Win32)" or "(Win64)" and would otherwise be handed a Unix-like path.
      windows_banner = (settings.TARGET_OS == settings.OS.WINDOWS or
                        re.search(r"\(Win(32|64|dows)\)?", server_banner, re.IGNORECASE) is not None)
      platform = settings.OS.WINDOWS if windows_banner else settings.OS.UNIX
      for server, roots in settings.SERVER_DOC_ROOTS.items():
        if server in settings.SERVER_BANNER.lower():
          # A server that runs on one platform only says which platform this is, whatever the
          # banner left out - IIS names no "(Win64)" and is no less Windows for it.
          settings.WEB_ROOT = roots.get(platform) or (list(roots.values())[0] if len(roots) == 1 else "")
          break
      break

  if server_banner and settings.VERBOSITY_LEVEL != 0:
    debug_msg = "The web server is '" + server_banner + "'."
    settings.print_data_to_stdout(settings.print_bold_debug_msg(debug_msg))


"""
Identify the underlying operating system based on the server banner.
"""
def os_identification(response):
  if not settings.IGNORE_IDENTIFIED_TARGET_OS:
    server_banner = response.info().get(settings.SERVER, "")
    check_os(server_banner)

  """
  Nothing is asked here, and nothing is said yet.

  The banner is the weakest of the three things that can answer this: a heuristic payload that
  executes settles it outright, and that runs in a moment. Asking first put the question before the
  evidence - and then ignored the answer when the evidence contradicted it.
  """
  if not settings.IDENTIFIED_TARGET_OS and not menu.options.os:
    settings.OS_IDENTIFICATION_PENDING = True


"""
Perform a target page reload after a specified delay (minimum 5 seconds).
"""
def url_reload(url, delay_seconds):
  # Ensure a minimum delay of 5 seconds before reloading
  if int(delay_seconds) < 5:
    delay_seconds = 5
  time.sleep(delay_seconds)

  request = _urllib.request.Request(url, method=settings.HTTPMETHOD.GET)
  headers.do_check(request)
  return get_request_response(request)

"""
Calculate the time related execution time
"""
_injection_lock = threading.Lock()
_injections_in_flight = 0
_transport_before_injection = None

# Send one payload, with the timeout widened to allow for the delay it asks for.
def perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url):
  global _injections_in_flight, _transport_before_injection
  # A time-related payload asks the target to sleep, so the answer is meant to be late. Waiting less
  # than the delay we asked for turns our own request into a connection error, which on a target
  # slow enough to need a raised delay would abort the scan.
  needed = injected_delay_allowance()
  """
  These two are read at the moment the socket is opened, and several workers can be here at once -
  so what is saved and put back is the state before the first of them arrived, not before each. Any
  other bookkeeping restores one worker's idea of the timeout while another's request is still in
  flight, and that request times out on a delay it correctly asked for.
  """
  with _injection_lock:
    if _injections_in_flight == 0:
      _transport_before_injection = (settings.TIMEOUT, settings.KEEP_ALIVE)
    _injections_in_flight += 1
    if needed > settings.TIMEOUT:
      settings.TIMEOUT = needed
      # A pooled connection keeps the timeout it was opened with, so a reused one would ignore this.
      settings.KEEP_ALIVE = False
  try:
    return _perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url)
  finally:
    with _injection_lock:
      _injections_in_flight -= 1
      if _injections_in_flight == 0 and _transport_before_injection is not None:
        settings.TIMEOUT, settings.KEEP_ALIVE = _transport_before_injection
        _transport_before_injection = None

"""
Seconds a request needs to allow for, when the payload deliberately delays the answer.
"""
def injected_delay_allowance():
  if not settings.TIME_RELATED_ATTACK:
    return 0
  delay = settings.CALIBRATED_TIMESEC or menu.options.timesec or 0
  # What the payload actually asks for, not what was configured - a target whose delay is built
  # differently would otherwise have its own answer cut off, which reads as no delay at all.
  # The false-positive round adds a few seconds of its own on top of the calibrated delay.
  return checks.injected_delay(delay) + settings.TIME_DELAY_STEP + 10

# Send the payload wherever the injection point is, and time the answer.
def _perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url):
  # Fix prefixes / suffixes
  payload, prefix = parameters.prefixes(payload, prefix)
  payload, suffix = parameters.suffixes(payload, suffix)
  
  payload = checks.tamper_outside_single_quotes(payload, lambda part: part.replace(settings.SINGLE_WHITESPACE, whitespace))
  payload = checks.perform_payload_modification(payload)
  # A parameter the target carries encoded is written back the way it arrived, the whole value at
  # once rather than the injected part alone - which is what makes the value it reads a valid one.
  payload = checks.apply_value_encoding(payload)

  # Check if defined "--verbose" option.
  if settings.VERBOSITY_LEVEL != 0:
    settings.print_data_to_stdout(settings.print_payload(payload))

  # Check if defined cookie with "INJECT_HERE" tag
  if menu.options.cookie and settings.INJECT_TAG in menu.options.cookie or settings.COOKIE_INJECTION:
    if not vuln_parameter:
      vuln_parameter = parameters.specify_cookie_parameter(menu.options.cookie)
    exec_time = cookie_injection(url, payload, http_request_method)
  # Check if defined custom header with "INJECT_HERE" tag
  elif settings.CUSTOM_HEADER_INJECTION:
    if not vuln_parameter:
      vuln_parameter = parameters.specify_custom_header_parameter("")
    exec_time = custom_header_injection(url, payload, http_request_method)
  # Check if defined user-agent with "INJECT_HERE" tag
  elif (menu.options.agent and settings.INJECT_TAG in menu.options.agent) or settings.USER_AGENT_INJECTION:
    if not vuln_parameter:
      vuln_parameter = parameters.specify_user_agent_parameter(settings.USER_AGENT.lower())
    exec_time = user_agent_injection(url, payload, http_request_method)
  # Check if defined referer with "INJECT_HERE" tag
  elif (menu.options.referer and settings.INJECT_TAG in menu.options.referer) or settings.REFERER_INJECTION:
    if not vuln_parameter:
      vuln_parameter = parameters.specify_referer_parameter(settings.REFERER.lower())
    exec_time = referer_injection(url, payload, http_request_method)
  # Check if defined host with "INJECT_HERE" tag
  elif (menu.options.host and settings.INJECT_TAG in menu.options.host) or settings.HOST_INJECTION:
    if not vuln_parameter:
      vuln_parameter = parameters.specify_host_parameter(settings.HOST.lower())
    exec_time = host_injection(url, payload, http_request_method)
  else:
    exec_time, vuln_parameter = init_injection(payload, http_request_method, url)

  return exec_time, vuln_parameter, payload, prefix, suffix
  
# eof
