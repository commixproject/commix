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

import os
import re
import sys

from src.utils import common
from src.utils import settings
from src.core.parse import cmdline as menu
from src.core.requests import tor
from src.core.requests import proxy
from src.core.parse import request
from src.core.requests import cookies
from src.core.controller import checks

"""
Everything the options say, checked and settled before a target is contacted.

An option the run cannot act on is the user's own to correct, and one that contradicts another
says so here rather than after a connection has been opened and a payload sent.
"""
def validate():
  # Check for missing mandatory option(s).
  if not settings.STDIN_PARSING and not any((menu.options.url, menu.options.logfile, menu.options.bulkfile, \
              menu.options.requestfile, menu.options.sitemap_url, menu.options.wizard, \
              menu.options.update, menu.options.list_tampers)):
    if not menu.options.purge:
      err_msg = "Missing a mandatory option (-u, -l, -m, -r, -x, --wizard, --update, --list-tampers or --purge). "
      err_msg += "Use -h for basic and -hh for advanced help."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit(settings.EXIT_FAILURE)

  # Any out-of-band option on its own is enough to ask for the channel.
  if any((menu.options.oob_server, menu.options.oob_token, menu.options.oob_poll != settings.OOB_POLL_INTERVAL)):
    menu.options.oob = True

  checks.init_keep_alive()
  checks.set_optimize()

  if menu.options.codec:
    if not settings.known_encoding(menu.options.codec):
      err_msg = "The provided charset '"  + menu.options.codec + "' is unknown. "
      err_msg += "Please visit 'http://docs.python.org/library/codecs.html#standard-encodings' "
      err_msg += "to get the full list of supported charsets."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit(settings.EXIT_FAILURE)
    else:
      settings.DEFAULT_CODEC  = menu.options.codec.lower()

  if menu.options.header and len(menu.options.header.split(settings.END_LINE.ESCAPED_LF))> 1:
      warn_msg = "Due to multiple provided HTTP headers, switching '--header' to '--headers'."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

  if menu.options.method:
    settings.HTTP_METHOD = menu.options.method

  if menu.options.answers:
    settings.ANSWERS = menu.options.answers

  # Check if defined "--proxy" option.
  if menu.options.proxy:
    if menu.options.tor:
      err_msg = "The switch '--tor' is incompatible with option '--proxy'."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit(settings.EXIT_FAILURE)

    if menu.options.ignore_proxy:
      err_msg = "The option '--proxy' is incompatible with switch '--ignore-proxy'."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit(settings.EXIT_FAILURE)

    match = re.search(settings.PROXY_REGEX, menu.options.proxy.strip())
    if not match:
      err_msg = "Proxy value must be in format '(" + "|".join(settings.PROXY_SCHEMES) + ")://address:port'."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit(settings.EXIT_FAILURE)
    _, proxy_scheme, proxy_cred, proxy_address, proxy_port = match.groups()
    settings.PROXY_SCHEME = (proxy_scheme or "http").lower()
    menu.options.proxy = proxy_address + ":" + proxy_port
    # Credentials written into the proxy value itself are the ones that proxy asks for.
    if proxy_cred:
      menu.options.proxy_cred = proxy_cred
    proxy.configure()

  if menu.options.proxy and menu.options.proxy_file:
    err_msg = "The option '--proxy' is incompatible with the option '--proxy-file'."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit(settings.EXIT_FAILURE)

  if menu.options.proxy_freq and not menu.options.proxy_file:
    err_msg = "The option '--proxy-freq' requires the option '--proxy-file'."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit(settings.EXIT_FAILURE)

  # Read once and kept in the order they were written, so a run that rotates through them is
  # repeatable rather than picking one at random.
  if menu.options.proxy_file:
    proxy.load_proxy_list()

  if menu.options.safe_post and not menu.options.safe_url:
    err_msg = "The option '--safe-post' requires the option '--safe-url'."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit(settings.EXIT_FAILURE)

  if menu.options.safe_req and any((menu.options.safe_url, menu.options.safe_post)):
    err_msg = "The option '--safe-req' is incompatible with the options '--safe-url' and '--safe-post'."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit(settings.EXIT_FAILURE)

  if menu.options.safe_freq and not any((menu.options.safe_url, menu.options.safe_req)):
    err_msg = "The option '--safe-freq' requires the option '--safe-url' or the option '--safe-req'."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit(settings.EXIT_FAILURE)

  if any((menu.options.safe_url, menu.options.safe_req)):
    if menu.options.safe_freq <= 0:
      err_msg = "You must specify a '--safe-freq' value, greater than zero, to visit a safe URL."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit(settings.EXIT_FAILURE)
    if menu.options.safe_url and not re.search(r"(?i)\Ahttp[s]*://", menu.options.safe_url):
      menu.options.safe_url = ("https://" if ":443/" in menu.options.safe_url else "http://") + menu.options.safe_url
    if menu.options.safe_req:
      settings.SAFE_REQUEST = request.parse_safe_request(menu.options.safe_req)

  for option_name, option_value in (("--csrf-url", menu.options.csrf_url), ("--csrf-method", menu.options.csrf_method), ("--csrf-data", menu.options.csrf_data)):
    if option_value and not menu.options.csrf_token:
      err_msg = "The option '" + option_name + "' requires the option '--csrf-token'."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit(settings.EXIT_FAILURE)

  if menu.options.csrf_token:
    # A token is one value at a time: a second worker spends the one the first was given, and both
    # requests are then answered as though neither had a token at all.
    if menu.options.threads > 1:
      err_msg = "The option '--csrf-token' is incompatible with the option '--threads'."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit(settings.EXIT_FAILURE)
    checks.set_anticsrf_token(menu.options.csrf_token)

  if menu.options.second_url and menu.options.second_req:
    err_msg = "The option '--second-url' is incompatible with the option '--second-req'."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit(settings.EXIT_FAILURE)

  if menu.options.second_req:
    info_msg = "Parsing the second-order HTTP request from '" + menu.options.second_req + "'."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
    settings.SECOND_ORDER_REQUEST = request.parse_single_request(menu.options.second_req, "second-order")

  if menu.options.retry_on:
    try:
      re.compile(menu.options.retry_on)
    except Exception as err:
      err_msg = "Invalid regular expression '" + menu.options.retry_on + "' (" + str(err) + ")."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit(settings.EXIT_FAILURE)

  # Asked for on its own, it has nothing to check: the run goes out the way it always would.
  if menu.options.check_tor and not any((menu.options.tor, menu.options.proxy)):
    err_msg = "The switch '--check-tor' requires the switch '--tor' or the option '--proxy'."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit(settings.EXIT_FAILURE)

  if menu.options.tor_type and not menu.options.tor:
    err_msg = "The option '--tor-type' requires the switch '--tor'."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit(settings.EXIT_FAILURE)

  if not menu.options.proxy:
    # Check if defined Tor (--tor option).
    if menu.options.tor:
      tor.set_proxy_settings()
      tor.do_check()

  if menu.options.ignore_session and menu.options.flush_session:
    err_msg = "The '--ignore-session' switch is unlikely to work combined with the '--flush-session' switch."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit(settings.EXIT_FAILURE)

  if menu.options.failed_tries == 0:
    err_msg = "You must specify '--failed-tries' value, greater than zero."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit(settings.EXIT_FAILURE)

  # Check if defined "--auth-cred" and/or '--auth-type'.
  if (menu.options.auth_type and not menu.options.auth_cred) or (menu.options.auth_cred and not menu.options.auth_type):
    err_msg = "You must specify both '--auth-cred' and '--auth-type' options."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit(settings.EXIT_FAILURE)

  if menu.options.auth_cred and menu.options.auth_type:
    if menu.options.auth_type.lower() in (settings.AUTH_TYPE.BASIC, settings.AUTH_TYPE.DIGEST) and not re.search(settings.AUTH_CRED_REGEX, menu.options.auth_cred):
      error_msg = "HTTP " + str(menu.options.auth_type)
      error_msg += " authentication credentials value must be in format 'username:password'."
      settings.print_data_to_stdout(settings.print_critical_msg(error_msg))
      raise SystemExit(settings.EXIT_FAILURE)

  if menu.options.requestfile and menu.options.url:
    err_msg = "The '-r' option is incompatible with option '-u' ('--url')."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit(settings.EXIT_FAILURE)

  if menu.options.bulkfile and menu.options.url:
    err_msg = "The '-m' option is incompatible with option '-u' ('--url')."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit(settings.EXIT_FAILURE)

  # Check the user-defined OS.
  if menu.options.os:
    checks.user_defined_os()

  # Check if defined "--abort-code" option.
  if menu.options.abort_code:
    try:
      settings.ABORT_CODE = [int(_) for _ in re.split(settings.PARAMETER_SPLITTING_REGEX, menu.options.abort_code)]
    except ValueError:
      err_msg = "The option '--abort-code' should contain a list of integer values."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit(settings.EXIT_FAILURE)

  # A page that asks to be retried is not a page to abort on: the two would otherwise both answer
  # for the same response, and the abort would win.
  if menu.options.retry_on and settings.ABORT_CODE:
    settings.ABORT_CODE = []

  # Check if defined "--ignore-code" option.
  if menu.options.ignore_code:
    try:
      settings.IGNORE_CODE = [int(_) for _ in re.split(settings.PARAMETER_SPLITTING_REGEX, menu.options.ignore_code)]
      if settings.VERBOSITY_LEVEL != 0:
        debug_msg = "Ignoring '" + str(', '.join(str(x) for x in settings.IGNORE_CODE)) + "' HTTP error code"+('', 's')[len(settings.IGNORE_CODE) > 1]+ "."
        settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
    except ValueError:
      err_msg = "The option '--ignore-code' should contain a list of integer values."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit(settings.EXIT_FAILURE)

  # Check if defined "--wizard" option.
  if menu.options.wizard:
    info_msg = "Starting wizard interface."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
    message = "Please enter full target URL (-u) "
    if menu.options.url:
      settings.print_data_to_stdout(settings.print_message(message + str(menu.options.url)))
    elif not menu.options.url and not settings.STDIN_PARSING:
      while True:
        menu.options.url = common.read_input(message, default=None, check_batch=True)
        if menu.options.url is None or len(menu.options.url) == 0:
          pass
        else:
          break
    message = "POST data (--data) [Enter for None] "
    if settings.STDIN_PARSING or menu.options.data:
      settings.print_data_to_stdout(settings.print_message(message + str(menu.options.data)))
    else:
      menu.options.data = common.read_input(message, default=None, check_batch=True)
      if menu.options.data is not None and len(menu.options.data) == 0:
        menu.options.data = False
    while True:
      message = "Injection difficulty (--level) [1-3, Default: 1] "
      if settings.STDIN_PARSING:
        settings.print_data_to_stdout(settings.print_message(message + str(settings.INJECTION_LEVEL)))
        break
      try:
        settings.INJECTION_LEVEL = int(common.read_input(message, default=settings.DEFAULT_INJECTION_LEVEL, check_batch=True))
        if settings.INJECTION_LEVEL > int(settings.HTTP_HEADER_INJECTION_LEVEL):
          pass
        else:
          break
      except ValueError:
        pass

  # Seconds to delay between each HTTP request.
  if menu.options.delay != 0:
    settings.DELAY = menu.options.delay

  # Random seconds added on top of that delay, which cannot be asked for backwards.
  if menu.options.jitter < 0:
    err_msg = "The value of the '--jitter' option must not be negative."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit(settings.EXIT_FAILURE)

  # Check if defined "--timesec" option.
  if menu.options.timesec != 0:
    settings.TIMESEC = menu.options.timesec

  # What an unstable connection needs more of - doubled, and only where the run did not say
  # otherwise itself: a value given by hand is the one that was meant.
  if menu.options.unstable:
    # The delay is held at zero until a technique asks for one, and the answer it gets is the
    # safe minimum - so that, not the zero, is what there is twice as much of.
    if not settings.USER_APPLIED_TIMESEC:
      settings.TIMESEC = menu.options.timesec = (settings.TIMESEC or settings.MIN_SAFE_TIMESEC) * 2
    if not settings.USER_APPLIED_RETRIES:
      settings.MAX_RETRIES = menu.options.retries = menu.options.retries * 2
    if not settings.USER_APPLIED_TIMEOUT:
      settings.TIMEOUT = menu.options.timeout = menu.options.timeout * 2
    if settings.VERBOSITY_LEVEL != 0:
      debug_msg = "Doubling what an unstable connection needs more of, except where it was given: "
      debug_msg += "'--time-sec=" + str(menu.options.timesec) + "', '--retries=" + str(menu.options.retries)
      debug_msg += "', '--timeout=" + str(menu.options.timeout) + "'."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

  # Check if defined "--threads" option.
  if menu.options.threads > 1:
    try:
      import concurrent.futures
      threads_supported = True
    except ImportError:
      threads_supported = False
    if not threads_supported:
      warn_msg = "'--threads' needs Python 3.2+; continuing with a single thread."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    elif menu.options.threads > settings.MAX_THREADS:
      settings.THREADS = settings.MAX_THREADS
      warn_msg = "Setting '--threads' to the maximum of " + str(settings.MAX_THREADS) + " concurrent HTTP requests."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    else:
      settings.THREADS = menu.options.threads
    if settings.THREADS > 1 and settings.VERBOSITY_LEVEL != 0:
      debug_msg = "Setting " + str(settings.THREADS) + " concurrent HTTP requests."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

  if menu.options.tor:
    # Doubled from the delay that would otherwise be asked for - which is the safe minimum until a
    # technique settles on one, rather than the zero the option sits at.
    settings.TIMESEC = menu.options.timesec = (settings.TIMESEC or settings.MIN_SAFE_TIMESEC) * 2
    warn_msg = "Increasing the value for the option '--time-sec' to"
    warn_msg += " " + str(settings.TIMESEC) + ", because you provided the switch '--tor'."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

  if menu.options.sitemap_url:
    settings.SITEMAP_CHECK = True

  if menu.options.crawldepth > 0 or settings.SITEMAP_CHECK:
    settings.CRAWLING = True

  if menu.options.crawl_exclude:
    if not settings.CRAWLING:
      err_msg = "The '--crawl-exclude' option requires usage of the '--crawl' option."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit(settings.EXIT_FAILURE)
    try:
      re.compile(menu.options.crawl_exclude)
    except Exception as e:
      err_msg = "invalid regular expression '" + menu.options.crawl_exclude + "' (" + str(e) + ")."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit(settings.EXIT_FAILURE)

  # Only a request carrying a body can be split into chunks.
  if menu.options.chunked and not any((menu.options.data, menu.options.requestfile, \
     menu.options.logfile, menu.options.forms)):
    err_msg = "The '--chunked' switch requires usage of POST data."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit(settings.EXIT_FAILURE)

  for option, cookies_file in (("--load-cookies", menu.options.load_cookies), ("--live-cookies", menu.options.live_cookies)):
    if cookies_file and not os.path.isfile(cookies_file):
      err_msg = "It seems the '" + cookies_file + "' file, provided with the '" + option + "' option, does not exist."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit(settings.EXIT_FAILURE)

  # The file keeps being read as it changes, so what it holds now would only be overwritten.
  if menu.options.load_cookies and not menu.options.live_cookies:
    menu.options.cookie = cookies.load_cookies()

  if menu.options.scope:
    try:
      re.compile(menu.options.scope)
    except Exception as e:
      err_msg = "invalid regular expression '" + menu.options.scope + "' (" + str(e) + ")."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit(settings.EXIT_FAILURE)
    info_msg = "Using regular expression '" + menu.options.scope + "' for filtering targets."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))

  if menu.options.forms and not settings.CRAWLING:
    err_msg = "The '--forms' switch requires the '--crawl' option."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit(settings.EXIT_FAILURE)

  # Check arguments
  if len(sys.argv) == 1 and not settings.STDIN_PARSING:
    menu.parser.print_help()
    settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
    raise SystemExit()
  else:
    # Check for INJECT_HERE tag.
    inject_tag_regex_match = re.search(settings.INJECT_TAG_REGEX, ",".join(str(x) for x in sys.argv))
    if inject_tag_regex_match:
      settings.INJECT_TAG = inject_tag_regex_match.group(0)

  # What can be answered without the target is answered before it is contacted: a path that does
  # not exist is no reason to have opened a connection, let alone to have sent it a payload.
  if menu.options.file_write is not None:
    if not os.path.exists(menu.options.file_write):
      err_msg = "The specified local file '" + menu.options.file_write + "' does not exist."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit(settings.EXIT_FAILURE)
    if not os.path.isfile(menu.options.file_write):
      err_msg = "The specified path '" + menu.options.file_write + "' is not a file."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit(settings.EXIT_FAILURE)

  # Check provided parameters for tests
  checks.check_provided_parameters()

  # Define the local path where Metasploit Framework is installed.
  if menu.options.msf_path:
    settings.METASPLOIT_PATH = menu.options.msf_path


# eof
