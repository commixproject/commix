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
      err_msg += "Use -h for help."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

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
      raise SystemExit()
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
      raise SystemExit()

    if menu.options.ignore_proxy:
      err_msg = "The option '--proxy' is incompatible with switch '--ignore-proxy'."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()

    for match in re.finditer(settings.PROXY_REGEX, menu.options.proxy):
      _, proxy_scheme, proxy_address, proxy_port = match.groups()
      if settings.SCHEME or proxy_scheme:
        if not settings.SCHEME:
          settings.SCHEME = proxy_scheme
        menu.options.proxy = proxy_address + ":" + proxy_port
        break
    else:
      err_msg = "Proxy value must be in format '(http|https)://address:port'."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()

  if not menu.options.proxy:
    # Check if defined Tor (--tor option).
    if menu.options.tor:
      if menu.options.tor_port:
        settings.TOR_HTTP_PROXY_PORT = menu.options.tor_port
      menu.options.proxy = settings.TOR_HTTP_PROXY_IP + ":" + settings.TOR_HTTP_PROXY_PORT
      tor.do_check()

  if menu.options.ignore_session and menu.options.flush_session:
    err_msg = "The '--ignore-session' switch is unlikely to work combined with the '--flush-session' switch."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  if menu.options.failed_tries == 0:
    err_msg = "You must specify '--failed-tries' value, greater than zero."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  # Check if defined "--auth-cred" and/or '--auth-type'.
  if (menu.options.auth_type and not menu.options.auth_cred) or (menu.options.auth_cred and not menu.options.auth_type):
    err_msg = "You must specify both '--auth-cred' and '--auth-type' options."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  if menu.options.auth_cred and menu.options.auth_type:
    if menu.options.auth_type.lower() in (settings.AUTH_TYPE.BASIC, settings.AUTH_TYPE.DIGEST) and not re.search(settings.AUTH_CRED_REGEX, menu.options.auth_cred):
      error_msg = "HTTP " + str(menu.options.auth_type)
      error_msg += " authentication credentials value must be in format 'username:password'."
      settings.print_data_to_stdout(settings.print_critical_msg(error_msg))
      raise SystemExit()

  if menu.options.requestfile and menu.options.url:
    err_msg = "The '-r' option is incompatible with option '-u' ('--url')."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  if menu.options.bulkfile and menu.options.url:
    err_msg = "The '-m' option is incompatible with option '-u' ('--url')."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

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
      raise SystemExit()

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
      raise SystemExit()

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

  # Check if defined "--timesec" option.
  if menu.options.timesec != 0:
    settings.TIMESEC = menu.options.timesec

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
    settings.TIMESEC = settings.TIMESEC * 2
    warn_msg = "Increasing default value for option '--time-sec' to"
    warn_msg += " " + str(settings.TIMESEC) + ", because you provided switch '--tor'."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

  if menu.options.sitemap_url:
    settings.SITEMAP_CHECK = True

  if menu.options.crawldepth > 0 or settings.SITEMAP_CHECK:
    settings.CRAWLING = True

  if menu.options.crawl_exclude:
    if not settings.CRAWLING:
      err_msg = "The '--crawl-exclude' option requires usage of the '--crawl' option."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()
    try:
      re.compile(menu.options.crawl_exclude)
    except Exception as e:
      err_msg = "invalid regular expression '" + menu.options.crawl_exclude + "' (" + str(e) + ")."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()

  # Only a request carrying a body can be split into chunks.
  if menu.options.chunked and not any((menu.options.data, menu.options.requestfile, \
     menu.options.logfile, menu.options.forms)):
    err_msg = "The '--chunked' switch requires usage of POST data."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  for option, cookies_file in (("--load-cookies", menu.options.load_cookies), ("--live-cookies", menu.options.live_cookies)):
    if cookies_file and not os.path.isfile(cookies_file):
      err_msg = "It seems the '" + cookies_file + "' file, provided with the '" + option + "' option, does not exist."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()

  # The file keeps being read as it changes, so what it holds now would only be overwritten.
  if menu.options.load_cookies and not menu.options.live_cookies:
    menu.options.cookie = cookies.load_cookies()

  if menu.options.scope:
    try:
      re.compile(menu.options.scope)
    except Exception as e:
      err_msg = "invalid regular expression '" + menu.options.scope + "' (" + str(e) + ")."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()
    info_msg = "Using regular expression '" + menu.options.scope + "' for filtering targets."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))

  if menu.options.forms and not settings.CRAWLING:
    err_msg = "The '--forms' switch requires the '--crawl' option."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

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
      raise SystemExit()
    if not os.path.isfile(menu.options.file_write):
      err_msg = "The specified path '" + menu.options.file_write + "' is not a file."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()

  # Check provided parameters for tests
  checks.check_provided_parameters()

  # Define the local path where Metasploit Framework is installed.
  if menu.options.msf_path:
    settings.METASPLOIT_PATH = menu.options.msf_path


# eof
