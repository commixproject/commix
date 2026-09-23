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

import json
import socket
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.six.moves import http_client as _http_client
from src.thirdparty.socks import socks
from src.core.parse import cmdline as menu
from src.utils import settings
from src.core.requests import proxy

# The first of the given ports that something on the loopback address is listening on.
def find_local_port(ports):
  for port in ports:
    probe = None
    try:
      try:
        probe = socket._orig_socket(socket.AF_INET, socket.SOCK_STREAM)
      except AttributeError:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      probe.settimeout(settings.TIMEOUT)
      probe.connect((settings.TOR_HTTP_PROXY_IP, int(port)))
      return int(port)
    except socket.error:
      pass
    finally:
      if probe is not None:
        try:
          probe.close()
        except socket.error:
          pass
  return None


# Route requests through an HTTP proxy standing in front of Tor.
def set_http_proxy_settings():
  info_msg = "Setting the Tor HTTP proxy settings."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))

  port = find_local_port((menu.options.tor_port,) if menu.options.tor_port else settings.DEFAULT_TOR_HTTP_PORTS)
  if not port:
    err_msg = "Could not establish a connection with the Tor HTTP proxy. "
    err_msg += "Please make sure that you have Tor (bundle) installed and set up, "
    err_msg += "so that you are able to successfully use the '--tor' switch."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit(settings.EXIT_FAILURE)

  settings.TOR_HTTP_PROXY_PORT = str(port)
  menu.options.proxy = settings.TOR_HTTP_PROXY_IP + ":" + settings.TOR_HTTP_PROXY_PORT

  if not menu.options.check_tor:
    warn_msg = "Use the '--check-tor' switch at your own convenience when accessing the Tor "
    warn_msg += "anonymizing network, because of known issues with the default settings of "
    warn_msg += "various bundles (e.g. Vidalia)."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))


# Route requests through the Tor service itself, which speaks SOCKS rather than HTTP.
def set_socks_proxy_settings():
  info_msg = "Setting the Tor SOCKS proxy settings."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))

  port = find_local_port((menu.options.tor_port,) if menu.options.tor_port else settings.DEFAULT_TOR_SOCKS_PORTS)
  if not port:
    err_msg = "Could not establish a connection with the Tor SOCKS proxy. "
    err_msg += "Please make sure that you have Tor service installed and set up, "
    err_msg += "so that you are able to successfully use the '--tor' switch."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit(settings.EXIT_FAILURE)

  # SOCKS5 has the names resolved at the other end, where SOCKS4 leaks each one to the local
  # resolver - which is the target's name, asked for by this host, in plain sight.
  socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5 if menu.options.tor_type == settings.PROXY_TYPE.SOCKS5 else socks.PROXY_TYPE_SOCKS4, settings.TOR_HTTP_PROXY_IP, port)
  socks.wrapmodule(_http_client)


# Route requests through Tor, as whichever kind of proxy it is listening as.
def set_proxy_settings():
  if not menu.options.tor:
    return
  tor_type = (menu.options.tor_type or settings.DEFAULT_TOR_TYPE).upper()
  if tor_type not in settings.TOR_TYPES:
    err_msg = "The value of the '--tor-type' option must be one of " + ", ".join("'" + _ + "'" for _ in settings.TOR_TYPES) + "."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit(settings.EXIT_FAILURE)
  menu.options.tor_type = tor_type

  if tor_type == settings.PROXY_TYPE.HTTP:
    set_http_proxy_settings()
  else:
    set_socks_proxy_settings()


# Ask the Tor network itself whether this run is really coming through it.
def do_check():
  if not menu.options.check_tor:
    return

  info_msg = "Checking the Tor connection."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))

  if menu.options.offline:
    err_msg = "You cannot use Tor network while offline."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit(settings.EXIT_FAILURE)

  try:
    request = _urllib.request.Request(settings.CHECK_TOR_API_PAGE, method=settings.HTTPMETHOD.GET)
    response = proxy.use_proxy(request)
    page = response.read().decode(settings.DEFAULT_CODEC)
    is_tor = json.loads(page).get("IsTor")
  except Exception:
    is_tor = None

  if not is_tor:
    err_msg = "It appears that Tor is not properly set. "
    err_msg += "Please try using the '--tor-type' and/or '--tor-port' options."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit(settings.EXIT_FAILURE)

  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "The connection is routed through the Tor network."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))


# eof
