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
from base64 import b64encode
from src.core.parse import cmdline as menu
from src.utils import settings
from src.core.requests import requests
from src.core.requests import redirection
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.six.moves import http_client as _http_client
from src.thirdparty.socks import socks

"""
Read the proxies of '--proxy-file', one per line, in the order they were written.

An entry carries what '--proxy' would: a scheme, credentials of its own, an address and a port -
so a SOCKS entry is not quietly read as HTTP, and a proxy that wants a password keeps it.
"""
def load_proxy_list():
  if not os.path.isfile(menu.options.proxy_file):
    err_msg = "It seems the '" + menu.options.proxy_file + "' file does not exist."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()
  with open(menu.options.proxy_file, encoding=settings.DEFAULT_CODEC, errors="replace") as file:
    content = file.read()
  for match in re.finditer(r"(?i)((http[^:\s]*|socks[^:\s]*)://)?(?:([^:@\s/]+:[^@\s/]*)@)?([\w\-.]+):(\d+)", content):
    _, scheme, cred, address, port = match.groups()
    settings.PROXY_LIST.append((scheme or "http", cred, address, port))
  if not settings.PROXY_LIST:
    err_msg = "No proxy was found in the '" + menu.options.proxy_file + "' file."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()
  info_msg = "Loaded " + str(len(settings.PROXY_LIST)) + " prox" + ("ies" if len(settings.PROXY_LIST) != 1 else "y")
  info_msg += " from the '" + os.path.split(menu.options.proxy_file)[1] + "' file."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  apply_proxy_from_list()

"""
Put the proxy the list is currently on in place, as though it had been given with '--proxy'.
"""
def apply_proxy_from_list():
  if not settings.PROXY_LIST:
    return
  scheme, cred, address, port = settings.PROXY_LIST[settings.PROXY_LIST_INDEX % len(settings.PROXY_LIST)]
  settings.PROXY_SCHEME = scheme
  menu.options.proxy = address + ":" + port
  # Credentials written next to the proxy itself outrank '--proxy-cred', which speaks for the rest.
  if cred:
    menu.options.proxy_cred = cred
  configure()

"""
Move on to the next proxy of the list, which is what '--proxy-freq' asks for every so many requests.
"""
def rotate_proxy():
  if len(settings.PROXY_LIST) < 2:
    return
  settings.PROXY_LIST_INDEX += 1
  apply_proxy_from_list()
  warn_msg = "Changing the proxy to '" + settings.PROXY_SCHEME + "://" + menu.options.proxy + "'."
  settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Whether the proxy in use speaks SOCKS, which is carried at the socket rather than by a handler.
"""
def is_socks():
  return (settings.PROXY_SCHEME or "").lower() in settings.SOCKS_SCHEMES

"""
The credentials of '--proxy-cred', as the pair they are made of.
"""
def credentials():
  if not menu.options.proxy_cred:
    return None, None
  match = re.search(r"\A(.*?):(.*?)\Z", menu.options.proxy_cred)
  if not match:
    err_msg = "The option '--proxy-cred' must be in format 'username:password'."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()
  return match.group(1), match.group(2)

"""
Put the proxy the options describe in place: SOCKS is spoken by the socket every request is made
on, while an HTTP proxy is named on the request itself.
"""
def configure():
  scheme = (settings.PROXY_SCHEME or "http").lower()
  if scheme not in settings.PROXY_SCHEMES:
    err_msg = "Proxy value must be in format '(" + "|".join(settings.PROXY_SCHEMES) + ")://address:port'."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  if scheme in settings.SOCKS_SCHEMES:
    username, password = credentials()
    address, _, port = menu.options.proxy.rpartition(":")
    # SOCKS4 has each name resolved by this host rather than at the other end, so the target's name
    # is asked for in plain sight - said once, rather than on every request it holds for.
    if scheme == "socks4" and not settings.SOCKS4_DNS_WARNING:
      settings.SOCKS4_DNS_WARNING = True
      warn_msg = "SOCKS4 does not support resolving (DNS) names, which leaks them to the local resolver."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5 if scheme == "socks5" else socks.PROXY_TYPE_SOCKS4, address, int(port), username=username, password=password)
    socks.wrapmodule(_http_client)
  else:
    try:
      socks.unwrapmodule(_http_client)
    except Exception:
      pass

"""
Name the proxy on one request, where it is an HTTP proxy - a SOCKS one is already carried beneath it.
"""
def apply_to_request(request):
  if not menu.options.proxy or is_socks():
    return
  request.set_proxy(menu.options.proxy, settings.SCHEME)
  header = authorization_header()
  if header:
    request.add_unredirected_header("Proxy-Authorization", header)

"""
The credentials a proxy asks for, as the header that carries them.
"""
def authorization_header():
  if not menu.options.proxy_cred:
    return None
  if ":" not in menu.options.proxy_cred:
    err_msg = "The option '--proxy-cred' must be in format 'username:password'."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()
  return "Basic " + b64encode(menu.options.proxy_cred.encode(settings.DEFAULT_CODEC)).decode().replace(settings.END_LINE.LF, "")

"""
Use the defined HTTP Proxy
"""
def use_proxy(request):
  try:
    if menu.options.ignore_proxy:
      proxy = _urllib.request.ProxyHandler({})
      opener = _urllib.request.build_opener(proxy, redirection.RedirectHandler(), _urllib.request.HTTPSHandler(context=settings.unverified_context()))
      _urllib.request.install_opener(opener)
    elif menu.options.tor and menu.options.tor_type == settings.PROXY_TYPE.HTTP:
      proxy = _urllib.request.ProxyHandler({settings.SCHEME:menu.options.proxy})
      opener = _urllib.request.build_opener(proxy, redirection.RedirectHandler(), _urllib.request.HTTPSHandler(context=settings.unverified_context()))
      _urllib.request.install_opener(opener)
    else:
      apply_to_request(request)
    return _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
  except Exception as err_msg:
    return requests.request_failed(err_msg)

"""
 Check if HTTP Proxy is defined.
"""
def do_check():
  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Setting the HTTP proxy for all HTTP requests. "
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

# eof
