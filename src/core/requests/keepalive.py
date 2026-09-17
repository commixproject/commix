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

import threading
from socket import error as SocketError
from src.thirdparty.six.moves import http_client as _http_client
from src.thirdparty.six.moves import urllib as _urllib

"""
Persistent (Keep-Alive) connections, reusing one socket per thread and origin.
"""

# Keyed by thread, so workers never share a socket.
_CONNECTIONS = {}
_LOCK = threading.Lock()

# A pooled socket that turned out to be unusable.
STALE_ERRORS = (SocketError, _http_client.BadStatusLine, _http_client.CannotSendRequest,
                _http_client.ResponseNotReady, _http_client.RemoteDisconnected,
                _http_client.ImproperConnectionState)

"""
The origin a connection can be reused for.
"""
def _key(req):
  return (threading.current_thread().ident, req.type, req.host, req._tunnel_host)

"""
Reusable only while the socket is up and the last response fully read.
"""
def _reusable(entry):
  connection, response = entry
  if connection.sock is None:
    return False
  return response is None or response.isclosed()

"""
Drop a pooled connection.
"""
def _discard(key):
  with _LOCK:
    entry = _CONNECTIONS.pop(key, None)
  if entry:
    try:
      entry[0].close()
    except Exception:
      pass

"""
Close every pooled connection.
"""
def close_all():
  with _LOCK:
    entries = list(_CONNECTIONS.values())
    _CONNECTIONS.clear()
  for connection, _ in entries:
    try:
      connection.close()
    except Exception:
      pass

"""
A pooled connection for the request's origin, or a new one.
"""
def _connection(key, http_class, req, tunnel_headers, http_conn_args, reuse):
  if reuse:
    with _LOCK:
      entry = _CONNECTIONS.get(key)
    if entry and _reusable(entry):
      return entry[0]
    _discard(key)

  connection = http_class(req.host, timeout=req.timeout, **http_conn_args)
  if req._tunnel_host:
    connection.set_tunnel(req._tunnel_host, headers=tunnel_headers)
  with _LOCK:
    _CONNECTIONS[key] = (connection, None)
  return connection

"""
The pooling counterpart of urllib's do_open().
"""
def do_open(handler, http_class, req, **http_conn_args):
  if not req.host:
    raise _urllib.error.URLError("no host given")

  headers = dict(req.unredirected_hdrs)
  headers.update({name: value for name, value in req.headers.items() if name not in headers})
  headers["Connection"] = "keep-alive"
  headers = {name.title(): value for name, value in headers.items()}

  tunnel_headers = {}
  if req._tunnel_host and "Proxy-Authorization" in headers:
    tunnel_headers["Proxy-Authorization"] = headers.pop("Proxy-Authorization")

  key = _key(req)
  response = None
  # A dropped socket only shows up on use, so retry once on a new one.
  for reuse in (True, False):
    connection = _connection(key, http_class, req, tunnel_headers, http_conn_args, reuse)
    connection.set_debuglevel(handler._debuglevel)
    try:
      connection.request(req.get_method(), req.selector, req.data, headers,
                         encode_chunked=req.has_header("Transfer-encoding"))
      response = connection.getresponse()
      break
    except STALE_ERRORS as err_msg:
      _discard(key)
      if not reuse:
        raise _urllib.error.URLError(err_msg)
    except Exception:
      _discard(key)
      raise

  if response.will_close:
    _discard(key)
  else:
    with _LOCK:
      _CONNECTIONS[key] = (connection, response)

  response.url = req.get_full_url()
  response.msg = response.reason
  return response

# eof
