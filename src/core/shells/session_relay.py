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

import sys
import socket
import threading
from src.utils import common
from src.utils import settings

# How long the built-in reverse handler waits for the callback before giving up.
ACCEPT_TIMEOUT = 15

"""
Runs execute_cmd(cmd) on a background thread so the main thread stays free to accept() the callback.
"""
def run_payload_send(execute_cmd, cmd, result):
  if settings.VERBOSITY_LEVEL == 0:
    threading.current_thread().commix_suppress_output = True
  try:
    result["shell"] = execute_cmd(cmd)
  except (Exception, SystemExit) as err:
    # Output is suppressed on this thread, so hand the reason back for the caller to report.
    result["error"] = err

"""
Bridges local stdin/stdout to a connected shell socket - line-buffered, not raw-TTY.
"""
def interactive_relay(sock, filename, url):
  remote_closed = threading.Event()

  # Carry whatever the socket says back to the terminal, until it says nothing more.
  def _reader():
    try:
      while True:
        data = sock.recv(4096)
        if not data:
          break
        with settings.PRINT_LOCK:
          settings._stdout_write(data.decode(settings.DEFAULT_CODEC, errors="replace"))
          sys.stdout.flush()
    except Exception:
      pass
    finally:
      remote_closed.set()

  threading.Thread(target=_reader, daemon=True).start()

  try:
    while not remote_closed.is_set():
      try:
        line = common.safe_input("")
      except KeyboardInterrupt:
        from src.core.controller import shell_options
        shell_options.back_or_quit_prompt("Session interrupted (Ctrl-C pressed). [(b)ack/(q)uit] ", filename, url)
        break
      except EOFError:
        break
      if remote_closed.is_set():
        settings.print_data_to_stdout(settings.print_info_msg("Session closed by the remote host."))
        break
      try:
        sock.sendall((line + "\n").encode(settings.DEFAULT_CODEC, "replace"))
      except (OSError, socket.error):
        settings.print_data_to_stdout(settings.print_info_msg("Session closed by the remote host."))
        break
  finally:
    # shutdown() before close() forces the EOF that makes the remote shell exit.
    try:
      sock.shutdown(socket.SHUT_RDWR)
    except Exception:
      pass
    try:
      sock.close()
    except Exception:
      pass

# eof
