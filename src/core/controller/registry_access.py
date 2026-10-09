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
from src.core.controller import checks
from src.core.controller import execution

"""
Read a Windows registry key value.
"""
def registry_read(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique):
  injector = execution.select_injector(technique)
  cmd, key, value = checks.registry_read_cmd()
  execute_cmd = execution.make_execute_cmd(injector, separator, maxlen, TAG, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, interpreter, filename, url_time_response, technique, OUTPUT_TEXTFILE, catch_time_error=True)
  shell, fresh = execute_cmd(cmd)
  checks.registry_read_status(shell, key, value, filename, settings.TIME_RELATED_ATTACK and fresh)

"""
Write a Windows registry key value.
"""
def registry_write(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique):
  injector = execution.select_injector(technique)
  cmd, key, value = checks.registry_write_cmd()
  execute_cmd = execution.make_execute_cmd(injector, separator, maxlen, TAG, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, interpreter, filename, url_time_response, technique, OUTPUT_TEXTFILE, catch_time_error=True)
  shell, fresh = execute_cmd(cmd)
  written = checks.registry_write_status(shell, key, value, settings.TIME_RELATED_ATTACK and fresh)
  # Done right away, not deferred to quit() - see the matching note in file_access.py's file_write().
  if written and menu.options.cleanup:
    checks.cleanup_registry_value(lambda c: execute_cmd(c)[0], key, value)

"""
Delete a Windows registry key, or a single value of it.
"""
def registry_delete(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique):
  injector = execution.select_injector(technique)
  cmd, key, value = checks.registry_delete_cmd()
  execute_cmd = execution.make_execute_cmd(injector, separator, maxlen, TAG, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, interpreter, filename, url_time_response, technique, OUTPUT_TEXTFILE, catch_time_error=True)
  shell, fresh = execute_cmd(cmd)
  checks.registry_delete_status(shell, key, value, settings.TIME_RELATED_ATTACK and fresh)

"""
Check the defined options
"""
def do_check(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique):
  if settings.TARGET_OS != settings.OS.WINDOWS:
    warn_msg = "The registry access options only apply to a Windows target, so they are skipped here."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    settings.REGISTRY_ACCESS_DONE = True
    return

  if menu.options.reg_add:
    registry_write(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique)
    settings.REGISTRY_ACCESS_DONE = True

  if menu.options.reg_read:
    registry_read(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique)
    settings.REGISTRY_ACCESS_DONE = True

  if menu.options.reg_del:
    registry_delete(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique)
    settings.REGISTRY_ACCESS_DONE = True

"""
Check stored session
"""
def stored_session(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique):
  # Target-wide - run once, on the first successful technique.
  if not settings.REGISTRY_ACCESS_DONE and menu.registry_options():
    do_check(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique)

# eof
