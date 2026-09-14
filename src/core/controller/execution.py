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
from src.core.requests import requests
from src.core.controller import checks

"""
Select the injector module for the given technique.
"""
def select_injector(technique):
  if technique == settings.INJECTION_TECHNIQUE.CLASSIC:
    from src.core.techniques.classic import cb_injector as injector
  elif technique == settings.INJECTION_TECHNIQUE.DYNAMIC_CODE:
    from src.core.eval import eb_injector as injector
  elif technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
    from src.core.techniques.time_based import tb_injector as injector
  elif technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
    from src.core.techniques.file_based import fb_injector as injector
  elif technique == settings.INJECTION_TECHNIQUE.OOB:
    from src.core.techniques.oob import oob_injector as injector
  else:
    from src.core.techniques.tempfile_based import tfb_injector as injector
  return injector

"""
Select the payloads module for the given time-related technique.
"""
def select_payloads_module(technique):
  if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
    payloads = checks.time_based_payloads()
  else:
    payloads = checks.tempfile_based_payloads()
  return payloads

"""
Build the Windows-specific command variant for time-related techniques, returning (cmd, previous_cmd).
"""
def windows_transform_cmd(cmd, technique, interpreter):
  previous_cmd = cmd
  if interpreter:
    if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
      cmd = settings.WIN_PYTHON_INTERPRETER + " -c \"import os; print len(os.popen('cmd /c " + cmd + "').read().strip())\""
    else:
      cmd = checks.quoted_cmd(cmd)
  elif technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
    # 'write', not 'write-host': the value is read back off the payload's own standard output, and
    # only the newer PowerShell writes what the latter prints there at all.
    cmd = "powershell.exe -InputFormat none write ([string](cmd /c " + cmd + ")).trim().length"
  # The tempfile-based payloads wrap the command themselves, in the one PowerShell they already
  # start - wrapping it here as well would cost a second process per probe, and the timing
  # measurement pays for every one of them.
  return cmd, previous_cmd

"""
Build a cache-less execute_cmd(cmd) -> output callback around the injector model, for callers (e.g. file writes) where re-running the command every time is required, not an optimization to skip.
"""
def make_simple_execute_cmd(injector, separator, maxlen, TAG, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, interpreter, filename, url_time_response, technique, OUTPUT_TEXTFILE, postprocess_time=lambda shell: shell, catch_time_error=False, results_based_injector=False):
  """
  'results_based_injector' is for a caller that has swapped in the classic injector under a
  time-related technique - the Windows file write does. How the command is sent is the injector's
  to say, and calling a results-based one with the time-related argument list raises TypeError.
  """
  def execute_cmd(cmd):
    if technique == settings.INJECTION_TECHNIQUE.OOB:
      return injector.injection(separator, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter)
    if settings.TIME_RELATED_ATTACK and not results_based_injector:
      try:
        if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
          check_exec_time, shell = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, interpreter, filename, url_time_response, technique)
        else:
          check_exec_time, shell = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, url_time_response, technique)
      except TypeError:
        if not catch_time_error:
          raise
        shell = ""
      return postprocess_time(shell)
    else:
      if technique == settings.INJECTION_TECHNIQUE.FILE_BASED and not results_based_injector:
        response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, interpreter, filename, technique)
      else:
        response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, interpreter, filename, technique)
        if settings.URL_RELOAD:
          response = requests.url_reload(url, timesec)
      shell = injector.injection_results(response, TAG, cmd, technique, url, OUTPUT_TEXTFILE, timesec)
      return "".join(str(p) for p in shell)
  return execute_cmd

"""
Build an execute_cmd(cmd) -> (output, fresh) callback around the injector model, with session caching - the shared logic behind every enumeration.py check.
"""
def make_execute_cmd(injector, separator, maxlen, TAG, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, interpreter, filename, url_time_response, technique, OUTPUT_TEXTFILE, postprocess=lambda shell: shell, postprocess_time=lambda shell: shell, catch_time_error=False):
  fire = make_simple_execute_cmd(injector, separator, maxlen, TAG, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, interpreter, filename, url_time_response, technique, OUTPUT_TEXTFILE, postprocess_time, catch_time_error)
  # Run one command, reusing a stored answer where the session already holds one.
  def execute_cmd(cmd):
    stored = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
    fresh = not checks.usable_stored_cmd(stored) or menu.options.ignore_session
    if fresh:
      shell = fire(cmd)
      if not settings.TIME_RELATED_ATTACK:
        shell = postprocess(shell)
      if shell:
        session_handler.store_cmd(url, cmd, shell, vuln_parameter)
    else:
      shell = stored
    return shell, fresh
  return execute_cmd

# eof
