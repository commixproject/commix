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
import os
import re
import sys
import time
import tempfile
import sqlite3
from datetime import date
from datetime import datetime
from src.utils import menu
from src.utils import common
from src.utils import settings
from src.utils import session_handler
from src.core.injections.controller import checks
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.colorama import Fore, Back, Style, init

"""
1. Generate injection logs (logs.txt) in "./ouput" file.
2. Check for logs updates and apply if any!
"""

"""
Directory creation
"""
def path_creation(path):
  if not os.path.exists(path):
    try:
      os.mkdir(path)
    except OSError as err_msg:
      try:
        error_msg = str(err_msg).split("] ")[1] + "."
      except IndexError:
        error_msg = str(err_msg) + "."
      settings.print_data_to_stdout(settings.print_critical_msg(error_msg))
      raise SystemExit()

"""
Logs filename creation.
"""
def logs_filename_creation(url):
  output_dir = menu.options.output_dir

  if output_dir:
    output_dir = os.path.abspath(output_dir)
    if os.path.isdir(output_dir):
      info_msg = "Using output directory '" + output_dir + "'."
      settings.print_data_to_stdout(settings.print_info_msg(info_msg))
    else:
      try:
        os.makedirs(output_dir, exist_ok=True)
        info_msg = "Created missing output directory '" + output_dir + "'."
        settings.print_data_to_stdout(settings.print_info_msg(info_msg))
      except OSError:
        error_msg = "Unable to create missing output directory '" + output_dir + "'."
        settings.print_data_to_stdout(settings.print_error_msg(error_msg))
        try:
          output_dir = tempfile.mkdtemp(prefix=settings.APPLICATION)
          warn_msg = "Using temporary output directory '" + output_dir + "' instead."
          settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
        except (OSError, RuntimeError):
          common.unhandled_exception()
  else:
    output_dir = settings.OUTPUT_DIR
    path_creation(os.path.dirname(output_dir))

  # Ensure path ends with OS-specific separator
  output_dir = os.path.join(output_dir, '')

  # Create the logs filename
  return create_log_file(url, output_dir)

"""
Create log files
"""
def create_log_file(url, output_dir):
  host = _urllib.parse.urlparse(url).netloc.replace(":","_") + "/"
  logs_path = output_dir + host

  path_creation(logs_path)

  # Create cli history file if does not exist.
  settings.CLI_HISTORY = logs_path + "cli_history"
  if not os.path.exists(settings.CLI_HISTORY):
    open(settings.CLI_HISTORY,'a').close()

  if menu.options.session_file is not None:
    if os.path.exists(menu.options.session_file):
      settings.SESSION_FILE = menu.options.session_file
    else:
      err_msg = "The provided session file ('" + menu.options.session_file + "') does not exist."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()
  else:
    settings.SESSION_FILE = logs_path + "session.db"

  # Load command history
  if settings.LOAD_SESSION == True and os.path.exists(settings.CLI_HISTORY):
    checks.load_cmd_history()

  # The logs filename construction.
  filename = logs_path + settings.OUTPUT_FILE
  try:
    with open(filename, 'a', encoding=settings.DEFAULT_CODEC) as output_file:
      if not menu.options.no_logging:
        output_file.write("\n" + "=" * 37)
        output_file.write("\n" + "| Started in " + \
          str(date.today()) + \
          " at " + datetime.now().strftime("%H:%M:%S") + " |")
        output_file.write("\n" + "=" * 37)
        output_file.write("\n" + re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + "Tested URL : " + url)
  except IOError as err_msg:
    try:
      error_msg = str(err_msg.args[0]).split("] ")[1] + "."
    except:
      error_msg = str(err_msg.args[0]) + "."
    settings.print_data_to_stdout(settings.print_critical_msg(error_msg))
    raise SystemExit()

  if not menu.options.output_dir:
    filename = os.path.abspath(filename)
    
  return filename

"""
Add the injection type / technique in log files.
"""
def add_type_and_technique(export_injection_info, filename, injection_type, technique):

  if export_injection_info == False:
    settings.SHOW_LOGS_MSG = True
    with open(filename, 'a', encoding=settings.DEFAULT_CODEC) as output_file:
      if not menu.options.no_logging:
        output_file.write("\n" + re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + "Type: " + injection_type.title())
        output_file.write("\n" + re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + "Technique: " + technique.title())
      export_injection_info = True
  return export_injection_info

"""
Add the vulnerable parameter in log files.
"""
def add_parameter(vp_flag, filename, the_type, header_name, http_request_method, vuln_parameter, payload):
  with open(filename, 'a', encoding=settings.DEFAULT_CODEC) as output_file:
    if not menu.options.no_logging:
      if header_name[1:] == settings.COOKIE.lower():
        header_name = " ("+ header_name[1:] + ") " + vuln_parameter
      if header_name[1:] == "":
        header_name = " ("+ http_request_method + ") " + vuln_parameter
      output_file.write("\n" + re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + the_type[1:].title() + ": " + header_name[1:])
      vp_flag = False
      output_file.write("\n")


"""
Add any payload in log files.
"""
def update_payload(filename, counter, payload):
  with open(filename, 'a', encoding=settings.DEFAULT_CODEC) as output_file:
    if not menu.options.no_logging:
      if "\n" in payload:
        output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + "Used payload: " + re.sub("%20", settings.SINGLE_WHITESPACE, _urllib.parse.unquote_plus(payload.replace("\n", "\\n"))) + "\n")
      else:
        output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + "Used payload: " + payload.replace("%20", settings.SINGLE_WHITESPACE) + "\n")

"""
Add any executed command and
execution output result in log files.
"""
def executed_command(filename, cmd, output):
  try:
    with open(filename, 'a', encoding=settings.DEFAULT_CODEC) as output_file:
      if not menu.options.no_logging:
        output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + "Executed command: " +  cmd + "\n")
        output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_SIGN) + "Execution output: " + str(output.encode(settings.DEFAULT_CODEC).decode()) + "\n")
  except:
    pass

"""
Fetched data logged to text files.
"""
def logs_notification(filename):
  # Save command history.
  if not menu.options.no_logging:
    info_msg = "Fetched data logged to text files under '" + filename + "'."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))

"""
Log all HTTP traffic into a textual file.
"""
def log_traffic(header):
  output_file = open(menu.options.traffic_file, "a")
  output_file.write(header)
  output_file.close()

"""
Print logs notification.
"""
def print_logs_notification(filename, url):
  if os.path.exists(settings.CLI_HISTORY):
    checks.save_cmd_history()
  if settings.SHOW_LOGS_MSG == True and not menu.options.no_logging:
    if not settings.LOAD_SESSION:
      logs_notification(filename)
  if url:
    session_handler.clear(url)

# eof