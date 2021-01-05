#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2021 Anastasios Stasinopoulos (@ancst).

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
import sqlite3
import datetime
from src.utils import menu
from src.utils import settings
from src.utils import session_handler
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.colorama import Fore, Back, Style, init

readline_error = False
if settings.IS_WINDOWS:
  try:
    import readline
  except ImportError:
    try:
      import pyreadline as readline
    except ImportError:
      readline_error = True
else:
  try:
    import readline
    if getattr(readline, '__doc__', '') is not None and 'libedit' in getattr(readline, '__doc__', ''):
      import gnureadline as readline
  except ImportError:
    try:
      import gnureadline as readline
    except ImportError:
      readline_error = True
pass

"""
1. Generate injection logs (logs.txt) in "./ouput" file.
2. Check for logs updates and apply if any!
"""

"""
Save command history.
"""
def save_cmd_history():
  try:
    cli_history = os.path.expanduser(settings.CLI_HISTORY)
    if os.path.exists(cli_history):
      readline.write_history_file(cli_history)
  except (IOError, AttributeError) as e:
    warn_msg = "There was a problem writing the history file '" + cli_history + "'."
    print(settings.print_warning_msg(warn_msg))

"""
Load commands from history.
"""
def load_cmd_history():
  try:
    cli_history = os.path.expanduser(settings.CLI_HISTORY)
    if os.path.exists(cli_history):
      readline.read_history_file(cli_history)
  except (IOError, AttributeError) as e:
    warn_msg = "There was a problem loading the history file '" + cli_history + "'."
    print(settings.print_warning_msg(warn_msg))

"""
Create log files
"""
def create_log_file(url, output_dir):
  if not output_dir.endswith("/"):
    output_dir = output_dir + "/"

  parts = url.split('//', 1)
  try:
    host = parts[1].split('/', 1)[0]
  except IndexError:
    host = parts[0].split('/', 1)[0]
  except OSError as err_msg:
    try:
      error_msg = str(err_msg.args[0]).split("] ")[1] + "."
    except:
      error_msg = str(err_msg.args[0]) + "."
    print(settings.print_critical_msg(error_msg))
    raise SystemExit()
      
  # Check if port is defined to host.
  if ":" in host:
    host = host.replace(":","_")
  try:
    os.stat(output_dir + host + "/")
  except:
    try:
      os.mkdir(output_dir + host + "/")
    except Exception as err_msg:
      try:
        error_msg = str(err_msg.args[0]).split("] ")[1] + "."
      except:
        error_msg = str(err_msg.args[0]) + "."
      print(settings.print_critical_msg(error_msg))
      raise SystemExit()

  # Create cli history file if does not exist.
  settings.CLI_HISTORY = output_dir + host + "/" + "cli_history"
  if not os.path.exists(settings.CLI_HISTORY):
      open(settings.CLI_HISTORY,'a').close()

  if menu.options.session_file is not None:
    if os.path.exists(menu.options.session_file):
      settings.SESSION_FILE = menu.options.session_file
    else:
       err_msg = "The provided session file ('" + \
                    menu.options.session_file + \
                    "') does not exist." 
       print(settings.print_critical_msg(err_msg))
       raise SystemExit()
  else:  
    settings.SESSION_FILE = output_dir + host + "/" + "session" + ".db"

  # Load command history
  load_cmd_history()

  # The logs filename construction.
  filename = output_dir + host + "/" + settings.OUTPUT_FILE
  try:
    output_file = open(filename, "a")
    output_file.write("\n" + "=" * 37)
    output_file.write("\n" + "| Started in " + \
      datetime.datetime.fromtimestamp(time.time()).strftime('%m/%d/%Y' + \
      " at " + '%H:%M:%S' + " |"))
    output_file.write("\n" + "=" * 37)
    output_file.write("\n" + re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + "Tested URL : " + url)
    output_file.close()
  except IOError as err_msg:
    try:
      error_msg = str(err_msg.args[0]).split("] ")[1] + "."
    except:
      error_msg = str(err_msg.args[0]) + "."
    print(settings.print_critical_msg(error_msg))
    raise SystemExit()
      
  return filename

"""
Add the injection type / technique in log files.
"""
def add_type_and_technique(export_injection_info, filename, injection_type, technique):
  if export_injection_info == False:
    settings.SHOW_LOGS_MSG = True
    output_file = open(filename, "a")
    output_file.write("\n" + re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + "Type: " + injection_type.title())
    output_file.write("\n" + re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + "Technique: " + technique.title())
    output_file.close()
    export_injection_info = True

  return export_injection_info

"""
Add the vulnerable parameter in log files.
"""
def add_parameter(vp_flag, filename, the_type, header_name, http_request_method, vuln_parameter, payload):
  output_file = open(filename, "a")
  if header_name[1:] == "cookie":
    header_name = " ("+ header_name[1:] + ") " + vuln_parameter
  if header_name[1:] == "":
    header_name = " ("+ http_request_method + ") " + vuln_parameter
  output_file.write("\n" + re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + the_type[1:].title() + ": " + header_name[1:])
  vp_flag = False
  output_file.write("\n")
  output_file.close()

"""
Add any payload in log files.
"""
def update_payload(filename, counter, payload):
  output_file = open(filename, "a")
  if "\n" in payload:
    output_file.write("    (" +str(counter)+ ") Payload: " + re.sub("%20", " ", _urllib.parse.unquote_plus(payload.replace("\n", "\\n"))) + "\n")
  else:
    output_file.write("    (" +str(counter)+ ") Payload: " + payload.replace("%20", " ") + "\n")
  output_file.close()

"""
Add any executed command and 
execution output result in log files.
"""
def executed_command(filename, cmd, output):
  try:
    output_file = open(filename, "a")
    output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + "Executed command: " +  cmd + "\n")
    output_file.write("    " + re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_SIGN) + "Execution output: " +  output + "\n")
    output_file.close()
  except TypeError:
    pass

"""
Fetched data logged to text files.
"""
def logs_notification(filename):
  # Save command history.
  info_msg = "Fetched data logged to text files under '" + os.getcwd() + "/" + filename + "'."
  print(settings.print_info_msg(info_msg))

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
  save_cmd_history()
  if settings.SHOW_LOGS_MSG == True:
    logs_notification(filename)
  if url:
    session_handler.clear(url)

# eof