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
import json
import time
import base64
import hashlib
import traceback
from src.utils import menu
from src.utils import settings
from src.thirdparty import six
from src.thirdparty.six.moves import input as _input
from src.thirdparty.six.moves import urllib as _urllib

"""
Invalid cmd output
"""
def invalid_cmd_output(cmd):
  err_msg = "Execution of the '" + cmd + "' command did not return any output."
  return err_msg

"""
Invalid option msg
"""
def invalid_option(option):
  err_msg = "'" + option + "' is not a valid answer."
  settings.print_data_to_stdout(settings.print_error_msg(err_msg))

"""
Reads input from terminal safely
"""
def safe_input(message):
  try:
    return _input(message)
  except UnicodeDecodeError as e:
    return _input(message.encode("utf-8", "ignore").decode("utf-8"))
  except Exception as err_msg:
    settings.print_data_to_stdout(settings.print_error_msg(err_msg))
    return ""

"""
Reads input from terminal
"""
def read_input(message, default=None, check_batch=True):
  def is_empty():
    value = safe_input(settings.print_message(message))
    if len(value) == 0:
      return default
    else:
      return value
  try:
    value = None
    if "\n" in message:
      message += ("\n" if message.count("\n") > 1 else "")
    elif len(message) == 0:
      return is_empty()
    if settings.ANSWERS:
      if not any(_ in settings.ANSWERS for _ in ",="):
        return is_empty()
      else:
        for item in settings.ANSWERS.split(','):
          question = item.split('=')[0].strip()
          answer = item.split('=')[1] if len(item.split('=')) > 1 else None
          if answer and question.lower() in message.lower():
            value = answer
            settings.print_data_to_stdout(settings.print_message(message + str(value)))
            return value
          elif answer is None and value:
            return is_empty()
    if value:
      if settings.VERBOSITY_LEVEL != 0:
        debug_msg = "Used the given answer."
        settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
      settings.print_data_to_stdout(settings.print_message(message + str(value)))
      return value
    elif value is None:
      if check_batch and menu.options.batch:
        settings.print_data_to_stdout(settings.print_message(message + str(default)))
        if settings.VERBOSITY_LEVEL != 0:
          debug_msg = "Used the default behavior, running in batch mode."
          settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
        return default
      else:
        return is_empty()
  except KeyboardInterrupt:
    settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
    raise

"""
Extract regex result
"""
def extract_regex_result(regex, content):
  result = None
  if regex and content and "?P<result>" in regex:
    match = re.search(regex, content)
    if match:
      result = match.group("result")
  return result

"""
Returns True if the current process is run under admin privileges
"""
def running_as_admin():
  is_admin = False
  if settings.PLATFORM in ("posix", "mac"):
    _ = os.geteuid()
    if isinstance(_, (float, six.integer_types)) and _ == 0:
      is_admin = True

  elif settings.IS_WINDOWS:
    import ctypes
    _ = ctypes.windll.shell32.IsUserAnAdmin()
    if isinstance(_, (float, six.integer_types)) and _ == 1:
      is_admin = True
  else:
    err_msg = settings.APPLICATION + " is not able to check if you are running it "
    err_msg += "as an administrator account on this platform. "
    settings.print_data_to_stdout(settings.print_error_msg(err_msg))
    is_admin = True

  return is_admin

"""
Get total number of days from last update
"""
def days_from_last_update():
  days_from_last_update = int(time.time() - os.path.getmtime(settings.SETTINGS_PATH)) // (3600 * 24)
  if days_from_last_update > settings.NAGGING_DAYS:
    warn_msg = "You haven't updated " + settings.APPLICATION + " for more than "
    warn_msg += str(days_from_last_update) + " day"
    warn_msg += "s"[days_from_last_update == 1:] + "!"
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Shows all HTTP error codes raised
"""
def show_http_error_codes():
  if settings.HTTP_ERROR_CODES_SUM and settings.VERBOSITY_LEVEL != 0:
    if any((str(_).startswith('4') or str(_).startswith('5')) and _ != settings.INTERNAL_SERVER_ERROR for _ in settings.HTTP_ERROR_CODES_SUM):
      debug_msg = "Too many 4xx and/or 5xx HTTP error codes "
      debug_msg += "could mean that some kind of protection is involved."
      settings.print_data_to_stdout(settings.print_bold_debug_msg(debug_msg))

"""
Automatically create a Github issue with unhandled exception information.
PS: Greetz @ sqlmap dev team for that great idea! :)
"""
def create_github_issue(err_msg, exc_msg):
  _ = re.sub(r"'[^']+'", "''", exc_msg)
  _ = re.sub(r"\s+line \d+", "", _)
  _ = re.sub(r'File ".+?/(\w+\.py)', r"\g<1>", _)
  _ = re.sub(r".+\Z", "", _)
  _ = re.sub(r"(Unicode[^:]*Error:).+", r"\g<1>", _)
  _ = re.sub(r"= _", "= ", _)
  _ = _.encode(settings.DEFAULT_CODEC)

  key = hashlib.md5(_).hexdigest()[:8]

  bug_report =  "Bug Report: Unhandled exception \"" + str([i for i in exc_msg.split('\n') if i][-1]) + "\" " +  "(#" + key + ")"

  while True:
    try:
      message = "Do you want to automatically create a new (anonymized) issue "
      message += "with the unhandled exception information at "
      message += "the official Github repository? [y/N] "
      choise = read_input(message, default="N", check_batch=True)
      if choise in settings.CHOICE_YES:
        break
      elif choise in settings.CHOICE_NO:
        settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
        return
      else:
        invalid_option(choise)
        pass
    except:
      settings.print_data_to_stdout("")
      raise SystemExit()

  err_msg = err_msg[err_msg.find("\n"):]
  request = _urllib.request.Request(url="https://api.github.com/search/issues?q=" + \
        _urllib.parse.quote("repo:commixproject/commix" + settings.SINGLE_WHITESPACE + str(bug_report))
        )

  try:
    content = _urllib.request.urlopen(request, timeout=settings.TIMEOUT).read()
    _ = json.loads(content)
    duplicate = _["total_count"] > 0
    closed = duplicate and _["items"][0]["state"] == "closed"
    if duplicate:
      warn_msg = "That issue seems to be already reported"
      if closed:
          warn_msg += " and resolved. Please update to the latest "
          warn_msg += "(dev) version from official GitHub repository at '" + settings.GIT_URL + "'"
      warn_msg += ".\n"
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
      return
  except:
    pass

  data = {"title": str(bug_report), "body": "```" + str(err_msg) + "\n```\n```\n" + str(exc_msg) + "```"}
  request = _urllib.request.Request(url = "https://api.github.com/repos/commixproject/commix/issues",
                                data = json.dumps(data).encode(),
                                headers = {settings.AUTHORIZATION: "token " + base64.b64decode(settings.GITHUB_REPORT_OAUTH_TOKEN.encode(settings.DEFAULT_CODEC)).decode()}
                                )
  try:
    content = _urllib.request.urlopen(request, timeout=settings.TIMEOUT).read()
  except Exception as err:
    content = None

  issue_url = re.search(r"https://github.com/commixproject/commix/issues/\d+", content.decode(settings.DEFAULT_CODEC) or "")
  if issue_url:
    info_msg = "The created Github issue can been found at the address '" + str(issue_url.group(0)) + "'.\n"
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  else:
    warn_msg = "Something went wrong while creating a Github issue."
    if settings.UNAUTHORIZED_ERROR in str(err):
      warn_msg += " Please update to the latest revision.\n"
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Masks sensitive data in the supplied message.
"""
def mask_sensitive_data(err_msg):
  for item in settings.SENSITIVE_OPTIONS:
    match = re.search(r"(?i)commix.+(" + str(item) + r")(\s+|=)([^-]+)", err_msg)
    if match:
      err_msg = err_msg.replace(match.group(3), '*' * len(match.group(3)) + settings.SINGLE_WHITESPACE)

  return err_msg

"""
Returns detailed message about occurred unhandled exception.
"""
def unhandled_exception():
  exc_msg = str(traceback.format_exc())

  if "bad marshal data" in exc_msg:
    match = re.search(r"\s*(.+)\s+ValueError", exc_msg)
    err_msg = "Identified corrupted .pyc file(s)."
    err_msg += "Please delete .pyc files on your system to fix the problem."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  elif "must be pinned buffer, not bytearray" in exc_msg:
    err_msg = "Error occurred at Python interpreter which "
    err_msg += "is fixed in 2.7.x. Please update accordingly. "
    err_msg += "(Reference: https://bugs.python.org/issue8104)"
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  elif any(_ in exc_msg for _ in ("MemoryError", "Cannot allocate memory")):
    err_msg = "Memory exhaustion detected."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  elif "Permission denied: '" in exc_msg:
    match = re.search(r"Permission denied: '([^']*)", exc_msg)
    err_msg = "Permission error occurred while accessing file '" + match.group(1) + "'."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  elif all(_ in exc_msg for _ in ("Access is denied", "subprocess", "metasploit")):
    err_msg = "Permission error occurred while running Metasploit."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  elif all(_ in exc_msg for _ in ("Permission denied", "metasploit")):
    err_msg = "Permission error occurred while using Metasploit."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  elif "Invalid argument" in exc_msg:
    err_msg = "Corrupted installation detected. "
    err_msg += "You should retrieve the latest (dev) version from official GitHub "
    err_msg += "repository at '" + settings.GIT_URL + "'."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  elif all(_ in exc_msg for _ in ("No such file", "_'")):
    err_msg = "Corrupted installation detected ('" + exc_msg.strip().split('\n')[-1] + "'). "
    err_msg += "You should retrieve the latest (dev) version from official GitHub "
    err_msg += "repository at '" + settings.GIT_URL + "'."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  elif "Invalid IPv6 URL" in exc_msg:
    err_msg = "invalid URL ('" + exc_msg.strip().split('\n')[-1] + "')"
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  elif any(_ in exc_msg for _ in ("Broken pipe",)):
    raise SystemExit()

  elif any(_ in exc_msg for _ in ("The paging file is too small",)):
    err_msg = "No space left for paging file."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  elif all(_ in exc_msg for _ in ("SyntaxError: Non-ASCII character", ".py on line", "but no encoding declared")) or \
       any(_ in exc_msg for _ in ("source code string cannot contain null bytes", "No module named")) or \
       any(_ in exc_msg for _ in ("ImportError", "ModuleNotFoundError", "<frozen", "Can't find file for module")):
    err_msg = "Invalid runtime environment ('" + exc_msg.split("Error: ")[-1].strip() + "')."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  elif any(_ in exc_msg for _ in ("No space left", "Disk quota exceeded", "Disk full while accessing")):
    err_msg = "No space left on output device."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  elif "Read-only file system" in exc_msg:
    err_msg = "Output device is mounted as read-only."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  elif "OperationalError: disk I/O error" in exc_msg:
    err_msg = "I/O error on output device."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  elif "Violation of BIDI" in exc_msg:
    err_msg = "Invalid URL (violation of Bidi IDNA rule - RFC 5893)."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  elif any(_ in exc_msg for _ in ("tempfile.mkdtemp", "tempfile.mkstemp", "tempfile.py")):
    err_msg = "Unable to write to the temporary directory. "
    err_msg += "Please make sure your disk is not full and "
    err_msg += "that you have sufficient permissions to "
    err_msg += "create temporary files and/or directories."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  else:
    err_msg = "Unhandled exception occurred in '" + settings.VERSION[1:] + "'. It is recommended to retry your "
    err_msg += "run with the latest (dev) version from official GitHub "
    err_msg += "repository at '" + settings.GIT_URL + "'. If the exception persists, please open a new issue "
    err_msg += "at '" + settings.ISSUES_PAGE + "' "
    err_msg += "with the following text and any other information required to "
    err_msg += "reproduce the bug. The "
    err_msg += "developers will try to reproduce the bug, fix it accordingly "
    err_msg += "and get back to you.\n"
    err_msg += settings.APPLICATION.capitalize() + " version: " + settings.VERSION[1:] + "\n"
    err_msg += "Python version: " + settings.PYTHON_VERSION + "\n"
    err_msg += "Operating system: " + os.name + "\n"
    err_msg += "Command line: " + re.sub(r".+?\bcommix\.py\b", "commix.py", " ".join(sys.argv)) + "\n"
    err_msg = mask_sensitive_data(err_msg)
    exc_msg = re.sub(r'".+?[/\\](\w+\.py)', r"\"\g<1>", exc_msg)
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg + "\n" + exc_msg.rstrip()))
    create_github_issue(err_msg, exc_msg[:])

"""
Load a list of non-empty lines from a text file.
"""
def load_list_from_file(file_path, description="file"):

  if not os.path.isfile(file_path):
    err_msg = "The " + description + " '" + file_path + "' was not found."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  try:
    with open(file_path, "r", encoding="utf-8") as f:
      items = [line.strip() for line in f if line.strip()]
  except IOError:
    err_msg = "Cannot read the " + description + " '" + file_path + "'. "
    err_msg += "Check if the file is corrupted or unreadable."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  if not items:
    err_msg = "The " + description + " '" + file_path + "' is empty."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  if settings.VERBOSITY_LEVEL > 0:
    debug_msg = "Loaded " + str(len(items)) + " entries from " + description + " '" + file_path + "'."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

  return items


# eof