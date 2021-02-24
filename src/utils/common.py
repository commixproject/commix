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
from src.thirdparty.six.moves import input as _input
from src.thirdparty.six.moves import urllib as _urllib

"""
Get total number of days from last update
"""
def days_from_last_update():
  days_from_last_update = int(time.time() - os.path.getmtime(settings.SETTINGS_PATH)) // (3600 * 24)
  if days_from_last_update > settings.NAGGING_DAYS:
    warn_msg = "You haven't updated " + settings.APPLICATION + " for more than "
    warn_msg += str(days_from_last_update) + " day"
    warn_msg += "s"[days_from_last_update == 1:] + "!"
    print(settings.print_warning_msg(warn_msg))

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
  _ = _.encode(settings.UNICODE_ENCODING)
  
  bug_report =  "Bug Report: Unhandled exception \"" + str([i for i in exc_msg.split('\n') if i][-1]) + "\""

  while True:
    try:
      if not menu.options.batch:
        question_msg = "Do you want to automatically create a new (anonymized) issue "
        question_msg += "with the unhandled exception information at "
        question_msg += "the official Github repository? [y/N] "
        choise = _input(settings.print_question_msg(question_msg))
      else:
        choise = ""
      if len(choise) == 0:
        choise = "n"
      if choise in settings.CHOICE_YES:
        break
      elif choise in settings.CHOICE_NO:
        print("")
        return
      else:
        err_msg = "'" + choise + "' is not a valid answer."  
        print(settings.print_error_msg(err_msg))
        pass
    except: 
      print("\n")
      raise SystemExit()

  err_msg = err_msg[err_msg.find("\n"):]
  request = _urllib.request.Request(url="https://api.github.com/search/issues?q=" + \
        _urllib.parse.quote("repo:commixproject/commix" + " " + str(bug_report))
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
      print(settings.print_warning_msg(warn_msg))
      return
  except:
    pass

  data = {"title": str(bug_report), "body": "```" + str(err_msg) + "\n```\n```\n" + str(exc_msg) + "```"}
  request = _urllib.request.Request(url = "https://api.github.com/repos/commixproject/commix/issues", 
                                data = json.dumps(data).encode(), 
                                headers = {"Authorization": "token " + base64.b64decode(settings.GITHUB_REPORT_OAUTH_TOKEN.encode(settings.UNICODE_ENCODING)).decode()}
                                )
  try:
    content = _urllib.request.urlopen(request, timeout=settings.TIMEOUT).read()
  except Exception as err:
    content = None

  issue_url = re.search(r"https://github.com/commixproject/commix/issues/\d+", content.decode(settings.UNICODE_ENCODING) or "")
  if issue_url:
    info_msg = "The created Github issue can been found at the address '" + str(issue_url.group(0)) + "'.\n"
    print(settings.print_info_msg(info_msg))
  else:
    warn_msg = "Something went wrong while creating a Github issue."
    if settings.UNAUTHORIZED_ERROR in str(err):
      warn_msg += " Please update to the latest revision.\n"
    print(settings.print_warning_msg(warn_msg))

"""
Masks sensitive data in the supplied message.
"""
def mask_sensitive_data(err_msg):
  for item in settings.SENSITIVE_OPTIONS:
    match = re.search(r"(?i)commix.+("+str(item)+")(\s+|=)([^ ]+)", err_msg)
    if match:
      err_msg = err_msg.replace(match.group(3), '*' * len(match.group(3)))
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
    print(settings.print_critical_msg(err_msg)) 
    raise SystemExit()

  elif all(_ in exc_msg for _ in ("No such file", "_'")):
    err_msg = "Corrupted installation detected ('" + exc_msg.strip().split('\n')[-1] + "'). "
    err_msg += "You should retrieve the latest development version from official GitHub "
    err_msg += "repository at '" + settings.GIT_URL + "'."
    print(settings.print_critical_msg(err_msg))
    raise SystemExit()

  elif "must be pinned buffer, not bytearray" in exc_msg:
    err_msg = "Error occurred at Python interpreter which "
    err_msg += "is fixed in 2.7.x. Please update accordingly. "
    err_msg += "(Reference: https://bugs.python.org/issue8104)"
    print(settings.print_critical_msg(err_msg))
    raise SystemExit()

  elif "MemoryError" in exc_msg:
    err_msg = "Memory exhaustion detected."
    print(settings.print_critical_msg(err_msg))
    raise SystemExit()

  elif all(_ in exc_msg for _ in ("Access is denied", "subprocess", "metasploit")):
    err_msg = "Permission error occurred while running Metasploit."
    print(settings.print_critical_msg(err_msg))
    raise SystemExit()

  elif all(_ in exc_msg for _ in ("Permission denied", "metasploit")):
    err_msg = "Permission error occurred while using Metasploit."
    print(settings.print_critical_msg(err_msg))
    raise SystemExit()

  elif all(_ in exc_msg for _ in ("No such file", "_'")):
    err_msg = "Corrupted installation detected ('" + exc_msg.strip().split('\n')[-1] + "'). " 
    err_msg += "You should retrieve the latest (dev) version from official GitHub "
    err_msg += "repository at '" + settings.GIT_URL + "'."
    print(settings.print_critical_msg(err_msg))
    raise SystemExit()

  elif "Invalid IPv6 URL" in exc_msg:
    err_msg = "invalid URL ('" + exc_msg.strip().split('\n')[-1] + "')"
    print(settings.print_critical_msg(err_msg))
    raise SystemExit()

  elif any(_ in exc_msg for _ in ("The paging file is too small",)):
    err_msg = "No space left for paging file."
    print(settings.print_critical_msg(err_msg))
    raise SystemExit()

  elif all(_ in exc_msg for _ in ("SyntaxError: Non-ASCII character", ".py on line", "but no encoding declared")) or \
       any(_ in exc_msg for _ in ("source code string cannot contain null bytes", "No module named")) or \
       any(_ in exc_msg for _ in ("ImportError", "ModuleNotFoundError", "Can't find file for module")):
    err_msg = "Invalid runtime environment ('" + exc_msg.split("Error: ")[-1].strip() + "')."
    print(settings.print_critical_msg(err_msg))
    raise SystemExit()

  elif any(_ in exc_msg for _ in ("No space left", "Disk quota exceeded", "Disk full while accessing")):
    err_msg = "No space left on output device."
    print(settings.print_critical_msg(err_msg))
    raise SystemExit()

  elif "Read-only file system" in exc_msg:
    err_msg = "Output device is mounted as read-only."
    print(settings.print_critical_msg(err_msg))
    raise SystemExit()

  elif "OperationalError: disk I/O error" in exc_msg:
    err_msg = "I/O error on output device."
    print(settings.print_critical_msg(err_msg))
    raise SystemExit()

  elif "Violation of BIDI" in exc_msg:
    err_msg = "Invalid URL (violation of Bidi IDNA rule - RFC 5893)."
    print(settings.print_critical_msg(err_msg))
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
    err_msg += "Commix version: " + settings.VERSION[1:] + "\n"
    err_msg += "Python version: " + settings.PYTHON_VERSION + "\n"
    err_msg += "Operating system: " + os.name + "\n"
    err_msg += "Command line: " + re.sub(r".+?\bcommix\.py\b", "commix.py", " ".join(sys.argv)) + "\n"
    err_msg = mask_sensitive_data(err_msg)
    exc_msg = re.sub(r'".+?[/\\](\w+\.py)', "\"\g<1>", exc_msg)
    print(settings.print_critical_msg(err_msg + "\n" + exc_msg.rstrip()))
    create_github_issue(err_msg, exc_msg[:])

# eof