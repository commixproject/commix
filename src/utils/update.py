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

import re
import os
import subprocess
from src.core.parse import cmdline as menu
from src.utils import settings
from src.utils import requirements
from src.utils import common
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.colorama import Fore, Style

"""
Check for updates (apply if any) and exit!
"""

"""
Where commix is installed, which is the repository to update.

Taken from this file rather than from the working directory: run from inside some other checkout,
a command that reaches for 'the' repository would otherwise reach for that one instead.
"""
def _install_path():
  return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

"""
The revision the install now sits at, shortened the way git itself shows it.
"""
def _revision_number(root):
  try:
    process = subprocess.Popen("git rev-parse --verify HEAD", shell=True, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, cwd=root)
    stdout, _ = process.communicate()
    match = re.search(r"(?i)[0-9a-f]{40}", stdout.decode(settings.DEFAULT_CODEC, errors="replace"))
    return match.group(0)[:7] if match else None
  except Exception:
    return None

"""
Anything the pull leaves behind that is no longer part of the tree.
"""
def _clean_up(root):
  for command in ("find . -name \"*.pyc\" -delete", "find . -empty -type d -delete"):
    try:
      subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=root).wait()
    except Exception:
      pass

"""
The commix's updater.
"""
def updater():
  if menu.options.offline:
    err_msg = "You cannot update " + settings.APPLICATION + " via GitHub without access to the Internet."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  root = _install_path()
  if not os.path.isdir(os.path.join(root, ".git")):
    err_msg = "Not a valid git repository. Please clone the '" + settings.APPLICATION + "' repository "
    err_msg += "from GitHub (e.g. 'git clone --depth 1 " + settings.GIT_URL + " " + settings.APPLICATION + "')."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  if not requirements.do_check("git"):
    err_msg = "The 'git' command was not found."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  info_msg = "Updating " + settings.APPLICATION + " to the latest development revision from the GitHub repository."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = settings.APPLICATION.capitalize() + " will try to update itself using the 'git' command."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

  output = ""
  success = False
  try:
    # What the working tree holds is restored, not discarded: a pull needs the tracked files back as
    # they were, and everything else in the directory is the user's own business.
    process = subprocess.Popen("git checkout . && git pull " + settings.GIT_URL + " HEAD", shell=True,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=root)
    stdout, _ = process.communicate()
    output = stdout.decode(settings.DEFAULT_CODEC, errors="replace")
    success = not process.returncode
  except Exception as err:
    output = str(err)

  if settings.VERBOSITY_LEVEL != 0 and output:
    settings.print_data_to_stdout(Fore.MAGENTA + settings.END_LINE.LF + output + Style.RESET_ALL)

  if success:
    _clean_up(root)
    revision = _revision_number(root)
    info_msg = ("Already at" if "Already" in output else "Updated to") + " the latest revision"
    info_msg += (" '" + revision + "'." if revision else ".")
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  else:
    # Git says what went wrong on one line and then offers pages of advice about it - the line is
    # what the reason is, so it is the line that is reported.
    reason = ""
    for line in output.splitlines():
      if line.lower().startswith(("fatal:", "error:")):
        reason = line.split(":", 1)[1].strip()
        break
    if not reason:
      reason = re.sub(r"\s+", settings.SINGLE_WHITESPACE, output).strip()
    err_msg = "The update could not be completed ('" + reason[:settings.MAX_UPDATE_REASON_LENGTH] + "')."
    settings.print_data_to_stdout(settings.print_error_msg(err_msg))
    if settings.IS_WINDOWS:
      info_msg = "For updating purposes on the Windows platform, it is recommended to use a GitHub "
      info_msg += "client for Windows (https://desktop.github.com/), or to download the latest "
      info_msg += "snapshot from " + settings.GIT_URL.replace(".git", "") + "/releases."
      settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  raise SystemExit()

"""
Check for new version of commix
"""
def check_for_update():
  try:
    response = _urllib.request.urlopen('https://raw.githubusercontent.com/commixproject/commix/master/src/utils/settings.py', timeout=settings.TIMEOUT, context=settings.verified_context())
    try:
      version_check = response.readlines()
    finally:
      response.close()
    for line in version_check:
      # readlines() returns bytes - decode before comparing/matching as text.
      line = line.decode(settings.DEFAULT_CODEC, errors="replace").rstrip()
      if "VERSION_NUM = " in line:
        update_version = line.replace("VERSION_NUM = ", "").replace("\"", "")
        break
    if (int(settings.VERSION_NUM.replace(".", "")[:2]) < int(update_version.replace(".", "")[:2])) or \
       ((int(settings.VERSION_NUM.replace(".", "")[:2]) == int(update_version.replace(".", "")[:2])) and \
         int(settings.VERSION_NUM.replace(".", "")[2:]) < int(update_version.replace(".", "")[2:])):
      while True:
        message = "Do you want to update to the latest version now? [Y/n] "
        do_update = common.read_input(message, default="Y", check_batch=True)
        if do_update in settings.CHOICE_YES:
          updater()
        elif do_update in settings.CHOICE_NO:
          break
        else:
          common.invalid_option(do_update)
          pass
  except KeyboardInterrupt:
    raise
  except:
    pass

# eof
