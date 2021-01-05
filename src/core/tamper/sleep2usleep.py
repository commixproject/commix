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
import sys
from src.utils import settings

"""
About: Replaces "sleep" with "usleep" [1] command in the generated payloads.
  [1] http://man7.org/linux/man-pages/man3/usleep.3.html
Notes: This tamper script works against *nix targets.
"""

__tamper__ = "sleep2usleep"

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

def tamper(payload):
  def sleep_to_usleep(payload):
    settings.TAMPER_SCRIPTS[__tamper__] = True
    for match in re.finditer(r"sleep" + settings.WHITESPACE[0] + "([1-9]\d+|[0-9])", payload):
      sleep_to_usleep = "u" + match.group(0).split(settings.WHITESPACE[0])[0]
      if match.group(0).split(settings.WHITESPACE[0])[1] != "0":
        usleep_delay = match.group(0).split(settings.WHITESPACE[0])[1] + "0" * 6
      else:
        usleep_delay = match.group(0).split(settings.WHITESPACE[0])[1]  
      payload = payload.replace(match.group(0), sleep_to_usleep + settings.WHITESPACE[0] + usleep_delay) 
    return payload

  if settings.TARGET_OS != "win":
    if settings.CLASSIC_STATE != False or \
       settings.EVAL_BASED_STATE != False or \
       settings.FILE_BASED_STATE != False:
      if settings.TRANFROM_PAYLOAD == None:
        settings.TRANFROM_PAYLOAD = False
        warn_msg = "All injection techniques, except for the time-relative ones, "
        warn_msg += "do not support the '" + __tamper__  + ".py' tamper script."
        sys.stdout.write("\r" + settings.print_warning_msg(warn_msg))
        sys.stdout.flush() 
        print
    else:
      settings.TRANFROM_PAYLOAD = True
      if settings.TRANFROM_PAYLOAD:
        payload = sleep_to_usleep(payload)

  else:
    if settings.TRANFROM_PAYLOAD == None:
      settings.TRANFROM_PAYLOAD = False
      warn_msg = "Windows target host(s), does not support the '" + __tamper__  + ".py' tamper script."
      sys.stdout.write("\r" + settings.print_warning_msg(warn_msg))
      sys.stdout.flush() 
      print

  return payload
  
# eof 