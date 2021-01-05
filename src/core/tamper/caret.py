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
About: Adds caret symbol (^) between the characters of the generated payloads.
Notes: This tamper script works against windows targets.
"""

__tamper__ = "caret"

if not settings.TAMPER_SCRIPTS[__tamper__]:
  settings.TAMPER_SCRIPTS[__tamper__] = True

def tamper(payload):
  def add_caret_symbol(payload):
    settings.TAMPER_SCRIPTS[__tamper__] = True
    if re.compile("\w+").findall(payload):
      if str(len(max(re.compile("\w+").findall(payload), key=lambda word: len(word)))) >= 5000:  
        long_string = max(re.compile("\w+").findall(payload), key=lambda word: len(word))

    rep = {
            "^^": "^",
            '"^t""^o""^k""^e""^n""^s"': '"t"^"o"^"k"^"e"^"n"^"s"',
            re.sub(r'([b-zD-Z])', r'^\1', long_string) : long_string.replace("^","")
          }
    payload = re.sub(r'([b-zD-Z])', r'^\1', payload)
    rep = dict((re.escape(k), v) for k, v in rep.items())
    pattern = re.compile("|".join(rep.keys()))
    payload = pattern.sub(lambda m: rep[re.escape(m.group(0))], payload)
    return payload

  if settings.TARGET_OS == "win":
    if settings.EVAL_BASED_STATE != False:
      if settings.TRANFROM_PAYLOAD == None:
        settings.TRANFROM_PAYLOAD = False
        warn_msg = "The dynamic code evaluation technique, does not support the '"+ __tamper__  +".py' tamper script."
        sys.stdout.write("\r" + settings.print_warning_msg(warn_msg))
        sys.stdout.flush() 
        print
    else:
      settings.TRANFROM_PAYLOAD = True
      if settings.TRANFROM_PAYLOAD:
        payload = add_caret_symbol(payload)
  else:
    if settings.TRANFROM_PAYLOAD == None:
      settings.TRANFROM_PAYLOAD = False
      warn_msg = "*nix target host(s), does not support the '"+ __tamper__  +".py' tamper script."
      sys.stdout.write("\r" + settings.print_warning_msg(warn_msg))
      sys.stdout.flush() 
      print

  return payload
    
# eof 