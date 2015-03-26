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
 
 For more see the file 'doc/COPYING' for copying permission.
"""

import sys
import os

"""
 The global variables.
"""

# About
APPLICATION = "commix"
DESCRIPTION = "Automated All-in-One OS Command Injection and Exploitation Tool"
AUTHOR  = "Anastasios Stasinopoulos"
VERSION = "v0.01b"
YEAR    = "2015"
TWITTER = "@ancst" 

# Inject Tag
INJECT_TAG = "INJECT_HERE"

# Check Commit ID
if os.path.isdir("./.git"):
  with open('.git/refs/heads/master', 'r') as f:
    COMMIT_ID = "-" + f.readline()[0:7]
else:
    COMMIT_ID = ""
    
# Output Directory
OUTPUT_DIR = ".output/"
dir = os.path.dirname(OUTPUT_DIR)
try:
    os.stat(OUTPUT_DIR)
except:
    os.mkdir(OUTPUT_DIR)       

# The base64 decode trick
B64_DEC_TRICK = " | base64 -d "

# The command injection seperators.
SEPERATORS = [" ",";","&","&&","|","||"]

# The command injection prefixes.
PREFIXES = ["","'",")","')","|","&"]

# The command injection suffixes.
SUFFIXES = ["","#","//","\\\\","&","|"]

# The white-spaces
WHITESPACES = ["%20","$IFS"]

# Bad combination of prefix and seperator
JUNK_COMBINATION = ["&&&","|||","|&&","&|"]

# Time delay
DELAY = 1

# The max help option length.
MAX_OPTION_LENGTH = 18

# Python version.
PYTHON_VERSION = sys.version.split()[0]

