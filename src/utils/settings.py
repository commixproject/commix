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
import urllib

"""
 The global variables.
"""

# About
APPLICATION = "commix"
DESCRIPTION = "Automated All-in-One OS Command Injection and Exploitation Tool"
AUTHOR  = "Anastasios Stasinopoulos"
VERSION = "v0.1b"
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

# The command injection separators.
SEPARATORS = ["",";","&","|","||","&&","%0a","%26","%26%26","%7C","%7C%7C"]

# The command injection prefixes.
PREFIXES = ["","'",")","')","|","&","%0a","%27","%29","%27%29","%7C","%26"] 

# The command injection suffixes.
SUFFIXES = ["","#","//","\\\\","&","|","%27","%5C%5C","%27%29","%26","%7C"]

# The white-spaces
WHITESPACES = ["%20","$IFS"]

# Bad combination of prefix and separator
JUNK_COMBINATION = ["&&&","|||","|&&","&|","%27;","&;","|;","%29;","%27%29;","%7C;","%26;","%27;","%27||","%29&","%27%29&","%7C&","%26&"]

# Time delay
DELAY = 1

# Default Temp Directorya
TMP_PATH = "/tmp/"

# Default Server's Root Directory
SRV_ROOT_DIR = "/var/www/"

# The max help option length.
MAX_OPTION_LENGTH = 18

# Python version.
PYTHON_VERSION = sys.version.split()[0]


