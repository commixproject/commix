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
import os
import sys
import time
import random
import string
import codecs
from src.core.compat import xrange
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.six.moves import reload_module as _reload_module
from src.thirdparty.colorama import Fore, Back, Style, init

# Status
FAIL_MSG = Fore.RED + " " * 10 + Style.RESET_ALL
FAIL_STATUS = "" + FAIL_MSG + ""
info_msg = Fore.GREEN + " " * 10 + Style.RESET_ALL
SUCCESS_STATUS = "" + info_msg + ""
# Status Signs
LEGAL_DISCLAIMER = "(" + Style.BRIGHT + Fore.RED + "!" + Style.RESET_ALL + ") " + "Legal disclaimer: "
INFO_SIGN = Style.RESET_ALL + "[" + Fore.GREEN + "info" + Style.RESET_ALL + "] "
INFO_BOLD_SIGN = "[" + Fore.GREEN + Style.BRIGHT + "info" + Style.RESET_ALL + "] " 
REQUEST_SIGN = Style.RESET_ALL + "[" + Style.BRIGHT + Back.MAGENTA + "traffic" + Style.RESET_ALL + "] "
RESPONSE_SIGN = Style.RESET_ALL + "[" + Style.BRIGHT + Back.MAGENTA + "traffic" + Style.RESET_ALL + "] "
QUESTION_SIGN = Style.BRIGHT
TOTAL_OF_REQUESTS_COLOR = Fore.LIGHTYELLOW_EX 
WARNING_SIGN = "[" + Fore.LIGHTYELLOW_EX  + "warning" + Style.RESET_ALL + "] "
WARNING_BOLD_SIGN = "[" + Style.BRIGHT + Fore.YELLOW  + "warning" + Style.RESET_ALL + "] " + Style.BRIGHT
ERROR_SIGN = "[" + Fore.RED + "error" + Style.RESET_ALL  + "] " 
CRITICAL_SIGN = "[" + Back.RED + "critical" + Style.RESET_ALL  + "] "
PAYLOAD_SIGN = "[" + Fore.CYAN + "payload" + Style.RESET_ALL + "] " 
SUB_CONTENT_SIGN = " " * 7 + Fore.GREY + "|_ " + Style.RESET_ALL
TRAFFIC_SIGN = HTTP_CONTENT_SIGN = ""
ABORTION_SIGN = ERROR_SIGN 
DEBUG_SIGN = "[" + Back.BLUE + Fore.WHITE + "debug" + Style.RESET_ALL + "] " 
DEBUG_BOLD_SIGN = "[" + Back.BLUE + Style.BRIGHT + Fore.WHITE + "debug" + Style.RESET_ALL + "] " + Style.BRIGHT
CHECK_SIGN = DEBUG_SIGN + "Checking pair of credentials: "

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
  result = WARNING_SIGN + str(warn_msg) + Style.RESET_ALL
  return result

# Print warning message
def print_bold_warning_msg(warn_msg):
  result = WARNING_BOLD_SIGN + str(warn_msg) + Style.RESET_ALL
  return result

# Print legal disclaimer message
def print_legal_disclaimer_msg(legal_disclaimer_msg):
  result = LEGAL_DISCLAIMER + str(legal_disclaimer_msg) + Style.RESET_ALL
  return result

# Print request HTTP message
def print_request_msg(req_msg):
  result = REQUEST_SIGN + str(req_msg) + Style.RESET_ALL
  return result

# Print response HTTP message
def print_response_msg(resp_msg):
  result = RESPONSE_SIGN + str(resp_msg) + Style.RESET_ALL
  return result

# Print information message
def print_info_msg(info_msg):
  result = INFO_SIGN + str(info_msg) + Style.RESET_ALL
  return result

# Print bold information message
def print_bold_info_msg(info_msg):
  result = INFO_BOLD_SIGN + Style.BRIGHT + str(info_msg) + Style.RESET_ALL
  return result

# Print payload (verbose mode)
def print_payload(payload):
  result = PAYLOAD_SIGN + str(payload) + Style.RESET_ALL
  return result

# Print HTTP traffic (verbose mode)
def print_traffic(traffic):
  result = TRAFFIC_SIGN + str(traffic) + Style.RESET_ALL
  return result

def print_request_num(number):
  result = TOTAL_OF_REQUESTS_COLOR + "#" + str(number) + Style.RESET_ALL
  return result

def print_output(output):
  result = Fore.GREEN + Style.BRIGHT + str(output) + Style.RESET_ALL
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
  result = QUESTION_SIGN + question_msg + Style.RESET_ALL
  return result

# Print sub content message
def print_sub_content(sub_content):
  result = SUB_CONTENT_SIGN + sub_content + Style.RESET_ALL
  return result

# Print debug message (verbose mode)
def print_debug_msg(debug_msg):
  result = DEBUG_SIGN + debug_msg + Style.RESET_ALL
  return result  

# Print bold debug message (verbose mode)
def print_bold_debug_msg(debug_msg):
  result = DEBUG_BOLD_SIGN + debug_msg + Style.RESET_ALL
  return result  

# argv checks
def sys_argv_checks():
  tamper_index = None
  for i in xrange(len(sys.argv)):
    # Disable coloring
    if sys.argv[i] == "--disable-coloring":
      from src.utils import colors
      colors.ENABLE_COLORING = False
    """
    Dirty hack from sqlmap [1], regarding merging of tamper script arguments (e.g. --tamper A --tamper B -> --tamper=A,B)
    [1] https://github.com/sqlmapproject/sqlmap/commit/f4a0820dcb5fded8bc4d0363c91276eb9a3445ae
    """
    if sys.argv[i].startswith("--tamper"):
      if tamper_index is None:
        tamper_index = i if '=' in sys.argv[i] else (i + 1 if i + 1 < len(sys.argv) and not sys.argv[i + 1].startswith('-') else None)
      else:
        sys.argv[tamper_index] = "%s,%s" % (sys.argv[tamper_index], sys.argv[i].split('=')[1] if '=' in sys.argv[i] else (sys.argv[i + 1] if i + 1 < len(sys.argv) and not sys.argv[i + 1].startswith('-') else ""))
        sys.argv[i] = ""

# argv input errors
def sys_argv_errors():
  _reload_module(sys)
  try:
    # Fix for Python 2.7
    sys.setdefaultencoding(UNICODE_ENCODING)
  except AttributeError:
    pass
  for i in xrange(len(sys.argv)):
    # Check for illegal (non-console) quote characters.
    if len(sys.argv[i]) > 1 and all(ord(_) in xrange(0x2018, 0x2020) for _ in ((sys.argv[i].split('=', 1)[-1].strip() or ' ')[0], sys.argv[i][-1])):
        err_msg = "Illegal (non-console) quote characters ('" + sys.argv[i] + "')."
        print(print_critical_msg(err_msg))
        raise SystemExit()
    # Check for illegal (non-console) comma characters.
    elif len(sys.argv[i]) > 1 and u"\uff0c" in sys.argv[i].split('=', 1)[-1]:
        err_msg = "Illegal (non-console) comma character ('" + sys.argv[i] + "')."
        print(print_critical_msg(err_msg))
        raise SystemExit()
    # Check for potentially miswritten (illegal '=') short option.
    elif re.search(r"\A-\w=.+", sys.argv[i]):
        err_msg = "Potentially miswritten (illegal '=') short option detected ('" + sys.argv[i] + "')."
        print(print_critical_msg(err_msg))
        raise SystemExit()

# argv checks
sys_argv_checks()

"""
The global variables.
"""
# About
APPLICATION = "commix"
DESCRIPTION_FULL = "Automated All-in-One OS Command Injection and Exploitation Tool"
DESCRIPTION = "The command injection exploiter"
AUTHOR  = "Anastasios Stasinopoulos"
VERSION_NUM = "3.2.73"
STABLE_VERSION = False
if STABLE_VERSION:
  VERSION = "v" + VERSION_NUM[:3] + "-stable"
else:
  VERSION = "v" + VERSION_NUM[:3] + "-dev#" + VERSION_NUM[4:]
YEAR = "2014-2021"
AUTHOR_TWITTER = "@ancst" 
APPLICATION_URL = "https://commixproject.com" 
APPLICATION_TWITTER = "@commixproject" 

# Default User-Agent
DEFAULT_USER_AGENT = APPLICATION + "/" + VERSION + " (" + APPLICATION_URL + ")"

# Legal Disclaimer
LEGAL_DISCLAIMER_MSG = "Usage of " + APPLICATION + " for attacking targets without prior mutual consent is illegal. " + \
                       "It is the end user's responsibility to obey all applicable local, state and federal laws. " + \
                       "Developers assume no liability and are not responsible for any misuse or damage caused by this program.\n"

# Random string generator
RANDOM_STRING_GENERATOR = ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(10))

# Random Tag
RANDOM_TAG = "" 

if RANDOM_TAG == "" : 
  RANDOM_TAG = RANDOM_STRING_GENERATOR

# Proxy
PROXY_REGEX = r"((http[^:]*)://)?([\w\-.]+):(\d+)"

# Inject Tag
INJECT_TAG = "INJECT_HERE"
INJECT_TAG_REGEX = r"(?i)INJECT[_]?HERE"
VALUE_BOUNDARIES = r'[\\/]+' 

#Basic heuristic checks for code injection warnings or... phpinfo page ;)
BASIC_TEST = "\\\\/{${eval(phpinfo())}}\\/\\"

# Executed phpinfo()
IDENTIFIED_PHPINFO = False
CODE_INJECTION_PHPINFO = r"PHP Version </td><td class=\"v\">(([\w\.]+))"

# Code injection warnings
IDENTIFIED_WARNINGS = False
CODE_INJECTION_WARNINGS = ["eval()'d code", "runtime-created function", "usort", "assert", "preg_replace"]

SKIP_CODE_INJECTIONS = False
SKIP_COMMAND_INJECTIONS = False

# User-defined stored post data.
USER_DEFINED_POST_DATA = ""

# The wildcard character
WILDCARD_CHAR = "*"

# Testable parameter(s) - comma separated. 
TEST_PARAMETER = ""

# Skip testing for given parameter(s) - comma separated. 
SKIP_PARAMETER = ""

# Use a proxy to connect to the target URL.
SCHEME = ""

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

# Git issue URL.
ISSUES_PAGE = "https://github.com/commixproject/" + APPLICATION + "/issues/new"

# Output Directory
OUTPUT_DIR = ".output/"  

# Output file name
OUTPUT_FILE_NAME = "logs"

# Output file name
OUTPUT_FILE_EXT = ".txt"
OUTPUT_FILE = OUTPUT_FILE_NAME + OUTPUT_FILE_EXT

# Max Length.
MAXLEN = "10000"

# Maximum response total page size (trimmed if larger)
MAX_CONNECTION_TOTAL_SIZE = 100 * 1024 * 1024

# Slow target response.
SLOW_TARGET_RESPONSE = 3

# The testable parameter.
TESTABLE_PARAMETER = "" 

# The HTTP header name.
HTTP_HEADER = ""

# The command injection prefixes.
PREFIXES = ["", " ", "'", "\"", "&", "%26", "|", "%7C", "%27", "%22", "'%26"]

# The command injection separators.
SEPARATORS = ["", ";", "%3B", "&", "%26", "&&", "%26%26", "|", "%7C", "||", "%7C%7C", "%0a", "%0d%0a"]

# The command injection suffixes.
SUFFIXES = ["", "'", "\"", "&&", "%26%26", "|", "%7C", "||", "%7C%7C", " #", "//", "\\\\", "%26'", "%27", "%22", "%5C%5C", "%2F%2F"]

# Bad combination of prefix and separator
JUNK_COMBINATION = ["&&&", "|||", "|&&", "&|", "&;", "|;", "%7C;", "%26;", "%7C&"]

# Execution functions
EXECUTION_FUNCTIONS = ["exec", "system", "shell_exec", "passthru", "proc_open", "popen"]

# The code injection prefixes.
EVAL_PREFIXES = ["{${", "\".", "'.", "", ";", "'", ")", "')", "\")", ");}", "');}", "\");}"]

# The code injection separators.
EVAL_SEPARATORS = ["", "%0a", "\\n", "%0d%0a", "\\r\\n"]

# The code injection suffixes.
EVAL_SUFFIXES = ["}}", ".\"", ".'", "", "\\\\", "//", "#", ")}"]

# The white-spaces
WHITESPACE = ["%20"]

# Reference: http://www.w3.org/Protocols/HTTP/Object_Headers.html#uri
URI_HTTP_HEADER = "URI"

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

# Counting the total of HTTP(S) requests
TOTAL_OF_REQUESTS = 0

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
CHOICE_YES = ['YES','YE','Y','yes','ye','y']

# Accepts 'NO','N','no','n'
CHOICE_NO = ['NO','N','no','n']

# Accepts 'QUIT','Q','quit','q'
CHOICE_QUIT = ['QUIT','Q','quit','q']

# Accepts 'W','w','U','u','Q','q'
CHOICE_OS = ['W','w','U','u','Q','q']

# Accepts 'C','c','S','s','Q','q','a','A','n','N'
CHOICE_PROCEED = ['C','c','S','s','Q','q','a','A','n','N']

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
        "Mozilla/5.0 (BB10; Kbd) AppleWebKit/537.35+ (KHTML, like Gecko) Version/10.3.3.2205 Mobile Safari/537.35+",
        "Mozilla/5.0 (Linux; Android 7.0; SM-G930V Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.125 Mobile Safari/537.36",
        "Mozilla/4.0 (compatible; MSIE 4.01; Windows CE; PPC; 240x320; HP iPAQ h6300)",
        "Mozilla/5.0 (Linux; Android 8.0.0; HTC 10 Build/OPR1.170623.027) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 4.4.4; HUAWEI H891L Build/HuaweiH891L) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/33.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safari/604.1",
        "Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Microsoft; Lumia 950) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Mobile Safari/537.36 Edge/15.14977",
        "Mozilla/5.0 (Linux; Android 4.1.1; Nexus 7 Build/JRO03D) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.166 Safari/535.19",
        "Mozilla/5.0 (SymbianOS/9.4; Series60/5.0 NokiaN97-1/10.0.012; Profile/MIDP-2.1 Configuration/CLDC-1.1; en-us) AppleWebKit/525 (KHTML, like Gecko) WicKed/7.1.12344",
        "Mozilla/5.0 (Linux; Android 8.0.0; Pixel Build/OPR3.170623.013) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.111 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; U; Android 4.4.4; en-gb; MI 3W Build/KTU84P) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/39.0.0.0 Mobile Safari/537.36 XiaoMi/MiuiBrowser/2.1.1",
]

# Default Scheme
SCHEME = ""

# Privoxy Proxy
PRIVOXY_IP = "127.0.0.1"
PRIVOXY_PORT = "8118"

# Cookie injection
COOKIE_INJECTION = False

# User-Agent injection
USER_AGENT_INJECTION = None

# Referer injection
REFERER_INJECTION = None

# Host injection
HOST_INJECTION = None

# Custom HTTP Headers injection
CUSTOM_HEADER_INJECTION = False
CUSTOM_HEADER_NAME = "" 

# Valid URL format check
VALID_URL_FORMAT = "https?://(?:www)?(?:[\w-]{2,255}(?:\.\w{2,6}){1,2})(?:/[\w&%?#-]{1,300})?"

VALID_URL = True

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

UNICODE_ENCODING = "utf8"

# Reference: http://en.wikipedia.org/wiki/ISO/IEC_8859-1
DEFAULT_PAGE_ENCODING = "iso-8859-1"
try:
  codecs.lookup(DEFAULT_PAGE_ENCODING)
except LookupError:
  DEFAULT_PAGE_ENCODING = UNICODE_ENCODING

# Character Sets List. 
# A complete list of the standard encodings Python supports.
ENCODING_LIST = [
  "iso-8859-1",
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

# Default value for HTTP Accept-Encoding header
HTTP_ACCEPT_ENCODING_HEADER_VALUE = "deflate"

# Default server banner
SERVER_BANNER = ""

# Server banners list
SERVER_BANNERS = [
    "Microsoft-IIS",
    "Apache",
    r"Nginx/([\w\.]+)",
    r"GWS/([\w\.]+)",
    r"lighttpd/([\w\.]+)",
    r"openresty/([\w\.]+)",
    r"LiteSpeed/([\w\.]+)",
    r"Sun-ONE-Web-Server/([\w\.]+)"
]

# Server banners list
SERVER_OS_BANNERS = [
    r"(Microsoft|Windows|Win32)",
    "Debian",
    "Ubuntu",
    "Fedora",
    "CentOS",
    "FreeBSD",
    "NetBSD",
    "OpenBSD",
    "Slackware",
    "SuSE",
    "Mandrake",
    "Gentoo",
    r"Mac[\-\_\ ]?OSX",
    r"Red[\-\_\ ]?Hat",
    "Unix"
]

# Extensions skipped by crawler
CRAWL_EXCLUDE_EXTENSIONS = [
  "3ds", "3g2", "3gp", "7z", "DS_Store", "a", "aac", "adp", "ai", "aif", "aiff", "apk", "ar", 
  "asf", "au", "avi", "bak", "bin", "bk", "bmp", "btif", "bz2", "cab", "caf", "cgm", "cmx", "cpio", "cr2", "dat", "deb", 
  "djvu", "dll", "dmg", "dmp", "dng", "doc", "docx", "dot", "dotx", "dra", "dsk", "dts", "dtshd", "dvb", "dwg", "dxf", 
  "ear", "ecelp4800", "ecelp7470", "ecelp9600", "egg", "eol", "eot", "epub", "exe", "f4v", "fbs", "fh", "fla", "flac", 
  "fli", "flv", "fpx", "fst", "fvt", "g3", "gif", "gz", "h261", "h263", "h264", "ico", "ief", "image", "img", "ipa", 
  "iso", "jar", "jpeg", "jpg", "jpgv", "jpm", "jxr", "ktx", "lvp", "lz", "lzma", "lzo", "m3u", "m4a", "m4v", "mar", 
  "mdi", "mid", "mj2", "mka", "mkv", "mmr", "mng", "mov", "movie", "mp3", "mp4", "mp4a", "mpeg", "mpg", "mpga", "mxu", 
  "nef", "npx", "o", "oga", "ogg", "ogv", "otf", "pbm", "pcx", "pdf", "pea", "pgm", "pic", "png", "pnm", "ppm", "pps", 
  "ppt", "pptx", "ps", "psd", "pya", "pyc", "pyo", "pyv", "qt", "rar", "ras", "raw", "rgb", "rip", "rlc", "rz", "s3m", 
  "s7z", "scm", "scpt", "sgi", "shar", "sil", "smv", "so", "sub", "swf", "tar", "tbz2", "tga", "tgz", "tif", "tiff", 
  "tlz", "ts", "ttf", "uvh", "uvi", "uvm", "uvp", "uvs", "uvu", "viv", "vob", "war", "wav", "wax", "wbmp", "wdp", "weba", 
  "webm", "webp", "whl", "wm", "wma", "wmv", "wmx", "woff", "woff2", "wvx", "xbm", "xif", "xls", "xlsx", "xlt", "xm", "xpi", 
  "xpm", "xwd", "xz", "z", "zip", "zipx"
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

# XML Data
IS_XML = False

# Regular expression for XML POST data
XML_RECOGNITION_REGEX = r'(?s)\A\s*<[^>]+>(.+>)?\s*\Z'

# JSON Data
IS_JSON = False

# Infixes used for automatic recognition of parameters carrying anti-CSRF tokens
CSRF_TOKEN_PARAMETER_INFIXES = ("csrf", "xsrf", "token")

# Regular expression used for detecting JSON POST data
JSON_RECOGNITION_REGEX = r'(?s)\A(\s*\[)*\s*\{.*"[^"]+"\s*:\s*("[^"]*"|\d+|true|false|null).*\}\s*(\]\s*)*\Z'

# Regular expression used for detecting JSON-like POST data
JSON_LIKE_RECOGNITION_REGEX = r"(?s)\A(\s*\[)*\s*\{.*'[^']+'\s*:\s*('[^']+'|\d+).*\}\s*(\]\s*)*\Z"

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
HTTP_HEADERS = [ "user-agent", "referer", "host" ]

RAW_HTTP_HEADERS = ""

# Tamper scripts dict
TAMPER_SCRIPTS = {
                  "space2ifs": False,
                  "base64encode": False,
                  "hexencode": False,
                  "space2plus": False,
                  "space2htab": False,
                  "space2vtab": False,
                  "doublequotes": False,
                  "singlequotes": False,
                  "caret": False,
                  "multiplespaces": False,
                  "backslashes": False,
                  "nested": False,
                  "sleep2usleep": False,
                  "sleep2timeout": False,
                  "xforwardedfor": False,
                  "dollaratsigns": False,
                  "uninitializedvariable": False
                 }

# HTTP Errors
BAD_REQUEST = "400"
UNAUTHORIZED_ERROR = "401"
FORBIDDEN_ERROR = "403"
NOT_FOUND_ERROR = "404"
NOT_ACCEPTABLE_ERROR = "406"
INTERNAL_SERVER_ERROR = "500"

HTTP_ERROR_CODES = [ BAD_REQUEST, UNAUTHORIZED_ERROR, FORBIDDEN_ERROR, NOT_FOUND_ERROR, NOT_ACCEPTABLE_ERROR, INTERNAL_SERVER_ERROR ]

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

# Default Timeout
TIMEOUT = 30

# Retries when the connection timeouts (Default: 3).
MAX_RETRIES = 3

# End of file
EOF = False

# Init Test
INIT_TEST = ""

# Check Tor again
TOR_CHECK_AGAIN = True

# URL for checking internet connection.
CHECK_INTERNET_ADDRESS = "http://ipinfo.io"

# Check internet connection.
CHECK_INTERNET = False

UNAUTHORIZED = False

# Multiple OS checks
CHECK_BOTH_OS = False
OS_CHECKS_NUM = 2

# Options to explicitly mask in anonymous (unhandled exception) reports.
SENSITIVE_OPTIONS = ["--data", "-d", "--cookie", "-p", "--url", "-u", "-x", "--auth-cred", "-r", "-l"]

# Github OAuth token used for creating an automatic issue for unhandled exceptions.
GITHUB_REPORT_OAUTH_TOKEN = "YjNiYjdhZDBlYzM2MmM2NGEzYTAzZTc4ZDg1NmYwZTUyZGZlN2EyZQ=="

# Tranform payloads (via tamper script(s))
TRANFROM_PAYLOAD = None

CAPTCHA_DETECED = None

BROWSER_VERIFICATION = None

# Regular expression used for recognition of generic "your ip has been blocked" messages.
BLOCKED_IP_REGEX = r"(?i)(\A|\b)ip\b.*\b(banned|blocked|block list|firewall)"

# Prefix for Google analytics cookie names
GOOGLE_ANALYTICS_COOKIE_PREFIX = "__UTM"

# Default path for tamper scripts
TAMPER_SCRIPTS_PATH = "src/core/tamper/"

# Default path for settings.py file
SETTINGS_PATH = os.path.abspath("src/utils/settings.py")

# Period after last-update to start nagging (about the old revision).
NAGGING_DAYS = 30

# HTTP Headers
COOKIE = "Cookie"
HOST = "Host"
USER_AGENT = "User-Agent"
REFERER = "Referer"
HTTP_ACCEPT_HEADER = "Accept"

# HTTP Headers values
HTTP_ACCEPT_HEADER_VALUE = "*/*"

# Regular expression used for ignoring some special chars
IGNORE_SPECIAL_CHAR_REGEX = "[^A-Za-z0-9.:,_]+"

# eof