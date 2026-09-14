#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2026 Anastasios Stasinopoulos (@ancst).

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
import threading as _threading
from datetime import date
from datetime import datetime
from src.core.compat import xrange
from src.thirdparty.six.moves import urllib as _urllib
from src.core import eval as _eval

# The language whose code injection grammar is in use; '--eval' can name another one.
EVAL_GRAMMAR = _eval.grammar()
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

from src.utils import colors
if not colors.ENABLE_COLORING:
  # Strip ANSI codes at write time - the print_*_msg helpers below always
  # build them in, regardless of this flag.
  init(strip=True, convert=False)

class HTTPMETHOD(object):
  GET = "GET"
  POST = "POST"
  HEAD = "HEAD"

# Status Signs
LEGAL_DISCLAIMER = "(" + Style.BRIGHT + Fore.RED + "!" + Style.RESET_ALL + ") " + "Legal disclaimer: "
INFO_SIGN = Style.RESET_ALL + "[" + Fore.GREEN + "info" + Style.RESET_ALL + "] "
INFO_BOLD_SIGN = "[" + Fore.GREEN + Style.BRIGHT + "info" + Style.RESET_ALL + "] "
REQUEST_SIGN = Style.RESET_ALL + "[" + Style.BRIGHT + Back.MAGENTA + "traffic" + Style.RESET_ALL + "] "
RESPONSE_SIGN = Style.RESET_ALL + "[" + Style.BRIGHT + Back.MAGENTA + "traffic" + Style.RESET_ALL + "] "
QUESTION_SIGN = Style.BRIGHT
TOTAL_OF_REQUESTS_COLOR = Fore.LIGHTYELLOW_EX
TRACEBACK = Fore.LIGHTRED_EX
WARNING_SIGN = "[" + Fore.LIGHTYELLOW_EX  + "warning" + Style.RESET_ALL + "] "
WARNING_BOLD_SIGN = "[" + Style.BRIGHT + Fore.YELLOW  + "warning" + Style.RESET_ALL + "] " + Style.BRIGHT
ERROR_SIGN = "[" + Fore.RED + "error" + Style.RESET_ALL  + "] "
ERROR_BOLD_SIGN = "["  + Style.BRIGHT + Fore.RED + "error" + Style.RESET_ALL  + "] "
CRITICAL_SIGN = "[" + Back.RED + "critical" + Style.RESET_ALL  + "] "
PAYLOAD_SIGN = "[" + Fore.CYAN + "payload" + Style.RESET_ALL + "] "
SUB_CONTENT_SIGN = ""
SUB_CONTENT_SIGN_TYPE = "" + Style.BRIGHT + "*" + Style.RESET_ALL + " "
#SUB_CONTENT_SIGN_TYPE = "[" + Fore.LIGHTRED_EX + "*" + Style.RESET_ALL + "] "
TRAFFIC_SIGN = HTTP_CONTENT_SIGN = ""
ABORTION_SIGN = ERROR_SIGN
DEBUG_SIGN = "[" + Back.BLUE + Fore.WHITE + "debug" + Style.RESET_ALL + "] "
DEBUG_BOLD_SIGN = "[" + Back.BLUE + Style.BRIGHT + Fore.WHITE + "debug" + Style.RESET_ALL + "] " + Style.BRIGHT
CHECK_SIGN = DEBUG_SIGN + "Checking for a valid pair of authentication credentials: "
OS_SHELL_TITLE = Style.BRIGHT + "Command Shell (type '?' for help)" + Style.RESET_ALL

RL_INVISIBLE_START = "\001"
RL_INVISIBLE_END = "\002"

# Colour codes wrapped so readline does not count them as characters on the line.
def styled_prompt(codes, text):
  return RL_INVISIBLE_START + codes + RL_INVISIBLE_END + text

OS_SHELL = "commix(os_shell) > "

# The timestamp every message carries.
def print_time():
  return "[" + Fore.LIGHTBLUE_EX  + datetime.now().strftime("%H:%M:%S") + Style.RESET_ALL + "] "

"""
Shared tail for the timestamped print_*_msg wrappers below.
"""
def _format_msg(sign, msg, bold=False, strip=True):
  prefix = Style.BRIGHT if bold else ""
  msg = str(msg).rstrip() if strip else str(msg)
  return print_time() + sign + prefix + msg + Style.RESET_ALL

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
  return _format_msg(ERROR_SIGN, err_msg)

# Print error message
def print_bold_error_msg(err_msg):
  return _format_msg(ERROR_BOLD_SIGN, err_msg, bold=True)

# Print critical error message
def print_critical_msg(err_msg):
  return _format_msg(CRITICAL_SIGN, err_msg)

# Print abortion message
def print_abort_msg(abort_msg):
  return _format_msg(ABORTION_SIGN, abort_msg)

# Print warning message
def print_warning_msg(warn_msg):
  return _format_msg(WARNING_SIGN, warn_msg)

_PRINTED_ONCE_MESSAGES = set()

"""
Print each warning message once per run, deduping by raw text.
"""
def print_once(raw_msg):
  if raw_msg not in _PRINTED_ONCE_MESSAGES:
    _PRINTED_ONCE_MESSAGES.add(raw_msg)
    print_data_to_stdout(print_warning_msg(raw_msg))

# Print warning message
def print_bold_warning_msg(warn_msg):
  return _format_msg(WARNING_BOLD_SIGN, warn_msg)

# Print debug message (verbose mode)
def print_debug_msg(debug_msg):
  return _format_msg(DEBUG_SIGN, debug_msg)

# Print bold debug message (verbose mode)
def print_bold_debug_msg(debug_msg):
  return _format_msg(DEBUG_BOLD_SIGN, debug_msg)

# Print request HTTP message
def print_request_msg(req_msg):
  return _format_msg(REQUEST_SIGN, req_msg)

# Print response HTTP message
def print_response_msg(resp_msg):
  return _format_msg(RESPONSE_SIGN, resp_msg)

# Print information message
def print_info_msg(info_msg):
  return _format_msg(INFO_SIGN, info_msg)

# Print bold information message
def print_bold_info_msg(info_msg):
  return _format_msg(INFO_BOLD_SIGN, info_msg, bold=True)

# How a line break is shown in a payload, so it does not split the line.
ESCAPED_CR = "\\r"
ESCAPED_CRLF = "\\r\\n"

# The control characters a payload can be built from, and how each is written where it is shown.
ESCAPED_CONTROLS = {"\t": "\\t", "\v": "\\v", "\x1a": "\\x1a"}

# Print payload (verbose mode)
def print_payload(payload):
  """
  One rendering for every payload that is shown, so the same payload never reads two ways.

  It is shown as it is built - real separators, real spaces - because that is the form worth
  reading and pasting; the wire form, with everything escaped for the request, is what the traffic
  at '-v 2' is for. The only things changed are the characters a terminal does not draw, which
  would otherwise split the line or leave two different payloads looking like the same one.
  """
  for sequence, shown in ((END_LINE.CRLF, ESCAPED_CRLF), (END_LINE.CR, ESCAPED_CR),
                          (END_LINE.LF, END_LINE.ESCAPED_LF)):
    payload = payload.replace(sequence, shown)
  payload = re.sub(r"[\x00-\x1f\x7f]", lambda match: ESCAPED_CONTROLS.get(match.group(0),
                   "\\x%02x" % ord(match.group(0))), payload)
  # A payload is shown exactly as long as it is, a trailing space included.
  return _format_msg(PAYLOAD_SIGN, payload, strip=False)

# Print HTTP traffic (verbose mode)
def print_traffic(traffic):
  result = TRAFFIC_SIGN + str(traffic) + Style.RESET_ALL
  return result

# The request's number, as the traffic log refers to it.
def print_request_num(number):
  result = TOTAL_OF_REQUESTS_COLOR + "#" + str(number) + Style.RESET_ALL
  return result

# Print HTTP response content (verbose mode)
def print_http_response_content(content):
  result = HTTP_CONTENT_SIGN + str(content) + Style.RESET_ALL
  return result

# Print checking message (verbose mode)
def print_checking_msg(payload):
  return _format_msg(CHECK_SIGN, payload, strip=False)

# Print question message
def print_message(message):
  result = QUESTION_SIGN + message + Style.RESET_ALL
  return result

"""
Bold version of a message for use as an input() prompt.
"""
def input_message(message):
  return styled_prompt(Style.BRIGHT, message)

"""
Clears any style an input() prompt (via styled_prompt()) left switched on.
"""
def reset_terminal_style():
  _stdout_write(Style.RESET_ALL)
  sys.stdout.flush()

# Print sub content message
"""
Something read off the target, written the way the summary blocks already are.

No timestamp and no sign: what was retrieved is the answer, not a step towards it, and it reads
apart from the running log for that. Quoted, so a value that is empty or padded is still visible,
and fenced where it runs to more than one line rather than trailing off the first.
"""
def print_retrieved_data(label, retrieved, quoted=True):
  text = str(retrieved)
  if text.endswith(END_LINE.CRLF):
    text = text[:-2]
  elif text.endswith(END_LINE.LF):
    text = text[:-1]
  if END_LINE.LF in text:
    # Its own lines, so the fence is all the delimiting it needs.
    body = END_LINE.LF + "---" + END_LINE.LF + text + END_LINE.LF + "---"
  elif len(text) > MAX_INLINE_VALUE_LENGTH:
    # One line, but longer than one: fenced so it starts where the eye is, rather than trailing off
    # the end of the label - still quoted, since nothing else marks where it begins and ends.
    body = END_LINE.LF + "---" + END_LINE.LF + ("'" + text + "'" if quoted else text) + END_LINE.LF + "---"
  else:
    body = SINGLE_WHITESPACE + ("'" + text + "'" if quoted else text)
  return Style.BRIGHT + label + ":" + body + Style.RESET_ALL

# Print output of command execution
def command_execution_output(shell):
  result = Fore.GREEN + Style.BRIGHT + shell + Style.RESET_ALL
  return result

"""
Write to stdout, falling back to a lossy re-encode for unsupported characters.
"""
def _stdout_write(data):
  try:
    sys.stdout.write(data)
  except UnicodeEncodeError:
    encoding = getattr(sys.stdout, "encoding", None) or DEFAULT_CODEC
    sys.stdout.write(data.encode(encoding, errors="replace").decode(encoding, errors="replace"))

"""
Print data to stdout
"""
def print_data_to_stdout(data):
  global PROGRESS_LINE_OPEN
  if getattr(_threading.current_thread(), "commix_suppress_output", False):
    return
  with PRINT_LOCK:
    # A bare "\r" only moves the cursor and does not open a line.
    if data == END_LINE.CR:
      _stdout_write(data)
      sys.stdout.flush()
      return

    has_cr = END_LINE.CR in data
    has_lf = END_LINE.LF in data
    # The marker that says a progress line is finished, which is exactly what closes it: without
    # that, the next line written over the top of it inherits its tail and its "(done)" with it.
    is_done_marker = data == " (done)"
    is_spinner_style = has_cr or data == "." or is_done_marker
    is_established_closer = data == SINGLE_WHITESPACE

    if is_established_closer and not PROGRESS_LINE_OPEN:
      return  # nothing open to close - skip the cosmetic blank line

    # Spinner continuations can append directly; other output needs a newline first.
    if PROGRESS_LINE_OPEN and not is_spinner_style and not is_established_closer:
      sys.stdout.write(END_LINE.LF)

    # Only spinner output stays unterminated; other messages always end with a newline. The
    # closer says nothing of its own, so it ends the line rather than leaving a space on it.
    if is_established_closer:
      data = END_LINE.LF
    elif not is_spinner_style or is_done_marker:
      data = data + END_LINE.LF

    _stdout_write(data)
    sys.stdout.flush()
    PROGRESS_LINE_OPEN = is_spinner_style and not has_lf and not is_done_marker

"""
Clear the current line before printing, without adding a blank line when already empty.
"""
def clear_current_line():
  global PROGRESS_LINE_OPEN
  with PRINT_LOCK:
    if PROGRESS_LINE_OPEN:
      sys.stdout.write(END_LINE.LF)
    else:
      sys.stdout.write(END_LINE.CR + "\033[K")
    sys.stdout.flush()
    PROGRESS_LINE_OPEN = False

"""
Close the current spinner line with a trailing newline.
"""
def close_progress_line():
  global PROGRESS_LINE_OPEN
  with PRINT_LOCK:
    if PROGRESS_LINE_OPEN:
      sys.stdout.write(END_LINE.LF)
      sys.stdout.flush()
    PROGRESS_LINE_OPEN = False

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
AUTHOR  = "Anastasios Stasinopoulos"
VERSION_NUM = "4.2"
REVISION = "130"
STABLE_RELEASE = False
VERSION = "v"
if STABLE_RELEASE:
  VERSION = VERSION + VERSION_NUM
  COLOR_VERSION = Style.BRIGHT + Style.UNDERLINE + Fore.WHITE + VERSION + Style.RESET_ALL
else:
  VERSION = VERSION + VERSION_NUM + ".dev" + REVISION
  COLOR_VERSION = Style.UNDERLINE + Fore.WHITE + VERSION + Style.RESET_ALL

YEAR = "2014-2026"
AUTHOR_X_ACCOUNT = "@ancst"
APPLICATION_URL = "https://commixproject.com"
APPLICATION_X_ACCOUNT = "@commixproject"

# Default User-Agent
DEFAULT_USER_AGENT = APPLICATION + "/" + VERSION + " (" + APPLICATION_URL + ")"

# Legal Disclaimer
LEGAL_DISCLAIMER_MSG = "Attacking targets without prior mutual consent is illegal. " + \
                       "Obeying applicable laws is your responsibility and "+ APPLICATION +" developers assume no liability.\n"

# Random string generator
RANDOM_STRING_GENERATOR = ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(10))
# Random variable name (E-Z only).
RANDOM_VAR_GENERATOR = ''.join(random.choice(string.ascii_uppercase[4:]) for _ in range(3))

# Path to text resources folder
TXT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'txt'))

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

# Safe characters to keep unescaped in URL paths
SAFE_PATH = "*%/"
# Safe characters to keep unescaped in query strings
SAFE_QUERY = SAFE_PATH + "=?&"

"""
Characters left unescaped inside a payload.

Only '%', so that the encoded sequences the payloads write for themselves survive - everything else
is escaped, the '&' and '=' that would otherwise end the parameter the payload travels in included.
The carrier is encoded separately, and keeps those two, being where they do the separating.
"""
SAFE_PAYLOAD = "%"

"""
A query string this long risks being cut off, so characters are given back to it one at a time.

Servers and proxies put their own limit on a request line, and an encoded payload is several times
the length of what it stands for. These four are legal in a query unencoded, so handing them back
shortens it without changing what the target reads - taken in turn, and only while it is still
over length, so a request that was never near the limit is encoded exactly as any other.
"""
URLENCODE_CHAR_LIMIT = 2000
URLENCODE_FAILSAFE_CHARS = "()|,"

"""
Whether '+' is one of the whitespace substitutes this run may use.

Asked of the whole list rather than its first entry: a tamper script can append a substitute rather
than replace one, and 'multiplespaces' repeats whichever is there - so a run that really does send
'+' for a space had its pluses escaped, and the target read them back as pluses rather than spaces.
"""
def plus_is_whitespace():
  return any(substitute and set(substitute) == set("+") for substitute in WHITESPACES)

"""
Safe query-string characters; allow '+' only when it is a whitespace substitute in use.
"""
def query_safe_chars():
  if plus_is_whitespace():
    return SAFE_QUERY + "+"
  return SAFE_QUERY

"""
Safe characters inside a payload, as above.
"""
def payload_safe_chars():
  if plus_is_whitespace():
    return SAFE_PAYLOAD + "+"
  return SAFE_PAYLOAD

# Default (windows) target host's python interpreter
WIN_PYTHON_INTERPRETER = "python.exe"
WIN_CUSTOM_PYTHON_INTERPRETER = "C:\\Python27\\python.exe"
USER_DEFINED_PYTHON_DIR = False

# Default (linux) target host's python interpreter
LINUX_PYTHON_INTERPRETER = "python3"
LINUX_CUSTOM_PYTHON_INTERPRETER = "python27"
USER_DEFINED_PYTHON_INTERPRETER = False

# Feeds 'set /p' from the null device, so its no-newline echo trick gets EOF instead of blocking.
CMD_NUL = "<nul"

CMD_SUB_PREFIX = "$("
CMD_SUB_SUFFIX = ")"

# Sent to be blocked, never to run: read-only and instant, in both shells, chained every way.
WAF_CHECK_PAYLOAD = ";cat /etc/passwd|type C:\\Windows\\win.ini&&dir ../../||$(cat /etc/passwd)"
WAF_ENABLED = False

class HEURISTIC_TEST(object):
  POSITIVE = True

# Basic command-injection checks, built fresh per parameter with random values and markers.
BASIC_STRING = ""
BASIC_COMMAND_INJECTION_PAYLOADS = []
ALTER_INTERPRETER_BASIC_COMMAND_INJECTION_PAYLOADS = []
BASIC_COMMAND_INJECTION_RESULT = ""
IDENTIFIED_COMMAND_INJECTION = False

# Basic heuristic checks for code injection: the probe that says code was evaluated, what its
# answer looks like coming back, and the interpreter's own complaints that give the same away.
# All of it belongs to the language, so it is read from its module under 'src/core/eval'.
EVAL_PROBE_PAYLOADS = EVAL_GRAMMAR.PROBE_PAYLOADS
EVAL_PROBE_REGEX = EVAL_GRAMMAR.PROBE_REGEX
EVAL_WARNINGS = EVAL_GRAMMAR.WARNINGS

# The probe answered, or the interpreter complained.
IDENTIFIED_EVAL_PROBE = False
IDENTIFIED_WARNINGS = False

SKIP_CODE_INJECTIONS = False
SKIP_COMMAND_INJECTIONS = False

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
# Patterns that legitimately contain '*' (e.g. 'Accept: */*').
PROBLEMATIC_CUSTOM_INJECTION_PATTERNS = r"(;q=[^;'*]+)|(\*/\*)"

class INJECTION_MARKER_LOCATION(object):
  URL = False
  DATA = False
  COOKIE = False
  HTTP_HEADERS = False
  CUSTOM_HTTP_HEADERS = False

SKIP_NON_CUSTOM_PARAMS = None

TESTABLE_PARAMETERS_LIST = []
SKIP_PARAMETERS_LIST = []
TESTABLE_PARAMETERS = None
NOT_TESTABLE_PARAMETERS = True
TESTED_PARAMETERS_LIST = []
METHODS_WITH_NON_LISTED_PARAMS = []

# Use a proxy to connect to the target URL.
SCHEME = ""

class OS(object):
  UNIX = "unix"
  WINDOWS = "windows"

# Default target host OS (Unix-like)
TARGET_OS = OS.UNIX

IDENTIFIED_TARGET_OS = False
IGNORE_IDENTIFIED_TARGET_OS = None

# Verbosity level (0-4, Default: 0)
VERBOSITY_LEVEL = 0

# Detection / Exploitation phase(s)
WAF_DETECTION_PHASE = False
DETECTION_PHASE = False
EXPLOITATION_PHASE = False

# Prevent the shell from interpreting the redirection operators.
NO_OUTPUT = ">/dev/null 2>&1"

# Exploitation techniques states
CLASSIC_STATE = False
EVAL_BASED_STATE = False
TIME_BASED_STATE = False
FILE_BASED_STATE = False
TEMPFILE_BASED_STATE = False
OOB_STATE = False

# The technique currently being announced/tested.
CURRENT_TECHNIQUE = None
TIME_RELATED_ATTACK = False
TIME_RELATED_ATTACK_WARNING = False
LAST_COMPLETED_TECHNIQUE = None
LAST_DOT_BUCKET = -1

# Stored applied techniques
SESSION_APPLIED_TECHNIQUES = ""

# The name of the operating system dependent module imported.
PLATFORM = os.name
IS_WINDOWS = PLATFORM == "nt"

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

# Max Length for execution output.
MAXLEN = 10000

STDIN_PARSING = False

# Slow target response.
SLOW_TARGET_RESPONSE = 3

# Number of samples estimate_response_time() takes the median of.
RESPONSE_TIME_SAMPLES = 3

# Pre-injection baseline - the target's own round-trip time before any delay logic runs.
URL_TIME_RESPONSE = 0
# (url, http_request_method) the response-time baseline is sampled from, filled in on first use.
BASELINE_TARGET = None
# Last reported minimum safe delay, so the same floor is announced only once.
REPORTED_MIN_SAFE_TIMESEC = None

# Cache url_response()'s connection-test timing for reuse by estimate_response_time().
INIT_CONNECTION_TIME = None

# When that connection-test response was fetched (time.time()).
INIT_CONNECTION_FETCH_TIME = None

# URL actually used for that request (may carry the WAF probe marker).
INIT_CONNECTION_URL = None

# Max wait before re-checking page stability.
STABILITY_CHECK_DELAY = 0.5

# Below this similarity ratio, two page fetches count as "dynamic".
STABILITY_SIMILARITY_THRESHOLD = 0.98

# One-time "reflected value(s) found" notice already shown this run.
REFLECTIVE_VALUE_FOUND = False

RESPONSE_DELAYS = False

TESTABLE_VALUE = ""

# Whether TESTABLE_VALUE has already been swapped for a disposable placeholder this scan.
TESTABLE_VALUE_OPTIMIZED = False

# The HTTP header name.
HTTP_HEADER = ""

EXTRA_HTTP_HEADERS = False

# Use the full printable ASCII range; bisection only depends on ordinal bounds.
CHAR_POOL_SINGLE = list(range(32, 127))
# Newline and tab are part of real command output, so they have to be recoverable too.
CHAR_POOL_MULTI = [9, 10] + list(range(32, 127))

"""
The command injection separators, as the shell reads them rather than as a URL spells them.

Written out here and encoded once at the end, where a payload meets the thing that carries it -
so what a payload is made of stays readable, nothing has to remember which half of it was already
escaped, and a character that is not a separator at all can be escaped without disturbing one that
is. It also means '%' is a per-cent sign here, not the start of an escape.
"""
SEPARATORS = []
DEFAULT_SEPARATORS = [";", "&", "|", ""]
SPECIAL_SEPARATORS = ["&&", "||", "\n", "\r\n", "\x1a"]
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

# Execution functions, and the boundaries that break into an evaluated string and close it again -
# all of them the language's own, and so read from its module rather than written out here.
EXECUTION_FUNCTIONS = []
EXECUTION_FUNCTIONS_LVL1 = EVAL_GRAMMAR.EXECUTION_FUNCTIONS_LVL1
EXECUTION_FUNCTIONS_LVL2 = EVAL_GRAMMAR.EXECUTION_FUNCTIONS_LVL2
EXECUTION_FUNCTIONS_LVL3 = EVAL_GRAMMAR.EXECUTION_FUNCTIONS_LVL3

# The code injection separators.
EVAL_SEPARATORS = []
EVAL_SEPARATORS_LVL1 = EVAL_GRAMMAR.SEPARATORS_LVL1
EVAL_SEPARATORS_LVL2 = EVAL_GRAMMAR.SEPARATORS_LVL2
EVAL_SEPARATORS_LVL3 = EVAL_GRAMMAR.SEPARATORS_LVL3

# The code injection prefixes.
EVAL_PREFIXES = []
EVAL_PREFIXES_LVL1 = EVAL_GRAMMAR.PREFIXES_LVL1
EVAL_PREFIXES_LVL2 = EVAL_GRAMMAR.PREFIXES_LVL2
EVAL_PREFIXES_LVL3 = EVAL_GRAMMAR.PREFIXES_LVL3

# The code injection suffixes.
EVAL_SUFFIXES = []
EVAL_SUFFIXES_LVL1 = EVAL_GRAMMAR.SUFFIXES_LVL1
EVAL_SUFFIXES_LVL2 = EVAL_GRAMMAR.SUFFIXES_LVL2
EVAL_SUFFIXES_LVL3 = EVAL_GRAMMAR.SUFFIXES_LVL3

# Raw payload (without tampering)
RAW_PAYLOAD = ""

# Single whitespace
SINGLE_WHITESPACE = " "

# The default whitespace, as a space - encoded with the rest of the payload at the end.
WHITESPACES = [SINGLE_WHITESPACE]

# Reference: http://www.w3.org/Protocols/HTTP/Object_Headers.html#uri
URI_HTTP_HEADER = "URI"

# Seconds to delay between each HTTP request.
DELAY = 0

# Seconds to delay the OS response.
TIMESEC = 0

# Minimum safe delay.
MIN_SAFE_TIMESEC = 5

# Higher minimum delay applied once this run has confirmed the target is unstable.
MIN_SAFE_TIMESEC_UNSTABLE = 10

# Seconds to delay between each HTTP retry.
DELAY_RETRY = 1

# Max number of concurrent HTTP requests during data retrieval.
THREADS = 1
MAX_THREADS = 10
# Thread count '-o' raises to, unless '--threads' was given.
OPTIMIZE_THREADS = 3
# Whether persistent (Keep-Alive) connections are in use.
KEEP_ALIVE = False
# Set when a time-related retrieval could not resolve every character of the output.
INCOMPLETE_OUTPUT = False
# Output length above which a time-related retrieval asks before spending a request per character.
LARGE_OUTPUT_THRESHOLD = 500

# Locks for shared state accessed by concurrent threads.
PRINT_LOCK = _threading.Lock()
REQUESTS_LOCK = _threading.Lock()

# Whether the last stdout line is still open (progress refresh / spinner dot).
PROGRESS_LINE_OPEN = False

DEFAULT_INJECTION_LEVEL = 1
COOKIE_INJECTION_LEVEL = 2
HTTP_HEADER_INJECTION_LEVEL = 3

# Level of tests to perform.
# The higher the value is, the higher the number of HTTP(s) requests are. (Default: 1)
INJECTION_LEVEL = 0
USER_APPLIED_LEVEL = False
USER_APPLIED_RETRIES = False
PERFORM_BASIC_SCANS = True

# Default Temp Directory
TMP_PATH = ""

# Default Server's Web-Root Directory
WEB_ROOT = ""
DEFAULT_WEB_ROOT = ""
CUSTOM_WEB_ROOT = False
CUSTOM_FILENAME = ""

# Whether '--web-root' was explicitly supplied on the CLI
USER_APPLIED_WEB_ROOT = False
USER_APPLIED_INTERPRETER = False
USER_APPLIED_TIMESEC = False
USER_APPLIED_TMP_PATH = False

# Whether '--auth-cred'/'--auth-type' were explicitly supplied on the CLI
USER_APPLIED_COOKIE = ""
USER_APPLIED_DATA = ""
USER_APPLIED_AUTH_CRED = False
USER_APPLIED_AUTH_TYPE = False

# Counting the total of HTTP(S) requests
TOTAL_OF_REQUESTS = 0
# Log-file report state.
LOGGED_FINDINGS_HEADER = False
LAST_LOGGED_PARAMETER = None
# The accumulating --report-json data, built only when that option is set.
REPORT_JSON = None
LAST_LOG_GROUP = "header"

# The max help option length.
MAX_OPTION_LENGTH = 18

# Python version.
PYTHON_VERSION = sys.version.split()[0]

# Enumeration Commands
# Output PowerShell's version number
PS_VERSION = "powershell.exe -NoProfile -InputFormat none write-host ($PSVersionTable.PSVersion.ToString(2))"

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
# Used by "download", so the file's exact bytes survive.
FILE_READ_B64 = "base64 <"
WIN_FILE_READ_B64 = "powershell.exe -c \"[Convert]::ToBase64String([IO.File]::ReadAllBytes('{}'))\""
FILE_WRITE_OPERATOR = " >"
FILE_APPEND_OPERATOR = " >>"
WIN_FILE_WRITE_OPERATOR = "powershell.exe Set-Content "
WIN_FILE_READ = "powershell.exe get-Content "

# List file
FILE_LIST = "ls "
FILE_LIST_WIN = "powershell.exe Test-Path -Path "

CERTUTIL_DECODE_CMD = "certutil -decode "

# Write file
FILE_WRITE = "printf "

# /etc/passwd
PASSWD_FILE = "/etc/passwd"

SYS_USERS = "awk -F ':' '{print $1}{print $3}{print $6}' " + PASSWD_FILE

# Exports users of localgroup
WIN_SYS_USERS = "powershell.exe -InputFormat none write-host (([string]$(net user)[4..($(net user).length-3)]))"
DEFAULT_WIN_USERS = ["Administrator", "DefaultAccount", "Guest"]

# What the target says instead of a list when the account running it may not ask for one. Seeing a
# built-in name is not the test - they can be renamed or removed - so this is what tells a refusal
# from a perfectly good enumeration of accounts we happen not to recognise.
WIN_ACCESS_DENIED = ["Access is denied", "System error 5", "not have permission", "Logon failure"]

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

# Remembers the answer to the "unexpected time delays" prompt.
UNSTABLE_REQUEST_CHOICE = None

# Remembers the answer to the "'/bin/' path prefix" prompt.
USE_BIN_SUBDIR_CHOICE = None

# How many seconds "Continue" has already added to timesec, capped by MAX_UNSTABLE_TIMESEC_BUMP.
UNSTABLE_REQUEST_BUMPS = 0

# Maximum cumulative seconds "Continue" may add to timesec over the run.
MAX_UNSTABLE_TIMESEC_BUMP = 5

# Available alternative shells
AVAILABLE_INTERPRETERS = ["python"]

"""
The short names a language is just as often written as, and what each one means.

'--eval' and '--interpreter' both take a language, so both read the same table - naming one of them
'py' should not be an error where naming it 'python' is not.
"""
LANGUAGE_ALIASES = {"py": "python", "python2": "python", "python3": "python", "php7": "php",
                    "php8": "php", "pl": "perl", "rb": "ruby"}

# The name a language was given by, resolved to the one commix knows it as.
def resolve_language(name):
  if not name:
    return name
  name = str(name).strip().lower()
  return LANGUAGE_ALIASES.get(name, name)

# Available injection techniques. Out-of-band is not one of them - it is the '--oob' switch, so that
# it can serve the modules too, which never go through '--technique'.
AVAILABLE_TECHNIQUES = ['c','t','f']
# The letter that used to name the evaluation sink before '--eval' did, the technique that reaches
# that sink today, and the one whose technique carries whichever sink it is given.
EVAL_TECHNIQUE_LETTER = 'e'
EVAL_CAPABLE_TECHNIQUES = ('c', 't', 'f')
OOB_TECHNIQUE_LETTER = 'o'
# The languages the evaluation sink knows how to reach, and the word standing for all of them.
SUPPORTED_EVAL_LANGUAGES = _eval.supported()

"""
Point the code injection grammar at one language, so that everything derived from it - the probe,
the boundaries, the functions that run a command - is that language's rather than the default's.
"""
LEVEL_SCOPED = ("SEPARATORS", "PREFIXES", "SUFFIXES", "EVAL_PREFIXES", "EVAL_SUFFIXES",
                "EVAL_SEPARATORS", "EXECUTION_FUNCTIONS")

"""
Narrow the boundary lists to the level being tested, taking each from its own '_LVL<n>' source.

Called again whenever those sources change - pointing the grammar at another language rewrites them,
and the lists the payloads are actually built from are these, not the sources.
"""
def apply_injection_level(level=None):
  suffix = {DEFAULT_INJECTION_LEVEL: "LVL1", COOKIE_INJECTION_LEVEL: "LVL2",
            HTTP_HEADER_INJECTION_LEVEL: "LVL3"}.get(INJECTION_LEVEL if level is None else level)
  if not suffix:
    return False
  for name in LEVEL_SCOPED:
    source = globals()[name + "_" + suffix]
    globals()[name] = sorted(set(source), key=source.index)
  return True

# Speak a different language: every payload is built from the grammar set here.
def set_eval_grammar(language):
  global EVAL_GRAMMAR, EVAL_PROBE_PAYLOADS, EVAL_PROBE_REGEX, EVAL_WARNINGS
  global EXECUTION_FUNCTIONS_LVL1, EXECUTION_FUNCTIONS_LVL2, EXECUTION_FUNCTIONS_LVL3
  global EVAL_SEPARATORS_LVL1, EVAL_SEPARATORS_LVL2, EVAL_SEPARATORS_LVL3
  global EVAL_PREFIXES_LVL1, EVAL_PREFIXES_LVL2, EVAL_PREFIXES_LVL3
  global EVAL_SUFFIXES_LVL1, EVAL_SUFFIXES_LVL2, EVAL_SUFFIXES_LVL3
  EVAL_GRAMMAR = _eval.grammar(language)
  EVAL_PROBE_PAYLOADS = EVAL_GRAMMAR.PROBE_PAYLOADS
  EVAL_PROBE_REGEX = EVAL_GRAMMAR.PROBE_REGEX
  EVAL_WARNINGS = EVAL_GRAMMAR.WARNINGS
  EXECUTION_FUNCTIONS_LVL1 = EVAL_GRAMMAR.EXECUTION_FUNCTIONS_LVL1
  EXECUTION_FUNCTIONS_LVL2 = EVAL_GRAMMAR.EXECUTION_FUNCTIONS_LVL2
  EXECUTION_FUNCTIONS_LVL3 = EVAL_GRAMMAR.EXECUTION_FUNCTIONS_LVL3
  EVAL_SEPARATORS_LVL1 = EVAL_GRAMMAR.SEPARATORS_LVL1
  EVAL_SEPARATORS_LVL2 = EVAL_GRAMMAR.SEPARATORS_LVL2
  EVAL_SEPARATORS_LVL3 = EVAL_GRAMMAR.SEPARATORS_LVL3
  EVAL_PREFIXES_LVL1 = EVAL_GRAMMAR.PREFIXES_LVL1
  EVAL_PREFIXES_LVL2 = EVAL_GRAMMAR.PREFIXES_LVL2
  EVAL_PREFIXES_LVL3 = EVAL_GRAMMAR.PREFIXES_LVL3
  EVAL_SUFFIXES_LVL1 = EVAL_GRAMMAR.SUFFIXES_LVL1
  EVAL_SUFFIXES_LVL2 = EVAL_GRAMMAR.SUFFIXES_LVL2
  EVAL_SUFFIXES_LVL3 = EVAL_GRAMMAR.SUFFIXES_LVL3
  # The lists the payloads are built from are narrowed from the sources just rewritten, so they are
  # taken again - otherwise the language named on the command line never reaches a single payload.
  apply_injection_level()
EVAL_ALL_LANGUAGES = 'all'
# Said once per run, however many parameters the heuristic sees an evaluation sink on.
EVAL_SUGGESTED = False

# Supported injection types
class INJECTION_TYPE(object):
  RESULTS_BASED_CI = "results-based command injection"
  RESULTS_BASED_CE = "results-based code injection"
  BLIND = "blind command injection"
  BLIND_CE = "blind code injection"
  SEMI_BLIND = "semi-blind command injection"
  SEMI_BLIND_CE = "semi-blind code injection"

# The injection types that name a code-evaluation sink rather than a command one. What was found
# is recorded as a type, so a stored finding is read back through this rather than through the
# technique that found it - the same technique serves either sink.
EVAL_INJECTION_TYPES = (INJECTION_TYPE.RESULTS_BASED_CE, INJECTION_TYPE.BLIND_CE, INJECTION_TYPE.SEMI_BLIND_CE)

# Supported injection techniques
class INJECTION_TECHNIQUE(object):
  CLASSIC = "classic command injection technique"
  DYNAMIC_CODE = "dynamic code evaluation technique"
  TIME_BASED = "time-based command injection technique"
  FILE_BASED = "file-based injection technique"
  TEMP_FILE_BASED = "tempfile-based injection technique"
  OOB = "out-of-band command injection technique"

# Canonical order techniques are tested and reported in.
TECHNIQUE_ORDER = [INJECTION_TECHNIQUE.CLASSIC, INJECTION_TECHNIQUE.DYNAMIC_CODE, INJECTION_TECHNIQUE.TIME_BASED, INJECTION_TECHNIQUE.FILE_BASED, INJECTION_TECHNIQUE.TEMP_FILE_BASED, INJECTION_TECHNIQUE.OOB]

USER_APPLIED_TECHNIQUE = False
SKIP_TECHNIQUES = False

# Out-of-band (OAST) support.
OOB_PROVIDER_INTERACTSH = "interactsh"
OOB_INTERACTSH_DOMAIN = "oast.fun"
OOB_SERVER = ""
OOB_TOKEN = ""
OOB_TIMEOUT = 15
OOB_POLL_INTERVAL = 5
# How often a wait asks the server itself, instead of sitting out the interval above. An interaction
# is on the server long before the next poll would bring it in, and a wait is the part of a run that
# has something to wait for - so it asks harder than the idle poller does.
OOB_WAIT_POLL_INTERVAL = 2
OOB_CHANNEL = None
OOB_TRANSPORT = ""
# The client the heuristic saw answer, tried first by the technique that follows it.
OOB_HEURISTIC_TRANSPORT = ""

# How many times a command's output is asked for over a name lookup before giving up on it.
OOB_DNS_ATTEMPTS = 2
# The HTTP clients the heuristic asked and never heard from, through a payload a name lookup proved
# had run. The sweep leaves those out and leads with the lookup instead of paying for them again.
OOB_HEURISTIC_HTTP_SILENT = []
OOB_EVAL = False
# Payloads reach the server over the same scheme it is polled on, so that command output is not
# sent in the clear unless the user asked for a plain-HTTP server.
OOB_SCHEME = "https"
# The port the payload's URL carries, when the out-of-band server is not on the scheme's own one.
OOB_PORT = None
# An out-of-band payload never reads the response, so a target that takes too long to answer has
# not failed - the interaction arrives on its own. Set once the channel is up.
OOB_IGNORE_TIMEOUT = False
# Seconds to wait on a probe's response before moving on. Some clients block for tens of seconds
# ('certutil' well past a minute), which would make a sweep take hours for nothing.
OOB_PROBE_TIMEOUT = 5
# Seconds the heuristic keeps waiting for an HTTP client once a name lookup has already answered,
# so the sweep is handed the client that can carry a command's output back whole.
OOB_HTTP_GRACE = 4
# How many of a sweep's first combinations are polled for eagerly, instead of waiting out the
# interval. The likeliest boundary comes first, so this usually ends the sweep after a few probes.
OOB_EAGER_POLLS = 3
SHELLSHOCK_OOB = False

# The tamper-count warning is per run, not per technique announcement.
TAMPER_WARNING_SHOWN = False

"""
The TLS context for target requests - a target's certificate is routinely self-signed or expired.
"""
def unverified_context():
  import ssl
  return ssl._create_unverified_context()

"""
The TLS context for commix's own infrastructure calls, which are verified.
"""
def verified_context():
  import os, ssl
  context = ssl.create_default_context()
  paths = ssl.get_default_verify_paths()
  if not (paths.cafile or paths.capath):
    for bundle in ("/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt",
                   "/etc/pki/tls/certs/ca-bundle.crt", "/usr/local/etc/openssl/cert.pem"):
      if os.path.exists(bundle):
        return ssl.create_default_context(cafile=bundle)
  return context
SKIP_OOB_INJECTIONS = False

# Raised by checks.handle_detection_interrupt() to unwind to the right point
# in the detection loop.
class SkipTechniqueException(Exception):
  pass

class EndDetectionPhaseException(Exception):
  pass

class NextParameterException(Exception):
  pass

class NextTargetException(Exception):
  pass

# Raised after a verbosity change mid-detection, to redo the current technique from the top.
class RetryTechniqueException(Exception):
  pass

# Default Scheme
SCHEME = ""

# TOR HTTP Proxy
TOR_HTTP_PROXY_IP = "127.0.0.1"
TOR_HTTP_PROXY_PORT = "8118"
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
        "use",
        "run",
        "set",
        "show",
        "download",
        "upload",
]

# Accepted reverse tcp shell menu options
SET_OPTIONS = [
        "LHOST",
        "RHOST",
        "LPORT",
        "SRVPORT",
        "URIPATH",
        "HANDLER",
]

# Delimiter used to separate individual cookies in the Cookie HTTP header
COOKIE_PARAM_DELIMITER = ";"
# Seconds spent waiting for the file of the '--live-cookies' option to hold something.
LIVE_COOKIES_TIMEOUT = 120

# Split parameter value
PARAMETER_SPLITTING_REGEX = ","

# Delimiter used to separate parameters in POST request body
POST_DATA_PARAM_DELIMITER = "&"

# Delimiter used to separate query parameters in a URL
URL_PARAM_DELIMITER = "&"

DEFAULT_CODEC = "utf8"

# Reference: http://en.wikipedia.org/wiki/ISO/IEC_8859-1
DEFAULT_PAGE_ENCODING = "iso-8859-1"
try:
  codecs.lookup(DEFAULT_PAGE_ENCODING)
except LookupError:
  DEFAULT_PAGE_ENCODING = DEFAULT_CODEC

# Whether this platform can actually read a charset, which a hand-kept list of names cannot say.
def known_encoding(name):
  try:
    return bool(name) and bool(codecs.lookup(str(name).strip()))
  except (LookupError, TypeError, ValueError):
    return False

"""
Whether a charset leaves plain ASCII alone.

What a payload is found by is a marker of ASCII letters, and a page only claims its encoding - a
page that claims one of the wide ones and serves something else is read as gibberish, the marker
with it, and the parameter is reported as not injectable. The claim is only worth acting on where
being wrong about it cannot cost that much: for these, being wrong costs the accented characters.
"""
def ascii_transparent_encoding(name):
  try:
    return "commix".encode(str(name).strip()) == b"commix"
  except (LookupError, TypeError, ValueError, UnicodeEncodeError):
    return False

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

# FIle access options
FILE_ACCESS_DONE = False

# Set when '--file-dest' targets the "/tmp/" directory, to switch straight to the tempfile-based technique.
CALL_TMP_BASED = False

# XML Data
IS_XML = False

# Regular expression for XML POST data
XML_RECOGNITION_REGEX = r'(?s)\A\s*<[^>]+>(.+>)?\s*\Z'

# JSON Data
IS_JSON = False
IS_VALID_JSON = False
# Whether the URL fragment being dropped has already been reported.
FRAGMENT_IGNORED = False
# Whether repeated JSON keys have already been reported.
DUPLICATE_JSON_KEYS_WARNED = False

# Indentation and separators of the JSON body as supplied, so it is rebuilt the way it arrived.
JSON_FORMATTING = (2, None)

# Whitespace between the XML tags as supplied, so the body is rebuilt the way it arrived.
XML_TAG_SEPARATORS = []

# Parameters holding session or framework state: injecting into one of these does not test the
# application, it logs the session out or makes the request invalid before it is even handled.
IGNORE_PARAMETERS = ("__VIEWSTATE", "__VIEWSTATEENCRYPTED", "__VIEWSTATEGENERATOR", "__EVENTARGUMENT",
                     "__EVENTTARGET", "__EVENTVALIDATION", "__SCROLLPOSITIONX", "__SCROLLPOSITIONY",
                     "__PREVIOUSPAGE", "ASPSESSIONID", "ASP.NET_SESSIONID", "JSESSIONID", "PHPSESSID",
                     "SESSID", "CFID", "CFTOKEN")

# Infixes used for automatic recognition of parameters carrying anti-CSRF tokens
CSRF_TOKEN_PARAMETER_INFIXES = ("csrf", "xsrf", "token", "nonce")

# Largest chunk built by the '--chunked' switch, small enough to break up what a filter looks for.
MAX_CHUNK_SIZE = 9
# Tokens a chunk is not allowed to hold whole, so none of them is ever visible in a single chunk.
CHUNKED_SPLIT_KEYWORDS = (
  "cat", "echo", "ping", "wget", "curl", "nc", "bash", "sh", "python", "perl", "whoami", "uname",
  "ifconfig", "ipconfig", "netstat", "dir", "type", "powershell", "cmd", "sleep", "timeout",
  "passwd", "etc", "bin", "system32", "&&", "||", ";", "|", "`", "$(", "${"
)
CHUNKED_SPLIT_KEYWORDS_REGEX = "|".join(re.escape(_) for _ in CHUNKED_SPLIT_KEYWORDS)

# Regular expression used for detecting JSON POST data
JSON_RECOGNITION_REGEX = r'(?s)\A(\s*\[)*\s*\{.*"[^"]+"\s*:\s*("[^"]*"|\d+|true|false|null).*\}\s*(\]\s*)*\Z'

# Regular expression used for detecting JSON-like POST data
JSON_LIKE_RECOGNITION_REGEX = r"(?s)\A(\s*\[)*\s*\{.*'[^']+'\s*:\s*('[^']+'|\d+).*\}\s*(\]\s*)*\Z"

# Base64 format recognition
BASE64_RECOGNITION_REGEX = r'^[A-Za-z0-9+/]+[=]{0,2}$'

# Hex encoded characters recognition
HEX_RECOGNITION_REGEX = r'^(0[xX])?[0-9a-fA-F]+$'

# Ignore short values that can coincidentally match the base64/hex charset.
ENCODING_MIN_LENGTH = 8

# Minimum printable-character ratio for treating a base64/hex charset match as encoded.
ENCODING_PLAUSIBILITY_RATIO = 0.85

DIRECTORY_REGEX = r'(?:/[^/]+)+?/\w+\.\w+'

# TFB Decimal
TFB_DECIMAL = False

# Ignore Error Message
IGNORE_ERR_MSG = False

# Windows PHP installed directory.
WIN_PHP_DIR = "C:\\xampp\\php\\php.exe"
USER_DEFINED_PHP_DIR = False

# Comment out
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
_ANSI_COLOR_REMOVAL_REGEX = re.compile(ANSI_COLOR_REMOVAL)

# The text with its colour codes taken out, for anywhere they would be read literally.
def strip_ansi_codes(text):
  return _ANSI_COLOR_REMOVAL_REGEX.sub("", text)

# Default LHOST / LPORT / RHOST setup,
# for the reverse TCP connection
LHOST = ""
LPORT = ""
# for the bind TCP connection
RHOST = ""
# Default settings (web_delivery).
URIPATH = "/"
SRVPORT = 8080

# Catch bind/reverse shells with a built-in listener instead of an external nc/ncat.
HANDLER = False
LAST_SELECTED_MODULE = ""

# Session Handler
SESSION_FILE = ""
LOAD_SESSION = None
# Whether a stored technique likely exists for the current target (host + method).
LIKELY_RESUME = False
# Cache stored techniques per parameter.
STORED_TECHNIQUES = {}
# Pending file/tempfile-based cleanups, asked at quit() - keyed by output file path.
PENDING_FILE_CLEANUPS = {}

# Output files written on the target, listed once per target when it is done with.
LEFTOVER_FILES = []
# Findings confirmed this run, for the end-of-run summary.
CONFIRMED_INJECTION_POINTS = []
# (prefix, suffix, separator, whitespace) confirmed by one technique, tried first by the others.
CONFIRMED_BOUNDARY = {}
# Whether the "keep testing others" prompt already fired for this target.
ASKED_KEEP_TESTING = False
# Post-detection actions (enumeration, file access, --os-cmd), deferred until quit().
PENDING_POST_DETECTION_ACTIONS = []
OS_CMD_DONE = False
# The single deferred --os-shell entry, run at quit().
PENDING_OS_SHELL_ENTRY = None
# Guards the resumed-session log notice against quit()'s recursion.
LOGS_NOTIFICATION_SHOWN = False
# Set once a finding is worth suggesting '--os-shell' for, printed where the run ends.
OS_SHELL_SUGGESTION_PENDING = False

# Path to file containing desktop/browser User-Agent strings
USER_AGENT_LIST = os.path.join(TXT_DIR, "user-agents.txt")

# Path to file containing mobile User-Agent strings
MOBILE_USER_AGENT_LIST = os.path.join(TXT_DIR, "mobile-user-agents.txt")

# Path to file with default username values
USERNAMES_TXT_FILE = os.path.join(TXT_DIR, "default_usernames.txt")

# Path to file with default password values
PASSWORDS_TXT_FILE = os.path.join(TXT_DIR, "default_passwords.txt")

# Path to file with known CGI scripts/pages potentially vulnerable to Shellshock
CGI_SCRIPTS = os.path.join(TXT_DIR, "shocker-cgi_list.txt")

REQUIRED_AUTHENTICATION = False

INJECTION_CHECKER = False

INSTALL_DIR = "/usr/share/"
WRAPPER_PATH = "/usr/bin/"

# Metasploit Framework Path
METASPLOIT_PATH = INSTALL_DIR + "/metasploit-framework/"

# Supported HTTP Authentication types
class AUTH_TYPE(object):
  BASIC = "basic"
  DIGEST = "digest"
  BEARER = "bearer"

# Cached digest realm, discovered from the target's WWW-Authenticate challenge.
DIGEST_AUTH_REALM = None

RAW_HTTP_HEADERS = ""

# Request blocks of a proxy log export, delimited by rows of '=' and starting on a method token.
PROXY_LOG_REQUEST_REGEX = r"={10,}\s+([A-Z]{3,} .+?)\s+(={10,}|\Z)"
# Requests of an XML history export, stored base64-encoded with the port kept apart.
PROXY_LOG_XML_REQUEST_REGEX = r'<port>(\d+)</port>.*?<request base64="true"><!\[CDATA\[([^]]+)'
# Targets parsed from a file holding more than one request, tested one after the other.
MULTI_REQUEST_TARGETS = []
# Targets left out by the '--scope' option, reported once the target list is known.
SKIPPED_OUT_OF_SCOPE = set()

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

# Execution priority for tamper scripts; each script defines its own __priority__.
class PRIORITY(object):
  HIGHEST = 100
  HIGHER = 75
  HIGH = 50
  ABOVE_NORMAL = 25
  NORMAL = 0
  BELOW_NORMAL = -25
  LOW = -50
  LOWER = -75
  LOWEST = -100

# Tamper script pairs that cannot be combined.
# Tamper scripts turned on by themselves once a WAF/IPS is found in front of the target.
# One script per bypass class: the whitespace, the command names, the casing and the client address.
# Only one of "uninitializedvariable" / "dollaratsigns" / "backslashes" can be used, they conflict.
# Each tier is heavier than the one before, and every one is listed by descending priority.
WAF_EVASION_PROFILE = {
                  "unix" : [
                    "randomcase,xforwardedfor,uninitializedvariable,space2ifs",
                    "rev,randomcase,xforwardedfor,dollaratsigns,space2htab"
                  ],
                  "windows" : [
                    "xforwardedfor,doublequotes,caret,space2vtab",
                    "xforwardedfor,doublequotes,caret,space2htab"
                  ]
}
# What the evasion actually turned on, so it is reported once and never applied twice.
WAF_EVASION_APPLIED = ""
# Whether the user agreed to the evasion, asked once and remembered for the rest of the run.
WAF_EVASION_CONSENT = None
# Which tier of the profile is in use, stepped up while the protection keeps blocking.
WAF_EVASION_TIER = 0
# Blocked responses seen since the last step up. A block reaching here already means the evasion
# in use was not enough, so there is nothing to wait for.
WAF_BLOCKS_SINCE_EVASION = 0
WAF_ESCALATION_THRESHOLD = 1
# Set when the evasion was just stepped up, so the technique that was blocked is tried again.
WAF_EVASION_ESCALATED = False

INCOMPATIBLE_TAMPER_SCRIPTS = [
                  # "\$" is a literal "$", so the escape kills the other script's "$@" / "${XX}".
                  ("backslashes", "dollaratsigns"),
                  ("backslashes", "uninitializedvariable"),
                  # "$@" lands inside "${XX}", corrupting the variable name.
                  ("dollaratsigns", "uninitializedvariable"),
                  # "''" is literal inside the double-quoted "tr" ranges that "randomcase" builds.
                  ("randomcase", "singlequotes")
]

# Words that must survive per-character obfuscation - shell keywords stop being keywords once
# obfuscated, and user-supplied commands can still use them.
IGNORE_TAMPER_TRANSFORMATION = [
                  "IFS",
                  "if",
                  "then",
                  "elif",
                  "else",
                  "fi",
                  "for",
                  "while",
                  "until",
                  "do",
                  "done",
                  "case",
                  "esac",
                  "in",
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
TOO_MANY_REQUESTS = "429"
UNAVAILABLE_FOR_LEGAL_REASONS = "451"
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
                      TOO_MANY_REQUESTS,
                      UNAVAILABLE_FOR_LEGAL_REASONS,
                      INTERNAL_SERVER_ERROR,
                      NOT_IMPLEMENTED,
                      BAD_GATEWAY,
                      SERVICE_UNAVAILABLE,
                      GATEWAY_TIMEOUT
                    ]

# Seconds added to the delay between requests, when the target answers as if it has had enough.
ADAPTIVE_DELAY = 0
# The delay stops moving once a time-related technique depends on it, since a delay that changed
# between the baseline and the measurements would read as the delay the payload was asked for.
ADAPTIVE_DELAY_FROZEN = False
# Where the backing off stops, and how many answered requests it takes to give a second back.
MAX_ADAPTIVE_DELAY = 8
ADAPTIVE_DELAY_RECOVERY = 10
ADAPTIVE_DELAY_STREAK = 0

# HTTP status codes a WAF/IPS typically returns when it blocks a request.
WAF_BLOCK_HTTP_CODES = [ FORBIDDEN_ERROR,
                         NOT_ACCEPTABLE_ERROR,
                         TOO_MANY_REQUESTS,
                         UNAVAILABLE_FOR_LEGAL_REASONS,
                         NOT_IMPLEMENTED,
                         SERVICE_UNAVAILABLE
                       ]

HTTP_ERROR_CODES_SUM = []

# End line
class END_LINE:
  CR = "\r"
  LF = "\n"
  CRLF = "\r\n"
  ESCAPED_LF = "\\n"

# List of end lines
END_LINES_LIST = [attr for attr in dir(END_LINE) if not callable(getattr(END_LINE, attr)) and not attr.startswith("__")]

# Check for updates on start up.
CHECK_FOR_UPDATES_ON_START = True

# Skip the mathematic calculation (Detection Phase)
SKIP_CALC = False

USE_BACKTICKS = False

METASPLOIT_ERROR_MSG =  "You need to have Metasploit installed. "
METASPLOIT_ERROR_MSG += "Please ensure it is installed in the right path."

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

# Failed writes to the web root, at most, before the temporary directory is offered instead. A
# smaller set of boundaries than this is gone through in full first, rather than stopped one short.
MAX_FAILED_TRIES = 50

# Consecutive connection errors tolerated before giving up.
CONNECTION_ERROR_RETRIES = 0
MAX_CONNECTION_ERROR_RETRIES = 5

# Count of connection-error warnings shown.
VISIBLE_CONNECTION_ERRORS = 0

# Statistical model for recognizing a delay against this target's own response times.
TIME_STDEV_COEFF = 7
TIME_OUTLIER_MAD_COEFF = 10
# Decision-threshold floor and shrink-candidate validity margin.
MIN_VALID_DELAYED_RESPONSE = 0.5
# Minimum delay-threshold margin above the mean, as a fraction of the mean.
MIN_RELATIVE_DELAY_MARGIN = 0.5
WARN_TIME_STDEV = 0.5

# One escalate/shrink step, in seconds - separate from the floor above.
TIME_DELAY_STEP = 1
# Target size of the upfront baseline warm-up.
MIN_TIME_RESPONSES = 30
MAX_TIME_RESPONSES = 200
RESPONSE_TIMES = []

# Answers to the technique's own payload with a condition that cannot hold, kept apart from
# the plain requests the model is warmed up with: those two cost different amounts.
PROBE_RESPONSE_TIMES = []
MIN_PROBE_RESPONSES = 5

# Samples needed before spikes are worth stripping from a response-time model. Tied to the smaller
# of the two models rather than the larger: the probe model is read from five samples up, and left
# unfiltered until fifteen a single slow probe sets the threshold above the delay it must detect.
MIN_OUTLIER_SAMPLE = MIN_PROBE_RESPONSES
# Set once a time-related payload's own cost has been sampled into the model above.
PAYLOAD_BASELINE_SAMPLED = False
# Whether the model above was sampled the way the payloads that follow are sent - concurrently,
# where '--threads' asks for it. A target answers a request slower while it is serving others.
CONCURRENT_BASELINE = False
LAGGING_CHECKED = False
LAGGING_DETECTED = False
TIME_DELAY_CANDIDATES = 3
# Retries for a failed (not just slow) request during time-based measurement.
TIME_RELATED_ATTACK_RETRIES = 3

# Best known timesec for this target.
CALIBRATED_TIMESEC = None

# Latched once a re-verification ever fails - widens retries and upgrades checks to a vote.
JITTER_SEEN = False
MAX_LENGTH_REVALIDATIONS = 5

# Use the observed charset for bisection when it is small enough; otherwise use the full range.
NARROWING_MIN_OBSERVED = 3
NARROWING_MAX_SET_SIZE = 64

# Number of most-frequent characters probed directly before bisecting.
FREQUENCY_PROBE_TOP_K = 3

# Prevent auto-shrink from undoing a delay increase after validation.
ADJUST_TIME_DELAY_DISABLED = False

# User's one-time answer to time-sec optimization; None means not asked yet.
ADJUST_TIME_DELAY_CHOICE = None

# Count clean validations since the last retry before re-enabling automatic delay adjustment.
VALIDATION_RUN = 0
VALID_TIME_CHARS_RUN_THRESHOLD = 100

# User's one-time answer to the multi-threading safety prompt; None means not asked yet.
THREADED_TIME_RETRIEVAL_CHOICE = None

# Technique titles to suppress when a fallback already announced the transition.
# The (parameter, technique) last announced, so a re-announcement reads as "Continuing with".
LAST_ANNOUNCED_TECHNIQUE = None

# The output file last announced, so the same one is not announced again for every separator tried.
LAST_ANNOUNCED_OUTPUT_FILE = None

# The history file already reported as unwritable, so every path out of a run does not repeat it.
FAILED_HISTORY_FILE = None

# How much of git's own complaint is repeated when an update fails.
MAX_UPDATE_REASON_LENGTH = 200

# Longer than this and a retrieved value is shown fenced, rather than running off the label's line.
MAX_INLINE_VALUE_LENGTH = 80

# How many answers the concurrency probe times on each side, and the total below which it cannot say.
CONCURRENCY_PROBE_REQUESTS = 16
CONCURRENCY_PROBE_FLOOR = 0.05

# Said while the target's own response times are still being sampled, so a delay can be told apart.
TIMING_BASELINE_MSG = "Time-related response comparison requires a larger statistical model"

# Retries for the false-positive/unexploitable-point re-verification during detection.
FALSE_POSITIVE_RETRIES = 3

# Verification rounds for classic/eval/file-based.
RESULTS_BASED_VERIFY_ROUNDS = 2

# Prefix marking an interrupted command result.
PARTIAL_VALUE_MARKER = "\x02COMMIX_PARTIAL\x02"

# Max characters shown at once in the live progress line.
PROGRESS_DISPLAY_WIDTH = 60

# Init Test
INIT_TEST = ""

# URL for checking internet connection.
CHECK_INTERNET_ADDRESS = "http://ipinfo.io"

# Check internet connection.
CHECK_INTERNET = False

UNAUTHORIZED = False

# Multiple OS checks
CHECK_BOTH_OS = False
OS_CHECKS_NUM = 2

# The banner did not name an operating system, and no heuristic has answered yet either. While this
# stands, the question is still open - it is put to the user only once nothing else has settled it.
OS_IDENTIFICATION_PENDING = False

# A language the target named for itself, e.g. through 'X-Powered-By'. The sweep starts with it.
IDENTIFIED_EVAL_LANGUAGE = None

# Options to explicitly mask in anonymous (unhandled exception) reports.
# Everything that can carry a target's identity or a credential into a report meant for strangers.
SENSITIVE_OPTIONS = ["--data", "-d", "--cookie", "-p", "--url", "-u", "-x", "--auth-cred", "-r", "-l",
                     "--proxy", "--header", "-H", "--headers", "--load-cookies", "--live-cookies",
                     "--csrf-token", "--host", "--referer"]

CAPTCHA_DETECED = None

BROWSER_VERIFICATION = None

# Regular expression used for recognition of generic "your ip has been blocked" messages.
BLOCKED_IP_REGEX = r"(?i)(\A|\b)ip\b.*\b(banned|blocked|block list|firewall)"

BLOCKED_IP_DETECTED = None

# Prefix for Google analytics cookie names
GOOGLE_ANALYTICS_COOKIE_REGEX = r"(?i)\A(_ga|_gid|_gat|_gcl_au|__utm[abcz])"

# Default path for tamper scripts
TAMPER_SCRIPTS_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '../',"tamper/")) + "/"

# Default path for settings.py file
SETTINGS_PATH = os.path.abspath(__file__)

# Period after last-update to start nagging (about the old revision).
NAGGING_DAYS = 31

# Stamp of the stored-session layout, part of every table name so that entries written by an
# earlier layout are never read back into a newer one; bump it whenever that layout changes.
SESSION_MILESTONE_VALUE = "sBxrpPDiKF"

TARGET_URL = ""
# Host:port (matches session_handler.table_name()'s hashing), unlike TARGET_URL above.
TARGET_NETLOC = ""
DOC_ROOT_TARGET_MARK = "%TARGET%"

# Windows common document roots
WINDOWS_DEFAULT_DOC_ROOTS = [
                  "C:\\Inetpub\\wwwroot\\",    # IIS default
                  "C:\\xampp\\htdocs\\",       # XAMPP default
                  "C:\\wamp\\www\\",           # WAMP default
                  "C:\\laragon\\www\\",        # Laragon default
                  "D:\\Inetpub\\wwwroot\\",    # IIS on D: drive (less common)
]
# Linux common document roots
LINUX_DEFAULT_DOC_ROOTS = [
                  "/var/www/html/",                                      # Debian/Ubuntu Apache default
                  "/var/www/" + DOC_ROOT_TARGET_MARK + "/public_html/",  # Older Debian/Ubuntu with custom doc root
                  "/var/www/" + DOC_ROOT_TARGET_MARK + "/",              # Alternative Debian/Ubuntu
                  "/usr/share/nginx/html/",                              # Nginx default
                  "/usr/local/apache2/htdocs/",                          # Apache default (source build)
                  "/usr/local/www/data/",                                # BSD-style
                  "/var/apache2/htdocs/",                                # Older Apache distros
                  "/var/www/nginx-default/",                             # Nginx variation
                  "/srv/www/htdocs/",                                    # SUSE/Fedora style
                  "/usr/local/lsws/DEFAULT/html/"                        # LiteSpeed default
]

"""
Where each web server commix recognises keeps its document root, per platform.

Named rather than indexed, so the lists above can be reordered or added to without silently handing
a target somebody else's directory. A server missing from a platform has no default worth guessing.
"""
SERVER_DOC_ROOTS = {
  # Tomcat names itself "Apache Tomcat" or "Apache-Coyote", so it is looked for before Apache is.
  "coyote":        {OS.WINDOWS: "C:\\Program Files\\Apache Software Foundation\\Tomcat\\webapps\\ROOT\\",
                    OS.UNIX: "/var/lib/tomcat/webapps/ROOT/"},
  "tomcat":        {OS.WINDOWS: "C:\\Program Files\\Apache Software Foundation\\Tomcat\\webapps\\ROOT\\",
                    OS.UNIX: "/var/lib/tomcat/webapps/ROOT/"},
  "microsoft-iis": {OS.WINDOWS: "C:\\Inetpub\\wwwroot\\"},
  "apache":        {OS.WINDOWS: "C:\\xampp\\htdocs\\", OS.UNIX: "/var/www/html/"},
  "openresty":     {OS.WINDOWS: "C:\\openresty\\html\\", OS.UNIX: "/usr/share/nginx/html/"},
  "nginx":         {OS.WINDOWS: "C:\\nginx\\html\\", OS.UNIX: "/usr/share/nginx/html/"},
  "litespeed":     {OS.UNIX: "/usr/local/lsws/DEFAULT/html/"},
  "lighttpd":      {OS.UNIX: "/var/www/html/"},
  "jetty":         {OS.UNIX: "/var/lib/jetty/webapps/ROOT/"},
  "caddy":         {OS.UNIX: "/usr/share/caddy/"},
}

DEFINED_WEBROOT = RECHECK_FILE_FOR_EXTRACTION = False

# HTTP Headers
COOKIE = "Cookie"
HOST = "Host"
USER_AGENT = "User-Agent"
REFERER = "Referer"
ACCEPT = "Accept"
ACCEPT_ENCODING = "Accept-Encoding"
AUTHORIZATION = "Authorization"
CONTENT_LENGTH = "Content-Length"
CONNECTION = "Connection"
TRANSFER_ENCODING = "Transfer-Encoding"
PROXY_CONNECTION = "Proxy-Connection"
IF_MODIFIED_SINCE = "If-Modified-Since"
IF_NONE_MATCH = "If-None-Match"
CONTENT_TYPE = "Content-Type"
SERVER = "Server"
SET_COOKIE = "Set-Cookie"
X_POWERED_BY = "X-Powered-By"
# HTTP Headers values
ACCEPT_VALUE = "*/*"
# What a body is sent as, unless it is recognised as one of the two below.
DEFAULT_HTTP_CONTENT_TYPE_VALUE = "application/x-www-form-urlencoded"
HTTP_CONTENT_TYPE_JSON_HEADER_VALUE = "application/json"
HTTP_CONTENT_TYPE_XML_HEADER_VALUE = "application/xml"
# Only what the response handling can actually decompress is asked for.
HTTP_ACCEPT_ENCODING_HEADER_VALUE = "gzip,deflate"

# The web server named by the 'Server' header, and the ones that are recognised.
SERVER_BANNER = ""
SERVER_BANNERS = [
    "Microsoft-IIS",
    # Ahead of the bare "Apache" below: Tomcat names itself with it, and keeps its own document root.
    r"Apache[ -](?:Tomcat|Coyote)/?([\w\.]+)?",
    "Apache",
    r"Nginx/([\w\.]+)",
    r"Jetty\(?([\w\.]+)?\)?",
    r"Caddy",
    r"GWS/([\w\.]+)",
    r"lighttpd/([\w\.]+)",
    r"openresty/([\w\.]+)",
    r"LiteSpeed/([\w\.]+)",
    r"Sun-ONE-Web-Server/([\w\.]+)"
]

# HTTP Headers
HTTP_HEADERS = [ USER_AGENT.lower(), REFERER.lower(), HOST.lower() ]
SHELLSHOCK_HTTP_HEADERS =[ COOKIE, USER_AGENT, REFERER ]

# Where a payload is carried, named by whatever dispatched the parameter rather than worked out
# from its name - a body field called 'host' is a body field, not the header it shares a name with.
CUSTOM_HEADER_PLACE = "(custom) HEADER"
HTTP_HEADER_PLACES = [ USER_AGENT, REFERER, HOST, CUSTOM_HEADER_PLACE ]

# The names a standard header answers to, so '-p'/'--skip-parameter' can name one as it is written.
HTTP_HEADER_ALIASES = {
                        USER_AGENT : ( "ua", "useragent", "user-agent" ),
                        REFERER : ( "ref", "referer", "referrer" ),
                        HOST : ( "host", ),
                      }

IGNORE_JSON_CHAR_REGEX = r"[{}\"\[\]]"

FLATTEN_JSON_SEPARATOR = ''.join(random.choice("{}") for _ in range(10)) + "_"
JSON_ENUMERATION_STARTED = False

PERFORM_CRACKING = False

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
# HTTP error codes already warned about, kept apart from what the user chose to ignore.
WARNED_HTTP_ERROR_CODES = set()

# Default crawling depth
DEFAULT_CRAWLING_DEPTH = 1

# Matches a "key=" pair with an empty value in a query/POST-data string, bounded by '&' or start/end.
EMPTY_FORM_FIELDS_REGEX = r'(&|\A)(?P<result>[^=&]+=)(?=&|\Z)'

SITEMAP_CHECK = None

SITEMAP_XML_FILE = "sitemap.xml"

FOLLOW_REDIRECT = True

# Set predefined answers (e.g. "quit=N,follow=N").
ANSWERS = ""

CHECKING_PARAMETER = ""

# Run host OS command(s) when injection point is found.
ALERT = False

PCRE_MODIFIER = "/e"


"""
State that belongs to the run and not to any one target: what the user asked for on the command
line, what has already been answered once and should not be asked again, and the tallies kept
across every target. Everything else is taken back to what it held before the first target, so
that nothing worked out about one target is read as true of the next. A new name is per-target
unless it is listed here - the omission that used to leak is now the safe direction.
"""
RUN_WIDE_STATE = frozenset((
  # Asked for on the command line, or worked out from it before any target was touched.
  "ABORT_CODE", "ALERT", "ANSWERS", "CHECK_FOR_UPDATES_ON_START", "CHECK_INTERNET",
  "CHECK_INTERNET_ADDRESS", "CLI_HISTORY", "CONNECTION_ERROR_RETRIES", "COOKIE_PARAM_DELIMITER",
  "DEFAULT_CODEC", "DEFAULT_CRAWLING_DEPTH", "DEFAULT_PAGE_ENCODING", "DELAY", "EXTRA_HTTP_HEADERS",
  "HTTP_METHOD", "IGNORE_CODE", "INJECT_TAG", "KEEP_ALIVE", "LHOST", "LINUX_PYTHON_INTERPRETER",
  "LPORT", "MAXLEN", "MAX_RETRIES", "METASPLOIT_PATH", "OOB_IGNORE_TIMEOUT", "OOB_POLL_INTERVAL",
  "OOB_PORT", "OOB_SCHEME", "OOB_SERVER", "OOB_TOKEN", "OOB_TRANSPORT", "PERFORM_CRACKING",
  "POST_CUSTOM_INJECTION_MARKER_CHAR", "PRE_CUSTOM_INJECTION_MARKER_CHAR", "RAW_HTTP_HEADERS",
  "REPORT_JSON", "RHOST", "SKIP_CALC", "SKIP_PARAMETERS_LIST", "SKIP_TECHNIQUES", "SRVPORT",
  "THREADS", "TIMEOUT", "TMP_PATH", "TOR_HTTP_PROXY_PORT", "URIPATH", "URL_PARAM_DELIMITER",
  "URL_RELOAD", "USER_DEFINED_PHP_DIR", "USER_DEFINED_PYTHON_DIR", "USER_DEFINED_PYTHON_INTERPRETER",
  "VERBOSITY_LEVEL", "WIN_PHP_DIR", "WIN_PYTHON_INTERPRETER",
  "USER_APPLIED_AUTH_CRED", "USER_APPLIED_AUTH_TYPE", "USER_APPLIED_CMD", "USER_APPLIED_COOKIE",
  "USER_APPLIED_DATA", "USER_APPLIED_LEVEL", "USER_APPLIED_RETRIES", "USER_APPLIED_TAMPER",
  "USER_APPLIED_TECHNIQUE", "USER_APPLIED_WEB_ROOT", "USER_APPLIED_INTERPRETER",
  "USER_APPLIED_TIMESEC", "USER_APPLIED_TMP_PATH",
  # Answered once by the user, and not worth asking again for every target.
  "ADJUST_TIME_DELAY_CHOICE", "IGNORE_IDENTIFIED_TARGET_OS", "RECOGNISE_OS",
  "THREADED_TIME_RETRIEVAL_CHOICE", "USE_BIN_SUBDIR_CHOICE", "WAF_EVASION_CONSENT",
  # Counted or noted for the run as a whole.
  "CRAWLED_SKIPPED_URLS_NUM", "CRAWLED_URLS_INJECTED", "CRAWLED_URLS_NUM", "CRAWLING",
  "CRAWLING_PHASE", "ENUMERATION_DONE", "FILE_ACCESS_DONE", "HANDLER", "HREF_SKIPPED",
  "HTTP_ERROR_CODES_SUM", "IDENTIFIED_WARNINGS", "INIT_TEST", "LAST_DOT_BUCKET", "LAST_LOG_GROUP",
  "LAST_LOGGED_PARAMETER", "LAST_SELECTED_MODULE", "LIKELY_RESUME", "LOGGED_FINDINGS_HEADER",
  "MULTI_REQUEST_TARGETS", "MULTI_TARGETS", "OS_CHECKS_NUM", "PROGRESS_LINE_OPEN", "READLINE_ERROR",
  "SESSION_FILE", "SHOW_LOGS_MSG", "TAMPER_SCRIPTS", "SITEMAP_CHECK", "SKIPPED_OUT_OF_SCOPE", "SKIP_VULNERABLE_HOST",
  "STDIN_PARSING", "TAMPER_WARNING_SHOWN", "TIME_RELATED_ATTACK_WARNING", "TOTAL_OF_REQUESTS", "EVAL_SUGGESTED",
  "VALIDATION_RUN", "VISIBLE_CONNECTION_ERRORS", "WARNED_HTTP_ERROR_CODES",
  # Set by the connection to whichever target is in hand, before this reset can be reached.
  "HOSTNAME", "SCHEME", "TARGET_NETLOC", "TARGET_URL",
))

"""
Options a target's own testing can change - a stored session replaces them, a technique settles a
directory - and which the next target is entitled to see as the user left them.
"""
RESTORED_OPTIONS = ("cookie", "data", "tamper", "os", "web_root", "tmp_path", "timesec",
                    "auth_cred", "auth_type", "level")

_TARGET_STATE_BASELINE = {}
_OPTIONS_BASELINE = {}
# Only values that can be copied without carrying a live object along with them.
_COPYABLE = (str, int, float, bool, type(None), list, dict, set, tuple, frozenset)

"""
Take the per-target state back to what it was before the first target was touched. The first call
records that baseline - at that point nothing has been learned yet - and every call after it
restores. Names listed in 'RUN_WIDE_STATE' are left alone.
"""
def reset_target_state(options=None):
  import copy
  if not _TARGET_STATE_BASELINE:
    for name, value in list(globals().items()):
      if not name.isupper() or name.startswith("_") or name in RUN_WIDE_STATE:
        continue
      if not isinstance(value, _COPYABLE):
        continue
      try:
        _TARGET_STATE_BASELINE[name] = copy.deepcopy(value)
      except Exception:
        continue
    if options is not None:
      for name in RESTORED_OPTIONS:
        if hasattr(options, name):
          _OPTIONS_BASELINE[name] = copy.deepcopy(getattr(options, name))
    return

  for name, value in _TARGET_STATE_BASELINE.items():
    globals()[name] = copy.deepcopy(value)
  if options is not None:
    for name, value in _OPTIONS_BASELINE.items():
      setattr(options, name, copy.deepcopy(value))

# eof
