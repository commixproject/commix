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

import os
import random
import string
import time

from src.utils import settings
from src.core.parse import cmdline as menu

"""
Evidence that the target really executed what was sent, rather than a restatement of what detection
already reported ('--proof').

Detection answers "does this parameter look injectable". A proof answers "run something only the
target could answer, and show the answer" - so each claim here is an experiment with a control and
a value drawn after the scan, which therefore cannot be sitting in a page, a cache or a reflection.
"""

# One entry per technique that proved the point, with the executor that reaches it.
def register(technique, vuln_parameter, http_request_method, execute_cmd, boundary=None):
  if not menu.options.proof:
    return
  for entry in settings.PROOF_EXECUTORS:
    if entry[0] == technique and entry[1] == vuln_parameter:
      return
  # The executor reads settings.TIME_RELATED_ATTACK when it runs, and a technique found later
  # changes it - so the value in force here is carried with it, as deferred actions do.
  time_related = settings.TIME_RELATED_ATTACK
  def run(cmd):
    settings.TIME_RELATED_ATTACK = time_related
    return execute_cmd(cmd)
  settings.PROOF_EXECUTORS.append((technique, vuln_parameter, http_request_method, run, boundary))

"""
A label for a technique, said the way the rest of the run says it.
"""
def _name(technique):
  from src.core.controller import checks
  try:
    name = checks.short_technique_label(technique).strip()
    return name[:-len(" technique")] if name.endswith(" technique") else name
  except Exception:
    return str(technique)

"""
A field, rendered the way the stored-session summary renders one.
"""
def _field(label, value):
  if isinstance(value, list):
    if not value:
      return ""
    head = value[0]
    rest = ["%s%s" % (" " * 21, _) for _ in value[1:]]
    return "\n".join(["%-20s %s" % (label + ":", head)] + rest)
  return "%-20s %s" % (label + ":", value)

"""
What the proof had to get through. On a filtered target this is the part that matters: the evidence
is worth more where the report also states that something was in the way and what carried data past it.
"""
def _evasion():
  lines = []
  if settings.WAF_ENABLED:
    lines.append("protection detected in front of the application")
  if settings.WAF_EVASION_APPLIED:
    lines.append("evasion applied automatically for the identified target")
  if menu.options.tamper:
    lines.append("tamper scripts in effect: " + str(menu.options.tamper))
  blocked = sorted(code for code in settings.WARNED_HTTP_ERROR_CODES
                   if str(code) in settings.WAF_BLOCK_HTTP_CODES)
  if blocked:
    lines.append("statuses a protection returns, seen during the run: " +
                 ", ".join(str(_) for _ in blocked))
  if settings.ADAPTIVE_DELAY:
    lines.append("requests were spaced out by %.1fs after the target asked for it" % settings.ADAPTIVE_DELAY)
  elif menu.options.delay:
    lines.append("requests were delayed by %.2fs each" % float(menu.options.delay))
  return lines

"""
What the challenge cost, said only where it can be counted - not every technique sends through a
path the counter sees, and a confident "0 requests" would be worse than saying nothing.
"""
def _cost(started, elapsed):
  sent = settings.TOTAL_OF_REQUESTS - started
  if sent > 0:
    return "spent:     %d request%s, %.2fs" % (sent, "s"[sent == 1:], elapsed)
  return "spent:     %.2fs" % elapsed

"""
Ask the target to work out something nobody could have written down in advance, and show what came
back. The operands are drawn here, after the scan, so the answer exists nowhere until it is computed.
"""
def _challenge(execute_cmd, technique):
  first = random.randint(1000000, 9999999)
  second = random.randint(1000000, 9999999)
  expected = str(first + second)
  marker = "".join(random.choice(string.ascii_uppercase) for _ in range(6))
  # Bracketed by a marker, so the answer cannot be mistaken for a number occurring anywhere else.
  cmd = "echo " + marker + "$((" + str(first) + "+" + str(second) + "))" + marker
  if settings.TARGET_OS == settings.OS.WINDOWS:
    cmd = "set /a " + str(first) + "+" + str(second)

  started = settings.TOTAL_OF_REQUESTS
  elapsed = time.time()
  try:
    answer = execute_cmd(cmd)
  except Exception:
    answer = ""
  elapsed = time.time() - elapsed
  answer = "".join(str(_) for _ in answer) if answer else ""

  carried = expected in answer
  lines = ["the target must work out %d + %d = %s, drawn at random after the scan started" % (first, second, expected),
           "(the product is in no page, cache or reflection - only something that executes could return it)",
           "sent:      " + cmd,
           "answered:  " + (answer.strip()[:120] if answer.strip() else "(nothing came back)"),
           _cost(started, elapsed)]
  return carried, expected, lines

"""
A technique that answers in time cannot hand the product back without spelling it out a character at
a time, which costs a request per character. Asked as a question instead, it costs two: hold the
response back if a*b is the product, and do not if a*b is the product plus one. Answering both ways
round proves the target worked the arithmetic out - not merely that it can be made to wait.
"""
def _inferential_challenge(boundary, vuln_parameter, http_request_method, technique):
  if not boundary:
    return False, ["no boundary was kept for this point, so nothing could be asked of the target"]
  separator, prefix, suffix, whitespace, url, timesec = boundary
  from src.core.controller import execution
  from src.core.requests import requests as _requests
  from src.core.controller import checks

  base = int(timesec or menu.options.timesec or settings.TIMESEC) or 3
  payloads = execution.select_payloads_module(technique)
  first = random.randint(1000000, 9999999)
  second = random.randint(1000000, 9999999)
  expected = first + second

  def _ask(target_value):
    # The technique's own conditional-delay payload, sent as one request and timed by the same code
    # that times every other one - not the extraction wrapper built on top of it.
    if settings.TARGET_OS == settings.OS.WINDOWS:
      payload = payloads.windows_condition_check(separator, str(first) + "+" + str(second),
                                                 target_value, base)
    else:
      condition = "$((" + str(first) + "+" + str(second) + ")) -eq " + str(target_value)
      payload = payloads.condition_check(separator, condition, base, http_request_method)
    if payload is None:
      return None, None
    exec_time = _requests.perform_injection(prefix, suffix, whitespace, payload, vuln_parameter,
                                            http_request_method, url)[0]
    return payload, exec_time

  started = settings.TOTAL_OF_REQUESTS
  began = time.time()
  true_payload, true_took = _ask(expected)
  false_payload, false_took = _ask(expected + 1)
  elapsed = time.time() - began

  if true_payload is None or false_payload is None:
    return False, ["this technique has no conditional-delay payload for the identified target"]

  # The product must be the one that delays, and the product plus one must not - the pair is what
  # rules out a target that is simply slow.
  carried = checks.time_related_shell(true_took, base) and not checks.time_related_shell(false_took, base)
  lines = ["the target must work out %d + %d and answer whether it is %d, drawn at random after the scan started"
           % (first, second, expected),
           "(the delay is the answer: held back where the product matches, returned at once where it does not)",
           "matches:     %.2fs" % true_took,
           "does not:    %.2fs" % false_took,
           "(one request each, timed the way every other request in the run is)",
           _cost(started, elapsed)]
  return carried, lines

"""
What an unmodified request costs, so the delays above are read against something.
"""
def _control_timing():
  if not settings.RESPONSE_TIMES:
    return []
  average = sum(settings.RESPONSE_TIMES) / float(len(settings.RESPONSE_TIMES))
  return ["unmodified request: %.3fs on average over %d samples" % (average, len(settings.RESPONSE_TIMES))]

"""
The control that rules out coincidence: the answer must not already be somewhere the run could have
read it without the target computing anything.
"""
def _control(expected):
  lines = []
  page = settings.ORIGINAL_PAGE or ""
  if page:
    lines.append("the unmodified page does not contain the answer: " +
                 ("confirmed" if expected not in page else "NOT confirmed - it is already there"))
  if settings.RESPONSE_TIMES:
    average = sum(settings.RESPONSE_TIMES) / float(len(settings.RESPONSE_TIMES))
    lines.append("unmodified request: %.3fs on average over %d samples" % (average, len(settings.RESPONSE_TIMES)))
  return lines

"""
Render the proof for every point that was confirmed, then write it beside the run's other output.
"""
def prove(filename, url):
  if not menu.options.proof or settings.PROOF_DONE or not settings.PROOF_EXECUTORS:
    return
  settings.PROOF_DONE = True

  info_msg = "Proving exploitation of the injection point(s) found."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))

  # The URL reached at quit() carries the injection marker and whatever the WAF probe appended, so
  # the target reported is the one that was asked for.
  target = menu.options.url or url or ""
  fields = [_field("Target", target)]
  if settings.USER_DEFINED_POST_DATA:
    fields.append(_field("Data", settings.USER_DEFINED_POST_DATA))
  if settings.TARGET_OS:
    platform = "Windows" if settings.TARGET_OS == settings.OS.WINDOWS else "Unix-like"
    if settings.TARGET_ARCH:
      platform += " (" + settings.TARGET_ARCH + ")"
    fields.append(_field("Back-end", platform))
  fields.append(_field("Verified", time.strftime("%Y-%m-%d %H:%M:%S")))

  proven = 0
  for technique, vuln_parameter, http_request_method, execute_cmd, boundary in settings.PROOF_EXECUTORS:
    # A technique that answers in time is proved on the clock; one that carries output is proved by
    # what came back.
    if technique in (settings.INJECTION_TECHNIQUE.TIME_BASED, settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED):
      carried, challenge = _inferential_challenge(boundary, vuln_parameter, http_request_method, technique)
      expected = None
    else:
      carried, expected, challenge = _challenge(execute_cmd, technique)
    proven += int(carried)
    fields.append("")
    fields.append(_field("Parameter", str(vuln_parameter) + " (" + str(http_request_method) + ")"))
    fields.append(_field("Technique", _name(technique)))
    fields.append(_field("Challenge", challenge))
    control = _control(expected) if expected else _control_timing()
    if control:
      fields.append(_field("Control", control))
    if carried:
      through = " through the protection in front of the application" if settings.WAF_ENABLED else ""
      if expected:
        verdict = ["PROVEN - the target executed what was sent and returned the result" + through]
      else:
        verdict = ["PROVEN - the target worked out the value and answered it through the delay" + through]
    else:
      verdict = ["NOT PROVEN - the answer did not come back through this technique"]
      if settings.WAF_ENABLED:
        verdict.append("a protection is interfering, so the point may be real with its output channel blocked")
        verdict.append("=> re-test with '--tamper', then prove again")
      else:
        verdict.append("=> treat it as unconfirmed unless a side effect proves otherwise (e.g. '--os-shell')")
    fields.append(_field("Verdict", verdict))

  total = len(settings.PROOF_EXECUTORS)
  if proven == total:
    header = "commix proved exploitation of the following injection point(s)"
  elif proven:
    header = "commix proved exploitation of " + str(proven) + " of " + str(total) + " reported injection point(s)"
  else:
    header = "commix could NOT prove exploitation of the reported injection point(s)"

  data = "\n".join(_ for _ in fields if _ != "" or True)
  settings.print_data_to_stdout(settings.END_LINE.LF + header + ":" + settings.END_LINE.LF +
                                "---" + settings.END_LINE.LF + data + settings.END_LINE.LF +
                                "---" + settings.END_LINE.LF)
  try:
    path = os.path.join(os.path.dirname(filename) or ".", "proof.txt")
    with open(path, "w") as proof_file:
      proof_file.write(header + ":" + settings.END_LINE.LF + "---" + settings.END_LINE.LF +
                       data + settings.END_LINE.LF + "---" + settings.END_LINE.LF)
    info_msg = "Proof of exploitation written to '" + path + "'."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  except OSError as err_msg:
    from src.utils import logs
    logs.write_failure(path, err_msg)

# eof
