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
import errno
import socket
from os import curdir, sep
from src.utils import menu
from src.utils import settings
from socket import error as socket_error
from src.thirdparty.colorama import Fore, Back, Style, init
from src.thirdparty.six.moves import _thread as thread
from src.thirdparty.six.moves import socketserver as _socketserver
from src.thirdparty.six.moves import BaseHTTPServer as _BaseHTTPServer

"""
Validates IPv4 addresses.
"""
def is_valid_ipv4(ip_addr):
    pattern = re.compile(r"""
        ^
        (?:
          # Dotted variants:
          (?:
            # Decimal 1-255 (no leading 0's)
            [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
          |
            0x0*[0-9a-f]{1,2}  # Hexadecimal 0x0 - 0xFF (possible leading 0's)
          |
            0+[1-3]?[0-7]{0,2} # Octal 0 - 0377 (possible leading 0's)
          )
          (?:                  # Repeat 0-3 times, separated by a dot
            \.
            (?:
              [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
            |
              0x0*[0-9a-f]{1,2}
            |
              0+[1-3]?[0-7]{0,2}
            )
          ){0,3}
        |
          0x0*[0-9a-f]{1,8}    # Hexadecimal notation, 0x0 - 0xffffffff
        |
          0+[0-3]?[0-7]{0,10}  # Octal notation, 0 - 037777777777
        |
          # Decimal notation, 1-4294967295:
          429496729[0-5]|42949672[0-8]\d|4294967[01]\d\d|429496[0-6]\d{3}|
          42949[0-5]\d{4}|4294[0-8]\d{5}|429[0-3]\d{6}|42[0-8]\d{7}|
          4[01]\d{8}|[1-3]\d{0,9}|[4-9]\d{0,8}
        )
        $
    """, re.VERBOSE | re.IGNORECASE)
    return pattern.match(ip_addr) is not None

def grab_ip_addr():
  try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8",53))
    s.settimeout(2)
    ip_addr = s.getsockname()[0]
    s.close()
    return ip_addr
  except socket_error as err_msg:
    if errno.ECONNREFUSED:
      warn_msg = "Internet seems unreachable."
      print(settings.print_warning_msg(warn_msg))
    else:
      print(settings.print_critical_msg(str(err_msg)) + "\n")
      raise SystemExit()

class Handler(_BaseHTTPServer.BaseHTTPRequestHandler):
    def do_GET(self):
      try:
        #Open the static file requested and send it
        f = open(self.path) 
        self.send_response(200)
        self.end_headers()
        self.wfile.write(f.read())
        f.close()

      except IOError:
        self.wfile.write(settings.APPLICATION + " " + settings.VERSION + " (https://commixproject.com)")
      
    def log_message(self, format, *args):
      return

class ReusableTCPServer(_socketserver.TCPServer):
    allow_reuse_address = True

def main():
  try:
    connection_refused = False
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  except socket_error:
    if errno.ECONNREFUSED:
      connection_refused = True
  if connection_refused == False:
    # Start the server in a background thread.
    httpd = ReusableTCPServer(('', settings.LOCAL_HTTP_PORT), Handler)
    thread.start_new_thread(httpd.serve_forever, ())
