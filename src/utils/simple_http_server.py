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

import errno
import thread
import socket
import SocketServer
from os import curdir, sep
from src.utils import menu
from src.utils import settings
from socket import error as socket_error
from src.thirdparty.colorama import Fore, Back, Style, init
from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
      try:
        #Open the static file requested and send it
        f = open(curdir + sep + self.path) 
        self.send_response(200)
        self.end_headers()
        self.wfile.write(f.read())
        f.close()

      except IOError:
        self.wfile.write(settings.APPLICATION + "/v" + settings.VERSION)
      
    def log_message(self, format, *args):
      return

class ReusableTCPServer(SocketServer.TCPServer):
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
