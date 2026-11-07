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
import base64
import shutil
import socket
import tempfile
import unittest

from tests._testutils import stage
from src.utils import settings
from src.core.parse import cmdline as menu
from src.core.parse import request

CREDENTIALS = "user:pw"
ENCODED = base64.b64encode(CREDENTIALS.encode()).decode()

"""
Fail closed: a captured request is read before anything is sent, so a test of that reading which
reaches for the network is a broken test rather than a slow one.
"""
def _no_transport(*args, **kwargs):
  raise RuntimeError("Reading a captured request is exercised offline; no transport may be opened.")

class _Captured(unittest.TestCase):
  def setUp(self):
    self.saved_sockets = (socket.socket, socket.create_connection, socket.getaddrinfo)
    socket.socket, socket.create_connection, socket.getaddrinfo = (_no_transport,) * 3
    self.saved_options = dict(vars(menu.options))
    self.saved_command_line = dict(request._command_line_options)
    menu.options.scope = None
    request._command_line_options.clear()
    self.directory = tempfile.mkdtemp(prefix="commix-auth-")

  def tearDown(self):
    socket.socket, socket.create_connection, socket.getaddrinfo = self.saved_sockets
    vars(menu.options).clear()
    vars(menu.options).update(self.saved_options)
    request._command_line_options.clear()
    request._command_line_options.update(self.saved_command_line)
    shutil.rmtree(self.directory, ignore_errors=True)

  def parse(self, *headers):
    path = os.path.join(self.directory, "captured.invalid.txt")
    raw = "GET /review?x=1 HTTP/1.1\n" + "".join(line + "\n" for line in headers) + "\n"
    with open(path, "w", encoding=settings.DEFAULT_CODEC) as handle:
      handle.write(raw)
    return request.parse_requests(path)[0]

class AuthorizationField(_Captured):
  """
  The 'Authorization' field of a captured request, read the way every other known field is.

  Matched anywhere in the line rather than at its start, as it was, the name was found inside
  'X-Authorization' too - so another header's credentials were adopted as the ones to authenticate
  with, and that header never reached the request, since what is read here is not kept as an extra.
  """
  def test_the_credentials_are_read_however_the_colon_is_spaced(self):
    for line in ("Authorization: Basic " + ENCODED,
                 "Authorization:Basic " + ENCODED,
                 "Authorization:\tBasic " + ENCODED,
                 "authorization:  Basic " + ENCODED):
      with self.subTest(line=line):
        target = self.parse("Host: asset.invalid", line)
        self.assertEqual("basic", target["auth_type"])
        self.assertEqual(CREDENTIALS, target["auth_cred"])

  def test_a_field_that_merely_ends_in_the_name_is_not_the_field(self):
    for name in ("X-Authorization", "Proxy-Authorization", "My-Authorization"):
      with self.subTest(name=name):
        target = self.parse("Host: asset.invalid", name + ": Basic " + ENCODED)
        self.assertIsNone(target["auth_type"], name + " was taken for the authorization field")
        self.assertIsNone(target["auth_cred"])

  def test_such_a_field_still_reaches_the_request_as_an_extra_header(self):
    target = self.parse("Host: asset.invalid", "X-Authorization: Basic " + ENCODED, "X-Trace: keepme")
    self.assertIn("X-Authorization", target["headers"] or "")
    self.assertIn("X-Trace", target["headers"] or "")

  def test_the_field_itself_is_consumed_rather_than_sent_again(self):
    target = self.parse("Host: asset.invalid", "Authorization: Basic " + ENCODED, "X-Trace: keepme")
    self.assertNotIn("Authorization", target["headers"] or "")
    self.assertIn("X-Trace", target["headers"] or "")

if __name__ == "__main__":
  unittest.main()
