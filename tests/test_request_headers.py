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
import sys
import socket
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# The modules below read the command line as they are imported, so keep pytest's own
# arguments away from them and hand the real ones back even if an import fails.
_COMMAND_LINE = list(sys.argv)
try:
  sys.argv = ["commix.py"]
  from src.utils import settings
  from src.core.parse import cmdline as menu
  from src.core.parse import request
finally:
  sys.argv = _COMMAND_LINE

TARGET = "/review?x=1"
SETTINGS_STATE = ("RAW_HTTP_HEADERS", "HTTP_METHOD", "USER_DEFINED_POST_DATA",
                  "IGNORE_USER_DEFINED_POST_DATA", "MULTI_REQUEST_TARGETS", "SKIPPED_OUT_OF_SCOPE")
SOCKET_ATTEMPTS = []

"""
Fail closed: a parser test that reaches for the network is a broken test, not a slow one.
"""
def _no_transport(*args, **kwargs):
  SOCKET_ATTEMPTS.append(args[:1])
  raise RuntimeError("Request parsing is exercised offline; no transport may be opened.")

def _raw(*headers, **kwargs):
  target = kwargs.get("target", TARGET)
  return kwargs.get("method", "GET") + " " + target + " HTTP/1.1\n" + "".join(line + "\n" for line in headers) + "\n"

class _OfflineRequests(unittest.TestCase):
  """
  A captured request file, parsed through the public entry point, with the network and the
  command line state it touches put back the way they were found.
  """
  def setUp(self):
    self.saved_options = dict(vars(menu.options))
    self.saved_command_line = dict(request._command_line_options)
    self.saved_settings = {name: getattr(settings, name) for name in SETTINGS_STATE}
    self.saved_sockets = (socket.socket, socket.create_connection, socket.getaddrinfo)
    socket.socket, socket.create_connection, socket.getaddrinfo = _no_transport, _no_transport, _no_transport
    # Nothing another test, an earlier suite or a real run left behind may decide what is expected here.
    menu.options.scope = None
    settings.SKIPPED_OUT_OF_SCOPE = []
    request._command_line_options.clear()
    self.directory = tempfile.mkdtemp(prefix="commix-request-")
    self.path = os.path.join(self.directory, "captured.invalid.txt")

  def tearDown(self):
    socket.socket, socket.create_connection, socket.getaddrinfo = self.saved_sockets
    for name in SETTINGS_STATE:
      setattr(settings, name, self.saved_settings[name])
    vars(menu.options).clear()
    vars(menu.options).update(self.saved_options)
    request._command_line_options.clear()
    request._command_line_options.update(self.saved_command_line)
    shutil.rmtree(self.directory, ignore_errors=True)
    self.assertEqual([], SOCKET_ATTEMPTS, "a request parser test opened a transport")

  def write(self, text):
    with open(self.path, "w", encoding=settings.DEFAULT_CODEC) as handle:
      handle.write(text)
    return self.path

  def targets(self, text):
    try:
      return request.parse_requests(self.write(text))
    except SystemExit:
      self.fail("a valid captured request was rejected: " + repr(text))

  def rejected(self, text):
    with self.assertRaises(SystemExit):
      request.parse_requests(self.write(text))

class HeaderValue(_OfflineRequests):
  """
  The optional whitespace a field line may carry, read off the value of one known header.
  Guarded like the rest: a helper test that opens a transport is just as wrong as a parse one.
  """
  def test_a_plain_space_is_not_part_of_the_value(self):
    for line in ("Host: asset.invalid", "host: asset.invalid", "HOST: asset.invalid"):
      self.assertEqual("asset.invalid", request._extract_header_value(settings.HOST, line))

  def test_no_whitespace_after_the_colon_is_allowed(self):
    for line in ("Host:asset.invalid", "Host:\tasset.invalid", "User-Agent:probe-a/1.0"):
      expected = "asset.invalid" if "Host" in line else "probe-a/1.0"
      name = settings.HOST if "Host" in line else settings.USER_AGENT
      self.assertEqual(expected, request._extract_header_value(name, line))

  def test_the_boundary_whitespace_of_the_value_is_dropped(self):
    for line, expected in (("Host:  asset.invalid", "asset.invalid"),
                           ("Host: \t asset.invalid", "asset.invalid"),
                           ("Host:\tasset.invalid \t", "asset.invalid"),
                           ("Host: asset.invalid   ", "asset.invalid"),
                           ("Cookie: \ta=1; b=2\t", "a=1; b=2")):
      self.assertEqual(expected, request._extract_header_value(line.split(":")[0], line))

  def test_the_inside_of_the_value_is_left_alone(self):
    for line, expected in (("Cookie: a=1;  b=2", "a=1;  b=2"),
                           ("Referer: https://ref.invalid/p?q=a:b", "https://ref.invalid/p?q=a:b"),
                           ("User-Agent: probe  agent/1.0", "probe  agent/1.0")):
      self.assertEqual(expected, request._extract_header_value(line.split(":")[0], line))

  def test_a_different_header_is_not_the_one_asked_for(self):
    for name, line in ((settings.HOST, "X-Host: other.invalid"),
                       (settings.HOST, "Hosted-By: other.invalid"),
                       (settings.HOST, "User-Agent: probe-a/1.0")):
      self.assertIsNone(request._extract_header_value(name, line))

class ParsedRequest(_OfflineRequests):
  """
  The same field line, read through the public parse of a captured request file.
  """
  def test_a_standard_request_is_parsed_as_before(self):
    targets = self.targets(_raw("Host: asset.invalid", "User-Agent: probe-a/1.0",
                                "Cookie: a=1; b=2", "Referer: http://ref.invalid/p?q=a:b"))
    self.assertEqual(1, len(targets))
    self.assertEqual("asset.invalid", targets[0]["host"])
    self.assertEqual("probe-a/1.0", targets[0]["agent"])
    self.assertEqual("a=1; b=2", targets[0]["cookie"])
    self.assertEqual("http://ref.invalid/p?q=a:b", targets[0]["referer"])
    self.assertEqual("http://asset.invalid" + TARGET, targets[0]["url"])

  def test_a_host_field_parses_whatever_whitespace_follows_its_colon(self):
    for line in ("Host: asset.invalid",
                 "Host:asset.invalid",
                 "Host:\tasset.invalid",
                 "Host:  asset.invalid",
                 "Host: \t asset.invalid",
                 "Host:\tasset.invalid \t",
                 "hOsT: asset.invalid"):
      with self.subTest(line=line):
        targets = self.targets(_raw(line))
        self.assertEqual(1, len(targets))
        self.assertEqual("asset.invalid", targets[0]["host"])
        self.assertEqual("http://asset.invalid" + TARGET, targets[0]["url"])

  def test_the_boundary_whitespace_of_a_known_field_does_not_survive(self):
    targets = self.targets(_raw("Host: asset.invalid", "User-Agent:\tprobe  agent/1.0 \t",
                                "Cookie:\ta=1; b=2  ", "Referer:  https://ref.invalid/p?q=a:b "))
    self.assertEqual("probe  agent/1.0", targets[0]["agent"])
    self.assertEqual("a=1; b=2", targets[0]["cookie"])
    self.assertEqual("https://ref.invalid/p?q=a:b", targets[0]["referer"])

  def test_a_host_field_without_a_value_is_rejected(self):
    for line in ("Host:", "Host: ", "Host:\t", "Host: \t "):
      with self.subTest(line=line):
        self.rejected(_raw(line, "User-Agent: probe-a/1.0"))

  def test_a_request_without_a_host_field_is_rejected(self):
    self.rejected(_raw("User-Agent: probe-a/1.0", "Cookie: a=1"))

  def test_a_field_that_only_ends_in_host_is_not_the_host(self):
    for line in ("X-Host: other.invalid", "X-Forwarded-Host: other.invalid", "Hosted-By: other.invalid"):
      with self.subTest(line=line):
        self.rejected(_raw(line, "User-Agent: probe-a/1.0"))

  def test_a_host_named_field_does_not_overrule_the_real_one(self):
    targets = self.targets(_raw("Host: asset.invalid", "X-Forwarded-Host: other.invalid",
                                "X-Host: other.invalid"))
    self.assertEqual("asset.invalid", targets[0]["host"])
    self.assertEqual("http://asset.invalid" + TARGET, targets[0]["url"])

class LogfileTarget(_OfflineRequests):
  """
  The same file, applied to the run's options the way '--requestfile' applies it.
  """
  def test_a_captured_request_becomes_the_run_target(self):
    self.write(_raw("Host:asset.invalid", "User-Agent:\tprobe-a/1.0", "Referer: https://ref.invalid/"))
    menu.options.requestfile = self.path
    menu.options.logfile = None
    targets = request.logfile_parser()
    self.assertEqual(1, len(targets))
    self.assertEqual("asset.invalid", menu.options.host)
    self.assertEqual("probe-a/1.0", menu.options.agent)
    self.assertEqual("https://ref.invalid/", menu.options.referer)
    self.assertEqual("https://asset.invalid" + TARGET, menu.options.url)
    self.assertTrue(settings.RAW_HTTP_HEADERS.startswith("Host:"))
    self.assertEqual(targets, settings.MULTI_REQUEST_TARGETS)

if __name__ == "__main__":
  unittest.main()
