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

import gzip
import unittest

from src.utils import har
from src.utils import settings
from src.core.parse import cmdline as menu
from src.thirdparty.six.moves import urllib as _urllib

PAGE = "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n" + ("<p>the page</p>\n" * 40) + "</head>\n"

class ABodyIsKeptTheWayItWasReadBack(unittest.TestCase):
  """
  What a file like this is opened for is the answer the target gave. The bytes it arrived
  compressed in are not that answer, and stored in its place they leave every entry of a gzipped
  response reading as binary under a "text/html" of its own.
  """
  def setUp(self):
    self._state = (menu.options.har, menu.options.http10, list(har.ENTRIES))
    menu.options.har = "/dev/null"
    menu.options.http10 = False
    del har.ENTRIES[:]

  def tearDown(self):
    (menu.options.har, menu.options.http10) = self._state[:2]
    har.ENTRIES[:] = self._state[2]

  def _entry(self, body, raw_body):
    request = _urllib.request.Request("http://t/a.php?addr=1", method="GET")
    har.collect(request, 200, "OK", {"Content-Type": "text/html", "Content-Encoding": "gzip"},
                body, 1000.0, 1001.0, raw_body=raw_body)
    return har.ENTRIES[-1]

  def test_the_page_is_stored_as_text_rather_than_as_what_arrived(self):
    raw = gzip.compress(PAGE.encode())
    content = self._entry(PAGE, raw)["response"]["content"]
    self.assertEqual(PAGE, content["text"])
    self.assertNotIn("encoding", content)

  def test_the_two_lengths_are_each_their_own(self):
    raw = gzip.compress(PAGE.encode())
    response = self._entry(PAGE, raw)["response"]
    self.assertEqual(len(PAGE), response["content"]["size"])
    self.assertEqual(len(raw), response["bodySize"])

  def test_what_the_compression_saved_is_said(self):
    raw = gzip.compress(PAGE.encode())
    response = self._entry(PAGE, raw)["response"]
    self.assertEqual(len(PAGE) - len(raw), response["content"]["compression"])

  def test_nothing_is_said_where_nothing_was_saved(self):
    self.assertNotIn("compression", self._entry(PAGE, PAGE.encode())["response"]["content"])

  def test_a_body_that_is_not_text_is_still_kept_whole(self):
    binary = b"\x89PNG\r\n\x1a\n\xff\xfe\x00"
    content = self._entry(binary, binary)["response"]["content"]
    self.assertEqual("base64", content["encoding"])

class ATimeIsKeptWithTheOffsetItWasTakenAt(unittest.TestCase):
  """
  A bare local timestamp is read as whichever zone whatever opens the file happens to assume, which
  moves every entry in it by the difference.
  """
  def setUp(self):
    self._state = (menu.options.har, menu.options.http10, list(har.ENTRIES))
    menu.options.har = "/dev/null"
    menu.options.http10 = False
    del har.ENTRIES[:]

  def tearDown(self):
    (menu.options.har, menu.options.http10) = self._state[:2]
    har.ENTRIES[:] = self._state[2]

  def test_the_timestamp_names_a_zone(self):
    request = _urllib.request.Request("http://t/a.php?addr=1", method="GET")
    har.collect(request, 200, "OK", {"Content-Type": "text/html"}, "x", 1000.0, 1001.0)
    started = har.ENTRIES[-1]["startedDateTime"]
    self.assertTrue(started[10:].endswith("Z") or "+" in started[10:] or "-" in started[10:], started)

if __name__ == '__main__':
  unittest.main()

# eof
