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

import threading
import unittest

from src.utils import settings
from src.core.requests import stability

class ASideRequestIsTheThreadsOwn(unittest.TestCase):
  """
  Each of them is asked for by a run-wide option, but the request it makes is made by one worker.
  Whatever another worker has in flight at that moment is a request of its own, and counting it is
  what the retry check it is read against depends on.
  """
  def setUp(self):
    for kind in settings.SIDE_REQUEST_KINDS:
      settings.set_side_request(kind, False)

  def tearDown(self):
    for kind in settings.SIDE_REQUEST_KINDS:
      settings.set_side_request(kind, False)

  def _counted_on_a_worker(self):
    counted = {}
    def worker():
      before = stability.requests_sent()
      stability.note_request_sent()
      counted["by"] = stability.requests_sent() - before
    thread = threading.Thread(target=worker)
    thread.start()
    thread.join()
    return counted["by"]

  def test_a_thread_in_one_does_not_count_its_own_request(self):
    before = stability.requests_sent()
    settings.set_side_request("safe_request", True)
    stability.note_request_sent()
    self.assertEqual(0, stability.requests_sent() - before)

  def test_it_counts_again_once_that_one_is_done(self):
    before = stability.requests_sent()
    settings.set_side_request("safe_request", True)
    settings.set_side_request("safe_request", False)
    stability.note_request_sent()
    self.assertEqual(1, stability.requests_sent() - before)

  def test_one_thread_being_in_one_says_nothing_about_another(self):
    for kind in settings.SIDE_REQUEST_KINDS:
      settings.set_side_request(kind, True)
      self.assertEqual(1, self._counted_on_a_worker(), kind)
      settings.set_side_request(kind, False)

  def test_a_kind_is_asked_about_by_name_as_well_as_in_general(self):
    settings.set_side_request("csrf_token", True)
    self.assertTrue(settings.in_side_request("csrf_token"))
    self.assertFalse(settings.in_side_request("safe_request"))
    self.assertTrue(settings.in_side_request())

if __name__ == '__main__':
  unittest.main()

# eof
