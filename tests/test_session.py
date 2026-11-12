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
import shutil
import sqlite3
import tempfile
import unittest

from tests import _testutils
from src.core.parse import cmdline as menu
from src.utils import settings
from src.utils import session_handler
from src.core.controller import checks

class SessionFixture(unittest.TestCase):
  """
  A session file of its own per test, and the globals a stored finding is read back against.
  """
  URL = "http://t/a.php?addr=127.0.0.1"

  def setUp(self):
    self._dir = tempfile.mkdtemp(prefix="commix-session-")
    self._state = (settings.SESSION_FILE, settings.TESTABLE_VALUE, settings.TESTABLE_VALUE_OPTIMIZED,
                   menu.options.data, menu.options.prefix, menu.options.ignore_session,
                   menu.options.flush_session, settings.REPLAY_NOTICES_SAID)
    self._out = settings.print_data_to_stdout
    self.said = []
    settings.print_data_to_stdout = self.said.append
    settings.SESSION_FILE = os.path.join(self._dir, "session.db")
    settings.TESTABLE_VALUE = "127.0.0.1"
    settings.TESTABLE_VALUE_OPTIMIZED = False
    settings.REPLAY_NOTICES_SAID = set()
    menu.options.data = None
    menu.options.prefix = None
    menu.options.ignore_session = False
    menu.options.flush_session = False

  def tearDown(self):
    (settings.SESSION_FILE, settings.TESTABLE_VALUE, settings.TESTABLE_VALUE_OPTIMIZED,
     menu.options.data, menu.options.prefix, menu.options.ignore_session,
     menu.options.flush_session, settings.REPLAY_NOTICES_SAID) = self._state
    settings.print_data_to_stdout = self._out
    shutil.rmtree(self._dir, ignore_errors=True)

  def stored_placeholder(self):
    return session_handler.check_stored_testable_value(self.URL, "addr", "GET")

class AStandInIsRememberedOnlyWhereItHeld(SessionFixture):
  """
  The parameter's own value is dropped on what the heuristic answered, and a technique may still
  need it back. What the session records has to be what the stored finding was made with.
  """
  def store(self, optimized, value):
    settings.TESTABLE_VALUE_OPTIMIZED = optimized
    settings.TESTABLE_VALUE = value
    session_handler.import_injection_points(
      self.URL, settings.INJECTION_TECHNIQUE.RESULTS_BASED, settings.INJECTION_TYPE.RESULTS_BASED_CI,
      "", ";", True, "addr", value, "", "TAG", False, value + ";echo TAG;", "GET", 0, 0, 0, 0, "1")

  def test_a_stand_in_the_finding_was_made_with_is_recorded(self):
    self.store(optimized=True, value="ABC")
    self.assertEqual("ABC", self.stored_placeholder())

  def test_a_finding_made_with_the_value_records_none(self):
    self.store(optimized=False, value="127.0.0.1")
    self.assertIsNone(self.stored_placeholder())

  def test_one_refused_afterwards_is_forgotten_rather_than_left_behind(self):
    self.store(optimized=True, value="ABC")
    # What the restore-and-retry path leaves: the value put back, the point found with it.
    self.store(optimized=False, value="127.0.0.1")
    self.assertIsNone(self.stored_placeholder())

  def test_the_probe_alone_records_nothing(self):
    from src.core.controller import controller
    self.assertNotIn("import_testable_value_status",
                     controller.probe_skip_testable_value_early.__code__.co_names)

class AReplayUsesWhatTheFindingWasMadeWith(SessionFixture):
  """
  A stand-in is put back into the request being replayed, and nothing else is.
  """
  def tagged(self, value):
    return "http://t/a.php?addr=" + value + settings.INJECT_TAG

  def test_a_stored_stand_in_is_put_back_into_the_body(self):
    session_handler.import_testable_value_status(self.URL, "addr", "GET", "ABC")
    menu.options.data = "addr=127.0.0.1" + settings.INJECT_TAG
    session_handler.reapply_testable_value(self.URL, "addr", "GET")
    self.assertEqual("addr=ABC" + settings.INJECT_TAG, menu.options.data)
    self.assertEqual("ABC", settings.TESTABLE_VALUE)
    self.assertTrue(settings.TESTABLE_VALUE_OPTIMIZED)

  def test_an_address_already_carrying_it_is_left_as_it_is(self):
    session_handler.import_testable_value_status(self.URL, "addr", "GET", "ABC")
    url = session_handler.reapply_testable_value(self.tagged("ABC"), "addr", "GET")
    self.assertEqual(self.tagged("ABC"), url)
    self.assertEqual("ABC", settings.TESTABLE_VALUE)

  def test_a_finding_made_with_the_value_is_not_rewritten_by_an_older_row(self):
    # A session file written before the stand-in was recorded with the finding can hold one the run
    # went on to refuse. The address says which value the stored finding was made with.
    session_handler.import_testable_value_status(self.URL, "addr", "GET", "ABC")
    url, prefix = session_handler.reapply_testable_value(self.tagged("127.0.0.1"), "addr", "GET", "127.0.0.1")
    self.assertEqual(self.tagged("127.0.0.1"), url)
    self.assertEqual("127.0.0.1", prefix)
    self.assertFalse(settings.TESTABLE_VALUE_OPTIMIZED)

  def test_nothing_is_done_where_no_stand_in_was_recorded(self):
    url, prefix = session_handler.reapply_testable_value(self.tagged("127.0.0.1"), "addr", "GET", "ZZZ")
    self.assertEqual(self.tagged("127.0.0.1"), url)
    self.assertEqual("ZZZ", prefix)

class AReplayedFindingIsWrittenOutWithTheValueTheRunWasGiven(SessionFixture):
  """
  The address a replay carries is the stored finding's own, holding the stand-in rather than the
  value - so what this run was given is kept as the stand-in takes its place. Without it a resumed
  finding goes out carrying three letters where the run that first found it wrote the value.
  """
  def setUp(self):
    SessionFixture.setUp(self)
    self._stood_in_for = settings.TESTABLE_VALUE_STOOD_IN_FOR
    settings.TESTABLE_VALUE_STOOD_IN_FOR = ""

  def tearDown(self):
    settings.TESTABLE_VALUE_STOOD_IN_FOR = self._stood_in_for
    SessionFixture.tearDown(self)

  def test_the_value_is_kept_as_the_stand_in_takes_its_place(self):
    session_handler.import_testable_value_status(self.URL, "addr", "GET", "ABC")
    session_handler.reapply_testable_value("http://t/a.php?addr=ABC" + settings.INJECT_TAG, "addr", "GET")
    self.assertEqual("127.0.0.1", settings.TESTABLE_VALUE_STOOD_IN_FOR)
    self.assertEqual("127.0.0.1;echo TAG;", checks.payload_with_own_value("ABC;echo TAG;"))

  def test_nothing_is_kept_where_the_finding_was_made_with_the_value(self):
    session_handler.import_testable_value_status(self.URL, "addr", "GET", "ABC")
    session_handler.reapply_testable_value("http://t/a.php?addr=127.0.0.1" + settings.INJECT_TAG, "addr", "GET", "127.0.0.1")
    self.assertEqual("", settings.TESTABLE_VALUE_STOOD_IN_FOR)

class APrefixOfTheUsersOwnOutranksTheStandIn(SessionFixture):
  """
  '--prefix' names what goes in front of the payload. A stand-in for the parameter's value is not
  that, and replacing one with the other sends a payload nobody asked for.
  """
  def setUp(self):
    SessionFixture.setUp(self)
    session_handler.import_testable_value_status(self.URL, "addr", "GET", "ABC")
    self.url = "http://t/a.php?addr=ABC" + settings.INJECT_TAG

  def test_the_value_it_stands_in_for_is_the_only_prefix_rewritten(self):
    url, prefix = session_handler.reapply_testable_value(self.url, "addr", "GET", "127.0.0.1")
    self.assertEqual("ABC", prefix)

  def test_a_prefix_naming_something_else_is_kept(self):
    url, prefix = session_handler.reapply_testable_value(self.url, "addr", "GET", "ZZZ")
    self.assertEqual("ZZZ", prefix)

  def test_a_boundary_prefix_is_kept(self):
    url, prefix = session_handler.reapply_testable_value(self.url, "addr", "GET", "\")")
    self.assertEqual("\")", prefix)

  def test_a_prefix_given_now_against_a_stored_one_is_said_out_loud(self):
    menu.options.prefix = "YYY"
    session_handler.reapply_testable_value(self.url, "addr", "GET", "ZZZ")
    self.assertTrue(any("prefix" in str(_) and "YYY" in str(_) for _ in self.said))

  def test_the_same_prefix_as_the_stored_one_is_said_nothing_about(self):
    menu.options.prefix = "ZZZ"
    session_handler.reapply_testable_value(self.url, "addr", "GET", "ZZZ")
    self.assertEqual([], self.said)

if __name__ == "__main__":
  unittest.main()
