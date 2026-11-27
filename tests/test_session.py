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
import json
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

class TheSessionKeepsOneRowPerThingItKnows(SessionFixture):
  """
  The value under test is stood in for by a placeholder made fresh every run, so the address a
  point is filed under differs from one run to the next for the very same point. Grouped on the
  whole of that address, the sweep that is meant to leave one row per point left every one of them,
  and the file grew by a row for every run that found the same point again.
  """
  def _rows(self, suffix):
    table = session_handler.table_name(self.URL) + suffix
    with sqlite3.connect(settings.SESSION_FILE) as conn:
      return conn.execute("SELECT COUNT(*) FROM \"" + table + "\";").fetchone()[0]

  def _point(self, placeholder, payload, method="GET"):
    table = session_handler.table_name(self.URL) + "_ip"
    with sqlite3.connect(settings.SESSION_FILE) as conn:
      conn.execute("CREATE TABLE IF NOT EXISTS \"" + table + "\" (id INTEGER PRIMARY KEY, url VARCHAR, "
                   "technique VARCHAR, vuln_parameter VARCHAR, http_header VARCHAR, payload VARCHAR, http_request_method VARCHAR);")
      conn.execute("INSERT INTO \"" + table + "\" (url, technique, vuln_parameter, http_header, payload, http_request_method) "
                   "VALUES (?, ?, ?, ?, ?, ?);",
                   ("http://t/a.php?addr=" + placeholder + "INJECT_HERE",
                    "results-based command injection technique", "addr", "", payload, method))
      conn.commit()

  def test_the_same_point_found_again_does_not_add_a_row(self):
    for placeholder in ("YJY", "AHF", "EOH"):
      self._point(placeholder, "payload-" + placeholder)
    session_handler.clear(self.URL)
    self.assertEqual(1, self._rows("_ip"))

  def test_a_point_found_by_another_method_is_a_point_of_its_own(self):
    # The same address answers to GET and to POST, and a resume looks one up by the method it is made with.
    self._point("YJY", "payload-get", "GET")
    self._point("AHF", "payload-post", "POST")
    session_handler.clear(self.URL)
    self.assertEqual(2, self._rows("_ip"))

  def test_the_row_kept_is_the_one_a_resumed_run_would_have_used(self):
    # Read back in order with the last of them kept, so the newest is the one that was in use - and
    # the only one whose stored payload was built with the options this session was given.
    for placeholder in ("YJY", "AHF", "EOH"):
      self._point(placeholder, "payload-" + placeholder)
    session_handler.clear(self.URL)
    table = session_handler.table_name(self.URL) + "_ip"
    with sqlite3.connect(settings.SESSION_FILE) as conn:
      self.assertEqual("payload-EOH", conn.execute("SELECT payload FROM \"" + table + "\";").fetchone()[0])

  def test_a_point_at_another_address_is_a_point_of_its_own(self):
    self._point("YJY", "payload-one")
    table = session_handler.table_name(self.URL) + "_ip"
    with sqlite3.connect(settings.SESSION_FILE) as conn:
      conn.execute("INSERT INTO \"" + table + "\" (url, technique, vuln_parameter, http_header, payload) "
                   "VALUES (?, ?, ?, ?, ?);", ("http://t/b.php?addr=AHFINJECT_HERE",
                   "results-based command injection technique", "addr", "", "payload-two"))
      conn.commit()
    session_handler.clear(self.URL)
    self.assertEqual(2, self._rows("_ip"))

  def test_a_command_asked_again_replaces_its_answer_rather_than_joining_it(self):
    session_handler.store_cmd(self.URL, "id", "uid=33(www-data)", "addr")
    session_handler.store_cmd(self.URL, "id", "uid=33(www-data)", "addr")
    session_handler.store_cmd(self.URL, "id", "uid=0(root)", "addr")
    self.assertEqual(1, self._rows("_ir"))
    self.assertEqual("uid=0(root)", session_handler.export_stored_cmd(self.URL, "id", "addr"))

  def test_another_command_is_an_answer_of_its_own(self):
    session_handler.store_cmd(self.URL, "id", "uid=33(www-data)", "addr")
    session_handler.store_cmd(self.URL, "whoami", "www-data", "addr")
    self.assertEqual(2, self._rows("_ir"))
    self.assertEqual("www-data", session_handler.export_stored_cmd(self.URL, "whoami", "addr"))

class OnlyCredentialsThatAreAPairAreKept(SessionFixture):
  """
  What the store holds is a username and a password. A bearer token is neither half of one - it is
  a single value, with no colon in it to split on.
  """
  def setUp(self):
    SessionFixture.setUp(self)
    self._auth = (menu.options.auth_cred, menu.options.auth_type, settings.LOAD_SESSION)
    settings.LOAD_SESSION = False

  def tearDown(self):
    (menu.options.auth_cred, menu.options.auth_type, settings.LOAD_SESSION) = self._auth
    SessionFixture.tearDown(self)

  def _stored(self):
    return session_handler.export_valid_credentials(self.URL, menu.options.auth_type)

  def test_a_bearer_token_is_left_alone(self):
    menu.options.auth_type, menu.options.auth_cred = "Bearer", "eyJhbGciOiJIUzI1NiJ9.e30.abc"
    self.assertFalse(session_handler.store_given_credentials(self.URL))
    self.assertIsNone(self._stored())

  def test_a_username_and_password_are_kept_as_the_pair_they_are(self):
    menu.options.auth_type, menu.options.auth_cred = "Basic", "admin:s3cr3t"
    self.assertTrue(session_handler.store_given_credentials(self.URL))
    self.assertEqual("admin:s3cr3t", self._stored())

  def test_a_password_carrying_a_colon_keeps_the_rest_of_it(self):
    menu.options.auth_type, menu.options.auth_cred = "Digest", "admin:a:b"
    self.assertTrue(session_handler.store_given_credentials(self.URL))
    self.assertEqual("admin:a:b", self._stored())

  def test_nothing_is_kept_from_a_session_that_is_being_read_back(self):
    menu.options.auth_type, menu.options.auth_cred = "Basic", "admin:s3cr3t"
    settings.LOAD_SESSION = True
    self.assertFalse(session_handler.store_given_credentials(self.URL))
    self.assertIsNone(self._stored())

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

class AResumeNarrowsOnlyToTheTechniquesTheOptionTakes(SessionFixture):
  """
  A stored finding narrows the techniques a later run tests. One that code injection or the
  out-of-band channel made carries a letter '--technique' does not take, and narrowing to it left
  nothing to test at all - every other technique reported as not selected.
  """
  def store(self, technique):
    session_handler.import_injection_points(
      self.URL, technique, settings.INJECTION_TYPE.RESULTS_BASED_CI,
      "", ";", True, "addr", "", "", "TAG", False, "127.0.0.1;echo TAG;", "GET", 0, 0, 0, 0, "1")

  def test_a_finding_of_the_option_s_own_letters_narrows_the_run(self):
    self.store(settings.INJECTION_TECHNIQUE.RESULTS_BASED)
    self.assertEqual("r", session_handler.applied_techniques(self.URL, "GET"))

  def test_a_code_injection_finding_alone_leaves_every_technique_selected(self):
    self.store(settings.INJECTION_TECHNIQUE.DYNAMIC_CODE)
    self.assertEqual("", session_handler.applied_techniques(self.URL, "GET"))

  def test_an_out_of_band_finding_alone_leaves_every_technique_selected(self):
    self.store(settings.INJECTION_TECHNIQUE.OOB)
    self.assertEqual("", session_handler.applied_techniques(self.URL, "GET"))

  def test_a_code_injection_finding_beside_others_keeps_the_results_based_letter_selected(self):
    self.store(settings.INJECTION_TECHNIQUE.DYNAMIC_CODE)
    self.store(settings.INJECTION_TECHNIQUE.TIME_BASED)
    self.store(settings.INJECTION_TECHNIQUE.FILE_BASED)
    self.assertEqual("frt", "".join(sorted(session_handler.applied_techniques(self.URL, "GET"))))

  def test_the_results_based_letter_is_not_named_twice(self):
    self.store(settings.INJECTION_TECHNIQUE.DYNAMIC_CODE)
    self.store(settings.INJECTION_TECHNIQUE.RESULTS_BASED)
    self.store(settings.INJECTION_TECHNIQUE.FILE_BASED)
    letters = session_handler.applied_techniques(self.URL, "GET")
    self.assertEqual(len(letters), len(set(letters)))
    self.assertEqual("fr", "".join(sorted(letters)))

  def test_the_letters_the_option_takes_survive_beside_one_it_does_not(self):
    self.store(settings.INJECTION_TECHNIQUE.OOB)
    self.store(settings.INJECTION_TECHNIQUE.TIME_BASED)
    self.assertEqual("t", session_handler.applied_techniques(self.URL, "GET"))

class AReplayIsMadeOnTheAddressGivenNow(SessionFixture):
  """
  What the finding was made with is the marked parameter alone: the rest of the query is this run's own.
  """
  def test_a_value_written_into_the_query_last_time_is_not_replayed(self):
    tag = settings.INJECT_TAG
    merged = session_handler.current_with_stored_point("http://t/a.php?junk=OLD&addr=ABC" + tag, "http://t/a.php?junk=NEW&addr=127.0.0.1" + tag)
    self.assertEqual("http://t/a.php?junk=NEW&addr=ABC" + tag, merged)

  def test_the_address_a_resumed_run_starts_from_is_the_one_given_now(self):
    # check_stored_injection_points is where the stored address replaced the current one before
    # anything else got to read it.
    tag = settings.INJECT_TAG
    stored = "http://t/a.php?junk=OLD&addr=127.0.0.1" + tag
    session_handler.import_injection_points(
      stored, settings.INJECTION_TECHNIQUE.RESULTS_BASED, settings.INJECTION_TYPE.RESULTS_BASED_CI,
      "", ";", True, "addr", "", "", "TAG", False, "127.0.0.1;echo TAG;", "GET", 0, 0, 0, 0, "1")
    state = (settings.LOAD_SESSION, settings.TESTABLE_PARAMETERS_LIST, settings.MULTI_TARGETS)
    try:
      settings.TESTABLE_PARAMETERS_LIST = []
      url, parameter = session_handler.check_stored_injection_points("http://t/a.php?junk=NEW&addr=127.0.0.1" + tag, "addr", "GET")
    finally:
      settings.LOAD_SESSION, settings.TESTABLE_PARAMETERS_LIST, settings.MULTI_TARGETS = state
    self.assertEqual("addr", parameter)
    self.assertIn("junk=NEW", url)
    self.assertNotIn("junk=OLD", url)

  def test_the_stored_address_stands_where_the_current_one_has_no_such_parameter(self):
    stored = "http://t/a.php?addr=ABC" + settings.INJECT_TAG
    self.assertEqual(stored, session_handler.current_with_stored_point(stored, "http://t/a.php?x=1"))
    self.assertEqual(stored, session_handler.current_with_stored_point(stored, None))

  def test_a_finding_made_in_the_body_replays_on_the_address_given_now(self):
    # No marked parameter in the stored address - what its query held last time is simply stale.
    self.assertEqual("http://t/a.php?token=NEW",
                     session_handler.current_with_stored_point("http://t/a.php?token=OLD", "http://t/a.php?token=NEW"))

  def test_a_mark_the_stored_address_did_not_have_is_not_moved_into_it(self):
    tag = settings.INJECT_TAG
    stored = "http://t/a.php?token=OLD"
    self.assertEqual(stored, session_handler.current_with_stored_point(stored, "http://t/a.php?addr=1" + tag))

  def test_a_fragment_stays_where_it_was(self):
    tag = settings.INJECT_TAG
    self.assertEqual("http://t/a.php?junk=NEW&addr=1" + tag + "#f",
                     session_handler.current_with_stored_point("http://t/a.php?addr=1" + tag + "&junk=OLD", "http://t/a.php?junk=NEW&addr=2#f"))

class TheSessionKeysByTheSiteNotByHowItWasWritten(SessionFixture):
  def test_case_credentials_default_port_and_query_do_not_make_another_site(self):
    one = session_handler.table_name("http://h.example?a=1")
    for url in ("http://H.EXAMPLE/x", "http://u:p@h.example:80/x", "h.example/p"):
      self.assertEqual(one, session_handler.table_name(url), url)
    self.assertNotEqual(one, session_handler.table_name("http://h.example:8080/x"))

  def test_stored_credentials_are_found_whatever_the_type_was_spelled_and_the_newest_wins(self):
    url = self.URL
    session_handler.import_valid_credentials(url, "Basic", url, "admin", "old")
    session_handler.import_valid_credentials(url, "basic", url, "admin", "new")
    self.assertEqual("admin:new", session_handler.export_valid_credentials(url, "basic"))

class TheSessionFileIsTheOwnersAlone(SessionFixture):
  def test_a_session_file_is_not_readable_by_others(self):
    import stat
    session_handler._SECURED_SESSION_FILES.discard(settings.SESSION_FILE)
    session_handler.store_cmd(self.URL, "id", "uid=33(www-data)", "addr")
    self.assertEqual(0o600, stat.S_IMODE(os.stat(settings.SESSION_FILE).st_mode))

class ADiscardedFindingIsNotResumed(SessionFixture):
  """
  A finding is written to the session the moment it is found, and the final re-ask can take it back
  afterwards - after which the next run resumed what this one had rejected.
  """
  def _store(self, technique, parameter="addr", method="GET"):
    session_handler.import_injection_points(
      self.URL, technique, settings.INJECTION_TYPE.RESULTS_BASED_CI,
      "", ";", True, parameter, "", "", "TAG", False, "127.0.0.1;echo TAG;", method, 0, 0, 0, 0, "1")

  def _techniques(self):
    table = session_handler.table_name(self.URL) + "_ip"
    with sqlite3.connect(settings.SESSION_FILE) as conn:
      return sorted(row[0] for row in conn.execute("SELECT technique FROM \"" + table + "\";"))

  def _point(self, technique, parameter="addr"):
    return (technique, "type", parameter, "payload", "GET", 1, "title")

  def test_only_the_discarded_row_goes(self):
    self._store(settings.INJECTION_TECHNIQUE.TIME_BASED)
    self._store(settings.INJECTION_TECHNIQUE.RESULTS_BASED)
    session_handler.discard_injection_points(self.URL, "GET", [self._point(settings.INJECTION_TECHNIQUE.TIME_BASED)])
    self.assertEqual([settings.INJECTION_TECHNIQUE.RESULTS_BASED], self._techniques())

  def test_another_parameter_and_another_method_are_left_alone(self):
    self._store(settings.INJECTION_TECHNIQUE.TIME_BASED, "addr")
    self._store(settings.INJECTION_TECHNIQUE.TIME_BASED, "other")
    self._store(settings.INJECTION_TECHNIQUE.TIME_BASED, "addr", "POST")
    session_handler.discard_injection_points(self.URL, "GET", [self._point(settings.INJECTION_TECHNIQUE.TIME_BASED, "addr")])
    self.assertEqual(2, len(self._techniques()))

  def test_the_stand_in_goes_with_the_last_finding_of_its_parameter(self):
    settings.TESTABLE_VALUE_OPTIMIZED, settings.TESTABLE_VALUE = True, "ABC"
    self._store(settings.INJECTION_TECHNIQUE.TIME_BASED)
    self.assertEqual("ABC", self.stored_placeholder())
    session_handler.discard_injection_points(self.URL, "GET", [self._point(settings.INJECTION_TECHNIQUE.TIME_BASED)])
    self.assertIsNone(self.stored_placeholder())

  def test_nothing_is_created_for_a_run_that_keeps_no_session(self):
    menu.options.ignore_session = True
    session_handler.discard_injection_points(self.URL, "GET", [self._point(settings.INJECTION_TECHNIQUE.TIME_BASED)])
    self.assertFalse(os.path.isfile(settings.SESSION_FILE))

class AStoredCookieThatIsPutBackIsSaid(SessionFixture):
  """
  The cookie and body a finding was made with are put back when the run is given none of its own -
  silently, so a cookie that had gone stale was a mystery and a login sat on the terminal unmarked.
  """
  LONG = "PHPSESSID=0123456789abcdefghijklmnopqrstuvwxyz0123456789"

  def setUp(self):
    SessionFixture.setUp(self)
    self._saved = (menu.options.cookie, settings.USER_APPLIED_COOKIE)
    menu.options.cookie = self.LONG
    session_handler.import_injection_points(
      self.URL, settings.INJECTION_TECHNIQUE.RESULTS_BASED, settings.INJECTION_TYPE.RESULTS_BASED_CI,
      "", ";", True, "addr", "", "", "TAG", False, "127.0.0.1;echo TAG;", "GET", 0, 0, 0, 0, "1")
    menu.options.cookie = None
    self.row = list(session_handler.load_stored_techniques(self.URL, "addr", "GET").values())[0]

  def tearDown(self):
    menu.options.cookie, settings.USER_APPLIED_COOKIE = self._saved
    SessionFixture.tearDown(self)

  def test_a_cookie_the_run_was_not_given_is_said_and_masked(self):
    settings.USER_APPLIED_COOKIE = None
    session_handler.apply_stored_technique(self.row)
    self.assertEqual(self.LONG, menu.options.cookie)
    said = " ".join(self.said)
    self.assertIn("from stored session", said)
    self.assertNotIn(self.LONG, said)
    self.assertIn("...", said)

  def test_a_cookie_the_run_was_given_is_not_announced_as_restored(self):
    settings.USER_APPLIED_COOKIE = self.LONG
    menu.options.cookie = self.LONG
    session_handler.apply_stored_technique(self.row)
    self.assertNotIn("from stored session", " ".join(self.said))

  def test_it_is_said_once_however_many_techniques_read_the_row(self):
    settings.USER_APPLIED_COOKIE = None
    session_handler.apply_stored_technique(self.row)
    session_handler.apply_stored_technique(self.row)
    self.assertEqual(1, len([_ for _ in self.said if "from stored session" in _]))

class AFindingIsReplayedWithTheValueAsItWasMade(SessionFixture):
  """
  A finding made with the value replaced was replayed with it kept, so the stored boundary no longer answered and the run started over.
  The session says which of the two it was, and a session written before it said so is left as it was.
  """
  def setUp(self):
    SessionFixture.setUp(self)
    self._replace = settings.REPLACE_VALUE

  def tearDown(self):
    settings.REPLACE_VALUE = self._replace
    SessionFixture.tearDown(self)

  def _store(self, replaced, payload="127.0.0.1;echo TAG;"):
    settings.REPLACE_VALUE = replaced
    session_handler.import_injection_points(
      self.URL, settings.INJECTION_TECHNIQUE.RESULTS_BASED, settings.INJECTION_TYPE.RESULTS_BASED_CI,
      "", ";", True, "addr", "", "", "TAG", False, payload, "GET", 0, 0, 0, 0, "1")

  def _row(self):
    return list(session_handler.load_stored_techniques(self.URL, "addr", "GET").values())[0]

  def _stored_flags(self):
    with sqlite3.connect(settings.SESSION_FILE) as conn:
      table = session_handler.table_name(self.URL) + "_ip"
      return [_[0] for _ in conn.execute("SELECT value_replaced FROM \"" + table + "\" ORDER BY id;")]

  def test_a_finding_made_with_the_value_replaced_is_replayed_with_it_replaced(self):
    self._store(True)
    settings.REPLACE_VALUE = False
    session_handler.apply_stored_technique(self._row())
    self.assertTrue(settings.REPLACE_VALUE)

  def test_a_finding_made_behind_the_value_is_replayed_behind_it(self):
    self._store(False)
    # What an earlier parameter's replay left in force is not carried into this one.
    settings.REPLACE_VALUE = True
    session_handler.apply_stored_technique(self._row())
    self.assertFalse(settings.REPLACE_VALUE)

  def test_the_session_holds_one_for_replaced_and_empty_otherwise(self):
    self._store(True)
    self._store(False, payload="127.0.0.1|echo TAG;")
    self.assertEqual(["1", ""], self._stored_flags())

  def test_a_row_written_before_the_column_existed_leaves_the_setting_as_it_was(self):
    self._store(True)
    older = tuple(self._row())[:32]
    for before in (True, False):
      settings.REPLACE_VALUE = before
      session_handler.apply_stored_technique(older)
      self.assertEqual(before, settings.REPLACE_VALUE)

  def test_a_session_file_from_before_the_column_gets_it_when_written_to(self):
    self._store(True)
    table = session_handler.table_name(self.URL) + "_ip"
    with sqlite3.connect(settings.SESSION_FILE) as conn:
      columns = [_[1] for _ in conn.execute("PRAGMA table_info(\"" + table + "\");") if _[1] not in ("id", "value_replaced")]
      conn.execute("DROP TABLE \"" + table + "\";")
      conn.execute("CREATE TABLE \"" + table + "\" (id INTEGER PRIMARY KEY, " + ", ".join(_ + " VARCHAR" for _ in columns) + ");")
    self._store(True)
    self.assertEqual(["1"], self._stored_flags())

  def test_the_same_finding_with_a_different_flag_is_a_row_of_its_own(self):
    self._store(True)
    self._store(True)
    self._store(False)
    self.assertEqual(["1", ""], self._stored_flags())

class AFindingIsReplayedWithTheTamperStateItWasMadeWith(SessionFixture):
  """
  A replay read the tamper state off the stored payload: a plain space read as '%20', and two
  backticks switched the backticks script on over a payload built with '$('. The session records the
  state the finding was made with, and a replay puts it back as it was; what it put back is undone
  before the next parameter, and a session from before the record is read as it always was.
  """
  PAYLOAD = "127.0.0.1|echo `echo X` $(echo Y)|tr a b"
  SETTINGS = ("WHITESPACES", "AUTO_TAMPER", "TAMPER_SCRIPTS", "MULTI_ENCODED_PAYLOAD", "CMD_SUB_PREFIX", "CMD_SUB_SUFFIX",
              "PRINT_WITH_ECHO", "STORED_TAMPER_STATE", "REPLAYED_STATE_PRIOR", "TARGET_OS", "REPLACE_VALUE", "WEB_ROOT",
              "INJECTION_LEVEL", "IGNORE_USER_DEFINED_POST_DATA", "HTTP_HEADER", "LOAD_SESSION",
              "TECHNIQUES_BEFORE_NARROWING", "TEMPFILE_BASED_STATE", "VALUE_ENCODING", "TESTABLE_VALUE_STOOD_IN_FOR")
  OPTIONS = ("tamper", "cookie", "tmp_path", "batch", "tech")

  def setUp(self):
    import copy
    SessionFixture.setUp(self)
    self._kept = dict((_, copy.deepcopy(getattr(settings, _))) for _ in self.SETTINGS)
    self._kept_options = dict((_, getattr(menu.options, _)) for _ in self.OPTIONS)
    menu.options.batch, menu.options.tamper, menu.options.cookie = True, None, None
    self._clean()

  def tearDown(self):
    for name, value in self._kept.items():
      setattr(settings, name, value)
    for name, value in self._kept_options.items():
      setattr(menu.options, name, value)
    SessionFixture.tearDown(self)

  def _clean(self):
    # A flag another test left set would make a script read as already in use.
    for name in settings.TAMPER_SCRIPTS:
      settings.TAMPER_SCRIPTS[name] = False
    settings.WHITESPACES, settings.AUTO_TAMPER, settings.MULTI_ENCODED_PAYLOAD = [settings.SINGLE_WHITESPACE], [], []
    settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX = settings.NESTING_SUBSTITUTION
    settings.STORED_TAMPER_STATE, settings.REPLAYED_STATE_PRIOR = None, {}
    settings.TARGET_OS = settings.OS.UNIX

  def _store(self, whitespace=" ", auto=(), backticks=False, tamper=None, payload=None):
    menu.options.tamper = tamper
    settings.WHITESPACES, settings.AUTO_TAMPER = [whitespace], list(auto)
    if backticks:
      settings.CMD_SUB_PREFIX = settings.CMD_SUB_SUFFIX = settings.BACKTICK_SUBSTITUTION
    session_handler.import_injection_points(
      self.URL, settings.INJECTION_TECHNIQUE.RESULTS_BASED, settings.INJECTION_TYPE.RESULTS_BASED_CI,
      "", ";", True, "addr", "", "", "TAG", False, payload or self.PAYLOAD, "GET", 0, 0, 0, 0, "1")
    self._clean()
    menu.options.tamper = None

  def _replay(self, row=None):
    row = row or list(session_handler.load_stored_techniques(self.URL, "addr", "GET").values())[0]
    settings.LOAD_SESSION = True
    session_handler.apply_stored_technique(row)
    checks.check_for_stored_tamper(row[10])

  def _scripts(self):
    own = [_ for _ in (menu.options.tamper or "").split(",") if _]
    return sorted(set(own) | set(settings.AUTO_TAMPER))

  def test_a_plain_space_and_dollar_paren_are_replayed_as_they_were(self):
    self._store()
    self._replay()
    self.assertEqual((settings.SINGLE_WHITESPACE, [], "$("), (settings.WHITESPACES[0], self._scripts(), settings.CMD_SUB_PREFIX))

  def test_backticks_left_in_force_without_the_script_are_replayed_without_it(self):
    self._store(backticks=True)
    self._replay()
    self.assertEqual((settings.SINGLE_WHITESPACE, [], "`"), (settings.WHITESPACES[0], self._scripts(), settings.CMD_SUB_PREFIX))

  def test_a_script_commix_reached_for_is_replayed_with_its_whitespace(self):
    self._store(whitespace="${IFS}", auto=("space2ifs",), payload=self.PAYLOAD.replace(" ", "${IFS}"))
    self._replay()
    self.assertEqual(("${IFS}", ["space2ifs"], "$("), (settings.WHITESPACES[0], self._scripts(), settings.CMD_SUB_PREFIX))

  def test_a_whitespace_left_over_before_the_replay_does_not_stand(self):
    self._store()
    settings.WHITESPACES = ["\t"]
    self._replay()
    self.assertEqual(settings.SINGLE_WHITESPACE, settings.WHITESPACES[0])

  def test_a_multiplied_whitespace_is_replayed_exactly(self):
    self._store(whitespace="\t" * 9, auto=("space2htab", "multiplespaces"), payload=self.PAYLOAD.replace(" ", "\t" * 9))
    self._replay()
    self.assertEqual("\t" * 9, settings.WHITESPACES[0])

  def test_the_users_own_script_is_replayed_with_the_space_it_was_found_with(self):
    self._store(tamper="backticks", backticks=True)
    self._replay()
    self.assertEqual((settings.SINGLE_WHITESPACE, ["backticks"], "`"), (settings.WHITESPACES[0], self._scripts(), settings.CMD_SUB_PREFIX))

  def test_a_row_from_before_the_record_is_read_off_the_payload_as_before(self):
    self._store()
    self._replay(tuple(list(session_handler.load_stored_techniques(self.URL, "addr", "GET").values())[0])[:33])
    self.assertEqual(("%20", "`"), (settings.WHITESPACES[0], settings.CMD_SUB_PREFIX))
    self.assertIn("backticks", settings.AUTO_TAMPER)

  def test_a_session_file_from_before_the_record_gets_it_when_written_to(self):
    self._store()
    table = session_handler.table_name(self.URL) + "_ip"
    with sqlite3.connect(settings.SESSION_FILE) as conn:
      columns = [_[1] for _ in conn.execute("PRAGMA table_info(\"" + table + "\");") if _[1] not in ("id", "tamper_state")]
      conn.execute("DROP TABLE \"" + table + "\";")
      conn.execute("CREATE TABLE \"" + table + "\" (id INTEGER PRIMARY KEY, " + ", ".join(_ + " VARCHAR" for _ in columns) + ");")
    self._store(backticks=True)
    self._replay()
    self.assertEqual("`", settings.CMD_SUB_PREFIX)

  def test_the_same_finding_made_another_way_is_a_row_of_its_own(self):
    self._store()
    self._store()
    self._store(backticks=True)
    with sqlite3.connect(settings.SESSION_FILE) as conn:
      table = session_handler.table_name(self.URL) + "_ip"
      self.assertEqual(2, conn.execute("SELECT COUNT(*) FROM \"" + table + "\";").fetchone()[0])

  def test_the_next_parameter_starts_from_what_the_run_had(self):
    self._store(whitespace="${IFS}", auto=("space2ifs",), tamper="nested", payload=self.PAYLOAD.replace(" ", "${IFS}"))
    with sqlite3.connect(settings.SESSION_FILE) as conn:
      table = session_handler.table_name(self.URL) + "_ip"
      conn.execute("UPDATE \"" + table + "\" SET cookie = 'sess=abc', target_os = 'windows', tmp_path = '/tmp/x';")
    self._replay()
    from src.core.controller import controller
    controller.reset_parameter_state()
    self.assertEqual((settings.SINGLE_WHITESPACE, [], "$(", None, None, settings.OS.UNIX, None),
                     (settings.WHITESPACES[0], settings.AUTO_TAMPER, settings.CMD_SUB_PREFIX, menu.options.tamper,
                      menu.options.cookie, settings.TARGET_OS, settings.STORED_TAMPER_STATE))
    self.assertNotEqual("/tmp/x", menu.options.tmp_path)

  def test_what_the_run_learned_on_its_own_is_kept(self):
    self._store()
    with sqlite3.connect(settings.SESSION_FILE) as conn:
      conn.execute("UPDATE \"" + session_handler.table_name(self.URL) + "_ip\" SET target_os = 'None';")
    self._replay()
    settings.TARGET_OS = settings.OS.WINDOWS
    checks.put_back_replayed_state()
    self.assertEqual(settings.OS.WINDOWS, settings.TARGET_OS)

  def test_the_record_written_with_a_finding_leaves_the_runs_own_snapshot_alone(self):
    # The snapshot a technique takes and puts back around a replay is another thing than this record.
    checks.restore_tamper_state(checks.tamper_state())
    self.assertTrue(json.loads(checks.finding_tamper_state()))

  def test_a_finding_made_without_post_data_stores_none_and_announces_none(self):
    menu.options.data = False
    self._store()
    with sqlite3.connect(settings.SESSION_FILE) as conn:
      table = session_handler.table_name(self.URL) + "_ip"
      self.assertEqual("", conn.execute("SELECT data FROM \"" + table + "\";").fetchone()[0])
    self._replay()
    self.assertFalse([_ for _ in self.said if "POST data" in str(_)])

  def test_an_older_sessions_stored_false_is_read_as_no_post_data(self):
    self._store()
    with sqlite3.connect(settings.SESSION_FILE) as conn:
      conn.execute("UPDATE \"" + session_handler.table_name(self.URL) + "_ip\" SET data = 'False';")
    self._replay()
    self.assertFalse([_ for _ in self.said if "POST data" in str(_)])
    self.assertIn(menu.options.data, (None, False))

if __name__ == "__main__":
  unittest.main()
