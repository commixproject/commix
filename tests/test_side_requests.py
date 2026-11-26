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

class TheAnswerToADigestChallengeIsPartOfTheRequestItInterrupted(unittest.TestCase):
  """
  A target that asks for Digest credentials answers each request with a 401 first; the request is then
  sent again with the credentials. That one send completes the first and is counted with it - counted
  apart, the request reads as retried and every timing taken against such a target is dropped. A send
  after it, the answer going out again, is a retry like any other.
  """
  URL = "http://t/a.php?a=1"

  def setUp(self):
    from src.core.parse import cmdline as menu
    from src.core.requests import headers
    self.menu, self.headers = menu, headers
    self._options = (menu.options.auth_type, menu.options.auth_cred, menu.options.url)
    self._realm = settings.DIGEST_AUTH_REALM
    stability.expect_challenge_answer(False)

  def tearDown(self):
    self.menu.options.auth_type, self.menu.options.auth_cred, self.menu.options.url = self._options
    settings.DIGEST_AUTH_REALM = self._realm
    stability.expect_challenge_answer(False)

  def _answer(self, resend):
    import io
    from email.message import Message
    from src.thirdparty.six.moves import urllib as _urllib
    handler = self.headers.DigestAuthHandler()
    handler.add_password("r", self.URL, "tester", "secret")
    handler.parent = type("Opener", (object,), {"open": lambda opener, request, timeout=None: resend()})()
    challenge = Message()
    challenge["WWW-Authenticate"] = 'Digest realm="r", nonce="n", qop="auth"'
    request = _urllib.request.Request(self.URL)
    # Set by the opener on the way out, and read again when the request is sent with credentials.
    request.timeout = 5
    return handler.http_error_401(request, io.BytesIO(b""), 401, "Unauthorized", challenge)

  def _sends(self, count):
    def resend():
      for _ in range(count):
        stability.note_request_sent()
      return "answered"
    return resend

  def test_the_send_with_credentials_is_not_counted_as_a_retry(self):
    before = stability.requests_sent()
    stability.note_request_sent()
    self.assertEqual("answered", self._answer(self._sends(1)))
    self.assertEqual(1, stability.requests_sent() - before)
    self.assertFalse(stability.request_was_retried(before))

  def test_a_send_after_the_answer_is_counted_as_a_retry(self):
    before = stability.requests_sent()
    stability.note_request_sent()
    self._answer(self._sends(2))
    self.assertTrue(stability.request_was_retried(before))

  def test_the_next_request_is_counted_once_the_challenge_is_answered(self):
    self._answer(self._sends(0))
    before = stability.requests_sent()
    stability.note_request_sent()
    self.assertEqual(1, stability.requests_sent() - before)

  def test_the_next_request_is_counted_when_the_answer_fails(self):
    def fail():
      raise IOError("connection reset")
    with self.assertRaises(IOError):
      self._answer(fail)
    before = stability.requests_sent()
    stability.note_request_sent()
    self.assertEqual(1, stability.requests_sent() - before)

  def test_a_run_given_digest_credentials_answers_through_it(self):
    self.menu.options.auth_type, self.menu.options.auth_cred, self.menu.options.url = "digest", "tester:secret", self.URL
    settings.DIGEST_AUTH_REALM = "r"
    self.assertTrue([_ for _ in self.headers.authentication_handlers() if isinstance(_, self.headers.DigestAuthHandler)])

if __name__ == '__main__':
  unittest.main()

# eof
