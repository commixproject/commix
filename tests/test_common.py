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

"""
The helpers a run leans on away from any target, and the one that decides what a crash report may
carry. Nothing here needs the network; all of it is read by code that does.
"""

import os
import re
import unittest

from src.core.parse import cmdline as menu
from src.utils import common
from src.utils import settings

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CMDLINE = os.path.join(ROOT, "src", "core", "parse", "cmdline.py")

class SanitisedReports(unittest.TestCase):
  """
  An unhandled exception offers to open a GitHub issue, and what it carries is read by strangers.
  Every option that can hold a credential, a token or a target has to be masked before it goes.
  """
  # Named for what they select, not for anything they could leak: a scheme, a registry key, a
  # delimiter character and a request count.
  NOT_A_SECRET = ("--auth-type", "--reg-key", "--cookie-del", "--proxy-freq")

  def _value_options_named_like_a_secret(self):
    with open(CMDLINE) as handle:
      source = handle.read()
    found = set()
    for name, body in re.findall(r'add_option\(\s*"(--[a-z0-9-]+)"(.*?)\)\s*\n', source, re.S):
      if 'action="store_true"' in body or 'action="store_false"' in body:
        continue
      if re.search(r"cred|passwd|password|token|secret|auth|cookie|proxy|header|url|host|referer|data", name):
        found.add(name)
    return found

  def test_the_scan_finds_the_options_at_all(self):
    self.assertGreater(len(self._value_options_named_like_a_secret()), 8)

  def test_every_option_that_can_carry_a_secret_is_masked(self):
    missing = sorted(_ for _ in self._value_options_named_like_a_secret()
                     if _ not in settings.SENSITIVE_OPTIONS and _ not in self.NOT_A_SECRET)
    self.assertEqual([], missing)

  def test_an_alias_is_masked_as_well_as_the_name_it_stands_for(self):
    """
    The report carries what was typed. An alias matches none of the masks written for the name it
    is an alias of, so naming only one of the two leaves the other one readable.
    """
    with open(CMDLINE) as handle:
      source = handle.read()
    missing = []
    for alias, name in re.findall(r'\(\s*"(--[a-z0-9-]+)",\s*"(--[a-z0-9-]+)"\s*\)', source):
      if name in settings.SENSITIVE_OPTIONS and alias not in settings.SENSITIVE_OPTIONS:
        missing.append(alias + " (alias of " + name + ")")
    self.assertEqual([], missing)

  def test_a_value_is_masked_whole(self):
    # A hyphen inside the value used to end the mask early, leaving the rest of it readable.
    self.assertEqual("--auth-cred=<sanitized>", common.mask_sensitive_data("--auth-cred=user:p-ssw0rd"))
    self.assertEqual("--auth-cred=<sanitized>", common.mask_sensitive_data('--auth-cred="a b c"'))
    self.assertEqual("--proxy-cred <sanitized>", common.mask_sensitive_data("--proxy-cred admin:hunter2"))

  def test_what_is_not_a_secret_is_left_alone(self):
    for text in ("--auth-type basic", "nothing here at all", "--technique=r"):
      self.assertEqual(text, common.mask_sensitive_data(text))

class SanitisedValues(unittest.TestCase):
  """
  A value reaches a report through more than the command line, so each one is masked wherever it
  turns up: quoted back by an exception, rebuilt into a URL, printed as part of a path.
  """
  def setUp(self):
    self.saved = dict((_, getattr(menu.options, _, None)) for _ in settings.SENSITIVE_VALUE_OPTIONS)
    menu.options.url = "http://target.example/vuln.php?id=1"
    menu.options.auth_cred = "admin:hunter2"
    menu.options.proxy_cred = "proxyuser:pr0xyp4ss"

  def tearDown(self):
    for name, value in self.saved.items():
      setattr(menu.options, name, value)

  def test_a_value_is_masked_away_from_its_own_option(self):
    for text, secret in (("connecting to http://target.example/vuln.php?id=1 failed", "target.example"),
                         ("basic auth admin:hunter2 rejected", "hunter2"),
                         ("proxy handshake with proxyuser:pr0xyp4ss timed out", "pr0xyp4ss")):
      self.assertNotIn(secret, common.mask_sensitive_data(text), text)

  def test_the_account_name_goes_with_the_home_directory(self):
    self.assertNotIn("bob", common.mask_sensitive_data('File "/home/bob/commix/x.py", line 1'))
    self.assertNotIn("alice", common.mask_sensitive_data('File "C:\\Users\\alice\\x.py", line 1'))

  def test_the_path_around_it_is_kept(self):
    masked = common.mask_sensitive_data('File "/home/bob/commix/src/core/x.py", line 1')
    self.assertIn("/commix/src/core/x.py", masked)

  def test_a_short_or_absent_value_is_not_matched(self):
    # Masking a one or two character value would blank unrelated text wherever it appeared.
    menu.options.auth_cred = "ab"
    self.assertEqual("ab cd ab", common.mask_sensitive_data("ab cd ab"))
    menu.options.auth_cred = None
    self.assertEqual("nothing to mask", common.mask_sensitive_data("nothing to mask"))

  def test_every_value_option_is_a_real_destination(self):
    missing = [_ for _ in settings.SENSITIVE_VALUE_OPTIONS if not hasattr(menu.options, _)]
    self.assertEqual([], missing)

class RegexResult(unittest.TestCase):
  """
  Reads one named group back, and nothing at all from a pattern that names none - which is how a
  caller is stopped from reading a group that moved.
  """
  def test_a_named_group_is_read_back(self):
    self.assertEqual("7", common.extract_regex_result(r"a(?P<result>\d)c", "xa7cz"))

  def test_a_pattern_without_the_name_answers_nothing(self):
    self.assertIsNone(common.extract_regex_result(r"a(\d)c", "xa7cz"))

  def test_no_match_and_no_input_answer_nothing(self):
    self.assertIsNone(common.extract_regex_result(r"(?P<result>zzz)", "xa7cz"))
    self.assertIsNone(common.extract_regex_result(r"(?P<result>a)", ""))
    self.assertIsNone(common.extract_regex_result("", "abc"))

if __name__ == "__main__":
  unittest.main()
