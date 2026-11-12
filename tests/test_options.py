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

import sys
import unittest

from src.utils import settings
from src.core import options
from src.core.requests import tor
from src.core.parse import cmdline as menu

OPTIONS_STATE = ("url", "cdel", "pdel", "tor", "tor_port", "tor_type", "proxy", "ignore_proxy",
                 "check_tor", "failed_tries")

class _AValidatedRun(unittest.TestCase):
  """
  What the options say, read the way a run reads them before a target is contacted - with the Tor
  lookup stood down, since a test that reaches for a local service is a broken test.
  """
  def setUp(self):
    self._options = {name: getattr(menu.options, name, None) for name in OPTIONS_STATE}
    self._printed = []
    self._print = settings.print_data_to_stdout
    self._tor = (tor.set_proxy_settings, tor.do_check)
    # Read back further down for the inject tag, and a bare one is a run with nothing asked of it.
    self._argv = list(sys.argv)
    sys.argv = ["commix.py", "-u", "http://t/a.php?addr=1"]
    settings.print_data_to_stdout = lambda text: self._printed.append(str(text))
    tor.set_proxy_settings = lambda *args, **kwargs: None
    tor.do_check = lambda *args, **kwargs: None
    menu.options.url = "http://t/a.php?addr=1"
    menu.options.cdel = None
    menu.options.pdel = None
    menu.options.tor = False
    menu.options.tor_port = False
    menu.options.tor_type = None
    menu.options.proxy = None
    menu.options.ignore_proxy = False
    menu.options.check_tor = False
    menu.options.failed_tries = None

  def tearDown(self):
    settings.print_data_to_stdout = self._print
    tor.set_proxy_settings, tor.do_check = self._tor
    sys.argv = self._argv
    for name, value in self._options.items():
      setattr(menu.options, name, value)

  def refused(self):
    self.assertRaises(SystemExit, options.validate)
    return "".join(self._printed)

class ADelimiterIsOneCharacter(_AValidatedRun):
  """
  A longer one splits the cookie where nothing asked it to, and every parameter behind the first
  one is then reported as absent rather than as split wrong.
  """
  def test_a_longer_one_is_refused_by_name(self):
    menu.options.cdel = "||"
    self.assertIn("'--cookie-del'", self.refused())

  def test_one_character_is_what_it_asks_for(self):
    menu.options.cdel = ";"
    options.validate()
    self.assertEqual(";", menu.options.cdel)

  def test_an_escape_counts_as_the_character_it_stands_for(self):
    # Written as an escape where the shell would otherwise eat the character itself, so what
    # arrives is two characters standing for one.
    menu.options.cdel = "\\n"
    options.validate()
    self.assertEqual("\n", menu.options.cdel)

class ANumberThatCannotMeanWhatItSaysIsRefused(_AValidatedRun):
  """
  Left to run, a count of less than one reaches the loop it bounds and stops it before its first
  turn - and what is reported is a target that answered nothing rather than a value that could
  never have been asked for.
  """
  def test_a_count_of_none_is_refused_by_name(self):
    menu.options.failed_tries = 0
    self.assertIn("'--failed-tries'", self.refused())

  def test_a_negative_count_is_refused_too(self):
    menu.options.failed_tries = -1
    self.assertIn("'--failed-tries'", self.refused())

  def test_a_count_of_one_is_what_it_asks_for(self):
    menu.options.failed_tries = 1
    options.validate()
    self.assertEqual(1, menu.options.failed_tries)

class APortIsANumberInARange(_AValidatedRun):
  """
  The lookup is handed the value as a number, so one that is not a number reaches it as an error
  of a kind it does not answer for, and one past the range as a Tor that is not listening.
  """
  def test_a_value_that_is_not_a_number_is_refused_by_name(self):
    menu.options.tor, menu.options.tor_port = True, "abc"
    self.assertIn("'--tor-port'", self.refused())

  def test_a_value_past_the_range_is_refused_by_name(self):
    menu.options.tor, menu.options.tor_port = True, "99999"
    self.assertIn("'--tor-port'", self.refused())

  def test_a_port_is_handed_on_as_a_number(self):
    menu.options.tor, menu.options.tor_port = True, "9050"
    options.validate()
    self.assertEqual(9050, menu.options.tor_port)

  def test_it_is_refused_without_the_switch_that_reads_it(self):
    menu.options.tor_port = "9050"
    self.assertIn("'--tor-port'", self.refused())

if __name__ == '__main__':
  unittest.main()

# eof
