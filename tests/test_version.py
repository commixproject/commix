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

import unittest

from src.utils import settings
from src.utils import version

class HowLongSinceThisCopyWasUpdated(unittest.TestCase):
  """
  Read off the files on disk rather than asked of a server, so a run that never reaches the network
  still knows how old the copy running it is.
  """
  def setUp(self):
    self._out = settings.print_data_to_stdout
    self._days = version.days_since_update
    self.said = []
    settings.print_data_to_stdout = self.said.append

  def tearDown(self):
    settings.print_data_to_stdout = self._out
    version.days_since_update = self._days

  def answering(self, days):
    version.days_since_update = lambda: days

  def written(self):
    return settings.strip_ansi_codes("\n".join(str(line) for line in self.said))

  def test_the_age_is_a_whole_number_of_days(self):
    days = version.days_since_update()
    self.assertIsInstance(days, int)
    self.assertGreaterEqual(days, 0)

  def test_a_copy_within_the_allowance_says_nothing(self):
    self.answering(settings.LAST_UPDATE_NAGGING_DAYS)
    version.announce_if_outdated()
    self.assertEqual("", self.written())

  def test_a_copy_past_it_says_how_many_days(self):
    self.answering(settings.LAST_UPDATE_NAGGING_DAYS + 34)
    version.announce_if_outdated()
    written = self.written()
    self.assertIn(str(settings.LAST_UPDATE_NAGGING_DAYS + 34) + " days ago", written)
    self.assertIn("'--update'", written)

  def test_a_copy_that_cannot_say_its_own_age_says_nothing(self):
    self.answering(None)
    version.announce_if_outdated()
    self.assertEqual("", self.written())

if __name__ == "__main__":
  unittest.main()
