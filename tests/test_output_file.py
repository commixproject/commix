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
from src.core.controller import injector

"""
A response standing in for the output file as the target serves it.
"""
class served(object):
  def __init__(self, body, headers=None):
    self._body = body.encode(settings.DEFAULT_CODEC)
    self._headers = headers or {}

  def read(self, *args, **kwargs):
    return self._body

  def info(self):
    return self._headers

  def getcode(self):
    return 200

class TheOutputFileIsReadAsTheCommandWroteIt(unittest.TestCase):
  """
  The file holds what the command printed. Stripped at both ends, an output that was indented, or
  padded, or was whitespace altogether came back without the part of it that said so.
  """
  def setUp(self):
    self._os = settings.TARGET_OS
    settings.TARGET_OS = settings.OS.UNIX

  def tearDown(self):
    settings.TARGET_OS = self._os

  def test_the_whitespace_the_output_begins_and_ends_with_is_kept(self):
    self.assertEqual("\t   \t\t\tX\t\t\t\t\t\t\t",
                     injector.output_file_content(served("\t   \t\t\tX\t\t\t\t\t\t\t")))

  def test_an_output_that_is_only_whitespace_is_not_read_as_an_empty_one(self):
    self.assertEqual("   ", injector.output_file_content(served("   ")))

  def test_the_line_breaks_it_ends_with_come_off_the_way_a_substitution_drops_them(self):
    self.assertEqual("a\nb", injector.output_file_content(served("a\nb\n\n")))

  def test_the_line_breaks_inside_it_stay_where_they_are(self):
    self.assertEqual("one\ntwo\nthree", injector.output_file_content(served("one\ntwo\nthree\n")))

class WhatTheTargetSaysAboutTheFileItself(unittest.TestCase):
  def test_an_entity_tag_is_preferred_over_a_date_a_second_at_a_time(self):
    self.assertEqual('"8-abc"', injector.output_file_validator(
      served("x", {"ETag": '"8-abc"', "Last-Modified": "Wed, 11 Nov 2026 18:36:17 GMT"})))

  def test_a_weak_tag_is_the_same_tag(self):
    self.assertEqual('"8-abc"', injector.output_file_validator(served("x", {"ETag": 'W/"8-abc"'})))

  def test_a_date_answers_where_there_is_no_tag(self):
    self.assertEqual("Wed, 11 Nov 2026 18:36:17 GMT", injector.output_file_validator(
      served("x", {"Last-Modified": "Wed, 11 Nov 2026 18:36:17 GMT"})))

  def test_a_target_that_says_nothing_about_the_file_answers_nothing(self):
    self.assertIsNone(injector.output_file_validator(served("x")))

class AnswerThisCommandsOutputOrNothing(unittest.TestCase):
  """
  A command the target never ran leaves the file as it was, and reading it then answers with
  whatever wrote it last - the marker the detection phase put there, or the command before this
  one. Handed back as this command's own, that is a wrong answer rather than a missing one.
  """
  def test_an_untouched_file_is_not_this_commands_output(self):
    self.assertTrue(injector.output_file_is_stale("MARKER", '"1-a"', "MARKER", '"1-a"'))

  def test_a_file_written_again_is_this_commands_output_even_where_it_says_the_same(self):
    # The same command run twice writes the file both times, and the tag moves with the write.
    self.assertFalse(injector.output_file_is_stale("uid=33", '"6-b"', "uid=33", '"6-a"'))

  def test_a_file_whose_contents_changed_is_this_commands_output(self):
    self.assertFalse(injector.output_file_is_stale("uid=33", '"6-a"', "MARKER", '"6-a"'))

  def test_nothing_is_withheld_from_a_target_that_says_nothing_about_the_file(self):
    # Without a tag there is no telling a rewrite from a repeat, and an answer withheld from a
    # command that worked is the worse of the two mistakes.
    self.assertFalse(injector.output_file_is_stale("uid=33", None, "uid=33", None))

  def test_the_first_read_of_a_run_is_answered(self):
    self.assertFalse(injector.output_file_is_stale("uid=33", '"6-a"', None, None))

if __name__ == "__main__":
  unittest.main()

# eof
