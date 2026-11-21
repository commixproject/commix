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

class TheSameCommandAskedTwiceIsNotTakenForANeverLandedWrite(unittest.TestCase):
  """
  A command run a second time can write back the very output it wrote before, inside the same
  second a weak validator (an 'ETag' or 'Last-Modified' resolved to whole seconds) cannot move in -
  identical content and an unmoved validator is then what running it twice looks like, not a write
  that never landed.
  """
  def test_the_same_command_run_again_is_not_stale(self):
    self.assertFalse(injector.output_file_is_stale("uid=33", '"6-a"', "uid=33", '"6-a"', cmd="id", previous_cmd="id"))

  def test_a_different_command_with_the_same_answer_still_is(self):
    self.assertTrue(injector.output_file_is_stale("uid=33", '"6-a"', "uid=33", '"6-a"', cmd="whoami", previous_cmd="id"))

  def test_the_detection_phase_marker_is_still_read_the_strict_way(self):
    # Nothing has written the file yet - a match against what detection left is read exactly as before.
    self.assertTrue(injector.output_file_is_stale("MARKER", '"1-a"', "MARKER", '"1-a"', cmd="id", previous_cmd=None))

  def test_a_run_that_never_passes_a_command_behaves_as_it_always_did(self):
    self.assertTrue(injector.output_file_is_stale("MARKER", '"1-a"', "MARKER", '"1-a"'))

class TheGuardAppliesEndToEndThroughInjectionResults(unittest.TestCase):
  """
  The same guard, wired through the function the file-based technique actually calls - not just the
  comparison it is built from.
  """
  NAMES = ("LAST_OUTPUT_FILE_CONTENT", "LAST_OUTPUT_FILE_VALIDATOR", "LAST_OUTPUT_FILE_CMD",
           "MAX_OUTPUT_FILE_READS", "OUTPUT_FILE_READ_DELAY")

  def setUp(self):
    self._saved = dict((name, getattr(settings, name)) for name in self.NAMES)
    settings.LAST_OUTPUT_FILE_CONTENT = settings.LAST_OUTPUT_FILE_VALIDATOR = settings.LAST_OUTPUT_FILE_CMD = None
    settings.MAX_OUTPUT_FILE_READS = 1
    self._fetch = injector.fetch_output_response

  def tearDown(self):
    for name, value in self._saved.items():
      setattr(settings, name, value)
    injector.fetch_output_response = self._fetch

  def _served_result(self, content, validator, cmd):
    injector.fetch_output_response = lambda url, OUTPUT_TEXTFILE, timesec, technique: served(content, {"ETag": validator})
    return injector.injection_results(None, "TAG", cmd, settings.INJECTION_TECHNIQUE.FILE_BASED, "http://t/", "f.txt", 0)

  def test_the_same_command_asked_twice_reads_both_times(self):
    self.assertEqual("uid=33", self._served_result("uid=33", '"6-a"', "id"))
    self.assertEqual("uid=33", self._served_result("uid=33", '"6-a"', "id"))

  def test_a_different_command_with_the_same_answer_reads_as_no_output(self):
    self._served_result("uid=33", '"6-a"', "id")
    self.assertEqual("", self._served_result("uid=33", '"6-a"', "whoami"))

if __name__ == "__main__":
  unittest.main()

# eof
