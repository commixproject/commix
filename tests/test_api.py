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
import socket
import tempfile
import unittest

from tests._testutils import stage
from src.utils import api
from src.core.parse import cmdline as menu

"""
Fail closed: the option logic is settled before anything is served, so a test of it that reaches for
the network is a broken test rather than a slow one.
"""
def _no_transport(*args, **kwargs):
  raise RuntimeError("The API's option handling is exercised offline; no transport may be opened.")

class _Offline(unittest.TestCase):
  def setUp(self):
    self.saved = (socket.socket, socket.create_connection)
    socket.socket, socket.create_connection = _no_transport, _no_transport
    self.directory = tempfile.mkdtemp(prefix="commix-api-")
    self.task = api.Task("0123456789abcdef", self.directory)

  def tearDown(self):
    socket.socket, socket.create_connection = self.saved
    shutil.rmtree(self.directory, ignore_errors=True)

class OptionNames(unittest.TestCase):
  """
  Every spelling the command line takes answers to the same option, since the API is asked in
  whichever of them the caller happens to know.
  """
  def test_an_option_answers_to_its_store_and_to_its_flags(self):
    for spelling in ("url", "--url", "-u"):
      self.assertIsNotNone(api._option(spelling.lstrip("-")), spelling + " names no option")
    self.assertEqual(api._option("url").dest, api._option("u").dest)

  def test_a_name_the_parser_does_not_know_names_nothing(self):
    self.assertIsNone(api._option("not_an_option_of_any_kind"))

class RefusedOptions(_Offline):
  """
  The options a task may not be given. Three of these lists exist for different reasons, and the
  first is the one that matters most: every option on it would act on the host serving the API
  rather than on the target, so a task that could set one would be remote code execution wearing
  the API's own clothes.
  """
  def test_an_option_that_would_act_on_the_api_host_is_refused(self):
    for name in sorted(api.REFUSED_OPTIONS):
      refusal = self.task.set_option(name, "whatever")
      self.assertIsNotNone(refusal, "'" + name + "' was accepted over the API")
      self.assertIn("cannot be set over the API", refusal)
      self.assertNotIn(name, [k for k, v in self.task.options.items() if v == "whatever"])

  def test_an_option_the_server_settles_itself_is_refused(self):
    for name in api.SERVER_OWNED_OPTIONS:
      refusal = self.task.set_option(name, "whatever")
      self.assertIsNotNone(refusal, "'" + name + "' was accepted over the API")
      self.assertIn("settled by the server", refusal)

  def test_an_option_a_run_is_never_given_is_refused(self):
    # Named rather than swept: the point is that the list is not empty and is actually consulted.
    self.assertTrue(api.UNCARRIED_OPTIONS, "no option is listed as uncarried")
    for name in api.UNCARRIED_OPTIONS:
      if api._option(name) is None:
        continue
      self.assertIsNotNone(self.task.set_option(name, "whatever"), "'" + name + "' was accepted")

  def test_an_unknown_option_is_refused_by_name(self):
    refusal = self.task.set_option("--not-an-option", "x")
    self.assertIsNotNone(refusal)
    self.assertIn("not-an-option", refusal)

class AcceptedOptions(_Offline):
  """
  What the API does take, and what it does with it.
  """
  def test_an_ordinary_option_is_kept_where_the_run_reads_it(self):
    self.assertIsNone(self.task.set_option("url", "http://target.invalid/x?a=1"))
    self.assertEqual("http://target.invalid/x?a=1", self.task.options["url"])

  def test_an_option_is_taken_by_its_flag_as_well_as_its_name(self):
    self.assertIsNone(self.task.set_option("--level", "3"))
    self.assertEqual(3, self.task.options["level"])

  def test_a_value_the_parser_would_not_take_is_refused_here(self):
    refusal = self.task.set_option("level", "three")
    self.assertIsNotNone(refusal, "a non-numeric level was accepted")
    self.assertIn("The option", refusal)

class QueryReading(unittest.TestCase):
  """
  What the handler reads off a request, settled without one being made.
  """
  def test_a_value_is_read_as_what_it_is_written_as(self):
    self.assertIs(True, api._typed("true"))
    self.assertIs(False, api._typed("FALSE"))
    self.assertEqual(3, api._typed("3"))
    self.assertEqual("3.1", api._typed("3.1"))
    self.assertEqual("ancst", api._typed("ancst"))

  def test_bounds_are_read_where_given_and_left_alone_where_not(self):
    self.assertEqual((2, 9), api._bounds({"start": ["2"], "end": ["9"]}))
    self.assertEqual((None, None), api._bounds({}))
    self.assertEqual((None, None), api._bounds({"start": ["x"], "end": []}))

if __name__ == "__main__":
  unittest.main()
