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
How a parameter is read out of a request and put back with the marker in it. Everything here is
string work, done before anything is sent - and getting it wrong moves the injection point rather
than failing outright, which is the kind of mistake a scan reports as 'not injectable'.
"""

import unittest

from src.core.requests import parameters
from src.utils import settings

class UrlParts(unittest.TestCase):
  def test_the_query_is_cut_from_the_path(self):
    self.assertEqual("http://h/a/b.php", parameters.get_url_part("http://h/a/b.php?x=1&y=2"))

  def test_a_url_without_a_query_is_left_whole(self):
    self.assertEqual("http://h/a/b.php", parameters.get_url_part("http://h/a/b.php"))

class KeyValues(unittest.TestCase):
  def test_the_value_is_what_follows_the_first_equals(self):
    self.assertEqual("1", parameters.get_kv_value("a=1"))

  def test_a_pair_without_a_value_answers_empty(self):
    self.assertEqual("", parameters.get_kv_value("a"))

  def test_an_equals_inside_the_value_is_kept(self):
    self.assertEqual("1=2", parameters.get_kv_value("a=1=2"))

class CdataWrapping(unittest.TestCase):
  def test_the_wrapper_comes_off(self):
    self.assertEqual("v", parameters.unwrap_cdata("<![CDATA[v]]>"))

  def test_a_bare_value_is_left_alone(self):
    self.assertEqual("v", parameters.unwrap_cdata("v"))

class MarkerPlacement(unittest.TestCase):
  def test_the_marker_lands_after_the_value_it_names(self):
    tagged = parameters.apply_tag_to_value("a=1&b=2", "1")
    self.assertEqual("a=1" + settings.INJECT_TAG + "&b=2", tagged)

  def test_the_other_values_are_untouched(self):
    self.assertIn("b=2", parameters.apply_tag_to_value("a=1&b=2", "1"))

class XmlShields(unittest.TestCase):
  """
  The leaves are lifted out so the payload cannot be read as markup, then put back. What matters is
  that putting them back returns exactly what was lifted - a drift here corrupts the request body.
  """
  def test_a_shielded_document_comes_back_whole(self):
    for document in ("<a><b>v</b></a>",
                     "<a><b>1</b><c>2</c></a>",
                     "<root><x>a&amp;b</x></root>",
                     "<a/>"):
      shielded, lifted = parameters.shield_xml_leaves(document)
      self.assertEqual(document, parameters.restore_xml_shields(shielded, lifted), document)

  def test_the_shielded_form_holds_none_of_the_leaf_text(self):
    shielded, lifted = parameters.shield_xml_leaves("<a><b>SECRET</b></a>")
    self.assertNotIn("SECRET", shielded)
    self.assertTrue(any("SECRET" in _ for _ in lifted))

class JsonShapes(unittest.TestCase):
  def test_an_empty_object_is_recognised(self):
    self.assertTrue(parameters.is_empty_json_object("{}"))
    self.assertTrue(parameters.is_empty_json_object(' { } '))

  def test_an_object_with_a_member_is_not(self):
    self.assertFalse(parameters.is_empty_json_object('{"a":1}'))

  def test_json_is_parsed_in_the_order_it_was_written(self):
    parsed = parameters.json_format('{"b":1,"a":2}')
    self.assertEqual(["b", "a"], list(parsed.keys()))

  def test_something_that_is_not_json_is_refused(self):
    # The callers decide what to do about it; answering a half-parse would be worse.
    self.assertRaises(Exception, parameters.json_format, "a=1&b=2")

class PostSplitting(unittest.TestCase):
  def test_a_form_body_splits_on_the_ampersand(self):
    split, original = parameters.split_post_parameters("a=1&b=2")
    self.assertEqual(["a=1", "b=2"], split)
    self.assertEqual("a=1&b=2", original)

  def test_a_single_pair_stays_one(self):
    split, _ = parameters.split_post_parameters("a=1")
    self.assertEqual(["a=1"], split)

if __name__ == "__main__":
  unittest.main()
