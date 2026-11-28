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
from src.core.parse import cmdline as menu

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

  def test_a_delimiter_carrying_a_backslash_splits_an_xml_body_as_it_stands(self):
    # The split puts the delimiter between the tags, where a backslash would otherwise be read as
    # an escape and "\1" as a group that was never asked for.
    state = (settings.IS_XML, settings.POST_DATA_PARAM_DELIMITER, settings.XML_TAG_SEPARATORS,
             menu.options.data, settings.USER_DEFINED_POST_DATA)
    settings.IS_XML = True
    settings.POST_DATA_PARAM_DELIMITER = "\\1"
    menu.options.data = settings.USER_DEFINED_POST_DATA = "<a>1</a><b>2</b>"
    try:
      split, _ = parameters.split_post_parameters("<a>1</a><b>2</b>")
      self.assertTrue(split)
    finally:
      (settings.IS_XML, settings.POST_DATA_PARAM_DELIMITER, settings.XML_TAG_SEPARATORS,
       menu.options.data, settings.USER_DEFINED_POST_DATA) = state

class NamedBoundary(unittest.TestCase):
  """
  What '--prefix' and '--suffix' do to the boundary the sweep was going to send.
  """
  def setUp(self):
    self.prefix, self.suffix = menu.options.prefix, menu.options.suffix
    self.load_session = settings.LOAD_SESSION
    settings.LOAD_SESSION = False

  def tearDown(self):
    menu.options.prefix, menu.options.suffix = self.prefix, self.suffix
    settings.LOAD_SESSION = self.load_session

  def test_a_named_boundary_stands_in_place_of_the_one_being_tried(self):
    """
    Added to it instead, what the user named arrives behind whatever each boundary already carried,
    so the sweep sends combinations nobody asked for and never once sends the one that was.
    """
    menu.options.prefix, menu.options.suffix = "'", "'"
    _, prefix = parameters.prefixes("payload", ";")
    _, suffix = parameters.suffixes("payload", "&")
    self.assertEqual("'", prefix)
    self.assertEqual("'", suffix)

  def test_an_unnamed_boundary_is_left_as_it_was(self):
    menu.options.prefix = menu.options.suffix = None
    _, prefix = parameters.prefixes("payload", ";")
    _, suffix = parameters.suffixes("payload", "&")
    self.assertEqual(";", prefix)
    self.assertEqual("&", suffix)

class TheParametersOwnValueInFrontOfAPayload(unittest.TestCase):
  """
  What 'prefixes' glues in front of a payload so that it reaches the sink behind the value the parameter arrived with - for a JSON body as for a form.
  """
  NAMES = ("IS_JSON", "TESTABLE_VALUE", "LOAD_SESSION", "REPLACE_VALUE")

  def setUp(self):
    self._saved = dict((name, getattr(settings, name)) for name in self.NAMES)
    self._prefix = menu.options.prefix
    menu.options.prefix = None
    settings.TESTABLE_VALUE = "127.0.0.1"
    settings.LOAD_SESSION = settings.REPLACE_VALUE = False

  def tearDown(self):
    for name, value in self._saved.items():
      setattr(settings, name, value)
    menu.options.prefix = self._prefix

  def test_a_json_payload_follows_the_value_as_a_form_one_does(self):
    for is_json in (True, False):
      settings.IS_JSON = is_json
      payload, prefix = parameters.prefixes(";echo", "")
      self.assertEqual(("127.0.0.1;echo", "127.0.0.1"), (payload, prefix))

  def test_standing_in_place_of_the_value_leaves_it_off_for_json_too(self):
    settings.IS_JSON = settings.REPLACE_VALUE = True
    self.assertEqual((";echo", ""), parameters.prefixes(";echo", ""))

  def test_a_resumed_session_leaves_it_off(self):
    settings.IS_JSON = settings.LOAD_SESSION = True
    self.assertEqual((";echo", ""), parameters.prefixes(";echo", ""))

class TestableValue(unittest.TestCase):
  """
  Whether the parameter's own value is handed to the target, or a placeholder put in its place.
  """
  def setUp(self):
    from src.core.controller import controller
    self.controller = controller
    self.testable_value = settings.TESTABLE_VALUE
    self.load_session = settings.LOAD_SESSION
    settings.TESTABLE_VALUE = "127.0.0.1"
    settings.LOAD_SESSION = False

  def tearDown(self):
    settings.TESTABLE_VALUE = self.testable_value
    settings.LOAD_SESSION = self.load_session

  def test_the_real_value_is_what_the_target_is_asked_with(self):
    """
    The command before the payload is given this value, so a placeholder the target was not
    answering on makes that command fail - and a separator that chains on it having succeeded then
    never fires, whatever the target would have carried.
    """
    url = "http://127.0.0.1/x.php?addr=127.0.0.1" + settings.INJECT_TAG
    self.assertEqual(url, self.controller.attempt_skip_testable_value(url, "GET", "addr"))
    self.assertEqual("127.0.0.1", settings.TESTABLE_VALUE)
    self.assertFalse(settings.TESTABLE_VALUE_OPTIMIZED)

  def test_a_placeholder_an_earlier_run_confirmed_is_taken_up_again(self):
    """
    The one exchange still made: a resumed run is handed what the run that stored it had already
    asked the payload's own question through, so it is taken as it stands rather than measured for
    again. Without this the stored answer is read and nothing is done with it.
    """
    stored = self.controller.session_handler.check_stored_testable_value
    try:
      self.controller.session_handler.check_stored_testable_value = lambda *_: "ABC"
      settings.LOAD_SESSION = True
      url = "http://127.0.0.1/x.php?addr=127.0.0.1" + settings.INJECT_TAG
      rewritten = self.controller.attempt_skip_testable_value(url, "GET", "addr")
      self.assertEqual("http://127.0.0.1/x.php?addr=ABC" + settings.INJECT_TAG, rewritten)
      self.assertEqual("ABC", settings.TESTABLE_VALUE)
      self.assertTrue(settings.TESTABLE_VALUE_OPTIMIZED)
    finally:
      self.controller.session_handler.check_stored_testable_value = stored
      settings.TESTABLE_VALUE_OPTIMIZED = False

if __name__ == "__main__":
  unittest.main()

class ReplacedValue(unittest.TestCase):
  """
  Where the payload goes relative to the value the parameter arrived with.

  Behind it is what nearly every sink wants. A sink reading the value's own first byte is the
  exception, and there the value has to go rather than sit in front of the payload - an
  interpreter's two-argument open() handed a leading '|' runs what follows, while the same pipe with
  a value before it is read as a filename and nothing runs at all.
  """
  def setUp(self):
    self.testable_value = settings.TESTABLE_VALUE
    self.replace_value = settings.REPLACE_VALUE
    self.prefix = menu.options.prefix
    menu.options.prefix = None
    settings.TESTABLE_VALUE = "127.0.0.1"

  def tearDown(self):
    settings.TESTABLE_VALUE = self.testable_value
    settings.REPLACE_VALUE = self.replace_value
    menu.options.prefix = self.prefix

  def test_the_value_is_carried_in_front_of_the_payload_by_default(self):
    settings.REPLACE_VALUE = False
    payload, prefix = parameters.prefixes(";echo Hello", "")
    self.assertTrue(payload.startswith("127.0.0.1"), repr(payload) + " drops the value")

  def test_the_payload_stands_alone_where_it_replaces_the_value(self):
    settings.REPLACE_VALUE = True
    payload, prefix = parameters.prefixes("|echo Hello", "")
    self.assertEqual("|echo Hello", payload)
    self.assertTrue(payload.startswith("|"), "the separator is not the value's first byte")

  def test_a_boundary_prefix_is_still_carried_when_the_value_is_replaced(self):
    settings.REPLACE_VALUE = True
    payload, prefix = parameters.prefixes(";echo Hello", "'")
    self.assertEqual("';echo Hello", payload)

class AMultipartBodyIsTestedFieldByField(unittest.TestCase):
  """
  A multipart form carries its fields in parts, each named in its own headers. Every field is a
  parameter of its own, named as the form names it, with the payload placed where its value ends and
  every boundary, header and other part left as it was; a file being uploaded is not one of them.
  """
  BODY = ('--BB\r\nContent-Disposition: form-data; name="host"\r\n\r\n127.0.0.1\r\n'
          '--BB\r\nContent-Disposition: form-data; name="note"\r\n\r\nline one\r\nline two\r\n'
          '--BB\r\nContent-Disposition: form-data; name="empty"\r\n\r\n\r\n'
          '--BB\r\nContent-Disposition: form-data; name="upload"; filename="a.txt"\r\nContent-Type: text/plain\r\n\r\nfile body\r\n'
          '--BB\r\nContent-Disposition: form-data; name="nested"\r\nContent-Type: multipart/mixed; boundary=CC\r\n\r\n--CC--\r\n'
          '--BB--\r\n')

  def setUp(self):
    import copy
    self._settings = dict((name, copy.deepcopy(value)) for name, value in vars(settings).items()
                          if name.isupper() and isinstance(value, (str, int, float, bool, type(None), list, dict, set, tuple)))
    self._options = dict((name, getattr(menu.options, name)) for name in ("batch", "skip_empty", "data", "test_parameter"))
    menu.options.batch, menu.options.skip_empty, menu.options.test_parameter = True, False, None

  def tearDown(self):
    for name, value in self._options.items():
      setattr(menu.options, name, value)
    for name, value in self._settings.items():
      setattr(settings, name, value)

  def _fields(self, body):
    return [(name, body[start:end]) for name, start, end in parameters.multipart_fields(body)]

  def test_each_field_is_read_with_its_whole_value(self):
    self.assertEqual([("host", "127.0.0.1"), ("note", "line one\r\nline two"), ("empty", "")], self._fields(self.BODY))

  def test_a_body_written_with_bare_line_feeds_is_read_alike(self):
    expected = [(name, value.replace("\r\n", "\n")) for name, value in self._fields(self.BODY)]
    self.assertEqual(expected, self._fields(self.BODY.replace("\r\n", "\n")))

  def test_one_candidate_per_field_with_the_tag_where_its_value_ends(self):
    candidates = parameters.multipart_candidates(self.BODY)
    self.assertEqual(3, len(candidates))
    for candidate in candidates:
      self.assertEqual(1, candidate.count(settings.INJECT_TAG))
      self.assertEqual(self.BODY, candidate.replace(settings.INJECT_TAG, ""))
    self.assertIn('name="host"\r\n\r\n127.0.0.1' + settings.INJECT_TAG + "\r\n--BB", candidates[0])

  def test_the_file_and_the_nested_body_are_never_candidates(self):
    for candidate in parameters.multipart_candidates(self.BODY):
      self.assertNotIn("file body" + settings.INJECT_TAG, candidate)
      self.assertNotIn("--CC--" + settings.INJECT_TAG, candidate)

  def test_only_the_marked_field_is_a_candidate_where_the_user_marked_one(self):
    settings.CUSTOM_INJECTION_MARKER = True
    marked = self.BODY.replace("127.0.0.1", "127.0.0.1" + settings.ASTERISK_MARKER)
    self.assertEqual([self.BODY.replace("127.0.0.1", "127.0.0.1" + settings.INJECT_TAG)], parameters.multipart_candidates(marked))

  def test_an_empty_field_is_left_out_on_request(self):
    menu.options.skip_empty = True
    self.assertEqual(2, len(parameters.multipart_candidates(self.BODY)))

  def test_a_candidate_is_named_after_its_field(self):
    settings.IS_MULTIPART = True
    candidate = parameters.multipart_candidates(self.BODY)[1]
    self.assertEqual("note", parameters.vuln_POST_param(candidate, "http://t/"))
    self.assertEqual("line one\r\nline two", settings.TESTABLE_VALUE)

  def test_the_body_is_recognised_and_split_into_its_fields(self):
    found = parameters.do_POST_check(self.BODY, "POST")
    self.assertTrue(settings.IS_MULTIPART)
    self.assertEqual(3, len(found))

  def test_a_form_body_is_not_taken_for_one(self):
    found = parameters.do_POST_check("host=127.0.0.1&name=form-data", "POST")
    self.assertFalse(settings.IS_MULTIPART)
    self.assertTrue(found)

class AMultipartBodyGoesOutAsOne(unittest.TestCase):
  """
  A part is cut at the boundary the Content-Type names, so a multipart body is sent under that type
  with its own boundary; a type the user names for the request is the one that goes out.
  """
  def setUp(self):
    import copy
    from src.core.requests import headers
    self.headers = headers
    self._settings = dict((name, copy.deepcopy(value)) for name, value in vars(settings).items()
                          if name.isupper() and isinstance(value, (str, int, float, bool, type(None), list, dict, set, tuple)))
    self._options = dict((name, getattr(menu.options, name)) for name in ("data", "header", "headers", "requestfile", "logfile", "url"))
    menu.options.header = menu.options.headers = menu.options.requestfile = menu.options.logfile = None
    menu.options.url = "http://t/upload.php"
    menu.options.data = AMultipartBodyIsTestedFieldByField.BODY
    settings.IS_MULTIPART, settings.EXTRA_HTTP_HEADERS, settings.RAW_HTTP_HEADERS = True, False, ""

  def tearDown(self):
    for name, value in self._options.items():
      setattr(menu.options, name, value)
    for name, value in self._settings.items():
      setattr(settings, name, value)

  def _type(self):
    from src.thirdparty.six.moves import urllib as _urllib
    request = _urllib.request.Request(menu.options.url, b"x", method="POST")
    self.headers.do_check(request, safe=True)
    return request.get_header("Content-type")

  def test_it_is_sent_as_multipart_with_its_own_boundary(self):
    self.assertEqual("multipart/form-data; boundary=BB", self._type())

  def test_a_type_the_user_names_is_the_one_sent(self):
    menu.options.header = "Content-Type: multipart/form-data; boundary=BB; charset=UTF-8"
    settings.EXTRA_HTTP_HEADERS = True
    self.assertEqual("multipart/form-data; boundary=BB; charset=UTF-8", self._type())

class AStructuredFieldIsSetAsideByItsOwnName(unittest.TestCase):
  """
  A field is set aside for what its name says - an anti-CSRF token, session state, a value
  '--randomize' refreshes - and never for what its value happens to hold. A JSON, XML or GraphQL
  piece carries its name and value together, so it is read for its name first, the way a form
  pair is; a value holding 'token' is ordinary input, and naming a field with '-p' tests it.
  """
  def setUp(self):
    import copy
    self._settings = dict((name, copy.deepcopy(value)) for name, value in vars(settings).items()
                          if name.isupper() and isinstance(value, (str, int, float, bool, type(None), list, dict, set, tuple)))
    self._options = dict((name, getattr(menu.options, name)) for name in ("batch", "skip_empty", "data", "test_parameter"))
    menu.options.batch, menu.options.skip_empty, menu.options.test_parameter = True, False, None
    settings.CSRF_TOKEN, settings.LOAD_SESSION = None, False
    settings.TESTABLE_PARAMETERS_LIST, settings.RANDOMIZE_PARAMETERS_LIST = [], []

  def tearDown(self):
    for name, value in self._options.items():
      setattr(menu.options, name, value)
    for name, value in self._settings.items():
      setattr(settings, name, value)

  def _tested(self, body):
    import io, contextlib
    settings.USER_DEFINED_POST_DATA = menu.options.data = body
    said = io.StringIO()
    with contextlib.redirect_stdout(said):
      found = parameters.do_POST_check(body, "POST")
      found = [found] if isinstance(found, str) else found
      names = [parameters.vuln_POST_param(_, "http://t/") for _ in found if settings.INJECT_TAG in _]
    return names, [_ for _ in said.getvalue().splitlines() if "Ignoring" in _ or "Skipping" in _]

  def test_each_format_names_a_piece_by_its_key(self):
    settings.IS_JSON = True
    self.assertEqual("host=mytoken.example.com", parameters.named_fragment('{"a":{"host":"mytoken.example.com"'))
    self.assertEqual("b=2", parameters.named_fragment(' "b": "2"}}'))
    self.assertEqual("host=1.2.3.4", parameters.named_fragment('{"query":"query { s(host: \\"1.2.3.4\\") }"}'))
    settings.IS_JSON, settings.IS_XML = False, True
    self.assertEqual("host=nonce", parameters.named_fragment("<host><![CDATA[nonce]]></host>"))
    self.assertEqual("<r>", parameters.named_fragment("<r>"))
    settings.IS_XML, settings.IS_GRAPHQL = False, True
    self.assertEqual("host=token", parameters.named_fragment('query { s(host: "token"'))

  def test_a_form_pair_is_left_as_it_is(self):
    self.assertEqual("csrf_token=a=b", parameters.named_fragment("csrf_token=a=b"))

  def test_a_value_holding_a_token_word_is_tested(self):
    for body in ('{"host":"mytoken.example.com","b":"2"}', "<r><host>nonce.example.com</host><b>2</b></r>",
                 'query { s(host: "xsrf.example.com", b: "2") { id } }'):
      for flag in ("IS_JSON", "IS_XML", "IS_GRAPHQL"):
        setattr(settings, flag, False)
      self.assertEqual((["host", "b"], []), self._tested(body), body)

  def test_a_key_naming_a_token_is_set_aside_with_a_word_said(self):
    names, said = self._tested('{"csrf_token":"abc","host":"1"}')
    self.assertEqual(["host"], names)
    self.assertEqual(1, len(said))
    self.assertIn("'csrf_token'", said[0])

  def test_naming_the_field_tests_it(self):
    settings.TESTABLE_PARAMETERS_LIST = ["csrf_token"]
    self.assertIn("csrf_token", self._tested("<r><csrf_token>abc</csrf_token><host>1</host></r>")[0])

  def test_a_nested_field_is_asked_for_by_its_path(self):
    from src.core.controller import checks
    settings.TESTABLE_PARAMETERS_LIST = ["a.csrf_token"]
    self.assertTrue(checks.explicitly_testable("csrf_token=abc"))
    settings.TESTABLE_PARAMETERS_LIST = ["a.host"]
    self.assertFalse(checks.explicitly_testable("csrf_token=abc"))

  def test_session_state_and_a_randomized_field_are_set_aside_by_name(self):
    settings.RANDOMIZE_PARAMETERS_LIST = ["b"]
    names, said = self._tested('{"__VIEWSTATE":"abc","host":"1","b":"2"}')
    self.assertEqual(["host"], names)
    self.assertEqual(2, len(said))

  def test_the_question_names_the_key(self):
    from src.utils import common
    asked, read_input = [], common.read_input
    common.read_input = lambda message, default=None, check_batch=True: "Y" if "process it" in message else (asked.append(message), "N")[1]
    menu.options.batch = False
    try:
      self._tested('{"csrf_token":"abc","host":"mytoken.example.com"}')
    finally:
      common.read_input = read_input
    self.assertEqual(1, len(asked))
    self.assertIn("'csrf_token'", asked[0])

class ABodyIsSentAsItIsWritten(unittest.TestCase):
  """
  A form, raw or GraphQL body goes out with every space the user wrote - in a value, in a name, in a
  document - and a name written after a delimiter's space is reported without it, the way a cookie's is.
  """
  def setUp(self):
    import copy
    self._settings = dict((name, copy.deepcopy(value)) for name, value in vars(settings).items()
                          if name.isupper() and isinstance(value, (str, int, float, bool, type(None), list, dict, set, tuple)))
    self._options = dict((name, getattr(menu.options, name)) for name in ("batch", "skip_empty", "data", "test_parameter"))
    menu.options.batch, menu.options.skip_empty, menu.options.test_parameter = True, False, None
    settings.TESTABLE_PARAMETERS_LIST, settings.RANDOMIZE_PARAMETERS_LIST = [], []

  def tearDown(self):
    for name, value in self._options.items():
      setattr(menu.options, name, value)
    for name, value in self._settings.items():
      setattr(settings, name, value)

  def _sent(self, body):
    import io, contextlib
    from src.core.controller import controller
    settings.USER_DEFINED_POST_DATA = menu.options.data = body
    captured, do_injection = [], controller.do_injection
    controller.do_injection = lambda found, *args: captured.extend(found)
    try:
      with contextlib.redirect_stdout(io.StringIO()):
        controller.post_request("http://t/", "POST", None, 0)
    finally:
      controller.do_injection = do_injection
    return [_ for _ in captured if settings.INJECT_TAG in _]

  def test_a_value_keeps_its_spaces(self):
    sent = self._sent("q=hello world&b=2")
    self.assertEqual(2, len(sent))
    for candidate in sent:
      self.assertIn("q=hello world", candidate)

  def test_a_name_keeps_its_space_and_is_reported_with_it(self):
    sent = self._sent("my field=1&b=2")
    self.assertIn("my field=1" + settings.INJECT_TAG, sent[0])
    self.assertEqual("my field", parameters.vuln_POST_param(sent[0], "http://t/"))

  def test_a_named_graphql_operation_is_left_valid(self):
    sent = self._sent('query GetUser { user(name: "x") { id } }')
    self.assertTrue(sent)
    self.assertTrue(all(_.startswith("query GetUser { user(") for _ in sent))

  def test_a_name_after_a_delimiters_space_is_read_without_it(self):
    sent = self._sent("a=1& b=2")
    self.assertIn("& b=2" + settings.INJECT_TAG, sent[1])
    self.assertEqual("b", parameters.vuln_POST_param(sent[1], "http://t/"))
    self.assertEqual("2", settings.TESTABLE_VALUE)

class ANestedJsonFieldIsHeldToTheSameRules(unittest.TestCase):
  """
  A field inside a nested JSON object is a parameter like any other: where the user marked one, it
  alone is tested, with the payload where the mark stood; one named like a token or session state is
  set aside, without taking its neighbours with it; and each field is tested once.
  """
  def setUp(self):
    import copy
    self._settings = dict((name, copy.deepcopy(value)) for name, value in vars(settings).items()
                          if name.isupper() and isinstance(value, (str, int, float, bool, type(None), list, dict, set, tuple)))
    self._options = dict((name, getattr(menu.options, name)) for name in ("batch", "skip_empty", "data", "test_parameter"))
    menu.options.batch, menu.options.skip_empty, menu.options.test_parameter = True, False, None
    settings.TESTABLE_PARAMETERS_LIST, settings.RANDOMIZE_PARAMETERS_LIST = [], []

  def tearDown(self):
    for name, value in self._options.items():
      setattr(menu.options, name, value)
    for name, value in self._settings.items():
      setattr(settings, name, value)

  def _tested(self, body, marked=False):
    import io, contextlib
    settings.CUSTOM_INJECTION_MARKER = marked
    body = body.replace("*", settings.ASTERISK_MARKER)
    settings.USER_DEFINED_POST_DATA = menu.options.data = body
    said = io.StringIO()
    with contextlib.redirect_stdout(said):
      found = parameters.do_POST_check(body, "POST")
      found = [found] if isinstance(found, str) else found
      found = [_ for _ in found if settings.INJECT_TAG in _]
      names = [parameters.vuln_POST_param(_, "http://t/") for _ in found]
    return names, found, [_ for _ in said.getvalue().splitlines() if "Ignoring" in _]

  def test_the_marked_field_alone_is_tested_where_the_mark_stood(self):
    names, found, _ = self._tested('{"a":{"b":"x*","d":"z"},"c":"y"}', marked=True)
    self.assertEqual(["a.b"], names)
    self.assertIn('"b":"x' + settings.INJECT_TAG + '"', found[0])
    self.assertNotIn(settings.ASTERISK_MARKER, found[0])

  def test_each_marked_field_is_a_candidate_of_its_own(self):
    names, found, _ = self._tested('{"a":{"b":"x*","d":"z*"}}', marked=True)
    self.assertEqual(["a.b", "a.d"], names)
    self.assertFalse(any(settings.ASTERISK_MARKER in _ for _ in found))

  def test_a_token_field_is_set_aside_without_its_neighbours(self):
    for body in ('{"a":{"csrf_token":"abc","host":"1"}}', '{"a":{"host":"1","csrf_token":"abc"}}'):
      names, _, said = self._tested(body)
      self.assertEqual(["a.host"], names, body)
      self.assertEqual(1, len(said), body)

  def test_each_field_is_tested_once(self):
    self.assertEqual(["a.x", "a.host", "c"], self._tested('{"a":{"x":"abc","host":"1"},"c":"2"}')[0])

  def test_other_shapes_are_read_as_before(self):
    self.assertEqual(["a", "e.f", "e.g"], self._tested('{"a":"1","e":{"f":"1","g":"2"}}')[0])
    self.assertEqual(["a.x", "a.d.e"], self._tested('{"a":{"x":"1","d":{"e":"1"}}}')[0])
    self.assertEqual(["a[0]", "a[1]", "e"], self._tested('{"a":["p","q"],"e":"y"}')[0])

  def test_a_bracket_inside_a_string_does_not_count_as_depth(self):
    self.assertEqual([0, 2, 1], parameters.json_fragment_depths(['{"a":{"x":"}{\\""', ' "y":"]"}', ' "c":"2"}']))

  def test_only_marked_leaves_come_back_from_a_nested_object(self):
    settings.CUSTOM_INJECTION_MARKER = True
    body = '{"a":{"b":"x' + settings.ASTERISK_MARKER + '","d":"z"}}'
    self.assertEqual(['{"a":{"b":"x' + settings.INJECT_TAG + '","d":"z"}}'], parameters.json_nested_leaf_candidates('{"a":{"b":"x' + settings.ASTERISK_MARKER + '"', body))

  def test_a_mark_inside_a_value_takes_the_payload_there(self):
    names, found, _ = self._tested('{"a":{"b":"x*y"},"c":"z"}', marked=True)
    self.assertIn('"b":"x' + settings.INJECT_TAG + 'y"', found[0])

  def test_no_field_is_tested_twice(self):
    names = self._tested('{"a":{"k":"1"},"b":{"k":"1"}}')[0]
    self.assertEqual(len(names), len(set(names)))

class AJsonDocumentIsReadForEveryValue(unittest.TestCase):
  """
  A JSON body is read as the document it is: every member of every object and every element of every
  array is a parameter of its own, an empty one included, named by its path; a comma inside a string
  belongs to that string, so the value is sent as it was written; and a body that already is JSON is
  never rewritten on its way in.
  """
  def setUp(self):
    import copy
    self._settings = dict((name, copy.deepcopy(value)) for name, value in vars(settings).items()
                          if name.isupper() and isinstance(value, (str, int, float, bool, type(None), list, dict, set, tuple)))
    self._options = dict((name, getattr(menu.options, name)) for name in ("batch", "skip_empty", "data", "test_parameter"))
    menu.options.batch, menu.options.skip_empty, menu.options.test_parameter = True, False, None
    settings.TESTABLE_PARAMETERS_LIST, settings.RANDOMIZE_PARAMETERS_LIST = [], []

  def tearDown(self):
    for name, value in self._options.items():
      setattr(menu.options, name, value)
    for name, value in self._settings.items():
      setattr(settings, name, value)

  def _tested(self, body, marked=False):
    import io, contextlib
    from src.core.controller import checks
    settings.CUSTOM_INJECTION_MARKER = marked
    body = body.replace("*", settings.ASTERISK_MARKER)
    settings.USER_DEFINED_POST_DATA = menu.options.data = body
    names, sent = [], {}
    with contextlib.redirect_stdout(io.StringIO()):
      found = parameters.do_POST_check(body, "POST")
      for candidate in ([found] if isinstance(found, str) else found):
        if settings.INJECT_TAG not in candidate:
          continue
        name = parameters.vuln_POST_param(candidate, "http://t/")
        names.append(name)
        if settings.IS_JSON:
          sent[name] = checks.json_data(checks.process_injectable_value(checks.escape_json_value("PAYLOAD"), candidate))
    return names, sent

  def test_every_element_of_an_array_is_a_parameter(self):
    self.assertEqual(["a[0]", "a[1]", "e"], self._tested('{"a":["p","q"],"e":"y"}')[0])
    self.assertEqual(["l[0].k", "l[0].m", "z"], self._tested('{"l":[{"k":"1","m":"2"}],"z":"3"}')[0])

  def test_a_top_level_array_is_named_by_its_index(self):
    names, sent = self._tested('[{"addr":"1"},{"addr":"2"}]')
    self.assertEqual(["[0].addr", "[1].addr"], names)
    self.assertEqual('[{"addr":"1"},{"addr":"PAYLOAD"}]', sent["[1].addr"])

  def test_a_marker_in_an_array_marks_that_element_alone(self):
    names, sent = self._tested('{"a":["x","y*"],"b":"z"}', marked=True)
    self.assertEqual(["a[1]"], names)
    self.assertNotIn(settings.ASTERISK_MARKER, sent["a[1]"])

  def test_an_empty_value_is_tested_unless_asked_not_to(self):
    self.assertEqual(["x", "y"], self._tested('{"x":"","y":"1"}')[0])
    menu.options.skip_empty = True
    self.assertEqual(["y"], self._tested('{"x":"","y":"1"}')[0])

  def test_a_comma_in_a_string_is_part_of_the_value_and_not_of_the_layout(self):
    names, sent = self._tested('{"a":"x","b":"Smith, Jane"}')
    self.assertEqual(["a", "b"], names)
    self.assertEqual('{"a":"PAYLOAD","b":"Smith, Jane"}', sent["a"])

  def test_a_body_that_is_json_is_not_rewritten_on_the_way_in(self):
    body = '{"a":"x","b":"Smith, Jane"}'
    self.assertEqual(body, parameters.configure_post_data_format(body, "POST"))

  def test_a_single_quoted_body_is_still_read(self):
    self.assertEqual(["a"], self._tested("{'a':'x'}")[0])

  def test_a_value_holding_escaped_quotes_is_tested(self):
    self.assertEqual(["s", "t"], self._tested('{"s":"say \\"hi\\"","t":"1"}')[0])

  def test_a_graphql_document_in_a_string_is_tested_at_its_argument(self):
    names, sent = self._tested('{"query":"query { ping(host: \\"127.0.0.1\\") }"}')
    self.assertEqual(["query"], names)
    self.assertIn('127.0.0.1PAYLOAD\\")', sent["query"])

  def test_a_number_is_sent_as_the_string_it_becomes(self):
    self.assertEqual('{"n":"PAYLOAD","s":"1"}', self._tested('{"n":5,"s":"1"}')[1]["n"])

  def test_an_empty_xml_element_is_tested(self):
    self.assertEqual(["a", "b"], self._tested("<r><a></a><b>2</b></r>")[0])
    self.assertEqual(["a", "b"], self._tested("<r><a/><b>2</b></r>")[0])

  def test_every_candidate_carries_the_tag_once(self):
    settings.IS_JSON, settings.CUSTOM_INJECTION_MARKER = True, True
    body = '{"a":["x","y' + settings.ASTERISK_MARKER + '"],"b":"z"}'
    candidates = parameters.json_candidates(body)
    self.assertEqual(1, len(candidates))
    self.assertTrue(all(_.count(settings.INJECT_TAG) == 1 for _ in candidates))

class APathMarkerIsAPlaceOfItsOwn(unittest.TestCase):
  """
  A marker in the path of a URL - where a REST-style address carries its values - is a place to test
  of its own, with or without a query beside it: one per marker, named by its place among them, its
  value the segment it sits in. A candidate that carries no tag is never handed on to be tested.
  """
  def setUp(self):
    import copy
    self._settings = dict((name, copy.deepcopy(value)) for name, value in vars(settings).items()
                          if name.isupper() and isinstance(value, (str, int, float, bool, type(None), list, dict, set, tuple)))
    self._options = dict((name, getattr(menu.options, name)) for name in ("batch", "skip_empty", "shellshock", "test_parameter", "tamper", "skip_urlencode"))
    menu.options.batch, menu.options.skip_empty, menu.options.shellshock, menu.options.test_parameter = True, False, False, None
    settings.TESTABLE_PARAMETERS_LIST, settings.CUSTOM_INJECTION_MARKER_PARAMETERS_LIST = [], []
    settings.USER_DEFINED_POST_DATA, settings.SKIP_NON_CUSTOM_PARAMS, settings.PATH_INJECTION_POINTS = None, None, {}

  def tearDown(self):
    for name, value in self._options.items():
      setattr(menu.options, name, value)
    for name, value in self._settings.items():
      setattr(settings, name, value)

  def _tested(self, address, marked=None):
    import io, contextlib
    settings.CUSTOM_INJECTION_MARKER = "*" in address if marked is None else marked
    with contextlib.redirect_stdout(io.StringIO()):
      found = parameters.do_GET_check("http://t/api/" + address, "GET")
    if found is False:
      return False
    tested = []
    for candidate in found:
      name = parameters.vuln_GET_param(candidate)
      tested.append((name, settings.TESTABLE_VALUE, candidate.replace("http://t/api/", "").replace(settings.INJECT_TAG, "<T>")))
    return tested

  def test_a_marker_in_a_path_without_a_query_is_tested(self):
    self.assertEqual([("#1", "127.0.0.1", "127.0.0.1<T>")], self._tested("127.0.0.1*"))
    self.assertEqual([("#1", "", "do/cmd/<T>")], self._tested("do/cmd/*"))

  def test_a_marker_in_the_path_is_tested_beside_a_query_that_carries_none(self):
    self.assertEqual([("#1", "127.0.0.1", "127.0.0.1<T>?a=1")], self._tested("127.0.0.1*?a=1"))

  def test_a_marker_in_the_path_and_one_in_the_query_are_two_places(self):
    self.assertEqual([("#1", "127.0.0.1", "127.0.0.1<T>?a=1"), ("a", "1", "127.0.0.1?a=1<T>")], self._tested("127.0.0.1*?a=1*"))

  def test_every_marker_in_a_path_is_a_place_named_by_its_order(self):
    self.assertEqual([("#1", "1", "x/1<T>/y/2"), ("#2", "2", "x/1/y/2<T>")], self._tested("x/1*/y/2*"))
    self.assertEqual([("#1", "7", "x/7<T>/y")], self._tested("x/7*/y"))

  def test_the_tag_written_out_in_the_path_is_tested_where_it_is(self):
    self.assertEqual([("#1", "127.0.0.1", "127.0.0.1<T>")], self._tested("127.0.0.1" + settings.INJECT_TAG))
    self.assertEqual([("#1", "", "<T>?a=1"), ("a", "1", "?a=1<T>")], self._tested(settings.INJECT_TAG + "?a=1"))

  def test_a_query_without_a_value_does_not_end_a_marked_path(self):
    self.assertEqual([("#1", "", "<T>?debug")], self._tested("*?debug"))

  def test_a_path_marker_tested_in_its_own_pass_leaves_nothing_else_behind(self):
    self.assertIs(False, self._tested("127.0.0.1*", marked=False))
    self.assertEqual([("a", "1", "127.0.0.1?a=1<T>")], self._tested("127.0.0.1*?a=1", marked=False))

  def test_a_query_is_tested_as_before(self):
    self.assertEqual([("a", "1", "x?a=1<T>&b=2"), ("b", "2", "x?a=1&b=2<T>")], self._tested("x?a=1&b=2"))
    self.assertEqual([("a", "1", "x?a=1<T>&b=2")], self._tested("x?a=1*&b=2"))
    self.assertEqual([("a", "1", "x?a=1<T>")], self._tested("x?a=1*"))
    # Tested in its own pass, the marked value is not handed on again without a tag.
    self.assertEqual([], self._tested("x?a=1*", marked=False))

  def test_a_payload_in_the_path_carries_no_stray_per_cent_sign_whatever_the_tampers(self):
    from src.core.controller import checks
    menu.options.tamper, menu.options.skip_urlencode = "space2ifs", False
    path, query = "http://t/api/127.0.0.1" + settings.INJECT_TAG, "http://t/api?a=1" + settings.INJECT_TAG
    self.assertEqual("printf%20%25s%09x", checks.encode_payload("printf %s%09x", path))
    # Where the server does not decode the payload itself, a tamper's own '%' is still left as written.
    self.assertEqual("printf%20%s%09x", checks.encode_payload("printf %s%09x", query))
    self.assertEqual("printf%20%s%09x", checks.encode_payload("printf %s%09x"))
    menu.options.tamper = None
    self.assertEqual("printf%20%25s", checks.encode_payload("printf %s", query))
