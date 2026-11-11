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

from tests._testutils import stage
from src.utils import settings
from src.core.controller import checks
from src.core.parse import cmdline as menu

class CurrentBoundary(unittest.TestCase):
  """
  What a rewrite reads back about the boundary the parameter at hand was proved on.
  """
  def test_whitespace_falls_back_to_a_plain_space(self):
    settings.WHITESPACES = []
    self.assertEqual(settings.SINGLE_WHITESPACE, checks.current_whitespace())
    settings.WHITESPACES = ["\t"]
    self.assertEqual("\t", checks.current_whitespace())

  def test_separator_is_none_until_a_boundary_is_recorded(self):
    settings.CONFIRMED_BOUNDARY = {}
    settings.CHECKING_PARAMETER = "P"
    self.assertIsNone(checks.current_separator())

  def test_separator_comes_back_from_the_recorded_boundary(self):
    for separator in (";", "&", "&&", "|", settings.END_LINE.LF):
      stage(separator)
      self.assertEqual(separator, checks.current_separator())

  def test_a_parameter_does_not_read_another_ones_boundary(self):
    stage(";")
    settings.CHECKING_PARAMETER = "OTHER"
    self.assertIsNone(checks.current_separator())

class AwkProgram(unittest.TestCase):
  """
  The program handed to awk, whose own statements are separated by the one under test.
  """
  def test_only_a_statement_separator_awk_reads_is_usable(self):
    self.assertTrue(checks.awk_separator_usable(";"))
    self.assertTrue(checks.awk_separator_usable(settings.END_LINE.LF))
    for separator in ("&", "&&", "|", "", None):
      self.assertFalse(checks.awk_separator_usable(separator), repr(separator) + " was taken as usable")

  def test_the_program_carries_nothing_but_its_own_separator(self):
    for separator in (";", settings.END_LINE.LF):
      program = checks.awk_reverse_program(separator)
      for smuggled in ("|", "&"):
        self.assertNotIn(smuggled, program)
      if separator != ";":
        self.assertNotIn(";", program)

  def test_the_program_has_no_space_inside_its_quotes(self):
    # A space there is the whitespace substitution's to replace, which awk would then read as text.
    for separator in (";", settings.END_LINE.LF):
      for fold in (False, True):
        program = checks.awk_reverse_program(separator, fold=fold)
        self.assertNotIn(settings.SINGLE_WHITESPACE, program.strip("'"))

  def test_the_fold_is_asked_for_explicitly(self):
    self.assertIn("tolower", checks.awk_reverse_program(";", fold=True))
    self.assertNotIn("tolower", checks.awk_reverse_program(";"))

class SmallDecisions(unittest.TestCase):
  """
  Helpers a run leans on in passing. None of them reaches the network, and each one decides
  something a later line reads back as fact.
  """
  def test_a_port_is_a_number_inside_the_range(self):
    for port in ("1", "80", "8080", "65535"):
      self.assertTrue(checks._validate_port(port), port)
    for port in ("0", "65536", "-1", "", "abc", "80.5"):
      self.assertFalse(checks._validate_port(port), port)

  def test_a_uid_is_classified_by_the_range_it_falls_in(self):
    self.assertEqual("root user", checks.classify_uid("0"))
    for uid in ("1", "98"):
      self.assertEqual("system user", checks.classify_uid(uid), uid)
    for uid in ("100", "500", "1000"):
      self.assertEqual("regular user", checks.classify_uid(uid), uid)
    for uid in ("99", "60001", "65534"):
      self.assertEqual("anonymous user", checks.classify_uid(uid), uid)
    self.assertEqual("non-trusted user", checks.classify_uid("60002"))

  def test_a_uid_past_the_last_range_is_not_classified(self):
    self.assertEqual("", checks.classify_uid("65535"))

  def test_a_uid_that_is_not_a_number_is_refused(self):
    # Read off the target's own output, so it is not trusted to be a number.
    self.assertRaises(ValueError, checks.classify_uid, "nobody")

  def test_a_command_is_wrapped_so_its_output_comes_back(self):
    was = (settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX)
    try:
      settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX = "$(", ")"
      wrapped = checks.add_command_substitution("id")
      self.assertIn("id", wrapped)
      self.assertIn(settings.CMD_SUB_PREFIX, wrapped)
    finally:
      settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX = was

class TamperDependencies(unittest.TestCase):
  """
  Why a script cannot be applied to the target at hand, or nothing where it can.
  """
  def test_a_shell_gate_answers_for_the_settled_operating_system(self):
    settings.TARGET_OS = settings.OS.UNIX
    self.assertIsNone(checks.tamper_dep_unix_only("x"))
    self.assertIsNotNone(checks.tamper_dep_windows_only("x"))
    settings.TARGET_OS = settings.OS.WINDOWS
    self.assertIsNotNone(checks.tamper_dep_unix_only("x"))
    self.assertIsNone(checks.tamper_dep_windows_only("x"))

  def test_a_sink_gate_reads_the_heuristic_as_well_as_the_switch(self):
    eval_sink, eval_state = menu.options.eval_sink, settings.EVAL_BASED_STATE
    try:
      menu.options.eval_sink, settings.EVAL_BASED_STATE = None, False
      self.assertIsNotNone(checks.tamper_dep_command_incompatible("x"))
      self.assertIsNone(checks.tamper_dep_eval_incompatible("x"))
      # The heuristic probe carries eval syntax before '--eval' is ever set.
      menu.options.eval_sink, settings.EVAL_BASED_STATE = None, True
      self.assertIsNone(checks.tamper_dep_command_incompatible("x"))
      self.assertIsNotNone(checks.tamper_dep_eval_incompatible("x"))
    finally:
      menu.options.eval_sink, settings.EVAL_BASED_STATE = eval_sink, eval_state

class BooleanOracleNoise(unittest.TestCase):
  """
  What the page moves on its own, weighed against what the question answered.
  """
  def setUp(self):
    self.markings = settings.DYNAMIC_MARKINGS
    settings.DYNAMIC_MARKINGS = []

  def tearDown(self):
    settings.DYNAMIC_MARKINGS = self.markings

  # The same page, twice, with only the command's own timing moving between them.
  def page(self, timing):
    return ("<html><body><p>the command was asked and answered here</p>"
            "<b>rtt min/avg/max/mdev = " + timing + " ms</b>"
            "<p>and the rest of this page stands perfectly still</p></body></html>")

  def test_two_answers_that_read_alike_are_not_an_answer(self):
    # Nothing told them apart, so there is no question this boundary answered.
    page = self.page("0.015/0.048/0.073/0.022")
    self.assertFalse(checks.calibrate_boolean_oracle(page, page))

  def test_a_shell_error_quoting_this_runs_own_digits_is_not_an_answer(self):
    """
    A filter that corrupts the payload before a shell sees it leaves the marker's own length sitting
    in the error the shell quotes it back in, which tells two pages apart without either command
    having run.
    """
    error = "sh: 1: AAAAAA%s: not found"
    self.assertFalse(checks.calibrate_boolean_oracle(error % "123456", error % "1234567"))

  def test_a_difference_that_moves_on_its_own_is_not_an_answer(self):
    """
    Two answers that are meant to differ, differing only where two answers that are meant to match
    already did. Taken for an answer, a boundary is confirmed on the strength of a timing.
    """
    true_page, false_page = self.page("0.015/0.048/0.073/0.022"), self.page("0.042/0.058/0.065/0.009")
    # Nothing learned about the page yet, so the timing reads as the two answers differing.
    self.assertTrue(checks.calibrate_boolean_oracle(true_page, false_page))
    # The same question asked twice is what says which part of it was never an answer.
    checks.find_dynamic_content(true_page, self.page("0.031/0.052/0.061/0.011"))
    self.assertTrue(settings.DYNAMIC_MARKINGS)
    self.assertFalse(checks.calibrate_boolean_oracle(true_page, false_page))

class ReAskedTechniques(unittest.TestCase):
  """
  Which findings are asked their question a second time before the parameter is reported.
  """
  def test_a_finding_weighed_as_a_page_is_re_asked(self):
    """
    The tempfile-based technique reads its tag back with a command of its own and weighs the answer
    as a page - the file is written where the web root could not be reached, so there is no URL to
    fetch it through. That is the same kind of evidence the other two rest on, and a page that moves
    on its own produces it without the command having run, so it is not exempt from the re-ask.
    """
    for technique in (settings.INJECTION_TECHNIQUE.BOOLEAN_BASED,
                      settings.INJECTION_TECHNIQUE.TIME_BASED,
                      settings.INJECTION_TECHNIQUE.TEMP_FILE_BASED):
      self.assertIn(technique, checks._INFERRED_TECHNIQUES)

  def test_a_finding_that_came_back_on_its_own_is_not(self):
    # A tag fetched out of the web root, or a hostname only this run knows being resolved, is not
    # something a target produces without having run the command.
    for technique in (settings.INJECTION_TECHNIQUE.RESULTS_BASED,
                      settings.INJECTION_TECHNIQUE.FILE_BASED,
                      settings.INJECTION_TECHNIQUE.OOB):
      self.assertNotIn(technique, checks._INFERRED_TECHNIQUES)

class Lagging(unittest.TestCase):
  """
  When a target's answers are called unsteady enough to raise the delay asked of it.
  """
  def tearDown(self):
    settings.RESPONSE_TIMES[:] = []
    settings.LAGGING_CHECKED = settings.LAGGING_DETECTED = False
    settings.JITTER_SEEN = settings.ADJUST_TIME_DELAY_DISABLED = False

  def verdict(self, pace, spread):
    settings.RESPONSE_TIMES[:] = [pace - spread, pace + spread] * 8
    settings.LAGGING_CHECKED = settings.LAGGING_DETECTED = False
    return checks.check_lagging()

  def test_a_slow_target_that_keeps_its_pace_is_not_lagging(self):
    """
    A sink that runs a command before answering moves by half a second on nothing more than being
    itself. Called laggy for it, the run raises the delay and every probe after pays the wait.
    """
    self.assertFalse(self.verdict(3.1, 0.5))
    self.assertFalse(self.verdict(10.0, 1.5))

  def test_a_slow_steady_target_is_not_offered_up_for_skipping(self):
    """
    The same question the time-based and tempfile-based handlers put before offering to skip the
    technique: a target that answers at the same speed every time is read as easily as a fast one,
    however long that speed is.
    """
    settings.RESPONSE_TIMES[:] = [10.0 - 1.5, 10.0 + 1.5] * 8
    self.assertFalse(checks.response_times_unsteady())
    settings.RESPONSE_TIMES[:] = [3.1 - 0.5, 3.1 + 0.5] * 8
    self.assertFalse(checks.response_times_unsteady())

  def test_answers_that_really_do_move_are_offered_up(self):
    settings.RESPONSE_TIMES[:] = [10.0 - 4.0, 10.0 + 4.0] * 8
    self.assertTrue(checks.response_times_unsteady())
    settings.RESPONSE_TIMES[:] = [0.8 - 0.6, 0.8 + 0.6] * 8
    self.assertTrue(checks.response_times_unsteady())

  def test_answers_that_move_against_their_own_pace_still_are(self):
    # Read in seconds of its own as well, so a page answering at once is not called steady for
    # moving by less than a slow one does.
    self.assertTrue(self.verdict(3.1, 1.2))
    self.assertTrue(self.verdict(0.1, 0.6))

class ProbeModel(unittest.TestCase):
  """
  Which timings are believed to be what a probe costs.
  """
  def setUp(self):
    self.disable_stats = menu.options.disable_stats
    menu.options.disable_stats = False
    # A sink that runs a command before answering, behind a filter that rejects the payload at once.
    settings.RESPONSE_TIMES[:] = [3.10, 3.12, 3.11, 3.13, 3.10, 3.12, 3.11, 3.12]
    settings.PROBE_RESPONSE_TIMES[:] = []

  def tearDown(self):
    menu.options.disable_stats = self.disable_stats
    settings.RESPONSE_TIMES[:] = []
    settings.PROBE_RESPONSE_TIMES[:] = []

  def test_an_answer_the_payload_never_reached_the_sink_for_is_not_a_probe(self):
    """
    A model built on what a refusal costs reads an ordinary answer as a delay, which raises the
    delay asked for and makes every probe after it wait longer for nothing.
    """
    for _ in range(13):
      checks.record_probe_response_time(0.01)
    self.assertEqual([], settings.PROBE_RESPONSE_TIMES)
    self.assertFalse(checks.time_related_shell(3.13, 10))
    self.assertTrue(checks.time_related_shell(13.1, 10))

  def test_a_probe_that_did_reach_it_still_counts(self):
    for exec_time in (3.15, 3.18, 3.14, 3.16, 3.17):
      checks.record_probe_response_time(exec_time)
    self.assertEqual(5, len(settings.PROBE_RESPONSE_TIMES))

class CarriedEncoding(unittest.TestCase):
  """
  How a value written in an encoding is read back off the request it rode in.
  """
  def test_padding_is_read_as_padding_however_the_url_spells_it(self):
    """
    A query string writes '=' as '%3D', so a descriptor worked out from the raw spelling reads a
    padded value as carrying no padding - and writing it back out then drops the padding, leaving
    the value not matching what arrived, so a parameter that carries base64 is refused for not.
    """
    for value in ("Z3Vlc3Q=", "YWJj", "YQ=="):
      described = checks.encoding_from_name("base64", value)
      self.assertEqual(value, checks.apply_encoding(checks.strip_encoding(value, described), described),
                       "the value " + repr(value) + " did not survive being read and written back")

class DigitValues(unittest.TestCase):
  """
  Which values are read as a number, since that is what decides the boundaries tried first.
  """
  def test_only_the_digits_a_shell_would_read_as_one(self):
    """
    'str.isdigit()' answers for every character Unicode calls a digit - a superscript two among
    them - so a value no shell would take for a number was read as one, and the boundaries a quoted
    value needs were ordered last on the strength of it.
    """
    for value in ("0", "4", "0042", "123456"):
      self.assertTrue(checks.is_digit(value), value + " is written out of digits")
    for value in (u"\xb2", u"\u0660", "3b3", "127.0.0.1", "-5", "1.5", "", " 4"):
      self.assertFalse(checks.is_digit(value), repr(value) + " is not")

class SinkBoundaries(unittest.TestCase):
  """
  Which boundaries are worth asking of the shell in hand.
  """
  def setUp(self):
    self.target_os = settings.TARGET_OS
    self.eval_sink = menu.options.eval_sink
    menu.options.eval_sink = None
    settings.apply_injection_level(settings.HTTP_HEADER_INJECTION_LEVEL)

  def tearDown(self):
    settings.TARGET_OS = self.target_os
    menu.options.eval_sink = self.eval_sink
    settings.apply_injection_level(settings.DEFAULT_INJECTION_LEVEL)

  def commented(self):
    _, suffixes, _ = checks.sink_boundaries()
    return [candidate for candidate in suffixes if candidate.strip() == settings.COMMENT]

  def test_a_shell_with_a_comment_is_offered_one(self):
    settings.TARGET_OS = settings.OS.UNIX
    self.assertTrue(self.commented())

  def test_a_shell_without_one_is_not(self):
    """
    'cmd.exe' has no comment a trailing marker can use, so a POSIX '#' asked of it is a boundary it
    cannot honour - sent once per separator, on every parameter tested.
    """
    settings.TARGET_OS = settings.OS.WINDOWS
    self.assertEqual([], self.commented())

class DelayThreshold(unittest.TestCase):
  """
  How late an answer has to be before it counts as a delay that was asked for.
  """
  def setUp(self):
    self.disable_stats = menu.options.disable_stats
    menu.options.disable_stats = False
    settings.PROBE_RESPONSE_TIMES[:] = []

  def tearDown(self):
    menu.options.disable_stats = self.disable_stats
    settings.RESPONSE_TIMES[:] = []
    settings.PROBE_RESPONSE_TIMES[:] = []

  # A steady target around the given pace, varying by a hundredth of a second either way.
  def steady_at(self, mean):
    settings.RESPONSE_TIMES[:] = [mean + (0.01 if index % 2 else -0.01) for index in range(8)]

  def test_a_delay_that_fires_is_seen_however_slow_the_target_is(self):
    for mean in (3.0, 6.0, 11.0, 20.0, 40.0):
      self.steady_at(mean)
      timesec = 5
      self.assertTrue(checks.time_related_shell(mean + timesec, timesec),
                      "a delay of " + str(timesec) + "s was missed on a target answering in " + str(mean) + "s")

  def test_an_ordinary_answer_is_not_read_as_a_delay(self):
    for mean in (3.0, 6.0, 11.0, 20.0, 40.0):
      self.steady_at(mean)
      self.assertFalse(checks.time_related_shell(mean, 5),
                       "a plain answer of " + str(mean) + "s was read as delayed")

  def test_the_margin_is_not_raised_past_the_delay_being_asked_for(self):
    self.steady_at(20.0)
    # Half of the delay asked for, where half the target's own pace would stand well above it.
    self.assertAlmostEqual(22.5, checks.current_delay_threshold(5), places=2)
    # Nothing to measure it against leaves the margin read off the target alone.
    self.assertAlmostEqual(30.0, checks.current_delay_threshold(), places=2)


class SkippedValueIsAccountedFor(unittest.TestCase):
  """
  What the summary says where the parameter's own value was dropped from later requests.
  """
  def setUp(self):
    self._flag = settings.TESTABLE_VALUE_OPTIMIZED
    self._value = settings.TESTABLE_VALUE
    self._points = settings.CONFIRMED_INJECTION_POINTS
    self._out = settings.print_data_to_stdout
    self.printed = []
    settings.print_data_to_stdout = lambda line: self.printed.append(line)

  def tearDown(self):
    settings.TESTABLE_VALUE_OPTIMIZED = self._flag
    settings.TESTABLE_VALUE = self._value
    settings.CONFIRMED_INJECTION_POINTS = self._points
    settings.print_data_to_stdout = self._out

  def summarise(self, optimized, value):
    settings.TESTABLE_VALUE_OPTIMIZED = optimized
    settings.TESTABLE_VALUE = value
    settings.CONFIRMED_INJECTION_POINTS = [
      ("File-based", "Blind command injection", "addr", "JGX;echo T >/var/www/html/T.txt;", "GET", 63)
    ]
    original = checks.target_fingerprint_summary
    checks.target_fingerprint_summary = lambda: None
    try:
      checks.confirmed_injection_points_summary()
    finally:
      checks.target_fingerprint_summary = original
    return "\n".join(str(line) for line in self.printed)

  def test_the_stand_in_value_is_named(self):
    output = self.summarise(True, "JGX")
    self.assertIn("was not required", output)
    self.assertIn("'JGX'", output)

  def test_nothing_is_said_where_the_real_value_was_used(self):
    self.assertNotIn("was not required", self.summarise(False, "127.0.0.1"))

  def test_nothing_is_said_where_there_is_no_value_to_name(self):
    self.assertNotIn("was not required", self.summarise(True, ""))

class EscapesInAnOptionValue(unittest.TestCase):
  """
  A value given as an escape, where the shell would have eaten the character itself.
  """
  def test_a_whitespace_escape_becomes_the_character(self):
    self.assertEqual("\n", checks.decode_string_escape("\\n"))
    self.assertEqual("\t", checks.decode_string_escape("\\t"))
    self.assertEqual("\r", checks.decode_string_escape("\\r"))

  def test_it_is_decoded_in_place(self):
    self.assertEqual("a\tb", checks.decode_string_escape("a\\tb"))

  def test_an_escaped_backslash_shields_what_follows(self):
    # Two passes would read this as a newline; one pass leaves the text it stands for.
    self.assertEqual("\\n", checks.decode_string_escape("\\\\n"))

  def test_a_value_with_no_escape_is_handed_back_as_it_is(self):
    for value in ("&", ";", "plain", "", None):
      self.assertEqual(value, checks.decode_string_escape(value))

  def test_a_non_ascii_byte_is_not_an_escape(self):
    self.assertEqual("\u00a7", checks.decode_string_escape("\u00a7"))

class ReflectionsTheTargetRewrote(unittest.TestCase):
  """
  Taking the payload back out of a page that did not hand it back verbatim.
  """
  PAYLOAD = "127.0.0.1;echo ABCDEF"

  def setUp(self):
    self._found = settings.REFLECTIVE_VALUE_FOUND
    self._out = settings.print_data_to_stdout
    settings.print_data_to_stdout = lambda *a, **k: None

  def tearDown(self):
    settings.REFLECTIVE_VALUE_FOUND = self._found
    settings.print_data_to_stdout = self._out

  def filtered(self, page, payload=None):
    settings.REFLECTIVE_VALUE_FOUND = False
    return checks.remove_reflected_values(page, payload or self.PAYLOAD)

  def test_the_payload_as_it_went_out(self):
    self.assertIn(settings.REFLECTED_VALUE_MARKER, self.filtered("a <b>127.0.0.1;echo ABCDEF</b> z"))

  def test_a_space_that_came_back_as_a_plus(self):
    self.assertIn(settings.REFLECTED_VALUE_MARKER, self.filtered("a <b>127.0.0.1;echo+ABCDEF</b> z"))

  def test_a_command_the_target_upper_cased(self):
    self.assertIn(settings.REFLECTED_VALUE_MARKER, self.filtered("a <b>127.0.0.1;ECHO ABCDEF</b> z"))

  def test_a_space_of_another_width(self):
    self.assertIn(settings.REFLECTED_VALUE_MARKER, self.filtered("a <b>127.0.0.1;echo\xa0ABCDEF</b> z"))

  def test_runs_scattered_through_unrelated_text_are_left_alone(self):
    # The payload's own runs are words a page says for itself - the value sent back, 'echo', a tag.
    page = "host 127.0.0.1 is up. " + "x" * 60 + " please echo this. " + "y" * 40 + " ABCDEF is the code."
    self.assertEqual(page, self.filtered(page))

  def test_a_page_without_the_payload_is_untouched(self):
    page = "nothing of the sort here"
    self.assertEqual(page, self.filtered(page))

  def test_a_payload_of_punctuation_alone_builds_no_pattern(self):
    # An open pattern with no run to anchor it would match at every position of every page.
    self.assertIsNone(checks.reflection_pattern(";|&"))
    page = "a perfectly ordinary page"
    self.assertEqual(page, self.filtered(page, ";|&"))

  def test_the_marker_is_the_same_length_whatever_the_payload(self):
    short = self.filtered("x 127.0.0.1;echo ABCDEF y")
    long_payload = "127.0.0.1;echo ABCDEFGHIJKLMNOP"
    longer = self.filtered("x " + long_payload + " y", long_payload)
    self.assertEqual(len(short), len(longer))

class DocumentRootFromALeakedPath(unittest.TestCase):
  """
  Cutting a root out of an absolute path the target printed about itself.
  """
  def root(self, body, url):
    class _Response(object):
      def read(self):
        return body.encode()
    original = checks.get_response, checks.decode_page_body
    checks.get_response = lambda _url: _Response()
    checks.decode_page_body = lambda raw, response: raw.decode()
    try:
      return checks.web_root_from_leaked_path(url)
    finally:
      checks.get_response, checks.decode_page_body = original

  def test_a_generic_name_is_what_it_is_cut_at(self):
    # Cut at "/www/", which is one of those names itself - not at the deeper "/html/", which is not.
    self.assertEqual("/var/www/",
                     self.root("Warning: in /var/www/html/a/b.php on line 2", "http://t/a/b.php"))

  def test_the_first_generic_name_in_the_list_wins(self):
    self.assertEqual("/srv/htdocs/",
                     self.root("Warning: /srv/htdocs/app/b.php", "http://t/app/b.php"))

  def test_the_host_names_its_own_root(self):
    self.assertEqual("/srv/t.example/",
                     self.root("Warning: /srv/t.example/a/b.php", "http://t.example/a/b.php"))

  def test_the_url_path_cuts_one_with_no_generic_name_in_it(self):
    self.assertEqual("/opt/app/current/",
                     self.root("Warning: /opt/app/current/scenarios/GET/classic.php on line 2",
                               "http://t/scenarios/GET/classic.php"))

  def test_a_windows_path_keeps_its_drive_and_separators(self):
    self.assertEqual("C:\\inetpub\\wwwroot\\",
                     self.root("Warning: C:\\inetpub\\wwwroot\\a\\b.php on line 2", "http://t/a/b.php"))

  def test_nothing_resembling_a_path_gives_nothing(self):
    self.assertIsNone(self.root("<html>no paths here</html>", "http://t/a/b.php"))

  def test_a_path_that_does_not_end_where_the_url_does_is_left_alone(self):
    # "/a" sits in the middle of it, which says nothing about where the root is.
    self.assertIsNone(self.root("Warning: /opt/a/deeper/elsewhere.php", "http://t/a/b.php"))

  def test_a_url_path_filling_the_whole_leaked_path_cuts_to_nothing(self):
    self.assertIsNone(self.root("Warning: /a/b.php on line 2", "http://t/a/b.php"))

class DocumentRootFromTheTarget(unittest.TestCase):
  """
  Working the document root back from the directory the script says it runs in.
  """
  def setUp(self):
    self._os = settings.TARGET_OS
    self._probe = settings.WEB_ROOT_PROBE

  def tearDown(self):
    settings.TARGET_OS = self._os
    settings.WEB_ROOT_PROBE = self._probe

  def arm(self, answer):
    settings.WEB_ROOT_PROBE = lambda cmd: answer

  def test_the_url_depth_comes_off_the_end(self):
    self.arm("/var/www/commix-testbed.com/public_html/scenarios/regular/GET")
    self.assertEqual("/var/www/commix-testbed.com/public_html/",
                     checks.web_root_from_target_cwd("http://t/scenarios/regular/GET/classic.php?addr=1"))

  def test_a_script_in_the_root_itself_leaves_the_root(self):
    self.arm("/var/www/html")
    self.assertEqual("/var/www/html/", checks.web_root_from_target_cwd("http://t/classic.php"))

  def test_a_directory_url_counts_as_its_own_directory(self):
    self.arm("/srv/app/admin")
    self.assertEqual("/srv/app/", checks.web_root_from_target_cwd("http://t/admin/"))

  def test_a_path_the_url_does_not_end_in_is_not_guessed_at(self):
    # An alias or a rewrite - the script is not stored under the path it was reached by, so the
    # depth says nothing about where the root is.
    self.arm("/opt/legacy/cgi")
    self.assertIsNone(checks.web_root_from_target_cwd("http://t/scenarios/regular/GET/classic.php"))

  def test_an_error_instead_of_a_path_is_not_a_root(self):
    for answer in ("sh: 1: pwd: not found", "", None, "   ", "relative/path"):
      self.arm(answer)
      self.assertIsNone(checks.web_root_from_target_cwd("http://t/a/b.php"))

  def test_windows_keeps_its_own_separator(self):
    settings.TARGET_OS = settings.OS.WINDOWS
    self.arm("C:\\AppServ\\www\\scenarios\\regular")
    self.assertEqual("C:\\AppServ\\www\\",
                     checks.web_root_from_target_cwd("http://t/scenarios/regular/classic.php"))

  def test_the_probe_is_spent_once_it_has_been_asked(self):
    # A root that fails is asked about again - the same answer twice over would keep handing back
    # the root that just failed instead of moving on to the candidates.
    self.arm("/var/www/html")
    self.assertEqual("/var/www/html/", checks.web_root_from_target_cwd("http://t/a.php"))
    self.assertIsNone(settings.WEB_ROOT_PROBE)
    self.assertIsNone(checks.web_root_from_target_cwd("http://t/a.php"))

  def test_nothing_is_asked_where_no_technique_armed_it(self):
    settings.WEB_ROOT_PROBE = None
    self.assertIsNone(checks.web_root_from_target_cwd("http://t/a/b.php"))

  def test_a_probe_that_raises_is_not_fatal(self):
    def boom(cmd):
      raise RuntimeError("no channel")
    settings.WEB_ROOT_PROBE = boom
    self.assertIsNone(checks.web_root_from_target_cwd("http://t/a/b.php"))

if __name__ == "__main__":
  unittest.main()

class EmptyTestableValue(unittest.TestCase):
  """
  Where the payload goes when the parameter it is testing arrived with no value at all.
  """
  def setUp(self):
    self.testable_value = settings.TESTABLE_VALUE

  def tearDown(self):
    settings.TESTABLE_VALUE = self.testable_value

  def test_an_empty_value_puts_the_payload_at_the_front(self):
    """
    Stood in for by a single whitespace, an empty value reached the target as the first byte of
    every payload - and a sink reading that byte for itself, an interpreter's own open() handed a
    leading '|', was never once sent the separator it was being tested with.
    """
    settings.TESTABLE_VALUE = ""
    carrier = "page=" + settings.INJECT_TAG
    spliced = checks.process_injectable_value("|echo Hello", carrier)
    self.assertEqual("page=|echo Hello", spliced)
    self.assertEqual("", settings.TESTABLE_VALUE)

  def test_a_value_of_its_own_still_carries_the_payload_behind_it(self):
    settings.TESTABLE_VALUE = "127.0.0.1"
    carrier = "addr=127.0.0.1" + settings.INJECT_TAG
    spliced = checks.process_injectable_value("127.0.0.1;echo Hello", carrier)
    self.assertEqual("addr=127.0.0.1;echo Hello", spliced)
