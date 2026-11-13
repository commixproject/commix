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

import io
import re
import threading
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
    self._verbosity = settings.VERBOSITY_LEVEL
    self._out = settings.print_data_to_stdout
    self.printed = []
    settings.print_data_to_stdout = lambda line: self.printed.append(line)
    settings.VERBOSITY_LEVEL = 1

  def tearDown(self):
    settings.TESTABLE_VALUE_OPTIMIZED = self._flag
    settings.TESTABLE_VALUE = self._value
    settings.CONFIRMED_INJECTION_POINTS = self._points
    settings.VERBOSITY_LEVEL = self._verbosity
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

  def test_it_is_kept_for_a_reader_following_the_run(self):
    # About how the run went rather than about the target, so a default run does not carry it.
    settings.VERBOSITY_LEVEL = 0
    self.assertNotIn("was not required", self.summarise(True, "JGX"))

class PagesComparedByTitleAlone(unittest.TestCase):
  """
  What '--titles' compares, where everything around the title moves by itself.
  """
  def setUp(self):
    self._titles, self._text_only = menu.options.titles, menu.options.text_only
    menu.options.titles, menu.options.text_only = True, False

  def tearDown(self):
    menu.options.titles, menu.options.text_only = self._titles, self._text_only

  def test_the_title_is_what_is_left(self):
    page = "<html><head><title> Results for 1 </title></head><body>counter 4821</body></html>"
    self.assertEqual("Results for 1", checks.comparable_page(page))

  def test_the_tag_is_found_whatever_its_case(self):
    self.assertEqual("No results", checks.page_title("<HTML><TITLE>No results</TITLE>"))

  def test_a_page_with_no_title_compares_as_nothing(self):
    self.assertEqual("", checks.comparable_page("<html>no title here</html>"))

  def test_two_pages_differing_only_below_the_title_read_as_one(self):
    a = "<html><title>Same</title><body>counter 1</body></html>"
    b = "<html><title>Same</title><body>counter 9999</body></html>"
    self.assertEqual(checks.comparable_page(a), checks.comparable_page(b))

  def test_two_pages_differing_in_the_title_do_not(self):
    a = "<html><title>Found</title><body>x</body></html>"
    b = "<html><title>Nothing</title><body>x</body></html>"
    self.assertNotEqual(checks.comparable_page(a), checks.comparable_page(b))

class NullConnectionIsNotAskedWhatItCannotSee(unittest.TestCase):
  """
  A length read off a header cannot answer a question about the body it did not fetch.
  """
  OPTIONS = ("string", "not_string", "regexp", "text_only", "titles")

  def setUp(self):
    from src.core import options as commix_options
    self.commix_options = commix_options
    self._saved = dict((name, getattr(menu.options, name)) for name in self.OPTIONS)
    self._null = menu.options.null_connection
    self._out = settings.print_data_to_stdout
    self.printed = []
    settings.print_data_to_stdout = lambda line: self.printed.append(str(line))

  def tearDown(self):
    for name, value in self._saved.items():
      setattr(menu.options, name, value)
    menu.options.null_connection = self._null
    settings.print_data_to_stdout = self._out

  def test_the_oracle_cannot_answer_a_body_question_without_a_body(self):
    # Why the guard exists: every answer is the same answer, whichever way it is fixed.
    settings.BOOLEAN_TRUE_LENGTH, settings.BOOLEAN_FALSE_LENGTH = 1000, 900
    for name in ("string", "not_string", "regexp"):
      for other in ("string", "not_string", "regexp", "code"):
        setattr(menu.options, other, None)
      setattr(menu.options, name, "root" if name != "regexp" else "ro+t")
      answers = set(checks.boolean_oracle(None, 200, page_length=_) for _ in (1000, 900, 950))
      self.assertEqual(1, len(answers), name + " gave more than one answer without a body")

class ValueSkippedOnlyOnEvidence(unittest.TestCase):
  """
  Dropping the parameter's own value is an optimisation, so it is taken only where the sink answered
  without it - and put back wherever it was taken and nothing was confirmed.
  """
  def setUp(self):
    from src.core.controller import controller
    self.controller = controller
    self._state = (settings.TESTABLE_VALUE, settings.TESTABLE_VALUE_OPTIMIZED,
                   settings.VALUE_SKIPPED_EARLY, settings.VALUE_SKIP_REFUSED, menu.options.data)
    self._request = controller.heuristic_request
    self._out = settings.print_data_to_stdout
    settings.print_data_to_stdout = lambda *a, **k: None
    settings.TESTABLE_VALUE = "127.0.0.1"
    settings.TESTABLE_VALUE_OPTIMIZED = False
    settings.VALUE_SKIPPED_EARLY = None
    settings.VALUE_SKIP_REFUSED = False
    menu.options.data = None

  def tearDown(self):
    (settings.TESTABLE_VALUE, settings.TESTABLE_VALUE_OPTIMIZED, settings.VALUE_SKIPPED_EARLY,
     settings.VALUE_SKIP_REFUSED, menu.options.data) = self._state
    self.controller.heuristic_request = self._request
    settings.print_data_to_stdout = self._out

  def answer(self, with_marker):
    class _Response(object):
      def read(self):
        return b""
    def _request(url, http_request_method, check_parameter, payload, whitespace, place):
      return (_Response() if with_marker else False), url
    self.controller.heuristic_request = _request
    original = checks.process_page_content
    checks.process_page_content = lambda response, action=None: "ok" if not with_marker else "uid=0(root) gid=0(root)"
    try:
      return self.controller.probe_skip_testable_value_early(
        "http://t/a.php?addr=127.0.0.1" + settings.INJECT_TAG, "GET", "addr", ";echo X", " ", None)
    finally:
      checks.process_page_content = original

  def test_a_sink_that_answered_without_it_has_it_dropped(self):
    url = self.answer(with_marker=True)
    self.assertTrue(settings.TESTABLE_VALUE_OPTIMIZED)
    self.assertNotIn("127.0.0.1", url)
    self.assertIsNotNone(settings.VALUE_SKIPPED_EARLY)

  def test_a_sink_that_did_not_answer_keeps_it(self):
    url = self.answer(with_marker=False)
    self.assertFalse(settings.TESTABLE_VALUE_OPTIMIZED)
    self.assertEqual("127.0.0.1", settings.TESTABLE_VALUE)
    self.assertIn("127.0.0.1", url)
    self.assertIsNone(settings.VALUE_SKIPPED_EARLY)

  def test_what_is_put_aside_restores_the_request_as_it_read(self):
    self.answer(with_marker=True)
    original_value, placeholder, original_url, original_data = settings.VALUE_SKIPPED_EARLY
    self.assertEqual("127.0.0.1", original_value)
    self.assertIn("127.0.0.1", original_url)
    self.assertEqual(3, len(placeholder))

  def test_it_is_not_dropped_a_second_time_once_refused(self):
    settings.VALUE_SKIP_REFUSED = True
    url = self.answer(with_marker=True)
    self.assertFalse(settings.TESTABLE_VALUE_OPTIMIZED)
    self.assertIn("127.0.0.1", url)

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

class RegistryAnswersAreReadForWhatTheySay(unittest.TestCase):
  """
  'reg' answers a missing key or value by name, and a refused one by name. An answer that said which
  of the two it was is not reported as either-or - the hedge is for an answer that said neither.
  """
  KEY = "HKLM\\SOFTWARE\\Nope"
  VALUE = "Version"
  NOT_FOUND = "ERROR: The system was unable to find the specified registry key or value."

  def setUp(self):
    self._out = settings.print_data_to_stdout
    self.said = []
    settings.print_data_to_stdout = self.said.append
    self._verbosity = settings.VERBOSITY_LEVEL

  def tearDown(self):
    settings.print_data_to_stdout = self._out
    settings.VERBOSITY_LEVEL = self._verbosity

  def read(self, shell):
    checks.registry_read_status(shell, self.KEY, self.VALUE, "commix.log")
    return settings.strip_ansi_codes("\n".join(str(_) for _ in self.said))

  def delete(self, shell, value=""):
    checks.registry_delete_status(shell, self.KEY, value)
    return settings.strip_ansi_codes("\n".join(str(_) for _ in self.said))

  def test_a_read_the_target_said_was_not_there_is_stated_as_that(self):
    said = self.read(self.NOT_FOUND)
    self.assertIn("The target has no registry key '" + self.KEY + "'", said)
    self.assertNotIn("you do not have permission to read it", said)

  def test_a_read_the_target_refused_is_still_stated_as_that(self):
    self.assertIn("do not have permission to read", self.read("ERROR: Access is denied."))

  def test_an_answer_that_said_neither_keeps_the_hedge(self):
    self.assertIn("This could mean the key/value does not exist", self.read(""))

  def test_the_phrase_is_found_without_the_prefix_the_shell_may_have_dropped(self):
    said = self.read("the system was unable to find the specified registry key or value")
    self.assertIn("The target has no registry key", said)

  def test_a_deletion_of_something_that_was_not_there_is_stated_as_that(self):
    said = self.delete(self.NOT_FOUND, value=self.VALUE)
    self.assertIn("to delete.", said)
    self.assertNotIn("does not appear to have been deleted", said)

class ParameterPollutionStatesOnlyWhatTheBannerSaid(unittest.TestCase):
  """
  Sending the parameter twice only evades anything where the application reads one occurrence and
  the filter another, and which one that is belongs to the platform. Where the banner named one that
  is known to choose, the position is a fact about the target; where it named nothing recognised,
  the position is where the platforms most often tested read it, and is said as the guess it is.
  """
  TARGET = "http://t/a.php?addr="
  PAYLOAD = ";echo TAG;"

  def setUp(self):
    self._state = (settings.SERVER_BANNER, settings.HPP_POSITION_SAID, settings.TESTABLE_VALUE,
                   settings.IS_JSON, settings.IS_XML, settings.IS_GRAPHQL, menu.options.hpp)
    self._out = settings.print_data_to_stdout
    self.said = []
    settings.print_data_to_stdout = self.said.append
    settings.HPP_POSITION_SAID = False
    settings.TESTABLE_VALUE = "127.0.0.1"
    settings.IS_JSON = False
    settings.IS_XML = False
    settings.IS_GRAPHQL = False
    menu.options.hpp = True

  def tearDown(self):
    (settings.SERVER_BANNER, settings.HPP_POSITION_SAID, settings.TESTABLE_VALUE,
     settings.IS_JSON, settings.IS_XML, settings.IS_GRAPHQL, menu.options.hpp) = self._state
    settings.print_data_to_stdout = self._out

  def pollute(self, banner):
    settings.SERVER_BANNER = banner
    polluted = checks.polluted_parameter(self.TARGET + self.PAYLOAD, self.PAYLOAD)
    return polluted, settings.strip_ansi_codes("\n".join(str(_) for _ in self.said))

  def test_a_platform_known_to_read_the_last_one_is_named_as_the_reason(self):
    polluted, said = self.pollute("Apache/2.4.7 (Ubuntu) PHP/5.5.9")
    self.assertTrue(polluted.endswith("addr=" + self.PAYLOAD))
    self.assertIn("with the payload last - which is the one 'Apache/2.4.7 (Ubuntu) PHP/5.5.9' reads.", said)

  def test_a_platform_known_to_read_the_first_one_is_named_as_the_reason(self):
    polluted, said = self.pollute("Jetty(9.4.z-SNAPSHOT)")
    self.assertTrue(polluted.endswith("addr=127.0.0.1"))
    self.assertIn("with the payload first - which is the one 'Jetty(9.4.z-SNAPSHOT)' reads.", said)

  def test_the_platform_decides_over_the_server_carrying_it(self):
    # 'Apache Tomcat' names both lists; the one that is a platform rather than a web server is the
    # one that reads the parameter, so the payload goes where Java reads it.
    polluted, said = self.pollute("Apache Tomcat/9.0.50")
    self.assertTrue(polluted.endswith("addr=127.0.0.1"))
    self.assertIn("with the payload first", said)

  def test_a_banner_naming_nothing_recognised_does_not_claim_the_target_reads_it(self):
    polluted, said = self.pollute("lighttpd/1.4.55")
    self.assertTrue(polluted.endswith("addr=" + self.PAYLOAD))
    self.assertNotIn("which is the one", said)
    self.assertIn("names nothing that says which of the two it chooses", said)

  def test_no_banner_at_all_is_said_to_have_decided_nothing(self):
    polluted, said = self.pollute("")
    self.assertTrue(polluted.endswith("addr=" + self.PAYLOAD))
    self.assertNotIn("which is the one", said)
    self.assertIn("this target named nothing to decide it by", said)

  def test_a_platform_that_joins_the_two_is_told_about_instead(self):
    polluted, said = self.pollute("Microsoft-IIS/8.5")
    self.assertEqual(self.TARGET + self.PAYLOAD, polluted)
    self.assertIn("cannot help here", said)

  def test_a_document_body_is_told_about_the_way_the_other_structured_ones_are(self):
    # A GraphQL document carries no second occurrence any more than JSON or XML does, and saying
    # so is what tells the switch apart from one that was applied and changed nothing.
    settings.IS_GRAPHQL = True
    polluted, said = self.pollute("Apache/2.4.7 (Ubuntu) PHP/5.5.9")
    self.assertEqual(self.TARGET + self.PAYLOAD, polluted)
    self.assertIn("not to a structured body", said)
    self.assertNotIn("Sending 'addr' twice", said)

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

class TheOutOfBandTechniqueIsAskedForOnItsOwn(unittest.TestCase):
  """
  Out-of-band is reached by '--oob' rather than by a letter of '--technique', and the letter it is
  written down as lives in one place, so the switch and what runs it cannot drift apart.
  """
  def setUp(self):
    self._state = (menu.options.oob, menu.options.tech)

  def tearDown(self):
    (menu.options.oob, menu.options.tech) = self._state

  def test_the_letter_is_not_one_the_user_can_name(self):
    self.assertNotIn(settings.OOB_TECHNIQUE_LETTER, settings.AVAILABLE_TECHNIQUES)

  def test_the_letter_is_written_down_in_one_place_only(self):
    # Spelled again at either end, the switch and the technique it reaches are free to drift apart
    # without anything failing, so both read it from the constant.
    import inspect
    from src.core import main
    from src.core.controller import controller
    self.assertIn("settings.OOB_TECHNIQUE_LETTER",
                  inspect.getsource(controller.oob_command_injection_technique))
    self.assertIn("menu.options.tech = settings.OOB_TECHNIQUE_LETTER",
                  io.open(inspect.getsourcefile(main), encoding="utf-8").read())

  def test_the_switch_alone_says_whether_it_runs(self):
    menu.options.tech = ""
    menu.options.oob = False
    self.assertFalse(checks.technique_selected(settings.OOB_TECHNIQUE_LETTER))
    menu.options.oob = True
    self.assertTrue(checks.technique_selected(settings.OOB_TECHNIQUE_LETTER))

  def test_what_the_switch_writes_down_is_read_back_as_the_same_technique(self):
    # What '--oob' leaves in the technique list is the letter the run then asks about, and asking
    # about any other one is answered no - the switch selects the out-of-band technique on its own.
    menu.options.oob = True
    menu.options.tech = settings.OOB_TECHNIQUE_LETTER
    self.assertTrue(checks.technique_selected(settings.OOB_TECHNIQUE_LETTER))
    for letter in settings.AVAILABLE_TECHNIQUES:
      self.assertFalse(checks.technique_selected(letter), letter + " ran alongside out-of-band")

class TheHeuristicProbeIsSentTheWayTheTestsAre(unittest.TestCase):
  """
  The probe decides whether a parameter is worth testing at all under '--smart', so it is carried
  the way the requests that follow it are carried - pollution included, since deciding on an
  unpolluted answer skips the parameter over the very request '--hpp' was given to replace.
  """
  def source(self):
    import inspect
    from src.core.controller import controller
    return inspect.getsource(controller.heuristic_request)

  def test_the_query_and_the_body_both_ask_for_pollution(self):
    source = self.source()
    self.assertIn("process_injectable_value(encoded_payload, url, pollute=True)", source)
    self.assertIn("process_injectable_value(body_payload, menu.options.data, pollute=True)", source)

  def test_the_cookie_is_left_alone(self):
    # A cookie separates with ';', so a second '&name=' in one is more of the first cookie's value
    # rather than another cookie - and nothing is gained by sending it.
    source = self.source()
    self.assertIn("process_injectable_value(encoded_payload, menu.options.cookie)", source)

class EveryTechniqueLeftOutIsNamed(unittest.TestCase):
  """
  What a run says it did not test is read from the one list of techniques, so a letter cannot be
  selectable with '--technique' and missing from the sentence that offers to test it.
  """
  def setUp(self):
    self._tech = menu.options.tech

  def tearDown(self):
    menu.options.tech = self._tech

  def untested(self, tech):
    menu.options.tech = tech
    return checks.untested_techniques()

  def test_every_selectable_letter_has_a_name(self):
    for letter in settings.AVAILABLE_TECHNIQUES:
      self.assertIn(letter, settings.TECHNIQUE_LETTER_NAMES, letter + " has no name to be said by")

  def test_the_one_technique_left_out_is_the_one_named(self):
    # Everything but boolean-based: the sentence read empty here, so a run was told to drop
    # '--technique' without being told what dropping it would add.
    self.assertEqual("boolean-based technique", self.untested("rtf"))
    self.assertEqual("file-based technique", self.untested("rbt"))

  def test_the_three_left_out_are_all_named(self):
    self.assertEqual("boolean-based, time-based and file-based techniques", self.untested("r"))
    self.assertEqual("results-based, time-based and file-based techniques", self.untested("b"))

  def test_a_run_that_leaves_nothing_out_says_nothing(self):
    self.assertEqual("", self.untested("".join(settings.AVAILABLE_TECHNIQUES)))

class ANamedModuleIsNotDroppedByAHeuristic(unittest.TestCase):
  """
  The CGI heuristic is there to offer the module where the path looks like it calls for it, not to
  take back one the user named: the list it reads is what commix knows of, not what the target
  serves, so a path missing from it says nothing about whether the module is worth running.
  """
  URL = "http://t/index.php?x=1"

  def setUp(self):
    self._state = (settings.USER_APPLIED_MODULE, settings.VERBOSITY_LEVEL,
                   menu.options.module, menu.options.shellshock)
    self._out = settings.print_data_to_stdout
    settings.print_data_to_stdout = lambda *_: None
    settings.VERBOSITY_LEVEL = 0

  def tearDown(self):
    (settings.USER_APPLIED_MODULE, settings.VERBOSITY_LEVEL,
     menu.options.module, menu.options.shellshock) = self._state
    settings.print_data_to_stdout = self._out

  def test_a_path_with_no_known_cgi_script_still_turns_it_off(self):
    settings.USER_APPLIED_MODULE = ()
    menu.options.shellshock = True
    checks.check_CGI_scripts(self.URL)
    self.assertFalse(menu.options.shellshock)

  def test_the_module_the_user_named_is_left_alone(self):
    # Turned off here, the module the run was started for was never loaded, and the only word about
    # it was a debug line about a list the target had nothing to do with.
    settings.USER_APPLIED_MODULE = ("shellshock",)
    menu.options.shellshock = True
    checks.check_CGI_scripts(self.URL)
    self.assertTrue(menu.options.shellshock)

  def test_what_was_named_is_recorded_by_name(self):
    menu.options.module = "Shellshock"
    checks.validate_modules()
    self.assertEqual(("shellshock",), settings.USER_APPLIED_MODULE)

class PollutionCarriesTheParametersOwnValue(unittest.TestCase):
  """
  The occurrence that is not the payload is the one meant to read as the value the application was
  sent. Where the sink turned out not to need that value a short random stand-in replaces it in
  every later request - and a filter checking the shape of what it is given passes an address and
  refuses three letters, which is the evasion defeating itself.
  """
  TARGET = "http://t/a.php?addr="
  PAYLOAD = ";echo TAG;"

  def setUp(self):
    self._state = (settings.SERVER_BANNER, settings.HPP_POSITION_SAID, settings.TESTABLE_VALUE,
                   settings.VALUE_SKIPPED_EARLY, settings.IS_JSON, settings.IS_XML,
                   settings.IS_GRAPHQL, menu.options.hpp)
    self._out = settings.print_data_to_stdout
    settings.print_data_to_stdout = lambda *_: None
    settings.SERVER_BANNER = "Apache/2.4.7 (Ubuntu) PHP/5.5.9"
    settings.HPP_POSITION_SAID = True
    settings.IS_JSON = settings.IS_XML = settings.IS_GRAPHQL = False
    menu.options.hpp = True

  def tearDown(self):
    (settings.SERVER_BANNER, settings.HPP_POSITION_SAID, settings.TESTABLE_VALUE,
     settings.VALUE_SKIPPED_EARLY, settings.IS_JSON, settings.IS_XML,
     settings.IS_GRAPHQL, menu.options.hpp) = self._state
    settings.print_data_to_stdout = self._out

  def test_the_clean_occurrence_carries_the_value_that_was_stood_in_for(self):
    settings.TESTABLE_VALUE = "QIF"
    settings.VALUE_SKIPPED_EARLY = ("127.0.0.1", "QIF", "", "")
    polluted = checks.polluted_parameter(self.TARGET + self.PAYLOAD, self.PAYLOAD)
    self.assertEqual("http://t/a.php?addr=127.0.0.1&addr=" + self.PAYLOAD, polluted)

  def test_a_value_that_was_never_stood_in_for_is_carried_as_it_is(self):
    settings.TESTABLE_VALUE = "127.0.0.1"
    settings.VALUE_SKIPPED_EARLY = None
    polluted = checks.polluted_parameter(self.TARGET + self.PAYLOAD, self.PAYLOAD)
    self.assertEqual("http://t/a.php?addr=127.0.0.1&addr=" + self.PAYLOAD, polluted)

  def test_an_empty_value_still_pollutes_with_nothing(self):
    settings.TESTABLE_VALUE = " "
    settings.VALUE_SKIPPED_EARLY = None
    polluted = checks.polluted_parameter(self.TARGET + self.PAYLOAD, self.PAYLOAD)
    self.assertEqual("http://t/a.php?addr=&addr=" + self.PAYLOAD, polluted)

class ThePayloadIsWrittenOutWithTheParametersOwnValue(unittest.TestCase):
  """
  What is printed at the end carries the value the target was given, the way the format this one
  follows writes it. The stand-in belongs to how the requests were built, which the run says in its
  own line rather than inside a payload somebody is going to copy out.
  """
  def setUp(self):
    self._state = (settings.TESTABLE_VALUE, settings.TESTABLE_VALUE_STOOD_IN_FOR)

  def tearDown(self):
    (settings.TESTABLE_VALUE, settings.TESTABLE_VALUE_STOOD_IN_FOR) = self._state

  def test_the_stand_in_at_the_front_is_the_value_it_stood_for(self):
    settings.TESTABLE_VALUE, settings.TESTABLE_VALUE_STOOD_IN_FOR = "QQE", "127.0.0.1"
    self.assertEqual("127.0.0.1;echo TAG;", checks.payload_with_own_value("QQE;echo TAG;"))

  def test_nothing_is_rewritten_where_no_value_was_stood_in_for(self):
    settings.TESTABLE_VALUE, settings.TESTABLE_VALUE_STOOD_IN_FOR = "127.0.0.1", ""
    self.assertEqual("127.0.0.1;echo TAG;", checks.payload_with_own_value("127.0.0.1;echo TAG;"))

  def test_only_the_one_at_the_front_is_rewritten(self):
    # Anything further in belongs to the payload, whatever it happens to read like.
    settings.TESTABLE_VALUE, settings.TESTABLE_VALUE_STOOD_IN_FOR = "QQE", "127.0.0.1"
    self.assertEqual("127.0.0.1;echo QQE;", checks.payload_with_own_value("QQE;echo QQE;"))

  def test_a_payload_that_does_not_start_with_it_is_left_alone(self):
    settings.TESTABLE_VALUE, settings.TESTABLE_VALUE_STOOD_IN_FOR = "QQE", "127.0.0.1"
    self.assertEqual("'QQE;echo TAG;", checks.payload_with_own_value("'QQE;echo TAG;"))

  def test_a_parameter_tested_with_its_own_value_is_left_alone(self):
    # Where the two are the same there was no stand-in, whatever a value carried over from an
    # earlier parameter happens to say.
    settings.TESTABLE_VALUE, settings.TESTABLE_VALUE_STOOD_IN_FOR = "127.0.0.1", "127.0.0.1"
    self.assertEqual("127.0.0.1;echo TAG;", checks.payload_with_own_value("127.0.0.1;echo TAG;"))

class ATamperedStandInIsStillWrittenOutAsTheValue(unittest.TestCase):
  """
  A tamper script rewrites the stand-in along with the rest of the payload it is given, so looking
  for the three letters at the front finds nothing and the finding goes out carrying them - beside
  an untampered one that goes out carrying the value, which is the whole of what this is for.
  """
  def setUp(self):
    self._state = (settings.TESTABLE_VALUE, settings.TESTABLE_VALUE_STOOD_IN_FOR,
                   settings.MULTI_ENCODED_PAYLOAD, settings.TARGET_OS, settings.RAW_PAYLOAD)
    settings.TESTABLE_VALUE, settings.TESTABLE_VALUE_STOOD_IN_FOR = "QQE", "127.0.0.1"
    settings.TARGET_OS = settings.OS.UNIX
    settings.MULTI_ENCODED_PAYLOAD = ["uninitializedvariable"]

  def tearDown(self):
    (settings.TESTABLE_VALUE, settings.TESTABLE_VALUE_STOOD_IN_FOR,
     settings.MULTI_ENCODED_PAYLOAD, settings.TARGET_OS, settings.RAW_PAYLOAD) = self._state

  def test_the_script_rewrites_the_stand_in_too(self):
    # What makes the plain search for it fail in the first place.
    self.assertNotIn("QQE", checks.perform_payload_modification("QQE;echo TAG;"))

  def test_the_value_goes_back_where_the_tampered_stand_in_was(self):
    sent = checks.perform_payload_modification("QQE;echo TAG;")
    written = checks.payload_with_own_value(sent)
    self.assertTrue(written.startswith("127.0.0.1;"))
    self.assertEqual(sent[len(checks.perform_payload_modification("QQE")):], written[len("127.0.0.1"):])

  def test_nothing_is_rewritten_where_no_script_is_applied(self):
    settings.MULTI_ENCODED_PAYLOAD = []
    self.assertEqual("${AB}Q;echo TAG;", checks.payload_with_own_value("${AB}Q;echo TAG;"))

class EveryPlatformIsToldWhatToInstall(unittest.TestCase):
  """
  The sentence names something on each of them. Built a piece at a time around two platforms, it
  stopped after "Download the" on every other one - which is where it is most likely to be read,
  since the module ships with Python there and a missing one is the interpreter's own packaging.
  """
  def setUp(self):
    self._state = (settings.IS_WINDOWS, settings.PLATFORM, settings.print_data_to_stdout)
    self.said = []
    settings.print_data_to_stdout = self.said.append

  def tearDown(self):
    (settings.IS_WINDOWS, settings.PLATFORM, settings.print_data_to_stdout) = self._state

  def _said_on(self, is_windows, platform):
    del self.said[:]
    settings.IS_WINDOWS, settings.PLATFORM = is_windows, platform
    checks.no_readline_module()
    return re.sub(r"\x1b\[[0-9;]*m", "", "".join(self.said)).strip()

  def test_each_one_is_named_something_to_install(self):
    for is_windows, platform, named in ((True, "nt", "pyreadline"), (False, "mac", "gnureadline"),
                                        (False, "posix", "readline")):
      said = self._said_on(is_windows, platform)
      self.assertIn(named, said, platform)

  def test_the_sentence_is_finished_on_each_one(self):
    for is_windows, platform in ((True, "nt"), (False, "mac"), (False, "posix")):
      said = self._said_on(is_windows, platform)
      self.assertTrue(said.endswith("."), platform)
      self.assertNotIn("Download the.", said)

class NothingTestedIsSaidAsTheReasonItWas(unittest.TestCase):
  """
  A name given with '-p' that the request does not carry is one thing; every parameter it does
  carry having been set aside is another. Told the first while looking at the parameter in their
  own URL, the user is sent after something that is not wrong.
  """
  def setUp(self):
    self._state = (list(settings.TESTABLE_PARAMETERS_LIST), settings.TESTABLE_PARAMETERS)

  def tearDown(self):
    (settings.TESTABLE_PARAMETERS_LIST, settings.TESTABLE_PARAMETERS) = self._state

  def test_a_name_the_request_does_not_carry_is_said_to_be_missing(self):
    settings.TESTABLE_PARAMETERS_LIST = ["nosuchparam"]
    settings.TESTABLE_PARAMETERS = None
    self.assertIn("not present", checks.nothing_tested_message())

  def test_a_name_it_does_carry_is_not(self):
    # Named with '-p' and found, then set aside by one of the options that do that.
    settings.TESTABLE_PARAMETERS_LIST = ["addr"]
    settings.TESTABLE_PARAMETERS = True
    self.assertIn("set aside", checks.nothing_tested_message())

  def test_with_no_name_given_at_all_nothing_is_said_about_one(self):
    settings.TESTABLE_PARAMETERS_LIST = []
    settings.TESTABLE_PARAMETERS = None
    self.assertIn("set aside", checks.nothing_tested_message())

class AFileIsAskedForWholeWhereTheTechniqueCanAnswerWhole(unittest.TestCase):
  """
  Asked for as base64, a file arrives as it is on disk - nothing the page does to whitespace can
  reach it. Which technique is carrying the command is what decides whether that is worth paying
  for, and it is the caller that knows which one: what is left in the run-wide name is whichever
  was last announced while the parameter was being tested, long before this is asked.
  """
  CONTENT = "one\ntwo\n"

  def setUp(self):
    import base64
    self._state = (settings.TARGET_OS, settings.CURRENT_TECHNIQUE, settings.DEFAULT_CODEC)
    settings.TARGET_OS = settings.OS.UNIX
    self.asked = []
    encoded = base64.b64encode(self.CONTENT.encode()).decode()
    self.execute_cmd = lambda cmd: (self.asked.append(cmd), (encoded, True))[1]

  def tearDown(self):
    (settings.TARGET_OS, settings.CURRENT_TECHNIQUE, settings.DEFAULT_CODEC) = self._state

  def test_the_technique_the_caller_names_is_the_one_that_decides(self):
    # The run-wide name says otherwise, which is exactly the case this exists for.
    settings.CURRENT_TECHNIQUE = settings.INJECTION_TECHNIQUE.FILE_BASED
    content, fresh = checks.file_read_encoded(self.execute_cmd, "/etc/passwd",
                                              settings.INJECTION_TECHNIQUE.RESULTS_BASED)
    self.assertEqual(self.CONTENT, content)
    self.assertTrue(fresh)

  def test_a_technique_that_reads_a_byte_at_a_time_is_not_asked_for_it(self):
    settings.CURRENT_TECHNIQUE = settings.INJECTION_TECHNIQUE.RESULTS_BASED
    content, fresh = checks.file_read_encoded(self.execute_cmd, "/etc/passwd",
                                              settings.INJECTION_TECHNIQUE.TIME_BASED)
    self.assertIsNone(content)
    self.assertEqual([], self.asked)

  def test_with_none_named_the_run_wide_one_still_answers(self):
    settings.CURRENT_TECHNIQUE = settings.INJECTION_TECHNIQUE.RESULTS_BASED
    self.assertEqual(self.CONTENT, checks.file_read_encoded(self.execute_cmd, "/etc/passwd")[0])
    settings.CURRENT_TECHNIQUE = settings.INJECTION_TECHNIQUE.FILE_BASED
    self.assertIsNone(checks.file_read_encoded(self.execute_cmd, "/etc/passwd")[0])

class WhatOneWorkerIsTestingIsNotWhatAnotherIs(unittest.TestCase):
  """
  The technique in hand is one worker's own. Several share a run, and the one a worker is on says
  nothing about what another is doing - read off a single name, a worker asks its question about
  whichever technique some other worker happened to announce last.
  """
  def setUp(self):
    self._state = settings.CURRENT_TECHNIQUE
    settings.set_technique(settings.INJECTION_TECHNIQUE.RESULTS_BASED)

  def tearDown(self):
    settings.set_technique(self._state)

  def test_a_worker_announcing_its_own_does_not_move_another(self):
    seen = {}
    def worker():
      settings.set_technique(settings.INJECTION_TECHNIQUE.TIME_BASED)
      seen["worker"] = settings.current_technique()
    thread = threading.Thread(target=worker)
    thread.start()
    thread.join()
    self.assertEqual(settings.INJECTION_TECHNIQUE.TIME_BASED, seen["worker"])
    self.assertEqual(settings.INJECTION_TECHNIQUE.RESULTS_BASED, settings.current_technique())

  def test_a_worker_that_announced_nothing_reads_the_runs_last_word(self):
    seen = {}
    thread = threading.Thread(target=lambda: seen.__setitem__("worker", settings.current_technique()))
    thread.start()
    thread.join()
    self.assertEqual(settings.INJECTION_TECHNIQUE.RESULTS_BASED, seen["worker"])

class ASubstitutionWrittenAnotherWayIsWorthOneMoreAsk(unittest.TestCase):
  """
  Every substitution written here opens with '$', and so does the '${IFS}' a filtered whitespace is
  first worked around with - so one filter on that character refuses the lot, the heuristic's own
  probe included. A backtick opens the same substitution and is a different character.
  """
  def setUp(self):
    from src.utils import common
    self._common = common
    self._state = (settings.BACKTICK_RETRY_CHOICE, settings.TARGET_OS, settings.USER_APPLIED_TAMPER,
                   list(settings.MULTI_ENCODED_PAYLOAD), menu.options.interpreter, menu.options.tamper,
                   common.read_input)
    settings.BACKTICK_RETRY_CHOICE = None
    settings.TARGET_OS = settings.OS.UNIX
    settings.USER_APPLIED_TAMPER = ""
    settings.MULTI_ENCODED_PAYLOAD = []
    menu.options.interpreter = None
    menu.options.tamper = None
    self.asked = []
    common.read_input = lambda message, **kwargs: self.asked.append(message) or "Y"

  def tearDown(self):
    (settings.BACKTICK_RETRY_CHOICE, settings.TARGET_OS, settings.USER_APPLIED_TAMPER,
     settings.MULTI_ENCODED_PAYLOAD, menu.options.interpreter, menu.options.tamper,
     self._common.read_input) = self._state

  def test_a_posix_target_with_no_scripts_of_its_own_is_worth_asking_about(self):
    self.assertTrue(checks.may_retry_through_backticks())

  def test_a_shell_without_one_is_not_asked_about(self):
    settings.TARGET_OS = settings.OS.WINDOWS
    self.assertFalse(checks.may_retry_through_backticks())

  def test_an_interpreter_is_handed_a_program_rather_than_a_shell_line(self):
    menu.options.interpreter = "php"
    self.assertFalse(checks.may_retry_through_backticks())

  def test_scripts_the_user_chose_are_left_as_they_were_chosen(self):
    menu.options.tamper = "space2ifs"
    self.assertFalse(checks.may_retry_through_backticks())
    menu.options.tamper = None
    settings.USER_APPLIED_TAMPER = "space2ifs"
    self.assertFalse(checks.may_retry_through_backticks())

  def test_it_is_not_asked_about_twice_over(self):
    settings.MULTI_ENCODED_PAYLOAD = ["backticks"]
    self.assertFalse(checks.may_retry_through_backticks())

  def test_the_answer_is_asked_for_once_and_held(self):
    self.assertTrue(checks.backtick_retry_consent())
    self.assertTrue(checks.backtick_retry_consent())
    self.assertEqual(1, len(self.asked))
    self.assertIn("'$'", self.asked[0])

  def test_a_no_is_held_just_the_same(self):
    self._common.read_input = lambda message, **kwargs: self.asked.append(message) or "n"
    self.assertFalse(checks.backtick_retry_consent())
    self.assertFalse(checks.backtick_retry_consent())
    self.assertEqual(1, len(self.asked))

class ABooleanAnswerIsReadAgainstTheSameRequest(unittest.TestCase):
  """
  What a boolean answer is compared with has to be what the same request returns with no payload.
  The page kept at startup is the target as it was given, which stops being that request once a
  short random value stands in for the parameter's own - and a target that writes the value back
  answers the two differently whatever the payload did.
  """
  def setUp(self):
    from src.core.requests import requests
    self.requests = requests
    self._state = (settings.TESTABLE_VALUE_OPTIMIZED, settings.TESTABLE_VALUE,
                   settings.ORIGINAL_PAGE, settings.STAND_IN_PAGE, settings.STAND_IN_PAGE_FOR)
    self._fetch = requests.page_without_payload
    self.asked = []
    settings.ORIGINAL_PAGE = "the page as it arrived"
    settings.STAND_IN_PAGE, settings.STAND_IN_PAGE_FOR = "", None

  def tearDown(self):
    (settings.TESTABLE_VALUE_OPTIMIZED, settings.TESTABLE_VALUE,
     settings.ORIGINAL_PAGE, settings.STAND_IN_PAGE, settings.STAND_IN_PAGE_FOR) = self._state
    self.requests.page_without_payload = self._fetch

  def answering(self, page):
    def fetch(url, http_request_method):
      self.asked.append((url, http_request_method))
      return page
    self.requests.page_without_payload = fetch

  def test_the_page_it_arrived_with_is_used_while_it_still_carries_its_own_value(self):
    settings.TESTABLE_VALUE_OPTIMIZED = False
    self.answering("never asked for")
    self.assertEqual("the page as it arrived", checks.comparison_baseline("http://t/", "GET"))
    self.assertEqual([], self.asked)

  def test_a_stand_in_is_asked_for_its_own_page_once(self):
    settings.TESTABLE_VALUE_OPTIMIZED, settings.TESTABLE_VALUE = True, "QQE"
    self.answering("the page the stand-in returns")
    for _ in range(3):
      self.assertEqual("the page the stand-in returns", checks.comparison_baseline("http://t/", "GET"))
    self.assertEqual(1, len(self.asked))

  def test_a_different_stand_in_is_asked_again(self):
    settings.TESTABLE_VALUE_OPTIMIZED, settings.TESTABLE_VALUE = True, "QQE"
    self.answering("first")
    checks.comparison_baseline("http://t/", "GET")
    settings.TESTABLE_VALUE = "ZZT"
    self.answering("second")
    self.assertEqual("second", checks.comparison_baseline("http://t/", "GET"))

  def test_a_target_that_will_not_answer_leaves_what_was_already_there(self):
    settings.TESTABLE_VALUE_OPTIMIZED, settings.TESTABLE_VALUE = True, "QQE"
    self.answering(None)
    self.assertEqual("the page as it arrived", checks.comparison_baseline("http://t/", "GET"))

class TheDelayThresholdIsTakenOverASample(unittest.TestCase):
  """
  The answers in hand are a sample of what the target does, not all of it, so the spread is taken
  over one fewer than there are. The coefficient the spread is multiplied by was chosen for that
  estimator; taking it over the count instead narrows the margin without saying so.
  """
  def setUp(self):
    self._state = (list(settings.RESPONSE_TIMES), list(settings.PROBE_RESPONSE_TIMES),
                   menu.options.disable_stats)
    menu.options.disable_stats = False
    settings.PROBE_RESPONSE_TIMES = []

  def tearDown(self):
    (settings.RESPONSE_TIMES, settings.PROBE_RESPONSE_TIMES, menu.options.disable_stats) = self._state

  def test_the_margin_is_the_wider_of_the_two_estimators(self):
    # A sample whose own spread is what the margin is made of, rather than one where the share of
    # the target's pace below it is the larger of the two and the estimator changes nothing.
    import statistics
    times = [0.4, 0.9, 0.5, 1.2, 0.6, 0.7, 0.5, 1.1, 0.8, 0.6, 0.9, 0.5, 0.7, 1.0, 0.6]
    settings.RESPONSE_TIMES = list(times)
    threshold = checks.current_delay_threshold()
    mean = statistics.mean(times)
    population = mean + settings.TIME_STDEV_COEFF * statistics.pstdev(times)
    sample = mean + settings.TIME_STDEV_COEFF * statistics.stdev(times)
    self.assertAlmostEqual(sample, threshold, places=6)
    self.assertGreater(threshold, population)

  def test_a_sample_too_small_to_spread_has_no_threshold_of_its_own(self):
    settings.RESPONSE_TIMES = [0.5]
    self.assertIsNone(checks.current_delay_threshold())

class TheOracleReadsTheWholeAnswer(unittest.TestCase):
  """
  What tells a true answer from a false one is as often something the application set in a header
  as anything it rendered, so the whole answer is read - and a pattern is matched the way the
  reference for this matches one, without regard to case and line by line.
  """
  class Headers(object):
    def __init__(self, lines):
      self.headers = lines

  def setUp(self):
    self._state = (menu.options.string, menu.options.not_string, menu.options.regexp,
                   menu.options.code, menu.options.lengths)
    menu.options.string = menu.options.not_string = menu.options.regexp = None
    menu.options.code = None
    menu.options.lengths = False

  def tearDown(self):
    (menu.options.string, menu.options.not_string, menu.options.regexp,
     menu.options.code, menu.options.lengths) = self._state

  def headers(self):
    return self.Headers(["Set-Cookie: answered=yes\r\n", "Server: Apache\r\n"])

  def test_a_string_is_looked_for_in_the_headers_as_well(self):
    menu.options.string = "answered=yes"
    self.assertTrue(checks.boolean_oracle("nothing in the body", headers=self.headers()))
    self.assertFalse(checks.boolean_oracle("nothing in the body"))

  def test_a_string_that_is_not_to_be_there_counts_the_headers_too(self):
    menu.options.not_string = "answered=yes"
    self.assertFalse(checks.boolean_oracle("nothing in the body", headers=self.headers()))

  def test_a_pattern_reads_the_headers_and_ignores_case(self):
    menu.options.regexp = r"set-cookie: ANSWERED"
    self.assertTrue(checks.boolean_oracle("nothing in the body", headers=self.headers()))

  def test_a_pattern_anchors_on_the_lines_of_the_answer(self):
    # '^' reading the whole answer rather than each of its lines matches nothing below the first.
    menu.options.regexp = r"^Server: Apache"
    self.assertTrue(checks.boolean_oracle("", headers=self.headers()))

  def test_a_pattern_that_does_not_compile_answers_nothing(self):
    menu.options.regexp = "([unclosed"
    self.assertIsNone(checks.boolean_oracle("body", headers=self.headers()))
