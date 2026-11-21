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
from src.core.controller import controller
from src.core.parse import cmdline as menu

class AStaticParameterIsWorthSayingSo(unittest.TestCase):
  """
  The boolean-based technique tells its true from its false by how far two pages differ, so a
  parameter that changes no page at all has no answer to give it. Asked for that technique as well
  as for '--skip-static', which was the only thing asking before - a run that spent the whole
  boundary matrix on such a parameter reported a target as not injectable without ever saying the
  one thing it had already measured.
  """
  def setUp(self):
    self._state = (menu.options.skip_static, menu.options.tech, menu.options.eval_sink)
    menu.options.eval_sink = False

  def tearDown(self):
    menu.options.skip_static, menu.options.tech, menu.options.eval_sink = self._state

  def test_the_technique_that_compares_pages_asks(self):
    menu.options.skip_static = False
    menu.options.tech = "b"
    self.assertTrue(controller.dynamism_worth_asking())

  def test_a_run_that_names_no_technique_runs_that_one_too(self):
    menu.options.skip_static = False
    menu.options.tech = ""
    self.assertTrue(controller.dynamism_worth_asking())

  def test_nothing_reading_a_page_by_comparing_it_leaves_the_request_unspent(self):
    menu.options.skip_static = False
    for tech in ("r", "t", "f", "rtf"):
      menu.options.tech = tech
      self.assertFalse(controller.dynamism_worth_asking(), tech + " spent a request on a remark")

  def test_the_switch_that_acts_on_the_answer_still_asks_on_its_own(self):
    menu.options.skip_static = True
    menu.options.tech = "r"
    self.assertTrue(controller.dynamism_worth_asking())

class TechniquesCarryingEitherSink(unittest.TestCase):
  """
  A technique that reaches both sinks is run against whichever one this run is testing: it is left
  out by the flag that skips that sink, it reports the sink it actually proved, and it names the
  injection for what it was rather than for the one the other sink would have been.
  """
  ARGS = ("http://t/a.php?x=1", 5, "f", "GET")

  def setUp(self):
    self._state = (settings.IDENTIFIED_COMMAND_INJECTION, settings.SKIP_CODE_INJECTIONS,
                   settings.SKIP_COMMAND_INJECTIONS, settings.OOB_STATE,
                   settings.BOOLEAN_BASED_STATE, settings.VERBOSITY_LEVEL,
                   menu.options.eval_sink, menu.options.oob, menu.options.tech)
    self._handlers = (controller.oob_handler.exploitation, controller.bb_handler.exploitation)
    settings.IDENTIFIED_COMMAND_INJECTION = False
    settings.SKIP_CODE_INJECTIONS = False
    settings.SKIP_COMMAND_INJECTIONS = False
    settings.VERBOSITY_LEVEL = 0
    menu.options.oob = True
    menu.options.tech = ""
    # Named rather than left standing for all of them, so the per-language sweep answers at once.
    menu.options.eval_sink = None
    self.sent = []
    def answered(url, timesec, filename, http_request_method, injection_type, technique, *rest):
      self.sent.append((technique, injection_type))
      return "proved"
    controller.oob_handler.exploitation = answered
    controller.bb_handler.exploitation = answered

  def tearDown(self):
    (settings.IDENTIFIED_COMMAND_INJECTION, settings.SKIP_CODE_INJECTIONS,
     settings.SKIP_COMMAND_INJECTIONS, settings.OOB_STATE,
     settings.BOOLEAN_BASED_STATE, settings.VERBOSITY_LEVEL,
     menu.options.eval_sink, menu.options.oob, menu.options.tech) = self._state
    (controller.oob_handler.exploitation, controller.bb_handler.exploitation) = self._handlers

  def run_oob(self):
    controller.oob_command_injection_technique(*self.ARGS)

  def run_boolean(self):
    controller.boolean_based_technique(*self.ARGS)

  def test_the_out_of_band_technique_is_left_out_with_the_sink_it_carries(self):
    # It had a skip flag of its own that nothing ever wrote, so no sink being settled could leave
    # it out and it was the one technique that ran whatever had already been established.
    settings.SKIP_COMMAND_INJECTIONS = True
    self.run_oob()
    self.assertEqual([], self.sent)

  def test_a_settled_command_sink_does_not_leave_out_the_code_injection_pass(self):
    menu.options.eval_sink = "php"
    settings.SKIP_COMMAND_INJECTIONS = True
    self.run_oob()
    self.assertEqual(1, len(self.sent))

  def test_a_settled_code_sink_leaves_out_the_code_injection_pass(self):
    menu.options.eval_sink = "php"
    settings.SKIP_CODE_INJECTIONS = True
    self.run_oob()
    self.assertEqual([], self.sent)

  def test_what_the_out_of_band_technique_proved_is_the_sink_it_was_run_against(self):
    menu.options.eval_sink = "php"
    self.run_oob()
    self.assertEqual([(settings.INJECTION_TECHNIQUE.OOB, settings.INJECTION_TYPE.BLIND_CE)], self.sent)
    self.assertTrue(settings.OOB_STATE)

  def test_a_code_injection_finding_is_not_recorded_as_a_command_one(self):
    # The flag is what makes the run say a command shell answered as well, which casts doubt on a
    # code injection finding - so a technique that only ever proved the code sink leaves it alone.
    menu.options.eval_sink = "php"
    for run in (self.run_oob, self.run_boolean):
      settings.IDENTIFIED_COMMAND_INJECTION = False
      run()
      self.assertFalse(settings.IDENTIFIED_COMMAND_INJECTION, run.__name__ + " claimed command injection")

  def test_a_command_injection_finding_still_is(self):
    for run in (self.run_oob, self.run_boolean):
      settings.IDENTIFIED_COMMAND_INJECTION = False
      run()
      self.assertTrue(settings.IDENTIFIED_COMMAND_INJECTION, run.__name__ + " proved nothing")

  def test_the_flag_nothing_ever_wrote_is_gone(self):
    self.assertFalse(hasattr(settings, "SKIP_OOB_INJECTIONS"))

  def test_a_shell_answering_does_not_settle_a_sink_that_was_asked_for_by_name(self):
    """
    Pinned on the source, since reaching the conclusion itself takes a live channel and a target
    that answers on it. Both heuristics set the flag the code injection techniques read, so a shell
    answering either of them would otherwise leave every one of them skipping itself.
    """
    import inspect
    for heuristic in (controller.oob_heuristic_basic, controller.command_injection_heuristic_basic):
      source = inspect.getsource(heuristic)
      self.assertIn("if not menu.options.eval_sink:", source,
                    heuristic.__name__ + " settles the sink whatever was asked for")

class SkippingTheTimeBasedTechniqueRunsNothingInItsPlace(unittest.TestCase):
  """
  Skipped under its own name it ran the file-based flow labelled as the time-based one, and left the
  timing flag set for every request after it.
  """
  def test_the_answer_skip_ends_it_with_the_flag_cleared(self):
    from src.core.techniques.time_based import tb_handler
    from src.utils import common
    state = (tb_handler.checks.response_times_unsteady, common.read_input, tb_handler.tb_injection_handler,
             settings.TIME_RELATED_ATTACK, settings.RESPONSE_DELAYS, settings.ADJUST_TIME_DELAY_DISABLED)
    ran = []
    tb_handler.checks.response_times_unsteady = lambda: True
    common.read_input = lambda *args, **kwargs: "s"
    tb_handler.tb_injection_handler = lambda *args: ran.append(args)
    try:
      self.assertFalse(tb_handler.exploitation("http://t/", 3, "f", "GET", 0, "type", settings.INJECTION_TECHNIQUE.TIME_BASED))
      self.assertEqual([], ran)
      self.assertFalse(settings.TIME_RELATED_ATTACK)
    finally:
      (tb_handler.checks.response_times_unsteady, common.read_input, tb_handler.tb_injection_handler,
       settings.TIME_RELATED_ATTACK, settings.RESPONSE_DELAYS, settings.ADJUST_TIME_DELAY_DISABLED) = state

class AnUnknownSystemIsAskedAboutWhereTheHeuristicWasSkipped(unittest.TestCase):
  """
  Skipping the heuristic left the question of which shell the target runs unasked and unanswered, and
  the run tested the one it started with - so Windows was never reached, and nothing said so.
  """
  NAMES = ("OS_IDENTIFICATION_PENDING", "CHECK_BOTH_OS", "OS_CHECKS_NUM", "print_data_to_stdout")

  def setUp(self):
    from src.core.controller import checks
    self.checks = checks
    self._saved = dict((name, getattr(settings, name)) for name in self.NAMES)
    self._define = checks.define_target_os
    settings.print_data_to_stdout = lambda *args: None
    self.asked = []
    def answered_no():
      self.asked.append(True)
      settings.CHECK_BOTH_OS = True
    checks.define_target_os = answered_no

  def tearDown(self):
    self.checks.define_target_os = self._define
    for name, value in self._saved.items():
      setattr(settings, name, value)

  def test_a_no_adds_the_other_shell_to_the_walk(self):
    settings.OS_IDENTIFICATION_PENDING, settings.CHECK_BOTH_OS, settings.OS_CHECKS_NUM = True, False, 2
    targets = [settings.OS.UNIX]
    controller.settle_unknown_os(targets)
    self.assertEqual([settings.OS.UNIX, settings.OS.WINDOWS], targets)
    self.assertFalse(settings.OS_IDENTIFICATION_PENDING)

  def test_a_system_something_already_answered_for_is_not_asked_about(self):
    settings.OS_IDENTIFICATION_PENDING = False
    targets = [settings.OS.UNIX]
    controller.settle_unknown_os(targets)
    self.assertEqual([], self.asked)
    self.assertEqual([settings.OS.UNIX], targets)

  def test_it_is_asked_once(self):
    settings.OS_IDENTIFICATION_PENDING, settings.CHECK_BOTH_OS, settings.OS_CHECKS_NUM = True, False, 2
    controller.settle_unknown_os([settings.OS.UNIX])
    controller.settle_unknown_os([settings.OS.UNIX])
    self.assertEqual(1, len(self.asked))

  def test_the_skipped_heuristic_reaches_it(self):
    import inspect
    source = inspect.getsource(controller.do_injection if hasattr(controller, "do_injection") else controller)
    self.assertIn("settle_unknown_os(os_targets)", inspect.getsource(controller))

if __name__ == "__main__":
  unittest.main()

class EachCommandRunsOnceInTheFormSettledBeforeIt(unittest.TestCase):
  """
  How a results-based answer is read - plainly, or exactly as printed through a more complex
  payload - is settled before the first command the user asked for, and every command then runs a
  single time. Settled after an output was read, the only way to read that output exactly is to run
  the command again, and a command with an effect of its own would have it twice. The target is
  asked first whether it has 'awk', by name: where it does not, there is nothing to ask the user.
  """
  def setUp(self):
    from src.core.controller import execution
    from src.utils import common
    self.execution, self.common = execution, common
    self._kept = (settings.RESULTS_BASED_EXACT_OUTPUT, settings.EXACT_OUTPUT_CHOICE,
                  settings.EXPLOITATION_STARTED, settings.TIME_RELATED_ATTACK, settings.URL_RELOAD,
                  common.read_input, settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX,
                  dict(settings.TAMPER_SCRIPTS), settings.TARGET_OS, menu.options.interpreter,
                  menu.options.batch)
    settings.RESULTS_BASED_EXACT_OUTPUT = False
    settings.EXACT_OUTPUT_CHOICE = None
    settings.EXPLOITATION_STARTED = True
    settings.TIME_RELATED_ATTACK = False
    settings.URL_RELOAD = False
    settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX = "$(", ")"
    for name in settings.TAMPER_SCRIPTS:
      settings.TAMPER_SCRIPTS[name] = False
    settings.TARGET_OS = settings.OS.UNIX
    menu.options.interpreter = None
    menu.options.batch = False
    self.asked, self.sent, self.commands = [], [], []

  def tearDown(self):
    (settings.RESULTS_BASED_EXACT_OUTPUT, settings.EXACT_OUTPUT_CHOICE,
     settings.EXPLOITATION_STARTED, settings.TIME_RELATED_ATTACK, settings.URL_RELOAD,
     self.common.read_input, settings.CMD_SUB_PREFIX, settings.CMD_SUB_SUFFIX,
     scripts, settings.TARGET_OS, menu.options.interpreter, menu.options.batch) = self._kept
    settings.TAMPER_SCRIPTS.clear()
    settings.TAMPER_SCRIPTS.update(scripts)

  def _answers(self, answer):
    asked = self.asked
    def read_input(message, default=None, check_batch=True):
      asked.append(message)
      return answer
    self.common.read_input = read_input

  def fire(self, answers, cmd="id"):
    # What the target answers, in the order it is asked - each a list of what the markers enclosed,
    # an empty one being markers that never came back.
    sent, said, commands = self.sent, list(answers), self.commands
    class Injector(object):
      @staticmethod
      def injection(*args, **kwargs):
        sent.append(settings.RESULTS_BASED_EXACT_OUTPUT)
        commands.append(args[2])
        return "response"
      @staticmethod
      def injection_results(*args, **kwargs):
        return said.pop(0)
    run = self.execution.make_simple_execute_cmd(
      Injector, ";", 10, "TAG", "", "", " ", 5, "GET", "http://t/", "p", None, "f",
      0, settings.INJECTION_TECHNIQUE.RESULTS_BASED, "")
    return run(cmd)

  def test_a_yes_reads_the_first_command_exactly_and_runs_it_once(self):
    self._answers("y")
    self.assertEqual("a  b", self.fire([["/usr/bin/awk"], ["a  b"]], cmd="ls"))
    self.assertEqual([settings.AWK_PRESENCE_CHECK, "ls"], self.commands)
    self.assertEqual([False, True], self.sent)
    self.assertEqual(1, len(self.asked))

  def test_a_no_reads_it_plainly_and_runs_it_once(self):
    self._answers("n")
    self.assertEqual("a b", self.fire([["/usr/bin/awk"], ["a b"]], cmd="ls"))
    self.assertEqual([settings.AWK_PRESENCE_CHECK, "ls"], self.commands)
    self.assertEqual([False, False], self.sent)

  def test_a_target_without_awk_is_not_asked_about_it(self):
    self._answers("y")
    self.assertEqual("a b", self.fire([[""], ["a b"]], cmd="ls"))
    self.assertEqual([], self.asked)
    self.assertEqual([settings.AWK_PRESENCE_CHECK, "ls"], self.commands)
    self.assertFalse(settings.RESULTS_BASED_EXACT_OUTPUT)

  def test_batch_sends_neither_the_check_nor_the_question(self):
    self._answers("y")
    menu.options.batch = True
    self.assertEqual("a b", self.fire([["a b"]], cmd="ls"))
    self.assertEqual(["ls"], self.commands)
    self.assertEqual([], self.asked)

  def test_batch_with_a_yes_given_by_name_checks_and_reads_exactly(self):
    self._answers("y")
    menu.options.batch = True
    kept, settings.ANSWERS = settings.ANSWERS, "preserve whitespace=y"
    try:
      self.assertEqual("a  b", self.fire([["/usr/bin/awk"], ["a  b"]], cmd="ls"))
    finally:
      settings.ANSWERS = kept
    self.assertEqual([settings.AWK_PRESENCE_CHECK, "ls"], self.commands)
    self.assertEqual([False, True], self.sent)

  def test_batch_with_a_no_given_by_name_sends_nothing_extra(self):
    menu.options.batch = True
    kept, settings.ANSWERS = settings.ANSWERS, "preserve whitespace=n"
    try:
      self.fire([["a b"]], cmd="ls")
    finally:
      settings.ANSWERS = kept
    self.assertEqual(["ls"], self.commands)

  def test_the_form_is_settled_once_for_the_target(self):
    self._answers("y")
    self.fire([["/usr/bin/awk"], ["x"]], cmd="ls")
    self.commands[:] = []
    self.fire([["y"]], cmd="id")
    self.assertEqual(["id"], self.commands)
    self.assertEqual(1, len(self.asked))

  def test_nothing_is_asked_before_the_commands_the_user_asked_for(self):
    # A web root, a shell type - the run's own commands during detection are read plainly.
    self._answers("y")
    settings.EXPLOITATION_STARTED = False
    self.assertEqual("/var/www", self.fire([["/var/www"]], cmd="pwd"))
    self.assertEqual(["pwd"], self.commands)
    self.assertIsNone(settings.EXACT_OUTPUT_CHOICE)

  def test_nothing_is_asked_where_a_yes_would_change_nothing(self):
    self._answers("y")
    settings.TARGET_OS = settings.OS.WINDOWS
    self.fire([["a b"]])
    settings.TARGET_OS = settings.OS.UNIX
    menu.options.interpreter = "python"
    self.fire([["a b"]])
    menu.options.interpreter = None
    settings.TAMPER_SCRIPTS["space2ifs"] = True
    self.fire([["a b"]])
    self.assertEqual([], self.asked)
    self.assertEqual(["id", "id", "id"], self.commands)

  def test_an_empty_output_is_not_a_reason_to_run_the_command_again(self):
    # The markers came back around nothing: the command ran and printed nothing.
    settings.RESULTS_BASED_EXACT_OUTPUT = True
    settings.EXACT_OUTPUT_CHOICE = True
    self.assertEqual("", self.fire([[""]], cmd="touch f"))
    self.assertEqual(["touch f"], self.commands)
    self.assertTrue(settings.RESULTS_BASED_EXACT_OUTPUT)

  def test_an_unanswered_complex_payload_is_sent_once_more_the_plain_way(self):
    # No markers at all: the payload never ran, so the plain one runs the command the first time.
    settings.RESULTS_BASED_EXACT_OUTPUT = True
    settings.EXACT_OUTPUT_CHOICE = True
    self.assertEqual("a b", self.fire([[], ["a b"]], cmd="ls"))
    self.assertEqual([True, False], self.sent)
    self.assertFalse(settings.RESULTS_BASED_EXACT_OUTPUT)

class WhatStoodInForOneParametersValueIsNotCarriedToTheNext(unittest.TestCase):
  """
  A parameter the sink did not need the value of leaves that value on record. The next parameter is
  tested with its own value from the first request, so a finding of its own written out with the
  last one's value in front of it names a request that was never sent.
  """
  def setUp(self):
    self._state = (settings.TESTABLE_VALUE_OPTIMIZED, settings.TESTABLE_VALUE_STOOD_IN_FOR,
                   settings.TECHNIQUES_BEFORE_NARROWING, menu.options.tech)

  def tearDown(self):
    (settings.TESTABLE_VALUE_OPTIMIZED, settings.TESTABLE_VALUE_STOOD_IN_FOR,
     settings.TECHNIQUES_BEFORE_NARROWING, menu.options.tech) = self._state

  def test_the_value_that_was_stood_in_for_is_put_down_with_the_parameter(self):
    settings.TESTABLE_VALUE_OPTIMIZED = True
    settings.TESTABLE_VALUE_STOOD_IN_FOR = "127.0.0.1"
    controller.reset_parameter_state()
    self.assertFalse(settings.TESTABLE_VALUE_OPTIMIZED)
    self.assertEqual("", settings.TESTABLE_VALUE_STOOD_IN_FOR)
