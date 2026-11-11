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

if __name__ == "__main__":
  unittest.main()

class AReadingThatNeedsAToolFallsBackWhenItIsNotThere(unittest.TestCase):
  """
  The exact reading of a command's output asks 'awk' of the target. A target without it answers
  nothing, where the reading that asks for none would have answered something - so an empty answer
  is asked again the once, and the rest of that target is read the plainer way.
  """
  def setUp(self):
    from src.core.controller import execution
    self.execution = execution
    self._exact = settings.RESULTS_BASED_EXACT_OUTPUT
    self._time = settings.TIME_RELATED_ATTACK
    self._reload = settings.URL_RELOAD
    settings.RESULTS_BASED_EXACT_OUTPUT = True
    settings.TIME_RELATED_ATTACK = False
    settings.URL_RELOAD = False
    self.sent = []

  def tearDown(self):
    settings.RESULTS_BASED_EXACT_OUTPUT = self._exact
    settings.TIME_RELATED_ATTACK = self._time
    settings.URL_RELOAD = self._reload

  def injector(self, answers):
    sent, said = self.sent, list(answers)
    class Injector(object):
      @staticmethod
      def injection(*args, **kwargs):
        sent.append(settings.RESULTS_BASED_EXACT_OUTPUT)
        return "response"
      @staticmethod
      def injection_results(*args, **kwargs):
        return said.pop(0)
    return Injector

  def fire(self, answers):
    run = self.execution.make_simple_execute_cmd(
      self.injector(answers), ";", 10, "TAG", "", "", " ", 5, "GET", "http://t/", "p", None, "f",
      0, settings.INJECTION_TECHNIQUE.RESULTS_BASED, "")
    return run("id")

  def test_an_empty_answer_is_asked_again_without_the_tool(self):
    self.assertEqual("plain", self.fire(["", "plain"]))
    self.assertEqual([True, False], self.sent)
    self.assertFalse(settings.RESULTS_BASED_EXACT_OUTPUT)

  def test_an_answer_that_came_back_is_not_asked_twice(self):
    self.assertEqual("exact  output", self.fire(["exact  output"]))
    self.assertEqual([True], self.sent)
    self.assertTrue(settings.RESULTS_BASED_EXACT_OUTPUT)

  def test_a_target_already_read_the_plain_way_asks_once(self):
    settings.RESULTS_BASED_EXACT_OUTPUT = False
    self.assertEqual("", self.fire([""]))
    self.assertEqual([False], self.sent)
