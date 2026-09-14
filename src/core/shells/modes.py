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

from src.core.parse import cmdline as menu
from src.utils import common
from src.utils import settings
from src.core.controller import checks

"""
The shared "use -> set -> run" loop behind the 'reverse_tcp' and 'bind_tcp' modes.
"""

MODE_NAMES = ("os_shell", "reverse_tcp", "bind_tcp")

# Per mode: the settings flag holding it, and the other TCP mode.
MODE_FLAGS = {
  "reverse_tcp": ("REVERSE_TCP", "bind_tcp"),
  "bind_tcp": ("BIND_TCP", "reverse_tcp"),
}

"""
Everything the shared loop needs that differs between the two modes.
"""
class ShellMode(object):
  # One shell mode, and the payload modules it can carry.
  def __init__(self, name, modules, help_menu, option_rows, required, required_hint, set_options, unsupported, build, usage_hint):
    self.name = name
    self.modules = modules
    self.help_menu = help_menu
    self.option_rows = option_rows
    self.required = required
    self.required_hint = required_hint
    self.set_options = set_options
    self.unsupported = unsupported
    self.build = build
    self.usage_hint = usage_hint
    self.flag, self.other = MODE_FLAGS[name]

  # The module's full name, as the mode refers to it.
  def qualified(self, module_path):
    return self.name + "/" + module_path

  # Why a module cannot be used here, naming what this mode supports instead.
  def unsupported_msg(self):
    unsupported, supported = self.unsupported
    return "The '" + unsupported.upper() + "' option is not usable for '" + self.name + "' mode. Use the '" + supported.upper() + "' option."

"""
Announce the mode, listing the compatible payloads until one is selected.
"""
def _announce(mode, selected_module):
  if selected_module is None:
    info_msg = "Selected mode: '" + mode.name + "'. Type 'set payload <payload>' to select one."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
    menu.print_module_table(
      "Compatible Payloads",
      [(path, description) for path, (description, _) in mode.modules.items()]
    )
  else:
    info_msg = "Selected payload: '" + mode.qualified(selected_module) + "'. Configure options with 'set', then type 'run'."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))

"""
Select a payload by path, accepting both the bare and the mode-qualified form.
"""
def _select_payload(mode, module_path, option):
  if module_path.startswith(mode.name + "/"):
    module_path = module_path[len(mode.name) + 1:]

  if module_path in mode.modules:
    info_msg = "Selected payload: '" + mode.qualified(module_path) + "'. Configure options with 'set', then type 'run'."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
    return module_path

  matches = sorted(_ for _ in mode.modules if _.startswith(module_path))
  if matches:
    info_msg = "Matching payloads:\n" + "\n".join("  set payload " + _ for _ in matches)
    settings.print_data_to_stdout(info_msg)
  else:
    common.invalid_option(option)
  return None

"""
Handle a "set ..." command.
"""
def _handle_set(mode, option, selected_module):
  argument = option[4:]
  keyword, separator, value = argument.partition(settings.SINGLE_WHITESPACE)
  keyword = keyword.lower()

  if keyword == "payload":
    return _select_payload(mode, value.strip(), option) or selected_module

  if keyword == mode.unsupported[0] and separator:
    settings.print_data_to_stdout(settings.print_error_msg(mode.unsupported_msg()))
    return selected_module

  for name, check in mode.set_options:
    if keyword == name and separator:
      check(value)
      return selected_module

  common.invalid_option(option)
  mistyped = argument.strip()
  if mistyped in mode.modules:
    settings.print_data_to_stdout("Did you mean 'set payload " + mistyped + "'? (options stay set when you switch payloads)")
  else:
    settings.print_data_to_stdout(mode.usage_hint)
  return selected_module

"""
Handle a "use ..." command; returns the mode to switch to, or None to stay.
"""
def _handle_use(mode, option):
  target = option[3:].strip().lower()

  if target == mode.name:
    warn_msg = "You are in '" + target + "' mode."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
  elif target == "os_shell":
    setattr(settings, mode.flag, False)
    return "os_shell"
  elif target == mode.other:
    setattr(settings, MODE_FLAGS[mode.other][0], True)
    setattr(settings, mode.flag, False)
    return mode.other
  else:
    common.invalid_option(option)
    settings.print_data_to_stdout("Use 'use os_shell' or 'use " + mode.other + "' to switch modes.")
  return None

"""
Generate the selected payload, once every required option is set.
"""
def _handle_run(mode, selected_module, separator):
  if selected_module is None:
    err_msg = "No payload selected. Use 'set payload <payload>' first."
    settings.print_data_to_stdout(settings.print_error_msg(err_msg))
    return None

  if any(len(getattr(settings, attribute)) == 0 for attribute in mode.required):
    settings.print_data_to_stdout(settings.print_error_msg(mode.required_hint))
    return None

  result = mode.build(selected_module, separator)
  if result is None:
    return None

  if settings.EVAL_BASED_STATE != False:
    result = checks.escape_unquoted_dollars(result)

  settings.LAST_SELECTED_MODULE = selected_module
  checks.shell_success(mode.name.split("_")[0])
  return result

"""
Run the mode's interactive prompt, returning either the generated payload or the mode to switch to.
"""
def shell_mode_options(mode, separator, filename, url):
  selected_module = settings.LAST_SELECTED_MODULE if settings.LAST_SELECTED_MODULE in mode.modules else None
  _announce(mode, selected_module)

  while True:
    prompt_name = mode.name if selected_module is None else mode.qualified(selected_module)
    try:
      option = common.safe_input("commix(" + prompt_name + ") > ")
    except KeyboardInterrupt:
      checks.handle_exploitation_interrupt(filename, url)
      continue
    lowered = option.lower()

    if lowered == "?":
      mode.help_menu()

    elif lowered == "quit" or lowered == "exit":
      checks.quit(filename, url, hard_exit=True)

    # "back" deselects the current payload first; a second "back" leaves the mode.
    elif lowered == "back":
      if selected_module is not None:
        selected_module = None
        settings.LAST_SELECTED_MODULE = ""
        continue
      setattr(settings, mode.flag, False)
      return option

    elif lowered in MODE_NAMES:
      err_msg = "Type 'use " + lowered + "' to switch to that mode."
      settings.print_data_to_stdout(settings.print_error_msg(err_msg))

    elif lowered == "use" or lowered[0:4] == "use ":
      switch_to = _handle_use(mode, option)
      if switch_to:
        return switch_to

    elif lowered in ("show options", "show"):
      menu.print_options_table("Options (" + mode.name + ")", mode.option_rows())

    elif lowered == "run":
      result = _handle_run(mode, selected_module, separator)
      if result is not None:
        return result

    elif lowered == "set" or lowered[0:4] == "set ":
      selected_module = _handle_set(mode, option, selected_module)

    else:
      common.invalid_option(option)

# eof
