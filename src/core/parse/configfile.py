#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2026 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

For more see the file 'readme/COPYING' for copying permission.
"""

import os

from src.utils import settings
from src.thirdparty.six.moves import configparser as _configparser

"""
The options a run was given, written out and read back.

The file is INI with one section per option group, which is the same grouping the help lists them
under - so what is saved reads as the run described rather than as a flat list of names. A value
given on the command line wins over the same value in the file, which is what lets a saved profile
stand for the settled part of a run while the target, or whatever else is being varied, is still
given directly.
"""

"""
Options that say what to do instead of how, and are therefore not part of a profile: saving it,
loading it, and the ones that print something and end the run.
"""
IGNORED = ("config_file", "save_config", "version", "install", "update", "advanced_help",
           "list_tampers", "purge", "smoke_test", "wizard")

"""
Every option the parser knows, as {group title: [(destination, option)]}.
"""
def _grouped(parser):
  grouped = []
  for group in parser.option_groups:
    options = [(option.dest, option) for option in group.option_list if option.dest and option.dest not in IGNORED]
    if options:
      grouped.append((group.title, options))
  return grouped

"""
What an option's value looks like in the file.

A switch is written as what it is, but an option that takes a value and was never given one is
written as nothing at all - several of them carry False for "unset", and writing that word would
read back as the value itself.
"""
def _written(option, value):
  if option.action in ("store_true", "store_false"):
    return str(bool(value))
  if value is None or value is False:
    return ""
  return str(value)

"""
An option's value read back as the type the run works with.

The parser calls anything it was not given a type for a string, while the default such an option
carries is often a number - and one read back as "5" is not the 5 it was written from, which is the
difference between a value left alone and a value that reads as having been asked for.
"""
def _read(option, default, raw):
  raw = raw.strip()
  if option.action in ("store_true", "store_false"):
    return raw.lower() in ("1", "true", "yes", "on")
  if raw == "":
    return None
  wanted = option.type
  if wanted in (None, "string") and not isinstance(default, bool):
    if isinstance(default, int):
      wanted = "int"
    elif isinstance(default, float):
      wanted = "float"
  if wanted == "int":
    return int(raw)
  if wanted in ("float", float):
    return float(raw)
  return raw

"""
Write the options this run was given to a configuration file.
"""
def save(parser, options, filename):
  config = _configparser.RawConfigParser()
  for title, group_options in _grouped(parser):
    config.add_section(title)
    for dest, option in sorted(group_options):
      config.set(title, dest, _written(option, getattr(options, dest, None)))
  try:
    directory = os.path.dirname(os.path.abspath(filename))
    if directory and not os.path.isdir(directory):
      os.makedirs(directory)
    with open(filename, "w") as output_file:
      config.write(output_file)
  except (OSError, IOError) as err_msg:
    error_msg = "Unable to write the configuration file to '" + filename + "' (" + str(err_msg) + ")."
    settings.print_data_to_stdout(settings.print_critical_msg(error_msg))
    raise SystemExit(settings.EXIT_FAILURE)
  info_msg = "Saved the options of this run to the configuration file '" + filename + "'."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))

"""
Apply a configuration file to the options this run was given.

Only where the option is still what the parser left it: the command line is the more particular of
the two, so anything named there is what the run keeps. The names applied are handed back, because
whether an option was asked for at all is something the run decides other things by.
"""
def load(parser, options, filename):
  if not os.path.isfile(filename):
    error_msg = "The configuration file '" + filename + "' does not exist."
    settings.print_data_to_stdout(settings.print_critical_msg(error_msg))
    raise SystemExit(settings.EXIT_FAILURE)
  config = _configparser.RawConfigParser()
  try:
    config.read(filename)
  except _configparser.Error as err_msg:
    error_msg = "Unable to read the configuration file '" + filename + "' (" + str(err_msg) + ")."
    settings.print_data_to_stdout(settings.print_critical_msg(error_msg))
    raise SystemExit(settings.EXIT_FAILURE)

  known = dict((dest, option) for _, group_options in _grouped(parser) for dest, option in group_options)
  applied, unknown = set(), []
  for section in config.sections():
    for dest, raw in config.items(section):
      if dest not in known:
        unknown.append(dest)
        continue
      option = known[dest]
      default = parser.defaults.get(dest)
      try:
        value = _read(option, default, raw)
      except ValueError:
        error_msg = "The configuration file gives '" + dest + "' the value '" + raw.strip() + "', which is not a "
        error_msg += str(option.type) + "."
        settings.print_data_to_stdout(settings.print_critical_msg(error_msg))
        raise SystemExit(settings.EXIT_FAILURE)
      # A value that is merely the default carries nothing, and setting it would make the option
      # look as though it had been asked for.
      if value is None or value == default:
        continue
      if getattr(options, dest, None) != default:
        continue
      setattr(options, dest, value)
      applied.add(dest)

  if unknown:
    warn_msg = "The configuration file names " + ", ".join("'" + name + "'" for name in sorted(set(unknown)))
    warn_msg += ", which " + ("are" if len(set(unknown)) > 1 else "is") + " not " + ("options" if len(set(unknown)) > 1 else "an option")
    warn_msg += " of this version - ignored."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
  return applied

# eof
