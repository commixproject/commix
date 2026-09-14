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
import stat
import random
import shutil
import string
import functools
from src.core.parse import cmdline as menu
from src.utils import settings
from src.thirdparty.six.moves import urllib as _urllib

"""
Safely removes (purges) output directory. With -u, scoped to just that target's subdirectory.
"""

"""
Run one purge stage over the given paths, logging the debug message and
returning True if any path in the stage failed.
"""
def _purge_stage(debug_msg, paths, action):
  if settings.VERBOSITY_LEVEL != 0:
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
  failed = False
  for path in paths:
    try:
      action(path)
    except:
      failed = True
  return failed

"""
Random filename used when renaming files/directories to random values.
"""
def _random_name():
  return "".join(random.sample(string.ascii_letters, random.randint(4, 8)))

"""
Overwrite a file's contents with random data of the same size.
"""
def _overwrite_with_random_data(path):
  filesize = os.path.getsize(path)
  with open(path, "w+b") as f:
    f.write(os.urandom(filesize))

"""
Truncate a file to zero length.
"""
def _truncate_file(path):
  with open(path, 'w'):
    pass

# Remove what this target's own output directory holds, and the directory with it.
def purge():
  directory = settings.OUTPUT_DIR
  if menu.options.url:
    host = _urllib.parse.urlparse(menu.options.url).netloc.replace(":", "_")
    if host:
      directory = os.path.join(directory, host)
  directory = os.path.abspath(directory)
  if not os.path.isdir(directory):
    warn_msg = "Skipping purging of directory '" + directory + "', as it does not exist."
    settings.print_data_to_stdout(settings.print_warning_msg(warn_msg))
    return
  info_msg = "Purging contents of directory '" + directory + "'."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  
  # Purging content of target directory.
  dir_paths = []
  file_paths = []
  for rootpath, directories, filenames in os.walk(directory):
    dir_paths.extend([os.path.abspath(os.path.join(rootpath, i)) for i in directories])
    file_paths.extend([os.path.abspath(os.path.join(rootpath, i)) for i in filenames])

  dir_paths.sort(key=functools.cmp_to_key(lambda x, y: y.count(os.path.sep) - x.count(os.path.sep)))

  failed = _purge_stage("Changing file attributes.", file_paths,
                         lambda p: os.chmod(p, stat.S_IREAD | stat.S_IWRITE))

  failed |= _purge_stage("Writing random data to files.", file_paths, _overwrite_with_random_data)

  failed |= _purge_stage("Truncating files.", file_paths, _truncate_file)

  failed |= _purge_stage("Renaming filenames to random values.", file_paths,
                          lambda p: os.rename(p, os.path.join(os.path.dirname(p), _random_name())))

  failed |= _purge_stage("Renaming directory names to random values.", dir_paths,
                          lambda p: os.rename(p, os.path.join(os.path.dirname(p), _random_name())))

  # Deleting the whole directory tree.
  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Deleting the whole directory tree."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
  try:
    shutil.rmtree(directory)
  except OSError:
    failed = True

  if failed:
    err_msg = "Problem occurred while removing directory '" + directory + "'."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))

# eof
