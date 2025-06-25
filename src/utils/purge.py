#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2025 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

"""
Based on "purge.py" script from sqlmap [1].
[1] https://github.com/sqlmapproject/sqlmap/blob/master/lib/utils/purge.py
"""

import os
import sys
import stat
import random
import shutil
import string
import functools
from src.utils import menu
from src.utils import settings
from src.core.compat import xrange
from src.thirdparty.colorama import Fore, Back, Style, init

"""
Safely removes (purges) output directory.
"""

def purge():
  directory = settings.OUTPUT_DIR
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

  # Changing file attributes.
  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Changing file attributes."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
    
  failed = False
  for file_path in file_paths:
    try:
      os.chmod(file_path, stat.S_IREAD | stat.S_IWRITE)
    except:
      failed = True
      pass

  # Writing random data to files.
  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Writing random data to files. "
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
    
  failed = False
  for file_path in file_paths:
    try:
      filesize = os.path.getsize(file_path)
      with open(file_path, "w+b") as f:
        f.write("".join(chr(random.randint(0, 255)) for _ in xrange(filesize)))
    except:
      failed = True
      pass

  # Truncating files.
  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Truncating files."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
    
  failed = False
  for file_path in file_paths:
    try:
      with open(file_path, 'w') as f:
        pass
    except:
      failed = True
      pass

  # Renaming filenames to random values.
  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Renaming filenames to random values."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
    
  failed = False
  for file_path in file_paths:
    try:
      os.rename(file_path, os.path.join(os.path.dirname(file_path), "".join(random.sample(string.ascii_letters, random.randint(4, 8)))))
    except:
      failed = True
      pass

  # Renaming directory names to random values.
  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Renaming directory names to random values."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
    
  failed = False
  dir_paths.sort(key=functools.cmp_to_key(lambda x, y: y.count(os.path.sep) - x.count(os.path.sep)))
  for dir_path in dir_paths:
    try:
      os.rename(dir_path, os.path.join(os.path.dirname(dir_path), "".join(random.sample(string.ascii_letters, random.randint(4, 8)))))
    except:
      failed = True
      pass

  # Deleting the whole directory tree.
  if settings.VERBOSITY_LEVEL != 0:
    debug_msg = "Deleting the whole directory tree."
    settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
  try:
    failed = False
    os.chdir(os.path.join(directory, ".."))
    shutil.rmtree(directory)
  except OSError as e:
    failed = True
  if failed:
    err_msg = "Problem occurred while removing directory '" + directory + "'."
    settings.print_data_to_stdout(settings.print_critical_msg(err_msg))

# eof