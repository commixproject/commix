#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (http://commixproject.com).
Copyright (c) 2014-2017 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

"""
Based on "purge.py" script from sqlmap [1].
[1] https://github.com/sqlmapproject/sqlmap/blob/55272f7a3b5a771b0630b7c8c4a61bab7ba8f27f/lib/utils/purge.py
"""

import os
import sys
import stat
import random
import shutil
import string

from src.utils import menu
from src.utils import settings
from src.thirdparty.colorama import Fore, Back, Style, init

def purge_output():
  directory = settings.OUTPUT_DIR
  if not os.path.isdir(directory):
    warn_msg = "Skipping purging of directory '" + directory + "' as it does not exist."
    print settings.print_warning_msg(warn_msg)
    return

  info_msg = "Purging content of directory '" + directory + "'"
  if not menu.options.verbose >= 1: 
    info_msg += "... "
  else:
     info_msg += ".\n" 
  sys.stdout.write(settings.print_info_msg(info_msg))
  sys.stdout.flush()  

  # Purging content of target directory.
  dir_paths = []
  file_paths = []
  for rootpath, directories, filenames in os.walk(directory):
    dir_paths.extend([os.path.abspath(os.path.join(rootpath, i)) for i in directories])
    file_paths.extend([os.path.abspath(os.path.join(rootpath, i)) for i in filenames])

  # Changing file attributes.
  if menu.options.verbose >= 1:
    info_msg = "Changing file attributes... "
    sys.stdout.write(settings.print_info_msg(info_msg))
    sys.stdout.flush() 
  failed = False
  for file_path in file_paths:
    try:
      os.chmod(file_path, stat.S_IREAD | stat.S_IWRITE)
    except:
      failed = True
      pass
  if menu.options.verbose >= 1:    
    if not failed:  
      print "[ " + Fore.GREEN + "SUCCEED" + Style.RESET_ALL + " ]"
    else:
      print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"

  # Writing random data to files.
  if menu.options.verbose >= 1:
    info_msg = "Writing random data to files... "
    sys.stdout.write(settings.print_info_msg(info_msg))
    sys.stdout.flush() 
  failed = False
  for file_path in file_paths:
    try:
      filesize = os.path.getsize(file_path)
      with open(file_path, "w+b") as f:
        f.write("".join(chr(random.randint(0, 255)) for _ in xrange(filesize)))
    except:
      failed = True
      pass
  if menu.options.verbose >= 1:    
    if not failed:  
      print "[ " + Fore.GREEN + "SUCCEED" + Style.RESET_ALL + " ]"
    else:
      print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"

  # Truncating files.
  if menu.options.verbose >= 1:
    info_msg = "Truncating files... "
    sys.stdout.write(settings.print_info_msg(info_msg))
    sys.stdout.flush() 
  failed = False
  for file_path in file_paths:
    try:
      with open(file_path, 'w') as f:
        pass
    except:
      failed = True
      pass
  if menu.options.verbose >= 1:    
    if not failed:  
      print "[ " + Fore.GREEN + "SUCCEED" + Style.RESET_ALL + " ]"
    else:
      print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"

  # Renaming filenames to random values.
  if menu.options.verbose >= 1:
    info_msg = "Renaming filenames to random values... "
    sys.stdout.write(settings.print_info_msg(info_msg))
    sys.stdout.flush() 
  failed = False
  for file_path in file_paths:
    try:
      os.rename(file_path, os.path.join(os.path.dirname(file_path), "".join(random.sample(string.ascii_letters, random.randint(4, 8)))))
    except:
      failed = True
      pass
  if menu.options.verbose >= 1:    
    if not failed:  
      print "[ " + Fore.GREEN + "SUCCEED" + Style.RESET_ALL + " ]"
    else:
      print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"

  # Renaming directory names to random values.
  if menu.options.verbose >= 1:
    info_msg = "Renaming directory names to random values... "
    sys.stdout.write(settings.print_info_msg(info_msg))
    sys.stdout.flush() 
  failed = False
  dir_paths.sort(cmp=lambda x, y: y.count(os.path.sep) - x.count(os.path.sep))
  for dir_path in dir_paths:
    try:
      os.rename(dir_path, os.path.join(os.path.dirname(dir_path), "".join(random.sample(string.ascii_letters, random.randint(4, 8)))))
    except:
      failed = True
      pass
  if menu.options.verbose >= 1:    
    if not failed:  
      print "[ " + Fore.GREEN + "SUCCEED" + Style.RESET_ALL + " ]"
    else:
      print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"

  # Deleting the whole directory tree. 
  if menu.options.verbose >= 1:
    info_msg = "Deleting the whole directory tree... "
    sys.stdout.write(settings.print_info_msg(info_msg))
  os.chdir(os.path.join(directory, ".."))
  failed = False
  try:
    shutil.rmtree(directory)
  except OSError, ex:
    failed = True  
  if not failed:  
    print "[ " + Fore.GREEN + "SUCCEED" + Style.RESET_ALL + " ]"
  else:
    print "[ " + Fore.RED + "FAILED" + Style.RESET_ALL + " ]"    
    err_msg = "Problem occurred while removing directory '" + directory + "'."
    print settings.print_critical_msg(err_msg)

#eof