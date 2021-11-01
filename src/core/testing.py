#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2021 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

For more see the file 'readme/COPYING' for copying permission.
"""

import re
import os
import sys
from src.utils import settings

"""
Runs the basic smoke testing
"""
def smoke_test():
    _ = True
    file_paths = []
    for root, directories, filenames in os.walk(settings.COMMIX_ROOT_PATH):
        file_paths.extend([os.path.abspath(os.path.join(root, i)) for i in filenames])

    for filename in file_paths:
      if os.path.splitext(filename)[1].lower() == ".py" and not "__init__.py" in filename:
        path = os.path.join(settings.COMMIX_ROOT_PATH, os.path.splitext(filename)[0])
        path = path.replace(settings.COMMIX_ROOT_PATH, '.')
        path = path.replace(os.sep, '.').lstrip('.')
        if "." in path:
          try:
            __import__(path)
          except Exception as ex:
            error_msg = "Failed while importing module '" + path + "' (" + str(ex) + ")."
            print(settings.print_error_msg(error_msg))
            _ = False

    if _:
        status = "succeeded without any issues"
    else:
        status = "failed"
    info_msg = "The smoke-test has been " + status + "."
    print(settings.print_info_msg(info_msg))
    raise SystemExit()


