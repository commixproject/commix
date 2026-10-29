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
import sys
import doctest
from src.utils import settings

"""
Runs the basic smoke testing
"""
def smoke_test():
    info_msg = "Executing smoke test."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))

    passed = True
    doctests = 0
    file_paths = []
    for root, directories, filenames in os.walk(settings.COMMIX_ROOT_PATH):
        # The suite is run on its own, by the test runner - this walk is for what commix imports.
        if "tests" in root.split(os.sep):
            continue
        file_paths.extend([os.path.abspath(os.path.join(root, i)) for i in filenames])

    for filename in file_paths:
      if os.path.splitext(filename)[1].lower() == ".py" and not "__init__.py" in filename:
        path = os.path.join(settings.COMMIX_ROOT_PATH, os.path.splitext(filename)[0])
        path = path.replace(settings.COMMIX_ROOT_PATH, '.')
        path = path.replace(os.sep, '.').lstrip('.')
        if "." in path:
          try:
            __import__(path)
            module = sys.modules[path]
            if settings.VERBOSITY_LEVEL != 0:
              debug_msg = "Succeeded importing '" + str(path) + "' module."
              settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
          except Exception as e:
            error_msg = "Failed importing '" + path + "' module due to '" + str(e) + "'."
            settings.print_data_to_stdout(settings.print_error_msg(error_msg))
            passed = False
          else:
            # The examples a module's own docstrings carry, run as the tests they are written as.
            failures, _ = doctest.testmod(module, verbose=False)
            if failures != 0:
              error_msg = "Failed " + str(failures) + " doctest(s) in '" + path + "' module."
              settings.print_data_to_stdout(settings.print_error_msg(error_msg))
              passed = False
            else:
              doctests += len(doctest.DocTestFinder().find(module))

    result = "Smoke test "
    if passed:
      result = result + "passed."
      if settings.VERBOSITY_LEVEL != 0:
        debug_msg = "Ran the examples in " + str(doctests) + " docstring(s)."
        settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
      settings.print_data_to_stdout(settings.print_bold_info_msg(result))
    else:
      result = result + "failed."
      settings.print_data_to_stdout(settings.print_bold_error_msg(result))
    raise SystemExit()

# eof
