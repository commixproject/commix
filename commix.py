#!/usr/bin/env python
# encoding: UTF-8

"""
This file is part of Commix Project (https://commixproject.com).
Copyright (c) 2014-2023 Anastasios Stasinopoulos (@ancst).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
 
For more see the file 'readme/COPYING' for copying permission.
"""

# Dummy check for missing module(s).
try:
  __import__("src.utils.version")
  from src.utils import version
  version.python_version()

except ImportError:
  err_msg = "Wrong installation detected (missing modules). "
  err_msg = "Visit 'https://github.com/commixproject/commix/' for further details. \n"
  print(settings.print_critical_msg(err_msg))
  raise SystemExit()

# Main
def main():
  import src.core.main

# Main
if __name__ == '__main__':
  try:
    main()
  except SystemExit:
    import sys
    raise SystemExit() 
  except KeyboardInterrupt:
    import sys
    raise SystemExit() 
  except IndentationError as err_msg:
    from src.utils import settings
    print(settings.print_critical_msg(err_msg) + ".\n")
    raise SystemExit() 
  except:
    from src.utils import common
    common.unhandled_exception()

# eof