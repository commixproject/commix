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

from src.utils import settings
from src.core.parse import cmdline as menu

"""
Present the certificate this run identifies itself with, on a context about to be used.

Some targets do not ask for credentials at all: they ask the client to prove itself while the
connection is being made, and answer nothing to one that cannot. There is no header for that and no
challenge to answer, so it belongs to the context rather than to the request - and to every context
this run builds, because which client is asking is a fact about the run and not about one request.
"""
def apply_client_certificate(context):
  if not getattr(menu.options, "auth_file", None):
    return context
  try:
    # The file holds both halves, so it is handed over as both.
    context.load_cert_chain(certfile=menu.options.auth_file, keyfile=menu.options.auth_file)
  except Exception as err:
    if not settings.PKI_FAILURE_SAID:
      settings.PKI_FAILURE_SAID = True
      err_msg = "Unable to use the certificate in '" + str(menu.options.auth_file) + "' (" + str(err) + ")."
      settings.print_data_to_stdout(settings.print_critical_msg(err_msg))
    raise SystemExit(settings.EXIT_FAILURE)
  return context

# eof
