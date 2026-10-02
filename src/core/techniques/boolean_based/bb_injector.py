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

from src.core.requests import requests
from src.core.controller import checks

"""
Send one question and read the answer off the page the target renders.

None where the answer cannot be read at all - a request that never arrived, or an oracle the run was
never given - which is not the same as a no and must not be bisected on.
"""
def ask(payload, prefix, suffix, whitespace, http_request_method, url, vuln_parameter):
  return answer(payload, prefix, suffix, whitespace, http_request_method, url, vuln_parameter)[0]

"""
The same question, with the name of the parameter the payload turned out to land in.

Worked out by the request rather than guessed at here, which is what lets a finding be reported
against the parameter it was actually found on.
"""
def answer(payload, prefix, suffix, whitespace, http_request_method, url, vuln_parameter):
  response, vuln_parameter, _, _, _ = requests.perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url)
  if response is False or response is None:
    return None, vuln_parameter
  try:
    page = checks.remove_reflected_values(checks.decode_page_body(response.read(), response), payload)
    code = response.getcode()
  except Exception:
    return None, vuln_parameter
  return checks.boolean_oracle(page, code), vuln_parameter

"""
The page a question came back with, for learning what a yes and a no look like on this target.

The payload comes back as it was actually sent, which is not always as it was passed in: the
parameter's own value is folded into it on the way out, and a finding reported without that fold
reads as a payload that replaces the value instead of following it.
"""
def page_of(payload, prefix, suffix, whitespace, http_request_method, url, vuln_parameter):
  response, vuln_parameter, sent_payload, prefix, suffix = requests.perform_injection(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url)
  if response is False or response is None:
    return None, None, vuln_parameter, prefix, suffix, sent_payload
  try:
    # The payload's own text is taken back out of the answer: a page that echoes what it was given
    # differs between two questions because of the questions, not because of what ran.
    page = checks.remove_reflected_values(checks.decode_page_body(response.read(), response), payload)
    return page, response.getcode(), vuln_parameter, prefix, suffix, sent_payload
  except Exception:
    return None, None, vuln_parameter, prefix, suffix, sent_payload

"""
Run a command and hand back what it printed, read a byte at a time off the page.

The same shape the out-of-band injector answers to, so that everything built on top - the enumeration
checks, the file access, '--os-cmd' and the shell - reaches this technique the way it reaches that one.
"""
def injection(separator, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter):
  from src.core.techniques.boolean_based import bb_handler as handler
  channel = handler.Channel(separator, prefix, suffix, whitespace, http_request_method, url, vuln_parameter)
  return handler.retrieve(channel, cmd)

# eof
