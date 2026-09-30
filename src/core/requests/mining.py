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

import re
import random
import string
import difflib

from src.utils import settings
from src.thirdparty.six.moves import urllib as _urllib

"""
A name the target can have no use for, so what it answers is what it answers to anything.
"""
def _decoy():
  return "".join(random.choice(string.ascii_lowercase) for _ in range(settings.MINING_DECOY_LENGTH))

"""
The candidate names, as the list carries them.
"""
def _candidates():
  try:
    with open(settings.PARAMETER_MINING_LIST, "r") as candidates:
      return [line.strip() for line in candidates if line.strip() and not line.startswith("#")]
  except IOError:
    return []

"""
The URL with the given names appended, each carrying a value the target has no reason to know.
"""
def _with(url, names):
  query = "&".join(name + "=" + _decoy() for name in names)
  return url + ("&" if "?" in url else "?") + query

"""
The page a URL answers with, read the way every other comparison in the run reads one.
"""
def _page(url, http_request_method):
  from src.core.requests import headers
  from src.core.requests import requests
  from src.core.controller import checks
  try:
    request = _urllib.request.Request(url, method=http_request_method)
    headers.do_check(request)
    response = requests.get_request_response(request)
    if response is None or isinstance(response, bool):
      return None
    return checks.comparable_page(checks.decode_page_body(response.read(), response))
  except Exception:
    return None

"""
The longest run of text a page carries that the one it is compared against does not.

Taken as a length rather than as a ratio of the whole: what a parameter adds is the same handful of
characters whether the page around it is a line or a hundred kilobytes, and a ratio reads the second
as unchanged.
"""
def _inserted(control, page):
  if control is None or page is None:
    return 0
  runs = [end - start for tag, _, _, start, end
          in difflib.SequenceMatcher(None, control, page).get_opcodes() if tag in ("insert", "replace")]
  return max(runs) if runs else 0

"""
Whether a page answers differently from the decoys', by more than the page moves on its own.
"""
def _differs(control, page, noise=0):
  return _inserted(control, page) > max(noise, settings.MINING_MINIMUM_INSERT)

"""
What the page moves on its own, measured at its widest rather than at whichever sample came first.

A page that answers differently at random - a rate limit, an interstitial, a cache that misses - can
hand back the same answer twice and read as a page that never moves, which leaves the next answer of
the other kind looking like a parameter.
"""
def _noise(url, samples, http_request_method):
  pages = [page for page in samples if page is not None]
  widest = 0
  for index, page in enumerate(pages):
    for other in pages[index + 1:]:
      widest = max(widest, _inserted(page, other), _inserted(other, page))
  return widest

"""
Whether a name answers differently every time it is asked, rather than once.

A page that moves on its own answers differently now and then whatever it is sent, so a name is kept
only where the difference is there each time it is looked for.
"""
def _confirmed(url, name, control, noise, http_request_method):
  for _ in range(settings.MINING_CONFIRMATIONS):
    if not _differs(control, _page(_with(url, [name]), http_request_method), noise):
      return False
  return True

"""
The names in a bucket the target answers to, found by halving the bucket rather than by asking for
each name on its own - a bucket that changes nothing is one request for every name in it.
"""
def _narrow(url, bucket, control, noise, http_request_method):
  if len(bucket) == 1:
    return list(bucket) if _confirmed(url, bucket[0], control, noise, http_request_method) else []
  middle = len(bucket) // 2
  found = []
  for half in (bucket[:middle], bucket[middle:]):
    if _differs(control, _page(_with(url, half), http_request_method), noise):
      found += _narrow(url, half, control, noise, http_request_method)
  return found

"""
The parameters a target answers to without naming them anywhere.

Each bucket of candidates is asked for in one request and only a bucket that changes the page is
taken apart, so the cost is the buckets rather than the names.
"""
def mine_parameters(url, http_request_method):
  names = [name for name in _candidates() if (name + "=") not in url]
  if not names:
    return []
  info_msg = "Mining for parameters the target answers to but does not name."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  size = settings.PARAMETER_MINING_BUCKET
  control = _page(_with(url, [_decoy() for _ in range(size)]), http_request_method)
  if control is None:
    return []
  # Several answers to names the target cannot know either, so that what the page moves on its own is
  # measured rather than read as an answer.
  samples = [control] + [_page(_with(url, [_decoy() for _ in range(size)]), http_request_method)
                         for _ in range(settings.MINING_NOISE_SAMPLES)]
  noise = _noise(url, samples, http_request_method)
  found = []
  for index in range(0, len(names), size):
    bucket = names[index:index + size]
    if _differs(control, _page(_with(url, bucket), http_request_method), noise):
      found += _narrow(url, bucket, control, noise, http_request_method)
  if found:
    info_msg = "The target answers to '" + "', '".join(found) + "'."
    settings.print_data_to_stdout(settings.print_info_msg(info_msg))
  return found

"""
The scripts a page loads from the same host, which the crawler passes over on its way to the links.
"""
def script_sources(url, content):
  sources = []
  for match in re.finditer(r'(?i)<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', content or ""):
    href = _urllib.parse.urljoin(url, match.group(1))
    if _urllib.parse.urlparse(url).netloc in href and href not in sources:
      sources.append(href)
  return sources[:settings.MAX_MINED_SCRIPTS]

"""
The endpoints written into a script, which a page never links to and a crawler never reaches.
"""
def endpoints_in(url, script):
  found = []
  for match in re.finditer(r"""["'](/[A-Za-z0-9_\-./]{2,}(?:\.\w{2,5}(?:\?[^"']*)?|\?[^"']*))["']""", script or ""):
    href = _urllib.parse.urljoin(url, match.group(1))
    if href not in found:
      found.append(href)
  return found

"""
The endpoints the scripts a page loads name, read once per script and bounded by size.
"""
def mine_endpoints(url, content, http_request_method):
  from src.core.requests import headers
  from src.core.requests import requests
  from src.core.controller import checks
  found = []
  for source in script_sources(url, content):
    try:
      request = _urllib.request.Request(source, method=settings.HTTPMETHOD.GET)
      headers.do_check(request)
      response = requests.get_request_response(request)
      if response is None or isinstance(response, bool):
        continue
      script = checks.decode_page_body(response.read()[:settings.MAX_MINED_SCRIPT_SIZE], response)
    except Exception:
      continue
    for href in endpoints_in(source, script):
      if href not in found:
        found.append(href)
  return found
