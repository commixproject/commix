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

import json
import base64
import datetime
import threading

from src.utils import settings
from src.core.parse import cmdline as menu
from src.thirdparty.six.moves import urllib as _urllib

"""
The run's HTTP traffic, kept in the form every proxy and browser already reads.

Reference: http://www.softwareishard.com/blog/har-12-spec/

What '-t' writes is meant to be read by a person, one request after another; this is the same
traffic as data, so that a request the run made can be replayed, filtered or diffed in the tools
the work is already being done in rather than read out of a transcript.
"""

ENTRIES = []
LOCK = threading.Lock()

"""
Whether this run is collecting.
"""
def active():
  return bool(menu.options.har)

"""
A header list in the shape the format asks for.
"""
def _headers(items):
  return [{"name": str(name), "value": str(value)} for name, value in items]

"""
A body as text, or as base64 where it is not text at all.

The format is JSON, so a body that does not decode has nowhere to go as text - an encoded copy
reproduces the request or the response, where a lossy decode of it would not.
"""
def _content(raw, mime):
  content = {"mimeType": mime or "", "size": len(raw or b"")}
  if not raw:
    content["text"] = ""
    return content
  if not isinstance(raw, bytes):
    content["text"] = raw
    return content
  try:
    content["text"] = raw.decode(settings.DEFAULT_CODEC)
  except (UnicodeDecodeError, LookupError):
    content["encoding"] = "base64"
    content["text"] = base64.b64encode(raw).decode("ascii")
  return content

"""
Record one request and the response it was answered with.

The request is read off the object that was sent rather than off the wire, so the two headers the
client fills in for itself are put back here - they are the ones a replay needs and the only ones
that would otherwise be missing.
"""
def collect(request, code, status, response_headers, body, started, ended):
  if not active():
    return
  try:
    url = request.get_full_url()
    headers = list(request.header_items())
    if not any(name.lower() == "host" for name, _ in headers):
      headers.append(("Host", _urllib.parse.urlsplit(url).netloc))
    data = request.data
    if data is not None and not any(name.lower() == "content-length" for name, _ in headers):
      headers.append(("Content-Length", str(len(data))))
    query = [{"name": name, "value": value}
             for name, value in _urllib.parse.parse_qsl(_urllib.parse.urlsplit(url).query, keep_blank_values=True)]
    entry = {
      "startedDateTime": datetime.datetime.fromtimestamp(started).isoformat(),
      "time": int(1000 * (ended - started)),
      "request": {
        "method": request.get_method(),
        "url": url,
        "httpVersion": "HTTP/1.0" if menu.options.http10 else "HTTP/1.1",
        "headers": _headers(headers),
        "queryString": query,
        "cookies": [],
        "headersSize": -1,
        "bodySize": len(data) if data is not None else 0,
      },
      "response": {
        "status": int(code) if str(code).isdigit() else 0,
        "statusText": str(status or ""),
        "httpVersion": "HTTP/1.1",
        "headers": _headers(response_headers.items() if response_headers else []),
        "cookies": [],
        "content": _content(body, response_headers.get("Content-Type") if response_headers else ""),
        "redirectURL": "",
        "headersSize": -1,
        "bodySize": len(body or b""),
      },
      "cache": {},
      "timings": {"send": -1, "wait": -1, "receive": -1},
    }
    if data is not None:
      entry["request"]["postData"] = _content(data, request.get_header("Content-type", ""))
  except Exception:
    # A request that cannot be described is not a reason to stop making them.
    return
  with LOCK:
    ENTRIES.append(entry)

"""
Write out what was collected.
"""
def write():
  if not active():
    return
  log = {"log": {
    "version": "1.2",
    "creator": {"name": settings.APPLICATION, "version": settings.VERSION},
    "entries": ENTRIES,
  }}
  try:
    with open(menu.options.har, "w", encoding=settings.DEFAULT_CODEC) as output_file:
      json.dump(log, output_file, indent=2, ensure_ascii=False)
  except (OSError, IOError) as err_msg:
    error_msg = "Unable to write the HAR file to '" + menu.options.har + "' (" + str(err_msg) + ")."
    settings.print_data_to_stdout(settings.print_error_msg(error_msg))
    return
  info_msg = "HTTP traffic of " + str(len(ENTRIES)) + " request" + "s"[len(ENTRIES) == 1:]
  info_msg += " logged to the HAR file '" + menu.options.har + "'."
  settings.print_data_to_stdout(settings.print_info_msg(info_msg))

# eof
