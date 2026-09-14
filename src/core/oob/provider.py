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

import random
import ssl
import string
import threading
import time

from src.utils import settings

# A guessable probe token would let anyone else's traffic pass for a finding.
_rand = random.SystemRandom()

"""
Build the TLS context used to reach the out-of-band server.
"""
def tls_context():
  return settings.verified_context()

"""
Explain a TLS failure against the out-of-band server.
"""
def tls_error(err):
  if not isinstance(getattr(err, "reason", None), ssl.SSLError) and not isinstance(err, ssl.SSLError):
    return None
  err_msg = "Could not verify the out-of-band server's certificate. This channel carries command "
  err_msg += "output, so it is always verified. Install a CA bundle, or reach a self-hosted server "
  err_msg += "over plain HTTP (i.e. '--oob-server=http://...')."
  return err_msg

"""
The out-of-band (OAST) provider interface shared by every backend.
"""

class Interaction(object):
  # One interaction the out-of-band server saw.
  def __init__(self, protocol, identifier, raw_request):
    self.protocol = protocol
    self.identifier = identifier
    self.raw_request = raw_request

class OOBProvider(object):
  name = ""

  # A session with an out-of-band server, before it has been registered.
  def __init__(self):
    self.domain = ""
    self.scheme = "https"
    self._interactions = {}
    self.seen_any = False
    self._lock = threading.Lock()
    self._stop_event = threading.Event()
    self._wake = threading.Event()
    self._poller = None

  """
  Register with the backend and begin polling.
  """
  def start(self):
    self._register()
    self._poller = threading.Thread(target=self._poll_loop)
    self._poller.daemon = True
    self._poller.start()

  """
  Return a (token, hostname) pair unique to a single probe.
  """
  def new_payload(self):
    token = "".join(_rand.choice(string.ascii_lowercase + string.digits) for _ in range(13))
    return token, self._hostname(token)

  """
  Block until an interaction carrying the token arrives, or the timeout expires.
  A protocol keeps waiting for that kind - name resolution always lands before the request itself.
  """
  def wait_for(self, token, timeout, protocol=None):
    deadline = time.time() + timeout
    next_poll = 0
    while True:
      # Ask the server now rather than sitting out the rest of the poll interval, which would
      # otherwise spend much of the timeout doing nothing - and keep asking, since the interaction
      # usually lands a moment after the round trip that went looking for it.
      if time.time() >= next_poll:
        self._wake.set()
        next_poll = time.time() + settings.OOB_WAIT_POLL_INTERVAL
      with self._lock:
        hits = list(self._interactions.get(token, []))
      if protocol:
        hits = [_ for _ in hits if _.protocol == protocol]
      if hits or time.time() >= deadline:
        return hits
      time.sleep(0.5)

  """
  Ask the server for interactions now, without waiting for the rest of the poll interval.
  """
  def poll_now(self):
    self._wake.set()

  """
  Report whether any interaction carrying the token has been seen.
  """
  def seen(self, token, protocol=None):
    with self._lock:
      hits = list(self._interactions.get(token, []))
    return [_ for _ in hits if _.protocol == protocol] if protocol else hits

  """
  Stop polling and release the backend registration.
  """
  def stop(self):
    self._stop_event.set()
    # Also break the poll wait, so shutdown does not sit out the interval.
    self._wake.set()
    if self._poller:
      self._poller.join(timeout=2)
    try:
      self._deregister()
    except Exception:
      pass

  """
  Record an interaction against the token embedded in its identifier.
  """
  def _record(self, interaction):
    token = self._token_of(interaction)
    if not token:
      return
    with self._lock:
      self.seen_any = True
      self._interactions.setdefault(token, []).append(interaction)

  """
  Poll the backend until stopped.
  """
  def _poll_loop(self):
    while not self._stop_event.is_set():
      try:
        for interaction in self._fetch():
          self._record(interaction)
      except Exception as err:
        if settings.VERBOSITY_LEVEL >= 2:
          debug_msg = "Failed to poll the out-of-band server (" + str(err) + ")."
          settings.print_data_to_stdout(settings.print_debug_msg(debug_msg))
      self._wake.wait(settings.OOB_POLL_INTERVAL)
      self._wake.clear()

  """
  Name the server the channel runs on.
  """
  def server_notice(self):
    return None

  # Claim a hostname from the server, which the payloads will make the target reach.
  def _register(self):
    raise NotImplementedError

  # Give the hostname back, where the server wants to know it is finished with.
  def _deregister(self):
    pass

  # Ask the server what has reached it since last time.
  def _fetch(self):
    raise NotImplementedError

  # The hostname a payload should reach, for this one probe.
  def _hostname(self, token):
    raise NotImplementedError

  # Which probe an interaction belongs to.
  def _token_of(self, interaction):
    raise NotImplementedError

  """
  The labels an interaction's name carried in front of the token.
  """
  def data_of(self, interaction):
    return []

"""
Build the out-of-band provider.
"""
def build():
  from src.core.oob import interactsh
  return interactsh.Interactsh()

# eof
