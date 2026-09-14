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

import base64
import json
import string
import uuid

from src.utils import settings
from src.core.oob import crypto
from src.core.oob.provider import Interaction, OOBProvider, tls_context, _rand
from src.thirdparty.six.moves import urllib as _urllib

"""
An interactsh client, speaking the register / poll / deregister protocol.
"""

class Interactsh(OOBProvider):
  name = settings.OOB_PROVIDER_INTERACTSH

  # A session with an interactsh server, keyed to the address it was opened against.
  def __init__(self):
    OOBProvider.__init__(self)
    self.server = settings.OOB_SERVER or ("https://" + settings.OOB_INTERACTSH_DOMAIN)
    if "://" not in self.server:
      self.server = "https://" + self.server
    self.server = self.server.rstrip("/")
    # A self-hosted server serves its own payloads, on the scheme it is reached on.
    parsed = _urllib.parse.urlparse(self.server)
    self.domain = (parsed.hostname or "").lower()
    self.scheme = (parsed.scheme or "https").lower()
    # A self-hosted server may listen anywhere, and the payload's URL has to say where.
    self.port = parsed.port
    self.token = settings.OOB_TOKEN
    self.correlation_id = "".join(_rand.choice(string.ascii_lowercase + string.digits) for _ in range(20))
    self.secret = str(uuid.uuid4())
    self._aes_key = None
    self._n = self._e = self._d = None

  """
  Issue a request against the interactsh server.
  """
  def _call(self, path, payload=None):
    url = self.server + path
    data = json.dumps(payload).encode(settings.DEFAULT_CODEC) if payload is not None else None
    request = _urllib.request.Request(url, data, method="POST" if data else "GET")
    request.add_header(settings.CONTENT_TYPE, "application/json")
    if self.token:
      request.add_header(settings.AUTHORIZATION, self.token)
    response = _urllib.request.urlopen(request, timeout=settings.TIMEOUT, context=tls_context())
    body = response.read().decode(settings.DEFAULT_CODEC, errors="replace")
    return json.loads(body) if body.strip() else {}

  """
  Generate a key pair and register it with the server.
  """
  def _register(self):
    self._n, self._e, self._d = crypto.generate_rsa_key()
    self._call("/register", {
      "public-key": crypto.public_key_pem_b64(self._n, self._e),
      "secret-key": self.secret,
      "correlation-id": self.correlation_id
    })

  """
  Release the registration.
  """
  def _deregister(self):
    self._call("/deregister", {"correlation-id": self.correlation_id, "secret-key": self.secret})

  """
  Poll for new interactions and decrypt them.
  """
  def _fetch(self):
    result = self._call("/poll?id=" + self.correlation_id + "&secret=" + self.secret)
    entries = result.get("data") or []
    if not entries:
      return []
    if self._aes_key is None:
      aes_key = result.get("aes_key")
      if not aes_key:
        return []
      self._aes_key = crypto.rsa_oaep_decrypt(base64.b64decode(aes_key), self._n, self._d)
    found = []
    for entry in entries:
      try:
        plaintext = crypto.aes_ctr_decrypt(self._aes_key, base64.b64decode(entry))
        record = json.loads(plaintext.decode(settings.DEFAULT_CODEC, errors="replace"))
      except Exception:
        continue
      found.append(Interaction(
        protocol=(record.get("protocol") or "").lower(),
        identifier=record.get("full-id") or record.get("unique-id") or "",
        raw_request=record.get("raw-request") or ""
      ))
    return found

  """
  Name the server the channel runs on.
  """
  def server_notice(self):
    notice = "Using out-of-band '" + self.domain + "' interactsh server."
    if not settings.OOB_SERVER:
      notice += " Use '--oob-server' for a self-hosted one."
    return notice

  """
  Build the hostname carrying a probe token.
  """
  def _hostname(self, token):
    return self.correlation_id + token + "." + self.domain

  """
  Recover the probe token from an interaction identifier.
  """
  def _token_of(self, interaction):
    for label in (interaction.identifier or "").lower().split("."):
      # A name carrying data has labels of its own in front, so the one holding the correlation id
      # is looked for among them all rather than at the start.
      if label.startswith(self.correlation_id):
        return label[len(self.correlation_id):]
    return None

  """
  The labels a name carried in front of the token, in the order they were asked for.
  """
  def data_of(self, interaction):
    labels = (interaction.identifier or "").lower().split(".")
    for index, label in enumerate(labels):
      if label.startswith(self.correlation_id):
        return labels[:index]
    return []

# eof
