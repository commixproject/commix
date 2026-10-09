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
from hashlib import md5, sha256, sha512

"""
Standalone (no third-party/system-crypt dependency) implementations of the '/etc/shadow' hash
formats '--passwords' actually meets in practice, so a dictionary attack against them works the
same on every platform Python runs on - the system 'crypt' module is deprecated, gone outright in
Python 3.13+, and even where present answers differently (or not at all) for these per libc.
"""

ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

# One recognizable format per shadow entry commix can actually try - paired with the hashcat '-m'
# mode a format it cannot try in pure Python would need instead (reference: hashcat.net/wiki, "example_hashes").
FORMATS = (
  ("md5_crypt",    r"\A\$1\$[^$]{1,8}\$[./0-9A-Za-z]+\Z",                              500),
  ("sha256_crypt", r"\A\$5\$(?:rounds=\d+\$)?[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{43}\Z", 7400),
  ("sha512_crypt", r"\A\$6\$(?:rounds=\d+\$)?[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}\Z", 1800),
  ("bcrypt",       r"\A\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}\Z",                          3200),
  ("yescrypt",     r"\A\$y\$[./0-9A-Za-z]+\$[./0-9A-Za-z]+\$[./0-9A-Za-z]+\Z",          None),
  ("des_crypt",    r"\A(?![0-9./A-Za-z]{0,12}\Z)[./0-9A-Za-z]{13}\Z",                  1500),
)

# Formats a plain dictionary attack here can actually try - the rest are recognized (so the user
# is told what they are and, where known, which hashcat mode suits them) but not brute-forced.
CRACKABLE = ("md5_crypt", "sha256_crypt", "sha512_crypt")

"""
The format name '--passwords' recognizes a hash as, or None where it fits none of them.
"""
def recognize(hash_):
  for name, regex, _ in FORMATS:
    if re.match(regex, hash_):
      return name
  return None

"""
The hashcat mode a recognized-but-uncrackable-here format would need, or None.
"""
def hashcat_mode(name):
  for fmt_name, _, mode in FORMATS:
    if fmt_name == name:
      return mode
  return None

"""
MD5-crypt ('$1$') - the traditional glibc 'crypt(3)' extension.
Reference: https://www.freebsd.org/cgi/man.cgi?query=crypt&sektion=3 (historical Poul-Henning Kamp algorithm)
"""
def _md5_crypt(password, salt):
  salt = salt[:8]
  ctx = password + b"$1$" + salt
  final = md5(password + salt + password).digest()

  pl = len(password)
  while pl > 0:
    ctx += final[:16] if pl > 16 else final[:pl]
    pl -= 16

  i = len(password)
  while i:
    ctx += b"\x00" if (i & 1) else password[0:1]
    i >>= 1
  final = md5(ctx).digest()

  for i in range(1000):
    ctx1 = password if (i & 1) else final[:16]
    if i % 3:
      ctx1 += salt
    if i % 7:
      ctx1 += password
    ctx1 += final[:16] if (i & 1) else password
    final = md5(ctx1).digest()

  def enc(value, count):
    out = ""
    for _ in range(count):
      out += ITOA64[value & 0x3f]
      value >>= 6
    return out

  digest = (
    enc((final[0] << 16) | (final[6] << 8) | final[12], 4) +
    enc((final[1] << 16) | (final[7] << 8) | final[13], 4) +
    enc((final[2] << 16) | (final[8] << 8) | final[14], 4) +
    enc((final[3] << 16) | (final[9] << 8) | final[15], 4) +
    enc((final[4] << 16) | (final[10] << 8) | final[5], 4) +
    enc(final[11], 2)
  )
  return "$1$" + salt.decode() + "$" + digest

# SHA-crypt (Drepper) final-permutation byte order, for the 16/32/64-byte digests used below.
_SHA256_ORDER = ((0, 10, 20), (21, 1, 11), (12, 22, 2), (3, 13, 23), (24, 4, 14), (15, 25, 5), (6, 16, 26), (27, 7, 17), (18, 28, 8), (9, 19, 29), (31, 30))
_SHA512_ORDER = ((0, 21, 42), (22, 43, 1), (44, 2, 23), (3, 24, 45), (25, 46, 4), (47, 5, 26), (6, 27, 48), (28, 49, 7), (50, 8, 29), (9, 30, 51), (31, 52, 10), (53, 11, 32), (12, 33, 54), (34, 55, 13), (56, 14, 35), (15, 36, 57), (37, 58, 16), (59, 17, 38), (18, 39, 60), (40, 61, 19), (62, 20, 41), (63,))

"""
SHA-256/512-crypt ('$5$'/'$6$') digest, per Drepper's public spec.
Reference: https://www.akkadia.org/drepper/SHA-crypt.txt
"""
def _sha_crypt_digest(password, salt, rounds, digestmod, order):
  dsize = digestmod().digest_size
  B = digestmod(password + salt + password).digest()

  ctx = digestmod(password + salt)
  cnt = len(password)
  while cnt > dsize:
    ctx.update(B)
    cnt -= dsize
  ctx.update(B[:cnt])

  i = len(password)
  while i:
    ctx.update(B if (i & 1) else password)
    i >>= 1
  A = ctx.digest()

  dp = digestmod()
  for _ in range(len(password)):
    dp.update(password)
  DP = dp.digest()
  P = DP * (len(password) // dsize) + DP[:len(password) % dsize]

  ds = digestmod()
  for _ in range(16 + A[0]):
    ds.update(salt)
  DS = ds.digest()
  S = DS * (len(salt) // dsize) + DS[:len(salt) % dsize]

  C = A
  for i in range(rounds):
    c = digestmod()
    c.update(P if (i & 1) else C)
    if i % 3:
      c.update(S)
    if i % 7:
      c.update(P)
    c.update(C if (i & 1) else P)
    C = c.digest()

  digest = ""
  for group in order:
    value = 0
    for idx in group:
      value = (value << 8) | C[idx]
    for _ in range((len(group) * 8 + 5) // 6):
      digest += ITOA64[value & 0x3f]
      value >>= 6
  return digest

def _sha2_crypt(password, salt_field, magic):
  rounds, salt = 5000, salt_field
  if salt.startswith("rounds="):
    prefix, salt = salt.split("$", 1)
    rounds = max(1000, min(999999999, int(prefix[len("rounds="):])))

  digestmod, order = (sha256, _SHA256_ORDER) if magic == "$5$" else (sha512, _SHA512_ORDER)
  digest = _sha_crypt_digest(password, salt.encode()[:16], rounds, digestmod, order)
  return magic + salt_field + "$" + digest

"""
Whether 'candidate' is the plaintext behind 'hash_' - the one entry point the dictionary attack
calls, parsing out whichever salt/rounds the hash's own format carries rather than asking the
caller to. Returns False for a hash in CRACKABLE but malformed, and for one recognize() has no
format for at all.
"""
def crack_candidate(hash_, candidate):
  candidate = candidate.encode("utf-8", "replace")
  try:
    if hash_.startswith("$1$"):
      _, _, salt, _ = hash_.split("$", 3)
      return _md5_crypt(candidate, salt.encode()) == hash_
    if hash_.startswith(("$5$", "$6$")):
      magic = hash_[:3]
      salt_field = hash_[3:hash_.rindex("$")]
      return _sha2_crypt(candidate, salt_field, magic) == hash_
  except (ValueError, IndexError, UnicodeError):
    return False
  return False

# eof
