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
import hashlib
import random
import struct

# Key material must not come from the Mersenne Twister.
_rand = random.SystemRandom()

"""
Minimal RSA-OAEP and AES-CTR support, keeping out-of-band providers dependency-free.
"""

SBOX = [
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d]

SMALL_PRIMES = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,
                101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,
                193,197,199,211,223,227,229,233,239,241,251]

"""
Multiply two bytes in GF(2^8).
"""
def _gmul(a, b):
  result = 0
  for _ in range(8):
    if b & 1:
      result ^= a
    high = a & 0x80
    a = (a << 1) & 0xff
    if high:
      a ^= 0x1b
    b >>= 1
  return result

"""
Expand an AES-256 key into the per-round key schedule.
"""
def _expand_key(key):
  nk, nr = 8, 14
  words = [list(key[i * 4:i * 4 + 4]) for i in range(nk)]
  for i in range(nk, 4 * (nr + 1)):
    temp = list(words[i - 1])
    if i % nk == 0:
      temp = temp[1:] + temp[:1]
      temp = [SBOX[b] for b in temp]
      temp[0] ^= RCON[i // nk - 1]
    elif i % nk == 4:
      temp = [SBOX[b] for b in temp]
    words.append([words[i - nk][j] ^ temp[j] for j in range(4)])
  return words

"""
Encrypt a single 16-byte block with AES-256.
"""
def _encrypt_block(block, words):
  state = [list(block[i::4]) for i in range(4)]
  # Mix the round key into the state, one column at a time.
  def add_round_key(rnd):
    for c in range(4):
      for r in range(4):
        state[r][c] ^= words[rnd * 4 + c][r]
  add_round_key(0)
  for rnd in range(1, 15):
    for r in range(4):
      for c in range(4):
        state[r][c] = SBOX[state[r][c]]
    for r in range(1, 4):
      state[r] = state[r][r:] + state[r][:r]
    if rnd != 14:
      for c in range(4):
        col = [state[r][c] for r in range(4)]
        state[0][c] = _gmul(col[0], 2) ^ _gmul(col[1], 3) ^ col[2] ^ col[3]
        state[1][c] = col[0] ^ _gmul(col[1], 2) ^ _gmul(col[2], 3) ^ col[3]
        state[2][c] = col[0] ^ col[1] ^ _gmul(col[2], 2) ^ _gmul(col[3], 3)
        state[3][c] = _gmul(col[0], 3) ^ col[1] ^ col[2] ^ _gmul(col[3], 2)
    add_round_key(rnd)
  return bytes(bytearray([state[r][c] for c in range(4) for r in range(4)]))

"""
Decrypt an AES-256-CTR blob whose first 16 bytes are the initial counter.
"""
def aes_ctr_decrypt(key, blob):
  if len(blob) <= 16:
    return b""
  words = _expand_key(key)
  counter = int(_to_long_bytes(blob[:16]), 16)
  data = blob[16:]
  out = bytearray()
  for offset in range(0, len(data), 16):
    block = struct.pack(">QQ", (counter >> 64) & 0xffffffffffffffff, counter & 0xffffffffffffffff)
    stream = _encrypt_block(bytearray(block), words)
    chunk = data[offset:offset + 16]
    out.extend(bytearray([chunk[i] ^ bytearray(stream)[i] for i in range(len(chunk))]))
    counter = (counter + 1) & ((1 << 128) - 1)
  return bytes(out)

"""
Render bytes as a hex string, readable back as an integer.
"""
def _to_long_bytes(raw):
  return "".join("%02x" % b for b in bytearray(raw)) or "0"

"""
The MGF1 mask generation function used by OAEP.
"""
def _mgf1(seed, length):
  out = b""
  counter = 0
  while len(out) < length:
    out += hashlib.sha256(seed + struct.pack(">I", counter)).digest()
    counter += 1
  return out[:length]

"""
Test a candidate for primality using Miller-Rabin.
"""
def _is_probable_prime(n, rounds=24):
  if n < 2:
    return False
  for p in SMALL_PRIMES:
    if n % p == 0:
      return n == p
  d, s = n - 1, 0
  while d % 2 == 0:
    d //= 2
    s += 1
  for _ in range(rounds):
    a = _rand.randrange(2, n - 1)
    x = pow(a, d, n)
    if x == 1 or x == n - 1:
      continue
    for _ in range(s - 1):
      x = (x * x) % n
      if x == n - 1:
        break
    else:
      return False
  return True

"""
Generate a random prime of the requested bit length.
"""
def _generate_prime(bits):
  while True:
    candidate = _rand.getrandbits(bits) | (1 << (bits - 1)) | 1
    if _is_probable_prime(candidate):
      return candidate

"""
Compute the modular inverse of a modulo m.
"""
def _modinv(a, m):
  old_r, r = a, m
  old_s, s = 1, 0
  while r:
    q = old_r // r
    old_r, r = r, old_r - q * r
    old_s, s = s, old_s - q * s
  return old_s % m

"""
Generate an RSA key pair, returned as (n, e, d).
"""
def generate_rsa_key(bits=2048):
  e = 65537
  while True:
    p = _generate_prime(bits // 2)
    q = _generate_prime(bits // 2)
    if p == q:
      continue
    phi = (p - 1) * (q - 1)
    if phi % e == 0:
      continue
    n = p * q
    if n.bit_length() != bits:
      continue
    return n, e, _modinv(e, phi)

"""
Encode a DER length prefix.
"""
def _der_len(length):
  if length < 0x80:
    return bytes(bytearray([length]))
  encoded = bytearray()
  while length:
    encoded.insert(0, length & 0xff)
    length >>= 8
  return bytes(bytearray([0x80 | len(encoded)])) + bytes(encoded)

"""
Encode a DER value of the given tag.
"""
def _der(tag, payload):
  return bytes(bytearray([tag])) + _der_len(len(payload)) + payload

"""
Encode a non-negative integer as a DER INTEGER.
"""
def _der_int(value):
  raw = bytearray()
  while value:
    raw.insert(0, value & 0xff)
    value >>= 8
  if not raw or raw[0] & 0x80:
    raw.insert(0, 0)
  return _der(0x02, bytes(raw))

"""
Render an RSA public key as the base64 of its PEM-wrapped PKIX encoding.
"""
def public_key_pem_b64(n, e):
  rsa_oid = _der(0x06, bytes(bytearray([0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01])))
  algorithm = _der(0x30, rsa_oid + _der(0x05, b""))
  key = _der(0x30, _der_int(n) + _der_int(e))
  spki = _der(0x30, algorithm + _der(0x03, bytes(bytearray([0x00])) + key))
  body = base64.b64encode(spki).decode()
  lines = [body[i:i + 64] for i in range(0, len(body), 64)]
  pem = "-----BEGIN RSA PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END RSA PUBLIC KEY-----\n"
  return base64.b64encode(pem.encode()).decode()

"""
Decrypt an RSA-OAEP (SHA-256) ciphertext with the private exponent.
"""
def rsa_oaep_decrypt(ciphertext, n, d):
  k = (n.bit_length() + 7) // 8
  if len(ciphertext) != k:
    raise ValueError("unexpected RSA block size")
  m = pow(int(_to_long_bytes(ciphertext), 16), d, n)
  encoded = bytearray(k)
  for i in range(k - 1, -1, -1):
    encoded[i] = m & 0xff
    m >>= 8
  h_len = 32
  masked_seed = bytes(encoded[1:1 + h_len])
  masked_db = bytes(encoded[1 + h_len:])
  seed_mask = _mgf1(masked_db, h_len)
  seed = bytes(bytearray([masked_seed[i] ^ bytearray(seed_mask)[i] for i in range(h_len)]))
  db_mask = _mgf1(seed, k - h_len - 1)
  db = bytearray([bytearray(masked_db)[i] ^ bytearray(db_mask)[i] for i in range(len(masked_db))])
  separator = h_len
  while separator < len(db) and db[separator] == 0:
    separator += 1
  if separator >= len(db) or db[separator] != 1:
    raise ValueError("malformed OAEP padding")
  return bytes(db[separator + 1:])

# eof
