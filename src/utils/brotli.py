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

import os
import hashlib
import zipfile
import threading

"""
A page that arrives compressed with Brotli (RFC 7932), read back like any other.

Decoding only - nothing here compresses. A target behind a CDN answers in Brotli as readily as in
gzip, and a page that cannot be read is a page nothing can be found in - so asking for it and then
depending on a library that may not be installed is not worth the findings it costs.

The static dictionary and the context table the format is defined against are data rather than
code: RFC 7932, Appendix A, read from 'data/txt/brotli-dictionary.tx_'.
"""

class BrotliError(Exception):
  pass

# What the packed table holds: the dictionary the format defines, and the context table after it.
DICTIONARY_LENGTH = 122784
CONTEXT_LENGTH = 2048
# Checked on load, so a swapped or truncated table is said out loud rather than quietly mis-decoded.
DICTIONARY_DIGEST = "20e42eb1b511c21806d4d227d07e5dd06877d8ce7b3a817f378f313653f35c70"

_TABLES = None
_TABLES_LOCK = threading.Lock()

"""
The dictionary's words are bucketed by length: 'size bits' says how many bits index a bucket, and
where each bucket starts follows from that.
"""
WORD_SIZE_BITS = (0, 0, 0, 0, 10, 10, 11, 11, 10, 10, 10, 10, 10, 9, 9, 8, 7, 7, 8, 7, 7, 6, 6, 5, 5)
WORD_OFFSETS = [0] * (len(WORD_SIZE_BITS) + 1)
for _length in range(len(WORD_SIZE_BITS)):
  WORD_OFFSETS[_length + 1] = WORD_OFFSETS[_length] + ((_length << WORD_SIZE_BITS[_length]) if WORD_SIZE_BITS[_length] else 0)

# What is done to a dictionary word before it is used, beyond the prefix and suffix put around it.
TRANSFORM_IDENTITY = 0
TRANSFORM_UPPERCASE_FIRST = 10
TRANSFORM_UPPERCASE_ALL = 11
TRANSFORM_OMIT_FIRST = 12

"""
The 121 transforms the format defines, in the order it defines them: what goes before the word,
what is done to the word, and what goes after it.
"""
TRANSFORMS = (
  (b'', 0, b''), (b'', 0, b' '),
  (b' ', 0, b' '), (b'', 12, b''),
  (b'', 10, b' '), (b'', 0, b' the '),
  (b' ', 0, b''), (b's ', 0, b' '),
  (b'', 0, b' of '), (b'', 10, b''),
  (b'', 0, b' and '), (b'', 13, b''),
  (b'', 1, b''), (b', ', 0, b' '),
  (b'', 0, b', '), (b' ', 10, b' '),
  (b'', 0, b' in '), (b'', 0, b' to '),
  (b'e ', 0, b' '), (b'', 0, b'"'),
  (b'', 0, b'.'), (b'', 0, b'">'),
  (b'', 0, b'\n'), (b'', 3, b''),
  (b'', 0, b']'), (b'', 0, b' for '),
  (b'', 14, b''), (b'', 2, b''),
  (b'', 0, b' a '), (b'', 0, b' that '),
  (b' ', 10, b''), (b'', 0, b'. '),
  (b'.', 0, b''), (b' ', 0, b', '),
  (b'', 15, b''), (b'', 0, b' with '),
  (b'', 0, b"'"), (b'', 0, b' from '),
  (b'', 0, b' by '), (b'', 16, b''),
  (b'', 17, b''), (b' the ', 0, b''),
  (b'', 4, b''), (b'', 0, b'. The '),
  (b'', 11, b''), (b'', 0, b' on '),
  (b'', 0, b' as '), (b'', 0, b' is '),
  (b'', 7, b''), (b'', 1, b'ing '),
  (b'', 0, b'\n\t'), (b'', 0, b':'),
  (b' ', 0, b'. '), (b'', 0, b'ed '),
  (b'', 20, b''), (b'', 18, b''),
  (b'', 6, b''), (b'', 0, b'('),
  (b'', 10, b', '), (b'', 8, b''),
  (b'', 0, b' at '), (b'', 0, b'ly '),
  (b' the ', 0, b' of '), (b'', 5, b''),
  (b'', 9, b''), (b' ', 10, b', '),
  (b'', 10, b'"'), (b'.', 0, b'('),
  (b'', 11, b' '), (b'', 10, b'">'),
  (b'', 0, b'="'), (b' ', 0, b'.'),
  (b'.com/', 0, b''), (b' the ', 0, b' of the '),
  (b'', 10, b"'"), (b'', 0, b'. This '),
  (b'', 0, b','), (b'.', 0, b' '),
  (b'', 10, b'('), (b'', 10, b'.'),
  (b'', 0, b' not '), (b' ', 0, b'="'),
  (b'', 0, b'er '), (b' ', 11, b' '),
  (b'', 0, b'al '), (b' ', 11, b''),
  (b'', 0, b"='"), (b'', 11, b'"'),
  (b'', 10, b'. '), (b' ', 0, b'('),
  (b'', 0, b'ful '), (b' ', 10, b'. '),
  (b'', 0, b'ive '), (b'', 0, b'less '),
  (b'', 11, b"'"), (b'', 0, b'est '),
  (b' ', 10, b'.'), (b'', 11, b'">'),
  (b' ', 0, b"='"), (b'', 10, b','),
  (b'', 0, b'ize '), (b'', 11, b'.'),
  (b'\xc2\xa0', 0, b''), (b' ', 0, b','),
  (b'', 10, b'="'), (b'', 11, b'="'),
  (b'', 0, b'ous '), (b'', 11, b', '),
  (b'', 10, b"='"), (b' ', 10, b','),
  (b' ', 11, b'="'), (b' ', 11, b', '),
  (b'', 11, b','), (b'', 11, b'('),
  (b'', 11, b'. '), (b' ', 11, b'.'),
  (b'', 11, b"='"), (b' ', 11, b'. '),
  (b' ', 10, b'="'), (b' ', 11, b"='"),
  (b' ', 10, b"='"),
)

"""
How long a run is: what each code stands for on its own, and how many bits are read after it to say
how far past that the run goes.
"""
INSERT_LENGTHS = ((0, 0), (0, 1), (0, 2), (0, 3), (0, 4), (0, 5), (1, 6), (1, 8),
                  (2, 10), (2, 14), (3, 18), (3, 26), (4, 34), (4, 50), (5, 66), (5, 98),
                  (6, 130), (7, 194), (8, 322), (9, 578), (10, 1090), (12, 2114), (14, 6210), (24, 22594))
COPY_LENGTHS = ((0, 2), (0, 3), (0, 4), (0, 5), (0, 6), (0, 7), (0, 8), (0, 9),
                (1, 10), (1, 12), (2, 14), (2, 18), (3, 22), (3, 30), (4, 38), (4, 54),
                (5, 70), (5, 102), (6, 134), (7, 198), (8, 326), (9, 582), (10, 1094), (24, 2118))
BLOCK_LENGTHS = ((2, 1), (2, 5), (2, 9), (2, 13), (3, 17), (3, 25), (3, 33), (3, 41),
                 (4, 49), (4, 65), (4, 81), (4, 97), (5, 113), (5, 145), (5, 177), (5, 209),
                 (6, 241), (6, 305), (7, 369), (8, 497), (9, 753), (10, 1265), (11, 2289), (12, 4337),
                 (13, 8433), (24, 16625))

# Which insert and which copy an insert-and-copy code stands for.
INSERT_RANGES = (0, 0, 8, 8, 0, 16, 8, 16, 16)
COPY_RANGES = (0, 8, 0, 8, 16, 0, 16, 8, 16)

# The order the code-length code's own lengths arrive in, and the fixed code they are read with.
CODE_LENGTH_ORDER = (1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15)
CODE_LENGTH_BITS = (2, 2, 2, 3, 2, 2, 2, 4, 2, 2, 2, 3, 2, 2, 2, 4)
CODE_LENGTH_VALUES = (0, 4, 3, 2, 0, 4, 3, 1, 0, 4, 3, 2, 0, 4, 3, 5)
# The two lengths that repeat what came before them rather than standing for a symbol of their own.
REPEAT_PREVIOUS = 16
REPEAT_ZERO = 17
# What a length is taken to be before any has been read, for a repeat that arrives first.
INITIAL_REPEATED_LENGTH = 8

"""
The four distances a stream starts with, before any of its own have been used - oldest first, so
the one a stream finds in hand as its last distance is the 4 at the end rather than the 16.
"""
INITIAL_DISTANCES = (16, 15, 11, 4)
# How much a page is allowed to decompress into, where the caller does not say.
DEFAULT_MAX_OUTPUT = 100 * 1024 * 1024

"""
The dictionary and the context table, read once and handed to every caller after that.
"""
def load_tables():
  global _TABLES
  if _TABLES is not None:
    return _TABLES
  with _TABLES_LOCK:
    if _TABLES is not None:
      return _TABLES
    try:
      path = os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, "data", "txt", "brotli-dictionary.tx_")
      archive = zipfile.ZipFile(path)
      try:
        names = archive.namelist()
        if len(names) != 1:
          raise BrotliError("unexpected layout in the Brotli table archive")
        raw = archive.read(names[0])
      finally:
        archive.close()
    except BrotliError:
      raise
    except Exception as err:
      raise BrotliError("the Brotli tables could not be read (" + str(err) + ")")
    if len(raw) != DICTIONARY_LENGTH + CONTEXT_LENGTH:
      raise BrotliError("the Brotli tables are not the length they should be")
    if hashlib.sha256(raw[:DICTIONARY_LENGTH]).hexdigest() != DICTIONARY_DIGEST:
      raise BrotliError("the Brotli dictionary is not the one this decoder was written against")
    # Published together, so a reader on another thread never sees one without the other.
    _TABLES = (bytearray(raw[:DICTIONARY_LENGTH]), bytearray(raw[DICTIONARY_LENGTH:]))
    return _TABLES

"""
The stream read a bit at a time, the lowest bit of each byte first, which is the order it was
written in.
"""
class _Reader(object):
  __slots__ = ("data", "length", "position", "accumulator", "available")

  def __init__(self, data):
    self.data = bytearray(data)
    self.length = len(self.data)
    self.position = 0
    self.accumulator = 0
    self.available = 0

  # One bit, with the next byte pulled in once the last one is spent.
  def bit(self):
    if self.available == 0:
      if self.position >= self.length:
        raise BrotliError("the Brotli stream ends in the middle of a code")
      self.accumulator = self.data[self.position]
      self.position += 1
      self.available = 8
    value = self.accumulator & 1
    self.accumulator >>= 1
    self.available -= 1
    return value

  # As many bits as asked for, the first one read being the lowest of the value.
  def bits(self, count):
    value = 0
    for shift in range(count):
      value |= self.bit() << shift
    return value

  """
  The next bits without spending them, for a code that is looked up before its length is known.

  What lies past the end of the stream reads as zero rather than as an error: the code being looked
  up may not need those bits, and the ones it does need are spent in the usual way.
  """
  def peek(self, count):
    saved = (self.position, self.accumulator, self.available)
    value = 0
    try:
      for shift in range(count):
        if self.available == 0 and self.position >= self.length:
          break
        value |= self.bit() << shift
    finally:
      self.position, self.accumulator, self.available = saved
    return value

  # Spend bits a lookup has already accounted for.
  def skip(self, count):
    for _ in range(count):
      self.bit()

  # Drop what is left of the byte in hand, for the parts written out whole bytes at a time.
  def align(self):
    self.accumulator = 0
    self.available = 0

  # Whole bytes, taken once the reader is back on a byte boundary.
  def take(self, count):
    if self.position + count > self.length:
      raise BrotliError("the Brotli stream ends in the middle of a block")
    chunk = self.data[self.position:self.position + count]
    self.position += count
    return chunk

"""
A prefix code, held as the number of codes at each length and the symbols in the order their codes
run - which is what reading one bit at a time asks for. No lookup table is built: a page is small
enough that the difference is not worth the memory.
"""
class _Code(object):
  __slots__ = ("counts", "symbols", "single")

  def __init__(self, lengths):
    counts = [0] * 16
    symbols = []
    for length in lengths:
      if length:
        counts[length] += 1
    for length in range(1, 16):
      if counts[length]:
        for symbol in range(len(lengths)):
          if lengths[symbol] == length:
            symbols.append(symbol)
    if not symbols:
      raise BrotliError("a Brotli prefix code stands for no symbol at all")
    self.counts = counts
    self.symbols = symbols
    # A code of one symbol is read without spending a bit: there is nothing to tell apart.
    self.single = symbols[0] if len(symbols) == 1 else None

  def read(self, reader):
    if self.single is not None:
      return self.single
    code = 0
    first = 0
    index = 0
    for length in range(1, 16):
      code |= reader.bit()
      count = self.counts[length]
      if code - first < count:
        return self.symbols[index + (code - first)]
      index += count
      first = (first + count) << 1
      code <<= 1
    raise BrotliError("a Brotli prefix code runs past the length a code can have")

"""
A code given as the few symbols it stands for, rather than as a length for every symbol.
"""
def _read_simple_code(reader, alphabet_size):
  width = max(1, (alphabet_size - 1).bit_length())
  count = reader.bits(2) + 1
  symbols = []
  for _ in range(count):
    symbol = reader.bits(width)
    if symbol >= alphabet_size or symbol in symbols:
      raise BrotliError("a Brotli prefix code names a symbol twice or one that does not exist")
    symbols.append(symbol)
  lengths = [0] * alphabet_size
  if count == 1:
    lengths[symbols[0]] = 1
  elif count == 2:
    lengths[symbols[0]] = lengths[symbols[1]] = 1
  elif count == 3:
    lengths[symbols[0]] = 1
    lengths[symbols[1]] = lengths[symbols[2]] = 2
  # Four symbols come either as an even code or as one that favours the first of them.
  elif reader.bit():
    lengths[symbols[0]] = 1
    lengths[symbols[1]] = 2
    lengths[symbols[2]] = lengths[symbols[3]] = 3
  else:
    for symbol in symbols:
      lengths[symbol] = 2
  return _Code(lengths)

"""
A code given as a length for every symbol, those lengths being written out with a code of their own.
"""
def _read_complex_code(reader, alphabet_size, skip):
  meta_lengths = [0] * 18
  space = 32
  used = 0
  for index in range(skip, 18):
    lookup = reader.peek(4)
    reader.skip(CODE_LENGTH_BITS[lookup])
    length = CODE_LENGTH_VALUES[lookup]
    meta_lengths[CODE_LENGTH_ORDER[index]] = length
    if length:
      space -= 32 >> length
      used += 1
      if space <= 0:
        break
  if used != 1 and space != 0:
    raise BrotliError("the lengths of a Brotli code do not add up to a code")
  meta_code = _Code(meta_lengths)

  lengths = [0] * alphabet_size
  symbol = 0
  space = 32768
  used = 0
  previous = INITIAL_REPEATED_LENGTH
  repeat = 0
  repeat_length = 0
  while symbol < alphabet_size and space > 0:
    length = meta_code.read(reader)
    if length < REPEAT_PREVIOUS:
      lengths[symbol] = length
      symbol += 1
      if length:
        previous = length
        space -= 32768 >> length
        used += 1
      repeat = 0
      continue
    """
    The two lengths that stand for a run rather than for a symbol: one repeats the last length
    used, the other repeats nothing at all. A run carried straight on from the one before it counts
    from where that one left off, rather than starting again.
    """
    extra_bits = length - 14
    written = previous if length == REPEAT_PREVIOUS else 0
    if repeat_length != written:
      repeat = 0
      repeat_length = written
    before = repeat
    if repeat > 0:
      repeat = (repeat - 2) << extra_bits
    repeat += reader.bits(extra_bits) + 3
    run = repeat - before
    if symbol + run > alphabet_size:
      raise BrotliError("a Brotli code repeats past the symbols it has")
    for _ in range(run):
      lengths[symbol] = written
      symbol += 1
    if written:
      space -= (32768 >> written) * run
      used += run
  if used != 1 and space != 0:
    raise BrotliError("the lengths of a Brotli code do not add up to a code")
  return _Code(lengths)

# A prefix code, however it was written out.
def _read_code(reader, alphabet_size):
  marker = reader.bits(2)
  if marker == 1:
    return _read_simple_code(reader, alphabet_size)
  return _read_complex_code(reader, alphabet_size, marker)

"""
How many kinds of block a meta-block switches between, written out as the count it is short of.
"""
def _read_type_count(reader):
  if not reader.bit():
    return 1
  width = reader.bits(3)
  if width == 0:
    return 2
  return reader.bits(width) + (1 << width) + 1

"""
Which tree each context is read with, undone from the runs and the ordering it was sent in.
"""
def _read_context_map(reader, tree_count, size):
  run_length_max = 0
  if reader.bit():
    run_length_max = reader.bits(4) + 1
  code = _read_code(reader, tree_count + run_length_max)
  values = []
  while len(values) < size:
    symbol = code.read(reader)
    if symbol == 0:
      values.append(0)
    elif symbol <= run_length_max:
      run = (1 << symbol) + reader.bits(symbol)
      if len(values) + run > size:
        raise BrotliError("a Brotli context map runs past its own length")
      values.extend([0] * run)
    else:
      values.append(symbol - run_length_max)
  # Sent as how far each value had moved since it was last used, rather than as the value itself.
  if reader.bit():
    order = list(range(256))
    for index in range(size):
      position = values[index]
      value = order[position]
      values[index] = value
      del order[position]
      order.insert(0, value)
  for value in values:
    if value >= tree_count:
      raise BrotliError("a Brotli context map names a tree that was never sent")
  return values

# The first character of a word written as a capital, or every character of it.
def _upper_case(word, once):
  result = bytearray(word)
  index = 0
  while index < len(result):
    first = result[index]
    if first < 0xC0:
      if 0x61 <= first <= 0x7A:
        result[index] ^= 32
      index += 1
    elif first < 0xE0:
      if index + 1 < len(result):
        result[index + 1] ^= 32
      index += 2
    else:
      if index + 2 < len(result):
        result[index + 2] ^= 5
      index += 3
    if once:
      break
  return result

"""
A dictionary word as the transform asked for leaves it.
"""
def _transform(word, transform_id):
  if transform_id >= len(TRANSFORMS):
    raise BrotliError("a Brotli stream asks for a word transform that does not exist")
  prefix, kind, suffix = TRANSFORMS[transform_id]
  if kind == TRANSFORM_IDENTITY:
    body = bytes(word)
  elif kind < TRANSFORM_UPPERCASE_FIRST:
    body = bytes(word[:max(0, len(word) - kind)])
  elif kind == TRANSFORM_UPPERCASE_FIRST:
    body = bytes(_upper_case(word, True))
  elif kind == TRANSFORM_UPPERCASE_ALL:
    body = bytes(_upper_case(word, False))
  else:
    body = bytes(word[min(len(word), kind - TRANSFORM_OMIT_FIRST + 1):])
  return prefix + body + suffix

"""
How far back a copy may reach: where the window ends, or where the output begins.
"""
def _read_window_bits(reader):
  if not reader.bit():
    return 16
  value = reader.bits(3)
  if value:
    return 17 + value
  value = reader.bits(3)
  if value == 1:
    raise BrotliError("the Brotli stream asks for a window this decoder does not read")
  if value:
    return 8 + value
  return 17

"""
The distance a code stands for, which is either one of the last four used or one spelled out.
"""
def _read_distance(reader, code, distances, index, postfix, direct):
  if code == 0:
    return distances[index & 3]
  if code < 4:
    return distances[(index - code) & 3]
  if code < 16:
    if code < 10:
      base = distances[index & 3]
      step = ((code - 4) >> 1) + 1
    else:
      base = distances[(index - 1) & 3]
      step = ((code - 10) >> 1) + 1
    distance = base + (step if code & 1 else -step)
    if distance <= 0:
      raise BrotliError("a Brotli distance reaches back past the start of the output")
    return distance
  value = code - 16
  if value < direct:
    return value + 1
  value -= direct
  extra_bits = 1 + (value >> (postfix + 1))
  high = value >> postfix
  low = value & ((1 << postfix) - 1)
  offset = ((2 + (high & 1)) << extra_bits) - 4
  return ((offset + reader.bits(extra_bits)) << postfix) + low + direct + 1

"""
Read a Brotli stream and hand back what it stands for.

Stopped at 'max_output' whatever the stream says: a few hundred bytes can name gigabytes, and
reading that whole is how a target empties the memory of the machine testing it.
"""
def decompress(data, max_output=DEFAULT_MAX_OUTPUT):
  dictionary, context_table = load_tables()
  reader = _Reader(data)
  max_backward = (1 << _read_window_bits(reader)) - 16

  output = bytearray()
  distances = list(INITIAL_DISTANCES)
  distance_index = len(distances) - 1

  while True:
    last = reader.bit()
    if last and reader.bit():
      break

    nibbles = reader.bits(2)
    if nibbles == 3:
      # Something the stream carries for its own reasons and nothing is read from: skipped whole.
      if reader.bit():
        raise BrotliError("a Brotli meta-block sets a bit that has to be zero")
      count = reader.bits(2)
      skip = 0
      for index in range(count):
        piece = reader.bits(8)
        if index + 1 == count and count > 1 and piece == 0:
          raise BrotliError("a Brotli meta-block gives its length with a spare byte")
        skip |= piece << (index * 8)
      if count:
        skip += 1
      reader.align()
      reader.take(skip)
      if last:
        break
      continue

    remaining = 0
    for index in range(nibbles + 4):
      piece = reader.bits(4)
      if index + 1 == nibbles + 4 and nibbles > 0 and piece == 0:
        raise BrotliError("a Brotli meta-block gives its length with a spare nibble")
      remaining |= piece << (index * 4)
    remaining += 1

    if not last and reader.bit():
      # Written out as it stands, so it is taken as it stands.
      reader.align()
      chunk = reader.take(remaining)
      if len(output) + len(chunk) > max_output:
        raise BrotliError("the Brotli stream decompresses to more than is allowed")
      output.extend(chunk)
      continue

    """
    How many kinds of literal, command and distance block this meta-block switches between, and the
    codes that say which kind comes next and how long it runs for. Where there is only one kind,
    nothing switches and the count is left past anything the meta-block can reach.
    """
    kinds = []
    types = [0, 0, 0]
    previous_types = [1, 1, 1]
    counts = [0, 0, 0]
    type_codes = [None, None, None]
    count_codes = [None, None, None]
    for category in range(3):
      count = _read_type_count(reader)
      kinds.append(count)
      if count > 1:
        type_codes[category] = _read_code(reader, count + 2)
        count_codes[category] = _read_code(reader, len(BLOCK_LENGTHS))
        extra, offset = BLOCK_LENGTHS[count_codes[category].read(reader)]
        counts[category] = offset + reader.bits(extra)
      else:
        counts[category] = 1 << 30

    postfix = reader.bits(2)
    direct = reader.bits(4) << postfix
    context_modes = [reader.bits(2) for _ in range(kinds[0])]

    literal_trees = _read_type_count(reader)
    if literal_trees > 1:
      literal_map = _read_context_map(reader, literal_trees, kinds[0] * 64)
    else:
      literal_map = [0] * (kinds[0] * 64)
    distance_trees = _read_type_count(reader)
    if distance_trees > 1:
      distance_map = _read_context_map(reader, distance_trees, kinds[2] * 4)
    else:
      distance_map = [0] * (kinds[2] * 4)

    literal_codes = [_read_code(reader, 256) for _ in range(literal_trees)]
    command_codes = [_read_code(reader, 704) for _ in range(kinds[1])]
    distance_codes = [_read_code(reader, 16 + direct + (48 << postfix)) for _ in range(distance_trees)]

    # The next kind of block of one category, and how long it runs for.
    def switch(category):
      symbol = type_codes[category].read(reader)
      if symbol == 0:
        following = previous_types[category]
      elif symbol == 1:
        following = (types[category] + 1) % kinds[category]
      else:
        following = symbol - 2
      if following >= kinds[category]:
        raise BrotliError("a Brotli block switch names a kind of block that was not sent")
      previous_types[category] = types[category]
      types[category] = following
      extra, offset = BLOCK_LENGTHS[count_codes[category].read(reader)]
      counts[category] = offset + reader.bits(extra)

    while remaining > 0:
      if counts[1] == 0:
        switch(1)
      counts[1] -= 1
      command = command_codes[types[1]].read(reader)
      section = command >> 6
      carries_distance = section >= 2
      if carries_distance:
        section -= 2
      extra, offset = INSERT_LENGTHS[INSERT_RANGES[section] + ((command >> 3) & 7)]
      insert_length = offset + reader.bits(extra)
      extra, offset = COPY_LENGTHS[COPY_RANGES[section] + (command & 7)]
      copy_length = offset + reader.bits(extra)

      if insert_length > remaining:
        raise BrotliError("a Brotli command writes past the end of its meta-block")
      if len(output) + insert_length > max_output:
        raise BrotliError("the Brotli stream decompresses to more than is allowed")
      for _ in range(insert_length):
        if counts[0] == 0:
          switch(0)
        counts[0] -= 1
        # Which tree a character is read with follows from the two characters before it.
        base = context_modes[types[0]] << 9
        first = output[-1] if output else 0
        second = output[-2] if len(output) > 1 else 0
        context = context_table[base + first] | context_table[base + 256 + second]
        output.append(literal_codes[literal_map[(types[0] << 6) + context]].read(reader))
      remaining -= insert_length
      # The last command of a meta-block may end on its characters, with nothing copied after them.
      if remaining <= 0:
        break

      if carries_distance:
        if counts[2] == 0:
          switch(2)
        counts[2] -= 1
        context = copy_length - 2 if copy_length < 5 else 3
        code = distance_codes[distance_map[(types[2] << 2) + context]].read(reader)
      else:
        code = 0
      distance = _read_distance(reader, code, distances, distance_index, postfix, direct)

      reach = max_backward if max_backward < len(output) else len(output)
      if distance > reach:
        # Past everything written so far, which is how the dictionary is asked for.
        word_id = distance - reach - 1
        if copy_length < 4 or copy_length > 24:
          raise BrotliError("a Brotli dictionary word is asked for at a length it cannot have")
        words = 1 << WORD_SIZE_BITS[copy_length]
        offset = WORD_OFFSETS[copy_length] + (word_id % words) * copy_length
        piece = _transform(dictionary[offset:offset + copy_length], word_id // words)
        if len(piece) > remaining:
          raise BrotliError("a Brotli dictionary word writes past the end of its meta-block")
        if len(output) + len(piece) > max_output:
          raise BrotliError("the Brotli stream decompresses to more than is allowed")
        output.extend(piece)
        remaining -= len(piece)
        continue

      if copy_length > remaining:
        raise BrotliError("a Brotli copy writes past the end of its meta-block")
      if len(output) + copy_length > max_output:
        raise BrotliError("the Brotli stream decompresses to more than is allowed")
      # A distance used again is not put back: only one spelled out afresh moves the four along.
      if code != 0:
        distance_index += 1
        distances[distance_index & 3] = distance
      start = len(output) - distance
      for step in range(copy_length):
        output.append(output[start + step])
      remaining -= copy_length

    if last:
      break

  return bytes(output)
