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

import binascii
import os
import sys
import unittest
import unittest.mock as mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.argv = ["commix.py"]

from src.utils import settings
from src.core.techniques.oob import oob_payloads as payloads
from src.core.techniques.oob import oob_injector
from src.core.oob.provider import Interaction


def _hex(text):
    return binascii.hexlify(text.encode(settings.DEFAULT_CODEC)).decode()


class MockChannel:
    """Minimal OOB channel returning a fixed set of DNS interactions."""

    def __init__(self):
        self._interactions = {}  # token -> [Interaction]
        self._labels = {}        # id(interaction) -> [label, ...]
        self._np_counter = 0

    def add(self, token, index, total, hex_data):
        label0 = str(index) + "-" + (str(total) if total is not None else "")
        itr = Interaction(protocol="dns", identifier="dummy." + token, raw_request="")
        self._labels[id(itr)] = [label0] + hex_data if isinstance(hex_data, list) else [label0, hex_data]
        self._interactions.setdefault(token, []).append(itr)
        return itr

    def seen(self, token, protocol=None):
        hits = list(self._interactions.get(token, []))
        return [i for i in hits if i.protocol == protocol] if protocol else hits

    def data_of(self, interaction):
        return self._labels.get(id(interaction), [])

    def poll_now(self):
        pass

    def new_payload(self):
        self._np_counter += 1
        token = "t{:012d}".format(self._np_counter)
        return token, "corrid" + token + ".oast.fun"


# ---------------------------------------------------------------------------
# decode_dns_output — pure reassembly from a chunks dict
# ---------------------------------------------------------------------------

class TestDecodeDnsOutput(unittest.TestCase):

    def test_single_chunk_ascii(self):
        self.assertEqual(payloads.decode_dns_output({1: _hex("hello")}), "hello")

    def test_multiple_chunks_in_order(self):
        hexed = _hex("hello world")
        mid = (len(hexed) // 2) & ~1  # keep even so no half-byte
        self.assertEqual(
            payloads.decode_dns_output({1: hexed[:mid], 2: hexed[mid:]}),
            "hello world",
        )

    def test_chunks_out_of_order_reassembled_correctly(self):
        hexed = _hex("abcdef")
        mid = (len(hexed) // 2) & ~1
        # deliver chunk 2 first
        self.assertEqual(
            payloads.decode_dns_output({2: hexed[mid:], 1: hexed[:mid]}),
            "abcdef",
        )

    def test_trailing_newline_stripped(self):
        self.assertEqual(payloads.decode_dns_output({1: _hex("hello\n")}), "hello")

    def test_trailing_crlf_stripped(self):
        self.assertEqual(payloads.decode_dns_output({1: _hex("hello\r\n")}), "hello")

    def test_empty_chunks_returns_empty_string(self):
        self.assertEqual(payloads.decode_dns_output({}), "")

    def test_non_ascii_bytes_round_trip(self):
        # od -tx1 encodes every byte, so non-ASCII survives the round trip.
        raw = b"\xc3\xa9l\xc3\xa8ve"  # UTF-8 "élève"
        hexed = binascii.hexlify(raw).decode()
        result = payloads.decode_dns_output({1: hexed})
        self.assertEqual(result.encode(settings.DEFAULT_CODEC, errors="replace"), raw)

    def test_gap_in_chunk_indices_returns_partial_decode(self):
        # decode_dns_output joins whatever chunks arrived in index order; a gap does not
        # crash it.  INCOMPLETE_OUTPUT is set by _dns_output after the loop, not here.
        hexed = _hex("abcdef")
        third = (len(hexed) // 3) & ~1
        # chunks 1 and 3 present; chunk 2 missing — result is defined but not "abcdef"
        result = payloads.decode_dns_output({1: hexed[:third], 3: hexed[third * 2:]})
        self.assertIsInstance(result, str)

    def test_contiguous_chunks_do_not_set_incomplete(self):
        hexed = _hex("hello world")
        mid = (len(hexed) // 2) & ~1
        settings.INCOMPLETE_OUTPUT = False
        payloads.decode_dns_output({1: hexed[:mid], 2: hexed[mid:]})
        self.assertFalse(settings.INCOMPLETE_OUTPUT)

    def test_hex_labels_are_lowercased_by_resolver(self):
        # A resolver may uppercase labels; decode_dns_output must still work.
        hexed = _hex("hi").upper()
        self.assertEqual(payloads.decode_dns_output({1: hexed}), "hi")


# ---------------------------------------------------------------------------
# _dns_output — the chunk-collection loop that drives the mock channel
# ---------------------------------------------------------------------------

class TestDnsOutputLoop(unittest.TestCase):

    def setUp(self):
        settings.OOB_TIMEOUT = 15
        settings.INCOMPLETE_OUTPUT = False

    # --- loop-format (separator `;`/`\n`): label carries "index-total" ---

    def test_loop_format_single_chunk(self):
        token = "aaa"
        ch = MockChannel()
        ch.add(token, index=1, total=1, hex_data=_hex("hello"))
        # time: call 1 → deadline base (0), call 2 → inside loop, never reached because
        # total is known and len(chunks)>=total breaks before the deadline check.
        with mock.patch("time.time", side_effect=[0, 0]):
            with mock.patch("time.sleep"):
                result = oob_injector._dns_output(ch, token)
        self.assertEqual(result, "hello")

    def test_loop_format_multi_chunk_all_arrive(self):
        token = "bbb"
        hexed = _hex("hello world")
        mid = (len(hexed) // 2) & ~1
        ch = MockChannel()
        ch.add(token, index=1, total=2, hex_data=hexed[:mid])
        ch.add(token, index=2, total=2, hex_data=hexed[mid:])
        with mock.patch("time.time", side_effect=[0, 0]):
            with mock.patch("time.sleep"):
                result = oob_injector._dns_output(ch, token)
        self.assertEqual(result, "hello world")

    def test_loop_format_out_of_order_arrival(self):
        # Chunks registered in reverse order; index key must still sort correctly.
        token = "ccc"
        hexed = _hex("xyz123")
        mid = (len(hexed) // 2) & ~1
        ch = MockChannel()
        ch.add(token, index=2, total=2, hex_data=hexed[mid:])
        ch.add(token, index=1, total=2, hex_data=hexed[:mid])
        with mock.patch("time.time", side_effect=[0, 0]):
            with mock.patch("time.sleep"):
                result = oob_injector._dns_output(ch, token)
        self.assertEqual(result, "xyz123")

    # --- xargs-format (separator `&`/`|`): label carries "index-" (no total) ---
    # quiet_polls reaches 2 after two iterations with no new chunks → break.

    def test_xargs_format_exits_on_quiet_polls(self):
        token = "ddd"
        ch = MockChannel()
        ch.add(token, index=1, total=None, hex_data=_hex("world"))
        # time calls: [0] deadline base, [0] iter1 deadline check, [0] iter2 check.
        # iter3: quiet_polls==2 → break before deadline check.
        with mock.patch("time.time", side_effect=[0, 0, 0]):
            with mock.patch("time.sleep"):
                result = oob_injector._dns_output(ch, token)
        self.assertEqual(result, "world")

    def test_xargs_format_hex_label_split_across_parts(self):
        # `data_of` may return more than two elements; labels[1:] are joined.
        token = "eee"
        ch = MockChannel()
        ch.add(token, index=1, total=None, hex_data=["61", "62"])  # "ab" split
        with mock.patch("time.time", side_effect=[0, 0, 0]):
            with mock.patch("time.sleep"):
                result = oob_injector._dns_output(ch, token)
        self.assertEqual(result, "ab")

    # --- timeout and partial output ---

    def test_timeout_partial_chunks_sets_incomplete(self):
        token = "fff"
        hexed = _hex("hi there")
        mid = (len(hexed) // 2) & ~1
        ch = MockChannel()
        ch.add(token, index=1, total=2, hex_data=hexed[:mid])
        # chunk 2 never arrives; deadline passes immediately inside the loop.
        # time: call 1 → 0 (deadline base, deadline = 30), call 2 → 9999 (past deadline).
        settings.INCOMPLETE_OUTPUT = False
        with mock.patch("time.time", side_effect=[0, 9999]):
            with mock.patch("time.sleep"):
                oob_injector._dns_output(ch, token)
        self.assertTrue(settings.INCOMPLETE_OUTPUT)

    def test_no_interactions_returns_empty_string(self):
        ch = MockChannel()
        with mock.patch("time.time", side_effect=[0, 9999]):
            with mock.patch("time.sleep"):
                result = oob_injector._dns_output(ch, "ggg")
        self.assertEqual(result, "")

    def test_interaction_with_too_few_labels_skipped(self):
        # A label list shorter than 2 must be silently ignored.
        token = "hhh"
        ch = MockChannel()
        itr = Interaction(protocol="dns", identifier="dummy." + token, raw_request="")
        ch._labels[id(itr)] = ["1-1"]  # only one label, no hex part
        ch._interactions[token] = [itr]
        with mock.patch("time.time", side_effect=[0, 9999]):
            with mock.patch("time.sleep"):
                result = oob_injector._dns_output(ch, token)
        self.assertEqual(result, "")

    def test_non_digit_index_label_skipped(self):
        # A label whose first part is not a digit must not crash or add to chunks.
        token = "iii"
        ch = MockChannel()
        itr = Interaction(protocol="dns", identifier="dummy." + token, raw_request="")
        ch._labels[id(itr)] = ["probe-1", _hex("x")]  # "probe" is not a digit
        ch._interactions[token] = [itr]
        with mock.patch("time.time", side_effect=[0, 9999]):
            with mock.patch("time.sleep"):
                result = oob_injector._dns_output(ch, token)
        self.assertEqual(result, "")

    def test_gap_in_chunk_indices_sets_incomplete(self):
        # Chunks 1 and 3 arrive (total=3); chunk 2 never does.
        # Deadline passes before total is satisfied → INCOMPLETE_OUTPUT set.
        token = "kkk"
        hexed = _hex("abcdef")
        third = (len(hexed) // 3) & ~1
        ch = MockChannel()
        ch.add(token, index=1, total=3, hex_data=hexed[:third])
        ch.add(token, index=3, total=3, hex_data=hexed[third * 2:])
        settings.INCOMPLETE_OUTPUT = False
        # time: call 1 → 0 (deadline=30), call 2 → 9999 (past deadline immediately)
        with mock.patch("time.time", side_effect=[0, 9999]):
            with mock.patch("time.sleep"):
                oob_injector._dns_output(ch, token)
        self.assertTrue(settings.INCOMPLETE_OUTPUT)

    def test_trailing_newline_stripped_end_to_end(self):
        # The pipeline always appends a newline; _dns_output must strip it.
        token = "jjj"
        ch = MockChannel()
        ch.add(token, index=1, total=1, hex_data=_hex("result\n"))
        with mock.patch("time.time", side_effect=[0, 0]):
            with mock.patch("time.sleep"):
                result = oob_injector._dns_output(ch, token)
        self.assertEqual(result, "result")


# ---------------------------------------------------------------------------
# Gap 1: dns_exfil_command label format vs. _dns_output expectations
# ---------------------------------------------------------------------------

class TestDnsExfilCommandFormat(unittest.TestCase):

    def setUp(self):
        settings.TARGET_OS = settings.OS.UNIX

    def tearDown(self):
        settings.TARGET_OS = settings.OS.UNIX

    # Loop-format separators (`;` and `\n`) use a while-loop that knows its total.
    def test_loop_separator_contains_index_total_pattern(self):
        cmd = payloads.dns_exfil_command("tok.oast.fun", "id", ";")
        self.assertIn("$n-$t", cmd)

    def test_loop_separator_encodes_output_with_od(self):
        cmd = payloads.dns_exfil_command("tok.oast.fun", "id", ";")
        self.assertIn("od -An -v -tx1", cmd)

    def test_loop_separator_contains_lookup_command(self):
        cmd = payloads.dns_exfil_command("tok.oast.fun", "id", ";")
        self.assertIn("nslookup", cmd)

    # Xargs-format separators (`&` and `|`) number chunks with `cat -n` + `tr`.
    def test_xargs_separator_contains_cat_n(self):
        cmd = payloads.dns_exfil_command("tok.oast.fun", "id", "&")
        self.assertIn("cat -n", cmd)

    def test_xargs_separator_converts_tab_to_dot(self):
        cmd = payloads.dns_exfil_command("tok.oast.fun", "id", "&")
        self.assertIn("tr '\\t' '.'", cmd)

    def test_xargs_separator_has_no_total_label(self):
        # Xargs format produces plain numbering ("1.<hex>"), not "1-3"
        cmd = payloads.dns_exfil_command("tok.oast.fun", "id", "&")
        self.assertNotIn("$n-$t", cmd)

    def test_xargs_label_parses_in_dns_output_loop(self):
        # labels[0] = "1" (no dash) is still parsed correctly via partition("-").
        token = "parsexargs"
        ch = MockChannel()
        hexed = _hex("ok")
        itr = Interaction(protocol="dns", identifier="dummy." + token, raw_request="")
        ch._labels[id(itr)] = ["1", hexed]   # plain index, no dash
        ch._interactions[token] = [itr]
        with mock.patch("time.time", side_effect=[0, 0, 0]):
            with mock.patch("time.sleep"):
                result = oob_injector._dns_output(ch, token)
        self.assertEqual(result, "ok")

    def test_windows_uses_powershell_and_bitconverter(self):
        settings.TARGET_OS = settings.OS.WINDOWS
        cmd = payloads.dns_exfil_command("tok.oast.fun", "id", "&")
        self.assertIn("powershell", cmd.lower())
        self.assertIn("BitConverter", cmd)

    def test_windows_label_carries_index_total(self):
        settings.TARGET_OS = settings.OS.WINDOWS
        cmd = payloads.dns_exfil_command("tok.oast.fun", "id", "&")
        # PowerShell embeds ($i/chunk)+1 and $t in the nslookup target
        self.assertIn("$t", cmd)
        self.assertIn("nslookup", cmd)


# ---------------------------------------------------------------------------
# Gap 2: Interactsh identifier parsing (_token_of / data_of)
# ---------------------------------------------------------------------------

class TestInteractshParsing(unittest.TestCase):

    CORR = "aabbccddeeaabbccddee"   # 20-char correlation id
    TOKEN = "aaabbbcccddd"           # 13-char probe token

    def _client(self):
        from src.core.oob.interactsh import Interactsh
        c = Interactsh.__new__(Interactsh)
        c.correlation_id = self.CORR
        c.domain = "oast.fun"
        return c

    def _itr(self, identifier):
        return Interaction(protocol="dns", identifier=identifier, raw_request="")

    def test_token_of_plain_probe(self):
        identifier = self.CORR + self.TOKEN + ".oast.fun"
        self.assertEqual(self._client()._token_of(self._itr(identifier)), self.TOKEN)

    def test_token_of_data_carrying(self):
        identifier = "1-3.deadbeef." + self.CORR + self.TOKEN + ".oast.fun"
        self.assertEqual(self._client()._token_of(self._itr(identifier)), self.TOKEN)

    def test_token_of_unknown_returns_none(self):
        self.assertIsNone(self._client()._token_of(self._itr("unknown.label.oast.fun")))

    def test_data_of_plain_probe_is_empty(self):
        identifier = self.CORR + self.TOKEN + ".oast.fun"
        self.assertEqual(self._client().data_of(self._itr(identifier)), [])

    def test_data_of_single_chunk(self):
        chunk = "6865786f6b"
        identifier = "1-1." + chunk + "." + self.CORR + self.TOKEN + ".oast.fun"
        self.assertEqual(self._client().data_of(self._itr(identifier)), ["1-1", chunk])

    def test_data_of_multipart_chunk(self):
        identifier = "1-2.part1.part2." + self.CORR + self.TOKEN + ".oast.fun"
        self.assertEqual(self._client().data_of(self._itr(identifier)), ["1-2", "part1", "part2"])

    def test_data_and_token_agree_on_boundary(self):
        # data_of and _token_of must find the same boundary label.
        chunk = "6162"
        identifier = "1-1." + chunk + "." + self.CORR + self.TOKEN + ".oast.fun"
        c = self._client()
        itr = self._itr(identifier)
        self.assertEqual(c._token_of(itr), self.TOKEN)
        labels = c.data_of(itr)
        self.assertEqual(labels[0], "1-1")
        self.assertEqual(labels[1], chunk)

    def test_data_of_xargs_format_plain_index(self):
        # Xargs produces "1.<hex>.<corr+token>.<domain>" — label0 is a plain number.
        chunk = "6162"
        identifier = "1." + chunk + "." + self.CORR + self.TOKEN + ".oast.fun"
        labels = self._client().data_of(self._itr(identifier))
        self.assertEqual(labels, ["1", chunk])

    def test_token_of_is_case_insensitive(self):
        # interactsh identifiers arrive lowercased; _token_of lower()s the label.
        identifier = (self.CORR + self.TOKEN + ".oast.fun").upper()
        self.assertEqual(self._client()._token_of(self._itr(identifier)), self.TOKEN)


# ---------------------------------------------------------------------------
# Gap 3: injection() retry logic
# ---------------------------------------------------------------------------

class TestInjectionRetry(unittest.TestCase):

    def setUp(self):
        settings.TARGET_OS = settings.OS.UNIX
        settings.OOB_EVAL = False
        settings.OOB_TRANSPORT = "dns"
        settings.OOB_DNS_ATTEMPTS = 2
        settings.OOB_TIMEOUT = 15
        settings.INCOMPLETE_OUTPUT = False
        self._ch = MockChannel()
        settings.OOB_CHANNEL = self._ch

    def tearDown(self):
        settings.OOB_CHANNEL = None
        settings.OOB_TRANSPORT = ""

    def _run(self, dns_side_effects):
        with mock.patch("src.core.techniques.oob.oob_injector._dns_output",
                        side_effect=dns_side_effects) as m:
            with mock.patch("src.core.controller.handler.oob_inject"):
                result = oob_injector.injection(";", "id", "", "", " ", "GET",
                                                "http://t/", "p")
        return result, m

    def test_retries_on_empty_first_response(self):
        result, m = self._run(["", "data"])
        self.assertEqual(result, "data")
        self.assertEqual(m.call_count, 2)

    def test_no_retry_when_first_attempt_succeeds(self):
        result, m = self._run(["first"])
        self.assertEqual(result, "first")
        self.assertEqual(m.call_count, 1)

    def test_both_empty_returns_empty_after_attempts(self):
        result, m = self._run(["", ""])
        self.assertEqual(result, "")
        self.assertEqual(m.call_count, 2)

    def test_attempts_1_never_retries(self):
        settings.OOB_DNS_ATTEMPTS = 1
        result, m = self._run([""])
        self.assertEqual(result, "")
        self.assertEqual(m.call_count, 1)

    def test_null_channel_returns_empty_immediately(self):
        settings.OOB_CHANNEL = None
        with mock.patch("src.core.techniques.oob.oob_injector._dns_output") as m:
            result = oob_injector.injection(";", "id", "", "", " ", "GET", "http://t/", "p")
        self.assertEqual(result, "")
        m.assert_not_called()

    def test_unsupported_transport_returns_empty_immediately(self):
        settings.OOB_TRANSPORT = "notreal"
        with mock.patch("src.core.techniques.oob.oob_injector._dns_output") as m:
            result = oob_injector.injection(";", "id", "", "", " ", "GET", "http://t/", "p")
        self.assertEqual(result, "")
        m.assert_not_called()


# ---------------------------------------------------------------------------
# Gap 4: heuristic_payload DNS probe
# ---------------------------------------------------------------------------

class TestHeuristicPayload(unittest.TestCase):

    def setUp(self):
        settings.TARGET_OS = settings.OS.UNIX
        settings.OOB_SCHEME = "https"

    def tearDown(self):
        settings.TARGET_OS = settings.OS.UNIX

    def test_posix_produces_three_probes(self):
        ch = MockChannel()
        _, probes = payloads.heuristic_payload(ch, settings.OS.UNIX)
        self.assertEqual(len(probes), 3)

    def test_windows_produces_three_probes(self):
        ch = MockChannel()
        _, probes = payloads.heuristic_payload(ch, settings.OS.WINDOWS)
        self.assertEqual(len(probes), 3)

    def test_posix_probe_transports_in_order(self):
        ch = MockChannel()
        _, probes = payloads.heuristic_payload(ch, settings.OS.UNIX)
        # pairs = ((";","curl"), ("&","dns"), ("|","dns"))
        self.assertEqual([t for _, t in probes], ["curl", "dns", "dns"])

    def test_windows_probe_transports_in_order(self):
        ch = MockChannel()
        _, probes = payloads.heuristic_payload(ch, settings.OS.WINDOWS)
        # pairs = (("&","curl"), ("&","dns"), ("|","dns"))
        self.assertEqual([t for _, t in probes], ["curl", "dns", "dns"])

    def test_probe_tokens_are_unique(self):
        ch = MockChannel()
        _, probes = payloads.heuristic_payload(ch, settings.OS.UNIX)
        tokens = [tok for tok, _ in probes]
        self.assertEqual(len(tokens), len(set(tokens)))

    def test_payload_contains_dns_lookup_command(self):
        ch = MockChannel()
        payload, _ = payloads.heuristic_payload(ch, settings.OS.UNIX)
        self.assertIn("nslookup", payload)

    def test_payload_contains_curl_command(self):
        ch = MockChannel()
        payload, _ = payloads.heuristic_payload(ch, settings.OS.UNIX)
        self.assertIn("curl", payload)

    def test_each_probe_token_present_in_payload(self):
        # The hostname for each probe embeds its token; the payload must reference it.
        ch = MockChannel()
        payload, probes = payloads.heuristic_payload(ch, settings.OS.UNIX)
        for token, _ in probes:
            self.assertIn(token, payload)

    def test_payload_is_nonempty_string(self):
        ch = MockChannel()
        payload, _ = payloads.heuristic_payload(ch, settings.OS.UNIX)
        self.assertIsInstance(payload, str)
        self.assertTrue(len(payload) > 0)


# ---------------------------------------------------------------------------
# OOB_EVAL: exfiltrate_eval and injection() with OOB_EVAL=True
# ---------------------------------------------------------------------------

class TestOobEval(unittest.TestCase):

    _HOST = "aabbccddeeaabbccddeetest0000token.oast.fun"

    def setUp(self):
        settings.TARGET_OS = settings.OS.UNIX
        settings.OOB_EVAL = False

    def tearDown(self):
        settings.OOB_EVAL = False

    # --- exfiltrate_eval structure -----------------------------------------

    def test_returns_nonempty_for_dns(self):
        result = payloads.exfiltrate_eval(";", "dns", self._HOST, "echo hello")
        self.assertTrue(result, "exfiltrate_eval returned empty for dns transport")

    def test_wraps_in_eval_grammar_backticks(self):
        # Default eval grammar is PHP: print(`...`);
        result = payloads.exfiltrate_eval(";", "dns", self._HOST, "echo hello")
        self.assertIn("`", result)
        self.assertTrue(result.strip().startswith("print("))

    def test_contains_dns_pipeline_structure(self):
        result = payloads.exfiltrate_eval(";", "dns", self._HOST, "echo hello")
        self.assertIn("nslookup", result)
        self.assertIn("od -An", result)

    def test_inner_command_matches_plain_exfiltrate(self):
        # The backtick content must be exactly what exfiltrate("", ...) builds.
        plain = payloads.exfiltrate("", "dns", self._HOST, "echo hello")
        wrapped = payloads.exfiltrate_eval(";", "dns", self._HOST, "echo hello")
        inner = wrapped.split("`")[1]
        self.assertEqual(inner, plain)

    def test_terminator_appended_when_separator_given(self):
        result = payloads.exfiltrate_eval(";", "dns", self._HOST, "echo hello")
        self.assertTrue(result.endswith(settings.EVAL_GRAMMAR.TERMINATOR))

    def test_no_extra_terminator_when_separator_empty(self):
        # With no separator the eval wrapper adds no extra terminator beyond
        # what _rendered() already produces (the PHP print statement ends in ;).
        with_sep = payloads.exfiltrate_eval(";", "dns", self._HOST, "echo hello")
        without_sep = payloads.exfiltrate_eval("", "dns", self._HOST, "echo hello")
        self.assertEqual(len(without_sep) + len(settings.EVAL_GRAMMAR.TERMINATOR),
                         len(with_sep))

    # --- injection() with OOB_EVAL=True ------------------------------------

    def test_injection_oob_eval_calls_dns_output(self):
        ch = MockChannel()
        settings.OOB_EVAL = True
        settings.OOB_TRANSPORT = "dns"
        settings.OOB_DNS_ATTEMPTS = 1
        settings.OOB_CHANNEL = ch
        try:
            with mock.patch("src.core.techniques.oob.oob_injector._dns_output",
                            return_value="eval_result") as m:
                with mock.patch("src.core.controller.handler.oob_inject"):
                    result = oob_injector.injection(";", "echo hello", "", "", " ",
                                                    "GET", "http://t/", "p")
            self.assertEqual(result, "eval_result")
            self.assertEqual(m.call_count, 1)
        finally:
            settings.OOB_CHANNEL = None
            settings.OOB_TRANSPORT = ""
            settings.OOB_EVAL = False

    def test_injection_oob_eval_retries_same_as_plain(self):
        # OOB_EVAL=True does not change the retry count.
        ch = MockChannel()
        settings.OOB_EVAL = True
        settings.OOB_TRANSPORT = "dns"
        settings.OOB_DNS_ATTEMPTS = 2
        settings.OOB_CHANNEL = ch
        try:
            with mock.patch("src.core.techniques.oob.oob_injector._dns_output",
                            side_effect=["", "second"]) as m:
                with mock.patch("src.core.controller.handler.oob_inject"):
                    result = oob_injector.injection(";", "echo hello", "", "", " ",
                                                    "GET", "http://t/", "p")
            self.assertEqual(result, "second")
            self.assertEqual(m.call_count, 2)
        finally:
            settings.OOB_CHANNEL = None
            settings.OOB_TRANSPORT = ""
            settings.OOB_EVAL = False


if __name__ == "__main__":
    unittest.main()
