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

"""
Integration test: OOB DNS data flow exercised end-to-end.

Spins up a local DNS UDP stub on a random high port, installs a fake
`nslookup` wrapper script that forwards queries to that stub, generates
dns_exfil_command shell pipelines from the production code, runs them
in a subprocess, then verifies that the captured labels reassemble back
to the original command output.

No root access required; no external network traffic.
"""

import binascii
import itertools
import os
import queue
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
import unittest.mock as mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.argv = ["commix.py"]

from src.utils import settings
from src.core.techniques.oob import oob_payloads as payloads
from src.core.techniques.oob import oob_injector
from src.core.oob.provider import Interaction


# Fixed correlation id and token so the production parsing code finds them.
CORR_ID = "aabbccddeeaabbccddee"   # 20 chars (interactsh format)
TOKEN   = "testtoken0000"           # 13 chars
HOSTNAME = CORR_ID + TOKEN + ".test.local"


# ---------------------------------------------------------------------------
# Minimal DNS UDP stub
# ---------------------------------------------------------------------------

class DnsStub:
    """
    Listens on a random local UDP port, records every DNS query name it
    receives, and sends a minimal NXDOMAIN reply so callers do not block.
    """

    def __init__(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.settimeout(0.3)
        self.port = self._sock.getsockname()[1]
        self._q = queue.Queue()
        self._running = False
        self._thread = None

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        try:
            self._sock.close()
        except OSError:
            pass
        if self._thread:
            self._thread.join(timeout=2)

    def _loop(self):
        while self._running:
            try:
                data, addr = self._sock.recvfrom(512)
            except (socket.timeout, OSError):
                continue
            name = self._parse_name(data)
            if name:
                self._q.put(name.lower())
            self._nxdomain(data, addr)

    def _nxdomain(self, query, addr):
        if len(query) < 12:
            return
        hdr = bytearray(query[:12])
        hdr[2] = 0x81   # QR=1, RD=1
        hdr[3] = 0x83   # RA=1, RCODE=3
        hdr[6] = hdr[7] = 0
        try:
            self._sock.sendto(bytes(hdr) + query[12:], addr)
        except OSError:
            pass

    @staticmethod
    def _parse_name(data):
        if len(data) < 13:
            return None
        pos = 12    # skip the 12-byte DNS header
        labels = []
        while pos < len(data):
            length = data[pos]
            if length == 0:
                break
            pos += 1
            if pos + length > len(data):
                return None
            labels.append(data[pos:pos + length].decode("ascii", errors="replace"))
            pos += length
        return ".".join(labels) if labels else None

    def drain(self, first_wait=5.0, idle=0.5):
        """Collect all query names: wait up to *first_wait* s for the first
        one, then keep draining until *idle* s of silence."""
        names = []
        try:
            names.append(self._q.get(timeout=first_wait))
        except queue.Empty:
            return names
        while True:
            try:
                names.append(self._q.get(timeout=idle))
            except queue.Empty:
                break
        return names


# ---------------------------------------------------------------------------
# Fake nslookup wrapper
# ---------------------------------------------------------------------------

# Python script that sends a real DNS UDP query to the stub.
_DNS_SENDER = """\
#!/usr/bin/env python3
import socket, sys, struct

host = sys.argv[1]
labels = host.lower().encode("ascii", errors="replace").split(b".")
question = b"".join(bytes([len(l)]) + l for l in labels) + b"\\x00"
question += struct.pack("!HH", 1, 1)        # QTYPE=A, QCLASS=IN
header = struct.pack("!HHHHHH", 0xAABB, 0x0100, 1, 0, 0, 0)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
try:
    s.sendto(header + question, ("127.0.0.1", {port}))
    s.recv(512)
except Exception:
    pass
"""

_NSLOOKUP_SH = """\
#!/bin/sh
exec python3 {sender} "$@"
"""


_NOOP_SH = "#!/bin/sh\nexit 1\n"


def _install_fake_nslookup(tmpdir, port):
    sender = os.path.join(tmpdir, "_dns_sender.py")
    wrapper = os.path.join(tmpdir, "nslookup")
    with open(sender, "w") as fh:
        fh.write(_DNS_SENDER.format(port=port))
    with open(wrapper, "w") as fh:
        fh.write(_NSLOOKUP_SH.format(sender=sender))
    os.chmod(wrapper, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)
    # When the '|' separator chains lookup tools with single pipes every command
    # in the pipeline runs simultaneously. Provide fast no-ops for the fallbacks
    # so they do not block waiting for I/O or a network reply.
    for name in ("getent", "host", "ping"):
        path = os.path.join(tmpdir, name)
        with open(path, "w") as fh:
            fh.write(_NOOP_SH)
        os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)


# ---------------------------------------------------------------------------
# Reassembly helper
# ---------------------------------------------------------------------------

def _reassemble(stub_names):
    """
    Given a list of raw DNS query names from the stub, use the production
    Interactsh parsing to build a mock channel, then call _dns_output to
    reassemble the command output.
    """
    from src.core.oob.interactsh import Interactsh

    client = Interactsh.__new__(Interactsh)
    client.correlation_id = CORR_ID
    client.domain = "test.local"

    class _Ch:
        def __init__(self):
            self._seen = []
            self._labels = {}

        def seen(self, token, protocol=None):
            hits = self._seen
            return [i for i in hits if i.protocol == protocol] if protocol else list(hits)

        def data_of(self, itr):
            return self._labels.get(id(itr), [])

        def poll_now(self):
            pass

    ch = _Ch()
    for name in stub_names:
        itr = Interaction(protocol="dns", identifier=name, raw_request="")
        if client._token_of(itr) == TOKEN:
            ch._seen.append(itr)
            ch._labels[id(itr)] = client.data_of(itr)

    # First call supplies the deadline base (0 → deadline = 30).
    # Second call (inside the loop) returns 9999 to trigger the exit path:
    # the deadline check fires after the first iteration processes all chunks.
    times = itertools.chain([0], itertools.repeat(9999))
    settings.OOB_TIMEOUT = 15
    settings.INCOMPLETE_OUTPUT = False
    with mock.patch("time.time", side_effect=times):
        with mock.patch("time.sleep"):
            return oob_injector._dns_output(ch, TOKEN)


# ---------------------------------------------------------------------------
# Integration test class
# ---------------------------------------------------------------------------

_TOOLS = ("sh", "od", "fold", "cat", "tr", "xargs", "python3")

@unittest.skipUnless(
    all(shutil.which(t) for t in _TOOLS),
    "one or more required tools missing: " + ", ".join(_TOOLS),
)
class TestDnsOobIntegration(unittest.TestCase):

    def setUp(self):
        settings.TARGET_OS = settings.OS.UNIX
        settings.INCOMPLETE_OUTPUT = False
        self._stub = DnsStub()
        self._stub.start()
        self._tmpdir = tempfile.mkdtemp(prefix="commix_oob_test_")
        _install_fake_nslookup(self._tmpdir, self._stub.port)

    def tearDown(self):
        self._stub.stop()
        shutil.rmtree(self._tmpdir, ignore_errors=True)
        settings.TARGET_OS = settings.OS.UNIX

    def _run(self, cmd, timeout=12):
        env = dict(os.environ)
        env["PATH"] = self._tmpdir + ":" + env.get("PATH", "/usr/bin:/bin")
        subprocess.run(
            ["sh", "-c", cmd],
            env=env,
            capture_output=True,
            timeout=timeout,
        )

    # --- xargs format (separator '&'): plain index labels, no total --------

    def test_xargs_single_chunk_ascii_round_trip(self):
        cmd = payloads.dns_exfil_command(HOSTNAME, "echo hello", "&")
        self._run(cmd)
        names = self._stub.drain()
        self.assertNotEqual(names, [], "no DNS queries captured")
        self.assertEqual(_reassemble(names), "hello")

    def test_xargs_multiword_output(self):
        cmd = payloads.dns_exfil_command(HOSTNAME, "echo 'foo bar baz'", "&")
        self._run(cmd)
        names = self._stub.drain()
        self.assertNotEqual(names, [], "no DNS queries captured")
        self.assertEqual(_reassemble(names), "foo bar baz")

    def test_xargs_multichunk_output(self):
        # 40 'B' chars → 80 hex chars → 2 chunks (60 + 20)
        cmd = payloads.dns_exfil_command(
            HOSTNAME, "printf '%s' 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'", "&"
        )
        self._run(cmd)
        names = self._stub.drain()
        self.assertNotEqual(names, [], "no DNS queries captured")
        self.assertEqual(_reassemble(names), "B" * 40)

    def test_xargs_labels_carry_plain_index(self):
        # xargs format: label0 should be a plain integer, no dash-separator
        from src.core.oob.interactsh import Interactsh
        client = Interactsh.__new__(Interactsh)
        client.correlation_id = CORR_ID
        client.domain = "test.local"
        cmd = payloads.dns_exfil_command(HOSTNAME, "echo hello", "&")
        self._run(cmd)
        names = self._stub.drain()
        self.assertNotEqual(names, [], "no DNS queries captured")
        for name in names:
            itr = Interaction(protocol="dns", identifier=name, raw_request="")
            if client._token_of(itr) == TOKEN:
                labels = client.data_of(itr)
                if labels:
                    _, _, count = labels[0].partition("-")
                    # count is empty → no total embedded in label
                    self.assertFalse(count.isdigit(),
                                     "xargs label should not carry a total: %r" % labels[0])

    def test_xargs_hex_labels_are_valid_hex(self):
        cmd = payloads.dns_exfil_command(HOSTNAME, "echo hello", "&")
        self._run(cmd)
        names = self._stub.drain()
        self.assertNotEqual(names, [], "no DNS queries captured")
        from src.core.oob.interactsh import Interactsh
        client = Interactsh.__new__(Interactsh)
        client.correlation_id = CORR_ID
        client.domain = "test.local"
        for name in names:
            itr = Interaction(protocol="dns", identifier=name, raw_request="")
            if client._token_of(itr) == TOKEN:
                hex_data = "".join(client.data_of(itr)[1:])
                self.assertEqual(len(hex_data) % 2, 0,
                                 "odd-length hex chunk: %r" % hex_data)
                binascii.unhexlify(hex_data)   # must not raise

    # --- loop format (separator ';'): labels carry index-total -------------

    def test_loop_single_chunk_ascii_round_trip(self):
        cmd = payloads.dns_exfil_command(HOSTNAME, "echo hello", ";")
        self._run(cmd)
        names = self._stub.drain()
        self.assertNotEqual(names, [], "no DNS queries captured")
        self.assertEqual(_reassemble(names), "hello")

    def test_loop_labels_carry_total(self):
        from src.core.oob.interactsh import Interactsh
        client = Interactsh.__new__(Interactsh)
        client.correlation_id = CORR_ID
        client.domain = "test.local"
        cmd = payloads.dns_exfil_command(HOSTNAME, "echo hello", ";")
        self._run(cmd)
        names = self._stub.drain()
        self.assertNotEqual(names, [], "no DNS queries captured")
        found_total = False
        for name in names:
            itr = Interaction(protocol="dns", identifier=name, raw_request="")
            if client._token_of(itr) == TOKEN:
                labels = client.data_of(itr)
                if labels:
                    _, _, count = labels[0].partition("-")
                    if count.isdigit():
                        found_total = True
                        break
        self.assertTrue(found_total, "no loop-format label with total found in %r" % names)

    def test_loop_multichunk_output(self):
        cmd = payloads.dns_exfil_command(
            HOSTNAME, "printf '%s' 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'", ";"
        )
        self._run(cmd)
        names = self._stub.drain()
        self.assertNotEqual(names, [], "no DNS queries captured")
        self.assertEqual(_reassemble(names), "C" * 40)

    def test_loop_chunk_count_consistent_across_labels(self):
        # All labels for one command run must agree on the total chunk count.
        from src.core.oob.interactsh import Interactsh
        client = Interactsh.__new__(Interactsh)
        client.correlation_id = CORR_ID
        client.domain = "test.local"
        cmd = payloads.dns_exfil_command(
            HOSTNAME, "printf '%s' 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD'", ";"
        )
        self._run(cmd)
        names = self._stub.drain()
        self.assertNotEqual(names, [], "no DNS queries captured")
        totals = set()
        for name in names:
            itr = Interaction(protocol="dns", identifier=name, raw_request="")
            if client._token_of(itr) == TOKEN:
                labels = client.data_of(itr)
                if labels:
                    _, _, count = labels[0].partition("-")
                    if count.isdigit():
                        totals.add(int(count))
        self.assertEqual(len(totals), 1,
                         "labels disagreed on chunk total: %r" % totals)

    # --- hostname embedding ------------------------------------------------

    def test_queries_embed_corr_id_and_token(self):
        # Every captured query name must contain the correlation id + token.
        cmd = payloads.dns_exfil_command(HOSTNAME, "echo hello", "&")
        self._run(cmd)
        names = self._stub.drain()
        self.assertNotEqual(names, [], "no DNS queries captured")
        for name in names:
            self.assertIn(CORR_ID + TOKEN, name,
                          "corr+token not found in %r" % name)


    # --- newline separator (\n): loop path, same label format as ';' -------

    def test_newline_loop_format_round_trip(self):
        cmd = payloads.dns_exfil_command(HOSTNAME, "echo hello", "\n")
        self._run(cmd)
        names = self._stub.drain()
        self.assertNotEqual(names, [], "no DNS queries captured")
        self.assertEqual(_reassemble(names), "hello")

    def test_newline_loop_labels_carry_total(self):
        from src.core.oob.interactsh import Interactsh
        client = Interactsh.__new__(Interactsh)
        client.correlation_id = CORR_ID
        client.domain = "test.local"
        cmd = payloads.dns_exfil_command(HOSTNAME, "echo hello", "\n")
        self._run(cmd)
        names = self._stub.drain()
        self.assertNotEqual(names, [], "no DNS queries captured")
        found = any(
            client._token_of(Interaction(protocol="dns", identifier=n, raw_request="")) == TOKEN
            and any(
                c.isdigit()
                for c in (client.data_of(Interaction(protocol="dns", identifier=n, raw_request=""))[0].partition("-")[2] or "")
            )
            for n in names
        )
        self.assertTrue(found, "no \\n-separator label with total found in %r" % names)

    # --- pipe separator (|): xargs path, single-pipe lookup chain ----------

    def test_pipe_xargs_format_round_trip(self):
        cmd = payloads.dns_exfil_command(HOSTNAME, "echo hello", "|")
        self._run(cmd)
        names = self._stub.drain()
        self.assertNotEqual(names, [], "no DNS queries captured")
        self.assertEqual(_reassemble(names), "hello")

    def test_pipe_xargs_labels_carry_plain_index(self):
        from src.core.oob.interactsh import Interactsh
        client = Interactsh.__new__(Interactsh)
        client.correlation_id = CORR_ID
        client.domain = "test.local"
        cmd = payloads.dns_exfil_command(HOSTNAME, "echo hello", "|")
        self._run(cmd)
        names = self._stub.drain()
        self.assertNotEqual(names, [], "no DNS queries captured")
        for name in names:
            itr = Interaction(protocol="dns", identifier=name, raw_request="")
            if client._token_of(itr) == TOKEN:
                labels = client.data_of(itr)
                if labels:
                    _, _, count = labels[0].partition("-")
                    self.assertFalse(count.isdigit(),
                                     "pipe-separator label should not carry total: %r" % labels[0])

    # --- OOB_EVAL: inner DNS command embedded in eval grammar wrapper -------

    def test_oob_eval_inner_command_round_trip(self):
        # exfiltrate_eval wraps the DNS pipeline in the eval-grammar's print
        # statement (PHP by default: print(`...`);).  The backtick content is
        # the same shell pipeline as the non-eval path.  Extract and run it.
        payload = payloads.exfiltrate_eval(";", "dns", HOSTNAME, "echo hello")
        self.assertIn("`", payload, "eval wrapper not present: %r" % payload[:60])
        inner_cmd = payload.split("`")[1]
        self._run(inner_cmd)
        names = self._stub.drain()
        self.assertNotEqual(names, [], "no DNS queries captured")
        self.assertEqual(_reassemble(names), "hello")

    def test_oob_eval_wrapper_does_not_alter_dns_queries(self):
        # Queries from the eval path and the plain path must be identical.
        from src.core.oob.interactsh import Interactsh
        client = Interactsh.__new__(Interactsh)
        client.correlation_id = CORR_ID
        client.domain = "test.local"

        # exfiltrate_eval wraps exfiltrate("", ...) — use the same separator so
        # both commands are runnable standalone (the ";" variant produces a
        # leading-semicolon injection fragment, not a plain shell script).
        plain_cmd = payloads.exfiltrate("", "dns", HOSTNAME, "echo hello")
        self._run(plain_cmd)
        plain_names = set(self._stub.drain())

        eval_payload = payloads.exfiltrate_eval(";", "dns", HOSTNAME, "echo hello")
        inner_cmd = eval_payload.split("`")[1]
        self._run(inner_cmd)
        eval_names = set(self._stub.drain())

        # Both runs must produce labels that carry the same decoded output.
        self.assertEqual(_reassemble(list(plain_names)), "hello")
        self.assertEqual(_reassemble(list(eval_names)),  "hello")


if __name__ == "__main__":
    unittest.main()
