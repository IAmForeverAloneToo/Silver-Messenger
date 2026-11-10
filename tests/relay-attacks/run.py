"""Attacks on a relay, each a regression test for something a review of
the relay in November 2026 found (see the changelog's Security entries).

Starts its own relay on a free port with a fresh data directory, runs every
attack, and fails if any of them works. Run after building:

    cargo build -p silver-relay && python3 tests/relay-attacks/run.py

The relay binary is taken from SILVER_BIN_DIR (default target/debug).
"""

import base64
import os
import resource
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.request

sys.path.insert(0, os.path.dirname(__file__))
from wsclient import WS  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BIN = os.environ.get("SILVER_BIN_DIR") or os.path.join(ROOT, "target", "debug")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Relay:
    def __init__(self, *extra):
        self.dir = tempfile.mkdtemp(prefix="silver-attack-")
        self.port, self.metrics = free_port(), free_port()
        self.p = subprocess.Popen(
            [os.path.join(BIN, "silver-relay"), "--listen", f"127.0.0.1:{self.port}",
             "--data-dir", os.path.join(self.dir, "data"),
             "--metrics-listen", f"127.0.0.1:{self.metrics}", *extra],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=1).close()
                return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("relay did not start")

    def rss_mb(self):
        with open(f"/proc/{self.p.pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS"):
                    return int(line.split()[1]) // 1024
        return 0

    def metric(self, name):
        body = urllib.request.urlopen(f"http://127.0.0.1:{self.metrics}/metrics", timeout=5).read()
        for line in body.decode().splitlines():
            if line.startswith(name + " "):
                return float(line.split()[1])
        return None

    def stop(self):
        self.p.terminate()
        try:
            self.p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.p.kill()
        shutil.rmtree(self.dir, ignore_errors=True)


def b64(n=32):
    return base64.b64encode(os.urandom(n)).decode()


# --- the attacks ---------------------------------------------------------


def silent_connections_are_closed(relay):
    """A connection that sends nothing, or an HTTP/2 preface and then
    nothing, used to be held for ever below every limit."""
    held = []
    for payload in (b"", b"PRI", b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"):
        s = socket.create_connection(("127.0.0.1", relay.port))
        if payload:
            s.sendall(payload)
        held.append(s)
    time.sleep(13)  # past the 10 s header timeout
    for s in held:
        s.settimeout(2)
        try:
            data = s.recv(4096)
            # Closed (b"") or answered with an error; never left open.
            assert data == b"" or data.startswith(b"HTTP/1.1 4"), data[:40]
        except socket.timeout:
            raise AssertionError("a silent connection is still open after the header timeout")


def ping_flood_does_not_grow_memory(relay):
    """A client that sends pings and reads nothing made the relay buffer a
    pong for each, without bound."""
    w = WS(relay.port)
    w.recv()
    w.send({"type": "blob_get", "blob": os.urandom(16).hex()})
    w.recv()
    before = relay.rss_mb()
    frame = b"\x89" + bytes([0x80 | 125]) + b"\0\0\0\0" + b"A" * 125
    block = frame * 8000
    w.s.settimeout(5)
    sent = 0
    try:
        for _ in range(300):
            w.s.sendall(block)
            sent += len(block)
    except OSError:
        pass  # the relay gave up on the connection, as it should
    grown = relay.rss_mb() - before
    assert grown < 64, f"relay grew {grown} MB after {sent >> 20} MB of pings"


def reconnecting_does_not_reset_limits(relay):
    """Every per-minute limit used to start full on each connection."""
    taken = 0
    for _ in range(6):
        w = WS(relay.port)
        w.recv()
        for _ in range(80):
            w.send({"type": "group_commit", "group": b64(), "epoch": 1, "token": b64(), "next": b64()})
            if w.recv().get("code") == "rate_limited":
                break
            taken += 1
        w.s.close()
    assert taken <= 35, f"{taken} frames over six reconnects against a limit of 30 a minute"


def empty_chunks_count_against_the_cap(relay):
    """Zero-byte file chunks used to cost a row each and count as nothing."""
    w = WS(relay.port)
    w.recv()
    for i in range(50):
        w.send({"type": "blob_put", "blob": os.urandom(16).hex(), "index": 0, "total": 2, "data": ""})
        w.recv()
    counted = relay.metric("silver_relay_blob_bytes")
    assert counted and counted >= 50 * 1024, f"50 empty chunks counted as {counted} bytes"


def forwarded_for_is_not_believed_by_default(relay):
    """Anything connecting from loopback used to choose its own address."""
    held, refused = [], 0
    for i in range(24):
        try:
            w = WS(relay.port, headers=(f"X-Forwarded-For: 203.0.113.{i}",))
            f = w.recv()
            if f.get("type") == "challenge":
                held.append(w)
            else:
                refused += 1
        except (EOFError, OSError):
            refused += 1
    for w in held:
        w.s.close()
    assert len(held) <= 16, f"{len(held)} connections accepted from one address with forged headers"


ATTACKS = [
    silent_connections_are_closed,
    ping_flood_does_not_grow_memory,
    reconnecting_does_not_reset_limits,
    empty_chunks_count_against_the_cap,
    forwarded_for_is_not_believed_by_default,
]


def main():
    resource.setrlimit(resource.RLIMIT_NOFILE, (4096, 4096))
    failed = 0
    for attack in ATTACKS:
        relay = Relay()
        try:
            attack(relay)
            print(f"{attack.__name__}: OK")
        except Exception:
            failed += 1
            print(f"{attack.__name__}: FAILED")
            traceback.print_exc()
        finally:
            relay.stop()
    if failed:
        print(f"{failed} attack(s) still work", file=sys.stderr)
        sys.exit(1)
    print("no attack worked")


if __name__ == "__main__":
    main()
