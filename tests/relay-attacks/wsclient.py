"""A bare WebSocket client for poking at a relay from tests: raw frames,
including the ones a well-behaved client never sends."""

import base64
import json
import os
import socket
import struct


class WS:
    def __init__(self, port, headers=(), host="127.0.0.1"):
        self.s = socket.create_connection((host, port), timeout=10)
        self.buf = b""
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f"GET /ws HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
            + "".join(h + "\r\n" for h in headers)
            + "\r\n"
        )
        self.s.sendall(req.encode())
        while b"\r\n\r\n" not in self.buf:
            d = self.s.recv(4096)
            if not d:
                raise EOFError("closed during upgrade")
            self.buf += d
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        self.status = head.split(b"\r\n")[0].decode()

    def send(self, obj):
        p = json.dumps(obj).encode()
        m = os.urandom(4)
        if len(p) < 126:
            hdr = b"\x81" + bytes([0x80 | len(p)])
        elif len(p) < 65536:
            hdr = b"\x81\xfe" + struct.pack(">H", len(p))
        else:
            hdr = b"\x81\xff" + struct.pack(">Q", len(p))
        self.s.sendall(hdr + m + bytes(b ^ m[i % 4] for i, b in enumerate(p)))

    def _need(self, n):
        while len(self.buf) < n:
            d = self.s.recv(65536)
            if not d:
                raise EOFError("closed")
            self.buf += d

    def recv(self):
        while True:
            self._need(2)
            op = self.buf[0] & 0x0F
            ln = self.buf[1] & 0x7F
            off = 2
            if ln == 126:
                self._need(4)
                ln = struct.unpack(">H", self.buf[2:4])[0]
                off = 4
            elif ln == 127:
                self._need(10)
                ln = struct.unpack(">Q", self.buf[2:10])[0]
                off = 10
            self._need(off + ln)
            p = self.buf[off : off + ln]
            self.buf = self.buf[off + ln :]
            if op == 1:
                return json.loads(p)
            if op == 8:
                raise EOFError("closed: " + p[2:].decode(errors="replace"))
