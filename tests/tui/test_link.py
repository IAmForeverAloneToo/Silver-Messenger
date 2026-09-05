"""`silver --link`: a fresh directory registers with the relay and prints a
link with a QR code, then waits; run again it prints a new link for the
same device; a directory in use refuses to become a device."""

import json
import os
import select
import subprocess
import time

from harness import *


class Linking:
    """`silver --link` as a child process, its output read line by line."""

    def __init__(self, data_dir, relay_url, name=None):
        args = [os.path.join(BIN, "silver"), "--data-dir", data_dir, "--relay", relay_url, "--link"]
        if name:
            args += ["--device-name", name]
        self.p = subprocess.Popen(
            args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            env=client_env(),
        )
        self.buf = b""
        self.lines = []

    def wait_line(self, needle, timeout=30):
        """Read until a line containing `needle` arrives; the line."""
        deadline = time.time() + timeout
        fd = self.p.stdout.fileno()
        while True:
            for line in self.lines:
                if needle in line:
                    return line
            remaining = deadline - time.time()
            if remaining <= 0:
                raise AssertionError(f"no line with {needle!r} within {timeout}s; got {self.lines!r}")
            ready, _, _ = select.select([fd], [], [], min(remaining, 0.5))
            if not ready:
                if self.p.poll() is not None:
                    raise AssertionError(f"silver --link exited with {self.p.returncode}: {self.lines!r}")
                continue
            chunk = os.read(fd, 4096)
            if not chunk:
                raise AssertionError(f"silver --link closed its output: {self.lines!r}")
            self.buf += chunk
            *done, self.buf = self.buf.split(b"\n")
            self.lines.extend(l.decode("utf-8", "replace") for l in done)

    def stop(self):
        self.p.terminate()
        try:
            self.p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.p.kill()


def main():
    relay = Relay()
    try:
        d = fresh_dir("link-device")
        first = Linking(d, relay.url, name="laptop")
        assert first.wait_line("Registering this device"), "it says what it does"
        line = first.wait_line("/devices link silver://link/")
        link = line.split("/devices link ", 1)[1].strip()
        device_id = identity(d)
        assert link.startswith(f"silver://link/{device_id}?secret="), link
        assert "&name=laptop" in link and "relay=ws%3A%2F%2F127.0.0.1" in link, link
        first.wait_line("scan this code")
        first.wait_line("Waiting for the primary")
        code = [l for l in first.lines if "█" in l or "▀" in l or "▄" in l]
        assert len(code) >= 10, f"a QR code is drawn ({len(code)} rows)"
        assert all(len(l.strip()) > 0 for l in code)
        # The device is registered: a lookup of it answers, and it belongs
        # to nobody yet (the link is still waiting).
        assert first.p.poll() is None, "it waits"
        first.stop()

        # Again, in the same directory: the same device, another secret.
        second = Linking(d, relay.url)
        line = second.wait_line("/devices link silver://link/")
        again = line.split("/devices link ", 1)[1].strip()
        assert again.startswith(f"silver://link/{device_id}?secret="), again
        assert again.split("&")[0] != link.split("&")[0], "a fresh secret"
        assert "&name=" not in again, "no name unless given"
        second.stop()

        # A directory in use does not become a device.
        used = fresh_dir("link-used")
        someone = identity(fresh_dir("link-someone"))
        identity(used)
        with open(os.path.join(used, "blocked.json"), "w") as f:
            json.dump([someone], f)
        refused = subprocess.run(
            [os.path.join(BIN, "silver"), "--data-dir", used, "--relay", relay.url, "--link"],
            capture_output=True, text=True, stdin=subprocess.DEVNULL, env=client_env(), timeout=60,
        )
        assert refused.returncode != 0, "refused"
        assert "in use" in refused.stderr, refused.stderr
    finally:
        relay.stop()


if __name__ == "__main__":
    run(main)
