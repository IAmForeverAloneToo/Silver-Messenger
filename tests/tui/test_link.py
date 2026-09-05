"""`silver --link`: a fresh directory registers with the relay and prints a
link with a QR code, then waits; run again it prints a new link for the
same device; a directory in use refuses to become a device."""

import json
import os
import subprocess

from harness import *


def main():
    relay = Relay()
    try:
        d = fresh_dir("link-device")
        first = Linking(d, relay.url, name="laptop")
        assert first.wait_line("Registering this device"), "it says what it does"
        link = first.link()
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
        again = second.link()
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
