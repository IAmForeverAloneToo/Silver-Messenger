"""A panic leaves the terminal usable: before the message prints, the
mouse, the paste and focus reports and the alternate screen are turned
off and the title is put back; the shell gets its terminal in its normal
mode; the next start works. Reader mode, which used none of the screen
modes, is left by turning off the reports alone. The client panics on
request through a trigger that debug builds carry (SILVER_DEBUG_PANIC_AFTER_MS)."""

import termios

from harness import *

FULL_LEAVES = [
    (b"\x1b[?1000l", "the mouse"),
    (b"\x1b[?1004l", "focus reports"),
    (b"\x1b[?2004l", "bracketed paste"),
    (b"\x1b[23;2t", "the title"),
    (b"\x1b[?1049l", "the alternate screen"),
]


def echo_is_on(t):
    """Whether the pty is in its normal mode: raw mode turns echo off."""
    return bool(termios.tcgetattr(t.m)[3] & termios.ECHO)


def panicked(t):
    """Wait for the client to die of its panic; the bytes it wrote before
    the message, and after."""
    code = t.p.wait(timeout=20)
    assert code == 101, f"a panic exits with 101, got {code}"
    raw = t.take_raw()
    at = raw.find(b"panicked at")
    assert at > 0, raw[-400:]
    return raw[:at], raw[at:]


def main():
    relay = Relay()
    a_dir = fresh_dir("panic-alice")
    identity(a_dir)

    # The full mode: everything set up is undone, in that order, before
    # the message, which lands on the normal screen; raw mode is off.
    a = Term(a_dir, relay.url, env=client_env(SILVER_DEBUG_PANIC_AFTER_MS="1500", RUST_BACKTRACE="0"))
    assert a.wait(G.connected + " connected"), "connect"
    assert not echo_is_on(a), "raw mode while running"
    before, after = panicked(a)
    for seq, what in FULL_LEAVES:
        assert seq in before, f"{what} is left before the message"
    assert before.find(b"\x1b[?1000l") < before.find(b"\x1b[?1049l"), "the mouse goes before the screen"
    assert b"\x1b[?1049h" not in after and b"\x1b[?1000h" not in after, "nothing set up again after"
    assert a.has("panicked at") and a.has("SILVER_DEBUG_PANIC_AFTER_MS"), "the message is readable"
    assert echo_is_on(a), "the terminal is back in its normal mode"

    # The next start works, and a normal exit leaves the same way.
    a = Term(a_dir, relay.url)
    assert a.wait(G.connected + " connected"), "start after a panic"
    a.quit()
    tail = a.take_raw()
    for seq, what in FULL_LEAVES:
        assert seq in tail, f"{what} is left on a normal exit"

    # Reader mode: the reports are turned off; the screen, the mouse and
    # the title were never touched.
    b = Term(a_dir, relay.url, extra=("--reader",), env=client_env(SILVER_DEBUG_PANIC_AFTER_MS="1500", RUST_BACKTRACE="0"))
    assert b.wait("Connected to ws://"), "reader mode connects"
    before, after = panicked(b)
    assert b"\x1b[?1004l" in before and b"\x1b[?2004l" in before, "the reports are left"
    whole = before + after
    assert b"\x1b[?1049" not in whole and b"\x1b[?1000" not in whole and b"\x1b[2" + b"3;2t" not in whole
    assert b.has("panicked at"), "the message is readable"
    assert echo_is_on(b), "the terminal is back in its normal mode"
    relay.stop()


if __name__ == "__main__":
    run(main)
