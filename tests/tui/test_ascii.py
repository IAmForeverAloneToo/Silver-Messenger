"""ASCII marks: forced with --ascii, detected on the Linux console, switched
and remembered with /marks, and overruled by a capable terminal."""

from harness import *


def bare(**extra):
    """An environment that names no terminal, plus `extra`."""
    env = client_env()
    for k in ("TERM_PROGRAM", "TMUX", "VTE_VERSION", "WT_SESSION", "LANG", "LC_ALL", "LC_CTYPE"):
        env.pop(k, None)
    env.update(extra)
    return env


def main():
    relay = Relay()
    a_dir, b_dir = fresh_dir("ascii-alice"), fresh_dir("ascii-bob")
    identity(a_dir)
    b_id = identity(b_dir)
    a = Term(a_dir, relay.url, extra=["--ascii"], env=bare(TERM="xterm-256color"))
    b = Term(b_dir, relay.url, env=bare(TERM="linux"))
    assert a.wait("* connected") and b.wait("* connected"), "ascii status dots"
    a.type(f"/add {b_id} bob\r")
    assert a.wait(" bob · "), "add"
    a.type("hello bob\r")
    assert a.wait("you v: hello bob"), "ascii accepted mark"
    assert b.wait("Contact request from"), "request"
    b.key(SHIFT_TAB)
    b.type("/accept 1\r")
    assert b.wait("hello bob"), "accept"
    b.type("/alias alice\r")
    b.type("hi alice\r")
    assert a.wait("hi alice"), "reply"
    assert b.wait("you vv: hi alice"), "ascii read mark on bob"
    a.type("second\r")
    assert a.wait("you vv: second"), "ascii marks on alice"
    a.type("/verify ok\r")
    assert a.wait("v bob"), "ascii verified mark in the list"
    b.type("/marks unicode\r")
    assert b.wait("you ✓✓: hi alice") and b.wait("● connected"), "live switch to unicode"
    b.quit()
    assert config(b_dir)["marks"] == "unicode"
    b = Term(b_dir, relay.url, env=bare(TERM="linux"))
    assert b.wait("● connected"), "remembered unicode beats the console"
    b.type("/marks auto\r")
    assert b.wait("* connected"), "auto goes back to ascii on the console"
    b.quit()
    b = Term(b_dir, relay.url, env=bare(TERM="linux", VTE_VERSION="7000"))
    assert b.wait("● connected"), "a capable terminal keeps unicode"
    for t in list(TERMS):
        t.quit()
    relay.stop()


if __name__ == "__main__":
    run(main)
