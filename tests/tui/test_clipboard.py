"""Copy and paste without a system clipboard: copies go to the terminal by
OSC 52, paste says how to paste instead, bracketed paste still works, and
Ctrl-C only quits on a second press."""

from harness import *


def main():
    relay = Relay()
    d = fresh_dir("clip-alice")
    my_id = identity(d)
    link = silver("--data-dir", d, "--relay", relay.url, "--print-invite")
    a = Term(d, relay.url)
    assert a.wait(G.connected + " connected"), "connect"
    a.take_raw()
    a.type("/copy id\r")
    assert a.wait("Handed your id to the terminal"), "copy id"
    assert osc52(a.take_raw()) == [my_id], "OSC 52 carries the id"
    a.type("/invite copy\r")
    assert a.wait("Handed your invite link"), "invite copy"
    assert osc52(a.take_raw()) == [link], "OSC 52 carries the link"
    a.type("/copy\r")
    assert a.wait("Select a chat first"), "/copy needs a chat"
    a.key(CTRL_V)
    assert a.wait("No system clipboard here"), "Ctrl-V without a clipboard"
    a.key(SHIFT_INSERT)
    assert a.wait("No system clipboard here"), "Shift-Insert without a clipboard"
    a.key(b"\x1b[200~pasted text\x1b[201~")
    assert a.has("pasted text"), "bracketed paste from the terminal"
    a.key(ESC)
    # Ctrl-C with nothing selected arms quitting rather than quitting.
    a.key(CTRL_C)
    assert a.wait("Press Ctrl-C again to quit"), "armed"
    time.sleep(0.5)
    assert a.p.poll() is None, "still running"
    time.sleep(3.0)
    a.key(CTRL_C)
    time.sleep(0.5)
    assert a.p.poll() is None, "the armed state expired"
    a.key(CTRL_C)
    time.sleep(1.0)
    assert a.p.poll() == 0, "the second Ctrl-C quits"
    TERMS.remove(a)
    a = Term(d, relay.url)
    assert a.wait(G.connected + " connected"), "reconnect"
    assert a.quit() == 0, "Ctrl-Q quits at once"
    relay.stop()


if __name__ == "__main__":
    run(main)
