"""The bell, the terminal-raised desktop notification, the unread count in
the window title, /notify, and which path the environment chooses. Every
notification says "New message" and nothing else: not the sender, not
the id a contact request shows, not a word of the message."""

import re

from harness import *

OSC777 = re.compile(rb"\x1b\]777;notify;([^\x1b]*)\x1b\\")
GENERIC = "Silver Messenger;New message"


def notifications(raw):
    """What every terminal-raised notification in `raw` said."""
    return [m.group(1).decode() for m in OSC777.finditer(raw)]


def main():
    pair = Pair("notify")
    a, b = pair.alice, pair.bob
    start = b.take_raw()
    assert b"\x1b[22;2t" in start, "title push"
    assert b"\x1b]2;Silver Messenger\x1b\\" in start, "plain title"
    a.type(f"/add {pair.b_id} bob\r")
    assert a.wait(" bob · "), "add"
    a.type("hello bob\r")
    assert b.wait("Contact request from"), "request"
    raw = b.take_raw()
    assert b"\x07" in raw, "bell for a contact request"
    # A contact request is announced, and the announcement carries no id
    # and no mention of what it is: the System pane has those.
    assert notifications(raw) == [GENERIC], notifications(raw)
    assert b"\x1b]9;Silver Messenger: New message\x1b\\" in raw, "OSC 9"
    assert b"\x1b]99;i=silver:d=0:p=title;Silver Messenger\x1b\\" in raw, "OSC 99 title"
    assert b"\x1b]99;i=silver:d=1:p=body;New message\x1b\\" in raw, "OSC 99 body"
    assert b"\x1b]2;Silver Messenger (1)\x1b\\" in raw, "title with one held message"
    b.key(SHIFT_TAB)
    b.type("/accept 1\r")
    assert b.wait("hello bob"), "accept"
    b.type("/alias alice\r")
    b.take_raw()
    # Bob is looking at alice's chat and the window is focused: no bell.
    a.type("looking at you\r")
    assert b.wait("looking at you"), "second"
    time.sleep(0.5)
    assert b"\x07" not in b.take_raw(), "no bell while the chat is open and focused"
    # The window loses focus: a message in the open chat rings, and the
    # notification still names nobody, though the chat shows the alias.
    b.key(FOCUS_OUT)
    b.take_raw()
    a.type("while you are away\r")
    assert b.wait("while you are away"), "third"
    time.sleep(0.5)
    raw = b.take_raw()
    assert b"\x07" in raw, "bell while unfocused"
    assert notifications(raw) == [GENERIC], notifications(raw)
    assert b"alice" not in b"".join(OSC777.findall(raw)), "the alias reached a notification"
    b.key(FOCUS_IN)
    # Bob on System: the title counts unread, the bell rings once for a burst.
    b.key(TAB)
    b.take_raw()
    for i in range(3):
        a.type(f"burst {i}\r")
    time.sleep(2.5)
    raw = b.take_raw()
    bells = raw.count(b"\x07")
    assert bells == 1, f"one bell for a burst, got {bells}"
    assert b"\x1b]2;Silver Messenger (3)\x1b\\" in raw, "unread count in the title"
    b.key(SHIFT_TAB)
    time.sleep(0.5)
    assert b"\x1b]2;Silver Messenger\x1b\\" in b.take_raw(), "title cleared when read"
    b.type("/notify off\r")
    b.key(TAB)
    assert b.wait("Notifications off"), "/notify off"
    b.take_raw()
    a.type("silent\r")
    time.sleep(2.0)
    raw = b.take_raw()
    assert b"\x07" not in raw and b"]777;" not in raw, "silent after /notify off"
    assert b"\x1b]2;Silver Messenger (1)\x1b\\" in raw, "the title still counts"
    b.type("/notify bell\r")
    assert b.wait("bell only"), "/notify bell"
    b.take_raw()
    a.type("ding\r")
    time.sleep(2.0)
    raw = b.take_raw()
    assert b"\x07" in raw and b"]777;" not in raw, "bell only"
    b.type("/notify all\r")
    assert b.wait("Notifications on"), "/notify all"
    b.quit()
    end = b.take_raw()
    assert b"\x1b[23;2t" in end, "title pop on exit"

    # --- the route, decided from the environment ---------------------------
    # Bob comes back under different environments; each time alice writes
    # once and what reaches the pty says which path was taken. The test's
    # own TERM (xterm-256color unless run.sh says otherwise) is one the
    # client does not recognise: both paths, so the sequences are written
    # (the desktop's part cannot be seen from a pty; on this Linux there is
    # no session bus, and the bell and title still work regardless).
    # A restarted bob is awaited by the words of the status line and not by
    # its mark: a Windows Terminal environment draws the Unicode marks
    # whatever TERM says, so the mark the harness expects under TERM=linux
    # is not the one on screen.

    def arrives(term, message):
        """Alice writes; the restarted bob is on System, so what shows that
        it arrived is the bell, after which the rest of the announcement
        has a moment to follow."""
        term.take_raw()
        a.type(message + "\r")
        assert term.wait_for(lambda: b"\x07" in term.raw, timeout=15, what=f"the bell for {message!r}")
        time.sleep(1.5)
        return term.take_raw()

    def restart(extra, message):
        term = Term(pair.b_dir, pair.relay.url, env=client_env(**extra))
        assert term.wait(" connected ws://", timeout=60), f"reconnect {extra}"
        return term, arrives(term, message)

    # Windows Terminal ignores the sequences: the desktop alone, so none
    # are written, and the bell still rings.
    term, raw = restart({"WT_SESSION": "test"}, "toast please")
    assert b"\x07" in raw, "bell under Windows Terminal"
    assert b"]777;" not in raw and b"]9;Silver" not in raw and b"]99;" not in raw, "no sequences for a terminal that ignores them"
    # ...unless told otherwise.
    term.type("/notify terminal\r")
    assert term.wait("this terminal's own sequences"), "/notify terminal"
    raw = arrives(term, "sequence please")
    assert notifications(raw) == [GENERIC], "forced terminal path"
    term.type("/notify all\r")
    assert term.wait("Notifications on"), "back to all"
    term.quit()

    # Over SSH the desktop is elsewhere: the sequences, whatever the
    # terminal, here one that would otherwise take the desktop.
    term, raw = restart({"SSH_TTY": "/dev/pts/9", "WT_SESSION": "test"}, "over ssh")
    assert notifications(raw) == [GENERIC], "sequences over SSH"
    term.quit()

    # Inside tmux the sequences are wrapped for passthrough.
    term, raw = restart({"TMUX": "/tmp/tmux-1000/default,1,0"}, "in tmux")
    assert b"\x1bPtmux;\x1b\x1b]777;notify;Silver Messenger;New message\x1b\x1b\\\x1b\\" in raw, "tmux passthrough"
    assert b"\x1b\x1b]9;Silver Messenger: New message" in raw, "OSC 9 wrapped too"
    term.quit()

    # A terminal that raises them itself: the sequences, and (unseen here)
    # not the desktop.
    term, raw = restart({"TERM_PROGRAM": "iTerm.app"}, "iterm here")
    assert notifications(raw) == [GENERIC], "sequences for iTerm2"
    term.quit()
    pair.stop()


if __name__ == "__main__":
    run(main)
