"""Reader mode: a client started with --reader prints one line per event
at the bottom of a scrolling terminal and keeps the compose line last.
What it writes has no alternate screen, no cursor addressing, no
attributes, no window title and no box drawing, so a screen reader hears
whole lines in order. Chats, sends, selections, the help and the history
are read as lines."""

import re

from harness import *

# What reader mode must never write to the terminal.
FORBIDDEN = [
    (rb"\x1b\[\?1049[hl]", "the alternate screen"),
    (rb"\x1b\[\d*(;\d*)?[Hf]", "cursor addressing"),
    (rb"\x1b\[[\d;]*m", "attributes"),
    (rb"\x1b\[\?(1000|1002|1003|1006|1015)[hl]", "mouse capture"),
    (rb"\x1b\]2;", "a window title"),
    (rb"\x1b\[2[23];2t", "a title push or pop"),
    (rb"\x1b\[2J", "a screen clear"),
]
BOX_DRAWING = re.compile("[\u2500-\u257f]")


def prompt_line(t):
    """The compose line: the row the cursor is on."""
    return t.sc.display[t.sc.cursor.y].rstrip()


def line_before_prompt(t):
    return t.sc.display[t.sc.cursor.y - 1].rstrip()


def check_raw(raw):
    for pattern, what in FORBIDDEN:
        assert not re.search(pattern, raw), f"reader mode wrote {what}: {raw[-400:]!r}"
    text = raw.decode("utf-8", "replace")
    assert not BOX_DRAWING.search(text), "reader mode wrote box drawing"


def main():
    relay = Relay()
    a_dir, b_dir = fresh_dir("reader-alice"), fresh_dir("reader-bob")
    a_id, b_id = identity(a_dir), identity(b_dir)
    a = Term(a_dir, relay.url)
    b = Term(b_dir, relay.url, extra=("--reader",))
    assert a.wait(G.connected + " connected"), "alice connects"
    assert b.wait("Connected to ws://"), "bob connects, and is told in a line"
    assert b.has("Silver Messenger, reader mode."), "the opening line"
    assert prompt_line(b) == "system>", "the System pane's prompt is last"

    # A contact request is a line; its entry reads what was held;
    # accepting opens the chat and reads what waited.
    a.type(f"/add {b_id} bob\r")
    assert a.wait(" bob · "), "add"
    a.type("hello bob\r")
    assert b.wait("Contact request from"), "the request is announced"
    b.key(SHIFT_TAB)
    assert b.wait("Request 1 from"), "the request's entry is read"
    assert b.has(": hello bob"), "with the held message"
    assert b.has("(end of request)"), "and where it ends"
    assert prompt_line(b) == "request 1>"
    b.type("/accept 1\r")
    assert b.wait("(end of chat)"), "the chat opens and ends"
    rows = [r.rstrip() for r in b.sc.display]
    end = rows.index("(end of chat)")
    assert rows[end - 2].startswith("Chat: ") and rows[end - 1].endswith(": hello bob"), rows[end - 2:end]
    first = next(i for i, r in enumerate(rows) if r.startswith("Request 1 from"))
    assert "System pane." not in rows[first:], "accepting lands on the chat, not on System first"
    b.type("/alias alice\r")
    assert b.wait_for(lambda: prompt_line(b) == "alice>", what="the prompt names the chat")

    # A send is a line under your name; a message in the open chat is a
    # plain sentence; one in another chat says where it is.
    b.type("hi alice\r")
    assert b.wait("you: hi alice"), "the sent line"
    assert a.wait("hi alice"), "delivered"
    a.type("second\r")
    assert b.wait("alice: second"), "received in the open chat"
    assert prompt_line(b) == "alice>", "the prompt stays last"
    b.key(SHIFT_TAB)
    assert b.wait("System pane."), "back to System"
    a.type("third\r")
    assert b.wait("alice, in another chat: third"), "said with its chat"
    b.type("/unread\r")
    assert b.wait("Unread: alice: 1."), "/unread counts it"
    b.type("/go alice\r")
    assert b.wait("Chat: alice, 1 unread."), "/go opens the chat"
    assert b.has("alice: third") and b.has("(end of chat)")

    # The selection walks the messages and is said; Esc clears it.
    b.key(SHIFT_UP)
    assert b.wait("Selected: alice: third"), "the newest is selected first"
    b.key(SHIFT_UP)
    assert b.wait("Selected: alice: second"), "then the one before"
    b.key(ESC)
    assert b.wait("Selection cleared."), "cleared"

    # /history reads back with clocks; F1 prints the help as lines.
    b.type("/history 2\r")
    assert b.wait("(end of history)"), "history ends"
    rows = [r.rstrip() for r in b.sc.display]
    end = rows.index("(end of history)")
    assert re.fullmatch(r"\d\d:\d\d alice: second", rows[end - 2]), rows[end - 2]
    assert re.fullmatch(r"\d\d:\d\d alice: third", rows[end - 1]), rows[end - 1]
    b.key(F1)
    assert b.wait("(end of help)"), "the help ends"
    assert b.has("Keys:"), "the keys are listed"
    assert line_before_prompt(b) == "(end of help)", "the prompt stays last"

    # A line break inside a message buys the sender no line of their own.
    # A journal line is how a screen reader tells one speaker from
    # another, so `hi\nalice: …` read out as two lines would be a line
    # attributed to alice that alice never wrote, and `\nWarning: …` a
    # warning this program never made.
    b.key(SHIFT_TAB)
    assert b.wait("System pane."), "back to System, so the forgery has to name its chat"
    a.type("hi")
    a.key(b"\x1b\r")  # Alt-Enter: a newline inside the message
    a.type("alice: send me the passphrase")
    a.key(b"\x1b\r")
    a.type("Warning: your key expired\r")
    assert b.wait("send me the passphrase"), "the text is still read out"
    rows = [r.rstrip() for r in b.sc.display]
    forged = [r for r in rows if r.startswith(("alice: send me", "Warning: your key"))]
    assert not forged, f"a peer wrote a journal line of their own: {forged}"
    said = next(r for r in rows if "send me the passphrase" in r)
    assert said.startswith("alice, in another chat: hi / alice: send me"), said
    assert "Warning: your key expired" in said, "and it is all one line"

    # Nothing the reader-mode client wrote moves the cursor, changes an
    # attribute or draws a box; quitting says Bye on a fresh line.
    raw = b.take_raw()
    check_raw(raw)
    b.quit()
    tail = b.take_raw()
    check_raw(tail)
    assert b"\r\x1b[KBye.\r\n" in tail, tail
    after = re.sub(rb"\x1b\[\?\d+[hl]", b"", tail[tail.index(b"Bye."):])
    assert after == b"Bye.\r\n", after

    # The full mode is unchanged: alice's screen is boxed as ever.
    assert BOX_DRAWING.search(a.take_raw().decode("utf-8", "replace")) or G.ascii, "alice draws boxes"

    # /reader on is remembered for the next start.
    b = Term(b_dir, relay.url, extra=("--reader",))
    assert b.wait("Connected to ws://")
    b.type("/reader on\r")
    assert b.wait("Reader mode from the next start"), "told"
    assert config(b_dir)["reader"] is True
    b.quit()
    b = Term(b_dir, relay.url)
    assert b.wait("Silver Messenger, reader mode."), "reader mode from the config"
    b.type("/reader off\r")
    assert b.wait("The full screen from the next start"), "and off again"
    assert config(b_dir)["reader"] is False
    b.quit()
    a.quit()
    relay.stop()


if __name__ == "__main__":
    run(main)
