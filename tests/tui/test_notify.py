"""The bell, the terminal-raised desktop notification, the unread count in
the window title, and /notify."""

from harness import *


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
    assert b"\x1b]777;notify;Silver Messenger;Contact request from" in raw, "OSC 777"
    assert b"\x1b]9;Silver Messenger: Contact request from" in raw, "OSC 9"
    assert b"\x1b]99;i=silver" in raw, "OSC 99"
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
    # The window loses focus: a message in the open chat rings.
    b.key(FOCUS_OUT)
    b.take_raw()
    a.type("while you are away\r")
    assert b.wait("while you are away"), "third"
    time.sleep(0.5)
    raw = b.take_raw()
    assert b"\x07" in raw and b"New message from alice" in raw, "bell while unfocused"
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
    b.quit()
    end = b.take_raw()
    assert b"\x1b[23;2t" in end, "title pop on exit"
    pair.stop()


if __name__ == "__main__":
    run(main)
