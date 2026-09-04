"""Connect, add a contact, requests, a two-way exchange, marks and receipts,
focus, and what survives a restart."""

from harness import *


def main():
    pair = Pair("basics")
    a, b = pair.alice, pair.bob
    a.type(f"/add {pair.b_id} bob\r")
    assert a.wait(" bob · "), "add"
    a.type("hello bob\r")
    assert b.wait("Contact request from"), "request lands in System"
    # A stranger's message gets no receipt: one mark only.
    time.sleep(1.5)
    assert a.wait_marks("hello bob", G.accepted), "stranger got a receipt?"
    b.key(SHIFT_TAB)
    assert b.wait("Contact requests"), "requests pane"
    b.type("/accept 1\r")
    assert b.wait("hello bob"), "accepted message moves into the chat"
    b.type("/alias alice\r")
    b.type("hi alice\r")
    assert a.wait("hi alice"), "reply"
    # Alice has the chat open and focused: read at once.
    assert b.wait_marks("hi alice", G.delivered, CYAN), "read receipt"
    a.type("second\r")
    assert a.wait_marks("second", G.delivered, CYAN), "read receipt the other way"
    # Bob looks away: delivered only. Back: read.
    b.key(TAB)
    a.type("third\r")
    assert a.wait_marks("third", G.delivered), "delivered"
    _, colours = a.marks("third")
    assert not colours & CYAN, colours
    b.key(SHIFT_TAB)
    assert a.wait_marks("third", G.delivered, CYAN), "read after switching back"
    # Bob's window loses focus with the chat open: not read until it returns.
    b.key(FOCUS_OUT)
    a.type("away?\r")
    assert a.wait_marks("away?", G.delivered), "delivered while unfocused"
    time.sleep(1.5)
    Term.pump_all()
    _, colours = a.marks("away?")
    assert not colours & CYAN, colours
    b.key(FOCUS_IN)
    assert a.wait_marks("away?", G.delivered, CYAN), "read once focus returns"
    # Read receipts off: delivered marks only.
    b.type("/receipts off\r")
    b.key(TAB)
    assert b.wait("Read receipts off"), "/receipts off"
    b.key(SHIFT_TAB)
    a.type("fourth\r")
    assert a.wait_marks("fourth", G.delivered), "delivered with receipts off"
    time.sleep(1.5)
    Term.pump_all()
    _, colours = a.marks("fourth")
    assert not colours & CYAN, colours
    # Everything survives a restart of alice.
    a.quit()
    a = Term(pair.a_dir, pair.relay.url)
    assert a.wait(G.connected + " connected"), "reconnect"
    a.key(TAB)
    assert a.wait_marks("third", G.delivered, CYAN), "read mark persisted"
    assert a.wait_marks("fourth", G.delivered), "delivered mark persisted"
    receipts = [h for h in history(pair.a_dir, pair.b_id) if "receipt" in h]
    assert len(receipts) >= 4, receipts
    pair.stop()


if __name__ == "__main__":
    run(main)
