"""Requests as chats (docs/design/requests.md): a stranger's message is an
entry of the chat list that rings once; bare /decline there is *not now*,
and the stranger's next message waits without ringing under the next
number; typing a reply on the entry accepts and sends; /requests lists
what waits; /whois, /copy id with Tab completion of the alias, a click on
the title that copies the id; bare /block from the chat and /unblock by a
prefix of the id."""

import re

from harness import *


def main():
    pair = Pair("requests")
    a, b = pair.alice, pair.bob
    a.type(f"/add {pair.b_id} bob\r")
    assert a.wait(" bob · "), "add"
    b.take_raw()

    # A stranger's first message rings once and is announced with its number.
    a.type("first\r")
    assert b.wait("Contact request from"), "announced"
    assert b.wait("number 1"), "with its number"
    time.sleep(0.5)
    raw = b.take_raw()
    assert b"\x07" in raw, "a stranger's first message rings"

    # Shift-Tab lands on the entry; a bare /decline there says not now.
    b.key(SHIFT_TAB)
    assert b.wait(" request 1 · not a contact · "), "the entry opens and says what it is"
    assert b.has("first"), "with the held message"
    # The arrival toast holds the status line for a few seconds first.
    assert b.wait("/accept · /decline · /block", timeout=10), "the status line offers the three"
    b.type("/decline\r")
    assert b.wait("Declined "), "declined"
    assert b.has("nothing sent"), "and nothing was sent"
    assert not b.has("? " + pair.a_id[:8]), "the entry is gone"

    # Written to again: back as request 2, quietly.
    b.take_raw()
    a.type("second\r")
    assert b.wait_for(
        lambda: "You declined them before, so this rang nothing." in flat(b),
        what="quiet on repeat",
    )
    time.sleep(1.0)
    raw = b.take_raw()
    assert b"\x07" not in raw, "no bell for a declined stranger"
    assert b"]777;" not in raw and b"]9;Silver" not in raw, "no notification either"
    assert b.has("number 2"), "numbers hold still: the next one, not 1 again"
    assert b.has("? " + pair.a_id[:8]), "the entry is back"

    # /requests lists what waits, with the number.
    b.type("/requests\r")
    assert b.wait("2. request from " + pair.a_id[:8]), "/requests lists it"

    # A reply typed on the entry accepts and is delivered.
    b.key(SHIFT_TAB)
    assert b.wait(" request 2 · "), "entry 2 opens"
    b.type("hello alice\r")
    assert b.wait(f" {pair.a_id[:8]}… · {pair.a_id[:20]}"), "answering accepts and opens the chat"
    assert a.wait("hello alice"), "and the reply is delivered"
    assert b.has("second"), "the held message is in the chat"
    assert not b.has("first"), "the declined message was dropped with the decline"
    b.type("/alias alice\r")
    assert b.wait(" alice · "), "named"

    # /whois in the chat, and /copy id with the alias completed by Tab.
    b.type("/whois\r")
    assert b.wait(f"alice: {pair.a_id}"), "/whois names the id"
    assert b.has("verified: no"), "and the standing"
    b.key(SHIFT_TAB)
    assert b.wait(" alice · "), "back to the chat"
    b.type("/copy id ali")
    b.key(TAB)
    assert b.wait_for(lambda: any("/copy id alice" in r for r in b.sc.display), what="Tab completes the alias")
    b.take_raw()
    b.type("\r")
    assert b.wait("alice's id"), "copied"
    raw = b.take_raw()
    assert b"\x1b]52;" in raw and base64.b64encode(pair.a_id.encode()) in raw, "the id went to the terminal's clipboard"

    # A click on the title copies the id too.
    b.take_raw()
    b.click(b.cols // 2, 0)
    assert b.wait("alice's id"), "the title click copies"
    assert base64.b64encode(pair.a_id.encode()) in b.take_raw(), "the same id"

    # Bare /block from the chat; /unblock by a prefix of the id.
    b.type("/block\r")
    assert b.wait("Blocked " + pair.a_id), "bare /block from the chat"
    a.type("still there?\r")
    time.sleep(1.5)
    Term.pump_all()
    assert not b.has("still there?"), "dropped on arrival"
    b.type(f"/unblock {pair.a_id[:6]}\r")
    assert b.wait("Unblocked " + pair.a_id), "/unblock by a prefix"
    pair.stop()


if __name__ == "__main__":
    run(main)
