"""The everyday features: a reply quoted from the reader's own copy, a
reaction under the message, an edit in place with its mark, a deletion for
everyone leaving a placeholder on both sides, a deletion for me that the
other side keeps, a timer that makes a message vanish on time on both
sides, and what the history keeps of it all."""

from harness import *


def main():
    pair = Pair("everyday", cols=120)
    pair.befriend()
    a, b = pair.alice, pair.bob

    # A reply quotes the message it answers, on each side from that
    # side's own copy: "alice: hello bob" for bob, "you: hello bob" for
    # alice.
    b.type("/reply yes, that one\r")
    assert b.wait("yes, that one"), "the reply is sent"
    assert b.has(G.reply + " alice: hello bob"), "quoted for bob"
    assert a.wait("yes, that one"), "the reply arrives"
    assert a.has(G.reply + " you: hello bob"), "quoted for alice"

    # A reaction shows under the message: at once here, and there once it
    # has left with a receipt's wait.
    a.type("/react +1\r")
    assert a.wait("+1 you"), "own reaction shown at once"
    assert b.wait("+1 alice", timeout=25), "the reaction reaches bob"

    # An edit shows in place, marked, on both sides.
    a.type("second thoughts\r")
    assert b.wait("second thoughts"), "the text arrives"
    a.type("/edit second thoughts, revised\r")
    assert a.wait("second thoughts, revised (edited)"), "edited here"
    assert b.wait("second thoughts, revised (edited)"), "and there"

    # Delete for everyone: a placeholder on both sides, the text gone.
    a.type("/delete\r")
    assert a.wait("· you deleted a message"), "placeholder here"
    assert b.wait("· alice deleted a message"), "placeholder there"
    assert not b.has("second thoughts"), "the text is gone from bob's screen"

    # Delete for me: gone here, kept there.
    b.type("only bob keeps this\r")
    assert a.wait("only bob keeps this"), "delivered"
    a.type("/delete me\r")
    assert a.wait("Removed from your devices"), "told"
    a.wait_for(lambda: not a.has("only bob keeps this"), what="the line removed")
    assert b.has("only bob keeps this"), "bob keeps his copy"

    # The history holds the placeholder and not the removed line.
    entries = [h for h in history(pair.a_dir, pair.b_id) if "id" in h]
    texts = [h.get("text") for h in entries]
    assert "only bob keeps this" not in texts, texts
    assert "second thoughts, revised" not in texts, texts
    assert any(h.get("deleted") for h in entries), entries

    # A timer: a note says who set it, the lines carry the mark, and the
    # message vanishes on time for the sender and for the reader.
    a.type("/timer 5s\r")
    assert a.wait("· you set messages to disappear after 5 seconds"), "the note here"
    assert b.wait("· alice set messages to disappear after 5 seconds"), "and there"
    a.type("going soon\r")
    assert b.wait("going soon"), "delivered"
    assert a.has(G.timer), "the timer mark"
    a.wait_for(lambda: not a.has("going soon"), timeout=15, what="vanished for the sender")
    b.wait_for(lambda: not b.has("going soon"), timeout=15, what="vanished for the reader")

    # In a group, the timer is an admin's word, told to the members and to
    # a newcomer; a reaction and an edit pass under the sender's name.
    a.type("/group new team\r")
    assert a.wait("you are an admin"), "the group pane opens"
    a.type("/timer 1h\r")
    assert a.wait("· you set messages to disappear after 1 hour"), "set in the group"
    a.type("/group add bob\r")
    assert a.wait("· you added bob"), "bob added"
    assert b.wait("# team"), "bob's list has the group"
    b.key(TAB)
    assert b.wait("· alice set messages to disappear after 1 hour"), "the newcomer is told"
    b.type("/timer off\r")
    assert b.wait("Only an admin sets a group's timer"), "not bob's to set"
    a.type("in the team\r")
    assert b.wait("in the team"), "delivered to the group"
    assert b.has(G.timer), "with the timer mark"
    b.type("/react +1\r")
    assert b.wait("+1 you"), "bob's reaction shown to him"
    assert a.wait("+1 bob"), "and to alice"
    a.type("/edit in the team, edited\r")
    assert b.wait("in the team, edited (edited)"), "edited for bob"
    assert a.has("in the team, edited (edited)"), "and for alice"

    # Nothing of it comes back after a restart; the placeholder does.
    a.quit()
    a = Term(pair.a_dir, pair.relay.url, cols=120)
    assert a.wait(G.connected + " connected"), "reconnect"
    a.key(TAB)
    assert a.wait("· you deleted a message"), "the placeholder is kept"
    assert not a.has("going soon") and not a.has("only bob keeps this"), "gone for good"
    pair.stop()


if __name__ == "__main__":
    run(main)
