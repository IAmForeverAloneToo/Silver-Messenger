"""Groups: one made and listed, a contact added and taken in at once, a
message to everyone with the writer's name and a mark once the relay has
every copy, a stranger's invitation waiting in Requests until /accept, a
join by invite link taken without a second yes, a rename seen by all, a
removal that ends what the removed member reads, a leave committed by the
admin's client, and what survives a restart."""

import re

from harness import *


def main():
    pair = Pair("groups", cols=140)
    pair.befriend()
    a, b = pair.alice, pair.bob

    # Alice makes a group: the chat list gets a row and the pane opens once
    # the relay has taken the group.
    a.type("/group new team\r")
    assert a.wait("# team"), "group listed"
    assert a.wait("you are an admin"), "the group pane opens"
    a.type("/group members\r")
    assert a.wait("team: 1 member(s)"), "/group members"
    assert a.has("you (admin)"), "the admin is listed"
    a.key(SHIFT_TAB)
    assert a.wait("you are an admin"), "back to the group pane"

    # Bob is a contact both ways: his client takes the Welcome at once.
    a.type("/group add bob\r")
    assert a.wait("· you added bob"), "add noted for alice"
    assert a.wait("2 members"), "title counts him"
    assert b.wait("# team"), "bob's chat list gets the group"
    b.key(TAB)
    assert b.wait("· alice added you"), "bob's pane says who added him"
    assert b.has("2 members"), "bob's title"

    # A message to everyone shows the writer's name at the other end, and
    # is marked once the relay has taken every copy.
    a.type("hello everyone\r")
    assert a.wait_marks("hello everyone", G.accepted), "accepted mark"
    assert b.wait(" alice: hello everyone"), "bob reads it, with the writer's name"
    b.type("hi all\r")
    assert a.wait(" bob: hi all"), "alice reads bob"
    assert b.wait_marks("hi all", G.accepted), "bob's mark"

    # Carol has never heard of alice: alice adds her as a contact and to
    # the group, and the invitation waits as an entry of carol's chat list.
    c_dir = fresh_dir("groups-carol")
    c_id = identity(c_dir)
    c = Term(c_dir, pair.relay.url, cols=140)
    assert c.wait(G.connected + " connected"), "carol connects"
    a.type(f"/add {c_id} carol\r")
    assert a.wait(" carol · "), "carol added as a contact"
    a.key(TAB)
    assert a.wait("you are an admin"), "back to the group"
    a.type("/group add carol\r")
    assert a.wait("· you added carol"), "carol added to the group"
    # The invitation's own line says it is there to open; Shift-Tab lands
    # on it, and its title says whose word the name is and how big it is.
    assert c.wait("invites you to the group team"), "carol is told of the invitation"
    # The line wraps somewhere; the number is read across the wrap, with
    # the box borders and the indent between the rows taken out.
    assert c.wait_for(
        lambda: "number 1:" in re.sub(r"[│\s]+", " ", " ".join(c.sc.display)),
        what="with its number",
    )
    time.sleep(0.5)
    assert b"\x07" not in c.take_raw(), "an invitation rings nothing; only a message does"
    c.key(SHIFT_TAB)
    assert c.wait(" invitation 1 · team · from "), "the invitation's pane"
    assert c.has("? invitation · team"), "listed as an invitation"
    assert c.has("3 members"), "with its size"
    # A bare /accept on the entry joins (the numbered form is covered by
    # the unit tests).
    c.type("/accept\r")
    assert c.wait("· "), "carol's group pane opens"
    assert c.wait("added you"), "with the note"
    assert c.has("3 members"), "carol's title"
    c.type("hello from carol\r")
    assert a.wait(" carol: hello from carol"), "alice reads carol"
    assert b.wait("hello from carol"), "bob reads carol"

    # Dave joins by the link alice hands out: his client asked, so the
    # Welcome needs no second yes.
    a.take_raw()
    a.type("/group invite copy\r")
    assert a.wait("Handed the invite link for team"), "link copied"
    links = wait_osc52(a)
    assert links and links[-1].startswith("silver://group/"), links
    link = links[-1]
    d_dir = fresh_dir("groups-dave")
    identity(d_dir)
    d = Term(d_dir, pair.relay.url, cols=140)
    assert d.wait(G.connected + " connected"), "dave connects"
    # Joining tells a stranger this id, so the link only says so; the
    # second line asks.
    d.type(f"/group join {link}\r")
    assert wait_flat(d, "tells the admin your id"), "joining says what it discloses"
    assert not d.has("Join request sent"), "and nothing is sent on one line"
    d.type("/group join confirm\r")
    assert d.wait("Join request sent"), "request sent"
    assert a.wait("joined by link"), "alice's client added dave"
    assert d.wait("# team"), "dave's chat list has the group"
    d.key(TAB)
    assert d.wait("· you joined by the link"), "dave's pane"
    assert d.has("4 members"), "dave's title"
    d.type("dave here\r")
    assert a.wait("dave here") and c.wait("dave here"), "everyone reads dave"

    # A rename by the admin reaches everyone.
    a.type("/group rename crew\r")
    assert a.wait("· you renamed the group to crew"), "alice's note"
    assert b.wait("· alice renamed the group to crew"), "bob's note"
    assert d.wait("renamed the group to crew") and d.has("# crew"), "dave's list follows"

    # Bob is removed: he sees it, and reads nothing more.
    a.type("/group remove bob\r")
    assert a.wait("· you removed bob"), "removal noted"
    assert b.wait("· alice removed you"), "bob told"
    assert b.wait("# crew (removed)"), "bob's row says so"
    a.type("without bob\r")
    assert c.wait("without bob") and d.wait("without bob"), "the others read on"
    time.sleep(1.5)
    Term.pump_all()
    assert not b.has("without bob"), "bob does not"
    b.type("too late\r")
    assert b.wait("Not sent to crew"), "bob cannot write either"

    # Carol leaves: the admin's client takes her out at once, and the
    # others hear of it from that commit.
    c.type("/group leave\r")
    assert c.wait("# crew (left)"), "carol's row says so"
    assert a.wait("· carol left"), "alice committed the leave"
    assert d.wait("left") and d.has("2 members"), "dave sees her go"

    # Everything is there after a restart of alice.
    a.quit()
    a = Term(pair.a_dir, pair.relay.url, cols=140)
    assert a.wait(G.connected + " connected"), "alice reconnects"
    assert a.has("# crew"), "the group is listed again"
    a.key(TAB)
    a.key(TAB)
    a.key(TAB)
    assert a.wait("2 members"), "the membership survived"
    assert a.has("hello everyone") and a.has("without bob"), "and the history"
    a.type("still here\r")
    assert d.wait("still here"), "and the keys"
    pair.stop()


if __name__ == "__main__":
    run(main)
