"""Groups: one made and listed, a contact added and taken in at once, a
message to everyone with the writer's name and a mark once the relay has
every copy, a stranger's invitation waiting in Requests until /accept, a
join by invite link taken without a second yes, a rename seen by all, a
removal that ends what the removed member reads, and what survives a
restart."""

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
    # the group, and the invitation waits in carol's Requests pane.
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
    assert c.wait("Requests"), "carol's Requests pane appears"
    c.key(SHIFT_TAB)
    assert c.wait("g1. team"), "the invitation is listed"
    assert c.has("a group of 3, from"), "with its size and sender"
    c.type("/accept g1\r")
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
    links = osc52(a.take_raw())
    assert links and links[-1].startswith("silver://group/"), links
    link = links[-1]
    d_dir = fresh_dir("groups-dave")
    identity(d_dir)
    d = Term(d_dir, pair.relay.url, cols=140)
    assert d.wait(G.connected + " connected"), "dave connects"
    d.type(f"/group join {link}\r")
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

    # Everything is there after a restart of alice.
    a.quit()
    a = Term(pair.a_dir, pair.relay.url, cols=140)
    assert a.wait(G.connected + " connected"), "alice reconnects"
    assert a.has("# crew"), "the group is listed again"
    a.key(TAB)
    a.key(TAB)
    a.key(TAB)
    assert a.wait("3 members"), "the membership survived"
    assert a.has("hello everyone") and a.has("without bob"), "and the history"
    a.type("still here\r")
    assert c.wait("still here"), "and the keys"
    pair.stop()


if __name__ == "__main__":
    run(main)
