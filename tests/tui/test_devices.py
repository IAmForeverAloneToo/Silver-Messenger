"""Devices: a second computer linked from the primary by the link it
prints, with the contacts, the history and the group that come along; a
message from the laptop shown on the primary as its own and answered to
both devices; the laptop in the group; the laptop unlinked, refused by
the relay and left out of what comes next; and the laptop erasing
itself."""

import os

from harness import *


def main():
    pair = Pair("devices", cols=140)
    pair.befriend()
    a, b = pair.alice, pair.bob

    # A group, so the laptop has one to follow into.
    a.type("/group new team\r")
    assert a.wait("you are an admin"), "the group pane opens"
    a.type("/group add bob\r")
    assert a.wait("· you added bob"), "bob added"
    assert b.wait("# team"), "bob's list has the group"

    # The laptop prints a link; alice takes it in with the history.
    l_dir = fresh_dir("devices-laptop")
    linking = Linking(l_dir, pair.relay.url, name="laptop")
    link = linking.link()
    a.type(f"/devices link {link}\r")
    assert a.wait('Linking "laptop"'), "alice starts linking"
    assert a.wait('Linked the device "laptop"', timeout=30), "linked"
    linking.wait_line("Linked: this is the device")
    linking.wait_line("Run silver to start", timeout=60)
    assert linking.p.wait(timeout=30) == 0, "the device's link run ends well"
    a.type("/devices\r")
    assert a.wait("1. laptop"), "the device is listed"

    # The laptop starts as alice's device: bob is there with the history,
    # and the group follows once the primary adds the laptop's leaf.
    l = Term(l_dir, pair.relay.url, cols=140)
    assert l.wait(G.connected + " connected"), "the laptop connects"
    assert l.wait("device laptop"), "the status line names the device"
    assert l.wait('This is the device "laptop"'), "the laptop knows whose it is"
    assert l.wait("Joined team", timeout=60), "the group followed"
    l.type("/devices\r")
    assert l.wait("the primary  "), "the primary is listed as a device"
    l.key(TAB)
    assert l.wait(" bob · "), "bob came along"
    assert l.wait("hello bob") and l.has("hi alice"), "the history came along"

    # The laptop writes: bob reads it as alice's, and alice's primary shows
    # it as her own. Bob answers: both devices read it.
    l.type("from the laptop\r")
    assert b.wait("from the laptop"), "bob reads the laptop's line"
    a.key(TAB)
    assert a.wait("from the laptop"), "the primary shows the laptop's line"
    assert a.has("you") , "as alice's own"
    b.type("both of you\r")
    assert a.wait("both of you"), "the primary reads bob"
    assert l.wait("both of you"), "and so does the laptop"

    # In the group, the laptop reads and writes as alice.
    a.key(TAB)
    assert a.wait("you are an admin"), "alice in the group"
    a.type("team hello\r")
    l.key(TAB)
    assert l.wait("team hello"), "the laptop reads the group"
    l.type("laptop in the group\r")
    assert a.wait("laptop in the group"), "the primary reads its device's group line"
    b.key(TAB)
    assert b.wait(" alice: laptop in the group"), "bob reads it as alice's"
    b.key(SHIFT_TAB)

    # Alice unlinks the laptop: the relay refuses it, and the next message
    # from bob reaches the primary alone.
    a.type("/devices remove 1\r")
    assert a.wait('Unlinked "laptop"'), "unlinked"
    assert l.wait("unlinked by your primary", timeout=30), "the laptop is told"
    a.type("/devices\r")
    assert a.wait("No linked devices"), "the list is empty again"
    a.key(TAB)
    b.type("just you now\r")
    assert a.wait("just you now"), "the primary reads bob"
    time.sleep(1.5)
    Term.pump_all()
    assert not l.has("just you now"), "the laptop does not"

    # The laptop erases itself.
    l.type("/devices leave confirm\r")
    assert l.p.wait(timeout=30) == 0, "the laptop exits"
    assert not os.path.exists(os.path.join(l_dir, "identity.json")), "keys erased"
    assert not os.path.exists(os.path.join(l_dir, "contacts.json")), "contacts erased"
    if l in TERMS:
        TERMS.remove(l)
    pair.stop()


if __name__ == "__main__":
    run(main)
