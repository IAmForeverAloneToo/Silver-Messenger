"""`/rekey` (docs/design/dh-rotation.md): the first line explains and
changes nothing; the second replaces the encryption key under the same
identity, and the contact's next message shows a KEY CHANGE notice — the
routine one, not the alarm for a key that is not theirs — after which
messages flow both ways under the new key."""

import json
import os
import time

from harness import *


def secrets(data_dir):
    with open(os.path.join(data_dir, "identity.json")) as f:
        return json.load(f)


def main():
    pair = Pair("rekey", cols=120)
    pair.befriend()
    a, b = pair.alice, pair.bob

    # The first line says what would happen and stops.
    a.type("/rekey\r")
    assert a.wait("/rekey confirm"), "the first line explains and asks for the second"
    assert not a.has("Encryption key replaced"), "nothing changed yet"

    # The second line goes ahead: the same identity, a new key. On disk
    # (plain here: no passphrase in the tests) the signing seed is what it
    # was, the Diffie-Hellman secret is new, and the old one is kept
    # aside with the time it goes.
    before = secrets(pair.a_dir)
    assert "previous_dh" not in before, "no previous key before a rekey"
    a.type("/rekey confirm\r")
    assert a.wait("Encryption key replaced"), "rekeyed"
    after = secrets(pair.a_dir)
    assert after["signing_seed"] == before["signing_seed"], "the identity did not move"
    assert after["dh_secret"] != before["dh_secret"], "the encryption key did"
    assert after["previous_dh"]["dh_secret"] == before["dh_secret"], "the old key is kept for the grace"
    assert after["previous_dh"]["until_ms"] > 0, "with the time it goes"

    # Alice writes next. Once the relay has her new key her sessions are
    # retired, so this message hands bob a fresh handshake under it; bob's
    # client sees a key that is not the one pinned, asks the relay, and
    # takes it as a key change -- signed by her identity, so a notice to
    # confirm, not an alarm. The notice is in bob's System pane.
    time.sleep(1.5)
    a.type("all done here\r")
    assert b.wait("all done here", timeout=30), "the message reaches bob under the new key"
    b.key(TAB)
    assert b.wait("┌ System"), "bob looks at System"
    assert b.wait("KEY CHANGE: alice's encryption key is different", timeout=30), "bob is told"
    assert b.has("/rekey") and b.has("reinstall"), "with the routine reason named"
    assert not b.has("may not be from"), "not the alarm for a key that is not theirs"
    assert not b.has("not the one they publish"), "nor the one for a retired key"
    b.key(TAB)
    assert b.wait("┌ alice"), "and back to the chat"

    # And back: bob's reply travels on the session alice just started.
    b.type("did you rekey?\r")
    assert a.wait("did you rekey?", timeout=30), "alice reads the reply"

    pair.stop()


if __name__ == "__main__":
    run(main)
