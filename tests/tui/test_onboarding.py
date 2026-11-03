"""The first launch at a terminal: the onboarding asks everything before
anything is written. Quitting leaves the directory empty and the next
start asks again; a passphrase chosen there protects the identity it
makes; linking goes on to the device link; reader mode asks the same
questions one line at a time."""

from harness import *

DOWN = b"\x1b[B"
RIGHT = b"\x1b[C"
CTRL_U = b"\x15"


def stop(t):
    t.p.terminate()
    t.p.wait(timeout=5)
    t.quit()


def pick(t, help_text, tries=6):
    """Turn the focused choice until its help says `help_text`."""
    for _ in range(tries):
        if t.has(help_text):
            return True
        t.key(RIGHT)
    return t.has(help_text)


def to_step(t, name):
    for _ in range(9):
        if t.has(f": {name}"):
            return True
        t.key(PGDN)
    return t.has(f": {name}")


def main():
    relay = Relay()
    try:
        # Quitting writes nothing, and says the next start asks again.
        d = fresh_dir("onboarding-quit")
        quit_ = Term(d, relay.url, tty=True)
        assert quit_.wait("setting up, step 1 of 8: Welcome"), "the onboarding opens"
        quit_.key(CTRL_C)
        assert quit_.wait("Nothing was set up"), "quitting says so"
        quit_.p.wait(timeout=5)
        quit_.quit()
        assert not os.path.exists(os.path.join(d, "identity.json")), "nothing was written"

        # A new identity under a passphrase.
        d = fresh_dir("onboarding-new")
        new = Term(d, relay.url, tty=True)
        assert new.wait("step 1 of 8: Welcome"), "the onboarding opens"
        assert to_step(new, "Protection"), "to the protection"
        assert pick(new, "Asked for at every start"), "a passphrase"
        new.key(DOWN)
        new.type("onboarding words")
        new.key(DOWN)
        new.type("other words")
        new.key(PGDN)
        assert new.wait("not the same"), "two different passphrases are refused"
        new.key(CTRL_U)
        new.type("onboarding words")
        assert to_step(new, "Review"), "to the review"
        assert new.wait("a passphrase"), "the review says what was chosen"
        new.key(ENTER)
        assert new.wait(G.connected + " connected", timeout=60), "the client starts"
        new.quit()
        vault = json.load(open(os.path.join(d, "vault.json")))
        assert vault["kdf"]["algorithm"] == "argon2id", "protected by the passphrase"
        again = Term(d, relay.url, tty=True)
        assert again.wait("Passphrase:"), "the next start asks for it, not the onboarding"
        again.type("onboarding words\r")
        assert again.wait(G.connected + " connected", timeout=60), "and opens"
        again.quit()

        # This computer linked to an identity kept elsewhere. Tall, so that
        # the QR code does not scroll the text away.
        d = fresh_dir("onboarding-link")
        link = Term(d, relay.url, rows=60, tty=True)
        assert link.wait("step 1 of 8: Welcome"), "the onboarding opens"
        link.key(PGDN)
        assert link.wait("A new identity"), "new or link"
        link.type("2")
        link.key(DOWN)
        link.type("laptop")
        assert to_step(link, "Protection"), "to the protection"
        assert pick(link, "Plain files"), "nothing"
        assert to_step(link, "Review"), "to the review"
        assert link.wait("linked to an identity you have"), "the review says so"
        link.key(ENTER)
        assert link.wait("On the device that holds your identity, run", timeout=60), "linking"
        assert link.wait("Waiting for the primary"), "and waits"
        stop(link)

        # Reader mode: the same questions, one per line.
        reader = Term(fresh_dir("onboarding-reader"), relay.url, extra=("--reader",), tty=True)
        assert reader.wait("Step 1 of 8: Welcome."), "line by line"
        assert reader.wait("Choose 1 to 4 [1]:"), "a numbered choice"
        stop(reader)
    finally:
        relay.stop()


if __name__ == "__main__":
    run(main)
