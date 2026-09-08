"""The first-run question at a terminal: the answer is typed in the open
(a passphrase is hidden; a yes or no is not), Enter alone means no and
starts an identity of this computer's own, and y goes on to make it a
device of an identity kept elsewhere."""

from harness import *

QUESTION = "Link this computer to an identity you already have? [y/N]"


def stop(t):
    t.p.terminate()
    t.p.wait(timeout=5)
    t.quit()


def main():
    relay = Relay()
    try:
        # No: the answer shows on the prompt line, and an identity of its
        # own follows, asking for its passphrase.
        no = Term(fresh_dir("first-run-no"), relay.url, tty=True)
        assert no.wait(QUESTION), "the question"
        no.type("n\r")
        assert no.wait("[y/N] n"), "the answer is shown as it is typed"
        assert no.wait("Passphrase (optional):"), "a new identity follows"
        no.type("first run\r")
        assert no.wait("Repeat passphrase:"), "repeat"
        no.type("first run\r")
        assert no.wait(G.connected + " connected", timeout=60), "the client starts"
        no.quit()

        # Enter alone is no as well.
        enter = Term(fresh_dir("first-run-enter"), relay.url, tty=True)
        assert enter.wait(QUESTION), "the question"
        enter.type("\r")
        assert enter.wait("Passphrase (optional):"), "Enter alone starts an identity"
        stop(enter)

        # Yes: the directory gets its passphrase question as any new one
        # does, then this computer registers as a device and prints its
        # link. Tall, so that the QR code does not scroll the text away.
        yes = Term(fresh_dir("first-run-yes"), relay.url, rows=60, tty=True)
        assert yes.wait(QUESTION), "the question"
        yes.type("y\r")
        assert yes.wait("[y/N] y"), "the answer is shown as it is typed"
        assert yes.wait("Passphrase (optional):"), "the passphrase question comes first"
        yes.type("\r")
        assert yes.wait("On the device that holds your identity, run", timeout=60), "linking begins"
        assert yes.wait("Waiting for the primary"), "and waits"
        stop(yes)
    finally:
        relay.stop()


if __name__ == "__main__":
    run(main)
