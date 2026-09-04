"""Protection at rest: the System pane says how the files are protected,
a passphrase encrypts config.json, /lock drops the keys and the passphrase
(from the environment here) opens the client again, and /lock without a
passphrase says why not."""

from harness import *


def main():
    relay = Relay()
    a_dir, b_dir = fresh_dir("lock-alice"), fresh_dir("lock-bob")
    identity(a_dir)
    identity(b_dir)

    # Alice sets a passphrase; from then on identity.json is ciphertext.
    env = client_env(SILVER_PASSPHRASE="correct horse")
    out = silver("--data-dir", a_dir, "--set-passphrase", env=env)
    assert "encrypted under your passphrase" in out, out
    raw = open(os.path.join(a_dir, "identity.json"), "rb").read()
    assert raw.startswith(b"SMV1") and b"signing_seed" not in raw, raw[:16]
    a = Term(a_dir, relay.url, env=env)
    assert a.wait(G.connected + " connected"), "alice connects with the passphrase from the environment"
    assert not a.has("stored unencrypted"), "no warning once a passphrase is set"
    a.type("/lock\r")
    assert a.wait_for(lambda: b"Locked." in a.raw, what="the lock message")
    assert a.wait(G.connected + " connected"), "unlocked again with the passphrase from the environment"
    assert a.wait("Welcome to Silver Messenger"), "a fresh start after the lock"
    a.quit()

    # Bob has no passphrase: the System pane says how (or whether) the files
    # are protected, and /lock has nothing to lock behind.
    b = Term(b_dir, relay.url)
    assert b.wait(G.connected + " connected"), "bob connects"
    protected = b.has("encrypted with a key kept in this computer's key store")
    plain = b.has("stored unencrypted")
    assert protected or plain, "the System pane says how the files are kept"
    b.type("/lock\r")
    assert b.wait("Locking needs a passphrase"), "no lock without a passphrase"
    b.quit()
    relay.stop()


if __name__ == "__main__":
    run(main)
