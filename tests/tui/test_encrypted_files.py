"""Received files kept as ciphertext: with a passphrase, /files encrypt on
writes downloads under the data key and the line says so, /files decrypt
writes a plain copy beside, /open hands the opener a private plain copy
that goes at exit, turning it off leaves the encrypted files readable,
and --export-history writes the conversation out of the unlocked store."""

import subprocess

from harness import *


def main():
    relay = Relay()
    a_dir, b_dir = fresh_dir("encrypted-alice"), fresh_dir("encrypted-bob")
    identity(a_dir)
    b_id = identity(b_dir)
    docs = fresh_dir("encrypted-docs")
    os.makedirs(docs, exist_ok=True)
    small = os.path.join(docs, "notes.txt")
    open(small, "w").write("kept under the data key\n")
    # Bob's directory is protected by a passphrase; alice's is plain.
    env = client_env(SILVER_PASSPHRASE="correct horse")
    silver("--data-dir", b_dir, "--set-passphrase", env=env)
    a = Term(a_dir, relay.url, cols=140)
    b = Term(b_dir, relay.url, cols=140, env=env)
    assert a.wait(G.connected + " connected") and b.wait(G.connected + " connected"), "connect"
    a.type(f"/add {b_id} bob\r")
    assert a.wait(" bob · "), "add"
    a.type("hello bob\r")
    assert b.wait("Contact request from"), "request"
    b.key(SHIFT_TAB)
    b.type("/accept 1\r")
    assert b.wait("hello bob"), "accept"
    b.type("/alias alice\r")
    b.type("hi alice\r")
    assert a.wait("hi alice"), "reply"

    # Without protection the option is refused; with it, taken.
    a.type("/files encrypt on\r")
    assert a.wait("stored unencrypted"), "refused on a plain directory"
    b.type("/files encrypt on\r")
    assert b.wait("written encrypted from now on"), "taken with a passphrase"

    a.type(f"/send {small}\r")
    assert b.wait("notes.txt (24 B) · /get to fetch"), "bob is asked"
    b.type("/get\r")
    assert b.wait("(encrypted)"), "the line says the file is encrypted"
    saved = os.path.join(b_dir, "downloads", "notes.txt")
    raw = open(saved, "rb").read()
    assert raw.startswith(b"SMV1") and b"kept under" not in raw, "ciphertext on disk"

    # A plain copy on request, beside it.
    b.type("/files decrypt\r")
    assert b.wait("Plain copy written"), "decrypted"
    plain = os.path.join(b_dir, "downloads", "notes (2).txt")
    assert open(plain).read() == "kept under the data key\n", "the plain copy"

    # /open hands the opener a private plain copy under .open/.
    b.type("/open\r")
    copy = os.path.join(b_dir, "downloads", ".open", "notes.txt")
    b.wait_for(lambda: os.path.exists(copy), what="the plain copy for the opener")
    assert open(copy).read() == "kept under the data key\n", "decrypted for the opener"
    assert os.stat(copy).st_mode & 0o777 == 0o600, oct(os.stat(copy).st_mode)

    # Off again: new files are plain, the encrypted one stays and is read.
    b.type("/files encrypt off\r")
    assert b.wait("plain files from now on"), "off"
    a.type(f"/send {small}\r")
    assert b.wait_for(lambda: sum("/get to fetch" in r for r in b.sc.display) == 1, what="second file waiting")
    b.type("/get\r")
    assert b.wait("notes (3).txt"), "saved plain under the next free name"
    assert open(os.path.join(b_dir, "downloads", "notes (3).txt")).read() == "kept under the data key\n"
    assert open(saved, "rb").read().startswith(b"SMV1"), "the encrypted one stays encrypted"

    # The plain copy for the opener goes with the client.
    b.quit()
    assert not os.path.exists(os.path.join(b_dir, "downloads", ".open")), "removed at exit"

    # The export: from the unlocked store, outside the data directory only.
    out = fresh_dir("encrypted-export")
    said = silver("--data-dir", b_dir, "--export-history", out, env=env)
    assert "Wrote 1 conversation(s)" in said, said
    exported = open(os.path.join(out, "alice.txt")).read()
    assert "alice: hello bob" in exported and "you: hi alice" in exported, exported
    assert "notes.txt" in exported, exported
    try:
        silver("--data-dir", b_dir, "--export-history", os.path.join(b_dir, "export"), env=env)
        assert False, "an export inside the data directory went through"
    except subprocess.CalledProcessError as e:
        assert "outside the data directory" in e.stderr, e.stderr
    a.quit()
    relay.stop()


if __name__ == "__main__":
    run(main)
