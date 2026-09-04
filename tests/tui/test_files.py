"""File transfer: capability checks, small and multi-chunk files, no
overwriting, spaces and ~ in paths, a stranger's file held unfetched, the
saved path remembered across a restart. With OLD_RELAY pointing at a relay
binary without file storage, also the refusal."""

from harness import *


def main():
    pair = Pair("files", cols=140)
    a, b = pair.alice, pair.bob
    docs = fresh_dir("files-docs")
    os.makedirs(docs)
    small = os.path.join(docs, "notes.txt")
    open(small, "w").write("hello from alice\n" * 10)
    big = os.path.join(docs, "photo.bin")
    big_bytes = os.urandom(150_000)  # three chunks
    open(big, "wb").write(big_bytes)
    open(os.path.join(docs, "space name.txt"), "w").write("with a space")

    a.type(f"/add {pair.b_id} bob\r")
    assert a.wait(" bob · "), "add"
    # Bob has never written: alice cannot know he takes files.
    a.type(f"/send {small}\r")
    assert a.wait("bob cannot receive files yet"), "unknown caps refused"
    a.type("hello bob\r")
    assert b.wait("Contact request from"), "request"
    b.key(SHIFT_TAB)
    b.type("/accept 1\r")
    assert b.wait("hello bob"), "accept"
    b.type("/alias alice\r")
    b.type("hi alice\r")
    assert a.wait("hi alice"), "reply"

    a.type("/send /nonexistent/file\r")
    assert a.wait("File not sent"), "missing file"
    a.type(f"/send {small}\r")
    assert a.wait("[file] notes.txt (170 B)"), "alice's file line"
    assert b.wait(f"[file] notes.txt (170 B) {G.arrow} "), "bob's saved line"
    got = os.path.join(pair.b_dir, "downloads", "notes.txt")
    assert open(got).read() == open(small).read(), "content"
    assert a.wait_marks("[file] notes.txt", G.delivered, CYAN), "read receipt on the file"

    b.type(f"/send {big}\r")
    assert b.wait("[file] photo.bin (146.5 KiB)"), "bob's file line"
    assert a.wait(f"[file] photo.bin (146.5 KiB) {G.arrow} "), "alice's saved line"
    assert open(os.path.join(pair.a_dir, "downloads", "photo.bin"), "rb").read() == big_bytes
    b.type(f"/send {big}\r")
    assert a.wait("photo (2).bin"), "second copy is not an overwrite"
    assert open(os.path.join(pair.a_dir, "downloads", "photo (2).bin"), "rb").read() == big_bytes
    a.type("/send ~/files-docs/space name.txt\r")
    assert b.wait(f"[file] space name.txt (12 B) {G.arrow} "), "space in the name, ~ in the path"

    texts = [h.get("text", "") for h in history(pair.b_dir, pair.a_id)]
    assert any(t.startswith("[file] notes.txt") for t in texts), texts

    # A removed contact's file is held with the request, not fetched.
    b.type("/remove\r")
    time.sleep(0.5)
    a.type(f"/send {small}\r")
    assert a.wait("Sent notes.txt"), "resend"
    assert b.wait_for(lambda: sum("Contact request from" in r for r in b.sc.display) >= 2, what="second request")
    b.key(SHIFT_TAB)
    assert b.wait("not fetched"), "held file notice"
    assert set(os.listdir(os.path.join(pair.b_dir, "downloads"))) == {"notes.txt", "space name.txt"}

    # Where a file went is remembered across restarts.
    a.quit()
    a = Term(pair.a_dir, pair.relay.url, cols=140)
    assert a.wait(G.connected + " connected"), "alice reconnect"
    a.key(TAB)
    assert a.wait(f"[file] photo.bin (146.5 KiB) {G.arrow} "), "saved path persisted"
    assert a.wait("photo (2).bin"), "second saved path persisted"
    pair.stop()

    old_relay = os.environ.get("OLD_RELAY")
    if old_relay:
        old = subprocess.Popen([old_relay, "--ephemeral", "--listen", "127.0.0.1:7825"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5)
        try:
            a = Term(pair.a_dir, "ws://127.0.0.1:7825/ws", cols=140)
            b = Term(pair.b_dir, "ws://127.0.0.1:7825/ws", cols=140)
            assert a.wait(G.connected + " connected") and b.wait(G.connected + " connected"), "old connect"
            a.key(TAB)
            a.type(f"/send {small}\r")
            assert a.wait("relay is too old for files"), "old relay refusal"
        finally:
            old.terminate()


if __name__ == "__main__":
    run(main)
