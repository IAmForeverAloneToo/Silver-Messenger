"""File transfer: capability checks, a file waits for /get by default, /files
auto fetches at once, a double click fetches, /get all, no overwriting,
spaces and ~ in paths, a stranger's file fetchable after /accept, waiting
and saved files remembered across a restart. With OLD_RELAY pointing at a
relay binary without file storage, also the refusal."""

from harness import *


def downloads(data_dir):
    path = os.path.join(data_dir, "downloads")
    return set(os.listdir(path)) if os.path.isdir(path) else set()


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

    # By default a file waits until bob asks for it.
    a.type(f"/send {small}\r")
    assert a.wait("[file] notes.txt (170 B)"), "alice's file line"
    assert b.wait("[file] notes.txt (170 B) · /get to fetch"), "bob is asked"
    time.sleep(0.5)
    assert downloads(pair.b_dir) == set(), "nothing written before /get"
    # The hint shows once the earlier toasts have gone.
    assert b.wait_for(lambda: "/get fetches notes.txt" in b.status(), what="status hint")
    b.type("/get\r")
    assert b.wait(f"[file] notes.txt (170 B) {G.arrow} "), "bob's saved line"
    got = os.path.join(pair.b_dir, "downloads", "notes.txt")
    assert open(got).read() == open(small).read(), "content"
    assert a.wait_marks("[file] notes.txt", G.delivered, CYAN), "read receipt on the file"
    b.type("/get\r")
    assert b.wait("No file is waiting"), "nothing left to fetch"

    # Bob trusts alice: her files are fetched as they arrive.
    b.type("/files\r")
    assert b.wait("Files from alice wait for /get"), "/files shows the setting"
    b.type("/files auto\r")
    assert b.wait("fetched as they arrive"), "/files auto"
    a.type(f"/send {small}\r")
    assert b.wait(f"[file] notes.txt (170 B) {G.arrow} ") and b.wait("notes (2).txt"), "auto fetch, no overwrite"
    # The last line with a text: a receipt line may land after it.
    texts = [h["text"] for h in history(pair.b_dir, pair.a_id) if "text" in h]
    assert texts[-1].endswith("notes (2).txt"), texts[-1]

    # Alice fetches bob's file with a double click on its line.
    b.type(f"/send {big}\r")
    assert b.wait("[file] photo.bin (146.5 KiB)"), "bob's file line"
    assert a.wait("[file] photo.bin (146.5 KiB) · /get to fetch"), "alice is asked"
    y, x = a.row_of("[file] photo.bin")
    a.click(x + 3, y)
    assert a.wait("Double-click to fetch photo.bin"), "click hint"
    time.sleep(0.6)
    a.click(x + 3, y)
    a.click(x + 3, y)
    assert a.wait(f"[file] photo.bin (146.5 KiB) {G.arrow} "), "double click fetches"
    assert open(os.path.join(pair.a_dir, "downloads", "photo.bin"), "rb").read() == big_bytes
    b.type(f"/send {big}\r")
    assert a.wait_for(lambda: sum("/get to fetch" in r for r in a.sc.display) == 1, what="second file waiting")
    a.type("/get\r")
    assert a.wait("photo (2).bin"), "second copy is not an overwrite"
    assert open(os.path.join(pair.a_dir, "downloads", "photo (2).bin"), "rb").read() == big_bytes
    a.type("/send ~/files-docs/space name.txt\r")
    assert b.wait(f"[file] space name.txt (12 B) {G.arrow} "), "space in the name, ~ in the path"

    texts = [h.get("text", "") for h in history(pair.b_dir, pair.a_id)]
    assert any(t.startswith("[file] notes.txt") for t in texts), texts

    # Files still waiting survive a restart, and /get all takes them together.
    b.type("/files ask\r")
    assert b.wait("wait for /get"), "/files ask"
    a.type(f"/send {small}\r")
    a.type(f"/send {small}\r")
    assert b.wait_for(lambda: sum("/get to fetch" in r for r in b.sc.display) == 2, what="two waiting")
    b.quit()
    b = Term(pair.b_dir, pair.relay.url, cols=140)
    assert b.wait(G.connected + " connected"), "bob reconnect"
    b.key(TAB)
    assert b.wait_for(lambda: sum("/get to fetch" in r for r in b.sc.display) == 2, what="still waiting after a restart")
    b.type("/get all\r")
    assert b.wait("notes (3).txt") and b.wait("notes (4).txt"), "/get all"
    assert downloads(pair.b_dir) == {"notes.txt", "notes (2).txt", "notes (3).txt", "notes (4).txt", "space name.txt"}

    # A removed contact's file is held with the request, never fetched, and
    # fetchable once they are accepted again.
    b.type("/remove\r")
    time.sleep(0.5)
    a.type(f"/send {small}\r")
    assert a.wait("Sent notes.txt"), "resend"
    assert b.wait("Contact request from"), "request again"
    b.key(SHIFT_TAB)
    assert b.wait("not fetched; /get can once you accept"), "held file notice"
    time.sleep(0.5)
    assert "notes (5).txt" not in downloads(pair.b_dir), "a stranger's file stays on the relay"
    b.type("/accept 1\r")
    assert b.wait("[file] notes.txt (170 B) · /get to fetch"), "fetchable after accept"
    b.type("/get\r")
    assert b.wait("notes (5).txt"), "fetched after accept"

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
