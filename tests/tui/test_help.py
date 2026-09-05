"""The help overlay, the status line's hints, Tab completion, and typos."""

from harness import *


def main():
    relay = Relay()
    a_dir, b_dir = fresh_dir("help-alice"), fresh_dir("help-bob")
    identity(a_dir)
    b_id = identity(b_dir)
    docs = fresh_dir("help-docs")
    os.makedirs(os.path.join(docs, "pictures"))
    for n in ("phone.txt", "photo.jpg"):
        open(os.path.join(docs, n), "w").write("x")
    a = Term(a_dir, relay.url)
    assert a.wait(G.connected + " connected"), "connect"
    assert a.has("Getting started:"), "guided first run"
    assert "/add <id or link>" in a.status() and "F1 help" in a.status(), a.status()

    a.key(F1)
    assert a.wait("Help · any other key closes"), "F1 opens help"
    assert a.has("/add <id or link>") and a.has("more (PgDn)"), "help content"
    # The table's length changes as commands come and go; what must hold is
    # that PgDn brings the rest into view, page by page, down to the keys.
    assert not a.has("/send <path>"), "the first page ends before /send"
    pages = 0
    while not a.has("/send <path>") and pages < 4:
        a.key(PGDN)
        pages += 1
    assert a.has("/send <path>") and pages >= 1, "PgDn scrolls"
    while not a.has("Ctrl-Q quits") and pages < 12:
        a.key(PGDN)
        pages += 1
    assert a.has("Ctrl-Q quits") and a.has("Keys"), "end of help"
    a.key(ESC)
    time.sleep(0.3)
    Term.pump_all()
    assert not a.has("Help · any"), "Esc closes"
    a.type("/help\r")
    assert a.wait("Help · any other key closes") and a.has("Commands"), "/help opens at the top"
    a.click(40, a.rows - 1)
    time.sleep(0.3)
    Term.pump_all()
    assert not a.has("Help · any"), "a click closes"
    a.click(40, a.rows - 1)
    assert a.wait("Help · any other key closes"), "the status line opens it"
    a.key(ESC)

    a.type("/se")
    time.sleep(0.3)
    Term.pump_all()
    assert "/search  /send  /session" in a.status(), a.status()
    a.key(TAB)
    assert a.input_line() == "/search" and "[/search]" in a.status(), (a.input_line(), a.status())
    a.key(TAB)
    assert a.input_line() == "/send", a.input_line()
    a.key(TAB)
    assert a.input_line() == "/session", a.input_line()
    a.key(TAB)
    assert a.input_line() == "/search", "cycles around"
    a.key(ESC)
    a.type("/notif")
    a.key(TAB)
    assert a.input_line() == "/notify" and "/notify all|bell|off:" in a.status(), a.status()
    a.key(ESC)
    a.type("/send")
    time.sleep(0.3)
    Term.pump_all()
    assert "/send <path>: send a file" in a.status(), a.status()
    a.key(ESC)
    a.type("/sned\r")
    assert a.wait("Did you mean /send?"), "typo suggestion"
    a.type("/xyzzy\r")
    assert a.wait("Unknown command /xyzzy. F1 lists"), "no suggestion"
    a.type(f"/send {docs}/ph")
    a.key(TAB)
    assert a.input_line().endswith("/phone.txt"), a.input_line()
    a.key(TAB)
    assert a.input_line().endswith("/photo.jpg"), a.input_line()
    a.key(ESC)
    a.type(f"/send {docs}/pi")
    a.key(TAB)
    assert a.input_line().endswith("/pictures/"), a.input_line()
    a.key(TAB)
    time.sleep(0.3)
    Term.pump_all()
    assert "Nothing to complete" in a.status(), a.status()
    a.key(ESC)

    b = Term(b_dir, relay.url)
    assert b.wait(G.connected + " connected"), "bob"
    a.type(f"/add {b_id} bob\r")
    assert a.wait(" bob · "), "add"
    assert a.wait_for(lambda: "Enter sends" in a.status(), what="chat hint after the lookup toast")
    a.key(TAB)
    assert a.wait("┌ System ─"), "Tab still switches chats"
    a.key(TAB)
    assert a.wait(" bob · ")
    for t in list(TERMS):
        t.quit()
    relay.stop()


if __name__ == "__main__":
    run(main)
