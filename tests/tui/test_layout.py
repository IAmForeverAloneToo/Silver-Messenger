"""The narrow layout, themes, focus borders, the "new messages" rule and
the date rule."""

from harness import *


def main():
    relay = Relay()
    a_dir, b_dir = fresh_dir("layout-alice"), fresh_dir("layout-bob")
    identity(a_dir)
    b_id = identity(b_dir)

    # A narrow terminal folds the chat list away and numbers the panes.
    a = Term(a_dir, relay.url, cols=60)
    assert a.wait(G.connected + " connected"), "connect"
    assert not a.sc.display[0].startswith("┌ Chats") and "┌ System 1/1 " in a.sc.display[0], a.sc.display[0]
    b = Term(b_dir, relay.url)
    assert b.wait(G.connected + " connected"), "bob"
    a.type(f"/add {b_id} bob\r")
    assert a.wait(" bob · ") and "2/2 " in a.sc.display[0], a.sc.display[0]
    a.key(TAB)
    assert a.wait("System 1/2"), "Tab in the narrow layout"
    a.quit()

    # Themes: dark by default, light and mono by flag, NO_COLOR, /theme remembered.
    a = Term(a_dir, relay.url)
    assert a.wait(G.connected + " connected"), "wide"
    a.key(TAB)
    assert a.wait(" bob · ")
    y, x = a.row_of("connected")
    dark_fg = a.fg_at(x, y)
    assert dark_fg != "default", "the dark theme colours the status"
    in_y = a.rows - 4  # top border of the one-row compose box
    assert "┌ Message" in a.sc.display[in_y]
    assert a.fg_at(a.cols - 1, in_y) != "default", "the compose box border is accented"
    assert a.fg_at(a.cols - 1, 0) == "default", "the chat border is plain without a selection"
    a.quit()
    a = Term(a_dir, relay.url, extra=["--theme", "light"])
    assert a.wait(G.connected + " connected"), "light"
    y, x = a.row_of("connected")
    assert a.fg_at(x, y) == dark_fg, "good news stays green"
    a.quit()
    a = Term(a_dir, relay.url, env=client_env(NO_COLOR="1"))
    assert a.wait(G.connected + " connected"), "NO_COLOR"
    y, x = a.row_of("connected")
    assert a.fg_at(x, y) == "default", "mono has no colours"
    a.type("/theme light\r")
    assert a.wait("Theme: light (remembered)"), "/theme"
    assert config(a_dir)["theme"] == "light"
    a.quit()
    # High contrast: colours by flag (NO_COLOR would strip them at the
    # terminal layer), and /theme remembers it.
    a = Term(a_dir, relay.url, extra=["--theme", "contrast"])
    assert a.wait(G.connected + " connected"), "contrast"
    y, x = a.row_of("connected")
    assert a.fg_at(x, y) != "default", "contrast colours the status"
    a.type("/theme contrast\r")
    assert a.wait("Theme: contrast (remembered)"), "/theme contrast"
    assert config(a_dir)["theme"] == "contrast"
    a.type("/theme light\r")
    assert a.wait("Theme: light (remembered)"), "back to light"
    a.quit()

    # The "new messages" rule, focus on selection, today's date rule.
    a = Term(a_dir, relay.url)
    assert a.wait(G.connected + " connected"), "again"
    a.key(TAB)
    assert a.wait(" bob · "), "open bob"
    a.type("hello bob\r")
    assert b.wait("Contact request from"), "request"
    b.key(SHIFT_TAB)
    b.type("/accept 1\r")
    assert b.wait("hello bob"), "accept"
    a.key(TAB)
    assert a.wait("┌ System"), "alice looks away"
    b.type("/alias alice\r")
    b.type("first\r")
    b.type("second\r")
    assert a.wait_for(lambda: any("bob" in r and " 2 " in r for r in a.sc.display), what="two unread")
    a.key(TAB)
    assert a.wait(" new messages "), "rule above the unread"
    ny, _ = a.row_of(" new messages ")
    fy, _ = a.row_of("bob: first")
    assert ny == fy - 1, (ny, fy)
    assert a.has("Today, "), "today's rule"
    a.key(SHIFT_UP)
    assert a.fg_at(a.cols - 1, 0) != "default", "the chat border is accented with a selection"
    a.key(ESC)
    a.type("got them\r")
    # The echo in the input box shows "got them" before Enter is handled;
    # the sent line has the colon, and the rule goes with the send.
    assert a.wait(": got them"), "reply"
    assert a.wait_for(lambda: not a.has(" new messages "), what="the rule gone"), (
        "the rule goes once you answer"
    )
    for t in list(TERMS):
        t.quit()
    relay.stop()


if __name__ == "__main__":
    run(main)
