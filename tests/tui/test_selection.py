"""Selecting text in the message pane with the mouse and the keyboard, and
what Ctrl-C copies."""

from harness import *


def copied(t):
    t.take_raw()
    t.key(CTRL_C)
    assert t.wait("to the terminal's clipboard"), "copy toast"
    got = osc52(t.take_raw())
    assert len(got) == 1, got
    return got[0]


def main():
    pair = Pair("select")
    pair.befriend()
    a, b = pair.alice, pair.bob
    long = ("the quick brown fox jumps over the lazy dog " * 3).strip()
    b.type(long + "\r")
    assert a.wait("lazy dog"), "long message"
    a.type("last one\r")
    assert a.wait("last one"), "last"
    time.sleep(0.5)
    Term.pump_all()

    # Drag over "alice" in "hi alice": highlighted, and Ctrl-C copies just that.
    y, x = a.row_of("hi alice")
    x0 = x + 3
    a.press(x0, y)
    a.drag(x0 + 4, y)
    a.release(x0 + 4, y)
    assert a.reversed_cells() == {(x0 + i, y) for i in range(5)}, a.reversed_cells()
    assert copied(a) == "alice", "drag copy"
    # Double click selects a word.
    y, x = a.row_of("quick brown")
    xw = x + 6
    a.click(xw, y)
    a.click(xw, y)
    assert copied(a) == "brown", "double click"
    # Triple click selects the whole wrapped message, copied clean.
    time.sleep(0.6)
    for _ in range(3):
        a.click(xw, y)
    assert len(a.reversed_cells()) >= 3 * 60, "every row of the message highlighted"
    text = copied(a)
    assert text.endswith("bob: " + long) and "\n" not in text, text
    # A click without a drag selects nothing; Ctrl-C then arms quitting.
    a.click(xw, y)
    time.sleep(0.6)
    assert not a.reversed_cells(), "a click does not select"
    a.key(CTRL_C)
    assert a.wait("Press Ctrl-C again"), "armed"
    time.sleep(3.2)
    # Shift-Up selects whole messages from the newest one.
    a.key(SHIFT_UP)
    a.key(SHIFT_UP)
    lines = copied(a).split("\n")
    assert len(lines) == 2 and lines[-1].endswith("you: last one") and lines[0].endswith("bob: " + long), lines
    for _ in range(3):
        a.key(SHIFT_UP)
    lines = copied(a).split("\n")
    assert len(lines) == 4 and lines[0].endswith("you: hello bob"), lines  # the date rule is left out
    for _ in range(3):
        a.key(SHIFT_DOWN)
    assert copied(a).endswith("you: last one"), "Shift-Down shrinks"
    a.key(SHIFT_DOWN)
    assert copied(a).endswith("you: last one"), "cannot shrink past the newest"
    # Esc clears the selection first, the input second.
    a.type("draft")
    a.key(ESC)
    assert not a.reversed_cells() and a.has("draft"), "Esc clears the selection, keeps the input"
    a.key(ESC)
    assert not a.has("draft"), "Esc clears the input"
    # A click elsewhere, or another pane, drops it.
    a.key(SHIFT_UP)
    assert a.reversed_cells()
    a.click(3, 3)
    assert not a.reversed_cells(), "click elsewhere clears"
    a.key(SHIFT_UP)
    a.key(TAB)
    a.key(TAB)
    assert not a.reversed_cells(), "pane switch clears"
    pair.stop()


if __name__ == "__main__":
    run(main)
