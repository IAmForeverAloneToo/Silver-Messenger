"""Mouse navigation: the chat list, file lines, the divider, the scrollbar."""

from harness import *


def main():
    pair = Pair("mouse")
    pair.befriend()
    a, b = pair.alice, pair.bob
    docs = fresh_dir("mouse-docs")
    os.makedirs(docs)
    small = os.path.join(docs, "notes.txt")
    open(small, "w").write("hello\n")
    b.type(f"/send {small}\r")
    assert a.wait("[file] notes.txt (6 B) · /get to fetch"), "file waits"
    a.type("/get\r")
    assert a.wait(f"[file] notes.txt (6 B) {G.arrow} "), "file"

    # Clicking rows of the chat list switches panes.
    a.click(3, 1)
    assert a.wait("┌ System ─"), "click System"
    a.click(3, 2)
    assert a.wait(" bob · "), "click bob"
    a.click(3, 12)
    time.sleep(0.3)
    Term.pump_all()
    assert a.has(" bob · "), "empty rows do nothing"
    # A click on a received file's line says how to open it; a double click opens.
    y, x = a.row_of("[file] notes.txt")
    a.click(x + 3, y)
    assert a.wait("Double-click to open notes.txt"), "hint"
    time.sleep(0.6)
    a.click(x + 3, y)
    a.click(x + 3, y)
    time.sleep(0.5)
    Term.pump_all()
    assert a.has("Opening ") or a.has("Could not open"), "double click opens (or says why not)"
    a.type("/open\r")
    time.sleep(0.5)
    Term.pump_all()
    assert a.has("Opening ") or a.has("Could not open"), "/open"
    # A program is never handed to the opener, from /open or a double click.
    prog = os.path.join(docs, "setup.exe")
    open(prog, "wb").write(b"MZ junk")
    b.type(f"/send {prog}\r")
    assert a.wait("[file] setup.exe (7 B) · /get to fetch"), "program waits"
    a.type("/get\r")
    assert a.wait(f"[file] setup.exe (7 B) {G.arrow} "), "program saved"
    a.type("/open\r")
    assert a.wait("Not opening setup.exe"), "/open refuses a program"
    time.sleep(0.6)
    y, x = a.row_of("[file] setup.exe")
    a.click(x + 3, y)
    a.click(x + 3, y)
    assert a.wait("Not opening setup.exe"), "double click refuses a program"
    # Dragging the divider resizes the chat list; the width is remembered.
    assert a.sc.display[0][25] == "┐", a.sc.display[0]
    a.press(25, 6)
    a.drag(30, 6)
    a.drag(35, 6)
    a.release(35, 6)
    assert a.sc.display[0][35] == "┐" and a.sc.display[0][36] == "┌", "resized to 36 columns"
    assert config(pair.a_dir)["sidebar_width"] == 36, "width saved"
    a.press(35, 6)
    a.drag(25, 6)
    a.release(25, 6)
    assert a.sc.display[0][25] == "┐", "resized back"
    # The scrollbar appears once the chat overflows; its top scrolls to the oldest rows.
    for i in range(15):
        b.type(f"line {i}\r")
    assert a.wait("line 14"), "filled"
    assert "█" in a.column(a.cols - 1), "scrollbar thumb on the right border"
    a.click(a.cols - 1, 1)
    assert a.wait("hello bob"), "scrolled to the top"
    assert a.has("more "), "rows-below indicator"
    a.press(a.cols - 1, 1)
    a.drag(a.cols - 1, a.rows - 4)
    a.release(a.cols - 1, a.rows - 4)
    assert a.wait("line 14"), "dragged back to the bottom"
    pair.stop()


if __name__ == "__main__":
    run(main)
