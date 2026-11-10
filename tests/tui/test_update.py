"""`/update` from inside the client: it asks the releases page in the
background, says so in the System pane, and leaves nothing beside the
binary while it does; the client goes on working meanwhile. Whether the
answer is "this is the newest release", a download, or a network error
depends on where the test runs, so the test asks only that one comes.
Downloading, checking and swapping are tested in the client's Rust tests
(update_download.rs, update/install.rs, kill.rs) and the app's.
"""

import os
import time

from harness import *

ANSWERS = ("newest release", "Could not update", "downloading and checking")


def main():
    pair = Pair("update")
    pair.befriend()
    a = pair.alice
    binary = os.path.join(BIN, "silver")
    before_files = set(os.listdir(BIN))
    before = (os.path.getmtime(binary), os.path.getsize(binary))

    a.type("/update\r")
    # The answer goes to the System pane, which is not the one a chat
    # leaves selected.
    a.key(TAB)
    assert a.wait("asking the releases page"), "/update asks in the background"
    deadline = time.time() + 30
    while time.time() < deadline and not any(flat(a).find(s) >= 0 for s in ANSWERS):
        Term.pump_all()
        time.sleep(0.2)
    assert any(s in flat(a) for s in ANSWERS), "an answer came"

    # The binary is as it was, and nothing appeared beside it: a download
    # waits in the data directory, and only /update with one ready puts it
    # in place.
    after = (os.path.getmtime(binary), os.path.getsize(binary))
    assert before == after, f"/update changed the binary: {before} -> {after}"
    new = set(os.listdir(BIN)) - before_files
    assert not [f for f in new if "silver" in f], new

    # And the client works meanwhile.
    a.key(SHIFT_TAB)
    a.type("still here\r")
    assert pair.bob.wait("still here"), "the client works during /update"

    pair.stop()


if __name__ == "__main__":
    run(main)
