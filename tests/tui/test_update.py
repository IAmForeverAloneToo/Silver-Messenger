"""`/update` reports where the client stands and installs nothing.

The point of the test is the second half of that sentence. The interface
holds an unlocked data directory, ratchet state in memory and open
sessions, so `/update` must not download or replace anything: it says
what to run from a shell and stops. `silver update` is the command that
installs, and its own checks are tested in the client's Rust tests.
"""

import os
import time

from harness import *


def main():
    pair = Pair("update")
    pair.befriend()
    a = pair.alice
    binary = os.path.join(BIN, "silver")
    before = (os.path.getmtime(binary), os.path.getsize(binary))

    a.type("/update\r")
    # The answer goes to the System pane, which is not the one a chat
    # leaves selected.
    a.key(TAB)
    assert a.wait("Silver Messenger"), "/update says which version this is"
    assert a.wait("silver update"), "/update points at the command that installs"

    # Nothing was fetched and nothing was replaced. A download would land
    # beside the binary as `.silver-v*.new`, and an install would move it
    # over the binary itself.
    time.sleep(1)
    Term.pump_all()
    after = (os.path.getmtime(binary), os.path.getsize(binary))
    assert before == after, f"/update changed the binary: {before} -> {after}"
    beside = os.listdir(BIN)
    assert not [f for f in beside if f.startswith(".silver-v")], beside
    assert "silver.old" not in beside, beside

    # And the client still works afterwards: this is a report, not a
    # state change.
    a.key(SHIFT_TAB)
    a.type("still here\r")
    assert pair.bob.wait("still here"), "the client works after /update"

    pair.stop()


if __name__ == "__main__":
    run(main)
