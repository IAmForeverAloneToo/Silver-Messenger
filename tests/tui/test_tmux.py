"""The client inside tmux, driven with send-keys and read with
capture-pane: it connects, talks to a client outside tmux, and draws
Unicode marks (tmux announces itself, so the console heuristic stays off)."""

import shutil

from harness import *

SOCK = "silver-tui-test"


def tmux(*args, check=True):
    return subprocess.run(["tmux", "-L", SOCK, *args], capture_output=True, text=True, check=check).stdout


def pane():
    return tmux("capture-pane", "-p", "-t", "silver")


def wait_pane(needle, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        Term.pump_all()
        if needle in pane():
            return True
        time.sleep(0.3)
    print(pane())
    return False


def main():
    if not shutil.which("tmux"):
        print("tmux not installed; skipping")
        return
    relay = Relay()
    a_dir, b_dir = fresh_dir("tmux-alice"), fresh_dir("tmux-bob")
    a_id, b_id = identity(a_dir), identity(b_dir)
    tmux("kill-server", check=False)
    env = client_env()
    env.pop("TMUX", None)
    cmd = f"{os.path.join(BIN, 'silver')} --data-dir {a_dir} --relay {relay.url}"
    subprocess.run(["tmux", "-L", SOCK, "-f", "/dev/null", "new-session", "-d", "-s", "silver",
                    "-x", "100", "-y", "24", cmd], check=True, env=env)
    try:
        assert wait_pane("● connected"), "connected inside tmux"
        b = Term(b_dir, relay.url)
        assert b.wait(G.connected + " connected"), "bob"
        tmux("send-keys", "-t", "silver", f"/add {b_id} bob", "Enter")
        assert wait_pane(" bob · "), "add"
        tmux("send-keys", "-t", "silver", "hello from tmux", "Enter")
        assert b.wait("Contact request from"), "request"
        b.key(SHIFT_TAB)
        b.type("/accept 1\r")
        assert b.wait("hello from tmux"), "accept"
        b.type("/alias alice\r")
        b.type("hi tmux\r")
        assert wait_pane("hi tmux"), "reply arrives in tmux"
        assert wait_pane("you ✓"), "unicode marks in tmux"
        # F1 help and Esc inside tmux.
        tmux("send-keys", "-t", "silver", "F1")
        assert wait_pane("Help · any other key closes"), "help in tmux"
        tmux("send-keys", "-t", "silver", "Escape")
        time.sleep(0.5)
        assert "Help · any" not in pane(), "help closed"
        tmux("send-keys", "-t", "silver", "C-q")
        time.sleep(1)
        assert tmux("has-session", "-t", "silver", check=False) == "" and \
            subprocess.run(["tmux", "-L", SOCK, "has-session", "-t", "silver"], capture_output=True).returncode != 0, \
            "the session ends when the client quits"
    finally:
        tmux("kill-server", check=False)
        for t in list(TERMS):
            t.quit()
        relay.stop()


if __name__ == "__main__":
    run(main)
