"""Drive the terminal client in a pseudo-terminal and read its screen.

Each test starts an in-memory relay on a free port, creates identities,
and spawns clients under a pty whose output is fed to a pyte screen
emulator. Keys and mouse events are written to the pty as the escape
sequences a terminal would send. Run one test with `python3 test_x.py`,
or all of them with `run.sh`.

Environment:
  TERM              the terminal type the clients see (default xterm-256color);
                    TERM=linux makes the client draw ASCII marks, and the
                    tests expect that
  SILVER_BIN_DIR    where `silver` and `silver-relay` are (default target/debug)
  SILVER_TEST_DIR   scratch directory (default: a fresh temporary one)
"""

import base64
import fcntl
import json
import os
import pty
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import time
import traceback

import pyte

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BIN = os.environ.get("SILVER_BIN_DIR") or os.path.join(ROOT, "target", "debug")
WORK = os.environ.get("SILVER_TEST_DIR") or tempfile.mkdtemp(prefix="silver-tui-")
TERM_NAME = os.environ.get("TERM", "xterm-256color")
COLS, ROWS = 100, 24

# The colours pyte reports for what crossterm sends: cyan (and bold cyan)
# and the greens, as 256-colour indices.
CYAN = {"cyan", "008080", "00cdcd"}


class Glyphs:
    def __init__(self, ascii):
        self.ascii = ascii
        if ascii:
            self.pending, self.accepted, self.delivered, self.failed = "..", "v", "vv", "x"
            self.verified, self.connected, self.arrow, self.more = "v", "*", "->", "v"
        else:
            self.pending, self.accepted, self.delivered, self.failed = "⋯", "✓", "✓✓", "✗"
            self.verified, self.connected, self.arrow, self.more = "✓", "●", "→", "↓"


G = Glyphs(TERM_NAME == "linux")


def silver(*args, env=None):
    """Run the client non-interactively and return its stdout."""
    return subprocess.run(
        [os.path.join(BIN, "silver"), *args],
        capture_output=True, text=True, check=True, stdin=subprocess.DEVNULL, env=env,
    ).stdout.strip()


def client_env(**extra):
    """The environment a spawned client gets: the chosen TERM, no proxy for
    the local relay, no system clipboard (so copies go to the terminal),
    HOME under the scratch directory."""
    env = {k: v for k, v in os.environ.items()
           if k not in ("DISPLAY", "WAYLAND_DISPLAY", "NO_COLOR", "SILVER_ASCII", "SILVER_THEME",
                        "SILVER_NO_MOUSE", "SILVER_RELAY", "SILVER_DATA_DIR")}
    env.update({"TERM": TERM_NAME, "HTTPS_PROXY": "", "https_proxy": "", "HOME": WORK})
    env.update(extra)
    return env


class Relay:
    def __init__(self, extra=(), log=None):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        out = open(log, "wb") if log else subprocess.DEVNULL
        self.p = subprocess.Popen(
            [os.path.join(BIN, "silver-relay"), "--ephemeral", "--listen", f"127.0.0.1:{self.port}", *extra],
            stdout=out, stderr=subprocess.STDOUT if log else subprocess.DEVNULL,
        )
        self.url = f"ws://127.0.0.1:{self.port}/ws"
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)

    def stop(self):
        self.p.terminate()
        try:
            self.p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.p.kill()


def fresh_dir(name):
    path = os.path.join(WORK, name)
    shutil.rmtree(path, ignore_errors=True)
    return path


def identity(data_dir):
    """Create (or read) the identity in `data_dir` and return its id."""
    return silver("--data-dir", data_dir, "--print-id")


TERMS = []


class Term:
    """A client running in a pty, with a pyte screen tracking its output."""

    def __init__(self, data_dir, relay_url, cols=COLS, rows=ROWS, extra=(), env=None):
        self.cols, self.rows = cols, rows
        m, s = pty.openpty()
        fcntl.ioctl(s, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        self.p = subprocess.Popen(
            [os.path.join(BIN, "silver"), "--data-dir", data_dir, "--relay", relay_url, *extra],
            stdin=s, stdout=s, stderr=s, env=env or client_env(), close_fds=True,
        )
        os.close(s)
        fcntl.fcntl(m, fcntl.F_SETFL, os.O_NONBLOCK)
        self.m = m
        self.sc = pyte.Screen(cols, rows)
        self.st = pyte.ByteStream(self.sc)
        self.raw = b""
        TERMS.append(self)

    # --- output ---------------------------------------------------------

    def pump(self):
        try:
            while True:
                chunk = os.read(self.m, 65536)
                if not chunk:
                    break
                self.raw += chunk
                self.st.feed(chunk)
        except (BlockingIOError, OSError):
            pass

    @staticmethod
    def pump_all():
        # A client nobody reads from blocks on its next screen write, so
        # every wait drains every terminal.
        for t in TERMS:
            t.pump()

    def has(self, needle):
        return any(needle in row for row in self.sc.display)

    def wait(self, needle, timeout=15):
        deadline = time.time() + timeout
        while time.time() < deadline:
            Term.pump_all()
            if self.has(needle):
                return True
            time.sleep(0.2)
        self.show(f"TIMEOUT waiting for {needle!r}")
        return False

    def wait_for(self, predicate, timeout=15, what="condition"):
        deadline = time.time() + timeout
        while time.time() < deadline:
            Term.pump_all()
            if predicate():
                return True
            time.sleep(0.2)
        self.show(f"TIMEOUT waiting for {what}")
        return False

    def take_raw(self):
        Term.pump_all()
        raw, self.raw = self.raw, b""
        return raw

    def show(self, name):
        print(f"=== {name} ===")
        for r in self.sc.display:
            if r.strip():
                print("|" + r.rstrip() + "|")

    def status(self):
        return self.sc.display[self.rows - 1]

    def input_line(self):
        return self.sc.display[self.rows - 3].strip("│ ")

    def row_of(self, needle):
        for y, r in enumerate(self.sc.display):
            if needle in r:
                return y, r.index(needle)
        raise AssertionError(f"no row with {needle!r}")

    def fg_at(self, x, y):
        return self.sc.buffer[y][x].fg

    def column(self, x):
        return "".join(self.sc.display[y][x] for y in range(self.rows))

    def reversed_cells(self):
        return {(x, y) for y in range(self.rows) for x in range(self.cols) if self.sc.buffer[y][x].reverse}

    def marks(self, text):
        """The marks on the row containing `text` and their colours."""
        mark_chars = set(G.delivered) | set(G.accepted) | set(G.pending) | set(G.failed)
        for y, row in enumerate(self.sc.display):
            if text in row:
                # "hh:mm you ✓✓: text": the marks sit between the name and ": ".
                head = row.split(": ")[0] if ": " in row else row
                head = head[6:] if len(head) > 6 else head  # past the clock
                cols = [x + 6 for x, ch in enumerate(head) if ch in mark_chars]
                return "".join(row[x] for x in cols), {self.sc.buffer[y][x].fg for x in cols}
        return None, set()

    def wait_marks(self, text, marks, colour=None, timeout=15):
        """Wait for the row with `text` to show exactly `marks`, optionally
        in `colour` (a set of pyte colour names)."""
        deadline = time.time() + timeout
        got, colours = None, set()
        while time.time() < deadline:
            Term.pump_all()
            got, colours = self.marks(text)
            if got == marks and (colour is None or colours & colour):
                return True
            time.sleep(0.2)
        print(f"marks for {text!r}: {got!r} {colours}")
        self.show("SCREEN")
        return False

    # --- input ----------------------------------------------------------

    def type(self, text):
        for ch in text:
            os.write(self.m, ch.encode())
            time.sleep(0.01)

    def key(self, seq, settle=0.2):
        os.write(self.m, seq)
        time.sleep(settle)
        Term.pump_all()

    # SGR mouse reports, with 0-based screen coordinates.
    def press(self, x, y, button=0):
        self.key(f"\x1b[<{button};{x + 1};{y + 1}M".encode())

    def drag(self, x, y):
        self.key(f"\x1b[<32;{x + 1};{y + 1}M".encode())

    def release(self, x, y):
        self.key(f"\x1b[<0;{x + 1};{y + 1}m".encode())

    def click(self, x, y):
        self.press(x, y)
        self.release(x, y)

    def quit(self):
        if self.p.poll() is None:
            self.key(b"\x11")
            try:
                self.p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.p.kill()
        if self in TERMS:
            TERMS.remove(self)
        return self.p.poll()


# Keys as the terminal sends them.
ENTER, ESC, TAB, SHIFT_TAB = b"\r", b"\x1b", b"\t", b"\x1b[Z"
CTRL_C, CTRL_Q, CTRL_V = b"\x03", b"\x11", b"\x16"
F1, PGUP, PGDN = b"\x1bOP", b"\x1b[5~", b"\x1b[6~"
SHIFT_UP, SHIFT_DOWN, SHIFT_INSERT = b"\x1b[1;2A", b"\x1b[1;2B", b"\x1b[2;2~"
FOCUS_IN, FOCUS_OUT = b"\x1b[I", b"\x1b[O"


def osc52(raw):
    """Texts handed to the terminal's clipboard in `raw` output."""
    out, i = [], 0
    while True:
        i = raw.find(b"\x1b]52;c;", i)
        if i < 0:
            return out
        j = raw.find(b"\x07", i)
        out.append(base64.b64decode(raw[i + 7:j]).decode())
        i = j


def config(data_dir):
    return json.load(open(os.path.join(data_dir, "config.json")))


def history(data_dir, peer_id):
    path = os.path.join(data_dir, "history", f"{peer_id}.jsonl")
    return [json.loads(line) for line in open(path) if line.strip()]


class Pair:
    """The usual start: a relay, alice and bob connected, bob added by alice."""

    def __init__(self, name, **term_kwargs):
        self.relay = Relay()
        self.a_dir, self.b_dir = fresh_dir(f"{name}-alice"), fresh_dir(f"{name}-bob")
        self.a_id, self.b_id = identity(self.a_dir), identity(self.b_dir)
        self.alice = Term(self.a_dir, self.relay.url, **term_kwargs)
        self.bob = Term(self.b_dir, self.relay.url, **term_kwargs)
        assert self.alice.wait(G.connected + " connected") and self.bob.wait(G.connected + " connected"), "connect"

    def befriend(self):
        """Alice adds bob, writes, bob accepts and answers; both chats open."""
        a, b = self.alice, self.bob
        a.type(f"/add {self.b_id} bob\r")
        assert a.wait(" bob · "), "add"
        a.type("hello bob\r")
        assert b.wait("Contact request from"), "request"
        b.key(SHIFT_TAB)
        b.type("/accept 1\r")
        assert b.wait("hello bob"), "accept"
        b.type("/alias alice\r")
        b.type("hi alice\r")
        assert a.wait("hi alice"), "reply"

    def stop(self):
        for t in list(TERMS):
            t.quit()
        self.relay.stop()


def run(main):
    """Run a test's `main`, printing every screen on failure."""
    name = os.path.basename(sys.argv[0])
    try:
        main()
    except BaseException:
        traceback.print_exc()
        for t in TERMS:
            t.pump()
            t.show(f"{name}: screen at failure")
        for t in list(TERMS):
            t.quit()
        print(f"{name}: FAILED")
        sys.exit(1)
    finally:
        for t in list(TERMS):
            t.quit()
    print(f"{name}: OK")
