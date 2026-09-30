# Terminals

What the client needs from a terminal, which terminals are known to give
it, and how each one is checked. The client talks to the terminal only
through escape sequences (crossterm and ratatui underneath), so anything
that speaks xterm's dialect works; the differences are in the fonts, in
what the terminal does with the mouse, and in what it does with a few
optional sequences.

## What the client asks of a terminal

| Feature | How | If the terminal lacks it |
| --- | --- | --- |
| Marks `✓ ✓✓ ⋯ ✗`, dots `● ◌ ○`, the reply quote `↳` and the timer `⧖` | Unicode glyphs from the font | Boxes; the client draws ASCII marks where it expects that, and `--ascii` or `/marks ascii` forces them |
| Box drawing, half blocks (QR code), `…`, `·`, `→` | Every monospace font that ships with an OS has them | Nothing to do |
| Mouse: wheel, clicks, drags | SGR mouse reporting, requested at start | Keyboard does everything; `--no-mouse` leaves the mouse to the terminal on purpose |
| Bracketed paste | Requested at start | Pasted text arrives as keystrokes (one message per line) |
| Focus events | Requested at start | The window counts as focused: read receipts go out for a chat left open |
| Copy | The OS clipboard (Windows, macOS, X11, Wayland), else OSC 52 to the terminal | Over SSH without OSC 52 support, copies stay in the terminal's own selection; use `Shift`+drag |
| Paste | The OS clipboard on `Ctrl-V`, `Shift-Insert`, right click | The terminal's own paste (usually `Ctrl-Shift-V`, `Cmd-V`, or the menu), which arrives as bracketed paste |
| Desktop notification | Through the terminal where it raises one itself, and through the operating system where it does not | Bell and the unread count in the window title still work |
| Window title | OSC 2, pushed at start and restored on exit | Ignored |
| Colour | 16 colours; `--theme mono` and `NO_COLOR` use bold, dim and reverse video only; `--theme contrast` is bright bold on black | Use mono |
| Reader mode (`--reader`) | Raw mode, bracketed paste and focus events only: no alternate screen, no mouse, no title, no attributes | Any terminal has these |

Three rows in more detail:

- The ASCII marks are `v vv .. x`, `>` and `~`. The client expects
  boxes on the classic Windows console, under `TERM=linux` and in a
  non-UTF-8 locale.
- A notification through the terminal is OSC 777, OSC 9 and OSC 99
  written together, and the terminal takes the one it knows; through
  the operating system it is the session bus on Linux, `osascript` on
  macOS and a toast on Windows. Which path is taken is decided from the
  environment at start; `/notify terminal` or `/notify desktop` forces
  one. Over SSH only the terminal path can reach the desktop, and only
  that path is taken. The text is `New message`, always.
- In reader mode lines end in `\r\n`, the compose line is erased with
  `\r ESC[K` and the cursor is moved within it with `ESC[nD`.

## Known terminals

The status column: *checked in CI* means the pseudo-terminal suite
(`tests/tui/`) runs against that terminal type on every push; *checked
by hand* names the release it was used on; *expected* means the
terminal documents the feature and nothing in the client is specific to
it.

What each shows and how it is checked:

| Terminal | Marks | Mouse | Selection with the mouse captured | Status |
| --- | --- | --- | --- | --- |
| Windows Terminal | Yes | Yes | `Shift`+drag; or use the client's own selection | Checked by hand on 0.4.0, and the toast on 0.13.0 |
| Windows console (conhost) | No: ASCII marks by default | Wheel and clicks | None once the mouse is captured: the client's own selection and `Ctrl-C`, or `--no-mouse` for QuickEdit | Checked by hand on 0.4.0; the toast expected |
| macOS Terminal.app | Yes | Yes | `Fn`+drag or `Option`+drag | Expected |
| iTerm2 | Yes | Yes | `Option`+drag | Expected |
| GNOME Terminal and other VTE terminals | Yes | Yes | `Shift`+drag | Expected |
| Konsole | Yes | Yes | `Shift`+drag | Expected |
| kitty | Yes | Yes | `Shift`+drag | Expected |
| WezTerm | Yes | Yes | `Shift`+drag | Expected |
| Alacritty | Yes | Yes | `Shift`+drag | Expected |
| foot | Yes | Yes | `Shift`+drag | Expected |
| xterm | Yes | Yes | `Shift`+drag | Checked in CI (`xterm-256color`) |
| tmux | Yes | Yes (with `mouse on`, tmux forwards the wheel and clicks) | tmux's own copy mode | Checked in CI (`test_tmux.py`; the notification wrapping in `test_notify.py`) |
| Linux virtual console | No: ASCII marks by default | No | gpm, if running | Checked in CI (`TERM=linux`) |
| SSH from any of the above | As the local terminal | As the local terminal | As the local terminal | Expected |

How the clipboard and notifications reach each:

| Terminal | Copy | Paste | Notification |
| --- | --- | --- | --- |
| Windows Terminal | OS clipboard | OS clipboard on `Ctrl-V`; `Ctrl-Shift-V` too | A Windows toast; the terminal ignores the sequences |
| Windows console (conhost) | OS clipboard | OS clipboard on `Ctrl-V`, `Shift-Insert`, right click | A Windows toast |
| macOS Terminal.app | OS clipboard | `Cmd-V` (bracketed paste); `Ctrl-V` reaches the client | Notification Center, through `osascript` |
| iTerm2 | OS clipboard; OSC 52 | `Cmd-V`; `Ctrl-V` reaches the client | OSC 9 toast, raised by iTerm2 itself |
| GNOME Terminal and other VTE terminals | OS clipboard | `Ctrl-Shift-V`, `Shift-Insert`; `Ctrl-V` reaches the client | The session bus; VTE has no notification sequence |
| Konsole | OS clipboard | `Ctrl-Shift-V`, `Shift-Insert` | The session bus |
| kitty | OS clipboard; OSC 52 | `Ctrl-Shift-V` | OSC 99, raised by kitty itself |
| WezTerm | OS clipboard; OSC 52 | `Ctrl-Shift-V` | OSC 777 or 9, raised by WezTerm itself |
| Alacritty | OS clipboard; OSC 52 | `Ctrl-Shift-V` | The session bus |
| foot | OS clipboard; OSC 52 | `Ctrl-Shift-V` | OSC 777, raised by foot itself |
| xterm | OSC 52 (when `allowWindowOps` permits) | `Shift-Insert` | The session bus; xterm is not one the client recognises, so the sequences are written too and ignored |
| tmux | OSC 52 through tmux when `set-clipboard on` | tmux paste (`prefix ]`) or the outer terminal's | The sequences wrapped in tmux's passthrough for the outer terminal (needs `allow-passthrough on`), and the session bus |
| Linux virtual console | OSC 52 is ignored | The console has no clipboard | Bell |
| SSH from any of the above | OSC 52 reaches the local terminal's clipboard where supported | The local terminal's paste | The local terminal's, where it raises one: only the terminal path is taken, since the desktop is on the other end |

## Running the checks

```sh
pip install pyte                       # a terminal emulator in Python, used to read the screen
tests/tui/run.sh                       # every test under TERM=xterm-256color
TERMS="xterm-256color linux" tests/tui/run.sh
tests/tui/run.sh test_help.py          # one test
```

Each test starts an in-memory relay and one or two clients in
pseudo-terminals, types as a person would, sends the mouse reports and
key sequences a terminal sends, and reads the screen back. CI runs the
suite under `xterm-256color` and `linux` on every push, plus a client
driven inside tmux. `cargo test -p silver-tui` also draws the main screen
into a test backend and compares it with `crates/silver-tui/tests/snapshots/main.txt`;
after a deliberate layout change, look at the new screen and accept it
with `UPDATE_SNAPSHOTS=1 cargo test -p silver-tui`.

## Screen readers

Reader mode (`silver --reader`; README, "Reader mode") is what a screen
reader is meant to read: whole lines arriving at the bottom of the
terminal, in order, with nothing decorative in them. What can be checked
without a screen reader is checked in CI: `tests/tui/test_reader.py` runs
a reader-mode client beside an ordinary one and asserts that the bytes it
writes carry no cursor addressing, no alternate screen, no attributes, no
window title, no mouse capture and no box drawing, that each event is one
line, and that the compose line stays last. What needs a screen reader is
the protocol below, run by hand. A row below is checked only once someone
has run the protocol and says so, with the versions used; until then the
client claims nothing.

The protocol, in a terminal the screen reader supports, with the reader
running:

1. Start `silver --reader` against a relay (`silver-relay --ephemeral` on
   the same machine will do) and an ordinary client for the other side.
   The opening line (`Silver Messenger, reader mode. …`) and `Connected
   to …` are read as they appear.
2. From the other client, add this one and write to it. `Contact request
   from …` is read; `Shift-Tab` reads the request's entry, its messages
   and `(end of request)`; `/accept` there reads the chat and the message
   in it; reviewing the cursor line reads the prompt as the chat's name.
3. Type a message and press Enter: `you: …` is read once (the reader's
   own echo of the typing is expected; the sent line must not be read
   twice).
4. Have the other side write while this chat is open (`alice: …`) and
   while another is (`alice, in another chat: …`); then `/unread`,
   `/go alice`, `Shift-Up`, `Esc`, `/history 3` and `F1`. Each is read as
   lines; nothing is read by name as a box-drawing or control character.
5. `Ctrl-Q`: `Bye.` and the shell prompt, with the terminal back in its
   normal mode (typed text echoes).

| Platform | Screen reader and terminal | Status |
| --- | --- | --- |
| Linux, GNOME | Orca with GNOME Terminal (VTE) | Unchecked |
| Windows | NVDA with Windows Terminal | Unchecked |
| Windows | Narrator with Windows Terminal | Unchecked |
| macOS | VoiceOver with Terminal.app | Unchecked |

A row becomes `Checked on <versions>` when the protocol has been run,
with anything that had to be worked around noted under Quirks.

## Quirks worth knowing

- **Mouse capture and selection.** Once a program asks for mouse
  reports, the terminal hands it every click, so its own text selection
  needs a modifier (`Shift` on Linux and Windows Terminal, `Option` or
  `Fn` on macOS). The classic Windows console has no such modifier and
  simply loses selection and right-click paste, which is why the client
  selects and pastes by itself. `--no-mouse` turns capture off entirely.
- **Ctrl-V.** Windows Terminal, iTerm2 and Terminal.app treat it as
  paste themselves and the client sees bracketed paste; VTE, Konsole,
  kitty, WezTerm and Alacritty pass it through and the client reads the
  clipboard. Either way the text lands in the compose box.
- **OSC 52** hands a copy to the terminal, which is the only way to reach
  the clipboard over SSH. xterm needs `allowWindowOps`, tmux needs
  `set -s set-clipboard on`, VTE terminals ignore it. On a desktop the
  client uses the OS clipboard first and OSC 52 only when there is none.
- **Focus events** are supported by every terminal listed except the
  Linux console. Without them the client cannot tell that you walked
  away, so a chat left open reports its messages as read.
- **Fonts.** The marks are `U+2713`, `U+2717`, `U+22EF` and the dots
  `U+25CF`, `U+25CC`, `U+25CB`. Consolas and Lucida Console lack the
  first three, which is what the classic console shows as boxes; Cascadia
  Mono (Windows Terminal's default), Menlo, SF Mono, DejaVu Sans Mono and
  Noto Mono have all of them.
