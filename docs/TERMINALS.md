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
| Marks `✓ ✓✓ ⋯ ✗`, dots `● ◌ ○`, the reply quote `↳` and the timer `⧖` | Unicode glyphs from the font | Boxes. The client draws ASCII marks (`v vv .. x`, `>` and `~`) where it expects that (the classic Windows console, `TERM=linux`, a non-UTF-8 locale); `--ascii` or `/marks ascii` forces it |
| Box drawing, half blocks (QR code), `…`, `·`, `→` | Every monospace font that ships with an OS has them | Nothing to do |
| Mouse: wheel, clicks, drags | SGR mouse reporting, requested at start | Keyboard does everything; `--no-mouse` leaves the mouse to the terminal on purpose |
| Bracketed paste | Requested at start | Pasted text arrives as keystrokes (one message per line) |
| Focus events | Requested at start | The window counts as focused: read receipts go out for a chat left open |
| Copy | The OS clipboard (Windows, macOS, X11, Wayland), else OSC 52 to the terminal | Over SSH without OSC 52 support, copies stay in the terminal's own selection; use `Shift`+drag |
| Paste | The OS clipboard on `Ctrl-V`, `Shift-Insert`, right click | The terminal's own paste (usually `Ctrl-Shift-V`, `Cmd-V`, or the menu), which arrives as bracketed paste |
| Desktop notification | OSC 777, OSC 9, OSC 99, written together; the terminal takes the one it knows | Bell and the unread count in the window title still work |
| Window title | OSC 2, pushed at start and restored on exit | Ignored |
| Colour | 16 colours; `--theme mono` and `NO_COLOR` use bold, dim and reverse video only; `--theme contrast` is bright bold text on black | Use mono |
| Reader mode (`--reader`) | Raw mode, bracketed paste and focus events only: no alternate screen, no mouse, no title, no attributes; lines end in `\r\n`, the compose line is erased with `\r ESC[K` and the cursor moved within it with `ESC[nD` | Any terminal has these |

## Known terminals

"Checked" means the pty test suite (`tests/tui/`) runs against that
terminal type in CI, or the client was used on it by hand. "Expected"
means the terminal documents the feature and nothing in the client is
specific to it.

| Terminal | Marks | Mouse | Selection with the mouse captured | Copy | Paste | Notification | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Windows Terminal | Yes | Yes | `Shift`+drag; or use the client's own selection | OS clipboard | OS clipboard on `Ctrl-V`; `Ctrl-Shift-V` too | Bell and title | Checked by hand on 0.4.0; the marks, selection and paste fixes of 0.5.0 are expected |
| Windows console (conhost) | No: ASCII marks by default | Wheel and clicks | None natively once the mouse is captured; the client's own selection and `Ctrl-C` copy instead, or `--no-mouse` for QuickEdit | OS clipboard | OS clipboard on `Ctrl-V`, `Shift-Insert`, right click | Bell and title | Checked by hand on 0.4.0 (the reason for Phase 5); 0.5.0 expected |
| macOS Terminal.app | Yes | Yes | `Fn`+drag or `Option`+drag | OS clipboard | `Cmd-V` (bracketed paste); `Ctrl-V` reaches the client | Bell and title | Expected |
| iTerm2 | Yes | Yes | `Option`+drag | OS clipboard; OSC 52 | `Cmd-V`; `Ctrl-V` reaches the client | OSC 9 toast | Expected |
| GNOME Terminal and other VTE terminals | Yes | Yes | `Shift`+drag | OS clipboard | `Ctrl-Shift-V`, `Shift-Insert`; `Ctrl-V` reaches the client | Bell and title (VTE has no notification sequence) | Expected |
| Konsole | Yes | Yes | `Shift`+drag | OS clipboard | `Ctrl-Shift-V`, `Shift-Insert` | Bell and title | Expected |
| kitty | Yes | Yes | `Shift`+drag | OS clipboard; OSC 52 | `Ctrl-Shift-V` | OSC 99 | Expected |
| WezTerm | Yes | Yes | `Shift`+drag | OS clipboard; OSC 52 | `Ctrl-Shift-V` | OSC 777 or 9 | Expected |
| Alacritty | Yes | Yes | `Shift`+drag | OS clipboard; OSC 52 | `Ctrl-Shift-V` | Bell and title | Expected |
| foot | Yes | Yes | `Shift`+drag | OS clipboard; OSC 52 | `Ctrl-Shift-V` | OSC 777 | Expected |
| xterm | Yes | Yes | `Shift`+drag | OSC 52 (when `allowWindowOps` permits) | `Shift-Insert` | Bell and title | Checked: the test suite runs as `xterm-256color` |
| tmux | Yes | Yes (with `mouse on`, tmux forwards the wheel and clicks) | tmux's own copy mode | OSC 52 through tmux when `set-clipboard on` | tmux paste (`prefix ]`) or the outer terminal's | Passed through by the outer terminal | Checked: `test_tmux.py` runs the client inside tmux |
| Linux virtual console | No: ASCII marks by default | No | gpm, if running | OSC 52 is ignored | The console has no clipboard | Bell | Checked: the test suite runs as `TERM=linux` |
| SSH from any of the above | As the local terminal | As the local terminal | As the local terminal | OSC 52 reaches the local terminal's clipboard where supported | The local terminal's paste | The local terminal's | Expected |

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
   from …` is read; `Shift-Tab` reads the Requests pane; `/accept 1` reads
   the chat and the message in it; reviewing the cursor line reads the
   prompt as the chat's name.
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
