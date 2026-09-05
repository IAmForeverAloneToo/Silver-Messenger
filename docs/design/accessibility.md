# Design note: accessibility in the terminal

Roadmap item 51. Written before the code, as the record of the decisions;
what ships is described in README.md and docs/TERMINALS.md when the code
lands. Where this note and the code later disagree, the code wins and
this note is corrected.

## 1. Decisions

| Question | Decision |
| --- | --- |
| What a screen reader needs | Text that arrives as whole lines at the bottom of a scrolling terminal, in the order things happen, with nothing decorative in it. A full-screen program that repaints panes gives a reader fragments of changed cells, box-drawing characters read out by name, and no order; that is the mode to avoid, not to patch. |
| Reader mode | A second renderer, `silver --reader` (`/reader on` remembers it, `SILVER_READER=1` too): no alternate screen, no box drawing, no marks, no colours or attributes, no mouse capture, no cursor movement beyond the compose line. Every event is one line appended at the bottom; the compose line is the last line and its prompt names the open chat. The rest of the client (commands, keys, the store, the network) is the same code. |
| What the lines say | Messages in the open chat as `alice: hello`, in another chat as `alice, in team: hello` (for a contact, whose chat is named after them, `alice, in another chat: hello`); sent lines as `you: hello` when the client records them, which is before the relay answers, a refusal arriving after as the warning and the toast the full mode shows (`Not delivered: …`); edits as `alice edited: …`, deletions as `alice deleted a message`, reactions as `alice reacted 👍 to: hello…` and `alice took back a reaction to: hello…`, each with `, in team,` after the name when that chat is not open; system notices, toasts and timer notes as themselves. Clocks are left out of the lines (a reader would say every one); `/history` shows them. (Corrected when the code landed: the note first wrote `alice (team): hello` and had the sent line wait for the relay.) |
| Where you are | Switching chats prints `Chat: bob, 3 unread` followed by the unread lines, or the last three when nothing is unread; the prompt reads `bob> `. Selecting a message with Shift-Up prints `Selected: alice: hello`, and the commands act on it as in the full mode. |
| Scrolling | The terminal's own scrollback and the reader's review keys; `PgUp`/`PgDn` do nothing in reader mode. `/history [n]` prints the last `n` lines of the open chat with their clocks; `/unread` prints what waits where. |
| High contrast | A fourth palette, `contrast` (`/theme contrast`, `--theme contrast`): bright bold text on a black background, black on bright yellow for the selected entry and the badges, white on red for errors; every colour pair above 5:1 and most above 10:1 on the usual 16-colour palettes (section 5 has the table). `mono` stays for no colour at all. (Corrected when the code landed: the note first said reverse video and red on white.) |
| Every action without the mouse | The audit in section 4: two actions had no keyboard path, resizing the chat list and jumping to a chat by name; `/sidebar <columns>` and `/go <name>` close them. Character-level text selection stays mouse-only by design: `Shift-Up` selects whole messages and `/copy` copies the last one, which is what a reader user needs. |
| Checking against screen readers | What can be checked in CI is checked in CI: a pty test drives the client in reader mode and asserts the raw output is linear (no cursor addressing outside the compose line, no box drawing, no attributes) and says the right things. What needs a screen reader is a manual protocol in docs/TERMINALS.md with a row per platform (Orca with GNOME Terminal, NVDA with Windows Terminal, VoiceOver with Terminal.app) and a status of `unchecked` until someone runs it; the client claims nothing it has not seen. |

## 2. Goals and non-goals

Goals:

* A blind or low-vision user runs the client with the screen reader they
  already use, in the terminal they already use, and follows a
  conversation as it happens.
* Every command and key of the full mode works in reader mode, with the
  same words, so the documentation is one.
* Nothing is taken from the full mode: reader mode is a renderer, not a
  fork.

Non-goals:

* Speech or sound from the client itself beyond the bell; the screen
  reader speaks.
* Braille display layouts, magnifier hints, or a GUI.
* Making the full mode readable by a screen reader: a repainting pane
  cannot be, which is the reason for the second renderer.

## 3. Reader mode

### 3.1 Terminal handling

* Raw mode for the keys, as now; bracketed paste and focus events
  requested, as now (paste lands in the compose line; focus decides read
  receipts).
* No alternate screen: what is printed stays in the scrollback, which is
  how a reader reviews it. No mouse capture. No window title changes.
  No SGR sequences at all, so a reader that reports attribute changes
  reports none.
* Printing a line: `\r`, erase to end of line, the line, `\r\n`, then the
  prompt and the compose text again. The cursor never leaves the compose
  line except through that sequence, and `\r\n` is the only movement
  that scrolls. A resize needs nothing.
* The compose line: `bob> ` and the text typed so far, the cursor where
  it is in the text (`Left`/`Right`/`Home`/`End` as in the full mode). A
  newline inserted with `Alt-Enter` shows as ` / ` in the compose line
  and is sent as a newline.
* Quitting prints `Bye.`; a lock prints its own word, as in the full
  mode. Either leaves the cursor at the start of a fresh line with raw
  mode off, so the shell prompt follows cleanly; a panic turns raw mode
  off before its message prints.

### 3.2 The journal

The app keeps, in reader mode only, a journal of lines to print: every
place that today makes a chat line, a system line or a toast pushes the
sentence a reader should hear. The renderer drains the journal on each
turn of the main loop and prints each line as 3.1 says. The rules for
what is pushed:

* A message received in the open chat: `name: text`; in another chat:
  `name, in group: text`, or `name, in another chat: text` for a
  contact, whose chat is named after them. Files: `alice sent a file:
  photo.jpg (1.2 MiB); /get fetches it`, and once fetched the toast
  `Saved <path>. …` as itself.
* A message sent: `you: text` as the client records it, before the relay
  answers; a refusal arrives after as `Warning: Relay refused a message:
  …` and `Not delivered: …`; nothing for a receipt.
* An edit, a deletion, a reaction, a timer note: as section 1 says.
* A note about a group (`· alice added bob`): the note's text.
* A system notice: its text, prefixed `Warning: ` at the warn level.
* A toast: its text, once, when it would appear; the throttle that
  replaces a toast with the next one does not apply, every toast is a
  line.
* A chat switch: `Chat: name, n unread.` then the unread lines (or the
  last three), then `(end of chat)`. Accepting a contact request opens
  the chat and reads it at once; the request's removal used to pass the
  selection through System first, invisible in the full mode and a
  spurious `System pane.` in this one, so it no longer does.
* A selection change: `Selected: ` and the line as it would be read,
  `Selection cleared.`; `Shift-Down` past the newest clears it too.
* Help: the command table and the keys as lines, the same text as the
  overlay.
* Unread elsewhere: when a message arrives in a chat that is not open,
  the line itself says the chat, so no count is printed then; `/unread`
  lists `bob: 2, team: 1`.

Lines are cut at the terminal width by the terminal, not wrapped by the
client, since wrapping would put cursor movements into the stream.

### 3.3 What changes in the full mode

Nothing visible. The journal is a `Vec<String>` the app pushes to only
when reader mode is on; the full renderer ignores it.

## 4. Keyboard coverage

Every mouse action and its keyboard equivalent, as of 0.10.0:

| With the mouse | Without |
| --- | --- |
| Click a chat in the list | `Tab`, `Shift-Tab`, `Alt-Up`, `Alt-Down`; `/go <name>` (new) |
| Wheel, scrollbar drag | `PgUp`, `PgDn`, `Ctrl-Home`, `Ctrl-End` |
| Drag the divider | `/sidebar <columns>` (new; remembered) |
| Double click a file line | `/get`, `/open` |
| Drag to select text, double click a word | `Shift-Up` / `Shift-Down` select messages; `/copy` copies the last message; character selection has no keyboard path, by design |
| Triple click a message | `Shift-Up` |
| Right click to paste | `Ctrl-V`, `Shift-Insert` |
| Click the status line for help | `F1`, `/help` |

`/go <name>` opens the chat whose contact alias, group name or id starts
with `name` (case-insensitive), or says it is ambiguous. `/sidebar <n>`
sets the chat list's width in columns (12 to 60) and keeps it in
`config.json`, where `sidebar_width` already lives.

## 5. High contrast

`contrast` is a palette, not a mode: the layout is unchanged.

| Role | Style |
| --- | --- |
| text | white on black (the terminal's default is not assumed: both set) |
| dim | white, not dim: nothing is dimmed in this palette |
| accent, your name, a contact's name | bright yellow, bold |
| selected entry, badge | black on bright yellow, bold |
| warning | bright yellow on black, bold |
| error | bright white on red, bold |
| good | bright green, bold |
| read mark | bright cyan, bold |
| toast | bright white on blue, bold |
| QR code | black on white, as everywhere |

Bright yellow and bright white on black, and black on bright yellow, sit
above 10:1 in the usual 16-colour palettes; white on red is the weakest
pair at about 5:1 and is used for errors alone, which are short and
bold.

## 6. Tests

* Rust: the contrast palette sets both a foreground and a background on
  every style; `/sidebar` clamps and persists; `/go` picks by prefix and
  refuses ambiguity; the journal gets one line per event of 3.2, with
  the words the note gives.
* Terminal (`tests/tui/test_reader.py`): two clients, one in reader
  mode. The raw bytes the reader-mode client writes are captured beside
  the screen: no `ESC [ … H` or `ESC [ … ; … H` (cursor addressing), no
  `ESC [ ? 1049` (alternate screen), no `ESC [ … m` (attributes), no box
  drawing; each event adds one line and the prompt stays last. The
  screen shows `Chat: bob, 1 unread`, the message, `you: …` after
  sending, `Selected: …` after `Shift-Up`, and the help as lines.
* The existing suite runs unchanged: reader mode is off by default.

## 7. Implementation order

1. Keyboard coverage and the palette: `/go`, `/sidebar`, `contrast`;
   help, README, the terminals table.
2. Reader mode: the journal, the renderer, `--reader`, `/reader`,
   `/history`, `/unread`; the pty test.
3. Documents: README, TERMINALS.md with the manual protocol and the
   per-platform rows, CHANGELOG, ROADMAP; this note's corrections.
