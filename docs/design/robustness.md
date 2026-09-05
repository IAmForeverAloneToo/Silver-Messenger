# Design note: client robustness

Roadmap item 52. Written before the code, as the record of the decisions;
what ships is described in README.md when the code lands. Where this note
and the code later disagree, the code wins and this note is corrected.

## 1. Decisions

| Question | Decision |
| --- | --- |
| The terminal after a panic | One hook, installed once at start, undoes exactly what the client set up and then hands the panic to the default hook, so the message prints on the normal screen with the keyboard and mouse back to the shell. A static records what was set up: the full mode's raw mode, alternate screen, mouse capture, bracketed paste, focus events and pushed title, or reader mode's raw mode, bracketed paste and focus events. The client enters and leaves the terminal itself rather than through ratatui's `init` and `restore`, whose hook puts back raw mode and the alternate screen and leaves mouse reporting, paste and focus modes and the title behind. |
| Provoking a panic in a test | A trigger compiled into debug builds only (`SILVER_DEBUG_PANIC_AFTER_MS`, read under `cfg(debug_assertions)`): the client panics on the first tick after that many milliseconds. Release builds have no such thing. |
| Atomic writes | Every whole-file store file is already written beside and renamed over; the rename is preceded by a sync of the file from now on, so a crash cannot leave the new name pointing at an empty file. Histories are append-only lines; a line cut short by a crash is kept unreadable and skipped on load, as now. |
| The kill test | A test in `silver-client` runs itself as a child that writes the store as fast as it can (the config, the contacts, history lines and their updates, with a passphrase and without), kills it at a random moment (SIGKILL; TerminateProcess on Windows), then opens the store: every file loads, the config is one the child wrote, the contacts are a list the child wrote, the history is a prefix of what the child wrote with at most one line lost. Twenty rounds. |
| Memory | In memory a conversation holds its newest 2,000 lines; the file holds all of them. The System pane holds its newest 500 lines. Updates waiting for a message that has not arrived are capped at 1,000 besides their day. The seen-id set is capped at 20,000 already. |
| What the cap hides | Nothing that a command reads: `/search` reads the files through the store (contacts and groups both) rather than the lines on screen, and `--export-history` reads the files. The chat's title says `older lines in the file` once the window is full. |
| The soak test | `tests/tui/soak.py --minutes N`: a relay and two clients exchanging messages both ways five times a second, a reaction, an edit and a deletion mixed in, each process's resident memory sampled every thirty seconds. It passes when every process is alive at the end, the last messages arrived, and each client's memory at the end is within a tenth of what it was at the half and under 256 MiB. CI runs three minutes on every push; the workflow can be dispatched with any length up to six hours; the day-long run is made by hand and its result recorded in section 7. |

## 2. Goals and non-goals

Goals:

* A panic anywhere in the client leaves the terminal usable and the
  message readable.
* A crash or a kill at any moment leaves a store that opens, with at most
  the line being written lost.
* A client left running for a day, in a busy chat, uses no more memory
  at the end than after its first hour.

Non-goals:

* Recovering from a panic and carrying on: the process ends, the store is
  consistent, the next start continues.
* Bounding what the store holds on disk: the history files grow with
  the conversation, as they should; a message goes only when its timer
  runs out or it is deleted.
* The relay's own bounds, which item 28 set.

## 3. The terminal, entered and left by the client

`crates/silver-tui/src/terminal.rs` owns the sequence:

* `enter_full(mouse)`: raw mode, the alternate screen, bracketed paste,
  focus events, mouse capture unless `--no-mouse`; then the app pushes
  the title as now. `leave_full(mouse)` undoes them in the reverse order;
  the title is popped by the hook as well as by the app, a pop with no
  push being ignored by terminals.
* `enter_reader()`: raw mode, bracketed paste, focus events;
  `leave_reader()` the reverse.
* A static `AtomicU8` holds which of the two is in force (or neither). The
  panic hook reads it, runs the matching `leave`, sets it to neither, and
  calls the hook that was installed before it (the default one, which
  prints the message and, with `RUST_BACKTRACE`, the trace).
* The hook is installed once, before the first entry; a lock and unlock
  cycle enters and leaves again without touching it.
* What is written on leaving, per mode, is a pure function of the mode,
  so a unit test can check the bytes; the pty test checks the terminal.

The private decrypted copies (`downloads/.open/`) are removed at the next
start, as now; a panic does not get to them.

## 4. The store under a kill

`write_atomic` syncs the temporary file before the rename, as
`write_private` does already. The directory is not synced: what matters
here is that a name never points at a torn file, which the rename gives,
and a lost rename (the old contents stay) is the same as a crash a moment
earlier.

The kill test found a second thing to fix: a line cut short by a crash
has no newline, and the next append used to glue its line onto it, so
the load skipped both. An append now looks at the file's last byte and
starts a fresh line when it must; the cut line alone is lost. (Corrected
when the code landed: the note said only the cut line was ever lost.)

The kill test (`crates/silver-client/tests/kill.rs`) runs its own test
binary as the child, told by an environment variable to be the writer:
a loop that saves the config with a counter in `sidebar_width`, the
contacts as a list whose length grows, and one history line per turn, a
`read` or `react` update every few lines, until it is killed. The parent
waits a random 5 to 60 ms, kills it, opens the store, and checks:

* `load_config`, `load_contacts`, `load_requests`, `load_blocked` and
  `load_history` all succeed;
* the config's counter and the contacts' length are values the child
  reached (the child writes the counter to its stdout after each save,
  and the parent reads what arrived);
* the history's entries are `0..n` in order for some `n` at most one
  below the child's last written line;
* a `.tmp` file left beside a store file does not stop the file loading.

Ten rounds plain, ten under a passphrase. The test runs on Linux, macOS
and Windows in CI's test job. Each child carries on from what the last
one left, so a cut line is followed by whole ones; the kill waits for
the child's first round (the unlock alone takes longer than the random
wait), and the reads and reactions are checked for the rounds that child
reported, since a kill between a round's entry and its read leaves the
entry without one for good, as a crash between two writes does in life.
(Corrected when the code landed.)

## 5. Memory

* `HISTORY_WINDOW = 2_000` lines per conversation, contacts and groups
  alike. Loading reads the file whole, as it must to apply the update
  lines, learns every id and keeps the newest window, so the transient
  cost of a start is the file and the steady cost the window; recording
  a line past the window drops the oldest and clears the selection and
  the new marker if they referred to it. A line is a few hundred bytes,
  so a window is under a megabyte and fifty busy chats under fifty.
* `SYSTEM_WINDOW = 500`: the System pane drops its oldest line past it.
* `LATE_CAP = 1_000` updates waiting for their message, oldest dropped
  first, on top of the day each waits at most.
* `/search` calls the store for each conversation in scope and searches
  the entries it returns, groups included (which the in-memory search
  did not cover), so the result is the same whatever the window holds.
* The chat pane's title carries `older lines in the file` when the
  window is full, and the status line at the top of the scroll says
  `/search finds older messages, --export-history writes them`.

## 6. The soak test

`tests/tui/soak.py` uses the pty harness: a relay with its abuse limits
lifted (the defaults allow sixty sends a minute, which a soak passes in
a quarter of one; the first run found this), alice and bob befriended,
then a loop for the given minutes. About four times a second one side
sends a numbered line (typing through the pty takes most of the time);
every 50th message the receiver reacts, every 100th the sender edits
its last line, every 150th deletes it. Every 30 s the script samples
`VmRSS` from `/proc/<pid>/status` for the three processes (Linux only,
which is where it runs), checks both screens still show the newest
numbered line, and prints a row. At the end:

* every process is alive and the last line sent each way is on the other
  screen;
* for each client, RSS at the end is at most 1.1 times RSS at the half
  (after the window fills, the memory is flat) and at most 256 MiB;
* the relay's RSS is at most 256 MiB.

CI: a `soak` job on push runs `--minutes 3` under `xterm-256color`; a
`workflow_dispatch` input runs it for up to 360 minutes. The day-long
run is by hand: `tests/tui/soak.py --minutes 1440`.

## 7. Results

The longest run so far is an hour, made on the day the code landed, on
a debug build, with the relay's abuse limits lifted:

| Time | Messages | alice | bob | relay |
| --- | --- | --- | --- | --- |
| start | 0 | 37 MiB | 37 MiB | 26 MiB |
| 30 min | 6,965 | 45 MiB | 47 MiB | 26 MiB |
| 60 min | 13,742 | 49 MiB | 51 MiB | 26 MiB |

Each client's memory at the end is within a tenth of its memory at the
half, and flat over the last twenty minutes; the relay's did not move.
The rise of the first forty minutes is what fills once and stays full:
the window of two thousand lines a side, the seen-id set (twenty
thousand ids, not full yet at the end), and the allocator's own
plateau. A three-minute run passes in CI on every push. The day-long
run has not been made yet; `tests/tui/soak.py --minutes 1440` makes it,
and its figures belong here when it has.

## 8. Tests

* Rust: the leave sequences per mode; the store under a kill (section
  4); the history window on load and on record, with the selection and
  the marker; the System and late caps; `/search` across the window and
  across groups.
* Terminal: `test_panic.py` starts a client with the trigger, sees the
  panic message on the normal screen, and checks the raw bytes after it
  for mouse capture off, the alternate screen left, paste and focus off
  and the title popped, in both modes; then that the next start works.
* Soak: as section 6.

## 9. Implementation order

1. The terminal module and the panic hook; the trigger; the pty test.
2. The sync before the rename; the kill test.
3. The windows and caps; `/search` through the store; the title and the
   status hint; the tests.
4. The soak script and the CI job; a run of an hour here, the day-long
   run recorded when made.
5. README, CHANGELOG, ROADMAP; this note's corrections.
