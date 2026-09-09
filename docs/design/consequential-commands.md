# Design note: commands that do more than they look like

Roadmap item 62.1, from findings H-2, M-7 and L-18 of the September 2026
audit. Written alongside the code rather than before it, because the
mechanism it settles already half existed; where this note and the code
disagree, the code wins and this note is corrected.

The client has one control for a command whose effect cannot be taken
back: `typed_it_themselves`, the paste guard. A terminal without
bracketed paste — the Linux console, older Windows consoles, some
multiplexer setups — hands a paste over as ordinary keystrokes, so a
pasted `hello\r/revoke confirm\r` runs the command and its confirmation
in one go. The guard measures how fast the line arrived and refuses one
that came in faster than anyone types, telling the user to type it out.

The audit found the guard applied to three commands and missing from the
one that gives away the most. `/devices link <link>` runs on a single
line, and it is not the copy of some history its name suggests:
`Identity::certify_device` signs a certificate with the account key, and
from then until the device is removed it reads everything sent to the
account and writes in its name.

## 1. The decision the audit's fix would have got wrong

The report's remedy was to put the paste guard on `/devices link` and on
five other commands. Applied literally that breaks the command it is
meant to protect. A device link is a user id and a secret; pasting it is
the documented workflow, printed by `silver --link` for exactly that
purpose. A guard whose only remedy is "type it out" is, on that command,
a guard whose remedy is impossible — and a control people cannot satisfy
is a control they learn to route around, which costs more than it buys.

So the guard is the right *mechanism* and the wrong *placement*. The fix
is to give the command a short second line and put the guard there, where
typing three words is a fair thing to ask. That also buys something the
guard alone never did: somewhere to say what the command would do, before
it does it.

## 2. Decisions

| Question | Decision |
| --- | --- |
| What the two-step shape is | The first line parses its argument and runs every check, then says in the System pane what the command would do, in the terms the person is being asked about, and stops. A short second line — `/devices link confirm`, `/relay confirm`, `/group join confirm` — goes ahead, and `typed_it_themselves` sits on that line. |
| Which commands get it | The three whose argument arrives by paste and whose effect reaches beyond this computer: `/devices link`, `/relay`, `/group join`. |
| Which get the paste guard alone | `/send <path>`, whose argument is a path a person can type. One pasted `/send ~/.ssh/id_ed25519` in an attacker's chat is the file gone, and the transfer report arrives too late to be an answer. Also the three that already had it: `/revoke`, `/rotate`, `/devices leave`. |
| Which get neither | `/unblock`, whose argument must be a prefix of an id *already on the blocked list*, so the worst a pasted line achieves is undoing a block the user themselves made, in a command the user can redo. Friction here would buy nothing and teach the reflex that confirmations are noise. `/alias` likewise: see below. |
| What a held command remembers | One slot, not one per command. Asking for a second thing forgets the first, so a confirmation always answers the question last put and never an older one still lying about. |
| How long it waits | Two minutes. A confirmation is an answer to a question just asked; after that the question is dropped rather than left for a later line to answer by accident. |
| What a refused paste does to the held command | Nothing. The guard says "type it out", so the command must still be there to type it out *for*, or the advice would be to start over. |
| Whether the checks are re-run | Yes, on the second line. Minutes passed: a device may have been linked, history has certainly moved. The line that says what was sent should describe what was sent. |
| `days` on `/devices link` | Bounded to 3650, and refused rather than clamped above it. Nothing breaks higher up — `Snapshot::gather` saturates and sends everything — but the confirmation names a number of days, and that sentence should read as a number somebody chose. |

## 3. What the first line says

For `/devices link`, the grant and not the mechanism: that the identity
signs a certificate, that the device is thereafter *you* — reading what
is sent to you, writing in your name, to your contacts and in your groups
— and that it stays so until removed. Then the device id in full, the
resolved name, and the contacts, groups and messages that would go with
it; then a line saying to check that id against the one the other
computer printed, because a link that did not come from that screen is
somebody else's device.

For `/relay`, that one relay is one network: registering again there, and
being unreachable to contacts who have not moved, is the whole cost, and
what waits on the relay being left stays on it.

For `/group join`, the disclosure: the admin learns this id whether or
not they let it in, and every member learns it if they do.

## 4. The group alias (L-18)

Not a confirmation question at all, and putting `/alias` behind the guard
— as the report suggested — would be friction in the wrong place: an
alias is trivially undone by another `/alias`, and pasting a name is a
reasonable thing to do.

The actual defect is that the two branches of the same command did
different things four lines apart. The contact branch ran its argument
through `printable`; the group branch stored what it was given, and
`GroupRecord::display_name()` is the string the reader's compose prompt
is built from — the one peer-influenced string the interface writes
without passing it through the cell buffer. So an alias carrying an
escape sequence reached the terminal intact.

The fix is filtering, in the same two places a contact alias is filtered:
on the way in (`Groups::set_alias`, and `expect_groups` for the copies
that arrive from this identity's own other devices) and on the way out
(`display_name`), because a data directory written by an earlier version
already holds whatever was typed then. The magic `40` both sides used is
now `files::MAX_ALIAS_CHARS`, in one place.

This is not defence against a peer: an alias is the user's own word for a
group, typed here or synced from their own device. It is defence against
a paste, and against the file on disk.

## 5. Non-goals

- **Confirming everything.** A confirmation the user answers by reflex is
  worse than none, because it spends the attention the three commands
  above need. The list in section 2 is meant to stay short.
- **A yes/no prompt.** The client's other irreversible commands take a
  second line, not a modal; matching them keeps one habit rather than two,
  and keeps reader mode working without a special case.
- **Bracketed-paste detection.** The guard measures arrival speed because
  the terminals that need it are the ones that do not offer bracketed
  paste. That is unchanged here.

## 6. What is tested

- The mechanism, through `/relay`, whose effect is a local file and needs
  no relay to observe: the first line changes nothing and says the cost;
  the second writes it; a confirmation with nothing waiting does nothing;
  a second question forgets the first; a stale one is refused and dropped;
  and a pasted confirmation is refused *without* dropping what it was
  confirming, so the remedy it advises actually works.
- `/devices link` end to end in `tests/tui/test_devices.py`, against a
  real relay and a real second device: the link alone names the grant and
  signs nothing, the device list stays empty, a confirmation written in
  one burst — as a terminal without bracketed paste would deliver a paste
  — is refused, and the same line typed out goes ahead.
- `/group join` end to end in `tests/tui/test_groups.py`.
- `/send`'s guard, and the group alias on the way in, on the way out, cut
  to length, and read back from a record that reached disk unfiltered.
