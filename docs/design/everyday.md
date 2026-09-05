# Design note: everyday privacy features

Roadmap item 50. Written before the code, as the record of the decisions;
the normative description of what ships goes into
[PROTOCOL.md](../PROTOCOL.md) (sections 4 and 13) when the code lands, and
the threat model grows the same day. Where this note and the code later
disagree, the code and PROTOCOL.md win and this note is corrected.

## 1. Decisions

| Question | Decision |
| --- | --- |
| Where it all lives | Inside the encrypted body, as content kinds (section 4 of the protocol) in one-to-one sessions and as application messages in groups. The relay sees a padded body like any other and learns nothing new; nothing here needs the relay. |
| Disappearing messages | A timer per conversation, set by either side of a one-to-one conversation and by an admin in a group, told to the other side as a message. It runs from the moment of sending for the sender and from the moment of reading for the recipient; an unread message waits. Each device deletes on its own clock; nothing is asked of the other side beyond running this software. |
| Delete for everyone | The author, within 24 hours of sending, asks every recipient's client to remove the message. A conforming client removes the text and the file reference, keeps a placeholder saying a message was deleted, and keeps any file it already saved. What it cannot recall is stated in the threat model, not softened. |
| Delete for me | Local: the message goes from this device's history and screen, and from the device's siblings, which are told by sync. The other side keeps its copy. |
| Edits | A new message of its own kind that names the message it replaces, from the author, within 24 hours of the original. Shown in place with an "edited" mark; the original stays in the history file and the export shows both. |
| Replies | An optional `reply_to` on a text or a file, naming the message answered. The quote is rendered from the reader's own history; a client that does not know the field shows the text alone, which is why replies need no capability. |
| Reactions | One short string (an emoji, or a few characters) per person per message, sent as a message naming its target; a later one replaces it and an empty one removes it. |
| Older clients | Three new in-body capabilities gate the new kinds one-to-one: `edits` (edit, delete for everyone), `reactions`, `timers`. To a contact whose client lacks one, the client does not send the kind; it says what the contact will not see, and where the local side can act alone (the timer) it does so and says the deletion is one-sided. In groups the gate is a leaf capability every 0.10.0 leaf declares. |
| Encrypted downloads | An option, `/files encrypt on`, only where the data directory is protected: received files are saved under the data key like every other file, and `/open` decrypts a private temporary copy for the program that opens it. Off by default, so files stay ordinary files for other programs, as today. |
| History export | `silver --export-history <dir>`: one file per conversation, plain text by default or JSON lines with `--format json`, written after unlocking the store. Deleted messages are left out; edits are shown as the latest text with the earlier versions in the JSON. |
| Message references | By the id a message goes by: the envelope id of the message to the contact's primary one-to-one (protocol section 14.4), the application message id in a group. |

## 2. Goals and non-goals

Goals:

* The features people expect of a messenger in daily use, without a
  single new thing for the relay to see: a timer, delete, edit, reply,
  react.
* Honest promises. A deletion or a timer is enforced by the other side's
  *software*, never by cryptography; the threat model says exactly what a
  recipient who keeps a copy can do, and the client never claims more.
* Nothing breaks for a client on 0.9.0: it is sent only what it can read,
  and where the sender's client cannot do what was asked it says so.
* Devices (item 48) and groups (item 47) see the same things: an edit made
  on one device shows on all, a group's timer applies to everyone in it.

Non-goals, for this item:

* View-once media, screenshot detection, or any promise about what a
  recipient's screen does. A terminal has a scrollback; nothing here
  pretends otherwise.
* Editing or deleting files' contents on the relay. A file message deleted
  for everyone loses its key with the message on conforming clients; the
  encrypted blob expires on the relay's schedule as any blob does.
* Threads, forwarding, stickers, formatting, mentions, typing indicators.
* Syncing history beyond what devices already do: an edit or a deletion
  made while a device was off waits in that device's mailbox like any
  message; a device linked later starts from the snapshot, which carries
  the latest state of each line.

## 3. What exists that this builds on

* `Content` (protocol section 4) is a tagged enum inside the encrypted
  body; a reader ignores fields it does not know but refuses a kind it
  does not know, which is why new kinds go behind in-body capabilities
  (4.3) and new fields on old kinds do not.
* The history file (`history/<id>.jsonl`) is append-only: an entry line
  per message, then update lines that add a receipt or replace a text
  (a fetched file's line naming where it was saved). Every line is
  encrypted under the data key with the file name bound; a whole file is
  rewritten only when a conversation moves to a successor identity.
* Read receipts already know the moment a message was shown: a message
  counts as read when its chat is in front of the user and the window has
  focus (`mark_selected_read`); that moment is where the recipient's timer
  starts.
* Devices (section 14) send a copy of everything a device sends to its
  siblings (`sync sent`), so an edit, a deletion for everyone, a reaction
  or a timer made on one device reaches the others by the same path as a
  text; `sync read` tells siblings what was shown.
* Groups (section 13) carry any `Content` as an application message and
  ignore kinds that are not a text or a file; every leaf declares MLS
  capabilities, which is what a sender can check before using a kind not
  every member's client may read.
* The vault encrypts files under a per-installation key with the file
  name bound (`FileCipher::encrypt(name, bytes)`); `downloads/` is the one
  place under the data directory it does not cover.
* The Shift-Up and Shift-Down selection of whole messages is how a user
  points at a message in the terminal.

## 4. Content kinds

All inside the body, alongside `text`, `receipt`, `file` and the rest; all
padded like any body, so the relay sees a reaction as it sees a receipt.

```json
{ "type": "text", "body": "yes, tomorrow", "reply_to": "<message id>" }
{ "type": "file", "name": "...", "...": "...", "reply_to": "<message id>" }
{ "type": "edit", "id": "<message id>", "body": "yes, on Tuesday" }
{ "type": "delete", "ids": [ "<message id>", "..." ] }
{ "type": "reaction", "id": "<message id>", "emoji": "👍" }
{ "type": "reaction", "id": "<message id>", "emoji": "" }
{ "type": "timer", "seconds": 86400 }
```

* `reply_to` is optional on `text` and `file`: the id of the message
  answered, which must be one in the same conversation. A client that
  does not know the field shows the text alone.
* `edit`: the new text of the message `id`, which the sender sent. Only
  the author may edit, and only within 24 hours of the original's
  `sent_at_ms`; a recipient refuses an edit for a message it holds from
  someone else, and applies one for a message it does not hold by
  keeping it for the day the message arrives (a group fan-out can
  cross). An edit is itself a message with an id, so it can be edited
  again (each edit names the *original*, so the chain stays flat) and
  can be deleted, which deletes the original with every edit of it.
* `delete`: the messages named are removed on receipt, author's only,
  any age. The recipient keeps a placeholder line ("a message was
  deleted") and, for a file already fetched, the saved file.
* `reaction`: `emoji` is 1 to 32 bytes of UTF-8 without control, blank
  or invisible characters (the zero width joiner of emoji sequences is
  allowed), or empty to remove the sender's reaction. One reaction per
  sender per message; a new one replaces it. Any member of a
  conversation may react to any message in it, its own included.
* `timer`: the conversation's disappearing-message timer from now on,
  in seconds: 0 turns it off, otherwise 1 to 31 536 000 (a year). It is
  a note in the conversation ("alice set messages to disappear after a
  day") and is not itself subject to the timer. One-to-one either side
  may set it; in a group only an admin, and members refuse one from
  anyone else.
* An `edit`, `delete`, `reaction` or `timer` is numbered with `seq` and
  carried in a session like any body; none of them gets a receipt or a
  notification, and none counts as unread.

**Capabilities** (4.3): `edits` says the client understands `edit` and
`delete`; `reactions`, `reaction`; `timers`, `timer`. A client from
0.10.0 advertises all three always. A sender uses a kind only towards a
contact whose last message advertised its capability; otherwise it does
not send it and tells its user: an edit or a reaction "will not show on
their client, which is older", a delete "cannot be deleted there", a
timer "is set here and messages will vanish on this side only". Replies
travel to everyone.

**Groups** (13.3): the same kinds as application messages, with the same
rules read from the MLS sender: edit and delete for the sender's own
messages, timer from an admin. Every key package and leaf from 0.10.0
declares MLS capability for the private-use extension type `0xF003`
(`silver_everyday`); no extension of that type is ever carried, and the
required capabilities of a group are unchanged. A client sends an edit, a
delete, a reaction or a timer to a group only when every leaf in the tree
declares `0xF003`; otherwise it names the members whose clients are
older and does not send. A member on 0.9.0 that were sent one would
report an unreadable message, which is why the check comes first.

## 5. Semantics, feature by feature

### 5.1 Disappearing messages

* The timer is a property of the conversation, kept in `contacts.json`
  (`expire_after_s`) and, for groups, in `groups.json`. Setting it sends
  a `timer` message and applies it locally; receiving one applies it and
  writes the note. A message sent or received while the timer is set
  carries the timer's value in its history entry (`expire_after_s`), so
  a later change of the timer does not touch messages already sent, as
  Signal does.
* A **sent** message's clock starts at its `sent_at_ms`. A **received**
  message's clock starts when it is read: the moment `mark_selected_read`
  runs for it, written to the history as a `read` update line (`ids`,
  `at_ms`) so a restart does not restart the clock, and told to siblings
  in `sync read`, which gains an optional `at_ms`. A message never read
  never expires; an unread message that is deleted for everyone by its
  author goes as any deletion.
* On a device that learns of a read from a sibling, the clock starts at
  the sibling's `at_ms` (or at receipt of the sync, from an older
  sibling).
* A sweeper in the client runs at start and every minute: a message whose
  clock plus its timer is past is deleted as "delete for me" is (5.3),
  without sync, since every device runs its own sweeper from the same
  facts. A message shown on screen when its time comes disappears at the
  next sweep.
* Files: an expired file message loses its line and its fetch reference;
  a file already saved stays in `downloads/` and the note says so once
  per conversation. That is the honest reading of "the message
  disappears, the file you saved is yours".
* One-to-one, when the contact's client lacks `timers`, the timer is set
  here alone: messages this side sent and received vanish here on time,
  and the contact keeps everything. The client says so when the timer is
  set and shows the timer as one-sided in `/timer`.
* In a group, an admin's `timer` applies to every member from that
  message on. A member added later does not see earlier messages and is
  told the timer by the client that added it, which sends the group's
  current `timer` to the group right after the Welcome, if one is set;
  members apply a repeat of the current value silently.

### 5.2 Delete for everyone

* `/delete` on a selected own message (or the last own message, with no
  selection) within 24 hours of sending: the message is removed here and
  on the siblings, a `delete` goes to every device of the contact (or
  every leaf of the group), and the line becomes "you deleted a message".
  Past 24 hours the command refuses and offers `/delete me`.
* On receipt from the author: the entry's text and fetch reference go,
  a placeholder line stays ("alice deleted a message"), reactions to it
  go, edits of it go, and a saved file stays. The placeholder can be
  removed with `/delete me`.
* A `delete` for a message the recipient does not hold (not yet arrived,
  or already gone) is kept as a tombstone for 24 hours so a late arrival
  is dropped on arrival.
* Promise, stated in the client and the threat model: the other side's
  copy goes if their client is this software, unmodified, on 0.10.0 or
  later, and running or later started with the deletion waiting in its
  mailbox. Nothing removes a screenshot, a copy taken by a modified
  client, an export or backup made before, or what the other person
  remembers. The relay held only ciphertext, and the deletion does not
  need it to do anything.

### 5.3 Delete for me

* `/delete me` on a selected message (or the last message): the entry's
  lines are removed from the history file by rewriting it (6.1), the
  screen forgets it, a `sync remove` (`peer` or `group`, `ids`) tells the
  siblings to do the same, and nothing goes to the other side.
* A tombstone `{ "gone": "<id>" }` stays in the file so that an update
  arriving later for that id (a receipt, an edit, a reaction) is dropped
  instead of resurrecting the line.

### 5.4 Edits

* `/edit <text>` on a selected own message (or the last own message)
  within 24 hours: an `edit` goes out (to every device of the contact and
  the siblings, as a text does), the line shows the new text with an
  "edited" mark, and the history gains an `edit` update line with the new
  text and the edit's own id and time. The original entry line is kept,
  so the file holds every version and the export can show them.
* Receipts and reactions stay attached to the original id. Editing a
  file message is refused (nothing to edit but the name).
* On receipt: applied when the author matches and the original is held;
  otherwise kept for 24 hours as 4 says. An edit of a message that was
  deleted is dropped.

### 5.5 Replies

* `/reply <text>` on a selected message (or the last received message):
  a text with `reply_to`. The line shows a quote above it, rendered from
  the reader's own history at draw time: the author's name and the first
  line of the target, cut to the width; "a message you do not have" when
  the target is unknown or gone; "a deleted message" when it was deleted.
  Files can be replies too (`/send` with a selection).
* The quote is never carried in the message: a snippet inside the body
  would let a sender misquote, and the reader's own copy cannot be
  misquoted.

### 5.6 Reactions

* `/react <emoji>` on a selected message (or the last received message);
  `/react none` removes yours. One per person per message; shown on a
  line under the message, by reaction, with the names of those who gave
  it ("👍 alice, you · ❤️ bob"). Reactions to a message that goes (deleted
  or expired) go with it.
* Stored as `reaction` update lines (`react: id, from, emoji`) in the
  history, the last one per sender winning.

## 6. Client

### 6.1 Storage

* History lines gain kinds, all as update lines after the entries:

  ```json
  { "read": [ "<id>", "..." ], "at_ms": 0 }
  { "edit": "<id>", "text": "...", "edit_id": "<id of the edit>", "at_ms": 0 }
  { "react": "<id>", "from": "<user id or absent for you>", "emoji": "👍" }
  { "gone": "<id>" }
  ```

  and the entry line gains `reply_to`, `expire_after_s`, `edited: true`
  and `deleted: true` where they apply. Loading reads every entry line
  first and then applies the update lines, so an update that stands
  before its entry in the file (a crossed group fan-out) still applies.
* **Rewriting.** A deletion, a "delete for me" or an expiry rewrites the
  file without the entry's lines and with a `gone` tombstone, under the
  same name binding, the way `migrate_history` rewrites today; the
  rewrite is atomic (write beside, rename over). The file's line count
  bounds the cost; a conversation of a few thousand lines rewrites in
  milliseconds.
* `contacts.json` gains `expire_after_s`; `groups.json` gains
  `expire_after_s` per group; `config.json` gains `encrypted_downloads`.
* The device snapshot (section 14.6) carries each line's current state:
  the latest text, `edited`, the reactions, the timer of each
  conversation, and no deleted or expired lines.

### 6.2 Engine

* A `everyday` module in `silver-client`: the rules as pure functions
  (`may_edit(now, sent_at)`, `may_delete_for_everyone(now, sent_at)`,
  `expires_at(entry, read_at)`, `check_emoji`, `check_timer`), the
  history update application (`apply_edit`, `apply_delete`,
  `apply_reaction`, `apply_read`), the sweeper (`sweep_expired(store,
  now)` over every conversation, returning what went), and the sync
  additions (`Sync::Read { at_ms }`, `Sync::Remove`).
* `Content` gains the four kinds and the field; `capability` gains
  `EDITS`, `REACTIONS`, `TIMERS`; `spread_of` sends them everywhere a
  text goes. The group engine declares `0xF003` in capabilities and
  offers `members_without(0xF003)` for the sender's check.
* The connection task passes the new kinds through as messages, as it
  passes a text; the front end applies them. A kind that arrives from a
  contact whose messages did not advertise the matching capability is
  applied all the same: the capability says what a client *reads*, and
  this one reads them.

### 6.3 Interface

* Commands: `/timer <30s|5m|1h|8h|1d|1w|off>` (and `/timer` to show),
  `/delete [me]`, `/edit <text>`, `/reply <text>`, `/react <emoji|none>`,
  `/files encrypt on|off`; `silver --export-history <dir> [--format
  text|json]`.
* A command that acts on a message acts on the selected one when exactly
  one message is selected (Shift-Up), otherwise on the last message the
  command makes sense for: the last own message for `/edit` and
  `/delete`, the last received for `/reply` and `/react`. The status line
  says which.
* Rendering: an "edited" mark after the time; a "deleted" placeholder in
  the dim style; a quote line above a reply; a reaction line below; a
  small mark (`⏳`, `~` in ASCII) on lines with a timer, and the remaining
  time in the status line when such a line is selected.
* The Requests pane holds messages from strangers as before; an edit,
  delete or reaction from a stranger is ignored, and a reply from one
  shows as a text.

### 6.4 Encrypted downloads

* `/files encrypt on` is accepted only when the data directory is
  protected (a key store key or a passphrase); otherwise the client
  explains that the files would be no safer than the directory. With it
  on, a fetched file is written through the vault cipher under its own
  name, so `downloads/photo.jpg` is ciphertext, and the history line
  says "(encrypted)". `/open` decrypts to `downloads/.open/<name>` with
  private permissions, hands that to the opener, and removes it when the
  client exits (and at the next start, whatever is left there). Turning
  the option off leaves encrypted files encrypted; `/open` still reads
  them, and `/files decrypt` writes a plain copy beside on request.
* Files saved before the option was turned on stay as they are.

### 6.5 History export

* `silver --export-history <dir>` unlocks the store as a normal start
  does, then writes `<contact alias or id>.txt` and `group-<name>.txt`
  (or `.jsonl`), one line per message: time, who, text, with "(edited)"
  and the reactions in brackets in the text form, and every field of the
  entry, the earlier texts of an edited message and the reactions as
  fields in the JSON form. Deleted and expired messages are not there;
  placeholders are. Existing files are never overwritten (`(2)` as for
  downloads), and the directory must be outside the data directory.

## 7. What the relay learns, and the threat model

* **Nothing new.** Every kind is a padded body inside a session or an
  MLS message: a reaction is the size of a receipt, an edit the size of
  a text. The relay cannot tell a deletion from a short message. A
  reaction leaves shortly after a delivery, as a receipt does, with the
  same jitter as receipts (it is queued through the receipt queue with
  the read-receipt delay), so timing says no more than receipts already
  say.
* **What delete for everyone promises**, in the threat model's words: a
  recipient whose client is this software, unmodified, on 0.10.0 or
  later, removes the message when the deletion reaches it, whether it is
  running or starts later with the deletion waiting in its mailbox. It
  cannot remove a screenshot, a copy a modified client kept, an export or
  a backup taken before, a file already saved, or the memory of a person
  who read it. The relay never had the plaintext; it holds the sealed
  original until the recipient acknowledges it, and a recipient that
  fetches both applies the deletion at once.
* **What a timer promises**: the same, from the moment the clock runs
  out on each device. A message read on the other side is theirs until
  then. A recipient on 0.9.0 keeps messages for good, and the sender's
  client says so.
* **A malicious contact** can edit and delete their own messages, which
  changes what the reader's history shows of *them*; the history keeps
  every version and the export shows them, so a contact cannot make a
  reader's record say something they did not send. They cannot edit,
  delete or react as anyone else: the author check is on the sealed
  sender (or the MLS sender), which cannot be forged.
* **A device thief** with the data directory gets what the directory
  holds: expired and deleted messages are gone from it (rewritten, not
  marked), files under the encrypted-downloads option are ciphertext
  like the rest, and the `downloads/.open/` copies are removed at exit
  and at the next start.
* **Deniability** is unchanged: the new kinds travel in v4 sessions like
  a text, and group messages stay signed inside MLS.

## 8. Sizes

Every new body is one padding step (160 bytes) or, for an edit, the size
of the text; a `delete` of a few ids and a `timer` fit the first step.
The history file grows by a line per event and shrinks on deletion. The
sweeper reads every conversation's file once a minute only when a timer
is set somewhere; with none set it does nothing.

## 9. Tests

* Protocol: the kinds and the field round-trip as JSON; `reply_to` on a
  text is ignored by a reader that does not know it (the reader of 0.9.0
  is the same code with the field removed, which the test models by
  parsing into a struct without it); the emoji and timer bounds; vectors
  for the padded encodings in `body.json`; the body fuzz target sees the
  new kinds through the existing generator.
* Client: the rules (24 hours, author only, timer bounds); history
  loading with updates before entries; rewriting on delete and expiry,
  the tombstone dropping a late edit and reaction; the sweeper deleting
  on time from `sent_at` and from `read_at` and never an unread message;
  a device snapshot carrying the current state; the sync additions.
  Through a relay: an edit, a delete, a reaction and a timer between two
  clients, the deleted message gone from the recipient's store, a reply
  quoting a known and an unknown target, the kinds withheld from a peer
  without the capability and the user told; in a group, the same among
  three members with the author and admin rules refused for the wrong
  sender, and a member whose leaf lacks `0xF003` named and spared.
* Terminal: a pty test of the commands and the rendering (edited mark,
  deleted placeholder, quote, reaction line, timer mark, a message
  vanishing on time with the timer set short), encrypted downloads
  (`/open` on a ciphertext file, the temporary copy removed at exit), and
  an export read back.

## 10. Implementation order

Each step is one commit on `main` with its tests:

1. Protocol: the content kinds and the field, the capabilities, the leaf
   capability type, bounds, vectors, the fuzz generator.
2. Client, storage and rules: history line kinds and loading order,
   rewriting and tombstones, the `everyday` module, the sweeper, the
   contact, group and config fields, `sync read` with `at_ms` and `sync
   remove`, the snapshot; tests.
3. Client, delivery: the kinds through sessions and groups, the spread,
   the group capability check, the receipt-queue jitter for reactions;
   end-to-end tests.
4. Terminal client: commands, selection targets, rendering, timers and
   the sweeper tick, group rules and the older-member message; pty test.
5. Encrypted downloads and history export.
6. Documents: PROTOCOL.md 4.x and 13.3, the threat model, README,
   CHANGELOG, roadmap; this note's corrections.

Compatibility through the steps: nothing sends a new kind until step 3,
and until then a 0.10.0 tree is a 0.9.0 client with more code.
