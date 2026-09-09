# Changelog

Notable changes to Silver Messenger. Versions follow [semantic
versioning](https://semver.org); while the major version is 0, a minor bump
means behaviour or the wire protocol changed in a way worth reading about.

## 0.15.0 - 2026-09-09

### Security

- `/devices link` no longer takes a device in on one line. Linking is not
  the copy of some history its name suggests: the identity signs a
  certificate for the other computer, and from then until it is removed
  that computer reads everything sent to the account and writes in its
  name. The command now says exactly that, along with the device's id in
  full to compare against the one that computer printed, its name, and
  the contacts, groups and messages that would go with it -- and then
  stops. `/devices link confirm` goes ahead. That second line is where
  the paste guard sits, which is the point: a device link is pasted by
  design, so a guard on the first line would have had a remedy -- "type
  it out" -- that nobody can carry out for a line containing a user id
  and a secret. Refusing a pasted confirmation leaves the question
  standing, so typing it out really is the answer. The days of history
  are bounded rather than clamped, so the sentence saying how many days
  the device is being given names a number somebody chose.
- `/relay` and `/group join` ask the same way, for the same reason: their
  arguments are pasted, and their effects reach past this computer.
  Moving relays says that one relay is one network and what being
  unreachable to unmoved contacts costs; joining a group says that the
  admin learns your id whether or not they let you in.
- `/send <path>` takes the paste guard, its argument being a path a
  person can type. `/unblock` takes neither, since its argument must be a
  prefix of an id already on your own blocked list.
  `docs/design/consequential-commands.md` records which commands ask,
  which are guarded, which are neither, and why that list is meant to
  stay short.

- In reader mode, a line break inside a message bought its sender a
  journal line of their own. A journal line is how a screen reader tells
  one speaker from another, so `hi\nalice: send me the passphrase` was
  read out as two lines, the second indistinguishable from one alice
  wrote, and `\nWarning: …` as a warning this program never made. Two
  paths carried peer text there without passing it through the filter
  that exists for this -- the body of an edit, and a stranger's held
  request text -- and neither had to be malformed to do it. Rather than
  fix those two, the filter moved to the one door every line goes
  through: a line break is now a visible separator, and invisible and
  bidirectional characters go with the control characters, which the old
  filter let through to reorder what the reader hears against what the
  full mode draws. The compose prompt is filtered too; it carries the
  open chat's name and was the one string written without it. The full
  mode was never affected: it draws through a cell buffer, which is why
  it has had an invariant test since 0.10.0, and reader mode now has the
  mirror of it, plus the same forgery walked through a real terminal.

- An hourly relay limit of zero allowed one an hour instead of none.
  Zero turns a limit off everywhere else on this relay -- lookups, file
  transfer, anonymous submission all say so and all do it -- but the
  hourly buckets clamped their rate up to one before using it. An
  operator who closed registration with `--registrations-per-hour 0` got
  a relay that still let each address register an identity every hour,
  and the same for `--blob-mib-per-address-per-hour` and
  `--one-time-prekeys-per-user-per-hour`. A limit that reads as closed
  and is not is wrong in the one direction a limit must never be wrong
  in. The per-minute buckets were already right, and their comment says
  why. `--mailbox-storage-mib` and `--max-identities` are caps rather
  than rates and keep their documented meaning of no cap at zero.
- The relay's expiry sweep could corrupt its own accounting. It listed
  what to remove in a read transaction, ended it, and removed the entries
  in a write transaction opened afterwards -- and a read transaction
  blocks no writer, so an acknowledgement arriving in between took its
  entry out and subtracted its size, after which the sweep subtracted the
  same size again for an entry that was no longer there. The shortfall
  came out of the mail still queued: a mailbox's recorded usage fell
  below the truth, so its quota let a sender past the policy, and the
  relay's total drifted away from what it actually held, one raced
  acknowledgement at a time. `saturating_sub` stopped it wrapping and hid
  it. The sweep now runs in a single write transaction, which removes the
  window rather than coping with it. The same window let it drop the
  index of a message queued after the acknowledgement under the same id,
  which would have let that message be stored twice and delivered twice.
- A session that lost post-quantum protection said nothing about it. The
  client showed what each new session was -- post-quantum throughout, in
  the handshake only, or classical -- which is no help for the case that
  matters: a classical session with a contact whose sessions had all been
  post-quantum reads exactly like a classical session with a contact who
  never had one. That is the shape of a bundle reaching you with the
  ML-KEM keys stripped out, which is what somebody recording the
  conversation to open later would arrange, and it looked ordinary. The
  best level a session with each contact has reached is now kept with the
  contact, and a session below it is reported when it starts and by
  `/session` while it lasts. A rise says nothing: that is a contact
  updating, and the session line already names it. The client cannot
  distinguish a stripped bundle from a contact on an older client, so it
  says what changed, gives both readings, and asks the user to check on
  another channel.
- A client built from a checkout with no `minisign.pub` installed
  whatever the release host served. Both the design note and the
  constant's own comment had said since 0.12.0 that such a build refuses
  to update; the code skipped the signature, installed the binary, ran
  it, and printed a line afterwards saying no signature had been checked
  -- which is a note in the log of a machine already running someone
  else's code. The two remaining checks are no substitute: the digest on
  the releases page and the digest in `SHA256SUMS` are both answers from
  the host serving the bytes, so they agree with each other for anything
  that host cares to hand out. It now refuses, before it fetches
  anything, and again at the point of use so no path through the check
  can end without a signature. Releases built from this repository are
  unaffected -- it publishes a key, and those clients were checking the
  signature all along.
- The key store could keep a wrapping key that nothing needed. 0.15.0
  already dropped a key made for a change that then failed, but only by
  running the failure path -- and the key is written to the store before
  the vault that makes it needed, so a crash, a kill or a power loss in
  the window between left a key nobody read, nobody remembered, and that
  still opened a copy of the directory taken while it was encrypted. The
  name of a key whose fate is undecided is now written to `vault.pending`
  before the step that could orphan it, and the next start takes out
  whatever that file names and the vault does not need. Removing the
  protection and erasing the device are covered the same way, both having
  had the same gap between deleting the vault and deleting the key.
  Deciding this needs the vault, so `write_atomic` now syncs the
  directory entry after the rename, not just the file's contents: until
  it does, a crash can leave the bytes safely on disk under no name.
- The same key-store check treated a vault it could not read as a vault
  that did not name the key, and deleted it. An unreadable vault is the
  absence of an answer, not a no, and the key it might name is the only
  way into every file in the directory: the check now keeps both the key
  and the note, and a later start decides.

### Fixed

- A group alias was stored exactly as typed while a contact alias was
  filtered, four lines apart in the same command. It mattered because a
  group's display name is what the reader-mode compose prompt is built
  from, and that prompt is written to the terminal without passing
  through the cell buffer, so an alias carrying an escape sequence
  reached it intact. Group aliases are now filtered where contact aliases
  are: on the way in, including the copies that arrive from your own
  other devices, and on the way out, because a data directory written by
  an earlier version already holds whatever was typed then.
- Erasing a device left the key that wrapped its files in the operating
  system's key store. The files went, the key stayed, and a copy of the
  data directory taken before the erase still had something to be opened
  with -- which is the one thing erasing is meant to prevent. A wipe now
  reads the vault before the files go and takes that key with them. A key
  made for a change that failed before the vault naming it was written is
  dropped in the same way, rather than left in the store with nothing
  reading it; and where a key is taken out at the end of a change, a
  failure to remove it is now reported rather than passed over, since the
  key still opens a copy of the directory from before the change.

### Changed

- On Windows the client keeps other programs of the same user out of its
  memory. `harden_process` disabled core files everywhere and stopped
  tracing on Linux, and had no Windows branch at all: an ordinary program
  started under the same account, with no elevation and no debugger,
  could open the running client and read the keys out of it, which an
  outside review demonstrated against 0.14.0 on Windows 11. The process
  object now carries an access list that allows only what a process must
  leave open -- asking its identity, ending it, waiting on it -- so that
  call is refused. This is cost rather than prevention: the owner of a
  process may rewrite its access list, so an attacker who knows to do
  that first is back where they were, and reading an unlocked client
  remains a limit no software on the same machine can close. macOS has
  neither protection and the threat model now says so.
  `SILVER_NO_PROCESS_HARDENING=1` turns it off where it gets in the way.
- The threat model gains "Program running as you" as an actor of its own:
  what such a program reads, what each platform manages against it and
  what each leaves, that the lock is the boundary that does hold because
  the client is torn down rather than marked unreadable, and that pages
  of an unlocked client may reach swap or a hibernation image, which
  full-disk encryption answers and this program does not.

## 0.14.0 - 2026-09-08

### Added

- Requests are chats you have not answered yet. A message from someone
  who is not a contact is an entry of its own at the bottom of the chat
  list, marked `?` and named by their id and nothing they chose; open it
  and every message they sent is there, not the last three. On it,
  `/accept`, `/decline` and `/block` take no argument, and a typed reply
  accepts and sends. A group invitation from a stranger is an entry in
  the same way. The one Requests pane, with its numbered list of everyone
  waiting, is gone; `/requests` prints that list into the System pane.
  The chat list scrolls to keep the selected entry on screen. Design
  note `docs/design/requests.md`; roadmap item 60.
- `/decline`: *not now*, where `/block` is *never*. The request and its
  messages go and the sender is told nothing, exactly as with a block;
  if they write again the request comes back, without a bell or a
  notification, until you accept them. Who you declined is remembered
  on this device (`declined.json`, at most two hundred) and forgotten
  when you accept or block them. An invitation is declined the same way,
  and its inviter's next one is quiet too.
- One way of naming a person under every command that takes one: an
  alias, the full id, or enough of the id to be one person's; with
  nothing given, the open chat. `/block`, `/unblock`, `/accept`,
  `/decline`, `/go`, `/group add`, `/group remove`, `/group admin`,
  `/copy id` and `/whois` all use it, and an ambiguous prefix says who
  it matched instead of guessing.
- `/copy id <who>` copies a contact's id, and a click on the title of a
  chat or a request copies the id shown there, since the title cannot be
  selected. `/whois [who]` prints a person's id, alias, verification
  state and how messages with them are protected into the System pane
  as ordinary selectable text. Tab completes contact aliases after every
  command that names a person, and group names too after `/go`.

### Changed

- The bell and the desktop notification are raised for a message
  received, and for nothing else: a message in a chat, in a group, from
  a stranger (their first), or reaching this device through a linked
  one. A group invitation, being added to a group and joining one by
  link no longer ring; they are in the System pane and the chat list. A
  stranger can ring the terminal once, and not again once declined.
- The numbers `/accept`, `/decline` and `/block` take hold still. A
  request or invitation is numbered when first seen, in one sequence for
  both kinds, and keeps its number until it is handled; a number is not
  reused within a run, so the one in the arrival line stays true.
  `/accept 3` takes entry 3 whichever kind it is; `/accept g3` takes it
  only if it is an invitation. `/unblock` takes enough of an id to be
  one of the blocked ones.

## 0.13.0 - 2026-09-08

### Added

- Desktop notifications that reach the desktop. Since 0.4.0 a notification
  was raised through the terminal alone -- OSC 777, 9 and 99 written to
  stdout -- which the common terminals ignore, so on Windows Terminal, the
  Windows console, Terminal.app, GNOME Terminal and every other VTE
  terminal, Konsole and Alacritty `/notify all` was a bell and nothing
  more. The client now asks the operating system itself where the
  terminal will not: the session bus on Linux, through the `zbus` the key
  store already links; `osascript` on macOS; a toast on Windows through
  `tauri-winrt-notification`, the one crate this adds, gated to Windows.
  Which path a run takes is decided once from the environment -- the
  terminal's own sequences for the terminals that raise one and over SSH,
  the desktop for the rest, both for a terminal the client does not
  recognise -- and `/notify terminal` or `/notify desktop` forces one.
  Inside tmux the sequences are wrapped in its passthrough. A machine
  without a notification service is left alone for ten minutes after one
  failed try, and the interface never waits for it. Design note
  `docs/design/notifications.md`; roadmap item 59.

### Changed

- A notification says `New message` and nothing else, on every path, for
  every event: not who wrote, not their alias or id, not a group's name,
  not a word of content. Until now the terminal-raised toast on kitty,
  iTerm2, WezTerm and foot named the sender, a contact request carried
  the requester's id, and a group event its name. The call that raises a
  notification takes no text at all now, so nothing about a message can
  reach one by mistake later either. Everything that was in a
  notification is still in the client: the System pane, the chat, the
  unread count in the window title.
- `/notify` gains `terminal` and `desktop`. `desktop`, which used to be
  another word for `all`, now forces the operating system's path.

## 0.12.5 - 2026-09-08

### Fixed

- `silver update` failed with "reading the answer: peer closed connection
  without sending TLS close_notify" from behind a TLS-inspecting proxy,
  the kind a workplace network runs. The update client asks over HTTP/1.0
  and reads the answer until the connection closes; a server or a
  middlebox that ends the body by closing the socket, without first
  sending the TLS close_notify that rustls wants, made the read fail even
  though the whole answer had already arrived. That close is now taken as
  the end of the answer, which it is. Nothing is trusted more for it: a
  release must still parse as JSON, and a download must still match
  `SHA256SUMS` and its signature before it replaces anything.

## 0.12.4 - 2026-09-07

### Fixed

- The first-run question, whether this computer should join an identity
  kept on another, hid the answer as it was typed. It was read with the
  passphrase routine, so `y` and `n` put nothing on the screen and looked
  as if they did nothing, and Enter on its own -- the natural next move
  -- quietly started a new identity. A yes-or-no question now shows its
  answer as it is typed, the way `silver update` has asked its own all
  along, and both go through the one routine. Passphrases stay hidden.
  Found on a Windows first run; it was the same everywhere.

## 0.12.3 - 2026-09-07

### Fixed

- The release notes named two files 0.12.2 had stopped publishing. The
  table told anyone running a relay to take `install.sh`, which left the
  release page in that same release, and a line below it described the
  archives, which left with it. The table now names the relay binary,
  which is what a relay operator actually takes, and the systemd unit and
  the installer are pointed at in the repository where they live. Written
  before the decision to publish only the program, and not read again
  after it -- which is the whole failure the fourteen-file release page
  was meant to end.

## 0.12.2 - 2026-09-07

### Changed

- A release page carries the program and nothing else. It had grown to
  thirty-six files, of which twenty were machinery -- ten SBOMs, five
  build records, five archives -- and the answer to "which one do I
  download" was somewhere among them. What is published now is fourteen
  files: `silver` and `silver-relay` for each of the five targets, one
  file each; the two Debian packages; and `SHA256SUMS` with its
  signature, which is not the program but is the only way to tell that
  what arrived is. The release notes lead with a table saying which file
  to take.
- The SBOMs and the build record are still made, attested and checked;
  they ride on the workflow run rather than the release page. The
  packaging archive does too -- it is a maintainer's working file. The
  per-file provenance attestation still covers everything published.
- The Homebrew formula installs the binaries rather than unpacking an
  archive: the client as its download, the relay as a resource beside it.
- The AUR package and the winget manifests are gone. Both were written,
  linted on every push and regenerated at every release, and neither was
  ever installable by anyone: the AUR needs a push to
  `aur.archlinux.org` from the maintainer's account and winget a pull
  request to `microsoft/winget-pkgs` per release, and neither had been
  done. They were upkeep producing nothing. An Arch or Windows user takes
  the one file for their platform from the release page, which is the
  whole client; `silver update` keeps it current from there. What the
  client does when it finds a binary a package manager owns is unchanged,
  and now covers managers this project does not publish to: it refuses to
  replace it, because a binary somebody else packaged is even less this
  client's to touch.
- `deploy/install.sh` is no longer a release asset. It stays in the
  repository and is read before it is run; the shorter path for an
  operator is now the relay binary from the release page, checked against
  the signed `SHA256SUMS`, beside the unit from the repository -- fewer
  moving parts than a script, and better checked.

## 0.12.1 - 2026-09-07

### Fixed

- `silver update` could not install anything in 0.12.0. The download is
  created the way any new file is, without the bit that lets it run, and
  the last check before a swap is running it to see that it reports the
  version expected -- so every update stopped there with "Permission
  denied" and nothing was installed. The download is made runnable, by
  its owner alone, as soon as it is written; the mode it finally keeps is
  still the replaced binary's, which the swap copies over it. Found by
  running the released 0.12.0 client against the real releases page
  rather than a test one, and now covered both by a unit test at the
  place the mode is set and by an integration test whose stand-in binary
  is one the test actually executes.

## 0.12.0 - 2026-09-07

### Added

- `silver update` replaces the running client with the newest release,
  after checking it four ways: against the SHA-256 the release API
  reports for that file, which arrives from a different origin than the
  bytes; against the same hash in `SHA256SUMS`, which is what a person
  checks by hand; against the project's signature over `SHA256SUMS`,
  using the key compiled into the client from `minisign.pub`, so what
  decides whether a binary may replace yours comes from the source and
  not from the network; and by running the downloaded file and requiring
  it to report the version expected. A disagreement anywhere leaves the
  running client alone and says what disagreed with what. The binary that
  was replaced is kept beside it, so `silver update --rollback` puts it
  back; `--check` reports without changing anything and `--to <version>`
  installs a named one, which going backwards also needs `--yes` for,
  since an older client may not read what a newer one has written.
  A client a package manager installed is refused with that manager's own
  command, because replacing it there breaks its verification and is
  undone by its next upgrade. Releases now carry the bare `silver` and
  `silver-relay` per target beside the archives, so an update fetches the
  client alone rather than an archive holding the relay, two SBOMs, the
  changelog and the licence. Design note
  [docs/design/updates.md](docs/design/updates.md).
- `/update` in the client says which version this is and what to run; it
  downloads nothing, because the interface holds an unlocked data
  directory and open sessions. `update_check` in `config.json` asks the
  releases page once a day at start and prints one line -- off unless
  turned on, since a check on a timer tells the release host an address,
  a program and the times it is used. Both go through the proxy the relay
  connection uses, so a client on Tor does not step outside it to ask.

### Security

- Releases are signed again, and this time the key exists. `SHA256SUMS`
  is signed with the project's minisign key, whose public half is
  `minisign.pub` at the repository root, so a download is checked with
  `minisign -Vm SHA256SUMS -p minisign.pub` and nothing needs to be asked
  of GitHub. 0.11.0 had removed the signing step on the grounds that a key
  the workflow can read says only what the build provenance says; that
  went too far. The secret store and the release assets are separate
  systems, so a signature made from a secret still survives someone who
  can only reach the published files, and since a verifier checks against
  `minisign.pub` either way, the step is also what makes an offline key a
  later decision rather than a rewrite. The workflow verifies its own
  signature against the published key before publishing, so a secret that
  is not that key fails the release instead of shipping something nobody
  can check.

### Added

- `packaging/new-signing-key.sh`, and `new-signing-key.ps1` for Windows,
  make the release signing key: unencrypted for the repository's secret
  store, where the workflow signs each release by itself, or `--by-hand`
  (`-ByHand`) for a password-protected key that never leaves the
  maintainer's machine. Both self-test the key before printing what to do
  with each half, and refuse to replace a key the repository already
  publishes.
- A `Signing key check` workflow, run by hand, signs a throwaway string
  with the secret and verifies it against `minisign.pub` -- the two
  commands a release runs, without building or publishing anything, so a
  mismatched key is found before a release rather than during one.

## 0.11.0 - 2026-09-07

The security review's Medium, Low and Informational findings, in the
order the response note sets out
([docs/design/audit-response.md](docs/design/audit-response.md)).
Section 13.1 of the report went out in 0.10.1; this is section 13.2 and
the Informational findings that sat beside those. That leaves four of
the 76, each of which changes a wire or an on-disk format and waits for
the version that may (roadmap item 57): a message's own id inside the
authenticated body, rollback protection for the key-bearing files, the
identity key bound into the v4 handshake, and history file names under
an HMAC.

Nothing here changes the wire protocol, so a 0.11.0 client talks to a
0.10.x relay and the other way round, and a relay upgraded to 0.11.0
keeps its database as it is. Two files a client keeps gain fields, both
readable by an older version and written only when they say something:
`contacts.json` records a per-sender acceptance window and which of your
own devices pinned or verified each contact, and `groups.json` records
whether an admin's word about you came from the group or from whoever
invited you, and how often each invite link has been answered.

### Security

- **A capability list cannot be merged into one name** (finding SM-P-03,
  Medium). The bytes an identity signs for its capabilities are the
  names joined with newlines, and nothing said a name could not contain
  one. So `["pq_ratchet", "groups", "devices"]` and the single name
  `"pq_ratchet\ngroups\ndevices"` sign the same bytes, and since a
  client matches a capability by exact string, a relay could re-serialise
  the three into one, keep the signature valid, and serve a bundle that
  advertises nothing — forcing a classical, non-deniable session and
  hiding that the owner does groups and devices at all. A name is now one
  or more of `[a-z0-9_]`, which makes the join unambiguous, and a bundle
  carrying anything else is refused rather than read as advertising
  nothing.

- **A ratchet header takes only the ML-KEM lengths it may** (finding
  SM-P-06, Low). The associated data lays the ML-KEM public key and
  ciphertext end to end with no length in front, and the fixed lengths
  were checked only where the fields were used, so a header carrying one
  2272-byte key and no ciphertext covered the same bytes as one carrying
  a 1184-byte key and a 1088-byte ciphertext. Nothing followed from it —
  the root key derived from the two differs, so the message key does and
  the AEAD fails — but the encoding should not lean on that. The lengths
  are checked before the associated data is built.

- **Group and device names are chosen without invisible characters**
  (finding SM-P-08, Low). Both checks refused control characters only,
  while a reaction already refused the zero-width spaces, the bidi
  embeddings and overrides, the word joiners and the byte-order mark. A
  group called `Team<U+202E>` or a device padded with zero-width spaces
  reached the sidebar, the "joined" lines and the device list. Those
  characters are refused where a name is chosen — creating or renaming a
  group, certifying a device. They are not refused where a name is read:
  the signature covers the bytes as they were written, and a group made
  or a device linked by an older version would otherwise stop verifying.

- **A group message id follows the rule a one-to-one id follows**
  (finding SM-P-09, Low). An id inside a group's application message was
  checked for length alone, while a one-to-one id must be printable
  ASCII. Since edits, deletions and reactions name ids, a newline or an
  escape sequence in one travelled into the history and the screen. Both
  now follow the same rule, and the specification's two sections agree.

- **An id is the canonical encoding of its key** (finding SM-P-10,
  Informational). Ed25519 decompression reduces the `y` coordinate
  modulo the field prime, so a handful of points had a second encoding
  that decompressed to the same key: two ids for one identity. None has a
  usable private key and strict verification refuses them anyway, but an
  id *is* a public key written down and there is one way to write each.
  A non-canonical encoding is refused.

- **A device certificate cannot encode a length it never checked**
  (finding SM-P-12, Informational). The name length goes into one byte,
  and the encoder was reachable through the transparency leaf on a bundle
  nothing had verified, so a name longer than 255 bytes was silently
  encoded wrong. The length is clamped instead, which makes the bytes
  differ from any name that verifies, so the signature fails and no leaf
  is quietly wrong.

- **Smaller client items** (finding SM-C-27, Informational). Each is
  minor on its own:

  A contact whose log head was below the checkpoints still kept — every
  256th entry, the last few thousand — was reported as a *fork*, which
  accuses them of seeing a different log, when all that had happened was
  that they had been away while the log grew. A position this client
  cannot speak to is now said to be unchecked rather than contradicted.

  `silver.log` is written only when `SILVER_LOG` asks for it, but it
  survived `/devices leave`, which erases everything else the identity
  left behind; it goes with the rest now. What it holds at `debug` — 
  envelope ids, contact ids, the relay and its errors — is stated in the
  README and the ASVS assessment, which claimed "sanitised aliases only"
  and was wrong.

  `observe_relay`'s comment said it says nothing to the relay; it makes
  the WebSocket upgrade request and closes, which the comment now says.

  Two clients on one data directory shared a `.tmp` name, so each could
  write over the other's half-written file and rename the result into
  place; the name carries the process id now. (Two clients on one
  directory is still not a way to run: they interleave history appends
  whatever the names are.)

  An invite or group link's `relay=` was taken as given, unbounded and
  unchecked, and offered to the user as a relay to switch to. It has to
  look like a relay URL now — `ws://` or `wss://`, a host, at most 512
  characters — and a `ws://` one is described as unencrypted rather than
  offered as a command to copy. An alias given to `/add` is kept to what
  a name can be.

  Reader mode has no alternate screen, so `/lock` printed the rest of
  the journal and left the whole conversation a scroll away from whoever
  was at the keyboard. Locking clears the screen and its scrollback.

  Everything in the System pane and every toast is filtered to one line
  with nothing a terminal acts on: some of what lands there is the
  relay's or a peer's, and the pane is also read aloud and written to
  the log.

- **A message that overtakes its neighbours is still a message** (finding
  SM-C-15, Low). Only the last `(epoch, seq)` from each sender was
  remembered, so anything below it was a replay: a message reported
  missing and then delivered — which a relay can arrange simply by
  handing a mailbox over in another order — was dropped rather than
  shown. A sixty-four-message window of what has arrived is kept
  alongside the highest, so a late message is shown once and only once.
  The same state closes a second hole: any different epoch counted as
  "a fresh installation", so a relay could hand a whole old conversation
  back under fresh envelope ids and have it accepted, the envelope id
  being outside every AEAD. Where the sender's previous numbering ended
  is remembered too, and numbering that goes back into it is a replay.
  A `contacts.json` written before this reads as "the highest, nothing
  else known" and its JSON is unchanged when there is nothing more to
  say.

- **The session store is bounded, and so is what a relay can make the
  client generate** (findings SM-C-14 and SM-C-15, Low). Sessions were
  capped at five per peer and nothing capped the peers, so anybody who
  knows an id could grow `sessions.json` without limit — twenty new
  identities an hour per address, five far-ahead handshakes each, a few
  kilobytes of ML-KEM state and up to two thousand skipped keys apiece,
  and the Requests cap dropping the *message* only after the session was
  stored. There is a cap on peers now (256), and beyond it the least
  useful goes: a stranger this client has only ever heard from before
  anybody it has written back to, and the longest unused before the
  rest; a peer no session with has been used for six months goes on its
  own. Separately, how many one-time keys are left and which were handed
  out is the relay's word: it can claim the deposit is empty on every
  connection while dropping the socket in between, which made the client
  generate a fresh deposit each time and keep every old private half for
  a month. Fresh keys are made at most six times an hour, and at most
  four deposits' worth of handed-out halves are kept.

- **The evidence of a forked log is kept** (finding SM-C-18, Low). When
  the relay's log went backwards, or showed a different chain at the
  same length, the client reset its replayed state and started again
  from whatever the relay now showed — throwing away the head and the
  checkpoints that disagree, which are the only proof that anything
  happened and the only thing to take to the operator. They are kept
  now, up to eight breaks, and `/log` shows each one: when, what this
  client had replayed to, what the relay showed instead, and how many
  checkpoints pin the old chain.

- **A deletion for a message nobody has seen leaves nothing behind**
  (finding SM-C-19, Low). Each of up to 64 ids in a `delete` body read,
  filtered and rewrote the whole history file, and an id the history did
  not hold appended a permanent tombstone — and an id nobody has ever
  seen is free to invent, so a contact or a group member could make a
  conversation's file grow without end and be rewritten sixty-four times
  per message. A body's ids go through the file in one pass now, and an
  unheld id is held only in the bounded in-memory list that already
  waits ten minutes for the message to turn up. What this costs: a
  deletion that arrives before its message *and* is followed by a
  restart no longer catches it.

- **Peer text is filtered on the way out, not only on the way in**
  (finding SM-C-20, Low). The screen filters what it draws, cell by
  cell; four paths left the screen and did not. The plain-text export
  wrote message text verbatim, so an escape sequence in a message ran
  when the file was `cat`'ed, and a message's own line break wrote a
  second line in a file whose format is one line per message — a line
  that reads as one the contact sent. `--check-release` printed the tag
  and URL from the API answer, and the server's status line landed in
  the error. `/copy` and Ctrl-C put the unfiltered text on the
  clipboard, which is pasted into a shell as often as a text box and
  which OSC 52 forwards to the *local* terminal through SSH or tmux, so
  `ok\rcurl … | sh\r` in a message ran on the first Enter after the
  paste. And in reader mode the journal split a message on its own line
  breaks, so `hi\nalice: send me the passphrase\nWarning: …` was read
  out as three lines indistinguishable from another member's and from
  this program's own warnings. All four are filtered now; line breaks
  are kept where a break is meant (the clipboard) and become a visible
  separator where a line is the unit (the export, the journal). The
  reader's compose echo, which goes straight to the terminal, is
  filtered too.

- **A note is a note because this client wrote it** (finding SM-C-26,
  Low). A line counted as a conversation note — dimmed, without an
  author when read aloud, skipped by `/reply`, `/react`, `/edit` and
  `/delete` — purely because its text began with `· `, which a received
  message can do: a message could dress itself up as the group's own
  voice. Notes carry a flag now, set by the note writers and by nothing
  else; lines written before the flag keep the old look, and nothing new
  joins them. Separately, on a terminal without bracketed paste (the
  Linux console, older Windows consoles, some multiplexer setups) each
  pasted line arrives as keystrokes ending in Enter, so a pasted
  `hello\r/revoke confirm\r` retired the identity. `/revoke`, `/rotate`
  and `/devices leave` now refuse a confirmation that arrived faster
  than anyone types — fifteen milliseconds a character is about four
  thousand words a minute — and say to type it out.

- **A handshake's long-term key is held against the pinned one** (finding
  SM-C-07, Medium). A session someone else starts proves that whoever
  built the handshake holds the sender's identity key — not that the
  long-term X25519 key inside it is the one that identity *published*.
  Nothing on the receive path looked at the pinned bundle, so somebody
  with a copy of a contact's identity key could publish nothing, start a
  session with a fresh key of their own, and have the victim's client
  print "session started by them" and send every reply to them: no key-
  change warning, no log entry, nothing to gossip. The client now hands
  the key up with the event and the front end compares it with the pin.
  On a mismatch the session is dropped, so nothing is replied into it,
  and the user is told plainly that the message may not be from the
  contact and to compare safety numbers over another channel.

- **An unreadable message names nobody it cannot prove** (finding
  SM-C-13, Low). For a v4 or v5 body the sender named at the
  sealed-sender layer is not authenticated by anything, and one of the
  ways a message fails to open — `UnknownSession` — needs no keys at
  all. So anyone, a blocked id or the relay included, could send a few
  bytes and have "A message from Alice could not be read … sending them
  a message starts a fresh session" appear on the victim's screen: a way
  to write in someone else's name, and past `/block`. A sender is now
  named only when the failure came from a session this client actually
  holds, whose id nobody else could know; every other failure says a
  message arrived that could not be read and names no one. The notices
  are gathered into one line a minute, since they cost the sender
  nothing.

- **A relay cannot quietly take back what it offered** (findings SM-C-05
  and SM-C-16, Medium and Low). The feature list arrives on every
  connection and is the relay's own word, different per client if it
  likes; nothing compared it with what the same host offered before. A
  relay that wanted to serve one client a stale or stripped bundle had
  only to leave `transparency` out of that client's `auth_ok`, and the
  client would check nothing, warn nothing and stop gossiping heads —
  which cost its contacts the ability to catch a fork through it too.
  The same for `anonymous_send`: the client fell back to submitting on
  the authenticated connection with a `warn!` and no sign on screen, so
  a relay learned which identity sent every message and a user routing
  through Tor could not tell. What each host has offered is remembered
  now, and anything withdrawn is said plainly, with what it costs, every
  time it happens. The status line marks a connection whose sends are no
  longer anonymous, and `--require-anonymous` refuses to send at all
  rather than fall back.

- **The data directory is the owner's alone** (finding SM-C-10, Medium).
  Only the key-bearing files were created 0600; the directory itself was
  0755 under a normal umask and `config.json`, `contacts.json`,
  `devices.json`, `requests.json`, `blocked.json`, every history file,
  downloads, exports and backups were 0644. On a machine with no key
  store and no passphrase — the headless-Linux case, where the fallback
  is plain files — any other local user could read the proxy's
  credentials, the invite token, the contact list and every
  conversation. The directory is now made 0700 (and an existing Silver
  directory is tightened on the way, though a directory that is not ours
  is left alone: `--data-dir` could name anything), every file the store
  writes goes through the private writer, and downloads, exports and
  backups are 0600 in a 0700 directory. The outbox and the transparency
  checkpoints are written and synced the way the rest are, rather than
  with a plain write.

- **Changing the passphrase changes the key** (finding SM-C-23, Low).
  Moving between a passphrase and the key store re-wrapped the same data
  key, so anyone with an old copy of `vault.json` and the passphrase in
  force when they took it went on reading everything written afterwards
  — including everything written after the passphrase was changed
  *because* the old one had got out. The files are rewritten under a
  fresh key instead. The vault names both keys while that runs, so a
  crash at any point leaves a directory that still opens: whichever key
  a file is under is in the vault, and the next unlock finishes the move
  and drops the old key.

- **A file asking for more work than the program will do is refused**
  (finding SM-C-21, Low). The Argon2id parameters are what the key to
  check the AEAD is made from, so they cannot themselves be
  authenticated: `vault.json`, or a backup file handed to somebody, could
  name any cost the `argon2` crate accepts — up to 4 TiB of memory — and
  the client would ask the allocator for it and be killed. Anything above
  1 GiB, 16 passes or 8 lanes is refused on read, far above the defaults
  (64 MiB, 3 passes, 1 lane).

- **Only what is shown goes to the system's opener** (finding SM-C-11,
  Medium). `/open` refused a list of extensions the system runs rather
  than shows, and the list was missing a good many: `.appref-ms`,
  `.scf`, `.chm`, `.xll`, `.search-ms`, `.rdp`, `.theme`, `.wsc`,
  `.msh*`, `.ps2`, `.pyz`, `.ahk`, `.udl`, `.iso` and the other disk
  images that mount themselves, `.job`, `.inetloc` and its macOS
  cousins, `.class`, `.lua`, `.tcl`, `.service`, and the macro-bearing
  office formats. A list of what to refuse is always one entry short of
  the next release of an operating system, so it is an allowlist now:
  pictures, PDFs and e-books, macro-free documents, text, sound, video
  and archives go to the opener and nothing else does. Anything else can
  still be opened from the downloads folder, which is the computer's
  decision and not this program's. Separately, the plain copy `/open`
  makes of an encrypted download never carried the mark of the web,
  so on Windows SmartScreen, Protected View and Office's macro blocking
  did not apply to it while they did to the plain file beside it; it
  carries one now, and a copy that could not be marked is reported
  rather than handed over as if it had been.

- **The release check goes the way everything else goes** (finding
  SM-C-09, Medium). `--check-release` took its proxy from the command
  line or the environment only, never from the settings, so a user who
  had run `silver --proxy socks5://127.0.0.1:9050` once — and whose
  relay traffic went through Tor from then on — reached GitHub directly
  with one documented command, resolving the name locally and telling
  GitHub and everyone on the path that this address runs Silver
  Messenger. It now reads the remembered proxy and extra roots, as the
  relay connection does; a protected directory asks for its passphrase
  so that they can be read, and `--proxy` on the command line answers
  the question without it.

- **The passphrase from the environment is spent, not kept** (finding
  SM-C-22, Low). `SILVER_PASSPHRASE` was held for the life of the
  process, so `/lock` and the idle lock dropped the keys and
  immediately re-derived them with nothing asked — a lock that opens
  itself locks nothing. It is used once and dropped now, and a lock
  asks for it again as it does for a typed one; `--keep-passphrase`
  keeps the old behaviour for runs nobody is sitting at. Passphrases
  read from the terminal and taken from the environment are held in
  memory that is wiped when it goes.

- **A mailbox is delivered a page at a time** (finding SM-R-07, Medium).
  A connection's outbound queue was unbounded, and logging in pushed
  every waiting envelope into it at once, so a client with a full
  mailbox made the relay hold the whole of it — up to the 32 MiB per
  mailbox — in memory; a client that opened a socket, logged in and
  then stopped reading held that memory for as long as it liked, since
  the idle timeout watches for silence and a blocked connection is not
  silent. Now the relay hands one connection at most sixteen envelopes
  at a time and sends the next as each acknowledgement comes back,
  reading from the mailbox in order each time, and gives up on a
  connection whose write has not gone in thirty seconds
  (`silver_relay_slow_closed_total` counts those). The relay's own copy
  of a session is the only one that can write to it, so evicting a
  client ends its connection whether or not the notice fits in the
  queue. A client must acknowledge what it is handed to be handed the
  rest, which this project's client has always done, poison envelope or
  not; `docs/PROTOCOL.md` section 7.1 says so now.

- **A group id nobody has used lately is still its group's** (finding
  SM-R-08, Medium). A sequencer entry that no commit had moved for 180
  days was deleted, and a group id with no entry belongs to whoever asks
  for it first: a member the group had removed could wait for the group
  to go quiet, create the entry at an epoch and a token hash of its own,
  and leave the real members' commits refused for as long as it kept
  re-creating it. An idle entry is now *retired* rather than dropped —
  a headstone keeping the epoch and the token hash the group died at —
  and only two things raise it, both of which need the group's exporter
  at that epoch: a creation for exactly those values, or a commit
  carrying the token itself. Anything else is refused as it would be
  against a live entry. A headstone nobody raises for a further 180 days
  goes, and the id is free again. Retired entries do not count against
  `--max-groups`, and `silver_relay_retired_groups` reports them. No
  wire change: the values a client already sends to re-create an entry
  the relay lost are the values a headstone asks for.

- **Smaller relay hardening** (findings SM-R-09 to SM-R-13). Each is
  minor on its own:

  A revoked identity could still log in, read and acknowledge its
  mailbox, and deposit key packages, though a revoked *device* was
  refused — so whoever held a key that was revoked because it was
  compromised kept the one thing revocation was for. A revoked identity
  is now refused at login like a revoked device.

  The sequencer's epoch was incremented with `+=`, and an anonymous
  connection could create an entry at `u64::MAX` and then commit it: the
  overflow panicked inside a write transaction and skipped the
  connection's own cleanup. The last epoch has no successor, so a commit
  from it is refused as stale.

  A dual-stack listener hands an IPv4 peer over as `::ffff:a.b.c.d`, and
  loopback detection, the trusted-proxy list and ban matching all used
  the address as it arrived: a loopback front was not recognised as
  trusted, so every client behind it shared one address's connection
  cap, and `ban 1.2.3.4` did not match the mapped form. Addresses are
  canonicalised before any of those comparisons.

  Serde's parse errors quote the offending input with its JSON escapes
  already decoded, and the relay logged them, so anyone who could open a
  socket could write a line of their choosing into a text-format log
  before authenticating. The log gets the kind of error and where it
  was; the client still gets the detail, which is its own input.

  An envelope id was whatever the sender put there, though it becomes a
  key in the store and reaches the recipient's client and log; it now
  follows the rule every message id follows, on `send` and on `ack`. A
  blob chunk is charged at least a kilobyte against the uploading
  address's budget, so a client cannot fill the store with zero-byte
  chunks no byte budget notices. `--lookups-per-minute 0` turns lookups
  off rather than allowing one a minute. The startup line reports the
  invite policy in force rather than the one the command line asked for,
  since an operator can change it at runtime. `--message-ttl-days`
  saturates instead of panicking on a number that overflows. And the
  data directory is made private only when the relay creates it, so
  `--data-dir .` no longer chmods the working directory.

  The threat model now also states, next to the journal's pseudonyms,
  that the transparency log keeps the time of every publish and serves it
  to anyone — a per-identity activity timeline that is inherent to the
  log being auditable.

- **A commit is framed and sealed before anything moves** (finding
  SM-P-05, Medium, and one more the review did not name). Committing went:
  ask the relay's sequencer, merge the commit, then frame it into a body
  and seal it to each member. Both of the last two steps can fail, and by
  then the sequencer had moved to the next epoch — so every other member's
  next commit was refused as stale, waiting for a commit that no one ever
  received, and the committer's own state reverted on restart. The group
  was wedged with no way back but to make it anew.

  Two things could make it fail. The inline threshold allowed a message of
  24 576 bytes, but the body is JSON with the message base64 inside it,
  padded to 160-byte steps, under a cap applied after the padding, so
  anything past about 24 411 bytes does not encode; a joiner has some say
  over the size of the commit that adds it, through its device name and
  its capabilities. And a member whose leaf carried a small-order X25519
  sealing key made the sealing fail for everyone — one member able to stop
  the whole group from sending, which the review did not name and which
  turned up while checking the first.

  Framing and sealing now happen while the commit is staged, before the
  sequencer is asked and before the commit is merged, so a failure is a
  staged commit that the caller discards and nothing else. The threshold
  is 24 360 bytes, which encodes for every kind of body, and a test says
  so; a reader still takes any inline message the body cap allows, so a
  sender with the older threshold is not cut off. A leaf whose sealing key
  is of small order is refused where leaves are read, so such a member
  never joins.

- **A rename gives a device a new certificate, not a second reading of
  the old one** (finding SM-P-07, Low). The device list's signature and
  its transparency leaf cover each entry's id and the time it was
  certified, not the name; renaming re-certified under the old time, so
  the old and the new certificate were interchangeable under both and a
  relay could serve either for the same signed list. A rename now carries
  a later time, which the signature and the leaf follow, and the
  specification says what the signature actually covers.

- **A provisioning message carries what fits** (finding SM-P-11,
  Informational). The sealing function allows an 8 MiB plaintext, but the
  message rides inside a plain body inside a ratchet body, each base64
  and each under the 32 KiB body cap, so what fits is some 18 to 24 KB —
  and the message carried every device revocation the account had ever
  issued. An account with a long history would eventually have been
  unable to link a device at all. It carries the newest sixteen; the rest
  reach the device with the next list its primary publishes, and the
  specification states the real limit rather than the unreachable one.

- **Decapsulation is fuzzed** (finding SM-P-13, Informational). The
  ML-KEM implementation and the group ciphersuite's hybrid on top of it
  both come from crates that state they have never been independently
  audited. The hybrid construction is what bounds that — a flaw in the
  ML-KEM half cannot take a session below its classical strength — but a
  flaw could still panic on a ciphertext someone chose, and decapsulation
  is reachable from the wire on every handshake and every post-quantum
  ratchet step. A `pq` fuzz target now exercises it with crafted
  ciphertexts and with real ones damaged, in CI with the rest; the threat
  model and the assessment say what the dependency costs and what the
  intended replacement is.

- **A group is not wedged by a leave, a refresh, or a commit that will
  not stage** (finding SM-G-03, Medium). Three ways one honest client
  broke a group and another honest client took the blame. A member's own
  Remove — the way one leaves — was refused in anyone else's commit, but
  OpenMLS's builder consumes the stored proposal queue by default, so a
  leaver's proposal rode along in whichever member self-updated next and
  every reader saw a non-admin removing a member. A member's own Remove
  is now accepted from any committer, and a non-admin's refresh leaves
  the queue alone: committing a leave is an admin's job. An admin that
  left was still named in the extension until an admin's commit took it
  out, while the rule "every admin is a member" was checked on every
  commit between — so the co-admin's next refresh broke the group;
  an admin whose every leaf left by its own proposal is now exempt. And a
  handshake at or above this client's epoch that will not stage means the
  group has moved on without it: it marks itself out of sync and starts
  the recovery that already exists, instead of refusing the message,
  saying nothing, and staying behind for good.

- **A commit is answered for by whoever made it** (finding SM-G-04,
  Medium). The committer's own new leaf — the one in the update path —
  went through none of the checks an added leaf goes through, so a member
  could self-update to a leaf with no sealing key or to a credential
  naming another identity it holds. The first wedged the group: every
  later read of the tree failed, and since that failure surfaced when the
  *next* commit was processed, the client that broke it was not the one
  named. Both the update-path leaf and any an Update proposal carries are
  now verified as an added leaf is, and must still name the account and
  device they named before; a tree that cannot be read after a merge
  marks the group broken by the committer of that commit.

- **An invitation costs what it costs and no more** (finding SM-G-05,
  Medium). A Welcome needs no permission from the person it invites and
  the last-resort key package is reusable, so a stranger could send as
  many as it liked for group ids it invented, each a full MLS tree on
  disk. At most twenty invitations now wait for an answer at once.
  Beyond `into_group`, where OpenMLS has already written the tree, any
  failure deletes that storage rather than leaving entries behind with no
  record naming them.

- **An admin by someone else's word does no admin's work by itself**
  (finding SM-G-06, Medium). A Welcome's group extension is written by
  whoever built the Welcome, so "you are an admin here" is the inviter's
  claim, not the group's. A hostile contact could hand somebody a group
  in which they were an admin and then drive their client: every join
  request answered with a commit and a Welcome sealed to every member,
  every "I am out of sync" answered the same way. In such a group the
  client now does an admin's automatic work only when the user asks for
  it; and everywhere, a member that stays out of sync is answered at most
  four times an hour.

- **A device is told whose account it is about to join** (finding
  SM-G-07, Medium). The link a new device prints carries a key and a
  device id but not an account, so whoever saw the QR code within its ten
  minutes could answer it with an account of their own: the certificate
  is signed by their key, every check passes, and the device joins them —
  every message typed on it going to their account, while the real
  primary is told the device belongs to an account already. Only the
  person holding both machines can tell the two apart, so the device now
  shows the account offered and asks before taking it. `silver --link
  --account <id>` answers in advance for a run nobody is sitting at, and
  with no terminal to ask the answer is no; a refusal leaves the link
  standing until it expires.

- **A member cannot fill the tree with devices** (finding SM-G-08,
  Medium). A group was capped at 256 members, counted as identities, and
  a member could certify devices of its own at will — so one member could
  add leaves until every message cost every other member hundreds of
  sealed envelopes. A commit is now refused if it leaves any identity
  with more than the nine leaves an account may link, or the tree with
  more than 256 × 9 in all.

- **The two ways back from a lost sequencer entry are wired to the
  client** (finding SM-G-09, Low). The engine could re-create an entry
  the relay had lost and could catch up an entry restored behind the
  group, and nothing called either: the answer to both was "the group
  moved on, try again", for ever. `not_found` now puts the entry back at
  the group's own epoch, and `stale` with an epoch behind the group
  replays the tokens the client kept until the entry catches up.

- **A Welcome is read before anything is given up** (finding SM-G-10,
  Low). A body that was not a Welcome at all was enough to drop an
  out-of-sync member's group state — which might still have recovered
  from held messages — and a group id is known to anyone who was ever in
  the group or held an invite link. The Welcome is parsed first, so
  nonsense costs nothing.

- **A rejoin does not eventually stop the deposit** (finding SM-G-11,
  Low). Join and rejoin requests each make a key package of their own and
  added it to the same list the client deposits, and the relay refuses an
  oversized deposit whole — so a member who drove a victim out of sync a
  dozen times left it depositing nothing at all until the surplus expired,
  up to ninety days later. The list is trimmed to what a deposit may
  hold before every deposit, oldest first, their secrets deleted with
  them.

- **Group state is written whatever happened** (finding SM-G-12, Low). A
  commit merged or a message key consumed, and then something after it
  failing, left the MLS state advanced in memory and not on disk: a crash
  then restored a state before the commit, or one in which a ciphertext
  already read would decrypt again. Everything received is persisted on
  the way out, success or failure.

- **Smaller group and device items** (finding SM-G-13, Informational).
  The sender ratchet was left at OpenMLS's default tolerance of five
  generations while the design note said 64, so messages from one sender
  that overtook each other by more than five were reported unreadable —
  a mailbox drains in whatever order it was filled. It is 64, on the
  groups this client makes and the ones it is invited to alike.

  A linked device could pin a contact's keys and mark them verified on
  its siblings through `sync contact`, and that stood after the device
  was unlinked. Both are trust the user placed in the device as much as
  in the contact, so each is now remembered against the device that sent
  it and undone when that device is unlinked: the pin dropped, so the
  next lookup pins afresh and any change is reported, and the verified
  mark cleared, so the safety numbers want comparing again. What each
  device pinned and verified itself is untouched.

  An invite link's "not already a member" was checked per device rather
  than per identity, though a member's further devices are put in the
  group by their own primary; and one link had no use bound, so it could
  add up to 256 identities, each costing the admin a commit and a Welcome
  to everyone. The check is per identity, as the specification always
  said, and an admin answers at most 32 asks for one invite key before
  saying the link wants resetting.

  A gossiped transparency log head was taken from any group message,
  including one in an invitation nobody had accepted and one from a
  blocked member — and comparing a head can tell the user their relay is
  showing two views of the log. A head now counts only from a group the
  user is actually in and a sender they have not blocked.

- **The compiler is pinned, and the release says which one** (finding
  SM-S-02, Low). `rust-toolchain.toml` said `channel = "stable"` and every
  workflow asked for "stable" explicitly, which overrides the file. Both
  float: a rebuild of a tagged commit a month later uses a different rustc
  and produces different bytes, and the reproducibility job compares two
  builds on the same runner minutes apart, which never notices. The file
  pins an exact version, one small local action installs what the file
  says everywhere, and each release carries a `BUILD-INFO.txt` naming the
  compiler, the commit, the flags and the timestamp — so a verifier reads
  the compiler off the tag instead of out of workflow logs that expire.

- **The installer is a release asset, and defaults to no public plaintext
  port** (finding SM-S-03, Low). It was documented as `curl … | bash` of a
  script from a branch, which is neither pinned nor checkable; it is now
  published with each release and listed in `SHA256SUMS`, and the README
  says to check it before running it as root. Four more: without
  `SILVER_DOMAIN` the listener is `127.0.0.1:7777` rather than
  `0.0.0.0:7777`, since a public port with no TLS should not be something
  anyone gets by accident (`SILVER_ALLOW_PLAINTEXT=1` is the opt-in for a
  relay behind a TLS front of your own); Rust is installed from
  `rustup-init` on the Rust project's own host, checked against the
  SHA-256 published next to it, instead of piping `sh.rustup.rs` into a
  shell; the public address printed at the end is the machine's own rather
  than one fetched from a third party, which would have told that third
  party the host runs a relay (`SILVER_PUBLIC_IP` says it outright behind
  NAT); and the environment file is edited with awk rather than a `sed`
  expression the operator's own domain could break.

- **The deploy workflow knows the server's host key in advance** (finding
  SM-S-04, Low). It ran `ssh-keyscan` on every run, which is trust on
  first use every run: whoever is on the path between GitHub's runners
  and the server could answer with a key of their own and take the deploy
  session. The key goes in the repository variable `VPS_HOST_KEY`, read
  once from somewhere trusted; without it the deploy stops and says how
  to get it.

- **Container images are pinned by digest** (finding SM-S-05, Low). The
  relay's base images and the two containers CI runs the Debian and Arch
  package checks in were named by tag, and a tag can be moved — so "a
  rebuild of the same release gives the same layers" held only while the
  tags did. All four carry a `@sha256:` digest now, moved by hand like
  the action pins. The Rust image also follows the pinned compiler.

- **The systemd unit carries the rest of the usual hardening** (finding
  SM-S-06, Informational). `UMask=0077`, `SystemCallFilter=@system-service`
  with `SystemCallErrorNumber=EPERM`, `ProtectClock`, `ProtectHostname`,
  `ProtectProc=invisible`, `ProcSubset=pid`, `RestrictRealtime`,
  `RestrictSUIDSGID` and `RemoveIPC`. The relay also shuts the directory
  holding its admin socket to 0700 before binding, which closes the moment
  between `bind` and the `chmod` after it wherever the relay runs, not
  only where the unit sets the umask.

- **Fuzzing keeps what it finds** (finding SM-S-08, Informational). Each
  target ran for a minute from an empty corpus on every push, and the
  corpus was thrown away; a minute from nothing explores very little. Each
  target's corpus is now carried between runs, so every run starts from
  what the last one found, and a weekly run gives each target half an
  hour. A new `identifier` target covers the base58 and JSON identifier
  path with inputs as large as the relay accepts, which is where SM-P-02
  was.

- **Release notes are the changelog, and nothing generated** (finding
  SM-S-09, Informational). GitHub's auto-generated notes list pull request
  titles written by whoever opened them, which reached every reader of a
  release page unreviewed; the notes are now the tag's changelog section
  alone. `packaging/update.sh` decides by `SHA256SUMS` what the Homebrew
  formula, the PKGBUILD and the winget manifests install, so it checks
  that file's minisign signature before reading it whenever the release
  is signed and the checkout has the key.

- **What a release signature is worth, said plainly** (findings SM-S-01,
  Medium, and SM-S-07, Informational). The threat model claimed a
  maintainer's signature that leaves "a compromised GitHub account
  without the signing key nothing to offer". No `minisign.pub` is
  published, so every release so far is unsigned by the maintainer; and
  the setup the README described puts the key in a repository secret,
  where the build already lives, which is not independent of GitHub at
  all. The README, the threat model, the security policy, the ASVS
  assessment and the distribution note now say what exists (GitHub's
  provenance attestation on every file), what a workflow-held key would
  and would not add, and what signing on a maintainer's own machine
  would. The threat model also records what the dependency tree carries:
  no known vulnerability, one unmaintained build-time macro crate that is
  not in the binary, and several dependencies present in two major
  versions because upstreams have not converged.

## 0.10.1 - 2026-09-06

An independent security review of the 0.10.0 line reported 76 findings.
The report is published whole as
[docs/audits/2026-09-security-audit.md](docs/audits/2026-09-security-audit.md),
and what was found when each finding was checked against the code, what
is done about it and in which release are in
[docs/design/audit-response.md](docs/design/audit-response.md). This
release carries the one Critical finding, all ten High ones, and the
Mediums that share their code. Nothing on the wire changes: every fix is
a stricter reader, a stricter relay, or a client that refuses what the
protocol already said it refuses. A 0.10.1 client works with a 0.10.0
relay and the other way round, with the exceptions the response note
lists in its section 5; **relay operators should upgrade**, since one of
these lets any identity that can register destroy any other identity's
account. [UPGRADING.md](docs/UPGRADING.md) says what an operator has to
set. The remaining findings are for 0.11.0 and, where they need a
format change, for 1.0.

### Security

- **A device revocation is bound to the device it is about** (findings
  SM-R-01, Critical, and SM-P-01, High). A device revocation is signed
  by an account, and that signature proves only that some key signed
  about some id. The relay took one for any id on the revoking account's
  own device list, and cut that id off for good: its mailbox and prekeys
  dropped, its logins, publishes and incoming mail refused, with no way
  back. Anyone who could register could therefore destroy any other
  identity's account on that relay by publishing a list naming it and
  revoking it, and, because clients acted on a revocation by device id
  alone, that identity's contacts dropped their sessions with it too.

  The relay now takes a statement only for a key whose own published
  bundle carries that account's certificate, or one on the list that has
  published nothing at all, and what a statement does is bound to the
  same claim: a login, a publish or a delivery is refused only while the
  id's bundle carries the certificate of the account that revoked it. A
  statement stored by an older relay refuses nothing, and
  `silver-relay admin unrevoke-device <who>` drops it. Clients act on a
  revocation only for a device they already know as that account's,
  wherever it came from, and no longer take a lookup of such an id to be
  a relay withholding an identity revocation. Protocol sections 14.2 and
  14.3 say the rules; the threat model says what a stranger cannot do.

- **A bound login is checked against the relay's own names** (findings
  SM-R-02, High, and SM-C-04, Medium). The login signs the relay's host
  so that a relay in the middle cannot forward another relay's challenge
  and use the answer there. The receiving relay compared the signed name
  with the `Host` header of the request, which whoever connects writes,
  so the attacker's own name matched on both sides and the login
  travelled: a hostile relay could read, acknowledge and delete its
  users' mail at the real relay. It now compares with the names it is
  configured with (the ACME domains, the names in `--tls-cert`, and
  `--host`), and says at start which they are, or that it knows none and
  has only the header to go by. Operators behind a TLS front, on an onion
  address, or reached by a bare address give `--host`; the installer
  writes it.

  The client no longer answers the older login, which signs the challenge
  without a name and is therefore worth the same at any relay, unless it
  is started with `--allow-unbound-login`. Only relays from before 0.6.0
  ask for it.

- **The relay's bounds cover the frames and the connections they
  missed** (findings SM-R-03 to SM-R-06). Four gaps, all of them ways to
  make a relay work for nothing:

  A connection was counted, timed and rate-limited only from the
  WebSocket upgrade on. Before that it was an HTTP request with no
  timeout at all, because the server builders install no timer and the
  library then discards its own default, so a connection that sent half a
  request line held a socket and a task until the process ran out of file
  descriptors, below every limit the relay counts. Both listeners now set
  a timer and give a request ten seconds to arrive.

  An envelope was stored for any recipient id, whether or not anyone had
  ever registered it, and there was no cap on queued mail across
  mailboxes. One anonymous connection could therefore write to the disk
  until it was full, with nothing to acknowledge the mail and nothing to
  free it before the message lifetime ran out. An envelope to an
  identity the relay holds no bundle for is now refused `not_found`, and
  `--mailbox-storage-mib` (4 GiB by default) caps what every mailbox
  holds together.

  `publish` and `ack` had no rate limit. A publish verifies a bundle's
  worth of signatures, makes three durable writes and appends a
  transparency-log entry that is never pruned; an ack was a durable write
  even for an id the relay had never heard of. Both have a budget now,
  sized well above what a client does, and an ack for somebody else's
  mail is answered from a read.

- **Protecting a data directory moves every file, and writes the key
  first** (findings SM-C-02, High, and SM-C-08, Medium). The
  re-encryption walked a list of ten file names that had not kept up with
  the store: `groups.json`, `groups.mls` and `revocation.json` were not
  on it, and neither were downloads kept encrypted. Adding protection to
  an existing directory therefore left the MLS epoch secrets, leaf
  private keys and key packages of every group lying in plaintext on a
  directory the client called protected, and taking protection off left
  those three files encrypted under a key that no longer existed, so
  every group became unreadable. The list now lives in one place, shared
  with the wipe, and a test protects and unprotects a directory holding
  one of everything.

  The vault, which holds the only copy of the data key, is now written
  before the files are encrypted under it rather than after. A crash or
  an error part-way through (the protection runs by itself on the first
  start on a machine with a key store) used to leave files nobody could
  ever read again; now the directory opens, and the next unlock seals
  whatever was left in the clear. A directory that was unprotected by
  0.10.0 or earlier cannot be recovered by this: those three files are
  still ciphertext under a key that is gone.

- **A relay pin names the relay's own certificate** (finding SM-C-01,
  High). A pin matched any certificate the server sent, not only the one
  it proves it holds the key for. Since the relay's certificate is public
  (`--print-pin` fetches it, and so can anyone), a proxy inspecting TLS
  could present its own leaf, validated through the root it installed,
  append the relay's certificate to the chain, and pass the pin on
  precisely the connection a pin exists to refuse. The pin is now matched
  against the end-entity certificate alone, which is the first one
  `--print-pin` prints and the one the README's `openssl` recipe
  computes. Anyone who pinned an issuer key from further down the chain
  has to pin the relay's own key instead.

- **An identifier is measured before it is decoded** (findings SM-P-02,
  High, and SM-C-17, Low). Base58 decoding is a big-integer conversion
  whose cost grows with the square of the input, and user and group ids
  were decoded from frame fields before any length check: on the relay
  that happens before the rate limits and before authentication, so a
  single 128 KiB frame of base58 characters cost about four and a half
  seconds of one core, and a handful of connections could keep a small
  relay busy. Text longer than the 44 characters an id can take is now
  refused without being decoded, in ids and in the secrets an invite or
  device link carries. The client also caps what it will read from a
  relay in one WebSocket message, where the library's 64 MiB default
  stood before, and refuses a blob chunk larger than a chunk can be.

- **A refused answer stops the send, and nothing goes out without
  forward secrecy** (findings SM-C-06 and SM-C-03, both Medium). When
  the transparency log said the relay was serving something other than
  what it logged, or withholding a statement it had logged, the client
  reported the refusal, told the user nothing was sent, and then sent the
  message under the bundle it already held. The one case that matters
  most is the one it got wrong: the log holds a contact's revocation, the
  relay withholds it, and the message goes to the revoked key. A refusal
  now fails the send that asked for the lookup. A revocation or a
  succession inside a refused answer is signed by its own subject, so one
  that verifies is raised to the user even though the answer around it
  was thrown away.

  Sending to a contact whose bundle carries no forward-secrecy keys is
  refused, as protocol section 8 has said since 0.8.0 that it would be:
  the plain v1 body it used to fall back to has no forward secrecy and no
  deniability, and stays readable ever after by whoever holds the
  recipient's identity key. Because prekeys are optional, a bundle with
  them taken out carries just as good a signature as one with them, so a
  relay could bring the fallback about at will; a client that already
  holds prekeys for that contact now keeps them, says the relay is
  serving the contact without, and starts the session from the keys it
  knows. A contact still running a client from before 0.3.0, or one built
  without a session store, has to update before they can be written to;
  their own messages are still read.

- **A received file is opened where the download put it, not where a
  message says** (finding SM-C-12, Medium). Which file a line stands for
  was recomputed at every load by reading the line's *text* for
  `[file] name (size) → /path`. A contact writes that text, so after a
  restart a message reading
  `[file] notes.txt (1 KiB) → /home/you/.local/share/silver-messenger/identity.json`
  became a line the client offered to open: `/open` would read the file,
  recognise the data directory's own encryption, decrypt it under the
  data key and put the plaintext where the opener could reach it, and
  `/files decrypt` would write a permanent plain copy into `downloads/`.
  Where a file went is now recorded by the download that wrote it and
  kept with the history entry as data; a path parsed out of an older
  line's text counts only if it is inside the downloads directory. On
  top of that, `/open` and `/files decrypt` resolve the path and refuse
  anything outside `downloads/`, whatever named it.

- **A parked group message costs the group what it carries, once**
  (finding SM-G-01, High). An MLS message too large for its envelope is
  parked in the blob store, and every member fetches it. Nothing bounded
  that: the reference could name up to the file limit of 16 MiB
  whatever kind of message it was, the client fetched every parked body
  it was told about (deduplicating by envelope id, so the same blob
  again per envelope), for any group id, from anyone; and a handshake
  whose plaintext header claimed a future epoch was held verbatim,
  bounded by count and time but not by size, then written into
  `groups.json` on every later group event. One member could therefore
  make every other member download 16 MiB per envelope and rewrite
  hundreds of megabytes to disk for ten minutes, without anything of it
  being read, let alone authenticated.

  A parked `welcome` or `handshake` is now capped at 1 MiB, which is
  well above the largest either can be (a commit adding 255 members is
  about 695 KiB), and every other kind at 64 KiB, none of which has any
  reason to be parked; a body naming a larger one is refused as
  malformed. A blob is fetched once, whatever names it, and only for a
  group this client is in or as a Welcome. Only a handshake that
  travelled inside its envelope is held, within 384 KiB per group as
  well as the count and the ten minutes; a parked one from a future
  epoch puts the group out of sync, which rejoins, rather than being
  kept.

- **A newly linked device joins a promised group only on its own
  account's word** (finding SM-G-02, High). When a device is linked, the
  primary tells it which groups it will be put in, and a Welcome for one
  of those was taken without asking whoever sent it. The admin check
  before it is no help: it reads the admin list inside the Welcome,
  which whoever built the Welcome wrote. A group id is known to anyone
  who ever held an invite link or was once a member, and the device's id
  is public in the account's device list, so a former member could race
  the primary and place the new device in a group of their own making,
  under the real group's name and alias — and the primary's real Welcome
  was then refused as "a Welcome to a group we are in".

  Only the account's own identity now fills the promise; a Welcome from
  anyone else is an ordinary invitation, waiting for the user under the
  name its own author gave, and what the primary promised stays
  promised. A second Welcome for a group already joined or already
  inviting is refused rather than replacing it, since reading it would
  mean throwing away a group already joined on the word of whoever sent
  the second; declining the invitation makes room.

## 0.10.0 - 2026-09-05

Phase 10 of the roadmap: what people expect of a messenger in daily use,
without a single new thing for the relay to see (replies, reactions,
edits, deletions, disappearing messages, encrypted downloads, a history
export); a reader mode for screen readers, a high-contrast palette and
every action without the mouse; a client that leaves the terminal
usable after a panic, a store that survives a kill, memory that stays
flat, and a soak test; packages for Debian, Homebrew, Arch and winget
built from the same release; and a contributor guide and a FAQ. Nothing
changes for a relay; see UPGRADING.md.

### Added

- **Replies, reactions, edits and deletions.** `/reply <text>` answers
  a message, quoted on every reader's screen from that reader's own
  copy, so a reply cannot misquote; `/react <emoji>` puts a reaction
  under a message and `/react none` takes it back; `/edit <text>`
  replaces the text of one of your messages within a day of sending,
  marked as edited, the history keeping every version; `/delete`
  removes one of your messages for everyone within a day, leaving a
  placeholder on every screen, and `/delete me` removes any message
  from your devices only. Each acts on the message selected with
  Shift-Up (or a triple click), else on the last one it makes sense
  for, and the status line names the selected message. Only the
  author's edits and deletions apply, checked against the sealed sender
  (the MLS sender in a group), and one that arrives before its message
  waits a day for it. All of it is content inside the encrypted body
  (protocol section 4.7), padded like any other, so the relay cannot
  tell a reaction from a receipt or a deletion from a short message; a
  contact whose client is older is never sent a kind it would not read,
  and the client says what they will not see. In groups the kinds go
  only when every member's leaf declares the new capability (13.1,
  13.3); otherwise the client names the members whose clients are older
  and sends nothing.
- **Disappearing messages.** `/timer 1d` (30s to 1w, or off) makes
  messages in a conversation go that long after you send them, or after
  the other side reads them, on every device on its own clock; a note
  says who set it, lines carry an hourglass while they have a timer,
  and the status line says how long a selected message has left. In a
  group the timer is an admin's word, told to a newcomer as they join.
  What ran out is rewritten out of the history, not marked. Towards a
  contact whose client is older the timer is set on this side alone,
  and the client says so. The threat model says exactly what a timer
  and a deletion promise: the other side's software keeps them, not
  cryptography.
- **Encrypted downloads.** `/files encrypt on`, where the data directory
  is protected, writes received files under the data key, so
  `downloads/` holds ciphertext like the rest; `/open` decrypts a
  private copy for the opener, removed at exit and at the next start,
  and `/files decrypt` writes a plain copy beside the file. Off by
  default.
- **History export.** `silver --export-history <dir>` writes every
  conversation to a file of its own, as text or, with `--format json`,
  as JSON lines with every field the history keeps; deleted and expired
  messages are not there, and nothing is overwritten.
- **Sync between devices** gains the moment a message was read, so a
  timer starts from the same instant on every device, and a `remove`
  kind by which a device tells its siblings what it deleted for itself
  (protocol 14.5).
- **Reader mode, for a screen reader.** `silver --reader` (`/reader on`
  remembers it, `SILVER_READER=1` too) runs the client as a
  line-at-a-time program: no alternate screen, no box drawing, no
  colours or attributes, no mouse, no window title. Every event is one
  line at the bottom of the terminal's own scrollback (`alice: hello`,
  `alice, in team: hello` when that chat is not open, `you: …`, `alice
  edited: …`, `alice deleted a message`, `alice reacted 👍 to: …`, a
  note's text, every notice and toast), and the compose line stays last
  with its prompt naming the open chat. Switching chats reads what is
  unread there or the last three lines; `Shift-Up` and `Shift-Down`
  select a message and say it; `/history [n]` reads the last lines back
  with their times; `/unread` says what waits where; `F1` prints the
  help as lines. Control characters in a message become spaces before a
  line is printed. The pty suite runs a reader-mode client and checks
  the bytes it writes. What needs a screen reader to check is a manual
  protocol in TERMINALS.md, unchecked until someone runs it.
- **Every action without the mouse, and a high-contrast palette.**
  `/go <name>` opens a chat by name and `/sidebar <columns>` resizes the
  chat list (remembered), the two things only the mouse could do;
  `/theme contrast` (`--theme contrast`) is bright bold text on black
  with every colour pair at high contrast, for low vision. Accepting a
  contact request opens the chat straight away rather than passing
  through System.
- **Client robustness.** A panic leaves the terminal usable: one hook
  undoes exactly what the client set up (the mouse, the paste and focus
  reports, the title, the alternate screen, raw mode) before the message
  prints, in the full mode and in reader mode alike. A crash or a kill
  leaves a store that opens: every whole-file write is synced before it
  is renamed into place, and a history line cut short by a crash no
  longer swallows the line appended after it; a kill test in
  `silver-client` runs a writer child, kills it at random moments and
  checks the store it left, on every platform CI tests. Memory stays
  flat: a conversation keeps its newest two thousand lines in memory
  (the file keeps all of them, the chat's title says so, and `/search`
  reads the files, groups included now), the System pane its newest
  five hundred, and the updates waiting for a message are capped. A
  soak test (`tests/tui/soak.py`) exchanges messages for as long as it
  is told and checks each process's memory is flat; CI runs three
  minutes of it on every push, and the workflow can be dispatched for
  up to six hours.
- **Distribution.** Every channel installs the bytes the release
  publishes, by checksum: a Homebrew tap in this repository (`brew tap
  iamforeveralonetoo/silver <repository url>`, then `brew install
  silver-messenger`, on macOS and Linux); a Debian package per
  architecture built in the release workflow from the Linux archives,
  attached beside them, in `SHA256SUMS` and attested, which installs
  both binaries and the relay's unit (not enabled); a PKGBUILD for Arch
  (`silver-messenger-bin`, in `packaging/aur/`, for the AUR once
  published); and winget manifests (`packaging/winget/`, for
  `winget-pkgs` once submitted). `packaging/update.sh` rewrites them all
  for a release from its `SHA256SUMS`, and the release attaches the
  result as an archive. The release workflow signs the Windows
  executables (Authenticode) and signs and notarises the macOS ones
  when the repository holds the secrets, and says so when it does not;
  README says how to compare a signed download with a rebuild. CI
  builds, lints and installs the Debian package, checks the PKGBUILD
  and its `.SRCINFO`, validates the manifests against Microsoft's
  schemas, and taps, audits, installs and tests the formula on macOS.
- **A contributor guide and a FAQ.** `CONTRIBUTING.md` says how to
  build, which checks a change must pass, how a change is proposed
  (an issue or a design note first when it decides something, one
  change per pull request with its tests and its documents), and what
  the code holds to. `docs/FAQ.md` answers, in short, the questions
  people ask first: what a relay is and who runs one, what the relay
  sees, how to know you are talking to the right person, what "secure"
  means here and what it does not, lost laptops, several computers,
  phones, forgotten passphrases, disappearing messages, files, backups,
  updates and where to report a problem.

### Changed

- The history file gains update lines (`read`, `edit`, `react`, `gone`)
  after the entries and is rewritten, atomically, when a message is
  removed for good; a client on 0.9.0 skips the lines it does not know
  and shows the rest. Every body from 0.10.0 advertises the `edits`,
  `reactions` and `timers` capabilities; every key package and leaf
  declares the private-use leaf capability `0xF003`, and a leaf that
  does not is refreshed at once.

## 0.9.0 - 2026-09-05

Phase 9 of the roadmap: more than two people, more than one device.
Groups run on MLS with a post-quantum hybrid suite, the relay as a dumb
delivery service and every member's client checking every change; one
identity runs on several devices, each with keys of its own certified by
the identity key, every message reaching every device, and a linked
device revocable without touching what contacts verified. The relay's
schema moves to 3 and its backup format to 2; see UPGRADING.md before
upgrading a relay.

### Added

- **Groups on MLS.** `/group new <name>` makes a group; `/group add
  <contact>` adds people, `/group invite` prints a link and a QR code
  anyone can ask to join by, and a group is a pane after the contacts
  with each line naming its writer. Groups run on MLS (RFC 9420, through
  OpenMLS) on the hybrid `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519`
  suite, so their key agreement is post-quantum like the one-to-one
  handshake; each member's leaf is signed by their identity key and
  carries their sealing key, and a group message is one MLS ciphertext
  sealed separately to every member into the ordinary envelope, so the
  relay sees envelopes to people and no group and keeps no membership
  list. Admins add and remove members, appoint admins, rename the group
  and reset its invite link; anyone may leave; every member's client
  checks every change against the group's rules and marks the group
  broken rather than accept a change that breaks them. An invitation
  from a contact is taken at once; one from a stranger waits in the
  Requests pane for `/accept g<n>` or `/decline g<n>`; the answer to a
  join by link needs no second yes. Files go to groups as to contacts;
  members refresh their keys weekly; a member that misses a change asks
  the admins to re-add it. One-to-one conversations stay on the Double
  Ratchet. Group messages are signed inside MLS and are not deniable,
  which the threat model records along with what the relay can still
  infer (a group's size and membership from delivery bursts, and when
  its epoch moves). Needs a relay on 0.9.0; `/group` says so on an
  older one. Protocol section 13, the threat model, and the design note
  `docs/design/groups.md` have the details.
- **Relay: key packages and the group epoch sequencer.** The relay keeps
  each identity's MLS key packages on deposit and hands them out like
  one-time prekeys (a last-resort one when the deposit runs dry), and
  keeps one epoch counter and one token hash per group, which orders
  the group's commits and says nothing else about it; both work on any
  relay from 0.9.0 with no switch, `--max-groups` caps the entries, idle
  ones go after 180 days, and four new metrics report on them. **The
  schema moves to 3 and the backup format to 2**: 0.8.0 refuses both,
  so take a backup before upgrading and read UPGRADING.md.
- **Protocol: the group body (v5).** A body version for one MLS message
  to one member, unsigned at the sealed layer like v4, with an MLS
  message that does not fit an envelope parked in the blob store; two
  private-use MLS extensions for the group's metadata and the members'
  sealing keys; the `groups` relay feature and bundle capability; the
  key package and sequencer frames. Vectors, property tests and a fuzz
  target cover the new encodings.
- **Multiple devices.** One identity on several computers. The identity
  key stays where it was made, the primary; every other device has keys
  of its own and a certificate signed by the identity key, listed in the
  account's bundle and signed there as a whole, so contacts learn a
  person's devices from the person's own word and a relay cannot add
  one. To link a computer, run `silver --link` on it (or say yes to the
  first-run prompt): it prints a link and a QR code, and `/devices link
  <link> [days]` on the primary certifies it, sends it the contacts, the
  groups and the last thirty days of history as a snapshot through the
  relay, sealed under a one-time secret only that computer holds, and
  adds it to every group. From then on a message to a contact goes to
  every device of theirs and a copy to every device of your own, each
  under its own forward-secret session and all under one id, so every
  device shows the same conversation, what one device sends the others
  show as sent, what one reads the others stop counting unread, and a
  contact added, renamed, verified or blocked on one is so on all. In
  groups each device is a leaf of its own. `/devices` lists them,
  `/devices remove <n>` revokes one (the relay cuts it off, contacts
  drop it, its group leaves go), `/devices name <n> <name>` renames one,
  and `/devices leave confirm` on a linked device erases it. Contacts
  verify the person, never a device: the safety number and the id are
  the identity's, and a linked device's loss costs what it held and
  nothing a contact must re-check. A contact on 0.8.0 keeps working (the
  primary passes their messages on); linking needs a relay on 0.9.0. At
  most eight devices per identity; history is not synced after the link.
  Protocol section 14, the threat model, and `docs/design/devices.md`
  have the details.
- **Relay: devices.** The relay keeps the device list and the device
  certificate in bundles, checks a device's claim to its account when
  it publishes, hands a client the linked devices' bundles with the
  account's (one prekey each), takes `revoke_device` from the account
  and cuts the device off (its connection closed, its mailbox and
  deposits dropped, its logins and envelopes for it refused), and logs
  the revocation in the transparency log under the device. A linked
  device is one more identity to the relay, against the same caps and
  invite token; two metrics count devices and revocations. No switch.
- **Protocol: devices.** Device certificates, the signed device list in
  the bundle and `device_of` on a device's bundle, device revocations
  and the `revoke_device` frame, the `device` and `id` body fields, the
  `sync`, `provision` and `device_revocation` content kinds, the
  `devices` capability and feature, the `silver_device` leaf extension
  (`0xF002`), the link and the provisioning seal, and the snapshot
  format. Vectors cover each statement, the link key, a provisioning
  message and the leaf bytes.

## 0.8.0 - 2026-09-05

Phase 8 of the roadmap: finishing the protocol. Every ratchet step is
post-quantum and every v4 message deniable, an identity can be revoked or
handed over, the relay keeps a transparency log that clients replay and
compare heads of inside their messages, the handshake and the ratchet are
modelled in Verifpal with published vectors and a harness that replays
them, and cover traffic is there for those who want it. The relay's
schema moves to 2; see UPGRADING.md before upgrading a relay.

### Added

- **Cover traffic, opt-in.** `/cover on` sends meaningless messages at
  random moments (every 30 seconds to three minutes) to contacts who have
  it on too, for ten minutes after each message from them, so two running
  clients cover each other while both are around and the relay cannot
  tell when they really talk or, for short and medium messages, which
  message is real. Cover is discarded on receipt without a trace, never
  queued while offline, and sent only to contacts whose last message
  advertised the new `cover` capability, so both sides have agreed to the
  cost (about 20 KB an hour per covered contact). It shows that the two
  are in contact and does not hide bursts, long messages, files, or
  connecting; it is off by default. Protocol section 4.6 and the threat
  model have the details.
- **Formal models and test vectors.** The handshake (v2 and v4) and the
  ratchet (v2 and v4) are modelled in Verifpal under `formal/`, against a
  classical, a quantum-capable and an active adversary and with a
  mid-conversation compromise; the outcome of every query is recorded in
  `formal/expected.txt`, the ones a model is meant to break included (the
  v4 handshake without its key-binding signature, a handshake without a
  one-time prekey under a later compromise, the v2 ratchet against an
  adversary that breaks X25519), and CI checks them on every push.
  Known-answer vectors for every operation live in `docs/vectors/`, with
  every intermediate value and the randomness fixed by a documented
  seeded generator; `cargo test` replays them and re-derives the
  intermediates from the byte layouts in `docs/PROTOCOL.md`. Property
  tests cover bodies, the sealed layer, sessions under random reordered
  schedules, statements, the transparency log and file chunks. Protocol
  section 12 says how to use the vectors and what the models leave out.
  For this, the protocol crate gained seeded variants of every operation
  that draws randomness (`initiate_with_rng`, `decrypt_with_rng`,
  `seal_bytes_with_rng` and friends, `from_seed` and `from_bytes`
  constructors); nothing on the wire changed.

- **Post-quantum ratchet (protocol v4).** When both clients advertise it
  (a signed `pq_ratchet` capability in the key bundle) and publish ML-KEM
  keys, a forward-secret session does an ML-KEM-768 step beside every
  Diffie–Hellman ratchet step, so healing after a compromise is
  post-quantum too, not only the handshake. The ratchet becomes
  post-quantum by itself once both peers are on 0.8.0 and the relay keeps
  the capability; otherwise the v2 ratchet is used, and `/session` says
  which. A relay older than 0.8.0 drops the capability, so the v4 ratchet
  needs a relay that keeps it.
- **Deniable messages (protocol v4).** A v4 session message carries no
  signature at the sealed-sender layer, so the recipient cannot prove to a
  third party who wrote it; the session's own authentication and the
  handshake's key-binding stand in for the signature. `/session` says
  whether a conversation's messages are deniable. The plain v1 body (sent
  only to peers with no prekeys) and v2 sessions stay signed; v1 is now
  scheduled for retirement: 0.8.0 and 0.9.0 still send it and warn, 0.10.0
  will refuse to.
- **Identity lifecycle: revoke and rotate.** `/revoke` retires an identity
  for good with a pre-signed revocation certificate, minted on first run
  and kept in the data directory and the encrypted backup so the key can be
  declared dead even after it is lost. `/rotate` moves to a fresh identity
  with a succession cross-signed by both the old and the new key, so
  contacts re-pin to the new key on their own without comparing safety
  numbers from scratch. Contacts learn from a copy pushed inside a message
  and from the relay, which serves the statements on lookup and refuses to
  publish a revoked identity ever again. A revocation is final: a revoked
  key cannot hand over, on the relay or in a contact's eyes. A revoked
  contact is marked as such and cannot be messaged; a succeeded contact is
  re-pinned and its conversation carried across. The relay keeps
  statements only for identities registered with it and counts each
  against the address's hourly registrations. Needs a relay on 0.8.0 (the
  `lifecycle` feature); older relays still carry the pushed copies. See
  protocol section 10.
- **Key transparency, small edition.** The relay keeps an append-only,
  hash-chained log of every key bundle change and lifecycle statement it
  serves, tells its head on login and with every lookup, and hands out the
  entries on request. The client replays the log, refuses a key the relay
  shows it that is not the latest one logged (a stale prekey, or one never
  logged) and a hidden revocation or handover, and carries the log head
  inside every encrypted message, so two contacts compare what the relay
  told each of them without reading numbers aloud: a relay that keeps two
  versions of its log is reported as a fork by the next message between
  them. `/log` shows where the log stands and where a contact appears in
  it. The relay's database schema moves to version 2, with the log seeded
  from what the relay already holds; a relay older than 0.8.0 refuses the
  database rather than serve changes it would not log. See protocol
  section 11 and UPGRADING.md.

## 0.7.0 - 2026-09-04

Phase 7 of the roadmap: running a relay well. The relay terminates TLS
itself, reports metrics, takes administration over a local socket, keeps
backups and a schema version, ships as a container image, and comes with
an operator's guide.

### Added

- **Built-in TLS.** The relay can terminate TLS itself: `--acme-domain`
  obtains a Let's Encrypt certificate (or one from any ACME certificate
  authority, `--acme-directory`) and renews it, proving control of the
  name over TLS on port 443 itself (TLS-ALPN-01), so no port 80 and no
  web server in front are needed; the account, the key and the
  certificate live under `acme/` in the data directory, readable by the
  relay's user only, and the key is kept across renewals so pinned
  clients keep working. `--tls-cert`/`--tls-key` serve a certificate from
  elsewhere and re-read the files when they change. The installer sets
  new installs up this way (`SILVER_DOMAIN`), keeps an existing Caddy
  front unless `SILVER_TLS=builtin` says to switch, and opens only port
  443. The ACME flow is tested end to end against Pebble in CI. The
  README says how to publish a relay as a Tor onion service.
- **Metrics and structured logs.** `silver-relay --metrics-listen`
  serves Prometheus metrics on a listener of its own, for loopback or a
  private network: connections and their cap, refusals by kind, failed
  logins in aggregate (the addresses stay out of the metrics; one that
  fails twenty times within an hour is named in a warning in the log),
  identities, queued messages, files on deposit against the cap, the
  certificate's expiry and failed renewals. `deploy/alerts.yml` carries
  alerting rules for the relay down, a certificate that will not renew,
  floods of failed logins or refused registrations, and a nearly full
  file store. `--log-format json` writes the log as JSON lines. The
  hourly summary now counts failed logins too.
- **Administration.** `silver-relay --admin-socket` answers
  `silver-relay admin` on a Unix socket that only root and the relay's
  user can open, so nothing about administration is on the network:
  `status`, `identities` (every identity under its log pseudonym, with
  mailbox size and prekey deposit), `evict`, `ban` and `unban` an address
  or an identity (kept across restarts, listed by `bans`), and
  `invite-set`, `invite-off` and `invite-reset` for the invite token
  without a restart. A banned address is refused at the door and a
  banned identity at login. The installer configures the socket and the
  unit gives it a private runtime directory. Nothing an administrator can
  do shows a message or a key.
- **Lifecycle.** The database carries a schema version: a relay brings an
  older layout along at its first start and refuses a newer one rather
  than misread it. `silver-relay backup` writes one consistent snapshot of
  the whole database, through the admin socket while the relay runs or
  from the data directory while it is stopped, in a format of the relay's
  own that is checked against its checksum before the file gets its name;
  `silver-relay restore` loads one into a stopped relay, moving an
  existing database aside with `--replace`. `docs/UPGRADING.md` says how
  to upgrade, roll back and move a relay. Each release now publishes a
  container image, `ghcr.io/iamforeveralonetoo/silver-relay` for amd64 and
  arm64 (the release's own static binary on an empty base, unprivileged,
  with a provenance attestation), `deploy/compose.yml` runs it with the
  built-in TLS, and `deploy/Dockerfile` builds it from source. Releases
  include Linux arm64 binaries.
- **An operator's guide.** `docs/OPERATING.md`: a checklist for a first
  deployment, sizing, what every limit bounds and when to change it, what
  the log records and how long to keep it, the metrics and what they
  mean, day-to-day administration, backups, updates, what to do after a
  compromise of the host, and how to shut a relay down. The installer now
  enables a nightly backup timer (`deploy/silver-relay-backup.timer`)
  that keeps two weeks of backups under the state directory.

## 0.6.0 - 2026-09-04

Phase 6: secure and private by default. A relay and a network observer are
shown less; a stolen data directory and a hostile relay get less; what a
peer sends is bounded and never reaches the terminal raw. Clients and
relays still interoperate with 0.4.0 and 0.5.0 peers; the new protections
turn on by themselves. The wire gains only optional, backward-compatible
additions (body padding as trailing spaces, a `padded_files` capability, a
relay-bound login), so an older peer reads a newer one and vice versa.
[docs/PROTOCOL.md](docs/PROTOCOL.md) and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) are rewritten for all of it.

### Added

- **Files you agree to.** Nothing announced by a peer is fetched on its
  own: a file waits until `/get`, or, per contact, `/files auto` fetches
  as they arrive. A `downloads/` quota (`downloads_quota_mib`, 1 GiB) is
  honoured, and a file whose declared size or chunk count is impossible is
  refused before a byte is asked for.
- **Opening files safely.** `/open` and the double click refuse to run an
  executable (a long, cross-platform list), mark downloads on Windows with
  the zone that makes SmartScreen check them, and normalise saved names
  (no path separators, control or invisible characters, no reserved device
  names, Unicode NFC), never overwriting.
- **Protected at rest without a passphrase.** With no passphrase set, the
  data key is kept in the operating system's key store (Credential Manager
  on Windows, Keychain on macOS, Secret Service on Linux), so a copied data
  directory is useless elsewhere; `--no-keystore` keeps the files plain.
  `/lock` and `lock_after_minutes` drop the keys and ask for the passphrase
  again; core dumps and same-user debuggers are refused; `silver.log` is
  created private; `SILVER_PASSPHRASE` is taken out of the environment
  before anything else runs.
- **Less for the relay to see.** Message bodies are padded to 160-byte
  steps, so a receipt, a short and a medium message are the same size on
  the wire. Delivery and read receipts leave after a random delay (up to
  2 s and 2–12 s), so a receipt no longer marks the moment a message was
  read. A recipient that advertises `padded_files` may be sent a file
  whose last chunk is filled to a whole 64 KiB, hiding its exact size from
  the relay. A SOCKS5 proxy option (`--proxy socks5://…`) sends both
  connections through Tor, each on its own circuit, so they no longer
  share an address. A relay's TLS key can be pinned (`--pin sha256:…`,
  shown by `--print-pin`), and a relay once reached over `wss://` is never
  talked to over plain `ws://`.
- **Relay-bound login.** The login signature now covers the relay's host
  name as well as the nonce, so a challenge collected by one relay is
  worthless at another; older logins are still accepted unless the
  operator turns them off (`--require-bound-auth`).
- **Relay abuse controls.** Limits per client address (open connections,
  new identities an hour, upload bytes an hour), an idle timeout, a total
  connection and identity cap, and per-user one-time-prekey hand-out
  limits, on top of the existing per-connection rates. A trusted TLS front
  can pass the real address in `X-Forwarded-For` (`--trusted-proxy`).
- **Relay logs and storage that reveal less.** The log names clients by a
  pseudonym that changes every run (`--log-ids` restores real ids); the
  database directory and file are private to the relay's user
  (`StateDirectoryMode=0700`).
- **Continuous fuzzing.** `cargo fuzz` targets for the frame, envelope,
  blob-chunk, session, invite-link, file-name and stored-record parsers
  run in CI, alongside stable-toolchain tests that throw random bytes at
  the same parsers and assert they never panic.
- **Post-quantum handshake (protocol v3).** Clients publish ML-KEM-768
  keys (FIPS 203) next to their X25519 prekeys: a signed medium-term key
  rotated weekly and one-time keys the relay hands out once, all signed
  by the identity key. A session's handshake encapsulates a secret to one
  of them and mixes it into the session key with the Diffie–Hellman
  values (PQXDH-style), so a recording of today's traffic cannot be opened
  by a future quantum computer, and a flaw in ML-KEM alone changes
  nothing. The chat title says `forward secret, post-quantum` when it
  applies; a peer or relay from before 0.6.0 gets the classical handshake
  and `/session` says so. The relay keeps the new keys, reports them in
  `prekey_status` and advertises `pq_prekeys`. Deniability was considered
  and decided against for now; the reasoning and the path to it are in
  `docs/PROTOCOL.md` section 9.
- **Releases you can check.** Binaries are built with `cargo auditable`
  from locked dependencies, with build paths and timestamps removed, so a
  rebuild of the tagged commit gives the same bytes (CI rebuilds twice on
  every push and compares). Each release carries a CycloneDX SBOM per
  binary, a SLSA build provenance attestation for every file, and a
  `SHA256SUMS` signed with the project's minisign key once the key is
  set up. Every GitHub Action is pinned to a commit hash, and the OpenSSF
  Scorecard runs weekly. `silver --check-release` asks the releases page whether a
  newer version exists; only on request, never by itself.
- **A security policy and an assessment.** `SECURITY.md` says how to
  report a vulnerability privately, what to expect, what is in scope and
  which versions get fixes. `docs/SECURITY_ASSESSMENT.md` walks the OWASP
  ASVS Level 2 controls and says, for each that applies, whether the code
  meets it and what closes any gap. The threat model is rewritten for the
  whole phase, with the assumptions, a future quantum adversary and a
  supply-chain attacker among the actors, what backs each claim, and a
  table of the gaps with where they close. Release builds now keep
  integer overflow checks on, so a wrapped counter is a crash to fix
  rather than a silent wrong number in a limit. An independent review of
  `silver-protocol` and the relay is planned before 1.0 and has not
  happened yet; the policy says how to offer one.

### Changed

- A signed prekey older than three weeks is refused: the sender falls back
  to a message without forward secrecy and says so, rather than start a
  session the peer could never read.
- `silver-tui`'s `main` scrubs the passphrase environment variables before
  the async runtime starts; that one function is the sole exception to the
  crate's `forbid(unsafe_code)` (documented and isolated).
- The capabilities a contact advertises are remembered the moment their
  request is accepted, so a file or receipt can go to them at once rather
  than waiting for their next message.

### Security

- Everything a peer or the relay sends is bounded before it is stored or
  drawn (message, alias and request caps; a per-sender request limit), and
  a terminal-safety test asserts that nothing a peer controls reaches the
  terminal as raw control sequences.

## 0.5.0 - 2026-09-04

A terminal client that feels native. Nothing on the wire changed; clients
and relays interoperate with 0.4.0 peers. `Ctrl-C` no longer quits on its
own (see below), which is the one habit to relearn.

### Added

- ASCII marks (`..`, `v`, `vv`, `x`) where the terminal's fonts are
  unlikely to have the Unicode ones: the classic Windows console,
  `TERM=linux`, a non-UTF-8 locale. `--ascii`, `SILVER_ASCII` and
  `/marks ascii|unicode|auto` decide by hand; the choice is remembered.
- A clipboard the client reads and writes itself: `Ctrl-V`, `Shift-Insert`
  and a right click paste from the system clipboard (Windows, macOS, X11,
  Wayland); `Ctrl-C` copies the selection, `/copy` the last message of the
  chat, `/copy id` your id, `/copy link` and `/invite copy` your invite
  link. Where there is no system clipboard (SSH, tmux, a headless box)
  copies go to the terminal's clipboard through OSC 52. `Ctrl-Q` quits;
  `Ctrl-C` with nothing selected asks to be pressed again.
- Text selection inside the client: drag with the mouse, double click a
  word, triple click a whole message, `Shift-Up`/`Shift-Down` extend by
  messages, `Esc` clears. Copying whole messages gives clean
  `hh:mm name: text` lines. The terminal's own selection (`Shift`+drag,
  or `--no-mouse`) keeps working.
- Mouse navigation: click a chat, Requests or System in the list to open
  it, drag the scrollbar that appears when the chat overflows, drag the
  divider to resize the list (remembered in `config.json` as
  `sidebar_width`), double-click a received file's line to open it with
  the system's opener; `/open` does the same for the last file.
- Discoverability: `F1` and `/help` open a scrollable help overlay built
  from the command table, `Tab` completes `/commands` and file paths,
  the status line hints at the keys for the focused pane, a mistyped
  command answers "Did you mean /x?", and a fresh identity (or one
  without contacts) gets a short guided start in the System pane.
- Layout and rendering: `--theme dark|light|mono` and `/theme` (`NO_COLOR`
  means mono, using bold, dim and reverse video only), a narrow layout
  under 70 columns that folds the list away and counts "N/M" in the chat
  title, the focused pane shown by an accented border, a "new messages"
  rule above what arrived since the chat was last open, "Today" and
  "Yesterday" on the date rules.
- Terminal tests: `tests/tui/` drives the client in a pseudo-terminal
  through a screen emulator and checks marks, clipboard, selection,
  mouse, help, layout, notifications and files; CI runs it under
  `xterm-256color` and `linux`, plus a run inside tmux, and a snapshot
  test of the main screen. `docs/TERMINALS.md` lists what the client
  needs from a terminal and what each known terminal does about it.

### Changed

- `config.json` gains `marks`, `theme` and `sidebar_width`.
- The README's quick start covers the release archives per platform and
  recommends Windows Terminal over the classic console.

## 0.4.0 - 2026-09-04

Everyday messaging: receipts, files, notifications, invite links and a more
comfortable terminal. Clients and relays interoperate with 0.3.0 peers;
receipts and files are only exchanged with clients that have shown they
understand them, and files need a relay from this version.

### Added

- Delivery and read receipts, sent as ordinary encrypted messages and
  shown as marks on sent lines: `⋯` waiting for the relay, `✓` accepted,
  `✓✓` delivered to the contact's device, `✓✓` in colour read. A chat open
  in a window without focus does not count as read until focus returns.
  `/receipts off` keeps read receipts to yourself; receipts are never sent
  to people you have not accepted. Every message now lists the sender's capabilities
  inside the encrypted body, so nothing is sent to a client that cannot
  read it.
- File transfer: `/send <path>` (also `/file`, `/attach`) encrypts a file
  of up to 16 MiB under a fresh per-file key, parks the ciphertext on the
  relay in 64 KiB chunks over the anonymous connection, and sends the key,
  name, size and SHA-256 to the contact inside a normal message. The
  recipient's client fetches, decrypts, checks and saves the file under
  its own name in `<data-dir>/downloads`, never overwriting, and the chat
  line says where it went, also after a restart. Progress is shown while
  sending and receiving. Files from people you have not accepted are
  listed with their request and never fetched.
- Relay: encrypted file chunks (`blob_put`, `blob_get`), a `blobs` feature
  flag, `--max-blob-mib` (16; 0 turns files off) and `--blob-storage-mib`
  (1024); chunks are rate limited per connection and expire with messages.
- Invite links (`silver://add/<id>?relay=…`): `/invite` shows yours with a
  QR code drawn in the terminal, `/add` accepts a link and warns when it
  names another relay, `--print-invite` prints it for scripts.
- Notifications: the terminal bell, a desktop notification raised through
  the terminal (WezTerm, kitty, foot, iTerm2, rxvt-unicode and others; it
  never contains the message) and the unread count in the window title.
  `/notify all|bell|off` chooses; a burst of messages makes one noise.
- Terminal polish: date separators between days, mouse-wheel and
  `PgUp`/`PgDn` scrolling with `Ctrl-Home`/`Ctrl-End`, `Up`/`Down` recall
  of earlier lines and commands, `Alt-Enter` for multi-line messages,
  bracketed paste that keeps line breaks, `/search <text>` across the
  selected chat or all chats, `Alt-Up`/`Alt-Down` to switch chats,
  `--no-mouse` to leave the mouse to the terminal.

### Changed

- `config.json` gains `read_receipts` and `notify`. History files gain
  receipt and text-update lines, which older clients skip.
- `docs/PROTOCOL.md` specifies capabilities, receipts, files and the blob
  frames; the threat model covers what receipts and file storage reveal.
- A message line born after the relay already answered no longer shows a
  pending mark until the next restart.

## 0.3.0 - 2026-09-04

Forward secrecy. Clients and relays from this version interoperate with
0.2.0 peers: a recipient without prekeys, or anyone behind an older relay,
is sent the v1 format and told so in the chat title.

### Added

- Forward-secret sessions (protocol v2): clients publish a signed prekey
  and one-time prekeys; the first message to a peer runs an X3DH handshake
  against them and every message after that is encrypted under a Double
  Ratchet key that is used once and discarded. The chat title says
  `forward secret` once a session exists, `/session` explains the state,
  and the System pane reports new sessions and messages that could not be
  read after one side lost its session state.
- Anonymous submission: the relay accepts messages on connections that
  never authenticate, and the client sends on such a connection (with TLS
  session resumption off) so the relay cannot pair a message with its
  sender. `--submit-authenticated` on the client and
  `--anonymous-sends-per-minute 0` on the relay turn it off.
- `docs/PROTOCOL.md`, the wire format and cryptography in full.
- Relay: one-time prekeys are stored, handed out one per lookup, and their
  status reported so clients can top up. `--anonymous-sends-per-minute`.

### Changed

- The data directory gains `prekeys.json` and `sessions.json`, encrypted
  like everything else under a passphrase. A restored backup starts with
  fresh prekeys and no sessions; peers notice and start over.
- A key change for a contact also drops the sessions with them.
- The threat model is updated for sessions and anonymous submission.

## 0.2.0 - 2026-09-04

Completes the trust model on top of the 0.1.0 baseline. Relay and client
from 0.2.0 interoperate with 0.1.0 peers, but the new relay behaviour only
applies once the relay itself is updated.

### Added

- `/verify` shows a 60-digit safety number derived from both identity keys;
  `/verify ok` marks a contact verified after comparing it out of band.
  Verified contacts carry a check mark.
- `/refresh` (and re-running `/add`) fetches a contact's key bundle again.
  A changed encryption key is adopted but reported loudly and clears the
  verified mark.
- Encrypted data directory: `--set-passphrase` protects keys, contacts,
  config, outbox and history with Argon2id and XChaCha20-Poly1305;
  `--remove-passphrase` reverses it. New identities are offered a
  passphrase on first start; `SILVER_PASSPHRASE` supplies one
  non-interactively.
- Identity backup and restore: `--export-backup FILE` and
  `--import-backup FILE [--force]`, encrypted under a passphrase of their
  own (`SILVER_BACKUP_PASSPHRASE` for scripts).
- Contact requests: messages from senders who are not contacts wait in a
  Requests pane until `/accept` or `/block`; `/unblock` and `/blocked`
  manage the block list.
- Relay rate limits per connection (`--sends-per-minute`,
  `--lookups-per-minute`) and optional invite-only registration
  (`--invite-token` on the relay, `--invite` on the client).
- `docs/THREAT_MODEL.md` describing what the relay, the network and a
  stolen device can each see.

### Changed

- Licensed under AGPL-3.0-only (was GPL-3.0). The relay serves a source
  notice at `/`.
- A send the relay refuses is answered with a `rejected` frame carrying the
  reason; rate-limited sends stay queued and are retried automatically.

## 0.1.0 - 2026-09-04

First tagged release.

- Ed25519 identities, X25519 key agreement, XChaCha20-Poly1305 envelopes
  with sealed sender and signed key bundles.
- Self-hosted relay that stores and forwards encrypted envelopes with
  persistent mailboxes (redb), acknowledgements, message expiry and
  per-mailbox quotas.
- Client with reconnect and backoff, an offline outbox, per-conversation
  sequence numbers, `wss://` with system and Mozilla roots, an extra CA
  option and HTTP CONNECT proxy support.
- Terminal UI with contacts, aliases and per-contact history.
- Installer for the relay with an optional Caddy TLS front, hardened
  systemd unit, CI with `cargo audit` and `cargo deny`, release workflow
  for Windows, macOS and Linux binaries with checksums.
