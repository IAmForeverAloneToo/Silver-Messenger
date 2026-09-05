# Changelog

Notable changes to Silver Messenger. Versions follow [semantic
versioning](https://semver.org); while the major version is 0, a minor bump
means behaviour or the wire protocol changed in a way worth reading about.

## Unreleased

Phase 10 of the roadmap begins with the everyday features: what people
expect of a messenger in daily use, without a single new thing for the
relay to see.

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
