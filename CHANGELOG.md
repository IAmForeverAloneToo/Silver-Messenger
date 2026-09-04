# Changelog

Notable changes to Silver Messenger. Versions follow [semantic
versioning](https://semver.org); while the major version is 0, a minor bump
means behaviour or the wire protocol changed in a way worth reading about.

## Unreleased

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
