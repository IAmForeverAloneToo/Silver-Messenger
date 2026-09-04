# Silver Messenger

End-to-end encrypted messaging in your terminal. Written in Rust; runs on
Windows, Linux and macOS.

Messages travel through a **self-hosted relay** that only ever stores and
forwards encrypted blobs. The relay cannot read your messages or forge them.
The sender's identity is sealed inside the ciphertext, so the envelope itself
names only the recipient; the relay can still see which connection submitted
it. What the relay, the network and a stolen laptop can and cannot learn is
spelled out in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Layout

The repository is a Cargo workspace with four crates:

| Crate             | What it is                                                                 |
| ----------------- | -------------------------------------------------------------------------- |
| `silver-protocol` | Shared types and all cryptography: identities, key bundles, sealed envelopes, relay wire frames. |
| `silver-relay`    | The relay server binary (`silver-relay`). Authenticates clients, stores key bundles, queues envelopes per recipient. |
| `silver-client`   | Client core with no UI: relay connection with auto-reconnect, local store (keys, contacts, history). |
| `silver-tui`      | The terminal client binary (`silver`), built on ratatui.                   |

## Quick start

### From the release binaries

Download the archive for your system from the
[releases page](https://github.com/IAmForeverAloneToo/Silver-Messenger/releases):

| System  | Archive                                                                 |
| ------- | ----------------------------------------------------------------------- |
| Windows | `silver-messenger-<version>-x86_64-pc-windows-msvc.zip`                 |
| macOS   | `…-aarch64-apple-darwin.tar.gz` (Apple Silicon), `…-x86_64-apple-darwin.tar.gz` (Intel) |
| Linux   | `…-x86_64-unknown-linux-musl.tar.gz` (static; runs on any distribution) |

Unpack it. Inside are the client `silver` (`silver.exe` on Windows), the
relay `silver-relay`, and the docs. Open a terminal in that folder and
point the client at a relay once:

```
.\silver.exe --relay wss://relay.example.org/ws     # Windows, in PowerShell or Windows Terminal
./silver --relay wss://relay.example.org/ws         # macOS and Linux
```

The relay is remembered, so from then on `silver` alone is enough (on
Windows, double-clicking `silver.exe` works too). A data directory from an
earlier version is picked up as it is.

**Windows:** use [Windows Terminal](https://aka.ms/terminal) (preinstalled
on Windows 11, in the Microsoft Store on Windows 10) rather than the
classic console window. Its fonts have the check marks, and selection, copy
and paste behave as you expect. In the classic console the client draws
ASCII marks (`v`, `vv`, `x`, `..`) by itself; `/marks` changes that, and
`--no-mouse` hands selection and right-click paste back to the console.

**macOS:** the binaries are not notarised yet, so the first start may be
refused. Right-click `silver` and choose Open once, or run
`xattr -d com.apple.quarantine silver`.

### From source

You need a Rust toolchain (https://rustup.rs). From the repository root:

```sh
# 1. Run a relay somewhere both parties can reach (defaults to 0.0.0.0:7777)
cargo run --release --bin silver-relay

# 2. Each person runs the client, pointing it at the relay once
cargo run --release --bin silver -- --relay ws://relay.example.org:7777/ws
```

### First steps

On first start the client generates an identity and shows your **user id** in
the System pane. Share it with the person you want to talk to (any channel
works; the id *is* your public key, so comparing it out of band is the same as
verifying a fingerprint). `/invite` shows it as a link
(`silver://add/<id>?relay=…`) and as a QR code that a phone can scan, so
nobody has to type 44 characters. Then:

```
/add <their-user-id or link> alice   # fetches their key from the relay and opens a chat
hello!                               # anything not starting with / is sent to the selected chat
/send ~/photo.jpg                    # sends a file (up to 16 MiB), encrypted like a message
```

A message from someone who is not a contact yet lands in the **Requests**
pane rather than in a chat; `/accept <n>` turns it into a contact (and moves
the held messages into the chat), `/block <n>` drops everything from that id
from then on. `/alias <name>` gives a contact a friendly name.

Sent messages carry a mark: `⋯` waiting for the relay, `✓` accepted by the
relay, `✓✓` delivered to the contact's device, `✓✓` in colour read, `✗`
refused. Received files are saved under their own name in
`<data-dir>/downloads` (never overwriting) and the chat line says where.

### Commands and keys

| Command                         | Effect                                                       |
| ------------------------------- | ------------------------------------------------------------ |
| `/add <user-id or link> [alias]` | Add a contact by id or invite link                           |
| `/invite [copy]`                | Show your invite link and a QR code of it; `copy` puts it on the clipboard |
| `/copy [id\|link]`              | Copy the last message of this chat, your id, or your invite link |
| `/alias <name>`                 | Name the selected contact                                    |
| `/remove`                       | Forget the selected contact (history file stays on disk)     |
| `/verify`                       | Show the safety number to compare with the selected contact  |
| `/verify ok` / `/verify no`     | Mark the selected contact as verified, or clear the mark     |
| `/refresh`                      | Fetch the selected contact's key again and report any change |
| `/session`                      | Show how messages with the selected contact are protected    |
| `/send <path>`                  | Send a file to the selected contact (also `/file`, `/attach`) |
| `/open`                         | Open the last file received in this chat (or double-click its line) |
| `/search <text>`                | Find messages in the selected chat, or in all chats from System |
| `/receipts on\|off`             | Tell contacts when you have read their messages (default on) |
| `/notify all\|bell\|off`        | Bell and desktop notification, bell only, or nothing         |
| `/marks ascii\|unicode\|auto`   | Draw the marks in ASCII if your terminal shows boxes for them |
| `/theme dark\|light\|mono`      | Colours for a dark or a light background, or none at all     |
| `/accept <n>`                   | Accept a contact request from the Requests pane              |
| `/block <n or id>`              | Drop everything from that id from now on                     |
| `/unblock <id>`, `/blocked`     | Undo a block; list blocked ids                               |
| `/me`                           | Show your own id                                             |
| `/relay <ws-url>`               | Change the relay (used on next start)                        |
| `/help`, `/quit`                |                                                              |

`F1` (or `/help`) opens a help overlay with all of this. `Tab` completes
`/commands` and file paths, and the status line at the bottom says what the
keys do where you are.

Mouse: click a chat, Requests or System in the list to open it, the wheel
scrolls, the scrollbar on the right edge can be dragged, so can the line
between the list and the chat to resize the list. Drag in the chat to select
text (double click selects a word, triple click a whole message), double
click a received file's line to open it.

Keys: `Tab` / `Shift-Tab` or `Alt-Up` / `Alt-Down` switch chats, `Up` /
`Down` recall earlier lines, `Alt-Enter` starts a new line in a message,
`PgUp` / `PgDn` scroll and `Ctrl-Home` / `Ctrl-End` jump, `Shift-Up` /
`Shift-Down` select messages. `Ctrl-C` copies the selection (with nothing
selected, pressing it twice quits), `Ctrl-V`, `Shift-Insert` or a right
click paste from the system clipboard, `Esc` clears the selection and then
the input line, `Ctrl-Q` quits. Copies go to the system clipboard, or to
the terminal's clipboard through OSC 52 over SSH and in tmux. Pasting keeps
line breaks. New messages in chats you are not looking at ring the bell,
raise a desktop notification where the terminal can (WezTerm, kitty, foot,
iTerm2, rxvt and others; the notification never contains the message), and
put the unread count in the window title; `/notify` adjusts that. If the
terminal is narrower than 70 columns the list folds away and the chat title
shows where you are.

### Options

```
silver --relay <URL>       relay WebSocket URL; remembered in config.json   (env SILVER_RELAY)
silver --data-dir <DIR>    where keys, contacts and history live            (env SILVER_DATA_DIR)
silver --ca-cert <PEM>     extra trusted root certificates for wss://; remembered (env SILVER_CA_CERT)
silver --proxy <URL>       HTTP CONNECT proxy to reach the relay through; remembered (env SILVER_PROXY, else HTTPS_PROXY)
silver --invite <TOKEN>    invite token for a relay that only registers invited identities; remembered (env SILVER_INVITE)
silver --print-id          print your user id and exit
silver --print-invite      print your invite link (silver://add/<id>?relay=…) and exit
silver --no-mouse          leave the mouse to the terminal: no wheel scrolling, but text selects without Shift (env SILVER_NO_MOUSE)
silver --ascii             draw marks in ASCII (v, vv, x, ..); chosen by itself in the classic Windows console (env SILVER_ASCII)
silver --theme <NAME>      dark (default), light for a light background, or mono for no colour; NO_COLOR means mono (env SILVER_THEME)
silver --set-passphrase    encrypt keys, contacts and history under a passphrase (asked at every start)
silver --remove-passphrase store everything unencrypted again
SILVER_PASSPHRASE=…        supplies the passphrase non-interactively (scripts, tests)
silver --export-backup <F> write an encrypted backup of identity and contacts to F (asks for a passphrase for it)
silver --import-backup <F> restore identity and contacts from F; add --force to replace an existing identity
SILVER_BACKUP_PASSPHRASE=… supplies the backup passphrase non-interactively
silver --submit-authenticated  send on the authenticated connection instead of the relay's anonymous one (env SILVER_SUBMIT_AUTHENTICATED)
SILVER_LOG=debug silver    write logs to <data-dir>/silver.log

silver-relay --listen <ADDR>          default 0.0.0.0:7777                          (env SILVER_RELAY_LISTEN)
silver-relay --data-dir <DIR>         database location; under systemd /var/lib/silver-relay (env SILVER_RELAY_DATA)
silver-relay --message-ttl-days <N>   delete unacknowledged messages after N days, default 30 (env SILVER_RELAY_TTL_DAYS)
silver-relay --max-mailbox-messages   per-recipient queue cap, default 1000            (env SILVER_RELAY_MAX_MESSAGES)
silver-relay --max-mailbox-mib        per-recipient queue cap in MiB, default 32       (env SILVER_RELAY_MAX_MIB)
silver-relay --sends-per-minute <N>   messages one connection may submit per minute, default 60 (env SILVER_RELAY_SENDS_PER_MINUTE)
silver-relay --lookups-per-minute <N> key lookups per connection per minute, default 30   (env SILVER_RELAY_LOOKUPS_PER_MINUTE)
silver-relay --invite-token <T>       only register new identities that present T   (env SILVER_RELAY_INVITE_TOKEN)
silver-relay --anonymous-sends-per-minute <N>  messages an unauthenticated connection may submit per minute, default 30; 0 turns anonymous submission off (env SILVER_RELAY_ANONYMOUS_SENDS_PER_MINUTE)
silver-relay --max-blob-mib <N>       largest encrypted file to store, default 16; 0 turns file transfer off (env SILVER_RELAY_MAX_BLOB_MIB)
silver-relay --blob-storage-mib <N>   encrypted file bytes to keep in total, default 1024 (env SILVER_RELAY_BLOB_STORAGE_MIB)
silver-relay --ephemeral              keep everything in memory only
RUST_LOG=debug silver-relay           relay log level
```

Default data directory: `~/.local/share/silver-messenger` on Linux,
`~/Library/Application Support/silver-messenger` on macOS,
`%APPDATA%\silver-messenger\data` on Windows. Received files go to
`downloads/` inside it; they are ordinary files, not encrypted at rest even
when a passphrase is set.

## Deploying a relay

A relay is a single static binary that needs one open TCP port. It runs as
the unprivileged `silver` user under a hardened systemd unit
(`deploy/silver-relay.service`), listening on `0.0.0.0:7777`. Settings live
in `/etc/silver-relay/relay.env`, the database in `/var/lib/silver-relay`,
and logs are in `journalctl -u silver-relay`.
Remember to open port 7777/tcp in your provider's firewall as well.

**From GitHub Actions** (works for a private repository): add the secrets
`VPS_HOST` and `VPS_SSH_KEY` (a private key whose public half is in the
server's `authorized_keys`; `VPS_USER` optionally, default `root`) and run
the **Deploy relay** workflow. It builds a static binary on the runner and
installs it over SSH, so the server needs neither Rust nor access to the
repository. The same workflow can show status and logs or restart the relay.

**By hand**, on a Debian/Ubuntu or Fedora server as root, if the repository
is public:

```sh
curl -fsSL https://raw.githubusercontent.com/IAmForeverAloneToo/Silver-Messenger/main/deploy/install.sh | bash
```

This installs build tools and Rust, clones the repository into
`/opt/silver-messenger`, and builds the relay on the server. Re-running it
updates to the latest `main`. With a `silver-relay` binary and
`silver-relay.service` placed next to it, the same script installs those
instead and needs no compiler.

Clients then start with `silver --relay ws://<server-ip>:7777/ws`.

**HTTPS / port 443.** Plain WebSocket on port 7777 is safe for message
content (everything is end-to-end encrypted before it leaves the client) but
exposes recipient ids and timing to the network path, and corporate or campus
proxies often block non-standard ports outright. Point a hostname at the
server and run the installer with `SILVER_DOMAIN=relay.example.org` (or set
the repository variable `VPS_DOMAIN` for the workflow). It installs Caddy as
a TLS front with an automatic Let's Encrypt certificate, moves the relay to
localhost, and opens ports 80 and 443 instead. Clients then use
`silver --relay wss://relay.example.org/ws`. The client trusts both the
operating system's certificate store and Mozilla's root bundle, so it also
works behind TLS-inspecting proxies whose root certificate is installed on
the machine.

## How the crypto works

The exact wire format and every constant are in
[docs/PROTOCOL.md](docs/PROTOCOL.md); what it protects against, and what
it does not, is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

* **Identity**: an Ed25519 signing key (its public half is your user id,
  shown as base58) plus a long-term X25519 key for Diffie–Hellman.
* **Key bundle**: your X25519 public key, signed with your identity key,
  plus your prekeys: a signed medium-term key rotated weekly and a batch of
  one-time keys. The relay stores and serves bundles, hands out one
  one-time key per lookup, and tells you when to deposit more. Clients
  verify the signatures and pin the long-term key on first use.
* **Envelope** (what the relay sees): `{ id, to, ephemeral_public, nonce, ciphertext }`.
  For each message the sender makes a fresh X25519 ephemeral key, derives a
  key with HKDF-SHA256 from `DH(ephemeral, recipient)`, and encrypts
  `sender_id || signature || body` with XChaCha20-Poly1305. The recipient id
  and ephemeral key are bound as associated data, and the signature covers the
  recipient, ephemeral key, nonce and body, so an envelope cannot be
  re-addressed, altered, or forged. The sender is inside the ciphertext, so
  the relay never sees it.
* **Forward-secret sessions**: when the recipient has published prekeys, the
  body inside the envelope is not the message but a Double Ratchet message.
  The first one carries an X3DH handshake against the recipient's identity
  key, signed prekey and a one-time prekey; from then on every message is
  encrypted under a key derived for it alone and discarded afterwards, and
  each change of direction in the conversation performs a fresh
  Diffie–Hellman step. A stolen device or key cannot decrypt messages that
  were already read, and a compromised chain heals at the next step. The
  chat title says `forward secret` once a session exists; `/session`
  explains the state. A recipient without prekeys (a client older than
  0.3.0, or anyone behind an older relay) is sent the plain v1 body
  instead, so everyone keeps talking during the upgrade.
* **Anonymous submission**: a relay from 0.3.0 on accepts messages on
  connections that never authenticate, and the client uses one such
  connection (with TLS session resumption off) for everything it sends. The
  relay therefore cannot pair an envelope with the identity that submitted
  it; it still sees the address and the timing. `--submit-authenticated`
  turns this off for networks that allow one connection only.
* **Capabilities, receipts and files**: every encrypted body lists what the
  sending client understands beyond text (`receipts`, `files`), so a client
  never sends a peer something it cannot read and old clients keep working.
  A delivery receipt goes back when a message has been decrypted and
  stored, a read receipt when it has been shown (`/receipts off` keeps
  those to yourself); both are ordinary encrypted messages, batched so a
  full mailbox costs one, and never sent to strangers. A file is encrypted
  on the sender's machine under a fresh per-file key (XChaCha20-Poly1305 in
  64 KiB chunks, each bound to the file id and its position), the
  ciphertext is parked on the relay in chunks over the anonymous connection,
  and the key, name, size and SHA-256 travel to the recipient inside a
  normal message. The recipient fetches the chunks, decrypts, checks the
  hash, and saves the file. The relay holds bytes it cannot read, for a
  recipient it cannot name, and deletes them with the message expiry.
  Files from people you have not accepted are listed with their request
  but never fetched.
* **Abuse controls**: strangers who know your id can write to you, but their
  messages wait in the Requests pane until you accept or block them. The
  relay limits each connection to 60 messages, 30 key lookups and 600 file
  chunks per minute, caps every mailbox and its total file storage, and can
  be told to register only identities that present an invite token.
* **Encryption at rest**: with a passphrase set, every file in the data
  directory (identity keys, prekeys, sessions, contacts, history, outbox,
  config) is encrypted
  with XChaCha20-Poly1305 under a random data key, which is itself wrapped
  by the passphrase stretched with Argon2id (64 MiB, 3 passes). Each file is
  bound to its own name and history is encrypted line by line. A new
  identity offers to set a passphrase on first start; `--set-passphrase`
  and `--remove-passphrase` change it later.
* **Backups**: `--export-backup` writes the identity keys and contact list
  to one file encrypted under a passphrase of its own (Argon2id and
  XChaCha20-Poly1305). `--import-backup` restores it onto a fresh
  installation: same id, same contacts, and a new message-numbering epoch so
  contacts see a reinstall rather than replays. History is not included.
* **Safety numbers**: `/verify` shows twelve groups of five digits derived
  from both identity keys, identical on both sides. Two people who read them
  to each other confirm that nobody sits between them; `/verify ok` records
  that. A contact's encryption key can only change with a signature from
  their identity key; when it does, the client warns loudly and clears the
  verified mark, because it means either a deliberate rotation or a stolen
  identity key.
* **Sequence numbers**: every message carries, inside the encrypted body, a
  per-conversation counter plus a random per-installation epoch. The
  recipient drops replays, points out gaps, and notices when a contact has
  started over from a fresh installation. Messages from older clients that
  do not number messages are accepted unchecked.
* **Relay auth**: on connect the relay sends a random nonce; the client signs
  it with its identity key. Only the owner of an id can read its mailbox.
* **Delivery**: the relay keeps an envelope in an embedded database until the
  recipient acknowledges it, so nothing is lost if a client drops
  mid-download or the relay restarts. Unacknowledged envelopes expire after
  30 days by default, mailboxes are capped per recipient, and resends of the
  same envelope id are ignored. Clients de-duplicate by envelope id too.
* **Outbox**: a message written while offline is sealed immediately, kept in
  `outbox.json` in the data directory, and handed to the relay on the next
  connection; it shows a pending mark (`⋯`) until the relay accepts it, and a
  failure mark (`✗`) if the relay refuses it for good.

What it does **not** do: deniability (messages are signed), padding of
message sizes, cover traffic. The ordered plan is in
[ROADMAP.md](ROADMAP.md).

## Development

```sh
cargo test --workspace            # unit tests + in-process relay end-to-end tests
cargo clippy --workspace --all-targets
cargo fmt --all
cargo deny check                  # advisories, licenses, duplicate crates (deny.toml)
cargo audit
```

CI runs the same checks on every push, plus the test suite on Linux, macOS
and Windows, and the terminal tests below under two terminal types.
Pushing a `v*` tag builds release archives for all platforms with a
`SHA256SUMS` file and publishes them on the releases page.

The terminal client is tested for real in `tests/tui/`: each test starts a
relay and one or two clients in pseudo-terminals, types, clicks, drags
and reads the screen back through a terminal emulator (`pip install pyte`
first; `tests/tui/run.sh` runs them all, `TERMS="xterm-256color linux"`
for both terminal types, and `test_tmux.py` drives a client inside tmux).
Which terminals are known to work, and how, is in
[docs/TERMINALS.md](docs/TERMINALS.md).

The end-to-end tests in `crates/silver-client/tests/e2e.rs` start a relay
on a random port, connect two clients, and check both directions, offline
queueing, reconnection after the relay goes away, forward-secret sessions
(including handshakes that wait in the mailbox, restarts, a peer that lost
its session state, and a peer without prekeys), anonymous submission,
capabilities and receipts, and file transfer (chunking, progress, a missing
blob, a tampered hash, a relay without file storage).

## License

AGPL-3.0. You may use, study, share and modify Silver Messenger freely; if
you distribute a modified version, or run a modified relay for other people
over a network, you must offer them its source under the same terms. The
relay serves a link to its source at `/` for that reason.
