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

Ready-made binaries for Windows, macOS and Linux are on the
[releases page](https://github.com/IAmForeverAloneToo/Silver-Messenger/releases)
(unpack and run `silver`). To build from source you need a Rust toolchain
(https://rustup.rs). Then, from the repository root:

```sh
# 1. Run a relay somewhere both parties can reach (defaults to 0.0.0.0:7777)
cargo run --release --bin silver-relay

# 2. Each person runs the client, pointing it at the relay once
cargo run --release --bin silver -- --relay ws://relay.example.org:7777/ws
```

On first start the client generates an identity and shows your **user id** in
the System pane. Share it with the person you want to talk to (any channel
works; the id *is* your public key, so comparing it out of band is the same as
verifying a fingerprint). Then:

```
/add <their-user-id> alice     # fetches their key from the relay and opens a chat
hello!                         # anything not starting with / is sent to the selected chat
```

A message from someone who is not a contact yet lands in the **Requests**
pane rather than in a chat; `/accept <n>` turns it into a contact (and moves
the held messages into the chat), `/block <n>` drops everything from that id
from then on. `/alias <name>` gives a contact a friendly name.

### Commands and keys

| Command                     | Effect                                                       |
| --------------------------- | ------------------------------------------------------------ |
| `/add <user-id> [alias]`    | Add a contact by id                                          |
| `/alias <name>`             | Name the selected contact                                    |
| `/remove`                   | Forget the selected contact (history file stays on disk)     |
| `/verify`                   | Show the safety number to compare with the selected contact  |
| `/verify ok` / `/verify no` | Mark the selected contact as verified, or clear the mark     |
| `/refresh`                  | Fetch the selected contact's key again and report any change |
| `/session`                  | Show how messages with the selected contact are protected    |
| `/accept <n>`               | Accept a contact request from the Requests pane              |
| `/block <n or id>`          | Drop everything from that id from now on                     |
| `/unblock <id>`, `/blocked` | Undo a block; list blocked ids                               |
| `/me`                       | Show your own id                                             |
| `/relay <ws-url>`           | Change the relay (used on next start)                        |
| `/help`, `/quit`            |                                                              |

Keys: `Tab` / `Shift-Tab` or `Up` / `Down` switch chats, `PgUp` / `PgDn`
scroll, `Esc` clears the input line, `Ctrl-C` quits.

### Options

```
silver --relay <URL>       relay WebSocket URL; remembered in config.json   (env SILVER_RELAY)
silver --data-dir <DIR>    where keys, contacts and history live            (env SILVER_DATA_DIR)
silver --ca-cert <PEM>     extra trusted root certificates for wss://; remembered (env SILVER_CA_CERT)
silver --proxy <URL>       HTTP CONNECT proxy to reach the relay through; remembered (env SILVER_PROXY, else HTTPS_PROXY)
silver --invite <TOKEN>    invite token for a relay that only registers invited identities; remembered (env SILVER_INVITE)
silver --print-id          print your user id and exit
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
silver-relay --ephemeral              keep everything in memory only
RUST_LOG=debug silver-relay           relay log level
```

Default data directory: `~/.local/share/silver-messenger` on Linux,
`~/Library/Application Support/silver-messenger` on macOS,
`%APPDATA%\silver-messenger\data` on Windows.

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
* **Abuse controls**: strangers who know your id can write to you, but their
  messages wait in the Requests pane until you accept or block them. The
  relay limits each connection to 60 messages and 30 key lookups per minute,
  caps every mailbox, and can be told to register only identities that
  present an invite token.
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
and Windows. Pushing a `v*` tag builds release archives for all platforms
with a `SHA256SUMS` file and publishes them on the releases page.

The end-to-end tests in `crates/silver-client/tests/e2e.rs` start a relay
on a random port, connect two clients, and check both directions, offline
queueing, reconnection after the relay goes away, forward-secret sessions
(including handshakes that wait in the mailbox, restarts, a peer that lost
its session state, and a peer without prekeys), and anonymous submission.

## License

AGPL-3.0. You may use, study, share and modify Silver Messenger freely; if
you distribute a modified version, or run a modified relay for other people
over a network, you must offer them its source under the same terms. The
relay serves a link to its source at `/` for that reason.
