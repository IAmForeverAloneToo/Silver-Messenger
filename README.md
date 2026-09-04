# Silver Message

End-to-end encrypted messaging in your terminal. Written in Rust; runs on
Windows, Linux and macOS.

Messages travel through a **self-hosted relay** that only ever stores and
forwards encrypted blobs. The relay cannot read your messages, and because the
sender's identity is sealed inside the ciphertext, it does not even learn who
sent a given message, only who it is for.

## Layout

The repository is a Cargo workspace with four crates:

| Crate             | What it is                                                                 |
| ----------------- | -------------------------------------------------------------------------- |
| `silver-protocol` | Shared types and all cryptography: identities, key bundles, sealed envelopes, relay wire frames. |
| `silver-relay`    | The relay server binary (`silver-relay`). Authenticates clients, stores key bundles, queues envelopes per recipient. |
| `silver-client`   | Client core with no UI: relay connection with auto-reconnect, local store (keys, contacts, history). |
| `silver-tui`      | The terminal client binary (`silver`), built on ratatui.                   |

## Quick start

You need a Rust toolchain (https://rustup.rs). Then, from the repository root:

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

Whoever receives a message from someone new gets a contact created
automatically; `/alias <name>` gives it a friendly name.

### Commands and keys

| Command                     | Effect                                                       |
| --------------------------- | ------------------------------------------------------------ |
| `/add <user-id> [alias]`    | Add a contact by id                                          |
| `/alias <name>`             | Name the selected contact                                    |
| `/remove`                   | Forget the selected contact (history file stays on disk)     |
| `/me`                       | Show your own id                                             |
| `/relay <ws-url>`           | Change the relay (used on next start)                        |
| `/help`, `/quit`            |                                                              |

Keys: `Tab` / `Shift-Tab` or `Up` / `Down` switch chats, `PgUp` / `PgDn`
scroll, `Esc` clears the input line, `Ctrl-C` quits.

### Options

```
silver --relay <URL>       relay WebSocket URL; remembered in config.json   (env SILVER_RELAY)
silver --data-dir <DIR>    where keys, contacts and history live            (env SILVER_DATA_DIR)
silver --print-id          print your user id and exit
SILVER_LOG=debug silver    write logs to <data-dir>/silver.log

silver-relay --listen <ADDR>   default 0.0.0.0:7777                         (env SILVER_RELAY_LISTEN)
RUST_LOG=debug silver-relay    relay log level
```

Default data directory: `~/.local/share/silver-message` on Linux,
`~/Library/Application Support/silver-message` on macOS,
`%APPDATA%\silver-message\data` on Windows.

## Deploying a relay

A relay is a single static-ish binary that needs one open TCP port. On a
fresh Debian/Ubuntu or Fedora VPS, as root:

```sh
curl -fsSL https://raw.githubusercontent.com/IAmForeverAloneToo/Silver-Messanger/main/deploy/install.sh | bash
```

The script installs build tools and Rust, clones this repository into
`/opt/silver-messanger`, builds the relay, and runs it as the unprivileged
`silver` user under a hardened systemd unit (`deploy/silver-relay.service`)
listening on `0.0.0.0:7777`. Re-running the script updates to the latest
`main`. Settings live in `/etc/silver-relay/relay.env`; logs are in
`journalctl -u silver-relay`. Remember to open port 7777/tcp in your
provider's firewall as well.

Clients then start with `silver --relay ws://<server-ip>:7777/ws`. The
transport is plain WebSocket for now, which is safe for message content
(everything is end-to-end encrypted before it leaves the client) but exposes
recipient ids and timing to the network path; put the relay behind a
TLS-terminating reverse proxy and use `wss://` once you have a domain name.

## How the crypto works (v1)

* **Identity**: an Ed25519 signing key (its public half is your user id,
  shown as base58) plus a long-term X25519 key for Diffie–Hellman.
* **Key bundle**: your X25519 public key, signed with your identity key. The
  relay stores and serves bundles; clients verify the signature and pin the
  key on first use.
* **Envelope** (what the relay sees): `{ id, to, ephemeral_public, nonce, ciphertext }`.
  For each message the sender makes a fresh X25519 ephemeral key, derives a
  key with HKDF-SHA256 from `DH(ephemeral, recipient)`, and encrypts
  `sender_id || signature || body` with XChaCha20-Poly1305. The recipient id
  and ephemeral key are bound as associated data, and the signature covers the
  recipient, ephemeral key, nonce and body, so an envelope cannot be
  re-addressed, altered, or forged.
* **Relay auth**: on connect the relay sends a random nonce; the client signs
  it with its identity key. Only the owner of an id can read its mailbox.
* **Delivery**: the relay keeps an envelope until the recipient acknowledges
  it, so nothing is lost if a client drops mid-download. Clients de-duplicate
  by envelope id.

What v1 does **not** do yet, and what is next:

- [ ] Forward secrecy against a later compromise of the recipient's long-term
      key (needs a Double-Ratchet-style session; the envelope format leaves
      room for it).
- [ ] Encrypt local history and keys at rest behind a passphrase.
- [ ] Relay persistence across restarts (mailboxes and bundles are in memory).
- [ ] Warn loudly when a contact's published key changes.
- [ ] Group chats, attachments, read receipts.
- [ ] TLS on the relay (`wss://` already works in the client; put the relay
      behind a reverse proxy that terminates TLS for now).

## Development

```sh
cargo test --workspace            # unit tests + an in-process relay end-to-end test
cargo clippy --workspace --all-targets
cargo fmt --all
```

The end-to-end test in `crates/silver-client/tests/e2e.rs` starts a relay on
a random port, connects two clients, and checks both directions, offline
queueing, and reconnection after the relay goes away.
