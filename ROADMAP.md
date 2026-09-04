# Roadmap

Ordered from first to last. Each item says why it sits where it does and
roughly how big it is (S: hours, M: a day or two, L: a week or more).
Tick items off as they land on `main`.

## Done

- [x] Workspace, protocol, relay, client core, TUI
- [x] End-to-end encryption with sealed sender, signed key bundles
- [x] Relay auth, mailbox with acknowledgements, reconnect with backoff
- [x] HTTPS relay behind Caddy, `wss://` with system and Mozilla roots,
      extra CA option, HTTP CONNECT proxy support
- [x] Installer, hardened systemd unit, deploy and release workflows
- [x] Live two-way and offline-delivery test against the deployed relay

## Phase 1: make what exists reliable

1. [x] **Relay persistence** (M). Mailboxes and key bundles in an embedded
       store (redb or SQLite) so an update or reboot loses nothing. Includes
       message expiry and a per-user disk quota. First because every deploy
       currently drops queued mail.
2. [ ] **Client outbox** (S). Queue messages written while offline and flush
       them on reconnect, with a visible pending state. Second because it is
       the other half of "nothing gets lost".
3. [ ] **Per-conversation sequence numbers** (S). A counter inside the
       encrypted body so the client detects replays, gaps and reordering.
       Early because later protocol work builds on it.
4. [ ] **v0.1.0 release, checksums, `cargo audit` and `cargo deny` in CI**
       (S). A tagged baseline before the trust-model changes.

## Phase 2: complete the trust model

5. [ ] **Threat model document** (S). What the relay, the network and a
       stolen device can each see. Written first so items 6 to 9 are
       measured against it.
6. [ ] **Key-change warnings and `/verify`** (S). Loud warning when a
       contact's published key changes; a short safety-number string to
       compare out of band; a verified mark on contacts.
7. [ ] **Encrypted local storage** (M). Keys and history under a passphrase
       (Argon2id, XChaCha20-Poly1305), optional OS keychain unlock.
8. [ ] **Identity backup and restore** (S). Seed phrase or encrypted export,
       so a lost machine is not a lost identity.
9. [ ] **Contact requests and relay abuse controls** (M). First messages
       from strangers land in a pending list; relay rate limits, per-sender
       quotas, optional invite-token registration.

## Phase 3: forward secrecy

10. [ ] **Double ratchet sessions** (L). Prekey bundles for the initial
        handshake, then a ratchet per conversation, negotiated as protocol
        v2 with a fallback so old clients keep working during rollout.
11. [ ] **Protocol specification** (S). Written alongside the ratchet so
        the wire format is documented once it stops changing.

## Phase 4: everyday messaging

12. [ ] **Delivery and read receipts** (S). Encrypted message types; the
        relay learns nothing new.
13. [ ] **TUI polish** (M). Date separators, mouse and keyboard scrolling,
        input history, multi-line composing, bracketed paste, `/search`.
14. [ ] **Notifications** (S). Terminal bell, desktop notifications, unread
        count in the window title.
15. [ ] **Invite links and QR codes** (S). `silver://add/<id>` and a QR
        rendered in the terminal, so ids are shared without copy-pasting
        44 characters.
16. [ ] **Attachments** (M). Encrypted files, chunked or via a relay blob
        endpoint, with a size cap and progress display.

## Phase 5: beyond one relay

17. [ ] **Relay metrics and admin tooling, built-in TLS** (S). Prometheus
        endpoint, mailbox inspection, ACME in the relay so Caddy is optional.
18. [ ] **Relay-agnostic addresses** (M). Contacts as `id@relay` so people
        on different self-hosted relays can talk.
19. [ ] **Username registry** (M). Optional, signed claims on a relay.
        Decide the openness of the network before this one.
20. [ ] **Group chats** (L). Sender keys, membership and invites.
21. [ ] **Multiple devices** (L). Linked devices first, full identity sync
        later.

## Continuous

- [ ] Fuzzing for the envelope and frame parsers, property tests for
      seal/open, a TUI snapshot test
- [ ] Docker image for the relay; code signing for Windows and macOS
- [ ] Contributor guide and FAQ for non-technical users
