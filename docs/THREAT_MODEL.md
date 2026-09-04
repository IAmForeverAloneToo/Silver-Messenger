# Threat model

What Silver Messenger protects, against whom, and where it currently falls
short. Every claim here is about the code on `main` today; the "Gaps"
remarks point at the roadmap item that closes each one. Keep this document
honest before adding features. The wire format itself is specified in
[PROTOCOL.md](PROTOCOL.md).

## Assets

| Asset | Where it lives | Why it matters |
| --- | --- | --- |
| Message content | Only on the two endpoints, and inside sealed envelopes in transit | The point of the program |
| Identity key (Ed25519) | `identity.json` on the client | Whoever holds it *is* you: can sign as you and start sessions as you |
| Long-term Diffie–Hellman key (X25519) | `identity.json` on the client | Opens the sealed layer of every envelope ever addressed to you; with the session state, reads v2 messages |
| Prekeys and session state | `prekeys.json`, `sessions.json` on the client | Current ratchet keys: reads messages in flight and the ones not yet ratcheted past |
| Contact list and history | `contacts.json`, `history/`, `outbox.json` on the client | Who you talk to and what was said |
| Received files | `downloads/` on the client, as ordinary files | Attachments people sent you; not covered by the passphrase |
| Files in transit | Encrypted chunks in the relay database for up to 30 days | Ciphertext only; the key is in the message |
| Social graph and timing | Relay memory and database, network path | Who talks to whom, when, how much |

## Actors

- **Relay operator**: runs the relay binary, can read its database and logs,
  can modify the software it runs.
- **Network observer**: sees traffic between a client and the relay (an ISP,
  a corporate proxy, a hotel Wi-Fi).
- **Stranger**: anyone who learns a user id. Ids are meant to be shareable.
- **Malicious contact**: someone you have added who later turns hostile.
- **Device thief**: someone with the client's data directory, with or
  without the running program's memory.
- **Compromised relay or identity key**: the attacker has the corresponding
  secret material.

## What each actor can and cannot do today

### Relay operator

Can:

- See every recipient id, every envelope size, and the timing of every
  send and delivery.
- See the network address and timing of the connection that submitted each
  envelope. With a relay and clients from 0.3.0 on, envelopes arrive on
  connections that never authenticate, so the relay is not told which
  identity sent them; it can still guess from addresses and timing, and a
  client that reaches a relay that offers no anonymous submission (or is
  told `--submit-authenticated`) submits on its authenticated connection,
  where the pairing is exact.
- Withhold, delay or reorder deliveries; drop mailboxes; refuse service.
- Serve a *stale* key bundle for a user, or withhold one-time prekeys so a
  session starts without one. It cannot serve a forged bundle or signed
  prekey: both are signed by the user's identity key and clients verify
  the signatures. A signed prekey older than three weeks is not used at
  all: the sender falls back to a message without forward secrecy and says
  so, rather than start a session its peer could never read.
- See that a file was sent and how big it is: the encrypted chunks are put
  and fetched on anonymous connections, but a blob of a certain size
  arriving from one address, a message delivered to a recipient, and a
  fetch of that blob shortly after from another address line up in time.
  It can also drop or withhold a blob, in which case the recipient sees a
  failed fetch. It cannot alter one: every chunk is authenticated under a
  key it does not have and bound to its position.
- Guess from sizes and timing that a small message going back right after
  a delivery is a receipt, and so that the recipient's client is running.

Cannot:

- Read message content, sequence numbers, timestamps, capabilities or
  receipts inside the body, or the content and name of a file.
- Forge a message from anyone: every body is signed by the sender's identity
  key and the signature is checked on the recipient.
- Impersonate a user to the relay: authentication is a signature over a
  fresh nonce and, from 0.6.0 on, the relay's own host name, so a login
  collected by one relay is worthless at another. (The older login without
  the host is still accepted from older clients unless the operator turns
  it off.)
- Re-address an envelope to a different recipient: the recipient id is bound
  into both the associated data and the signature.
- Replay an old envelope to its recipient undetected: envelope ids are
  deduplicated, sequence numbers are checked, and a ratchet message key is
  used once.

### Network observer

Sees the same as the relay operator when the transport is plain `ws://`
(recipient ids, sizes, timing, and which client connection sent what). Over
`wss://` on port 443 the observer sees only that a client talks to the relay
host, plus traffic volume and timing. TLS certificates are validated against
the operating system's trust store and Mozilla's roots; a corporate proxy
that inspects TLS with an installed root sees what the relay sees.

### Stranger who knows your id

Can send you messages until your mailbox is full, can fetch your public
key bundle, and by looking you up repeatedly can take your one-time
prekeys, though the relay hands out at most 30 an hour for one user;
sessions then start without one, which costs the first message the
fourth Diffie–Hellman term until the deposit is topped up. Cannot learn who
your contacts are from the relay. Their messages are decrypted but held in
the Requests pane until you accept them (at most 50 strangers, 20
messages each), and a blocked id is dropped on arrival. A file they
announce is never fetched while they are a stranger, and they get no
receipts, so they cannot tell whether you are there. On the relay, each
connection is limited to 60 messages, 30 lookups and 600 file chunks per
minute (30 messages for anonymous connections); each address to 16
connections, 20 new identities and 256 MiB of uploads an hour; mailboxes,
file storage and the number of identities are capped, and an operator can
require an invite token to register at all. Flooding a mailbox to its cap
remains possible for anyone with the id; filling the relay's shared file
storage now takes as many addresses as there are 256 MiB shares in it.

### Malicious contact

Can send you anything, including messages that claim any timestamp, and
files with any name and content; the client strips path separators from
the name and never overwrites, but what is inside the file is for you and
your other software to judge. Learns when their messages reached your
client and, unless you turn read receipts off, when you looked at them,
which says when you are at the keyboard. Cannot forge messages from
someone else. Cannot learn your other contacts. Cannot decrypt messages
between you and others.

### Device thief

With the data directory and no passphrase set, they get the identity keys,
the prekeys and session state, the full history, contacts, and any queued
outgoing messages. They can impersonate you and read future messages to
you. What they cannot do, thanks to the ratchet, is read v2 messages that
were already received and ratcheted past if those were recorded in transit:
the message keys are gone. With a passphrase set, every file is encrypted
under a key that only the passphrase unlocks (Argon2id, 64 MiB and 3
passes, then XChaCha20-Poly1305), so the thief is left guessing the
passphrase offline; a weak passphrase is the remaining risk. Received
files in `downloads/` are the exception: they are saved as ordinary files
so other programs can open them, and stay readable without the
passphrase. Memory of a
running, unlocked client still holds the keys. There is no way to revoke an
identity; the only remedy is to tell your contacts out of band and start a
new one. A backup file (`--export-backup`) is encrypted under its own
passphrase and holds the identity keys and contacts (not sessions or
prekeys), so it deserves the same care as the data directory. (Revocation
is not yet planned.)

### Compromised long-term Diffie–Hellman key

Opens the sealed layer of every envelope ever sent to that user, which
reveals the sender of each and, for v1 messages (from or to a client that
has not published prekeys), the content. For v2 messages the content is
protected by the session: without the session state and the private
prekeys of the time, it stays unreadable. With the prekeys as well, the
attacker can derive sessions started against those prekeys and read their
messages until the next DH ratchet step they cannot follow. Both keys live
in the same directory, so in practice this is the device-thief case above.

### Compromised identity key

The attacker can publish a new Diffie–Hellman key and prekeys for the
victim and read new messages sent to them, and can sign messages as them.
Contacts see the published key change (loudly) and their sessions with the
victim are dropped, but cannot tell a compromise from a legitimate reinstall
without comparing safety numbers out of band.

## Cryptographic design in brief

- **Identity**: Ed25519 signing key; its public key, base58-encoded, is the
  user id. Comparing ids is comparing public keys.
- **Key bundle**: the user's X25519 public key, signed with the identity key
  under a domain-separated prefix, plus (0.3.0 on) a signed medium-term
  prekey and a batch of unsigned one-time prekeys. Relays store and serve
  bundles and hand out one one-time key per lookup.
- **Envelope**: per message, a fresh X25519 ephemeral key; HKDF-SHA256 of the
  shared secret (info bound to both public keys) yields an XChaCha20-Poly1305
  key. The plaintext is `sender id || signature || body`; associated data is
  `recipient id || ephemeral public key`. The signature covers recipient,
  ephemeral key, nonce and body.
- **Sessions** (0.3.0 on): an X3DH handshake against the recipient's prekeys
  derives a root key; a Double Ratchet (HKDF-SHA256 root chain, HMAC-SHA256
  message chains, XChaCha20-Poly1305 per message) encrypts the body under a
  key used once and discarded. A new DH step whenever the conversation
  changes direction heals a compromised chain. The result is carried as the
  envelope body, so the sealed layer still hides the sender.
- **Relay auth**: the relay sends a 32-byte random nonce; the client signs it
  under a domain-separated prefix. Only the holder of an identity key can
  read that identity's mailbox. Submission needs no authentication at all.
- **Sequence numbers**: a per-conversation counter and a per-installation
  random epoch inside the body. Replays are dropped, gaps reported.
- **Receipts and capabilities** (0.4.0 on): both live inside the encrypted
  body, so the relay sees neither which clients have which features nor
  which messages were read.
- **Files** (0.4.0 on): a random per-file key and nonce; each 64 KiB chunk
  is XChaCha20-Poly1305 with the blob id, chunk index and chunk count as
  associated data, and the whole file's SHA-256 travels with the key
  inside the message. The relay stores ciphertext under a random id that
  only the message reveals.

Deliberately absent so far: deniability (messages are signed), padding of
message sizes, cover traffic, post-quantum key agreement.

## Trust decisions a user makes

1. **Which relay to use.** The relay is trusted for availability and for
   metadata, never for content.
2. **Whether an id belongs to who they think.** Adding a contact by id
   trusts the channel the id arrived over. Safety numbers (`/verify`) let
   two people confirm it by voice or in person.
3. **Whether to keep a key that changed.** A new Diffie–Hellman key signed by
   the same identity is either a reinstall or a stolen identity key. The
   client says so, drops the sessions, and leaves the decision to the user.

## Out of scope

- Compromise of the operating system or terminal of a running client.
- A relay that is itself the target of denial of service.
- Hiding the fact that someone uses Silver Messenger at all.
