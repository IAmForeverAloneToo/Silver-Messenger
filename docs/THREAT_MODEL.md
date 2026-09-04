# Threat model

What Silver Messenger protects, against whom, and where it currently falls
short. Every claim here is about the code on `main` today; the "Gaps" column
points at the roadmap item that closes each one. Keep this document honest
before adding features.

## Assets

| Asset | Where it lives | Why it matters |
| --- | --- | --- |
| Message content | Only on the two endpoints, and inside sealed envelopes in transit | The point of the program |
| Identity key (Ed25519) | `identity.json` on the client | Whoever holds it *is* you: can read new messages sent to you and sign as you |
| Diffie–Hellman key (X25519) | `identity.json` on the client | Decrypts every envelope ever addressed to you |
| Contact list and history | `contacts.json`, `history/`, `outbox.json` on the client | Who you talk to and what was said |
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
- See which **authenticated session** submitted each envelope. The sender
  id is sealed inside the ciphertext and absent from the envelope, but a
  client sends over the same connection it authenticated on, so the operator
  can correlate sender and recipient by watching connections. This is a
  metadata leak, not a content leak.
- Withhold, delay or reorder deliveries; drop mailboxes; refuse service.
- Serve a *stale* key bundle for a user. It cannot serve a forged one: bundles
  are signed by the user's identity key and clients verify the signature.

Cannot:

- Read message content, sequence numbers or timestamps inside the body.
- Forge a message from anyone: every body is signed by the sender's identity
  key and the signature is checked on the recipient.
- Impersonate a user to the relay: authentication is a signature over a
  fresh nonce.
- Re-address an envelope to a different recipient: the recipient id is bound
  into both the associated data and the signature.
- Replay an old envelope to its recipient undetected: envelope ids are
  deduplicated and, for numbered senders, sequence numbers are checked.

### Network observer

Sees the same as the relay operator when the transport is plain `ws://`
(recipient ids, sizes, timing, and which client connection sent what). Over
`wss://` on port 443 the observer sees only that a client talks to the relay
host, plus traffic volume and timing. TLS certificates are validated against
the operating system's trust store and Mozilla's roots; a corporate proxy
that inspects TLS with an installed root sees what the relay sees.

### Stranger who knows your id

Can send you messages until your mailbox is full, and can fetch your public
key bundle. Cannot learn who your contacts are from the relay. Today every
message from an unknown sender is accepted and creates a contact
automatically. (Gap: roadmap item 9.)

### Malicious contact

Can send you anything, including messages that claim any timestamp. Cannot
forge messages from someone else. Cannot learn your other contacts. Cannot
decrypt messages between you and others.

### Device thief

With the data directory and no passphrase set, they get the identity keys
(read all future messages to you and impersonate you), the full history,
contacts, and any queued outgoing messages. With a passphrase set, every
file is encrypted under a key that only the passphrase unlocks (Argon2id,
64 MiB and 3 passes, then XChaCha20-Poly1305), so the thief is left guessing
the passphrase offline; a weak passphrase is the remaining risk. Memory of a
running, unlocked client still holds the keys. There is no way to revoke an
identity; the only remedy is to tell your contacts out of band and start a
new one. (Gap: roadmap item 8 for backup; revocation is not yet planned.)

### Compromised long-term Diffie–Hellman key

Every envelope ever sent to that user, if it was recorded in transit or
kept by the relay, becomes readable. There is no forward secrecy yet. (Gap:
roadmap item 10, the ratchet.)

### Compromised identity key

The attacker can publish a new Diffie–Hellman key for the victim and read
new messages sent to them, and can sign messages as them. Contacts will see
the published key change (roadmap item 6 makes this loud) but cannot tell a
compromise from a legitimate reinstall without comparing safety numbers out
of band.

## Cryptographic design in brief

- **Identity**: Ed25519 signing key; its public key, base58-encoded, is the
  user id. Comparing ids is comparing public keys.
- **Key bundle**: the user's X25519 public key, signed with the identity key
  under a domain-separated prefix. Relays store and serve bundles.
- **Envelope**: per message, a fresh X25519 ephemeral key; HKDF-SHA256 of the
  shared secret (info bound to both public keys) yields an XChaCha20-Poly1305
  key. The plaintext is `sender id || signature || body`; associated data is
  `recipient id || ephemeral public key`. The signature covers recipient,
  ephemeral key, nonce and body. The body is JSON: timestamp, sequence
  number and epoch, and the content.
- **Relay auth**: the relay sends a 32-byte random nonce; the client signs it
  under a domain-separated prefix. Only the holder of an identity key can
  read that identity's mailbox.
- **Sequence numbers**: a per-conversation counter and a per-installation
  random epoch inside the body. Replays are dropped, gaps reported.

Deliberately absent so far: forward secrecy, post-compromise security,
deniability (messages are signed), padding of message sizes, cover traffic.

## Trust decisions a user makes

1. **Which relay to use.** The relay is trusted for availability and for
   metadata, never for content.
2. **Whether an id belongs to who they think.** Adding a contact by id
   trusts the channel the id arrived over. Safety numbers (item 6) let two
   people confirm it by voice or in person.
3. **Whether to keep a key that changed.** A new Diffie–Hellman key signed by
   the same identity is either a reinstall or a stolen identity key. The
   client will say so and leave the decision to the user (item 6).

## Out of scope

- Compromise of the operating system or terminal of a running client.
- A relay that is itself the target of denial of service.
- Hiding the fact that someone uses Silver Messenger at all.
