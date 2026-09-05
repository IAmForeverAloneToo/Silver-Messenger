# Threat model

What Silver Messenger protects, against whom, and where it falls short.
Every claim here is about the code on `main` at the end of Phase 7 (the
0.7.0 line). The "Gaps" section at the end points at the roadmap item that
closes each one, or says that nothing is planned. Keep this document honest
before adding features. The wire format is specified in
[PROTOCOL.md](PROTOCOL.md); how the code measures up control by control is
in [SECURITY_ASSESSMENT.md](SECURITY_ASSESSMENT.md); how to report a
problem is in [SECURITY.md](../SECURITY.md).

## What is assumed

- The user's operating system, terminal and hardware are not compromised.
  A keylogger or a screen recorder defeats everything below.
- The Rust toolchain and the crates the program is built from do what they
  say. What is done to make a tampered build detectable is under
  *Supply chain*.
- The relay operator is trusted for availability and, to the extent the
  sections below describe, for metadata. Never for content.
- Users can compare safety numbers out of band when it matters. Without
  that, an identity is whoever the relay first served it as.

## Assets

| Asset | Where it lives | Why it matters |
| --- | --- | --- |
| Message content | Only on the two endpoints, and inside sealed envelopes in transit | The point of the program |
| Identity key (Ed25519) | `identity.json` on the client | Whoever holds it *is* you: can sign as you and start sessions as you |
| Long-term Diffie–Hellman key (X25519) | `identity.json` on the client | Opens the sealed layer of every envelope ever addressed to you; with the session state, reads v2 messages |
| Prekeys and session state | `prekeys.json`, `sessions.json` on the client | Current ratchet keys and the private halves of published prekeys (X25519 and ML-KEM): reads messages in flight and the ones not yet ratcheted past |
| Contact list and history | `contacts.json`, `history/`, `outbox.json` on the client | Who you talk to and what was said |
| Received files | `downloads/` on the client, as ordinary files | Attachments people sent you; not covered by the data key |
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
- **Holder of a compromised key**: the attacker has a user's long-term
  Diffie–Hellman key or identity key.
- **Future quantum adversary**: someone who records traffic today and
  breaks X25519 and Ed25519 later.
- **Supply-chain attacker**: someone who can alter what users download or
  what the build consumes.

## What each actor can and cannot do

### Relay operator

Can:

- See every recipient id, the timing of every send and delivery, and
  every envelope's size to the nearest 160 bytes (bodies are padded in
  steps, so a receipt, a short and a medium message look alike; a long
  message is still visibly long).
- See the network address and timing of the connection that submitted each
  envelope. Envelopes arrive on connections that never authenticate, so
  the relay is not told which identity sent them; it can still guess from
  addresses and timing, and a client that reaches a relay offering no
  anonymous submission (or is told `--submit-authenticated`) submits on
  its authenticated connection, where the pairing is exact. A client that
  goes through Tor (`--proxy socks5://127.0.0.1:9050`) gives each
  connection its own circuit, so the two connections arrive from different
  exit addresses and the address tells the relay nothing; timing still
  does.
- Withhold, delay or reorder deliveries; drop mailboxes; refuse service.
  The administration that makes this a command rather than a database
  edit (evict an identity, ban an address or an identity, change the
  invite token) is over a Unix socket on the host that only root and the
  relay's user can open; there is no administration over the network,
  and nothing it offers shows a message or a key. A backup taken over the
  same socket holds what the database holds and no more, and is the
  operator's to keep as private as the database.
- Serve a *stale* key bundle for a user, or withhold one-time prekeys so a
  session starts without one. It cannot serve a forged bundle or signed
  prekey: both are signed by the user's identity key and clients verify
  the signatures. A signed prekey older than three weeks is not used at
  all: the sender falls back to a message without forward secrecy and says
  so, rather than start a session its peer could never read.
- Strip the ML-KEM keys from a bundle (a relay older than 0.6.0 does this
  without meaning to), so that the session starts with the classical
  handshake instead of the post-quantum one; or strip the signed
  `pq_ratchet` capability (a relay older than 0.8.0 does this without
  meaning to), so the ratchet is X25519 only rather than the post-quantum
  v4 ratchet. It cannot substitute an ML-KEM key, one-time ones included,
  nor forge the capability signature: all are signed. Either downgrade
  only removes protection the session would have added; the client shows
  which handshake and ratchet a session got, and `/session` says why.
- See that a file was sent and roughly how big it is (to the nearest
  64 KiB between clients that pad, exactly otherwise): the encrypted
  chunks are put and fetched on anonymous connections, but a blob of a
  certain size arriving from one address, a message delivered to a
  recipient, and a fetch of that blob some time after from another address
  line up in time. It can also drop or withhold a blob, in which case the
  recipient sees a failed fetch. It cannot alter one: every chunk is
  authenticated under a key it does not have and bound to its position.
- Guess from timing that a message going back some seconds after a
  delivery is a receipt, and so that the recipient's client is running.
  The guess is weak: receipts are the same size as short messages and
  leave after a random delay (up to two seconds for delivery, two to
  twelve for read receipts), so a receipt no longer marks the moment a
  message was read.

Cannot:

- Read message content, sequence numbers, timestamps, capabilities or
  receipts inside the body, or the content and name of a file.
- Forge a message from anyone: every body is signed by the sender's identity
  key and the signature is checked on the recipient.
- Impersonate a user to the relay, or to another relay: authentication is
  a signature over a fresh nonce and the relay's own host name, so a login
  collected by one relay is worthless at another. (The older login without
  the host is still accepted from older clients unless the operator turns
  it off with `--require-bound-auth`.)
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
that inspects TLS with an installed root sees what the relay sees, unless
the client carries a pin for the relay's key (`--pin`), in which case the
connection fails loudly instead of going through the proxy's certificate.
A relay once reached over `wss://` is never talked to over `ws://` again
by that client, so a changed URL (a bad invite link, a typo, a tampered
config file) cannot quietly strip the transport encryption. From 0.7.0
the relay terminates TLS itself and obtains its certificate over the same
port, so nothing but the relay sees the plain WebSocket; the certificate's
private key lives in the relay's data directory, readable by its user
only, which is the exposure a TLS front on the same host had. Through Tor
the observer near the client sees Tor traffic and nothing about the
relay; the relay's operator and anyone near the relay see Tor exit
addresses. A relay published as an onion service has no public address
at all, and its traffic never leaves the Tor network. Certificate revocation is not checked (no OCSP or CRL); a
revoked-but-unexpired certificate in the wrong hands is caught only by a
pin.

### Stranger who knows your id

Can send you messages until your mailbox is full, can fetch your public
key bundle, and by looking you up repeatedly can take your one-time
prekeys, though the relay hands out at most 30 an hour for one user;
sessions then start without one, which costs the first message the
fourth Diffie–Hellman term (and the one-time ML-KEM key; the signed one
still gives the post-quantum secret) until the deposit is topped up.
Cannot learn who your contacts are from the relay. Their messages are
decrypted but held in the Requests pane until you accept them (at most 50
strangers, 20 messages each), and a blocked id is dropped on arrival. A
file they announce is never fetched while they are a stranger, and they
get no receipts, so they cannot tell whether you are there. On the relay,
each connection is limited to 60 messages, 30 lookups and 600 file chunks
per minute (30 messages for anonymous connections); each address to 16
connections, 20 new identities and 256 MiB of uploads an hour; mailboxes,
file storage and the number of identities are capped, and an operator can
require an invite token to register at all. Flooding a mailbox to its cap
remains possible for anyone with the id; filling the relay's shared file
storage takes as many addresses as there are 256 MiB shares in it.

### Malicious contact

Can send you anything, including messages that claim any timestamp, and
files with any name and content. The client bounds all of it: messages are
cut at 4000 characters, a claimed send time at most two minutes ahead;
names are sanitised so that nothing they contain reaches the terminal or
the file system raw; a file is fetched only when you ask (or you told the
client to fetch that contact's files as they arrive), never overwrites,
and is refused for opening if the system would run it rather than show
it. What is inside the file is for you and your other software to judge.
They learn when their messages reached your client and, unless you turn
read receipts off, roughly when you looked at them, which says when you
are at the keyboard. Cannot forge messages from someone else. Cannot learn
your other contacts. Cannot decrypt messages between you and others.

### Device thief

With the data directory alone they get nothing readable on a system with
a key store (Windows Credential Manager, macOS Keychain, Secret Service):
the data key is wrapped under a random key kept there, so a copied
directory is useless elsewhere. With a passphrase set, every file is
encrypted under a key that only the passphrase unlocks (Argon2id, 64 MiB
and 3 passes, then XChaCha20-Poly1305), and the thief is left guessing
the passphrase offline; a weak passphrase is the remaining risk. Where
there is neither (no key store and no passphrase), the files are plain and
the client says so at start. Received files in `downloads/` are the
exception in every case: they are saved as ordinary files so other
programs can open them.

With the keys (a thief who also has the key store, the passphrase, or the
memory of a running, unlocked client), they get the identity keys, the
prekeys and session state, the full history, contacts, and any queued
outgoing messages. They can impersonate you and read future messages to
you. What they cannot do, thanks to the ratchet, is read messages that
were already received and ratcheted past if those were recorded in
transit: the message keys are gone. `/lock` and the idle lock drop the
keys from memory; core dumps are off, and on Linux the process is not
dumpable or traceable by other processes of the same user. There is no
way to revoke an identity; the only remedy is to tell your contacts out of
band and start a new one. A backup file (`--export-backup`) is encrypted
under its own passphrase and holds the identity keys and contacts (not
sessions or prekeys), so it deserves the same care as the data directory.

### Holder of a compromised long-term Diffie–Hellman key

Opens the sealed layer of every envelope ever sent to that user, which
reveals the sender of each and, for v1 messages (from or to a client that
has not published prekeys), the content. For session messages the content
is protected by the session: without the session state and the private
prekeys of the time, it stays unreadable. With the prekeys as well, the
attacker can derive sessions started against those prekeys and read their
messages until the next Diffie–Hellman ratchet step they cannot follow.
Both keys live in the same directory, so in practice this is the
device-thief case above.

### Holder of a compromised identity key

The attacker can publish a new Diffie–Hellman key and prekeys for the
victim and read new messages sent to them, and can sign messages as them.
Contacts see the published key change (loudly) and their sessions with the
victim are dropped, but cannot tell a compromise from a legitimate reinstall
without comparing safety numbers out of band.

### Future quantum adversary with a recording

A quantum computer that breaks X25519 opens, from a recording, the sealed
layer of every envelope (so: who sent what to whom, and the content of v1
messages) and the classical session handshakes, and so every session
started before 0.6.0 or against a peer or relay without ML-KEM support.
Sessions started with the post-quantum handshake stay closed: their key
also depends on an ML-KEM-768 secret the recording does not contain. In a
v2 session the ratchet steps after the handshake are X25519 only, so such
an adversary who also obtains the session key another way can follow the
ratchet forward from that point; a v4 session (0.8.0, both clients on it)
refreshes an ML-KEM secret at every step, so even an adversary who obtains
the session key heals out of it within a round trip. Signatures (Ed25519)
would let it forge messages *from the moment it has the power*, not
retroactively.

### Supply-chain attacker

Can put a tampered binary on a mirror, or a poisoned crate in the
dependency tree, or a bad step in the build. What stops each is under
*Supply chain* below; the short version is that a release can be
rebuilt bit for bit from its tag, carries GitHub's provenance and the
maintainer's signature, and embeds the exact dependency tree, so a
tampered download or build is detectable by anyone who checks. What is
not detectable this way is a compromised toolchain or runner (the
provenance would then be honestly issued for a dishonest build); an
independent rebuild is the answer to that.

## Cryptographic design in brief

- **Identity**: Ed25519 signing key; its public key, base58-encoded, is the
  user id. Comparing ids is comparing public keys.
- **Key bundle**: the user's X25519 public key, signed with the identity key
  under a domain-separated prefix, plus a signed medium-term prekey, a
  batch of unsigned one-time prekeys and, from 0.6.0, a signed medium-term
  ML-KEM-768 key and a batch of signed one-time ones. Relays store and
  serve bundles and hand out one one-time key of each kind per lookup.
- **Envelope**: per message, a fresh X25519 ephemeral key; HKDF-SHA256 of the
  shared secret (info bound to both public keys) yields an XChaCha20-Poly1305
  key. The plaintext is `sender id || signature || body`; associated data is
  `recipient id || ephemeral public key`. The signature covers recipient,
  ephemeral key, nonce and body.
- **Sessions**: an X3DH handshake against the recipient's prekeys derives a
  root key; a Double Ratchet (HKDF-SHA256 root chain, HMAC-SHA256 message
  chains, XChaCha20-Poly1305 per message) encrypts the body under a key
  used once and discarded. A new DH step whenever the conversation changes
  direction heals a compromised chain. The result is carried as the
  envelope body, so the sealed layer still hides the sender.
- **Post-quantum handshake** (0.6.0 on): the session key also depends on
  an ML-KEM-768 secret encapsulated to a signed key the recipient
  published (PQXDH-style), so a recording of today's traffic cannot be
  opened by a future quantum computer that breaks X25519, and a flaw in
  ML-KEM alone leaves the session as strong as before.
- **Post-quantum ratchet** (0.8.0 on, protocol v4): every ratchet step
  does an ML-KEM-768 step beside the X25519 one, so the session heals
  against a quantum adversary too, not only at the start. It runs when
  both clients advertise it (a signed `pq_ratchet` capability in the
  bundle) and the relay keeps the capability; otherwise the ratchet is
  X25519 only, which the client shows.
- **Deniability** (0.8.0 on, protocol v4): a v4 session message carries no
  signature at the sealed layer, so the recipient cannot prove to anyone
  else who wrote it. The session's AEAD authenticates it to the recipient,
  and the handshake is deniable. A v1 body (no prekeys) and a v2 session
  (an older peer or relay) are still signed; the client shows which a
  session is.
- **Relay auth**: the relay sends a 32-byte random nonce; the client signs it
  together with the relay's host name under a domain-separated prefix. Only
  the holder of an identity key can read that identity's mailbox.
  Submission needs no authentication at all.
- **Sequence numbers**: a per-conversation counter and a per-installation
  random epoch inside the body. Replays are dropped, gaps reported.
- **Receipts and capabilities**: both live inside the encrypted body, so the
  relay sees neither which clients have which features nor which messages
  were read.
- **Files**: a random per-file key and nonce; each 64 KiB chunk is
  XChaCha20-Poly1305 with the blob id, chunk index and chunk count as
  associated data, and the whole file's SHA-256 travels with the key
  inside the message. The relay stores ciphertext under a random id that
  only the message reveals.
- **Sizes and timing**: bodies are padded with spaces to 160-byte steps
  and, between clients that support it, the last file chunk to a whole
  64 KiB; receipts leave after a random delay. Both connections can go
  through a SOCKS5 proxy such as Tor, one circuit per connection.
- **At rest**: a per-installation data key, wrapped by the OS key store or
  by a passphrase through Argon2id; every file under it is
  XChaCha20-Poly1305.

Deliberately absent: cover traffic (roadmap item 46). Deniability is
provided for v4 sessions (above); v1 and v2 messages are still signed
until v1 is retired and every peer is on v4.

## Trust decisions a user makes

1. **Which relay to use.** The relay is trusted for availability and for
   metadata, never for content.
2. **Whether an id belongs to who they think.** Adding a contact by id
   trusts the channel the id arrived over. Safety numbers (`/verify`) let
   two people confirm it by voice or in person.
3. **Whether to keep a key that changed.** A new Diffie–Hellman key signed by
   the same identity is either a reinstall or a stolen identity key. The
   client says so, drops the sessions, and leaves the decision to the user.
4. **Whether to set a passphrase.** Without one, the data is as safe as the
   operating system's key store and login; with one, as safe as the
   passphrase.

## Supply chain

The software itself is an attack surface: a tampered download, a
poisoned dependency or a compromised build machine defeats every
protection above. What is done about that, from 0.6.0:

- **Builds you can check.** Release binaries are built from locked
  dependencies with build paths and timestamps removed, so rebuilding the
  tagged commit gives the same bytes; CI rebuilds the Linux binaries twice
  on every push and fails if they differ. The README says how to repeat
  the build and compare.
- **Provenance and signatures.** Every release file carries a SLSA build
  provenance attestation issued by GitHub for the workflow run that built
  it (`gh attestation verify`), and `SHA256SUMS` is signed with the
  project's minisign key once that key is set up (`minisign.pub` in the
  repository). The attestation says *which workflow built what from which
  commit*; the signature says *the maintainer published this*. Together
  they leave a hostile mirror, a swapped download, or a compromised GitHub
  account without the signing key nothing to offer that checks out.
- **What is inside.** Binaries are built with `cargo auditable`, so the
  exact dependency versions are embedded and `cargo audit bin` can check
  a binary against the advisory database years later; a CycloneDX SBOM
  is published next to each binary.
- **The build itself.** Every GitHub Action is pinned to a commit hash,
  workflow tokens can only read except where publishing needs to write,
  `cargo deny` refuses advisories, unexpected licences and unknown
  sources, and the OpenSSF Scorecard reports on the repository's
  practices in public. Pins are moved by hand; `cargo audit` on every
  push is what catches a vulnerable crate in the meantime.
- **Updates are never automatic.** `silver --check-release` asks the
  releases page once, on request, and prints the answer; nothing is
  downloaded or run.

Not addressed: a compromised Rust toolchain or GitHub-hosted runner (the
attestation would then be honestly issued for a dishonest build; the
reproducible-build check by an independent party is the answer), and a
maintainer's account plus signing key both being taken.

## What backs these claims

- The test suite: unit tests on every cryptographic operation with
  tampering cases, end-to-end tests through a real relay (sessions,
  handshakes waiting in the mailbox, restarts, lost state, anonymous
  submission, files, TLS with trusted and untrusted roots, key pins,
  proxies), pseudo-terminal tests of the client under two terminal types,
  and a test that renders peer-controlled text through the real terminal
  backend and asserts nothing unescaped reaches it.
- Fuzzing: `cargo fuzz` targets for every parser that sees peer or relay
  data, a minute each on every push, plus the same parsers under seeded
  random input in the ordinary test suite.
- Static checks: `forbid(unsafe_code)` in every crate but the terminal
  binary (one documented exception), clippy with warnings denied,
  `cargo audit`, `cargo deny`, the reproducible-build job.
- The control-by-control walk in [SECURITY_ASSESSMENT.md](SECURITY_ASSESSMENT.md).
- Not yet: a review by anyone who did not write the code. It is planned
  before 1.0 (roadmap item 35), and [SECURITY.md](../SECURITY.md) says how
  to get in touch about it.

## Gaps and where they close

| Gap | Status |
| --- | --- |
| Deniability: a recipient can prove who wrote what | Closed for v4 sessions (0.8.0): a v4 body carries no sealed-layer signature (`PROTOCOL.md` section 9). Still open for v1 bodies (no prekeys) and v2 sessions (older peer or relay), which stay signed until v1 is retired. |
| Cover traffic: the relay and the network see when messages travel and roughly how big they are | Roadmap item 46 (opt-in). Padding steps and receipt delays (0.6.0) are as far as this goes until then. |
| Post-quantum ratchet steps: after the hybrid handshake the ratchet is X25519 only | Closed for v4 sessions (0.8.0, roadmap item 41): every ratchet step does an ML-KEM step. A v2 session (older peer or relay) is still X25519-only after the handshake. |
| Identity revocation | Not planned; the remedy is a new identity and word of mouth. |
| Certificate revocation checking | Not planned; key pins are the mitigation. |
| Received files stored unencrypted in `downloads/` | By design, so other programs can open them; a "keep encrypted" option could follow if asked for. |
| History kept until the user removes it | By design; an expiry setting could follow if asked for. |
| A panic in the terminal client can leave the terminal in raw mode | Small; next client pass. |
| Group chats and multiple devices are not designed yet, so nothing here says what they protect | Roadmap items 47 and 48; this document grows when they do. |

## Out of scope

- Compromise of the operating system or terminal of a running client.
- A relay that is itself the target of denial of service.
- Hiding the fact that someone uses Silver Messenger at all.
