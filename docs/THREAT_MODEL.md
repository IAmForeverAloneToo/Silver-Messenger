# Threat model

What Silver Messenger protects, against whom, and where it falls short.
Every claim here is about the code on `main` at the end of Phase 10 and
the security review that followed it (the 0.12.3 line). The "Gaps" section at the end points at the roadmap item that
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
  *Supply chain*, which also says plainly what the release signature is
  and is not today.
- The relay operator is trusted for availability and, to the extent the
  sections below describe, for metadata. Never for content.
- Users can compare safety numbers out of band when it matters. Without
  that, an identity is whoever the relay first served it as.

## Assets

| Asset | Where it lives | Why it matters |
| --- | --- | --- |
| Message content | Only on the two endpoints, and inside sealed envelopes in transit | The point of the program |
| Identity key (Ed25519) | `identity.json` on the primary, and nowhere else | Whoever holds it *is* you: can sign as you, start sessions as you, and link and revoke devices |
| Long-term Diffie–Hellman key (X25519) | `identity.json` on each device, its own | Opens the sealed layer of every envelope ever addressed to that device; with the session state, reads v2 messages |
| Device key and certificate | `identity.json` on a linked device (its own Ed25519 and X25519 keys, and under `linked` the account's certificate for it) | Whoever holds them reads and writes as you, on that device, until the primary revokes it; the certificate itself is public |
| Device list and revocations | `devices.json` on every device (the list the primary publishes and the revocations it issued; on a linked device, as last synced) | Public, signed by the identity key; says which devices contacts seal to |
| Prekeys and session state | `prekeys.json`, `sessions.json` on the client | Current ratchet keys and the private halves of published prekeys (X25519 and ML-KEM): reads messages in flight and the ones not yet ratcheted past |
| Contact list and history | `contacts.json`, `history/`, `outbox.json` on the client | Who you talk to and what was said |
| Group state | `groups.mls`, `groups.json`, `history/group-*.jsonl` on the client | The MLS tree and epoch secrets of every group (reads its messages until the next commit you miss), the key package private halves, who is in which group, and what was said there |
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
- **Device thief**: someone with a client's data directory, with or
  without the running program's memory. From 0.9.0 that directory may be
  the primary's, which holds the identity key, or a linked device's,
  which holds a device key and a certificate and no identity key.
- **Program running as you**: an ordinary program started under the same
  account as the client, with no elevation and no debugger sent by an
  administrator. Against an unlocked client it reads what the client
  holds.
- **A line you did not write**: someone who gets a command onto the input
  line without the user reading it, by way of the clipboard, on a
  terminal that hands a paste over as keystrokes.
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
  message is still visibly long). Between two contacts who both turned
  cover traffic on (`/cover on`, protocol section 4.6), the timing says
  less while both clients run: meaningless messages go between them at
  random moments whether or not they are talking, so a real message is
  not told from cover by when it went or, for short and medium messages,
  by its size. The relay still sees that the two are in contact, sees
  bursts and long messages stand out, sees files, and sees each client
  connect and disconnect; nothing covers contacts who did not turn it on
  or are not around.
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
- Offer one client fewer features than another, and take back what it
  offered before: leaving `transparency` out of one client's login turns
  off that client's checking of the keys the relay serves, and leaving
  out `anonymous_send` makes it submit on the authenticated connection,
  where the relay sees which identity sent each message. From 0.11.0 the
  client remembers what each relay host has offered and says so, with
  what it costs, whenever something goes missing; the status line marks
  a connection whose sends are no longer anonymous, and
  `--require-anonymous` refuses to send at all rather than fall back.
- Keep a per-identity record of when each publish happened: the
  transparency log stores the time of every entry, and the log is served
  to anyone who asks, so a permanent timeline of when an identity was
  active is a side effect of the log being auditable at all. It is
  inherent to key transparency rather than a choice the relay makes, and
  it sits beside the journal's pseudonyms, which hide who is who in the
  log file but not this.
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
  From 0.15.0 it also says when that is *less* than a session with the
  same contact used to get. Showing the new session's protection was not
  enough on its own: a classical session with somebody whose sessions had
  all been post-quantum read exactly like a classical session with
  somebody who had never had one, so the one case worth noticing looked
  like the ordinary one. The strongest level a session with each contact
  has reached is kept with the contact, and a session below it is
  reported at the time and in `/session` for as long as it lasts. The
  client cannot tell a stripped bundle from a contact who moved to an
  older client — both arrive as a bundle without ML-KEM keys — so it
  says what changed, names both readings, and asks the user to check with
  the contact over another channel.
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
- See that a group exists and when it changes: the epoch sequencer
  (protocol section 13.5) keeps one counter and one hash per group,
  moved by commits that arrive on anonymous connections, so the relay
  learns that some group moved to epoch 12 at 10:04, and not who is in
  it or who committed. It holds no membership list.
- Infer a group's membership and size from delivery: a group message is
  a burst of envelopes from one connection to N recipients within a
  second, so the recipient set, repeated over time, is the group's
  membership minus the sender, and the burst size is its size. Cover
  traffic does not apply to groups; Tor hides the sender's address and
  nothing else about the burst.
- See who fetched whose key package: `key_package` goes on the
  authenticated connection, so the relay learns that A is about to add B
  to some group, as it learns that A looked B up before their first
  message. It also sees that each identity keeps key packages on
  deposit, which says the client reads groups, not that it is in any.
- See that a Welcome or a large commit went by, as a blob of that size
  (a group of a dozen or more members, or many added at once), the way
  it sees a file.
- See how many devices a person has, which ids they are and what the
  owner named them: the device list, certificates and names included,
  is in the signed bundle it serves, and each device logs in under its
  own id, so it pairs devices with accounts and sees each device's
  connections where it saw one client's. It sees a message to a person
  with two devices as two envelopes from one anonymous connection within
  a second, and the sender's copies to its own devices as more of them,
  so it infers device counts from bursts as it infers group sizes
  (protocol section 14). It learns nothing new about content or senders:
  a copy for another device is an ordinary sealed envelope.

Cannot:

- Read message content, sequence numbers, timestamps, capabilities or
  receipts inside the body, or the content and name of a file.
- Forge a message from anyone. A v1 or v2 body is signed by the sender's
  identity key and the signature is checked by the recipient. A v4 body
  is authenticated by the session's AEAD, whose keys only the two peers
  hold, together with the handshake's key-binding signature (protocol
  section 4.2.1), which is what stops a third party from standing in as
  the sender at the start; `formal/handshake_unbound.vp` is the model
  without it, and finds exactly that attack.
- Impersonate a user to the relay, or to another relay: authentication is
  a signature over a fresh nonce and the relay's own host name, so a login
  collected by one relay is worthless at another. The receiving relay
  compares that name with the names it is configured with, not with the
  header of the request it was reached by, which the party connecting
  writes; an operator whose relay is reached under a name it does not
  otherwise know gives it with `--host`, and one that knows no name says
  so at start. A client answers the older login, which signs the nonce
  alone and would be worth the same anywhere, only when started with
  `--allow-unbound-login`; relays still take it from clients that offer
  it unless the operator turns it off with `--require-bound-auth`.
- Re-address an envelope to a different recipient: the recipient id is bound
  into both the associated data and the signature.
- Replay an old envelope to its recipient undetected: envelope ids are
  deduplicated, sequence numbers are checked, and a ratchet message key is
  used once.
- Read a group message, learn a group's name or member list, add a
  member to a group, or forge a group message: every group message is
  MLS ciphertext under keys only members derive, the name and the admin
  list live inside the group context every member agrees on, a Welcome
  needs the group's secrets, a key package it hands out is verified
  against the identity that signed it before anyone is added on its
  strength, and every message is signed by its sender's leaf, which is
  the sender's identity key. It can move a group's epoch counter only
  with a token that members of the current epoch derive (it keeps a
  hash, not the token), and a removed member cannot either; what it can
  do to a group is what it can do to a mailbox, refuse or delay. Nor can
  a removed member take a group's id back by waiting: from 0.11.0 an
  entry the relay retires for sitting still leaves a headstone, and only
  the epoch and token hash the group ended at will raise it — which is
  to say, only somebody who was still a member then.
- Add a device to anyone's account, or forge a device certificate: the
  list is signed as a whole by the identity key and bound to the bundle,
  every certificate is the identity key's signature, and clients verify
  both. It can serve a stale list or keep serving a device its owner
  revoked, and is caught for either by the transparency log, where a
  device's bundles and its revocation are logged under the device as an
  identity's are; a revoked device is also refused by the relay itself
  and dropped by every contact the primary's next message reaches.
- Cut an identity off by treating it as somebody's device. An account
  signs a list, and a list is only that account's word: a key is a device
  of that account here when the bundle it published carries the account's
  certificate, and a revocation refuses a login, a publish or a delivery
  only while that is so. A relay that stored such a statement under an
  older rule refuses nothing on its strength, and its operator can drop
  it (`admin unrevoke-device`). Clients hold to the same rule: a
  revocation is acted on for a device already known as that account's,
  whoever handed it over.
- Have a message sent without forward secrecy by taking every prekey out
  of the bundle it serves. Prekeys are optional, so a stripped bundle's
  signature still checks out and only the client's own memory tells the
  two apart: a client that already holds a bundle with prekeys for that
  contact keeps it, says the relay is now serving them without, and
  starts the session from the keys it knows; a client that holds nothing
  refuses to send rather than fall back to the old plain body, which
  whoever later holds the recipient's identity key could read. What the
  relay can still do is serve a *stale* bundle, and a signed prekey older
  than three weeks is not used at all (above).
- Bury a revocation by making the answer that carries it fail. A
  revocation or a succession is signed by its own subject, so one that
  verifies is raised to the user even when the transparency check refuses
  the answer around it. A refusal also stops the send that asked for the
  lookup: nothing goes out under a bundle already held while the log and
  what the relay serves disagree.

### Network observer

Sees the same as the relay operator when the transport is plain `ws://`
(recipient ids, sizes, timing, and which client connection sent what). Over
`wss://` on port 443 the observer sees only that a client talks to the relay
host, plus traffic volume and timing. TLS certificates are validated against
the operating system's trust store and Mozilla's roots; a corporate proxy
that inspects TLS with an installed root sees what the relay sees, unless
the client carries a pin for the relay's key (`--pin`), in which case the
connection fails loudly instead of going through the proxy's certificate.
The pin is matched against the certificate the server proves it holds the
key for, and nothing else it sends: the relay's real certificate is
public, so a proxy could otherwise append it to its own chain and have
the pin match the connection it is reading.
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
decrypted but held as a request -- an entry of the chat list that shows
their id and nothing they chose -- until you accept them (at most 50
strangers, 20 messages each), and a blocked id is dropped on arrival. A
file they announce is never fetched while they are a stranger, and they
get no receipts, so they cannot tell whether you are there: reading,
declining and blocking all look like silence to them. They can ring your
terminal once, with their first message; declined, they cannot ring it
again until you accept them, since a declined stranger's next request
waits without a bell or a notification (`docs/design/requests.md`). On the relay,
each connection is limited to 60 messages, 30 lookups and 600 file chunks
per minute (30 messages for anonymous connections); each address to 16
connections, 20 new identities and 256 MiB of uploads an hour; mailboxes,
file storage and the number of identities are capped, and an operator can
require an invite token to register at all. Flooding a mailbox to its cap
remains possible for anyone with the id; filling the relay's shared file
storage takes as many addresses as there are 256 MiB shares in it. What a
full mailbox costs the relay is disk, not memory: from 0.11.0 a
connection is handed at most sixteen envelopes at a time and the rest as
it acknowledges them, so the size of what is waiting does not decide how
much the relay holds for the reader, and a connection that stops reading
is closed after thirty seconds rather than left with a queue. From
your bundle they also learn how many devices you have, their ids and the
names you gave them (the certificates are in the bundle, so a name like
"office" is public; the client shows names to your own devices only),
can look each up as they look you up, and can fill each device's mailbox
as they can yours. Knowing a device's id does not let them cut it off:
they can sign a device revocation naming it, since a signature is only
their own word, but a client acts on one for a device it knows as that
account's, and the relay takes one only from the account the device
claims.

### Malicious contact

Can send you anything, including messages that claim any timestamp, and
files with any name and content. The client bounds all of it: a message
held from a stranger, before you accept them, is cut at 4000 characters,
and every message of any kind is bounded by the 32 KiB body it travels in
(`PROTOCOL.md` section 3); a claimed send time is at most two minutes
ahead;
names are sanitised so that nothing they contain reaches the terminal or
the file system raw; a file is fetched only when you ask (or you told the
client to fetch that contact's files as they arrive), never overwrites,
and reaches the system's opener only if its kind is one that is *shown*
rather than run (0.11.0: an allowlist — pictures, PDFs, text, sound,
video, archives — where before it was a list of dangerous extensions
that was always one entry short of a new one). Anything else you can
still open yourself from the downloads folder, which is your computer's
decision to make and not this program's. On Windows every copy carries
the mark of the web, the plain copy `/open` makes of an encrypted
download included, so SmartScreen, Protected View and Office's macro
blocking apply to it; a copy that could not be marked is not handed over
silently. What is inside the file is for you and your other software to judge.
What they write is filtered wherever it leaves the screen as well as on
it (0.11.0): the plain-text export, the clipboard (which OSC 52 carries
to the local terminal through SSH or tmux), the reader's spoken lines
and its compose echo. A line break in a message stays inside its line
where a line is the unit, so nothing they send reads as a second
message, as another member, or as one of this program's own warnings;
and a conversation note is one because this client wrote it, not because
the text starts the way a note does.
Nothing they write picks the file that `/open` or `/files decrypt` acts
on: where a received file went is what the download recorded, and only
`downloads/` is reachable either way, so a message whose text is dressed
up as a saved file (`[file] notes.txt → …/identity.json`) opens nothing
and decrypts nothing.
They learn when their messages reached your client and, unless you turn
read receipts off, roughly when you looked at them, which says when you
are at the keyboard. Cannot forge messages from someone else. Cannot learn
your other contacts. Cannot decrypt messages between you and others.
Cannot pass a device off as yours or as anyone else's: a device
certificate verifies only against the account it names, a body whose
certificate does not verify for the key that sealed the envelope is
dropped as a forgery, and a `sync` message from anyone but your own
devices is dropped without a word. What they learn of your devices is
what a stranger learns from your bundle, plus which device each message
of yours came from, which the certificate in it says.

From 0.10.0 they can edit and delete their own messages, which changes
what your screen shows of *them* and nothing of what you wrote: the
author check is on the sealed sender (the MLS sender in a group), which
cannot be forged, so they cannot edit, delete or react as anyone else,
and your history keeps every version of what they sent, which the
export shows. A member who saw a message before you did cannot edit or
suppress it on the author's behalf either: an edit or a tombstone kept
for a message that has not arrived applies only to that person's own.
A timer they set removes, from your side on your client's own clock,
the messages sent or received from then on, and the note in the
conversation says they set it; what you read before stays, and an
export or a backup taken before keeps its copy. A reaction is a short
string of their choosing, bounded and cleaned like a name. What a
deletion or a timer of *yours* does on their side is a promise their
software keeps or does not: an unmodified client on 0.10.0 or later
removes the message when the deletion reaches it or the timer runs
out; a modified client, a screenshot, an export or a backup taken
before, a file they already saved, and what they remember are beyond
it, and the client never claims otherwise.

In a group, a contact who is a member sees everything said in it, as in
any group, and learns the member list, which is what a group is. A
contact who invites you to a group makes your client join it in MLS
terms at once (the key package is spent; nothing is shown until you say
yes); a stranger's invitation waits as an entry of the chat list, labelled
an invitation and showing the inviter's id beside the name they chose,
and rings nothing; a blocked sender's is declined unseen. Because joining
takes the group id, a
second Welcome for a group already joined or already inviting is
refused, and declining is what makes room for another: whoever sends the
first Welcome for an id cannot be allowed to decide what that id is,
since a group id is known to whoever ever held an invite link or was
once a member, and the admin list inside a Welcome is written by whoever
built it. For the same reason a newly linked device takes a group
without asking only from its own account, which is who puts a device of
yours in a group; a Welcome from anyone else for a group your primary
named at link time is an ordinary invitation, shown under the name its
own author gave.

A member's messages cost the others only what they carry. A commit or a
Welcome too large for its envelope is parked on the relay and fetched by
everyone it reaches, so it is capped at 1 MiB (a commit adding 255
members is about 695 KiB) rather than at the file limit, fetched once
per blob whatever names it, and fetched at all only for a group the
client is in or as a Welcome, which is how a group first arrives. A
handshake from a future epoch, which nothing has read yet, is kept only
when it travelled inside its envelope, and within a size (384 KiB per
group) as well as a count; anything else puts the group out of sync,
which rejoins.

A member who turns hostile can send a commit that breaks the group's
rules (an add or a removal by a non-admin, a group left without admins,
a changed ciphersuite); every
honest client refuses it, marks the group broken naming the sender, and
stops there, so the rogue member can wedge the group, which an admin
then makes anew without them, but cannot get an intruder's keys accepted
or read on after being removed. An admin controls membership: a
compromised admin can add anyone and remove anyone until the other
admins remove it, and a group with one admin is that person's to keep
or lose. A member who leaves keeps whatever it read; a removed one reads
nothing sent after the commit that removed it, and nothing before it
that was not already delivered. Group messages are not deniable: MLS
signs every one with the sender's identity key, so a member can prove
to a third party who wrote what, which one-to-one v4 messages do not
allow and which is why one-to-one conversations stay on the ratchet.

### Device thief

With the data directory alone they get nothing readable on a system with
a key store (Windows Credential Manager, macOS Keychain, Secret Service):
the data key is wrapped under a random key kept there, so a copied
directory is useless elsewhere. With a passphrase set, every file is
encrypted under a key that only the passphrase unlocks (Argon2id, 64 MiB
and 3 passes, then XChaCha20-Poly1305), and the thief is left guessing
the passphrase offline; a weak passphrase is the remaining risk.
Changing the passphrase, or moving between it and the key store, moves
the files onto a fresh data key (0.11.0), so somebody holding an old copy
of `vault.json` and the passphrase that was in force when they took it
reads nothing written after the change — which is what changing a
passphrase is for. The key that is moved off is taken out of the key
store as part of the change, and from 0.15.0 so is the key of a directory
that is erased and the key of a change that failed before the vault
naming it was written: until then, erasing a device left its wrapping key
in the key store, where an old copy of the directory taken before the
erase still had something to be opened with, and a program of the same
user could read it. That last part only held while the process lived to
run its own error paths, so 0.15.0 also writes the name of a key whose
fate is undecided to `vault.pending` *before* the step that could orphan
it — creating the key, or removing the vault that names it — and the next
start takes out anything that file names and the vault does not need. A
crash, a kill or a power loss in that window therefore costs an extra
start, not a key left in the store for good. The same check refuses to
delete when the vault cannot be read at all rather than when it says no:
an unreadable vault is the absence of an answer, and acting on it would
throw away the key that opens every file in the directory. Where
there is neither (no key store and no passphrase), the files are plain and
the client says so at start. Plain or not, the data directory and every
file in it are the owner's alone (0.11.0: the directory 0700, the files
0600, an existing directory tightened on the way) — on Unix. Those are
Unix permissions and the code that sets them is compiled only there;
on Windows the data directory takes the access rules it inherits, which
under a user profile keep other unprivileged users out and, for a
`--data-dir` placed somewhere world-writable, do not. This is the same
shape as the process hardening of 0.15.0: said plainly rather than
implied to be the same everywhere. Where the permissions do apply, a
shared machine's other users do not read the settings — which hold the proxy's credentials
and the invite token — the contact list, or the history. Received files in `downloads/` are saved
as ordinary files so other programs can open them, unless `/files
encrypt on` was chosen (0.10.0), which writes them under the data key
like the rest; `/open` then hands the opener a private plain copy under
`downloads/.open/`, removed when the client exits and at its next start,
and `/files decrypt` writes a plain copy on request. Both act on
`downloads/` and nothing else: where a received file went is recorded by
the download that wrote it, not read back out of the line's text, which
is the sender's to write, and a path outside that directory is refused
whatever names it — the key that reads a file kept as ciphertext reads
every other file of the directory too. Messages that ran
out (a timer) or were deleted are rewritten out of the history files
rather than marked, so the directory does not hold them; the placeholder
of a message its author deleted for everyone stays, without the text.

With the keys (a thief who also has the key store, the passphrase, or the
memory of a running, unlocked client), they get the keys the directory
holds (on the primary the identity key, on a linked device its own device
key and certificate), the prekeys and session state, the full history,
contacts, and any queued outgoing messages. They can impersonate you and
read future messages to you. What they cannot do, thanks to the ratchet, is read messages that
were already received and ratcheted past if those were recorded in
transit: the message keys are gone. The same holds for groups: the
thief reads and writes in every group you are in until the next commit
their copy cannot follow (every member's client refreshes its leaf
within a week, and any add or removal is such a commit), and past group
messages recorded in transit stay closed, since MLS deletes each
message key after use and the epoch secrets of past epochs after three
epochs; the key package private halves in the same file let them accept
an invitation meant for you until those packages are used up or expire. `/lock` and the idle lock drop the
keys from memory, along with the contacts and history that were decrypted
beside them, since the client is torn down and built again; core dumps
are off, and a process of the same user is kept from reading this one's
memory as far as each platform allows ("Program running as you"). To retire the
identity itself there is a pre-signed revocation certificate (`/revoke`,
protocol section 10), minted on first run and kept aside so the key can be
declared dead even after it is lost; contacts that see it stop trusting the
key. The same certificate in a thief's hands is a denial of service — they
can publish it and kill your identity — which you recover from by starting
a new one, so it is no worse than the loss of the keys it sits beside. A
backup file (`--export-backup`) is encrypted under its own passphrase and
holds the identity keys, the revocation certificate, contacts and the
device list (not sessions or prekeys), so it deserves the same care as
the data directory.

From 0.9.0 the directory may be one device of several (protocol section
14), and which one matters. A **linked device's** thief gets what that
device holds: its history from the day it was linked (and the snapshot
of recent history and the contact list it was given then), its sessions
with every contact's devices and with its siblings, the group epochs it
is in, and the power to read and write as you until the primary revokes
it, which `/devices remove` does at once. They do not get the identity
key. Once the device is revoked, contacts have nothing to re-verify and
the safety number is what it was: the revocation is served and logged
by the relay, which cuts the device off, and pushed to contacts inside
the next message, and they drop their sessions with the device; its
leaves go from every group with the next commit, so it reads nothing
sent after. A **primary's** thief gets what the identity thief above
gets, and with it the power to link devices of their own and to revoke
yours; the pre-signed revocation certificate ends the identity, devices
included. A device the relay tells it is revoked stops and says so, but
does not erase itself on the relay's word, since a hostile relay could
say it falsely; its owner erases it (`/devices leave confirm`, or by
hand). What is no better than before: every device holds every
conversation from the day it was linked, so one device taken exposes
what you read on any of them, which is the price of having the message
on every device and the reason to link only computers you keep.

A desktop notification (0.13.0) says `Silver Messenger` and `New message`
and nothing else, whichever path raises it — the terminal's own sequences
or the operating system's notification service — so what a lock screen,
a notification history or a glance at the screen learns is that a message
arrived and when; never from whom, and never what. The call that raises
one takes no text, so this holds by construction rather than by care. The
unread count stays in the terminal's window title, which does not leave
the terminal. Design note
[docs/design/notifications.md](design/notifications.md).

### Program running as you

Not the operating system's owner and not a debugger sent by an
administrator: an ordinary program, started under the same account as the
client, of the kind a user runs by accident. Against a client that is
unlocked it wins, and that is a property of the machine rather than of
this program: to show a message the client must hold it in memory, and
memory belonging to your account is in reach of your account. It reads
the keys, the contacts and the history without needing the passphrase or
the key store, and the data directory is its to copy in any case. This
was demonstrated on Windows 11 against 0.14.0 by a program with no
elevation, which read the keys out of the running client.

What the client does anyway is raise the cost, and it differs by platform
because what the platforms offer differs:

| Platform | What is done | What it leaves |
| --- | --- | --- |
| Linux | No core file, and the process is not dumpable, so a process of the same user may neither trace it nor read `/proc/<pid>/mem` | Root, and anything already attached |
| Windows (0.15.0) | No core file, and the process object carries a restricted access list, so opening it for reading is refused | An attacker who rewrites that list first, which the owner of a process may do; and an administrator |
| macOS | No core file | A debugger run by the same user, which macOS allows for a program it started; this is an open gap with no good answer short of signing the program and asking Apple for the hardened runtime |

None of it touches a program that attached before the client started, and
none of it is prevention. The boundary that does hold is the lock:
`/lock`, the idle lock and quitting take the whole client down and build
it again from the passphrase, so the keys, the decrypted contacts and the
history are gone from memory and not merely marked unreadable. A client
left unlocked and unattended is the case none of this covers.

Two further paths lead out of memory and are not closed here. Pages of an
unlocked client may be written to swap or to a hibernation image and
outlive the process; the client does not pin its pages in memory, and
pinning the key alone would not cover the messages beside it, so
full-disk encryption is what answers this one. And an attacker who can
write where the client is read from replaces the program itself, against
which a signature on a release is worth only as much as the check the
person makes before running it.

### A line you did not write

Not on your computer at all: someone who gets a command onto your input
line without your reading it. The clipboard is the way in — a web page
whose copy button hands over more than it showed, a "paste this to fix
the error" in a support chat, a clipboard-history tool with an entry from
somewhere else — and it works because a terminal without bracketed paste
(the Linux console, older Windows consoles, some multiplexer setups)
delivers a paste as ordinary keystrokes, so a carriage return inside it
submits the line and starts the next one.

Two controls answer this, and which one applies is a judgement about the
command's argument rather than about its blast radius.

Where the argument is something a person can type — a file path — the
paste guard is the whole answer. The client measures how fast the line
arrived: a paste is microseconds a character, four milliseconds a
character is three thousand words a minute, and a line that came in
faster than anyone types is refused with the remedy of typing it out.
`/send`, `/revoke`, `/rotate` and `/devices leave` are guarded this way.

Where the argument is itself pasted by design — a device link, a group
link, a relay URL, all of which carry ids and secrets nobody types — the
guard alone would be a control that cannot be satisfied, so the command
is split. The first line parses it, checks it, and says what it would do:
`/devices link` names the certificate the identity would sign and that
the device thereafter reads and writes as the account; `/relay` names the
network being left; `/group join` names who learns your id. Then it
stops, and a short second line goes ahead — and that line, three words
long, is the one the guard sits on. The held command is forgotten after
two minutes and replaced by any later one, so a confirmation always
answers the question last put.

What this does not cover: a person who reads the sentence and confirms
anyway, and a terminal where the attacker can drive the keyboard rather
than the clipboard, which is the *Program running as you* case above.
`docs/design/consequential-commands.md` records which commands take which
control and why the list is meant to stay short — a confirmation answered
by reflex spends the attention the three commands above need.

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
without comparing safety numbers out of band. The victim recovers by
retiring the key: `/revoke` declares it dead so contacts stop trusting it,
and `/rotate` hands over to a fresh identity with a cross-signed succession
so contacts re-pin to the new key on their own (protocol section 10). A
revocation is final: the relay serves no succession for a revoked key and
a contact ignores one, so the attacker cannot answer the revocation by
naming their own successor. What remains is a race on the succession
alone — an attacker's succession that a contact applied before the
victim's revocation is not undone by it, since the contact no longer has
the old key pinned — and nothing here undoes what was already read. It
does end the attacker's ability to be taken for the victim going forward,
and the pre-signed certificate lets the victim revoke even when the
attacker took the only copy of the key. With the identity key the
attacker can also certify devices of their own and revoke the victim's:
a device the victim did not link shows in `/devices`, every list change
is a logged bundle change, and the revocation ends every device with the
identity.

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
retroactively. Groups are on the hybrid MLS ciphersuite (X-Wing: ML-KEM-768
with X25519, protocol section 13.1), so a recording of a group's traffic
stays closed the same way; the sealed layer around each group envelope is
X25519 alone and opens to such an adversary as every sealed layer does,
revealing the sender of each envelope and nothing of the MLS ciphertext
inside.

What this rests on is worth naming. The ML-KEM implementation comes from
`ml-kem`, and the group ciphersuite's from `x-wing` on top of it; both
crates say of themselves that they have never been independently
audited. The hybrid construction is the answer to that: every key that
uses ML-KEM combines it with X25519, so a flaw in the ML-KEM half cannot
take a session below the classical strength it would have had without
it. What a flaw could still do is panic on a ciphertext someone chose,
since decapsulation is reachable from the wire on every handshake and
every post-quantum ratchet step; the `pq` fuzz target exercises exactly
that, with crafted ciphertexts and with real ones damaged. A formally
verified backend (`libcrux-ml-kem`, already in the tree under `hpke-rs`)
is the intended replacement once one API serves both paths.

### Supply-chain attacker

Can put a tampered binary on a mirror, or a poisoned crate in the
dependency tree, or a bad step in the build. What stops each is under
*Supply chain* below; the short version is that a release can be
rebuilt bit for bit from its tag, carries GitHub's provenance (a
maintainer's signature is designed for and not published yet), and
embeds the exact dependency tree, so a tampered download or build is
detectable by anyone who checks. What is
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
  direction heals a compromised chain against an attacker who, after the
  compromise, only listens; one who keeps injecting ratchet keys of its
  own stays in, which no ratchet prevents and the models in `formal/`
  state. The result is carried as the envelope body, so the sealed layer
  still hides the sender.
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
  and the handshake is deniable. A v2 session (an older peer or relay) is
  still signed, as is a v1 body, which from 0.10.1 is sent only by a
  client built without a session store and where a peer's prekeys are too
  old to start a session; the client shows which a session is.
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
  64 KiB; receipts leave after a random delay. Cover traffic, opt-in and
  mutual (`/cover on`), sends meaningless messages at random intervals
  (30 seconds to three minutes) to contacts who do the same, for ten
  minutes after each message from them, so two running clients cover
  each other while both are around. Both connections can go through a
  SOCKS5 proxy such as Tor, one circuit per connection.
- **Groups** (0.9.0 on): MLS (RFC 9420) through OpenMLS on the
  `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519` suite (X-Wing HPKE,
  AES-128-GCM, SHA-256, Ed25519), each member's leaf signed by its
  identity key and carrying its sealing key. A group message is one MLS
  ciphertext sealed separately to every member into the ordinary
  envelope, so the relay sees N envelopes and no group; membership
  changes are commits every member checks against the group's own rules
  (admins add and remove; anyone may leave), ordered by a counter the
  relay keeps per group and moves only for a token members of the
  current epoch can derive. Forward secrecy and post-compromise security
  across membership changes are MLS's; every member refreshes its leaf
  within a week. Group messages are signed inside MLS and are not
  deniable.
- **Devices** (0.9.0 on): a linked device is a key pair of its own
  (Ed25519 and X25519, like an identity's) with a certificate signed by
  the identity key, which never leaves the primary; the account's bundle
  lists its devices, signed as a whole and bound to the bundle. A message
  is sealed once per device of the recipient's and once per other device
  of the sender's, each under its own Double Ratchet session, so every
  device has it and no key is shared between devices. A device is
  revoked by a signed statement the relay serves, logs and enforces and
  contacts act on. Linking sends the new device its certificate and a
  snapshot through the relay, sealed under a key from a one-time secret
  the device printed. In groups a device is a leaf of its own, signed by
  the device key with the certificate in the leaf.
- **At rest**: a per-installation data key, wrapped by the OS key store or
  by a passphrase through Argon2id; every file under it is
  XChaCha20-Poly1305.

Deliberately off by default: cover traffic (`/cover on`, roadmap item
46), which costs bandwidth on both sides and the relay. Deniability is
provided for v4 sessions (above); v1 and v2 messages are still signed
until v1 is retired and every peer is on v4, and group messages are
signed by design.

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
5. **Whether to join a group, and whom to make an admin.** A group's
   members see everything said in it and each other's ids; an admin
   decides who those members are. An invitation from a contact is taken
   on your behalf; one from a stranger waits for you.
6. **Which computers to link.** A linked device reads and writes as you
   until you remove it, and holds every conversation from the day it was
   linked. Its loss costs what it held and nothing a contact must
   re-check; the primary's loss is the identity's.

## Supply chain

The software itself is an attack surface: a tampered download, a
poisoned dependency or a compromised build machine defeats every
protection above. What is done about that, from 0.6.0:

- **Builds you can check.** Release binaries are built from locked
  dependencies with build paths and timestamps removed, so rebuilding the
  tagged commit gives the same bytes; CI rebuilds the Linux binaries twice
  on every push and fails if they differ. The README says how to repeat
  the build and compare.
- **Provenance, and a signature that is not there yet.** Every release
  file carries a SLSA build provenance attestation issued by GitHub for
  the workflow run that built it (`gh attestation verify`): it says
  *which workflow built what from which commit*, and GitHub's
  transparency log holds the record. That is what a download can be
  checked against today, and it defeats a hostile mirror or a swapped
  file. It does not defeat GitHub, or whoever holds the maintainer's
  account: an attestation issued for a workflow run they started is
  honestly issued.

  A maintainer's signature over `SHA256SUMS` would be the independent
  root, and there is none: the repository publishes no `minisign.pub`, so
  every release so far is unsigned by the maintainer and the run says so.
  When one is set up it is set up off this platform — generated and kept
  on a machine the maintainer holds, `SHA256SUMS` signed there after each
  release and the signature attached by hand. The release workflow does
  not sign and holds no signing key, on purpose: a key it could use would
  live where the build lives, so a compromised account or a workflow run
  with access to secrets could sign with it, and it would say exactly
  what the attestation says. Until the key exists, the attestation is the
  whole of it, and this section is to be read that way.
- **What is inside.** Binaries are built with `cargo auditable`, so the
  exact dependency versions are embedded and `cargo audit bin` can check
  a binary against the advisory database years later; a CycloneDX SBOM
  is published next to each binary.
- **The build itself.** Every GitHub Action is pinned to a commit hash,
  every container image the build and the tests use is pinned by digest,
  and the compiler is pinned to an exact version in `rust-toolchain.toml`
  rather than floating on "stable", so a rebuild a year later uses the
  compiler the release used and a verifier reads it off the tag instead
  of out of expiring workflow logs. Workflow tokens can only read except
  where publishing needs to write, `cargo deny` refuses advisories,
  unexpected licences and unknown sources, and the OpenSSF Scorecard
  reports on the repository's practices in public. Pins are moved by
  hand; `cargo audit` on every push is what catches a vulnerable crate in
  the meantime. Anyone who can run a workflow in this repository can
  publish a release from any commit — standard GitHub behaviour, and a
  reason the account itself is the thing to protect.

  What is in the tree is worth stating too. `cargo audit` reports no
  vulnerability; it reports one unmaintained crate, `proc-macro-error2`,
  a build-time procedural-macro helper reached through the verified
  cryptography crates under OpenMLS, which is not in the binary. Several
  dependencies appear in two major versions at once (`curve25519-dalek`,
  `x25519-dalek`, `rand`, `getrandom`, `hkdf`/`hmac`/`sha2`,
  `tokio-tungstenite`) because upstreams have not converged; each
  duplicate is more code in the binary and more advisories to track, and
  `cargo deny` warns about them on every run rather than failing, since
  the fix is upstream and not here.
- **Updates are never automatic** (0.12.0 on). `silver update` downloads
  and installs, and it runs only when a person runs it: the interface's
  `/update` reports and installs nothing, and the `update_check` setting
  -- off unless turned on -- asks the releases page once a day and prints
  a line, never downloading. What an update is checked against before the
  running binary is touched: the SHA-256 the release API reports, which
  arrives from a different origin than the bytes; the same hash in
  `SHA256SUMS`; the project's signature over `SHA256SUMS`, against the
  key compiled into the client from `minisign.pub`, so the key is not
  something the network can substitute; and the downloaded file reporting
  the version expected of it. A release the signature does not cover is
  refused. What this does not defend against is the release host itself,
  and the account that can run the signing workflow -- the same limit as
  the signature it rests on, above. Every request goes through the proxy
  the relay connection uses, so a client on Tor does not step outside it
  to ask about updates.
- **Packages add convenience, not trust** (0.10.0 on). The Debian
  package is built by the release workflow from the release binaries, so
  it carries the same bytes, and it is listed in `SHA256SUMS`, signed
  and attested with them; the Homebrew tap installs those binaries by
  their checksums and nothing else. Those two are what the project
  publishes; anything else that packages it is somebody else's, and
  `silver update` refuses to replace a binary a package manager owns. A code signature on the Windows or macOS executable,
  when the maintainer's certificate or Apple membership is in the
  repository's secrets, says the platform's own checker can name the
  signer; it adds no bytes the attestation does not cover, and a signed
  download compares with a rebuild once the signature is stripped
  (README, "Verifying a release"). Without the secrets the workflow
  says so and the platform goes out unsigned, as before.

Not addressed: a compromised Rust toolchain or GitHub-hosted runner (the
attestation would then be honestly issued for a dishonest build; the
reproducible-build check by an independent party is the answer), and a
maintainer's GitHub account being taken — from 0.12.0 the release
signature is made in the workflow from a repository secret, so whoever
can run a workflow can sign, and only a key kept off this platform would
change that.

## What backs these claims

- Formal models: Verifpal models of the handshake (v2 and v4, with and
  without a one-time prekey, against a classical and a quantum-capable
  adversary) and of the ratchet (v2 and v4, against a passive adversary
  that reads both devices mid-conversation, a quantum-capable one, and an
  active one), in `formal/`. Each query's outcome is recorded and checked
  in CI on every push, including the models that are meant to break (the
  v4 handshake without its key-binding signature, a handshake without a
  one-time prekey under a later compromise of the signed prekeys, the v2
  ratchet against an adversary that breaks X25519), which show why the
  protocol is as it is. `formal/README.md` maps each query to the claim
  above it backs, and says what the models leave out: Verifpal finds
  attacks within a bounded number of sessions and proves nothing beyond
  that bound; sealed-sender anonymity, deniability and the transparency
  log are argued in `PROTOCOL.md`, not modelled.
- Known-answer vectors for every operation in `docs/vectors/`, replayed
  against the code on every test run by a harness that also re-derives
  each intermediate value from the byte layouts in `PROTOCOL.md`, so the
  specification, the code and the vectors are checked against each other
  and a second implementation can check itself.
- Property tests: bodies of any content round-trip or are refused at the
  size limit, the sealed layer opens only intact and only for its
  recipient, sessions read every message under any schedule of reordered
  delivery and refuse any damaged one, every statement and log entry is
  broken by any change, file chunks open only in their place.
- The test suite: unit tests on every cryptographic operation with
  tampering cases, end-to-end tests through a real relay (sessions,
  handshakes waiting in the mailbox, restarts, lost state, anonymous
  submission, files, TLS with trusted and untrusted roots, key pins,
  proxies, groups forming, talking and shrinking, a device linked by
  its link while a stranger's message under another secret is ignored,
  a message reaching both devices of an account under one id, a
  revoked device cut off and dropped, sync from a stranger dropped),
  the groups engine against a fake sequencer (every membership rule
  refused, a forged commit breaking the group for everyone honest, a
  removed member unable to read on, crossed commits, a lost race, out of
  sync and rejoin, a rewound sequencer caught up, a forged device leaf
  refused, a device added and removed by its own identity and refused
  to anyone else's), the relay's rules for device claims and
  revocations, pseudo-terminal tests of the client under two terminal
  types (a laptop linked, unlinked and erased among them), and a test
  that renders peer-controlled text through the real terminal backend
  and asserts nothing unescaped reaches it.
- MLS itself: its security is RFC 9420's and the literature's, not
  modelled here; the Verifpal models cover the one-to-one handshake and
  ratchet only. The parts around MLS that are this program's (the
  sequencer's property that no two commits stand for one epoch and no
  non-member moves it, the membership rules, the Welcome checks) are
  stated in protocol section 13 and tested, not proved.
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
| Deniability: a recipient can prove who wrote what | Closed for v4 sessions (0.8.0): a v4 body carries no sealed-layer signature (`PROTOCOL.md` section 9). Still open for v2 sessions (older peer or relay), which stay signed, and for the v1 body, no longer sent to a peer without prekeys (0.10.1) but still sent where their prekeys are too old to start a session. |
| Cover traffic: the relay and the network see when messages travel and roughly how big they are | Closed as far as it goes (0.8.0, roadmap item 46, opt-in): two contacts who both turn it on send meaningless messages to each other at random moments while both clients run, so the relay cannot tell when they really talk or, for short and medium messages, which message is real. What remains: it shows the two are in contact, bursts and long messages stand out, files are visible, connecting and disconnecting are visible, and nothing covers contacts who did not opt in or are not around. It is off by default because it costs bandwidth. |
| Post-quantum ratchet steps: after the hybrid handshake the ratchet is X25519 only | Closed for v4 sessions (0.8.0, roadmap item 41): every ratchet step does an ML-KEM step. A v2 session (older peer or relay) is still X25519-only after the handshake. |
| Identity revocation | Closed (0.8.0, roadmap item 43): a pre-signed revocation certificate kept in the data directory and the backup, and a cross-signed succession for a planned rotation, served by the relay and verified by contacts (`PROTOCOL.md` section 10). A revocation is final. What remains is the race on a succession an attacker holding a compromised key issued before its owner revoked it. |
| A relay that serves one person a stale key, hides a revocation or handover from them, or tells two people two different stories | Closed (0.8.0, roadmap item 44): the relay keeps a hash-chained log of every key change and statement, clients replay it, refuse what it does not bear out, and compare log heads inside every message, so a fork is reported by the next message between two people it treated differently (`PROTOCOL.md` section 11). Substitution of an identity was never possible, the id being the key. What remains: two contacts who never message each other never compare heads, and a relay that forks for one client and everyone that client talks to is caught only through someone on the other side. |
| Certificate revocation checking | Not planned; key pins are the mitigation. |
| Received files stored unencrypted in `downloads/` | Closed as an option (0.10.0, roadmap item 50): `/files encrypt on`, where the directory is protected, keeps received files as ciphertext under the data key, `/open` decrypting a private copy that goes at exit. Off by default, so other programs can open the files. |
| History kept until the user removes it | Closed (0.10.0, roadmap item 50): a per-conversation timer removes messages on each device's own clock, from sending for the sender and from reading for the reader; `/delete me` removes any message from one's own devices; both rewrite the history file rather than mark it. |
| Delete for everyone and disappearing messages: what they promise | By design (0.10.0): enforced by the other side's software, never by cryptography. An unmodified client on 0.10.0 or later removes the message when the deletion reaches it or the timer runs out, and the client says exactly that; a screenshot, a modified client, an export or a backup taken before, a file already saved and a person's memory are beyond it. The relay holds only ciphertext and does nothing for either; it cannot tell a deletion from a short message. |
| A panic in the terminal client can leave the terminal in raw mode | Small; next client pass. |
| Groups: what the relay learns, and what a member can do | Groups exist from 0.9.0 (roadmap item 47) and this document says what they protect. What remains, by design: the relay sees a group's size and membership by inference from delivery bursts and sees each group's epoch move; group messages are not deniable; a rogue member can wedge a group (every honest client stops rather than accept a rule-breaking commit) and an admin has to make it anew; a leaver stays in the tree until an admin's client commits the leave, and a declined invitation leaves a dead leaf until an admin removes it; a member absent past its mailbox's quota rejoins and loses the messages between. Cover traffic does not cover groups. |
| Multiple devices: what a second device adds to the attack surface | Done (0.9.0, roadmap item 48), and this document says what devices protect: the identity key stays on the primary, a linked device is certified and revocable, contacts verify the identity and never a device, the relay cannot add or keep a device unseen (`PROTOCOL.md` section 14). What remains, by design: the relay learns how many devices a person has and which ids, and infers it again from delivery bursts; a linked device holds every conversation from the day it was linked plus the snapshot it was given, so its theft exposes what the person read anywhere; a revoked device is told so but erases itself only on its owner's word; the primary's loss is still the identity's, restored from the backup; a succession moves no devices. |

## Out of scope

- Reading the memory of a client that is unlocked and running, by a
  program of the same user or anything above it. The cost of that is
  raised as far as each platform allows and the limit is described under
  "Program running as you"; it is not defended against, and no software
  on the same machine could.
- Compromise of the operating system or terminal of a running client.
- A relay that is itself the target of denial of service.
- Hiding the fact that someone uses Silver Messenger at all.
