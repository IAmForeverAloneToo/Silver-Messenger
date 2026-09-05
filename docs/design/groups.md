# Design note: groups on MLS

Roadmap item 47. This note is written before the code and is the record of
the decisions; the normative description of what ships goes into
[PROTOCOL.md](../PROTOCOL.md) section 13 when the code lands, and the
threat model grows the same day. Where this note and the code later
disagree, the code and PROTOCOL.md win and this note is corrected.

## 1. Decisions

| Question | Decision |
| --- | --- |
| Protocol | MLS, RFC 9420, through OpenMLS 0.9. |
| One-to-one conversations | Stay on the Double Ratchet (roadmap item 41). A group is anything created with `/group new`, whatever its size. |
| Ciphersuite | `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519` from draft-ietf-mls-pq-ciphersuites: X-Wing (ML-KEM-768 + X25519) HPKE, AES-128-GCM, SHA-256, Ed25519 signatures. The code point is the draft's provisional one (0x004F in OpenMLS); it moves with the RFC, by re-initialising groups. No other suite is offered. |
| Credentials | `BasicCredential` whose identity is the 32-byte user id; the leaf signature key is the identity key itself. Item 48 puts per-device keys in the same slot. |
| Delivery | Client fan-out: one sealed envelope per member through the member's existing mailbox, the relay learns no membership list. Commit ordering by a small relay-side epoch sequencer that holds one counter and one hash per group and cannot read anything. |
| Membership | Admins add and remove; anyone may ask to leave; the creator is the first admin and admins appoint admins. The rules are checked by every member on every commit; a commit that breaks them is refused and the group is declared broken rather than let an intruder in. |
| Invites | Links (and QR codes) carrying the group id, one admin's id and an invite secret; a join request goes to that admin, who adds the joiner. Rotating the secret voids old links. |
| Oversize messages | An MLS message that does not fit the envelope travels as an encrypted blob whose key is in the envelope, with the file machinery of section 7.5. |
| Sealed sender | Kept: group envelopes are sealed to each member with no sealed-layer signature, the way v4 bodies are; the sender is authenticated inside MLS by its leaf signature. |
| Deniability | Not for groups: MLS signs every message with the sender's leaf key. Documented, and the reason one-to-one stays on the ratchet. |
| Receipts, cover traffic, typing | Not in groups. |
| Relay schema | Version 3: two new tables, key packages and group sequencer entries. |

## 2. Goals and non-goals

Goals:

* Group conversations with the security MLS gives: confidentiality and
  integrity among members, forward secrecy and post-compromise security
  across membership changes, agreement on who is in the group, and
  post-quantum confidentiality at the same level the one-to-one protocol
  has since v3 and v4.
* The relay learns as little as it does for one-to-one messages: not who
  wrote, not what, not who is in a group. What it inevitably learns is
  listed in section 10 and goes into the threat model as it is.
* A client from 0.8.0 keeps working for one-to-one with a 0.9.0 client and
  is never sent a group message; a relay from 0.8.0 keeps serving
  one-to-one messages for 0.9.0 clients, which then see groups as
  unavailable on that relay.
* Item 48 (multiple devices) fits without a second redesign: a device is a
  leaf, and nothing here assumes one leaf per identity.

Non-goals, for this item:

* Interoperability with other MLS implementations. One relay is one
  network and every client is this one; the wire format is described so a
  second implementation could follow it, but nothing is tested against
  one.
* Groups larger than 256 members. Fan-out makes sending cost linear in the
  size of the group; 256 is where a text message costs the sender about
  a megabyte of upload.
* History for new members, external commits, resumption of a group across
  a succession, group avatars, per-member permissions beyond admin or not,
  and anything that needs the relay to understand MLS.

## 3. What exists that this builds on

* The sealed-sender envelope (PROTOCOL.md section 3) addresses exactly one
  recipient; the body inside is versioned by `v` and padded to 160-byte
  steps; a v4 body carries no sealed-layer signature.
* The relay keeps one mailbox per recipient, replays it on login, and
  accepts envelopes from anonymous connections (section 7.2), which is what
  makes sealed sender complete.
* One-time prekeys are deposited by the owner, handed out once each, rate
  limited per user, and reported back (`prekey_status`); that machinery is
  what key packages need, with a different payload.
* Files go through the blob store as encrypted 64 KiB chunks under a key
  carried inside the message (section 7.5), with no addressing and no
  ownership.
* Signed bundle capabilities (`caps` in the bundle, section 2) are the
  relay-proof way to advertise support before a first message; in-body
  `caps` gate content kinds for older clients.
* The client's stores are JSON files under the data directory, encrypted
  under the vault key when one is set; sessions are rewritten after every
  message.

## 4. Cryptographic choices

### 4.1 Ciphersuite

`MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519`:

* KEM: X-Wing, the ML-KEM-768 + X25519 hybrid of draft-connolly-cfrg-xwing-kem
  (HPKE KEM 0x647a), which is what draft-ietf-mls-pq-ciphersuites means by
  `MLKEM768X25519`. The one-to-one protocol already gives post-quantum
  confidentiality in the handshake (v3) and the ratchet (v4); shipping
  groups on a classical suite would open exactly the harvest-now,
  decrypt-later gap the threat model closed in Phase 8. X-Wing has a proof
  of IND-CCA security assuming either component holds.
* AEAD and hash: AES-128-GCM and SHA-256, because that is the pairing the
  working-group draft defines with Ed25519; the ChaCha20-Poly1305 variant
  with X-Wing exists only in an individual draft. AES-GCM here comes from
  RustCrypto and is constant time.
* Signatures: Ed25519, so the leaf signature key can be the identity key
  and the transparency log already covers the binding. Authenticity is
  therefore classical only, as it is for the rest of the protocol; the
  ML-DSA suites wait for the day the identity key itself moves.

Standardisation status: draft-ietf-mls-pq-ciphersuites (July 2026) has
provisional code points. OpenMLS assigns 0x004F. Because every client is
this one, a provisional code point is an internal matter: PROTOCOL.md
records it, and when the RFC assigns the final one, groups are
re-initialised (RFC 9420 `ReInit`, or re-creation by an admin) under a
bumped group protocol version. That is one commit per group, and the
sequencer entry moves with it. If OpenMLS's post-quantum feature turns out
unfit in the spike (section 15), the fallback is RFC 9420's
`MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` with the same
re-initialisation path to the hybrid suite later, and the threat model
says so in plain words. The spike decides; the note is corrected.

### 4.2 Credentials and leaves

* Credential: `BasicCredential` with `identity = user id` (the raw 32-byte
  Ed25519 verifying key, the same bytes that identify a person everywhere
  else).
* Leaf signature key: the identity key. A member verifies every leaf it
  sees the way it verifies a bundle: the credential's identity and the
  signature key must be the same key. Item 48 relaxes this to "the
  signature key is the identity key or one of the device keys the
  identity's bundle lists and signs".
* Leaf node extension `0xF001` (`silver_seal`, private-use range): the
  member's sealed-layer X25519 public key (`IKdh`, 32 bytes). It is signed
  by the leaf's signature, so a member learns every other member's sealing
  key from the tree, verified by the identity that owns it, without one
  lookup per member and without the relay in the loop. A member whose
  sealing key changes has a new identity (succession) and is re-added.
* Capabilities in every key package and leaf: protocol version `mls10`,
  the one ciphersuite, extensions `0xF000` and `0xF001`, credential type
  basic, no non-default proposal types.

### 4.3 Group context extension `0xF000` (`silver_group`)

The group's own metadata lives in the group context, so it is agreed by
every member, ordered by commits, and covered by the transcript hash:

```
struct {
  uint8   version;          // 1
  opaque  name<0..64>;      // UTF-8, may be empty
  UserId  admins<32..8192>; // at least one, at most 256, sorted
  opaque  invite_key[32];   // rotated to void invite links
  uint64  created_at_ms;
} SilverGroup;
```

Changing it is a `GroupContextExtensions` proposal committed by an admin.
The `RequiredCapabilities` extension of every group lists `0xF000` and
`0xF001`, so a leaf that cannot carry them cannot be added.

### 4.4 Wire format policy and configuration

* `PURE_CIPHERTEXT_WIRE_FORMAT_POLICY`: handshake messages are encrypted
  too. Nobody but members reads them anyway, and it keeps the sealed
  prefix from being the only thing hiding a membership change.
* `use_ratchet_tree_extension = true`: a Welcome carries the tree; there
  is no tree server.
* `max_past_epochs = 3`, out-of-order tolerance 64, maximum forward
  distance 1000 (the ratchet's `MAX_SKIP`): application messages from a
  recent epoch that arrive after a commit still decrypt.
* MLS padding off; the envelope pads the whole body to 160-byte steps as
  today.
* Every commit carries an update path (OpenMLS's default for adds and
  removes), and every member commits a self-update when its leaf is seven
  days old, the signed-prekey rotation period, so a compromise heals
  within a week even in a quiet group.

## 5. Delivery

### 5.1 Fan-out through the members' mailboxes

A group message is one MLS ciphertext. The sender seals it once per
member (excluding itself) into an ordinary envelope addressed to that
member and submits the envelopes on the anonymous connection, the way
one-to-one messages go. Each member finds it in its own mailbox, subject
to its own quota and its own 30-day expiry, exactly like any other
message. Welcomes go the same way to the new member alone.

Why not a group mailbox on the relay, which the roadmap's wording
suggested: a group mailbox is one upload per message and a trivial place
to order commits, but the relay then keeps a membership list (it must know
whom to serve, or see who reads), a new kind of quota, per-member read
cursors, and a second delivery path with its own offline semantics; and
for the relay to not learn membership, reads would have to be anonymous
and tokenised. Fan-out keeps one delivery path, one quota, one expiry
rule, sealed sender for free, and gives the relay nothing but the same
per-recipient rows it already stores. The price is upload bandwidth
proportional to group size, which section 12 quantifies and which is the
same trade Signal makes.

What fan-out leaves the relay: a burst of envelopes from one anonymous
connection to a set of recipients, from which it can infer that those
recipients form a group and roughly how large it is. Section 10 says so.

### 5.2 The epoch sequencer

MLS needs every member to apply the same commit for each epoch; two
commits built on the same epoch fork the group. Something must pick one.
The relay does, with one row per group it knows nothing else about:

```
group_id (32 bytes, random) -> { epoch: u64, next: [u8; 32], updated_at }
```

`next` is the SHA-256 of a token only members of the *current* epoch can
produce: `token(e) = MLS-Exporter(label = "silver-messenger/v1/group-sequencer",
context = group_id, length = 32)` of epoch `e`. To move the group from
epoch `e` to `e + 1`, a committer presents `token(e)` and the hash of
`token(e + 1)`, which it knows before merging its own commit (OpenMLS
exposes the staged commit's exporter). The relay compares the stored
epoch and hash, and if both match, stores `e + 1` and the new hash; the
first committer wins, the second gets `stale` with the relay's epoch and
throws its pending commit away, waits for the winning commit to arrive in
its mailbox, merges it, and rebuilds on top. Only after the sequencer has
accepted a commit does the committer fan it out and send Welcomes, which
is also what OpenMLS's own guidance requires.

Properties:

* The relay verifies a hash of an exporter output; it learns nothing that
  decrypts anything, and a removed member, which does not have the new
  epoch's exporter, cannot move the counter. A malicious relay can refuse
  or scramble the counter, which is a denial of service it could always
  cause by dropping mail.
* Tokens are not encryption keys, so a client keeps the last 64 of them.
  If a restore takes the relay's counter back (docs/UPGRADING.md already
  warns that a restore shortens the transparency log the same way), a
  member that sees `stale` with a *lower* epoch replays its tokens from
  that epoch forward, one accepted `group_commit` per step, and the
  counter catches up. A relay taken back more than 64 epochs, or a group
  whose entry expired, is re-created by any member (`group_create` on a
  missing id, with the current epoch and hash) and the rest re-sync from
  their mailboxes as usual.
* A member whose local commit lost the race and who never receives the
  winning commit (mailbox full, or the winner was a rogue commit refused
  by policy, section 7.6) declares the group out of sync after ten
  minutes and asks to be re-added (section 7.5).
* Creation: the creator sends `group_create` with epoch 0 and the hash of
  `token(0)` right after `MlsGroup::new`. Ids are 32 random bytes, so
  nobody creates someone else's group first. Entries idle for 180 days
  expire; a live group refreshes its entry with every commit.

The sequencer frames go on any connection, authenticated or anonymous;
clients use the anonymous one, so the relay does not learn which identity
committed. They count against the connection's `send` budget and against
the address's registration budget for `group_create`.

### 5.3 Ordering at the receiver

Envelopes reach a member in its mailbox's order, which is arrival order at
the relay. Two committers' fan-outs can cross on the network, so a member
can receive the commit for epoch `e + 2` before the one for `e + 1`. The
client keeps a small per-group hold queue for handshake messages from the
future (at most 16, at most ten minutes) and retries them after each
merge. Application messages from a past epoch decrypt for three epochs;
older ones are reported as undecryptable, which is what happens today when
the ratchet has moved on.

## 6. Wire changes

### 6.1 Key packages (relay, section 7)

New frames, authenticated connection only:

| `type` | Fields | Notes |
| --- | --- | --- |
| `key_packages` | `packages` (list of `{ref, expires_at_ms, data}`), `last_resort` (`{ref, expires_at_ms, data}` or absent) | Replaces the deposit: whatever is not listed is forgotten, as for prekeys. `ref` is the MLS `KeyPackageRef` (b64, 32 bytes), `data` the TLS-serialised `KeyPackage` (b64, at most 4096 bytes). At most 30 packages plus one last resort. The relay stores them opaque; it cannot parse MLS and never needs to. |
| `key_package` | `user_id` | Ask for one of `user_id`'s key packages. |

| `type` | Fields | Notes |
| --- | --- | --- |
| `key_package_status` | `remaining`, `consumed` (list of `ref`) | After `key_packages`: how many are on deposit and which refs were handed out since the last deposit. |
| `key_package_result` | `user_id`, `package` (or `null`), `last_resort` | One package, removed from the deposit as it is handed out, oldest first; the last-resort one, never removed, when the deposit is empty; `null` when the identity has none. Only for a connection that has deposited its own packages, at most 30 per target user per hour per requester, the prekey handout rule. |

The fetcher verifies what it gets: it parses, checks the ciphersuite,
the credential identity against `user_id`, the leaf signature key against
that identity, the signatures, the lifetime and the capabilities, and
refuses to add on any failure with a message that names the relay. A relay
that hands out a stale package costs the new member's first epoch some
forward secrecy, as a replayed one-time prekey does.

Relay feature `groups`: key packages and the sequencer. A client sees no
`groups` in `auth_ok` and shows every group command as unavailable on
this relay.

### 6.2 Sequencer (relay, section 7)

| `type` | Fields | Notes |
| --- | --- | --- |
| `group_create` | `group`, `epoch`, `next` | Create the entry if there is none. Idempotent for the same three values. |
| `group_commit` | `group`, `epoch`, `token`, `next` | Move from `epoch` to `epoch + 1` if the entry stands at `epoch` and `SHA-256(token)` is what it holds. |

| `type` | Fields | Notes |
| --- | --- | --- |
| `group_state` | `group`, `epoch` | The entry now stands at `epoch`. |
| `group_rejected` | `group`, `code`, `epoch`? | `stale` (with the relay's `epoch`), `not_found`, `exists`, `forbidden`, `rate_limited`. |

`group` is b64 of 32 bytes; `token` and `next` are b64 of 32 bytes.

### 6.3 Body version 5: the group body

A body with `v: 5` carries one MLS message for one group:

```json
{ "v": 5, "group": "<b64 32 bytes>", "kind": "<kind>",
  "mls": "<b64 TLS-serialised MLSMessage>",
  "blob": { "blob": "<id>", "key": "<b64>", "chunks": n, "size": n, "sha256": "<b64>" },
  "join": { "proof": "<b64 32 bytes>" } }
```

* `kind`: `welcome` (an MLS `Welcome`), `handshake` (a `PrivateMessage`
  carrying a proposal or commit), `message` (a `PrivateMessage` carrying
  an application message), `join` (a `KeyPackage`, with `join.proof`,
  section 7.3), `rejoin` (a `KeyPackage` from a member that fell out of
  sync, section 7.5).
* Exactly one of `mls` and `blob` is present. `blob` is used when the MLS
  message exceeds 24 KiB: the message is encrypted and chunked with the
  file scheme of section 7.5 (a fresh key, padded chunks) and stored in
  the blob store; the recipient fetches it before processing. Welcomes to
  groups of more than a dozen members and commits that add many members
  take this path; a text message never does.
* The sealed layer is unsigned for `v: 5`, as for `v: 4`: the AEAD binds
  the envelope to its recipient, MLS gives every kind its own signature
  (the leaf's for handshake and application messages and for the
  GroupInfo inside a Welcome; the key package's own for `join` and
  `rejoin`), and MLS's per-message keys rule out replay. The sender id in
  the sealed prefix is set truthfully but is a hint: the receiving client
  takes the sender from MLS.
* Padding: the whole body to 160-byte steps, as today, so a short group
  text is the size of a short one-to-one text.

The plaintext of an application message is JSON, the shape of a
one-to-one body's payload:

```json
{ "id": "<uuid>", "sent_at_ms": n, "content": { ... }, "head": { ... } }
```

`content` is a `text` or `file` of section 4; `head` is the sender's
transparency log head, so members gossip heads across groups the way
contacts do one-to-one. Receipts, lifecycle statements and cover are not
sent in groups; a client that finds one ignores it.

### 6.4 Capabilities

* Bundle (signed): `groups`. A client advertises it while it deposits key
  packages; a contact whose bundle lacks it is shown as "cannot be added
  to groups yet" rather than looked up for a key package that is not
  there.
* In-body (unsigned): nothing new. A v5 body is never sent to a client
  that did not publish a key package, and a key package is published only
  by a client that understands v5.

## 7. Group lifecycle

### 7.1 Create

`/group new <name>`: the client makes a fresh group id, the `silver_group`
context extension with itself as the only admin, a random invite key and
the name, creates the MLS group at epoch 0 with its own key package
material, registers the sequencer entry, and stores the group. Nothing is
sent.

### 7.2 Add

`/group add <contact>` by an admin: the client checks the contact's bundle
advertises `groups` and is not revoked, fetches one key package
(`key_package`), verifies it (section 6.1), builds a commit with the Add,
takes the sequencer step, merges, fans the commit out to the existing
members and seals the Welcome to the new one. If the sequencer says
`stale`, it discards the pending commit, processes what arrived, and
retries once, then reports.

The invitee's client verifies the Welcome (the sender's credential, every
member's leaf against its identity, the group context's extensions and
required capabilities, the ciphersuite) and then, if the sender is a
contact, joins at once and shows the group; if the sender is a stranger,
holds the Welcome in the Requests pane as "X invites you to <name>
(n members)" until `/accept` or `/block`, as held messages are today. A
Welcome held past the key package's lifetime, or whose group has since
moved on, still joins at that epoch and catches up from the mailbox.

### 7.3 Join by link

`/group invite` prints `silver://group/<group id>?relay=<url>&via=<admin id>&key=<invite secret>`
and a QR code. `key` is `HMAC-SHA256(invite_key, "silver-messenger/v1/group-invite" || group_id)`
truncated to 16 bytes, so the link does not carry the invite key itself
and a rotated invite key voids every link.

`/group join <link>`: the joiner looks the admin up (as `/add` does),
generates a key package for the purpose, and sends a `join` body to the
admin with `join.proof = HMAC-SHA256(key, "silver-messenger/v1/group-join" || group_id || joiner id)`.
The admin's client verifies the proof against its current invite key,
checks the joiner is not blocked and not already a member, and adds it as
in 7.2; members see "X joined by link". A link names one admin; if that
admin is gone the link is dead and someone makes a new one. `/group link
reset` rotates the invite key (a `GroupContextExtensions` commit) and
prints the new link.

### 7.4 Leave and remove

* `/group leave`: the member sends a Remove proposal for its own leaf, marks
  the group left locally, stops reading it, and deletes its state. An
  admin's client commits pending proposals as soon as it sees them; until
  one does, the leaver is still in the tree and could still decrypt, which
  is what the `(leaving)` mark on the member means. The last admin cannot
  leave without appointing another; the last member leaving deletes the
  group.
* `/group remove <member>` by an admin: a commit with the Remove. The
  removed member gets the commit, sees it was removed, keeps its history
  and deletes its MLS state.
* `/group admin add|remove <member>`: a `GroupContextExtensions` commit
  changing `admins`. An admin cannot remove the last admin (itself).

### 7.5 Out of sync and rejoin

A member falls out of sync when it misses a commit for good: its mailbox
was full or expired, or a handshake message it holds never resolves. The
client detects it by an epoch gap that the hold queue does not close in
ten minutes, or by `stale` from the sequencer with a higher epoch than
its own and no commit arriving, and then sends a `rejoin` body (a fresh
key package) to every admin it knows of. An admin's client, on a `rejoin`
from a current member, commits a Remove and an Add for that member in one
commit and sends the Welcome. History is kept; the messages between are
lost, and the pane says so.

### 7.6 Membership rules

Every member checks every commit before merging it, against the group
context of the epoch the commit leaves:

* Add, Remove (other than a member removing itself by proposal) and
  GroupContextExtensions proposals are accepted only in a commit whose
  committer is an admin.
* A non-admin's commit may contain only its own Update, plus Remove
  proposals it merely references that were made by the members they
  remove (leaves).
* `admins` never becomes empty, never exceeds 256, and only lists members.
* The ciphersuite, the required capabilities and the extension types never
  change.

A commit that breaks a rule is not merged; the member marks the group
broken, names the committer, and stops sending. Because every client
applies the same rules, the honest members all stop at the same epoch
while the sequencer, which cannot check policy, has moved on; a rogue
member can therefore wedge a group but cannot get an intruder's keys
accepted. Recovery is `/group recreate` by an admin: a new group with the
same name and the honest members, the old one abandoned. Confidentiality
over availability, and the threat model says a malicious member is
outside what MLS protects against anyway.

### 7.7 Contacts, names, verification

Members are identified by user id. The pane shows a member as the
contact's alias when they are a contact, else as the short id; `/group
members` lists them with the verified mark for contacts whose safety
number was checked; `/add <id>` from the member list makes a contact.
A group's name is the one in its context; the local user may set a
personal alias for a group with `/alias`, as for contacts.

## 8. Client

### 8.1 Storage

* `groups.redb`: an OpenMLS `StorageProvider` over redb, one table per
  kind of entry OpenMLS stores, every value encrypted under the vault
  data key when protection is on (the JSON stores are encrypted the same
  way today). OpenMLS's deletions become deletions; redb reuses freed
  pages, so at-rest forward secrecy is best effort, as it is for the
  sessions file. The key package private parts live here too.
* `groups.json`: the client's own index, one entry per group: id, name
  and alias, our role, the members as last seen (ids and sealing keys),
  the last 64 sequencer tokens, the hold queue, read position, muted
  flag, `left` or `broken` state with the reason.
* `history/group-<id>.jsonl`: the conversation, each line with the sender
  id, the same line format as contact history.
* Backups (`silver backup`) include all three; a restore that goes back
  in time leaves the group out of sync, and the rejoin path (7.5) fixes
  it.

### 8.2 Engine

A `groups` module in `silver-client`:

* `KeyPackages`: keeps 20 on deposit and a last-resort one, regenerates
  when fewer than 10 remain or a package is older than 30 days, deposits
  with every publish, and reads `key_package_status` to forget consumed
  ones. Lifetime 90 days; the last-resort one is rotated every 30 days.
* `Group`: create, add, remove, leave, appoint, send, receive, join,
  rejoin, recreate, self-update on schedule; the hold queue; the policy
  check; the sequencer client with token history and catch-up; the
  oversize path through the blob store.
* Events for the UI: `GroupMessage`, `GroupChanged` (members, admins,
  name), `GroupInvite` (a held Welcome), `GroupJoined`, `GroupLeft`,
  `GroupBroken`, `GroupOutOfSync`, and `Sent` and `Rejected` per envelope
  as today, aggregated by the UI into one mark per message.
* Outbox: group envelopes queue like others; a group message is "sent"
  when every envelope of its fan-out is. A fan-out interrupted by a
  disconnect resumes from the outbox.

### 8.3 Interface

Group panes in the sidebar after contacts, with the same unread badges;
lines show the sender; marks are `⋯` (queued) and `✓` (every envelope
accepted), no `✓✓`. Commands: `/group new|add|remove|leave|members|
invite|join|link reset|admin add|admin remove|rename|recreate|info`,
`/mute`; the file commands work in a group pane; `/copy`, `/search`,
selection and everything in the message pane work unchanged. The help
overlay and the status line learn the group commands from the table as
they do today.

## 9. Relay

* Tables: `key_packages` (`(user, seq) -> {ref, expires_at_ms, data}`),
  `key_packages_used` (`(user, ref)`), `key_package_last_resort`
  (`user -> {ref, expires_at_ms, data}`), `groups`
  (`group_id -> {epoch, next, created_at_ms, updated_at_ms}`). Schema
  version 3; the migration creates them and nothing else; 0.8.0 refuses a
  version-3 database, as it refuses version 2 already (UPGRADING.md).
* Backup and restore carry them; the backup format adds record kinds.
* Limits: 30 key packages plus one last resort per user, 4096 bytes each,
  a deposit at most once a minute; handouts 30 per target per requester
  per hour, only to connections that deposited their own; 100 000
  sequencer entries, 20 `group_create` an hour per address, entries
  expire after 180 days idle; sequencer frames count as `send`.
* Metrics: groups known, key packages on deposit and handed out, sequencer
  commits and rejections. Nothing per group.
* Admin socket: `status` reports the counts; there is no listing of
  groups or their epochs, since neither says anything useful and both say
  something about who is active.
* Logs: a `group_create` and a `group_commit` log at debug with the group
  id hashed, as identities are.

## 10. What the relay learns, and the threat model

New rows for the threat model, stated as they are:

* **That a group exists, and when it changes**: sequencer entries with
  their epoch and commit times, from anonymous connections. Not who is in
  it, not who committed.
* **Membership by inference**: a burst of envelopes from one anonymous
  connection to N recipients within a second is a group message; the
  recipient set, repeated over time, is the group's membership minus the
  sender; the burst size is the group's size. Cover traffic does not
  apply to groups. Tor hides the sender's address and nothing else.
* **Who fetched whose key package**: `key_package` is on the authenticated
  connection, so the relay learns that A added B to some group, as it
  learns that A looked B up before their first message today.
* **Sizes**: a Welcome or a large commit going through the blob store is
  visible as a blob of that size, as a file is.

What does not change: the relay reads no content, sees no sender, holds
no membership list, cannot add a member (a Welcome needs the group's
secrets; a key package is verified against the identity that signed it),
and cannot replay a message (MLS keys are single use). What is weaker
than one-to-one: group messages are not deniable; MLS signs every one
with the sender's identity key. What is new against members: a member
sees everything, as in any group; a removed member sees nothing after the
commit that removed it, and nothing before it that it did not already
receive; an admin controls membership, so an admin's compromise is
membership control until the other admins remove it; a malicious member
can wedge the group's sequencer (7.6) but not break confidentiality.

The transparency log is not extended: key packages are verified against
the identity key, whose binding the log already covers, and the sealing
key in a leaf is signed by that identity. The one thing the log would add,
freshness of a handed-out key package, is worth one epoch of forward
secrecy and no more.

## 11. Multiple devices (item 48), so this is not redone

* A device is a leaf; the credential identity stays the user id; the leaf
  signature key becomes the device key, and members verify it against the
  device list the bundle carries and signs.
* Key packages are per device, deposited under the identity with a device
  id; the relay hands out one per device on request (`key_package` gains
  a `device` field, and `key_package_result` returns a list).
* Adding an identity adds all its devices in one commit; a new device
  joins every group by being added by one of the identity's other
  devices, which are admins for their own identity's leaves in the
  policy of 7.6 (an identity's device may add or remove that identity's
  other devices).
* Fan-out goes per device; the sealing key in `silver_seal` is per device.

Nothing in sections 4 to 9 assumes one leaf per identity except the
verification rule "signature key equals identity key", which is the one
line item 48 changes.

## 12. Sizes

With X-Wing, the public keys are large: 1216 bytes per HPKE public key,
1120 bytes per ciphertext. Estimates, to be measured in the spike and
corrected here:

| Object | Size | Path |
| --- | --- | --- |
| Key package | about 2.8 KiB | 20 on deposit is about 56 KiB, under the 128 KiB frame |
| Text message (padded body) | 320 to 480 bytes | envelope, the size of a one-to-one text |
| Commit with path, 16 members | about 12 KiB | envelope |
| Commit with path, 256 members | about 24 KiB | envelope or blob, at the edge |
| Commit adding 10 members | about 30 KiB plus path | blob |
| Welcome with tree, 16 members | about 40 KiB | blob |
| Welcome with tree, 256 members | about 700 KiB | blob |

Fan-out cost to the sender: a text message to a group of N costs N
envelopes of about 480 bytes: 8 KiB for 16, 120 KiB for 256. A commit
costs N times its size, so an admin adding to a group of 256 uploads up
to 6 MiB; through Tor that is slow and is said in the docs. The relay's
per-recipient quota (1000 envelopes, 32 MiB) is unchanged; a very active
group of 256 fills an absent member's mailbox in about a thousand
messages, after which that member rejoins on return (7.5).

## 13. Tests

* Protocol: v5 body encode and decode, padding steps, oversize decision,
  the `silver_group` and `silver_seal` encodings; vectors for each in
  `docs/vectors/`, and the body property generator gains v5.
* Client, unit: the storage provider round-trips and deletes every entry
  kind; key package generation, verification and refusal cases (wrong
  identity, wrong suite, expired, missing capability); group lifecycle
  against a fake sequencer (create, add, welcome, message, remove, leave,
  admin change, rename, link join with a valid and an invalid proof, a
  rotated link); two committers racing and the loser rebuilding; a
  restore-rewound sequencer and the token catch-up; the hold queue with
  a crossed commit; every policy rule in 7.6 refused; out-of-sync
  detection and rejoin; a removed member failing to decrypt the next
  epoch.
* Relay: key package deposit semantics (replace, cap, size, handout order,
  last resort, rate), sequencer semantics (create, idempotent create,
  commit, stale, not found, expiry, limits), schema migration 2 to 3,
  backup and restore of the new tables, metrics.
* End to end, in `crates/silver-client/tests`: three clients through an
  in-process relay form a group, message, add a fourth by link, remove
  one, and the removed one cannot read on; a Welcome from a stranger is
  held; a client on a relay without `groups` reports groups unavailable.
* Terminal: one pty test for the group commands and rendering.
* Fuzz: a `group_body` target over the v5 decoder and the two extension
  decoders.
* Formal: none new. MLS's security proofs are RFC 9420's and the
  literature's; the Verifpal models cover the handshake and the ratchet,
  not MLS. The sequencer's property (no two commits for one epoch, no
  step by a non-member) is stated and tested, not modelled.

## 14. Implementation order

Each step is one commit on `main` with its tests, in this order, so the
tree is always green and each piece can be reviewed alone:

1. Spike (not committed unless it becomes step 4's skeleton): OpenMLS 0.9
   with `draft-ietf-mls-pq-ciphersuites` on stable 1.94; the suite works
   for create, add, message, remove; sizes measured; section 12 and
   section 4.1 corrected.
2. Protocol: `GroupBody` (`v: 5`), the extension encodings, key package
   and sequencer frames, the `groups` capability and feature, vectors,
   properties, fuzz target.
3. Relay: key packages, sequencer, schema 3, backup, limits, metrics,
   admin status, tests, UPGRADING.md.
4. Client: storage provider, key packages, the `groups` engine, events,
   outbox integration, e2e tests.
5. Terminal client: panes, commands, rendering, requests, pty test.
6. Documents: PROTOCOL.md section 13, THREAT_MODEL.md rows and gaps,
   README, OPERATING.md limits, CHANGELOG, roadmap tick; this note's
   corrections.

Compatibility through the steps: nothing sends a v5 body until step 4,
and nothing deposits a key package until then, so a partially landed tree
is a 0.8.0 client with more code.

## 15. Open points, to be settled by the spike

* Whether OpenMLS's post-quantum feature builds and behaves on all three
  CI platforms with the pinned toolchain; the fallback is in 4.1.
* The exact sizes of section 12.
* Whether `StagedCommit::export_secret` gives the next epoch's exporter for
  the committer's own pending commit, which the sequencer step relies on;
  if not, the committer merges first and the sequencer step happens
  inside a storage transaction that is rolled back on `stale`.
* Whether the redb-backed storage provider's write amplification is
  acceptable for a busy group, or whether a write-behind cache with
  explicit flush points is needed.
