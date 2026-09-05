# Design note: multiple devices

Roadmap item 48. Written before the code, as the record of the decisions;
the normative description of what ships goes into
[PROTOCOL.md](../PROTOCOL.md) section 14 when the code lands, and the
threat model grows the same day. Where this note and the code later
disagree, the code and PROTOCOL.md win and this note is corrected.

## 1. Decisions

| Question | Decision |
| --- | --- |
| What a device is | A key pair of its own (Ed25519 and X25519, like an identity's), certified by the identity key. The identity key stays where it was made, on the **primary**; every other device is a **linked device** holding only its own keys and a certificate. |
| What people see | The user id stays the identity key. Contacts add, verify and message a person; devices are the person's business. The safety number does not change. |
| Addressing | A device is an identity to the relay: it logs in with its own key, has its own mailbox and its own bundle with its own prekeys. Nothing in the relay's routing changes. The account's bundle lists the devices, signed by the identity key. |
| Sessions | One Double Ratchet session per (device, device) pair, as Sesame does. A message to a contact is sealed once per device of theirs and once per other device of one's own, so every device of both people has it. |
| Groups | A device is a leaf. The credential identity is the user id; the leaf signature key is the device key, carried with its certificate in a leaf extension, so members verify a leaf from the tree alone. An identity's devices add and remove that identity's other leaves without being admins. |
| Linking | The new device prints a link with its device id and a one-time secret; the primary takes the link and answers, through the relay, with the certificate and what the device needs to start, under a key derived from the secret. The identity key never leaves the primary. |
| Unlinking and compromise | The primary publishes a new device list without the device and a signed device revocation the relay serves and logs; contacts drop their sessions with it; the identity's other devices remove its leaves. The identity survives a linked device's loss. Losing the primary is losing the identity key: the backup restores it. |
| History | Optional, at link time only: the primary offers a snapshot of history through the blob store, under a key inside the provisioning message. Nothing syncs history afterwards; what happens from then on reaches every device as it happens. |
| Compatibility | A client from 0.8.0 keeps talking to a person with linked devices: it seals to the account's bundle, which is still the primary's, and the primary forwards to the other devices. Linked devices need a relay on 0.9.0, which keeps the device list in the bundle. |
| Relay schema | Version 3, the one groups brought (both are new in 0.9.0): device revocations, served and logged like identity revocations. |

## 2. Goals and non-goals

Goals:

* One person, several running clients (a laptop, a server, later a
  phone), with the same contacts and groups, each device seeing what the
  others send and receive from the moment it is linked.
* A linked device is never as valuable as the identity: taking it gives
  what it has read and the power to write until it is revoked, not the
  identity key, so revoking it is enough and contacts do not have to
  re-verify anything.
* Contacts learn of a person's devices from the person's own signed list
  and nothing else; a relay cannot add a device, and every device a
  contact talks to is certified by the key the contact pinned.
* What the relay learns stays as it is: one more identity per device,
  and a few more envelopes per message.
* The groups design (item 47, section 11 of its note) said what changes
  for devices; this note does that and nothing that contradicts it.

Non-goals, for this item:

* A phone client. The linking flow works by pasting text and shows a QR
  code for the day a phone can scan it; nothing else is built for a
  phone.
* Moving the identity key between devices, or several primaries. One
  device holds the identity key; the backup is how it moves.
* Continuous history sync. History is a per-device record, as before;
  the snapshot at link time is the one exception.
* Per-device verification. Contacts verify the identity; the identity
  vouches for its devices.

## 3. What exists that this builds on

* The identity is an Ed25519 key whose public half is the user id, plus
  an X25519 key for the sealed layer (PROTOCOL.md section 1); a device
  is exactly that pair, so nothing new is needed to make, store or
  protect one.
* The relay keeps identities in a table keyed by the id, with a mailbox,
  a bundle, prekeys, key packages and a transparency log entry per bundle
  change; it does not care what an identity is for. A device is an
  identity to it (section 5).
* Signed bundle capabilities (section 2) say what an identity can do
  before a first message; the device list goes in the same signed
  bundle.
* Lifecycle statements (section 10) are self-contained signed statements
  the relay stores, serves on lookup, logs and lets clients push inside
  messages; a device revocation is one more of those.
* Sessions are kept per peer id, several per peer, with the initiator
  rule (section 8); a device id is a peer id, so per-device sessions
  need no new store.
* Groups verify every leaf against its credential (section 13.1) with a
  private-use leaf extension for the sealing key; a second extension for
  the certificate follows the same pattern, and the membership rules
  already name the committer's identity, not its leaf.
* The invite and group links (`silver://add/`, `silver://group/`) and
  their QR codes give the linking link its shape.

## 4. Keys, certificates, statements

### 4.1 Device keys

A device generates, on first run in linked mode, an Ed25519 signing key
and an X25519 key exactly as an identity does. Its **device id** is the
b58 of the Ed25519 public key, 44 characters like a user id; it is shown
to the owner in `/devices` and to nobody else. The primary's device is
the identity itself: its device id is the user id, and it needs no
certificate.

### 4.2 Device certificate

```json
{ "account": "<user id>", "device": "<device id>", "created_at_ms": n,
  "name": "laptop", "signature": "<b64 64 bytes>" }
```

`signature = sign_IK("silver-messenger/v5/device", account (32) || device (32)
|| created_at_ms (8 BE) || name length (1) || name)`, with `name` at most
32 bytes of UTF-8 without control characters, chosen by the owner and
shown only to the owner's devices. A certificate verifies against the
account's identity key alone, so a contact who has the account pinned
can check a device without the relay. Certificates are never revoked in
place: a device is revoked by a statement (4.4) and dropped from the
list (4.3).

### 4.3 The device list in the bundle

The account's bundle (section 2) gains

```json
"devices": [ <certificate>, ... ],
"devices_signature": "<b64 64 bytes>"
```

with `devices_signature = sign_IK("silver-messenger/v5/device-list",
dh_public (32) || count (2 BE) || (device (32) || created_at_ms (8 BE))*)`
over the devices in ascending device id order. The list holds the linked
devices only (the primary is the bundle's owner) and at most 8 of them.
It is signed as a whole so a relay cannot serve a list with one device
left out: the signature covers the set. The bundle's transparency leaf
(section 11.2) grows by the list, so a change of devices is a logged
bundle change like a prekey rotation:

```text
|| devices? : 0x00, or 0x01 || count (2 BE) || (device (32) || created_at_ms (8 BE))* || devices_signature (64)
```

A relay that does not keep the field (before 0.9.0) drops it when it
re-serialises the bundle, which is why linked devices need the `devices`
relay feature: a client on such a relay does not link devices, and one
that has devices and finds itself on such a relay says so and works from
the primary alone.

A linked device's own bundle is an ordinary bundle signed by the device
key (its `dh_public`, its prekeys, its capabilities) plus

```json
"device_of": <certificate>
```

so whoever looks the device up learns whose it is and can verify the
claim against the account. The relay verifies the certificate on
`publish` (it costs one signature check) and refuses a bundle whose
`device_of` does not verify, so a device id cannot claim an account it
is not certified for; that is a courtesy, since clients verify it again.

### 4.4 Device revocation

```json
{ "account": "<user id>", "device": "<device id>", "created_at_ms": n,
  "signature": "<b64 64 bytes>" }
```

`signature = sign_IK("silver-messenger/v5/device-revocation", account (32)
|| device (32) || created_at_ms (8 BE))`. Made by the primary when the
owner unlinks a device or reports it lost; sent to the relay in a
`revoke_device` frame on the primary's authenticated connection; stored
under the device id; served in every `lookup_result` for the device and
for the account (`device_revocations`); logged in the transparency log
as a revocation of the device (6.1); pushed inside messages to contacts
that advertise `lifecycle`, as identity revocations are. The relay
disconnects the device if it is online, telling it why, refuses its
later logins and publishes, drops its mailbox and deposits, and refuses
envelopes for it with `not_found`. A contact that sees one for a device
it has sessions with drops those sessions and stops sending to it. A
device that sees its own revocation forgets its keys and says so.

The relay takes the statement only for a device it knows as the
account's: one on the account's published list, or one whose own bundle
carries the account's certificate. Otherwise any account could cut any
identity off by calling it a device of its own. A device already revoked
is answered again without a second entry, so a client that lost the
reply may repeat itself.

An identity revocation (section 10.1) covers every device: a contact
retires the contact, devices included, and the relay refuses the devices
too, since their certificates name a dead account.

### 4.5 Succession

A succession (10.2) moves contacts to a new identity. Devices do not
move with it: the new primary links them again, which is one link each.
The design is honest about this rather than carrying certificates across
keys; rotations are rare.

## 5. Delivery

### 5.1 Per-device sessions and fan-out

A message to a contact is one plain body, encrypted once per session:
one session per device of the contact (their primary is one of them) and
one per other device of one's own. Each becomes an envelope to that
device's id, sealed to that device's sealing key, submitted as today. The
recipient's devices each find it in their own mailbox; the sender's other
devices find their copy and show it as sent (5.3). A contact with two
linked devices and a sender with one costs four envelopes where one was
sent; the sizes stay what they were.

The message goes by one id everywhere: the id of the envelope to the
contact's primary. Every other envelope is a copy, and its body says so
in a new optional field `id` (6.2), so the recipient's devices record and
acknowledge the same message whatever envelope brought it, and the
sender's devices, told the id in the sync copy, mark the same line when
the receipts come. The relay sees envelopes with ids of their own, as it
must (it de-duplicates by id), and nothing that ties them together.

A client reports a message sent once the relay has taken every envelope
of it. The envelope to the contact's primary refused for good is the
message refused; a copy refused as for a device the relay does not
deliver to (`not_found`) means the device is gone, and the sender drops
its sessions with it and fetches the list again before the next message;
any other refused copy is reported and the message still counts as sent
once the rest are, since it reached the person.

Not every content spreads alike: a text or a file goes to every device of
the contact's and, as a sync copy, to every device of one's own; a
receipt or a lifecycle statement (an identity's or a device's) goes to
every device of the contact's and to no device of one's own, which learn
what was read by `sync read` and what was revoked by `sync devices`;
cover goes to the one device the contact last wrote from; `sync` and a
provisioning message go to the one device addressed.

Sessions with a contact's devices start the way sessions do now: a fresh
lookup of the device's bundle (with a one-time prekey), a handshake in
the first message. The initiator rule and the five-sessions-per-peer cap
apply per device.

### 5.2 Learning a contact's devices

A client learns the list from the account's bundle: on `/add`, on every
fresh lookup before a session starts, on `/refresh`, and whenever a
message arrives from a device it does not know (5.4). It refreshes a
contact's list at most once an hour by itself, and the relay says when
it is stale: a `send` to a device id whose account has since dropped it
is refused with `not_found` once the revocation is stored, and the
relay's `lookup_result` for the account carries the current list. A
sender that finds a new device on the list starts a session with it
before its next message; one that finds a device gone drops its
sessions with it.

The relay does not add anything of its own: the list is signed, and a
relay serving a stale one is caught by the transparency log as a stale
bundle is (11.4).

### 5.3 Sync between one's own devices

A device's other devices are recipients of everything it sends, in a
form that says what it was:

```json
{ "type": "sync", "kind": "sent", "peer": "<user id>", "id": "<message id>",
  "sent_at_ms": n, "content": { ... } }
```

a copy of a message sent to `peer` (a `text` or `file`), shown as one's
own line in that conversation; and

```json
{ "type": "sync", "kind": "read", "peer": "<user id>", "ids": [ ... ] }
{ "type": "sync", "kind": "contact", "action": "add|remove|alias|verify|block|unblock|files", ... }
{ "type": "sync", "kind": "devices", "devices": [ <certificate>, ... ], "revoked": [ <revocation>, ... ] }
{ "type": "sync", "kind": "received", "from": "<user id>", "id": "...", "sent_at_ms": n, "content": { ... } }
{ "type": "sync", "kind": "leave" }
```

for read marks, contact list changes, device list changes (so a linked
device knows its siblings and the primary's revocations reach it),
messages received from a sender that did not address the other devices
(a client before 0.9.0, which seals to the account only: the primary
forwards those, and only those; a sender that advertises the `devices`
capability in its body has sent to every device itself), and a device
asking to be unlinked (7.2: the primary revokes it on receipt, the other
devices ignore it). `sync` content is accepted only from a device
certified for one's own account and is never sent to anyone else; a
client that receives one from a contact ignores it. Group messages need
no sync: every leaf gets its own copy.

Receipts go to every device of the sender's account, so each device
marks its copy; `read` receipts leave from the device that showed the
message, and its siblings learn through `sync read` that they need not.
Cover traffic goes to the device a contact last wrote from and to no
sibling.

### 5.4 A message from an unknown device

The sealed prefix names the device that sealed the envelope. A body from
a device other than the account's primary carries the certificate in a
new optional field `device` (section 4 bodies, all versions), so the
recipient can attribute the message to the account and verify the device
without a lookup; a client also looks the device up on the relay when it
wants the one-time prekey anyway. A certificate that does not verify
against a pinned account, or names an account the recipient has marked
revoked, makes the message refused as a forgery, not held as a request.
A message from a certified device of an account that is not a contact
is a contact request from that account, as it is today. A body from the
primary carries no `device`.

The capability `devices` in the body says the sender addressed every
device it knew of the recipient's; it is what the primary uses to decide
whether to forward (5.3).

## 6. Wire changes

### 6.1 Relay

| `type` | Fields | Notes |
| --- | --- | --- |
| `revoke_device` | `revocation` | A device revocation (4.4), on the account's authenticated connection, for a device the relay knows as the account's. Stored, served, logged; the device is cut off. |
| `lookup_result` gains | `device_bundles`?, `device_revocations`? | For an account with devices: the linked devices' bundles as the relay would serve them on their own lookups (a one-time prekey popped from each, under the same rules), attached for a client whose own published bundle advertises the `devices` capability, since any other would not use them and their prekeys would be wasted on it; and every device revocation the account has issued, for every client. For a device: its bundle carries `device_of`; `device_revocations` holds its own, if any. |
| `auth_ok` features | `devices` | The relay keeps the device list and `device_of` in bundles, answers `revoke_device`, attaches device bundles to lookups. Absent before 0.9.0; clients then do not link. |
| `publish` | unchanged frame | The relay verifies `device_of` when present and refuses a bundle whose certificate does not verify, whose account is unknown to it, revoked, or has revoked this device, or that lists more than 8 devices or a device it knows to be revoked. A device registers like any identity: it counts against the address's registrations and the identity cap, and takes an invite token where one is required (the primary's link carries it, 7.1). |

Transparency: the bundle leaf grows by the device list (4.3), and only
when the bundle has one, so the leaf of a bundle without devices is
what it was and a relay that drops the fields and a client that keeps
them agree on it. A device revocation is logged as a `revocation` entry
whose subject is the *device* (an identity to the relay) with leaf
`SHA-256("silver-messenger/v5/transparency-device-revocation" || account || device || created_at_ms || signature)`;
no new entry kind, so a client from before devices replays the log as
before and never looks a device up, while a client that does expects
the statement in the device's answer as it expects an identity
revocation in an identity's. A device's own bundles are logged under the
device as an identity's are. The client's checks (11.4) apply to device
bundles as to any bundle.

Limits: 8 linked devices per account; `revoke_device` counts against the
address's registrations for the hour like the other statements; a
`lookup` of an account with devices costs the requester one lookup and
the target's hand-out budget one prekey per device.

### 6.2 Body fields and capabilities

* `device` (optional, any body version): the sender's certificate (5.4).
* `id` (optional, plain bodies): the id the message goes by, on a copy
  for a device other than the one the message was first sealed for
  (5.1); printable ASCII, at most 64 bytes. Absent when the envelope's
  id is the message's.
* Content kind `sync` (5.3), with `kind` as listed.
* Content kind `device_revocation`: a device revocation (4.4) pushed to
  a contact inside a message, as identity revocations are, so the
  contact drops its sessions with the device at once rather than at its
  next lookup. Only to contacts that advertise `devices` in their
  bodies, which know the kind; a client before 0.9.0 would refuse the
  whole body as unreadable.
* In-body capability `devices`: the sender is a 0.9.0 client that seals
  to every device it knows (5.3, 5.4). Advertised always from 0.9.0.
* Bundle capability `devices`: the identity's client reads `sync`, is a
  primary or a linked device, and may be sent to per device. A linked
  device's bundle advertises it; a primary's does once it is on 0.9.0.
  A sender treats an account whose bundle lacks it as one device, the
  bundle's own, as today.

### 6.3 Groups

* Leaf extension `0xF002` (`silver_device`): the device certificate,
  encoded as `account (32) || device (32) || created_at_ms (8 BE) || name
  length (1) || name || signature (64)`. Present in every linked device's
  leaf and absent from a primary's.
* Verification of a leaf (13.1) becomes: the credential identity and the
  signature key are the same key (a primary), or the leaf carries a
  `silver_device` whose `device` is the signature key, whose `account`
  is the credential identity, and whose signature verifies. Every
  0.9.0 key package and leaf declares capability for `0xF002`; the
  required capabilities of existing groups are left as they are.
* Membership rules (13.7) gain: a committer may add leaves whose
  credential identity is its own and remove leaves whose credential
  identity is its own, admin or not; the identity, not the leaf, is what
  the admin list names, and a group's members as shown are identities.
* No released client has groups without device leaves (both are new in
  0.9.0), so every member of every group can verify one, and a device is
  added to a group as soon as its account is in it; no check for members
  on an older client is needed. Should a later leaf extension ever need
  one, the capability every leaf declares is what such a check would
  read.
* Key packages are per device (each device deposits its own under its
  own id); an admin adding an account fetches the account's device list
  and one key package per device, and adds every device in one commit.
  A device that joins the account later is added by one of the account's
  devices (rule above), from the key package the new device deposited.
* Fan-out and Welcomes go per leaf, which they already do. A Welcome
  from a device of one's own identity is taken without asking, as is
  one for a group the primary named at link time (7.4), whose alias is
  applied from the start.
* Rejoin (13.8) is per leaf: a device out of sync asks the admins and
  the account's other devices, and any of them may answer. Leaving
  (13.7) is per leaf too: `/group leave` on one device takes that
  device's leaf out, and the identity stays a member by its other
  devices until they leave as well. An invite link names the device
  that made it as the one to ask, so the request reaches the device
  whose owner is watching.

### 6.4 The link

```text
silver://link/<device id>?secret=<b58 16 bytes>&relay=<percent-encoded url>[&name=<percent-encoded>]
```

printed by the new device with a QR code. `secret` is 16 random bytes
made for this link; the link is good for ten minutes and one use. The
relay named is the one the device registered its bundle with, which must
be the primary's (one relay is one network).

## 7. Lifecycle

### 7.1 Linking

On the new device: `silver --link` (or the first-run prompt's "link this
device to an identity you already have") generates the device keys,
registers the device's bundle with the relay (without `device_of` yet;
prekeys included, so the primary can start a session with it), prints
the link and the QR code, and waits. The device does not know the
account yet.

On the primary: `/devices link <link>` (or `/devices link` and paste).
The primary makes the certificate with `created_at_ms` now and the
name from the link or the owner's answer, looks the device up, starts a
session with it, and sends a **provisioning** message: the certificate,
the account's user id, the device list as it will be published (the new
device on it) and the revocations issued, and the reference of a
**snapshot** (7.4), a file on the relay's blob store with the contacts
(aliases, verified marks, pinned bundles, file settings, the revoked
mark), the blocked ids, the groups (ids, names, aliases) the account is
in, and the recent history; the whole body is encrypted once more under
`HKDF-SHA256(secret, "silver-messenger/v5/link")` before it goes into
the session, so that only the device that printed the link reads it,
whoever else was handed the device id. The contacts go in the snapshot
and not in the message because a body holds 32 KiB and a pinned bundle
is kilobytes; the message itself holds the certificates and
revocations, at most a few hundred bytes each. The primary then
publishes its bundle with the device on the list, adds the device to
every group it can (6.3), and syncs the new list to its other devices.

The new device decrypts the provisioning message with the secret,
verifies the certificate against the account id it names and the
account against the sender, keeps the certificate and the list,
republishes its bundle with `device_of`, and is linked; then it fetches
the snapshot and takes the contacts, the blocked ids, the groups and
the history. If the primary sends something under the wrong secret (a
stranger who saw the device id) the device sees a message it cannot
open from an unknown peer and ignores it, as it ignores any such thing.
If the primary never answers, the link expires and the device says so;
`silver --link` again makes a new one. A snapshot that cannot be fetched
leaves the device linked with an empty contact list, and says so: the
primary's later `sync contact` messages fill in what changes from then
on, and the owner adds the rest by hand.

The invite token: a closed relay takes a device's registration only with
a token; the primary's config holds it and the owner passes it to the
new device on the command line as for any first registration.

### 7.2 Unlinking

`/devices remove <n>` on the primary: a device revocation (4.4) to the
relay, the device dropped from the published list, `sync devices` to
the remaining devices, the device's leaves removed from every group by
the primary's next commit in each, and the revocation pushed to
contacts inside their next message. The device itself, on seeing the
revocation (the relay closes its connection with a message that says
so, and refuses its next login), says so and stops; it does not erase
itself on the relay's word alone, since a relay could say so falsely,
and `/devices leave confirm` erases it. `/devices leave confirm` on a
linked device asks the primary the same by a `sync leave` message,
waits for the relay to take it, erases its keys, contacts and history
(the settings and the files saved in `downloads/` stay) and exits; the
primary revokes the device on receipt. A linked device that can no
longer reach the primary is removed from the primary when the owner
gets to it.

### 7.3 Losing a device

A lost linked device is removed as above; its sessions and its share of
group epochs are gone with the next commits (a week at most by the
self-update rule, at once by the removal). A lost primary is a lost
identity key: `--import-backup` on a new machine restores the identity
and, from the backup, the contacts and the device list; the restored
primary republishes the list, links nothing anew, and the linked devices
carry on (their certificates are valid; the primary re-establishes
sessions with them). A primary that is gone with no backup is the
existing story: `/revoke` from a linked device is not possible (it holds
no identity key), so the pre-signed revocation certificate stays what it
was, in the backup; a linked device keeps working until the certificates
are useless because the account is dead to everyone, and the owner
starts a new identity.

### 7.4 The snapshot

The primary, when linking, gathers one snapshot: the contacts, the
blocked ids, the groups it is in, and the last N days of history
(default 30, `days` in `/devices link`, 0 for none) of every contact and
group, each line with the furthest receipt it got. The snapshot is one
JSON document (`format: silver-messenger-snapshot`, `version: 1`) sent
as a padded file of section 4.5: encrypted under a key of its own,
uploaded to the blob store, its reference (a `file` content) inside the
provisioning message. The new device fetches it, takes the contacts
with their sequence numbers reset (each device numbers its own stream),
imports the lines into its own history files, and shows them. A
snapshot larger than a file may be (16 MiB) is cut at the newest
messages that fit. Nothing syncs history later; a device that was off
for a week has the week's messages in its own mailbox (up to its quota),
and beyond that the messages are gone for it, as they would be for the
one device today.

## 8. Client

### 8.1 Storage

* `identity.json` on a linked device holds the device keys and, under
  `linked`, the account id, the certificate and the name; the file's
  shape is what it is for a primary plus that field, so everything that
  loads an identity keeps working.
* `contacts.json`: each contact gains `devices` (the list as last
  fetched, with `fetched_at_ms`) and per-device `received` sequences;
  `sent_seq` stays per contact, since every device of one's own numbers
  its own stream.
* `sessions.json`: unchanged in shape; peers are device ids. A contact's
  primary is keyed by the account id, as before.
* `devices.json` on the primary: the linked devices with names,
  certificates and revocations issued; on a linked device the same list
  as last synced.
* Groups: `MemberInfo` gains `device` (the leaf's device id, the
  identity's own for a primary); the member list shown is by identity.

### 8.2 Engine

* `devices` module: the device state (the list, the certificate on a
  linked device, revocations) and what to fan out to, given a contact
  and one's own list. `linking` module: the link, the provisioning
  message, the snapshot; `Client::link_device` on the primary and
  `take_link` on the device.
* `Client::send_content` becomes send-to-account: it resolves the
  account's devices (from the bundle it holds or fetches; the devices'
  bundles come with the account's lookup, or from a lookup of the device)
  and one's own, encrypts per session, submits every envelope, and
  reports one `Delivery` per message with the copies listed; the
  `Sent`/`Rejected` events are aggregated as 5.1 says, under the
  message's id. `Client::send_sync` tells one's own devices something;
  `Client::revoke_device` (the primary) sends the statement, republishes
  without the device and syncs the list.
* Receiving: a body with a certificate is from the account the
  certificate names, once the certificate verifies for the key that
  sealed the envelope (else the message is dropped as a forgery); the
  front end sees `from` as the account and `device` as the certificate.
  `sync` is taken from one's own devices only and raised as an event of
  its own; a device list from the primary is applied by the client before
  the event. A `device_revocation` ends the sessions with the device. A
  text or file from a sender whose body does not advertise `devices` is
  passed on by the primary as `sync received`.
* The transparency check treats device ids as subjects like any other:
  a device's bundle that comes with an account's answer is checked
  against the device's latest logged bundle, and a served device
  revocation against the revocation logged under the device; one that
  does not hold up is left out of the answer and reported, and the
  answer for the account stands.

### 8.3 Interface

`/devices` lists this account's devices with names, which one this is,
and when each was linked; `/devices link <link> [days]` (primary; `days`
of history to send, default 30, 0 for none), `/devices remove <n>`
(primary), `/devices name <n> <name>` (primary: a fresh certificate for
the same key, which the renamed device takes as its own from the next
`sync devices`; there is no sync kind for a device to ask for a name, so
naming stays on the primary), `/devices join` (primary: every linked
device into the groups it is not in yet, for one that had no key
packages on the relay when it was linked), `/devices leave confirm`
(linked device). `silver --link` on a fresh data directory prints the
link and waits, and a first run at a terminal asks whether to link the
computer instead of starting an identity. On a linked device the status
line names the device, and the identity's id is what `/me`, the invite
link, the safety number and group membership go by. The System pane
announces links and removals; a sibling's reading is not announced, the
marks show it. `/session` says how many devices a contact has and how
many are under a session.

## 9. Relay

* Tables `device_revocations` (`device id -> DeviceRevocation JSON`) and
  `device_revocations_by_account` (`(account, device)`, so an account's
  lookup finds the ones it issued without a walk), in schema version 3,
  the one groups brought: both are new in 0.9.0, and 0.8.0 refuses the
  database for the group tables already (UPGRADING.md). Backup format 2
  carries them in two record kinds of its own.
* Bundles keep `devices`, `devices_signature` and `device_of` (the bundle
  type gains the fields; the relay re-serialises what it parsed, so the
  fields survive from 0.9.0 on).
* `publish` verifies `device_of` (the certificate, and that the account
  is registered here and not revoked), refuses a revoked device whatever
  it now says and a list that names one; `lookup` attaches device
  bundles for a client whose bundle advertises `devices` and revocations
  for every client; `revoke_device` stores, logs and cuts the device off;
  `send` to a revoked device is refused with `not_found`; a revoked
  device, and a device of a revoked account, is refused at login and
  told why. An identity revocation closes the connections of the
  account's listed devices.
* Metrics: `silver_relay_devices` (bundles that carry `device_of`,
  counted as bundles come and go rather than by a walk at every scrape)
  and `silver_relay_device_revocations_total`; `admin status` shows both.
  Nothing per account.
* Limits: 8 devices per account; statements against the registration
  budget; the identity cap counts devices.

## 10. What the relay learns, and the threat model

New rows, stated as they are:

* **How many devices a person has, and which ids they are**: the device
  list is in the signed bundle the relay serves, and each device logs in
  under its own id, so the relay pairs devices with accounts and sees
  each device's connections. It could already see one client's; now it
  sees three.
* **Message multiplicity**: a message to a person with two devices is
  two envelopes from one anonymous connection within a second; the
  relay infers device counts from bursts as it infers group sizes.
* **Nothing new about content or senders**: sync copies are ordinary
  sealed envelopes to one's own devices; the relay sees a person's
  devices receiving mail at the same moments as their contact does,
  which it could infer from the list alone.

What a linked device's thief gets: what the device holds (its history,
its sessions, the group epochs it is in, the contact list) and the power
to write as the person until the primary revokes it; not the identity
key, so contacts need nothing re-verified once it is revoked, and the
revocation is served and logged so the relay cannot keep the device
alive for anyone who checks the log. What a primary's thief gets is
what an identity thief gets today, plus the power to link and revoke
devices. A device that a hostile relay keeps serving after its
revocation is caught by the log, as a stale bundle is; a hostile relay
cannot add a device (the list is signed) and cannot make a certificate.
What is weaker: a person's blast radius on compromise of any device is
everything that device could read, which with sync is every
conversation, as it is for the one device today.

## 11. Sizes

A text to a contact with `d` devices from a sender with `o` other
devices is `d + o` envelopes of 320 to 480 bytes; for two people with
two devices each, four envelopes where one was. A device certificate is
about 200 bytes of JSON in a body (one padding step, sometimes). A
provisioning message is a few kilobytes plus the contact list; a history
snapshot is a file. A leaf with the certificate extension is 136 bytes
larger; a 256-member group with two devices each is a 512-leaf tree,
which is within what section 13.10 measured for 256 members times two.

## 12. Tests

* Protocol: certificates, lists and revocations sign, verify and refuse
  tampering; the bundle leaf with devices; the `sync` and `device` body
  fields round-trip; vectors for each.
* Client: a link end to end between two ephemeral clients (the
  provisioning message under the secret, the wrong secret ignored, the
  device certified and republished); fan-out to a contact's devices and
  one's own with sent copies shown; a contact's new device picked up
  before the next message and a revoked one dropped; the primary
  forwarding a 0.8.0 sender's message; groups with device leaves added
  by the account's own device, the rule refused for another's device,
  and a group with an old member left alone; the transparency check on
  device bundles and revocations.
* Relay: device bundles kept and served with the account, `device_of`
  verified, the list cap, `revoke_device` storing, logging and cutting
  off, a revoked device's login refused, the tables in the schema
  migration and the backup.
* Terminal: `silver --link` and `/devices link` between two clients
  through a relay, a message from a contact reaching both, a sent copy
  on the other device, a removal, and the older-client case with the
  release binary of 0.8.0 when it is on the runner.

## 13. Implementation order

Each step is one commit on `main` with its tests:

1. Protocol: device certificate, list, revocation, leaf hash, body field
   and `sync` content, capabilities and feature, link, vectors.
2. Relay: bundle fields, `revoke_device`, lookups with device bundles,
   log entries, the tables in schema 3 and backup format 2, metrics,
   tests.
3. Client, sessions: per-device fan-out and sync, device list refresh,
   revocations, the primary's forwarding; tests.
4. Client, linking: `--link`, the provisioning message, the snapshot,
   devices in the backup.
5. Groups: the `silver_device` leaf extension, the verification and
   membership rules, per-device key packages, the old-member check.
6. Terminal client: `/devices`, the first-run prompt, `/session`.
7. Documents: PROTOCOL.md section 14, the threat model, README,
   OPERATING.md, UPGRADING.md, CHANGELOG, roadmap.

Compatibility through the steps: nothing sends a `sync` body or a
certificate until step 3, nothing links until step 4, and no device leaf
enters a group until step 5, so a partially landed tree is the groups
client with more code, as a partially landed groups tree was 0.8.0.
