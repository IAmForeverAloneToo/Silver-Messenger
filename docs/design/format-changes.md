# Design note: the changes that need a new format

Roadmap item 57. Four findings from the first review (section 13.3) and
one from its relay half were left out of 0.10.1 and 0.11.0 for the same
reason: each changes a wire or an on-disk format, and neither release was
allowed to. This note settles what each becomes, which release carries
it, and what old peers and old directories do meanwhile — before any of
it is written, as the roadmap item asks.

Nothing here is reachable by a stranger. Every one is either defence in
depth against an attacker who already holds something (a key, write
access to a live directory) or a leak of metadata the threat model
describes. They are grouped by what they change, because that is what
decides when they can ship.

## 1. The two that change what is on disk

**SM-C-24, rollback binding.** The AAD of an encrypted file is its name
and nothing else, so somebody with write access to a live directory can
put back an older `sessions.json` (reusing ratchet state, so the next
send repeats a message key), an older `contacts.json` (undoing a
key-change warning or a `verified` mark), or drop, reorder and duplicate
history lines. Each file gains a generation counter bound into its AAD,
kept in the vault and raised on every write; a file whose generation is
behind the vault's is refused rather than read. History lines gain their
index in the AAD, so a line cannot be moved or dropped without the read
failing.

**SM-C-25, history file names.** `history/<user id>.jsonl` names the
contact in the file name, so a directory listing is the contact and group
list and the modification times are the activity times — with every file
encrypted. The names become `history/<HMAC of the id under the data
key>.jsonl`. Line lengths still approximate message lengths and that
stays documented rather than padded: padding history to hide lengths from
somebody who already has the directory is a lot of disk for an attacker
who, in the cases that matter, also has the key.

These two go together, in one release, because they touch the same files
and want one migration: on first unlock, rewrite each history file under
its new name and stamp every file's generation. The migration is
resumable and idempotent — it is the same shape as the rotation the vault
already does — and a directory half-migrated by a crash finishes on the
next unlock. A directory written by an older client is migrated on sight;
a directory written by a newer one is refused by an older client, which
is what the vault version field is for and what it already does.

**Neither needs the wire to change**, so they need no protocol bump and
no coordination with peers. They should ship first, on their own, for
exactly that reason.

## 2. The two that change what goes on the wire

**SM-P-14, the message id inside the authenticated body.** A message's id
is chosen by its sender and sits outside every AEAD and signature, so a
relay renames a message and the recipient's edits, deletions, reactions
and receipts all name the new id. A copy in the plain body already exists
for device copies. It becomes mandatory and is compared against the
envelope id, and a mismatch is refused.

**The device counter-signature.** A device certificate is signed by the
account, which proves the account meant to enroll *a* device; it does not
prove the device agreed. The device signs the certificate too, so an
account cannot enroll a key its holder never offered. SM-R-01's own path
is fixed; this closes the shape of it.

Both add a field. The transition is the usual one and is why they go
together: the field is optional for one minor release, during which a
client sends it and accepts its absence; then required, at which point a
client that never sent it cannot start a session. Two releases, not one,
and the second is the one that may not be skipped in an upgrade.

## 3. The one that is a decision, not a change

**SM-P-04.** A v4 message carries no signature at the sealed layer —
that is the point of v4, and what makes it deniable. What tells the
responder the initiator is who they claim is `init.identity_dh_signature`
and the fact that the handshake needs the initiator's X25519 secret. But
that signature is the initiator's *published, public* bundle signature
over their own DH key: a static value anybody can copy. So whoever holds
A's X25519 secret alone — not A's identity key — can start v4 sessions as
A with every one of A's contacts.

The review's fix is a fresh signature by the identity key over the
transcript. **That trades away exactly what v4 exists for.** A signature
over the transcript is a transferable proof that A took part in this
handshake, which is what the deniable body was built to avoid; the
response to the first review already recorded that a transcript signature
is not deniable, contrary to that report's aside. So this is not a fix to
schedule — it is a choice between two properties, and it belongs to
whoever decides what the program is for:

* **Keep v4 deniable**, and accept that the X25519 key is an
  impersonation key of the same weight as the identity key. Both live in
  the same file, so in practice the difference only matters to an
  attacker who reads one and not the other — which the September 2026
  review showed is not far-fetched, since a memory read finds the DH key
  in use on every envelope.
* **Bind the identity key freshly**, and lose deniability for v4
  handshakes while keeping it for v4 bodies.

The review's *minimum* is neither: say so in the threat model. That is
done as of 0.15.0 and was overdue — the threat model's section on a
compromised Diffie–Hellman key listed only what it decrypts, and has
listed impersonation since. Whichever of the two above is chosen later,
the documentation is no longer wrong in the meantime.

## 4. Order and versions

1. **The on-disk pair**, in the next minor release. No peer coordination,
   one migration, and it closes the evil-maid rollback that is the
   sharpest of the five.
2. **The wire pair as optional fields**, in the release after, so every
   client in use is sending them before anything requires them.
3. **The wire pair as required**, one release later, with the changelog
   saying plainly that a client older than the first of those two cannot
   start a session after it.
4. **SM-P-04**, whenever the deniability question is answered, and not
   before.

Nothing above is a reason to delay 1.0 except its own schedule: none of
these is a break, and the on-disk pair can land without touching a peer.
