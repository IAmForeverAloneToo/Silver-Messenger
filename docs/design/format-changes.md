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
encrypted. The names become `history/<MAC of the id>.jsonl` (§5.4 says
under which key, which is not the data key). Line lengths still approximate message lengths and that
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
exactly that reason. Section 5 settles how they are built, which this
section deliberately did not: where a counter that an attacker cannot
also roll back is supposed to live, what it costs to raise one on every
message, and how a directory of files named after nothing is still
enumerable.

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

## 5. How the on-disk pair is built

Section 1 said what SM-C-24 and SM-C-25 become. Writing them turns out to
need four things settled first, and none of them is obvious enough to
decide in the code.

### 5.1 What a rollback counter can and cannot catch

The counter has to live somewhere the attacker cannot put back along with
the file it protects — and everything this program writes is in one
directory that the attacker, by assumption, can write to. So there is a
limit here, and it should be stated rather than implied away: **an
attacker who rolls the whole directory back to a consistent earlier
state cannot be caught from inside it.** Every file agrees with every
other, because they did once.

What the counter catches is the *partial* rollback, which is the finding:
one file put back while the rest moves on. Put `sessions.json` back and
its counter is behind what the anchor says, so it is refused; put the
anchor back too and now every *other* file is ahead of it, which is the
same signal from the other side. Both directions are tampering and both
are refused. That is a real narrowing — it is the difference between
"replace one file" and "replay a whole directory from a backup you
already had" — and it is all a local counter can be.

Two things sit outside it and stay documented rather than closed. Full
directory replay, above. And deleting the directory, which no counter
prevents and which is not a rollback: a fresh directory has no anchor to
disagree with.

### 5.2 Where the counters live: not in `vault.json`

Section 1 said "kept in the vault", and that is nearly right and wrong in
one important way. `vault.json` is **not encrypted** — it holds the KDF
parameters and the wrapped data key, both of which have to be readable
before anything can be decrypted. Putting a per-file counter map there
would put the *file names* there, and under SM-C-25 those names are what
we just went to the trouble of making meaningless. Worse, anything that
mapped a name back to a conversation would hand over the contact list in
plaintext, which is the leak SM-C-25 exists to close.

So the anchoring is two-level:

* **`state`**, a new encrypted file beside the others, bound to its own
  name. It holds the generation of every file, and the conversation
  index (§5.4). What stops an older `state` being read as the current one
  is not its own generation in its AAD but the generation *inside* it,
  checked against the number below — which is the same strength (an
  attacker cannot forge either) and is simpler, because reading the
  kept-back copy then needs no guess about which generation it was at.
* **`vault.json`** gains exactly one new number: the generation of
  `state`. A plaintext integer that says "the state file must be at
  version N" leaks how many times the directory has been written, which
  the modification times already say.

Each file carries its own generation too, in its header, in the clear.
That is not a weakening — the number is also in the associated data, so
changing the header makes the tag fail, and a header that cannot lie is
as good as one that is encrypted. It is what makes §5.5 possible: a
reader that has lost `state` can still open the files, which it could not
if the only way to know a file's generation were the record that was
lost. Two magic numbers distinguish the shapes, so nothing has to guess.

**A directory with no protection at rest is not bound at all.** There is
no AEAD to put a generation into, and an attacker who can write the
directory can simply edit the plaintext; a counter there would be
decoration. The client already says at start that such a directory is
not protected, and that statement now covers this too.

Each write is then: write the file, write `state`, write `vault.json`,
in that order, each atomically and each fsynced with its parent
directory, as `write_atomic` has done since 0.15.0. **The file goes
first and the anchor is raised after it**, which is worth spelling out
because the opposite order is the tempting one and is wrong.

A crash between the two leaves the file one generation ahead of the
anchor. So *ahead by one* is the interrupted-write case, accepted with a
line in the log; *behind*, or ahead by more than one, is refused. Raising
the anchor first would invert that — the crash case would be a file one
generation behind, which would have to be accepted, and a file one
generation behind is precisely the old copy the attacker is putting
back. It would hand away the whole point.

Accepting "ahead by one" costs nothing, because a file at a generation
the anchor has not reached is one the attacker would have to encrypt,
and the key is what they do not have. The only way to produce one is to
have seen the directory at that generation and rolled the anchor *back*
— and an anchor rolled back leaves every other file ahead of it by more
than one, which is refused, unless the whole directory went back
together, which §5.1 has already said is outside what this can see.

### 5.3 What history costs, and why the counter is a line count

`append_history_line` is an append with no fsync today. A generation
raised per line would make every message a `state` write, a `vault.json`
write and two fsyncs — for a log that a person adds to at conversational
speed, that is affordable; for a client collecting five hundred queued
messages after a week offline, it is five hundred of them.

So the unit is the **write operation, not the line**: a batch of appends
records the file's new length once. Which makes the counter for a history
file its **length in bytes**, and the check exact rather than
approximate: a file shorter than the record says has been truncated.

Length, and not a count of lines, because of what goes in each line's
associated data. Section 1 says "its index", and the index that works is
the line's **byte offset**, not its ordinal — an offset is what an append
already knows, and an ordinal would make every message read the whole
conversation to find out what number it is. The offset is as strong: take
a line out and everything after it moves, so none of it opens; put two
lines the other way round and neither is where it was written. What the
offset cannot show is the end being cut off, and that is what the
recorded length is for.

Longer than the record is not tampering but the ordinary interrupted
append, and it is safe to accept for the same reason a whole file one
generation ahead is: producing a line that opens at the offset it sits at
takes the key.

### 5.4 Enumerating a directory of meaningless names

`conversations()` reads the history directory and parses each file name
back into a contact or group id. Under SM-C-25 there is nothing to parse,
and the two callers both need the *complete* set: `sweep_expired` deletes
messages whose timer ran out, so a conversation it cannot see is one
whose disappearing messages never disappear, and `export_history` writes
what it can find. Rebuilding the list from the contacts and groups files
is not the same set — history outlives a contact who was removed, and
that is exactly the history a sweeper must still reach.

So `state` carries the index: for each history file, its name and the
conversation it belongs to.

The **key** those names are MACed under does not live there, though —
it lives in `vault.json`, wrapped under the same key-encryption key as
the data key. Two reasons, both found by writing it. It cannot be
derived from the data key, because that key rotates whenever a
passphrase is set or dropped, and every conversation on disk would be
renamed each time. And it must not be in `state`, because losing that
record would then lose the names: the files would still decrypt and
nobody would know which was whose. In the vault it is re-wrapped by a
rotation and left alone, and a lost `state` costs the index, which can
be rebuilt for every conversation whose contact or group is still
known.

### 5.5 A `state` file that will not open

This is the new failure that did not exist before: one small file whose
loss refuses the whole directory. `write_atomic` plus the fsync of the
parent makes losing it unlikely, and the previous version is kept as
`state.prev` so an interrupted write has something to fall back to.

If both are unreadable the client says so and stops, rather than quietly
carrying on without the protection it claims to have. Precisely: the
**unlock still succeeds** and every read and write then refuses with the
reason. Failing the unlock would be the tidier-looking choice and the
wrong one — the way out needs the data key, so a directory that would not
unlock would be a directory with no way out.

That way out is `--reset-rollback-protection`, which rebuilds `state`
from the generations the files themselves carry and says plainly, in the
log and to the person running it, that whatever happened to the directory
before that moment is now unprovable. From the next write on it is bound
again. A directory that cannot be opened at all would be a worse answer
than one that can be opened with its history of tampering forfeited, and
the choice belongs to the person whose messages they are.

### 5.6 The migration

One pass on first unlock of a directory written by an older version,
resumable and idempotent, in the shape of the data-key rotation the
vault already does:

1. For each `history/<id>.jsonl`, decrypt each line under the old name,
   re-encrypt it under the new name with its index in the AAD, and write
   it to `history/<HMAC>.jsonl` atomically. Record the id in the index.
2. Remove the old file only once the new one is written and fsynced.
3. Stamp every file's generation into `state`, then write `vault.json`.

A crash leaves an old-named file whose new-named counterpart may or may
not exist; on the next unlock, one that exists means step 2 was
interrupted and the old file is removed, and one that does not means
step 1 was, and it is done again. The vault version field carries the
change, so an older client refuses the directory rather than reading half
of it — which is what that field has always been for.
