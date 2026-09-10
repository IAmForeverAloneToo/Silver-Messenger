# Replacing the Diffie–Hellman key under the same identity

*Design note, September 2026. Written before the code, as
`docs/design/format-changes.md` section 3 promised: that section put the
two properties side by side and left the choice. This note records the
choice and what follows from it.*

## 1. The decision

**Protocol v4 stays deniable.** SM-P-04 in the second review observed
that whoever holds an identity's long-term X25519 secret alone — not its
signing key — can start v4 sessions as that identity with every one of
its contacts, because a v4 handshake authenticates the initiator by a
*published, static* signature over that key plus the handshake needing
the matching secret. The review's fix was a fresh signature by the
identity key over the transcript.

That fix is declined, and not for cost. Deniable authentication *means*
the responder could have produced the transcript alone, which means the
authenticator has to be something derived from a Diffie–Hellman secret
rather than a signature — and a secret that authenticates you is, when
stolen, a secret that impersonates you. Signal has exactly this shape:
its identity key *is* an X25519 key, and whoever holds it starts
sessions as its owner. This program's only difference is that it keeps
two keys where Signal keeps one, and the review noticed that the second
carries the same weight as the first. That is true. It is also the
defining property of the thing item 42 chose on purpose, and giving it
up would close a gap that only exists relative to a design where
deniability is not wanted.

What the observation does call for is two things the program did not
have, and this note is about them:

1. **The key has to be replaceable without a new identity.** Today the
   only answer to "the Diffie–Hellman key was read out of memory" is
   `/rotate`, which hands the whole identity over: a new safety number,
   a succession every contact has to take, devices re-linked. For a key
   the threat model now calls an impersonation key, that is the wrong
   size of answer. Rotating the X25519 key alone costs contacts one
   key-change notice and one new handshake.
2. **A responder has to accept only the key the identity currently
   publishes.** Rotation is worth nothing without this: the old key's
   bundle signature stays a valid signature by the identity over the old
   key forever, so a responder that checks the signature and stops would
   go on accepting handshakes made with a key its owner has retired.
   Today's responder does exactly that — it verifies the signature
   (`Session::respond`) and hands the claimed key up for the front end
   to compare with the *pinned* one, which catches a key the peer never
   published but not a key the peer published and has since replaced.

With both, an attacker holding the old secret can still read what was
sealed to it — they always could — but can no longer start a
conversation as its owner with anybody whose client makes the check.
That is the property rotation buys, and it is the whole of it.

## 2. What rotates and what does not

| Key | On `/rekey` |
|---|---|
| Long-term X25519 (`dh_secret`; the sealed-layer key, `IKdh` in X3DH/PQXDH, the group leaf's sealing key) | **Replaced.** The old secret is kept aside for a bounded time (section 5) and then erased. |
| Identity signing key (Ed25519) | Unchanged. The safety number does not move. |
| Signed and one-time prekeys, ML-KEM prekeys | Unchanged; they have a rotation of their own (`SIGNED_PREKEY_ROTATION`), and they are not the key at issue. |
| Device keys and certificates | Unchanged. A linked device has its own X25519 key and rekeys it itself; the account's rekey is the account's. |
| MLS leaf signature key | Unchanged. The leaf's *sealing key* extension changes, which is a leaf update, not a new leaf (section 6). |
| Pre-signed revocation certificate | Unchanged; it revokes the identity, which is the same identity. |

## 3. The bundle

The bundle already carries the Diffie–Hellman key signed by the identity
(`signature` over `dh_public` under `BUNDLE_DOMAIN`, protocol section
2). A rekey republishes the bundle with the new key and a new signature,
and the relay logs it in the transparency log as it logs any bundle
change. No format changes: the bundle is what it was, with a different
key in it. A client from any version reads it.

The order on the rekeying side is: **write the new secret to disk, then
publish it.** Never the reverse — a client that published a key and then
died before saving its secret would have told the world to seal to a
key nobody holds.

## 4. What a contact does

### 4.1 When it sends to the rekeyed identity

Nothing new. The send path already looks the peer up (through the
transparency check), compares the answer with the pinned bundle, and on
a difference drops its sessions with that peer and re-pins with a
**KEY CHANGE** notice that clears the verified mark (`key_changed` in
`Client::send`, `note_key_change` in the front end). The next message
starts a session against the new key. The notice's wording gains the
routine reason — "they ran `/rekey`, reinstalled, or their identity key
is compromised" — but the action is the one it was: confirm and
`/verify`.

### 4.2 When it receives a handshake from the rekeyed identity — the new rule

A session the *peer* started carries the long-term key the handshake
claimed as the peer's own. The rule becomes:

> **A responder accepts a peer-started session only if the key it
> claimed is the key the peer currently publishes.**

Concretely, when a body with a handshake opens and the connection has
just derived a new session from it:

1. The connection **defers** delivering that message and the
   `SessionEstablished` event, sends a lookup for the peer, and parks
   the message until the relay answers. The lookup goes through the
   transparency check like any other, so a relay serving a key it never
   logged is refused rather than believed.
2. When the answer arrives, the event carries the verdict alongside the
   claimed key: `published: Some(<the relay's current key>)`, or
   `None` when there was no answer to trust (the relay could not be
   asked, or the answer failed the transparency check).
3. The front end, which holds the pin, decides:

   | claimed vs published | claimed vs pinned | Outcome |
   |---|---|---|
   | equal | equal | Ordinary. |
   | equal | differs | **Key change**, the same as 4.1: re-pin, clear the verified mark, say so. The session stands — it was made with the key they publish. |
   | differs | equal | **Refused**: "started a session with a key they have since replaced". The session is dropped and the message shown with that warning. This is the old-key attacker after a rekey. |
   | differs | differs | **Refused**: "a key that is not the one they publish, nor the one pinned" — today's warning, now with the relay's word behind it. |
   | unknown (`None`) | equal | Ordinary; the check was not made and the pin is what there is. |
   | unknown (`None`) | differs | **Refused**, as today: a key that is not the pinned one and cannot be checked. |

   The two `None` rows are exactly today's behaviour, so a client that
   cannot reach its relay loses nothing it had.

Why defer rather than deliver and warn afterwards, which is what the
pin-only check does today: the first message of a peer-started session
arrives *with* the handshake, and displaying it sends a read receipt
into the session it came in on. Delivering before the verdict would
hand an attacker who started the session one receipt — small, but it is
a message encrypted to somebody the check is about to refuse, and the
point of checking at the boundary (item 62.9) is that nothing is acted
on before it is checked. The cost is one relay round trip before the
first message of a new session from a peer shows, which is a latency
nobody will see. A disconnect while a message is parked flushes it with
`published: None`, so a message is never lost to the check; it is
delivered under the pin rule instead.

This check is a policy on which key a responder accepts. It changes no
message, no format and no signature, so the formal model and the
published test vectors are untouched: the model's authentication
property already assumes the responder holds the initiator's published
key, which is what the check makes true.

## 5. The grace window

The old secret is kept for **30 days** after a rekey, for two reasons:

* **Sealed layers.** Every envelope to an identity is sealed to its
  Diffie–Hellman key (protocol section 3). A sender that could not reach
  the relay seals to the key it has pinned; a message queued for a
  recipient who is offline sits in the relay's mailbox until fetched.
  Without the old secret, an envelope sealed to it before the sender saw
  the change would open to nothing. The relay keeps a message for
  `DEFAULT_MESSAGE_TTL` — 30 days — so that is the longest an envelope
  sealed to the old key can still arrive, and the window is set equal
  to it. A test in the relay crate asserts the two constants agree, so
  neither moves without the other.
* **Handshakes against the old key.** A contact that started a session
  against the pinned (old) key before seeing the change computed its
  X3DH against that key. The responder tries the current key and, when
  the body does not open under it, the previous one — the handshake's
  associated data binds the responder's public key, so the wrong key
  fails cleanly at the first AEAD rather than producing a session that
  silently disagrees.

Keeping the old secret costs nothing the rekey was meant to buy. What an
attacker with a copy of it could do with it — open envelopes sealed to
it — they could do already; what they lose is being *accepted* with it,
and that is decided by the published key (section 4), not by whether the
owner still holds the secret.

After the window the secret is erased from `identity.json` on the next
start or the next daily pass, whichever first. A second rekey inside the
window replaces the previous key at once: one previous key is kept, not
a history, and someone who rekeys twice in a month has cut the first
key's window short on purpose.

On disk, `IdentitySecrets` gains an optional `previous_dh` (the secret
and its `until_ms`). It is absent when there is none, so an
`identity.json` written by this version reads in an older one — which
ignores the field and simply has no grace — and one written by an older
version reads here.

## 6. Groups

An MLS leaf carries the member's sealing key as an extension
(`silver_seal`, `docs/design/groups.md` section 4), and every group
envelope is sealed to the recipient's leaf key. That note said "a member
whose sealing key changes has a new identity and is re-added", which was
true when the only way the key changed was `/rotate`. It is no longer
true, and the note is corrected.

A rekey marks every active group's leaf as due for refresh. The
self-update that follows (`stage_self_update`, the same commit the
seven-day cadence makes) builds its leaf extensions from the identity's
*current* key, so the committed leaf carries the new sealing key; other
members verify the updated leaf under the rules already there for an
Update — same identity, same device, a sealing key present — and take
the new key from it when they rebuild their member list from the tree.
Until a member has processed that commit it seals to the old key, which
the grace window opens. A group that cannot be committed to right now
(another commit staged, or the relay's sequencer refusing) is caught by
the next self-update pass, as any due refresh is.

Nothing about the group's own keys moves: the leaf signature key, the
epoch secrets and the sender ratchets are MLS's and do not involve
`IKdh`.

## 7. The command

`/rekey` — a new command rather than a mode of `/rotate`, because the two
do different-sized things and the one people reach for in a hurry should
not be one argument away from the one that changes their safety number.

* Two-step, with the paste guard: `/rekey` says what will happen
  (contacts see a key-change notice and their verified mark for you
  clears; every conversation restarts under the new key; groups refresh)
  and stops; `/rekey confirm` goes ahead, and `typed_it_themselves` sits
  on that line, as `docs/design/consequential-commands.md` has it for
  `/rotate`. The verified marks other people hold for you are what makes
  this consequential: a rekey costs every contact a `/verify`.
* Refused on a linked device ("rekeyed on your primary") and while a
  `/rotate` is pending in this session, for the same reason `/rotate`
  refuses a second handover: a key signed by an identity contacts have
  not pinned yet.
* What it does, in order: new key; `identity.json` saved with the old
  secret under `previous_dh`; every session dropped, so each
  conversation restarts with a handshake under the new key; bundle
  republished; every active group's leaf marked due and the self-update
  pass run at once; a System line saying what contacts will see.

If saving fails, the in-memory key is put back and nothing is published:
a key that is not on disk is not a key this identity has.

## 8. The threat model, after

The section *Holder of a compromised long-term Diffie–Hellman key* says
what the key decrypts and, since 0.16.0, that from v4 it impersonates.
It now also says what to do: `/rekey`, after which the old secret opens
what was sealed to it but starts no session as its owner with any
contact whose client checks the published key — which is every client
from this version. A contact on an older client checks the pin alone
and is protected only once it has sent to the rekeyed identity and
re-pinned. The window between reading the key and the owner noticing is
what the memory-protection section is about, and this does not shorten
it; it bounds what the key is worth afterwards.

## 9. Non-goals

* **Automatic periodic rekeying.** Prekeys rotate on a schedule because
  nobody sees it; a rekey costs every contact a verified mark, so it is
  something a person decides to do. The command exists so that the
  decision is cheap, not so that it is made for them.
* **Rekeying a linked device from the primary.** A device's key is the
  device's; the primary can revoke the device. That is the existing
  remedy and the right size for a device.
* **Binding the identity key into the handshake.** Declined, section 1.

## 10. What is tested

* Protocol: a rekeyed identity opens an envelope sealed to its previous
  key inside the window and not after it is expired; a handshake made
  against the previous key opens under the retry and one against a key
  never held does not; `IdentitySecrets` round-trips with and without
  `previous_dh`, and the previous secret is gone from the JSON once
  expired.
* Relay: `DEFAULT_MESSAGE_TTL` equals the grace window.
* Client: after a rekey the bundle on the relay carries the new key
  under a valid signature; a contact's next send reports `key_changed`
  and the message arrives; a handshake the rekeyed identity starts
  reaches the contact with `published == claimed`; a handshake made with
  the *old* key after the rekey reaches the contact with `published !=
  claimed`; a message parked for the check is delivered with `None` when
  the connection drops before the answer.
* Groups: after a rekey and the self-update pass, the other members'
  record of the sealing key is the new one, and a message sealed to it
  opens.
* Terminal: `/rekey` without `confirm` explains and does nothing;
  `/rekey confirm` on a primary republishes and the contact's next
  message shows KEY CHANGE without the "may not be from" alarm; on a
  linked device it is refused.
