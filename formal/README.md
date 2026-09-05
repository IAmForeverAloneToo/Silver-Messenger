# Formal models

Verifpal models of the handshake and the ratchet of
[`docs/PROTOCOL.md`](../docs/PROTOCOL.md), with the properties
[`docs/THREAT_MODEL.md`](../docs/THREAT_MODEL.md) claims for them stated
as queries. Each model's header comment says what it models, what it
leaves out, and what Verifpal is expected to find; `expected.txt` records
the outcome of every query, and `check.sh` runs the models and refuses any
difference. CI runs `check.sh` on every push; the whole set takes under a
minute.

Some queries are *expected to fail*: those models remove one piece of the
protocol, or put the adversary past what the protocol claims to resist,
and the attack Verifpal finds is the reason the piece is there. They are
as much a part of the record as the ones that pass.

## Running

```sh
cargo install --locked verifpal --version 1.4.2
formal/check.sh                            # every model against expected.txt
verifpal verify formal/handshake_unbound.vp   # one, with the attack trace
```

The models are written for Verifpal 1.4, which has a KEM, runs every
principal in two concurrent sessions, and narrates each attack it finds
as numbered steps. `check.sh` compares Verifpal's result code (one letter
and one digit per query, `c0` a confidentiality query that holds, `a1` an
authentication query with an attack) with what `expected.txt` says; a
model that is not listed there fails the check. `VERIFPAL=/path/to/binary`
points the script at a build that is not on the path.

## What each model shows

| Model | Adversary | Query | Expected | Backs |
| --- | --- | --- | --- | --- |
| `handshake.vp` (v4: PQXDH, key-binding signature, first chain; one-time prekey used) | active; afterwards learns both identity keys and both DH identity keys | confidentiality of the first message | holds | forward secrecy of the handshake against a later compromise of the long-term keys: "holder of a compromised long-term Diffie–Hellman key" opens no session content |
| | | authentication of the first message | holds | "the relay cannot forge a message from anyone" (v4), and cannot make Bob accept the same first flight twice: his one-time prekey is fresh per run |
| `handshake_prekeys.vp` (the same) | passive; afterwards learns the long-term keys *and* Bob's signed prekeys, before they rotated | confidentiality | holds | what a one-time prekey buys (protocol section 2): with every other input recoverable, the deleted one-time prekey keeps the message closed |
| | | authentication | holds | |
| `handshake_no_opk.vp` (the same, no one-time prekey) | the same | confidentiality | **fails** | the limit stated under "holder of a compromised long-term Diffie–Hellman key": "with the prekeys as well, the attacker can derive sessions started against those prekeys"; why signed prekeys are rotated and deleted (section 8) and one-time prekeys kept on deposit |
| | | authentication | holds | |
| `handshake_pq.vp` (v4) | active; afterwards learns every X25519 secret, the ephemeral, the ratchet key and the one-time prekey included, but not the ML-KEM prekey | confidentiality | holds | "future quantum adversary with a recording": a post-quantum handshake stays closed |
| | | authentication | holds | |
| `handshake_unbound.vp` (v4 without `identity_dh_signature`) | active | confidentiality | holds | |
| | | authentication | **fails** | why a v4 handshake requires the key-binding signature (protocol section 4.2.1): without it the attacker substitutes its own DH identity key and Bob takes its first message for Alice's |
| `handshake_v2.vp` (v2: X3DH, envelope signature; one session, see below) | active; afterwards learns both identity keys, both DH identity keys and Bob's signed prekey | confidentiality | holds | the same claims for v2 sessions |
| | | authentication | holds | the envelope signature does for v2 what the key-binding signature does for v4 |
| `ratchet.vp` (v4: DH and ML-KEM step per turn, two round trips) | passive; between messages 2 and 3 reads both devices (current root, DH and ML-KEM keys) | confidentiality of messages 1 and 2 | holds | forward secrecy: "read messages that were already received and ratcheted past: the message keys are gone" |
| | | confidentiality of message 3 | **fails** | the window after a compromise: the message made from compromised state and the peer's compromised keys is readable, the Double Ratchet's own limit |
| | | confidentiality of message 4 | holds | healing: "a new DH step whenever the conversation changes direction heals a compromised chain", against an adversary that then only listens |
| `ratchet_active.vp` (v4) | active, no compromise | confidentiality and authentication of all four messages | holds | the ratchet itself: substituting a ratchet key, ML-KEM key or ciphertext breaks the message it came with and steers nobody onto a chain the attacker shares; a message replayed into the other session is refused |
| `ratchet_quantum.vp` (v4) | passive; the read of `ratchet.vp` plus every X25519 secret of every turn; no ML-KEM ratchet key made after the read | messages 1, 2 | holds | |
| | | message 3 | **fails** | the same window |
| | | message 4 | holds | "a v4 session refreshes an ML-KEM secret at every step, so even an adversary who obtains the session key heals out of it within a round trip": the ML-KEM step alone carries the recovery |
| `ratchet_v2_quantum.vp` (v2: DH step only) | the same | messages 1, 2 | holds | |
| | | message 3 | **fails** | |
| | | message 4 | **fails** | "in a v2 session ... such an adversary who also obtains the session key another way can follow the ratchet forward from that point": what the v4 ratchet (roadmap item 41) closes |

Two findings that shaped the set, both of them the protocol document's
own statements found again by the tool:

- **An active relay can spend the one-time prekey's protection.** With
  Bob's signed prekeys added to the leak of `handshake.vp` (an active
  adversary, a compromise before rotation), Verifpal substitutes the
  unsigned one-time prekey in the bundle for a key it later learns to
  compute against, and reads Alice's first message once the signed
  prekeys leak. Bob never reads that message (his one-time prekey does
  not match), which is what section 2 says a substituted one-time prekey
  is good for: "only to deny the extra forward secrecy it brings". The
  protection the one-time prekey gives against a passive recording is
  `handshake_prekeys.vp`; the window closes when the signed prekeys
  rotate.
- **A v2 first flight has nothing fresh from Bob before its signature
  check.** With two concurrent sessions, Verifpal replays Alice's whole
  first flight into Bob's other session and Bob's envelope signature
  check accepts it (his one-time prekey, which would refuse it, is used
  only afterwards); the tool itself notes this is a replay question, not
  a forgery. Replay of an envelope is refused by the client, not the
  cryptography: envelope ids are de-duplicated, sequence numbers are
  checked, and a session refuses a message key it has used (protocol
  section 8). None of that is in the model, so `handshake_v2.vp` runs
  with one session and its authentication query asks about forgery
  alone. The v4 flight (`handshake.vp`) passes with two sessions because
  its first check is the session's AEAD, under a key Bob's fresh one-time
  prekey went into.

## Modelling choices

- **ML-KEM is Verifpal's KEM**: `KEM_ENCAP` with fresh randomness and
  `KEM_DECAP`, on a key made with `PUBKEY`. The model depends on no
  other property of ML-KEM-768.
- **Guarded values.** The only guarded values (`[..]`, which the attacker
  reads but cannot replace) are the identity keys `gik_a` and `gik_b`,
  and in the ratchet models Bob's signed prekey `gspk`, which the
  handshake authenticated. Guarding the identity keys models each side
  having the other's id pinned: the id *is* the key. Everything else
  crosses the relay, which is the attacker, and in the handshake models
  that includes every bundle value and its signature, so the models
  exercise the signature checks rather than assume them.
- **Constants.** The signature domains and HKDF infos are public
  constants (`d_*`, `info_*`) hashed in with what they separate; salts,
  the 0xFF prefix of X3DH and the chain-KDF byte are left out, as is the
  session id in the associated data (a hash of two values already bound
  into the key). The chain KDF (HMAC) and the message key derivation
  (HKDF) are one step each, since every turn is the first message of its
  chain.
- **Unrolled.** Verifpal has no loops; the ratchet is written out for
  two round trips, the fewest that show a compromise, the message in its
  window and the recovery after it.
- **Passive adversary for healing.** Post-compromise security is a
  property against an adversary that stops interfering once it has the
  state; one that keeps injecting its own ratchet keys can stay in a
  session indefinitely, which no ratchet prevents. `ratchet.vp` and the
  quantum variants therefore use `attacker[passive]` with leaks, and
  `ratchet_active.vp` covers the active adversary without a compromise.

## What the models do not cover

- **The bound.** Verifpal finds attacks within a bounded number of
  sessions (two, unless a model says otherwise) and reports a query as
  passing when its search found none. A passing query is evidence, not
  a proof. Tamarin or ProVerif would give unbounded proofs and are the
  next step if the outside review (roadmap item 35) asks for them.
- **Sealed-sender anonymity and deniability** (protocol sections 3
  and 9) are not modelled: Verifpal has no observational-equivalence
  query that states them. They are argued in the protocol document.
- **The transparency log** (section 11) is a hash chain plus a
  behaviour of the client; its properties are argued in section 11 and
  checked by the vectors and the client's tests, not modelled.
- **Client behaviour** (section 8): replay protection, prekey rotation
  and deletion, and when a session is dropped are what the client does,
  and the models take them as given where they matter (above).
- **Cryptographic strength** of the primitives is assumed, as in every
  symbolic model: X25519, ML-KEM-768, Ed25519, HKDF-SHA256, HMAC-SHA256
  and XChaCha20-Poly1305 are perfect boxes.
- **Bytes.** The models say nothing about encodings; the vectors in
  [`docs/vectors/`](../docs/vectors/) do.
