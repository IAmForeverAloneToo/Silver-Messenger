# Test vectors

Known-answer vectors for every cryptographic operation in
[PROTOCOL.md](../PROTOCOL.md), so that a second implementation can check
itself byte for byte, and so that a change to this one that moves any of
them is seen. The harness that replays them against `silver-protocol` is
`crates/silver-protocol/tests/vectors.rs`; it runs with the ordinary test
suite.

## Format

Each file is one JSON object:

```json
{
  "description": "what the file covers",
  "cases": [
    { "name": "...", "inputs": { ... }, "outputs": { ... } }
  ]
}
```

`inputs` is everything another implementation needs to start from;
`outputs` is what it must arrive at. Bytes are standard padded base64,
user ids are base58 (as on the wire), integers are decimal. Where a
structure has a wire form (a key bundle, an `InitHeader`, an `Envelope`, a
`LogEntry`), the vector carries it in that form, so the same JSON can be
parsed by the implementation under test.

Alongside the final result, each case gives the intermediate values on
the way to it (each Diffie–Hellman output, each KDF input and output, the
associated data of each AEAD, the exact bytes a signature is over), so a
mismatch points at the step that differs.

## Randomness

Where an operation draws random bytes, the vector fixes them through a
seeded generator: SHA-256 in counter mode, block `i` being
`SHA-256(seed || i)` with `i` a big-endian 64-bit counter from 0, bytes
handed out from the blocks in order. Each case carries the seed, and the
order in which the operation consumes the stream is stated with the
operation:

| Operation | Draws, in order |
| --- | --- |
| `seal` (an envelope) | ephemeral X25519 secret (32), nonce (24), the 16 bytes of the envelope id (a version-4 UUID) |
| `initiate` (a handshake) | ephemeral X25519 secret (32); on a post-quantum bundle the ML-KEM encapsulation randomness `m` (32); on the post-quantum ratchet the seed `d ‖ z` of the first ML-KEM ratchet key (64); the first ratchet X25519 secret (32) |
| a ratchet step (receiving a message that starts a new chain) | the fresh X25519 secret (32); on the post-quantum ratchet the seed of the new ML-KEM ratchet key (64), then, if the peer sent a ratchet key to encapsulate to, the encapsulation randomness `m` (32) |

X25519 secrets are used as drawn (clamping happens inside the scalar
multiplication, per RFC 7748). ML-KEM keys are expanded from their FIPS
203 seed `d ‖ z` and encapsulation uses the drawn `m` directly (FIPS 203
algorithm 17 with `m` given), so an implementation with a deterministic
ML-KEM interface reproduces the ciphertexts exactly.

## Files

| File | What it fixes |
| --- | --- |
| `identity.json` | user id, X25519 public key and bundle signature from an identity's two secrets; the safety number of a pair |
| `signatures.json` | the exact bytes and domain of every other signature: signed prekey, ML-KEM prekey, bundle capabilities, revocation, succession, device certificate, device list, device revocation, relay login (v1 and host-bound) |
| `kdf.json` | the session id, the handshake secret (X3DH and PQXDH, with and without a one-time prekey), the root KDF (v2, and v4 with and without an ML-KEM secret), the chain KDF, a message key's AEAD key and nonce |
| `handshake.json` | a whole handshake from fixed keys and a fixed seed: the bundle as served, every intermediate value, the `InitHeader`, the first message; classical (v2), hybrid (v3) and post-quantum ratchet (v4) |
| `ratchet.json` | two round trips with late and out-of-order delivery: every header and ciphertext, and what each ratchet step drew; v2 and v4 |
| `envelope.json` | the sealed-sender layer from a fixed seed: signed (v1) and deniable (v4) |
| `body.json` | the padded encoding of each body kind, a copy for a second device naming its message's id and a device revocation among them |
| `transparency.json` | the subject, bundle and statement leaves (bundles with and without a device list, a linked device's own, and a device revocation among them), and a three-entry chain with every hash and head |
| `group.json` | the group context and leaf seal-key extensions as bytes, the invite link key and join proof, the sequencer token hash, and an application message's plaintext (section 13); the MLS messages themselves follow RFC 9420 |
| `blob.json` | file chunk nonces, associated data and ciphertexts |
| `device.json` | linking a device (section 14): the link key from the link's secret, a provisioning message sealed under it, and a device certificate as the bytes a group leaf carries |

## Changing them

The harness compares what the crate computes with what the files say and
fails on any difference, in either direction. To regenerate after a
deliberate change:

```sh
SILVER_WRITE_VECTORS=1 cargo test -p silver-protocol --test vectors
```

and read the diff: every line that moved is a byte on the wire or in a
key that moved, which is a protocol change and needs a version, a note in
`PROTOCOL.md` and a changelog entry. The inputs are fixed in the harness
and the files both; the harness refuses a file whose inputs drifted from
its own.
