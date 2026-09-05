# Silver Messenger protocol

This is the wire format and the cryptography as implemented on `main`. It
is written so that a second implementation could interoperate with this one
without reading the source; where the source and this document disagree,
the source is the bug. Byte encodings, domain strings and constants are
given exactly.

Three protocol versions coexist. **v1** is the sealed-envelope format of
the first release; **v2** adds prekeys and forward-secret sessions *inside*
the same envelope, so relays and v1 clients cannot tell the two apart from
the outside; **v3** makes the session handshake a hybrid of X3DH and
ML-KEM-768 (PQXDH-style), which changes only the bundle's prekeys, the
`init` header and the session-key derivation. A client speaks v3 to a peer
whose bundle carries ML-KEM keys, v2 to one with X25519 prekeys only, and
v1 to one that has published no prekeys.

Notation: `||` is concatenation, `BE` is big-endian, `b64` is standard
padded base64, `b58` is Bitcoin-alphabet base58. All JSON is UTF-8 text; a
reader must ignore fields it does not know.

## 1. Identities and keys

| Key | Algorithm | Purpose |
| --- | --- | --- |
| Identity key `IK` | Ed25519 | Signs everything below. Its public key **is** the user id, shown as b58 (44 characters). |
| Long-term DH key `IKdh` | X25519 | The sealed-envelope layer and the X3DH handshake. |
| Signed prekey `SPK` | X25519 | Medium-term X3DH key, rotated weekly, signed by `IK`. |
| One-time prekey `OPK` | X25519 | Single-use X3DH key, unsigned, handed out once by the relay. |
| Ephemeral keys | X25519 | Fresh per envelope (`EK_env`) and per handshake (`EK`). |
| Ratchet keys | X25519 | Fresh per Double Ratchet step. |

Every signature is over a domain-separated message:

```
sign(domain, m) = Ed25519_sign(IK, domain || 0x00 || m)
```

verified with Ed25519 strict verification. Domains are ASCII strings
without the terminating byte.

Every X25519 output is rejected if it is all zero (a non-contributory
low-order point).

## 2. Key bundle

What a relay stores for a user and serves on lookup:

```json
{
  "user_id":   "<b58 IK public key>",
  "dh_public": "<b64 IKdh public key>",
  "signature": "<b64 64 bytes>",
  "prekeys": {                              // v2 clients only
    "signed":   { "id": 123, "public": "<b64>", "created_at_ms": 0, "signature": "<b64>" },
    "one_time": [ { "id": 456, "public": "<b64>" } ],
    "pq_signed":   { "id": 789,  "public": "<b64 1184 bytes>", "created_at_ms": 0, "signature": "<b64>" },   // v3 clients only
    "pq_one_time": [ { "id": 1011, "public": "<b64 1184 bytes>", "created_at_ms": 0, "signature": "<b64>" } ]
  }
}
```

* `signature = sign("silver-messenger/v1/key-bundle", dh_public)` (the raw
  32 bytes). This is unchanged from v1 and does not cover `prekeys`, so a v1
  reader verifies a v2 bundle after ignoring the field it does not know.
* `prekeys.signed.signature = sign("silver-messenger/v2/signed-prekey",
  id (4 BE) || public (32) || created_at_ms (8 BE))`.
* One-time prekeys are not signed. A relay cannot use a substituted one to
  read anything (section 5), only to deny the extra forward secrecy it
  brings.
* `pq_signed` and each entry of `pq_one_time` are ML-KEM-768 encapsulation
  keys (FIPS 203 `ek`, 1184 bytes), with `signature =
  sign("silver-messenger/v3/pq-prekey", id (4 BE) || public (1184) ||
  created_at_ms (8 BE))`. Unlike X25519 one-time keys these *are* signed:
  a substituted ML-KEM key would hand whoever planted it the post-quantum
  half of the secret. A reader rejects a key of any other length before
  checking the signature. `pq_signed` is rotated and retained like
  `signed` (section 8); `pq_one_time` is handled like `one_time`, with at
  most 50 on deposit.
* On a `publish`, `one_time` lists every one-time key the client still
  holds (at most 200). On a `lookup_result` it holds at most one, chosen
  and then forgotten by the relay, and only for clients that themselves
  published prekeys on that connection. `pq_one_time` follows the same
  rule.
* Prekey ids are 32-bit, non-zero, unique per user among live keys of every
  kind; this implementation picks them at random.
* A relay without the `pq_prekeys` feature (7.3) drops `pq_signed` and
  `pq_one_time` when it re-serialises the bundle, so sessions through it
  are v2. Clients show which handshake a session got.
* From 0.8.0 a bundle may also carry a signed capability list:
  ```json
  "caps": ["pq_ratchet"],
  "caps_signature": "<b64 64 bytes>"
  ```
  with `caps_signature = sign("silver-messenger/v4/bundle-caps", dh_public
  (32) || caps.join("\n"))`. `pq_ratchet` says the client reads v4 bodies
  (section 4.2). The signature lets a peer trust the advertisement even
  though the relay serves it; a relay that drops the fields only downgrades
  the session to v3, which the clients show, and one that adds them cannot
  forge the signature. A client publishes `pq_ratchet` only when it also
  publishes ML-KEM keys, since v4 needs the post-quantum handshake. A relay
  older than 0.8.0 drops the two fields when it re-serialises the bundle,
  so the post-quantum ratchet needs a relay that keeps them. From 0.9.0
  the list may also carry `groups`: the client keeps MLS key packages on
  deposit and reads group bodies (section 13); a client adds a contact to
  a group only when the contact's bundle says so.

## 3. Envelope (the sealed-sender layer)

What a relay sees and routes:

```json
{ "id": "<uuid>", "to": "<b58 recipient id>",
  "ephemeral_public": "<b64 EK_env public>",
  "nonce": "<b64 24 bytes>", "ciphertext": "<b64>" }
```

Sealing `body` (the bytes of section 4) from `A` to `B`:

```
EK_env       = fresh X25519 key pair
shared       = X25519(EK_env.secret, IKdh_B)
key          = HKDF-SHA256(salt = none, ikm = shared,
                 info = "silver-messenger/v1/xchacha20poly1305" || EK_env.public || IKdh_B)   -> 32 bytes
nonce        = 24 random bytes
signature    = sign_A("silver-messenger/v1/envelope", to || EK_env.public || nonce || body)
plaintext    = IK_A.public (32) || signature (64) || body
ciphertext   = XChaCha20-Poly1305(key, nonce, plaintext, aad = to (32) || EK_env.public (32))
```

`to` and `IK_A.public` are the raw 32-byte keys. The recipient decrypts,
splits off the sender id and signature, verifies the signature with the
sender id, and only then decodes the body. Because the signature covers
`to`, the ephemeral key and the nonce, an envelope cannot be re-addressed or
replayed as a different envelope; because the sender id is inside the
ciphertext, the relay never learns it.

Limits: `body` at most 32 768 bytes; `ciphertext` at most 33 904 bytes;
a WebSocket frame at most 131 072 bytes.

## 4. Body

The body is JSON. Its version is the integer field `v`, absent (0) or 1 for
a plain body, 2 for a ratchet body, 4 for a ratchet body that runs the
post-quantum ratchet and is deniable (no sealed-layer signature), and 5
for a group body, which carries one MLS message and is unsigned at the
sealed layer as well (section 13). Other values are rejected. (There is
no v3 body: the post-quantum *handshake* of 0.6.0 kept `v: 2`, since it
changes only what goes into `init`.)

**Padding.** An encoded body is padded with trailing ASCII spaces (0x20)
to a multiple of 160 bytes (clients from 0.6.0). JSON ignores trailing
whitespace, so a padded body decodes like an unpadded one and vice versa,
which is what keeps older and newer clients talking. The ciphertext is the
body plus a fixed 112 bytes, so a relay sees envelope sizes in 160-byte
steps: a receipt, a short and a medium message are the same size on the
wire. A ratchet body is padded twice, once as the inner plain body and once
around it.

### 4.1 Plain body (v1)

```json
{ "sent_at_ms": 1700000000000, "epoch": 8271, "seq": 12,
  "content": { "type": "text", "body": "hello" },
  "caps": ["receipts", "files"],
  "head": { "index": 4093, "hash": "<b64 32 bytes>" } }
```

`seq` counts messages from this sender to this recipient from 1; `epoch` is
a random 64-bit value fixed for one installation, so a reinstall (which
restarts `seq`) is distinguishable from a replay. `seq = 0` means the sender
does not number messages. `caps` (absent or empty on clients before 0.4.0)
is described in 4.3. `head` (absent on clients before 0.8.0 and on clients
whose relay keeps no log) is the head of the relay's transparency log as
the sender last verified it, for the recipient to compare with its own
(section 11); inside the encrypted body, the relay can neither read nor
alter it. `content.type` is one of `text`, `receipt` (4.4), `file` (4.5),
`revocation` and `succession` (section 10); unknown types are rejected by
this implementation, which is why a sender only uses the latter four
towards peers that advertised them.

### 4.2 Ratchet body (v2 and v4)

```json
{ "v": 2,
  "session": "<b64 16 bytes>",
  "init": { "identity_dh": "<b64 IKdh_A>", "ephemeral": "<b64 EK_A>",
            "signed_prekey_id": 123, "one_time_prekey_id": 456,
            "pq_prekey_id": 1011, "kem_ciphertext": "<b64 1088 bytes>",     // optional; the pq_ pair is the v3 handshake
            "identity_dh_signature": "<b64 64 bytes>" },                    // v4 only (§4.2.1)
  "message": { "header": { "dh": "<b64>", "pn": 0, "n": 3,
                           "kem": "<b64 1184 bytes>",                       // v4 only (§6.1)
                           "kem_ct": "<b64 1088 bytes>" },                  // v4 only, and not on the first chain of a direction
               "ciphertext": "<b64>" } }
```

`message.ciphertext` decrypts (section 6) to the bytes of a **plain body**
(4.1), so everything a v1 message carries, including `seq` and `epoch`, is
carried unchanged one layer deeper. `init` is present on every message the
initiator sends until it has received a message on the session; a responder
that already has the session ignores it. `pq_prekey_id` and
`kem_ciphertext` are present together or not at all.

A **v2** body is signed at the sealed layer (section 3) like a plain body,
carries no `kem`/`kem_ct`/`identity_dh_signature`, and its handshake is
X3DH or PQXDH. It stays `v: 2` for the post-quantum handshake, since a v2
responder can never be asked to answer one anyway (it publishes no ML-KEM
keys) and nothing else about the body changes.

A **v4** body runs the post-quantum ratchet (section 6.1) and is **not**
signed at the sealed layer (the sealed-sender signature is 64 zero bytes),
which makes it deniable (section 9). Two things make up for the missing
signature: the session's own AEAD, which only the two endpoints can
produce, and `init.identity_dh_signature` (§4.2.1). A client sends v4 only
to a peer whose bundle both publishes ML-KEM keys and advertises the
`pq_ratchet` capability (section 8); otherwise it sends v2 (or v1 to a peer
with no prekeys).

#### 4.2.1 Handshake key-binding (v4)

Because a v4 body is not signed, nothing at the sealed layer ties the
initiator's `identity_dh` to the identity id it claims to be from. So the
v4 `init` carries `identity_dh_signature`: the initiator's identity-key
signature over `identity_dh` under the domain `silver-messenger/v1/key-bundle`
— the very signature its key bundle (section 2) carries. The responder
verifies it against the sender id (the id inside the sealed layer) before
deriving the session, and refuses the handshake if it is missing or wrong.
This is deniable: the signature is over the sender's own public key, is
published in every bundle, and says nothing about who was talked to. It
prevents a third party from substituting its own `identity_dh` (and so its
own DH1) to impersonate the sender while claiming their id.

### 4.3 Capabilities

`caps` lists, inside the encrypted body, what the sending client
understands beyond `text`. A recipient remembers the most recent list per
peer and sends a content type only to peers whose last message carried the
matching capability. The list is protected like the rest of the body, so
the relay does not learn which clients have which features.

| Capability | Meaning |
| --- | --- |
| `receipts` | Understands `receipt` content and wants to be sent it. |
| `files` | Understands `file` content and can fetch blobs (section 7.5). |
| `padded_files` | Cuts a fetched file to its announced `size`, so the sender may pad the last chunk (4.5). |
| `lifecycle` | Understands `revocation` and `succession` content: identity-lifecycle statements pushed inside a message (section 10). |
| `cover` | Understands `cover` content and wants it: the client's user has cover traffic on (4.6). Advertised only while that is so. |

### 4.4 Receipts

```json
{ "type": "receipt", "kind": "delivered", "ids": ["<envelope id>", "..."] }
```

`kind` is `delivered` (the messages with these ids were decrypted and
stored) or `read` (they were shown to the user); `read` implies
`delivered`. `ids` are envelope ids the recipient of the receipt sent. A
receipt is an ordinary body, numbered with `seq` like any other, and is
carried in a session when one exists. This implementation batches ids and
sends one receipt per peer and kind, sends `delivered` for every stored
message and `read` only while the user has not turned read receipts off,
and never sends receipts to a sender it has not accepted as a contact. A
batch waits 400 ms plus a random while (up to 2 s for `delivered`, 2 to
12 s for `read`), so that the moment a receipt leaves does not mark the
moment a message arrived or was looked at. Receipts from strangers are
ignored.

### 4.5 Files

A file travels as encrypted chunks parked on the relay (a *blob*, section
7.5) plus a message that says how to fetch and open them:

```json
{ "type": "file", "name": "photo.jpg", "size": 150000,
  "blob": "<32 hex characters>", "key": { "key": "<b64 32 bytes>", "nonce": "<b64 24 bytes>" },
  "chunks": 3, "sha256": "<b64 32 bytes>" }
```

The sender picks a random 16-byte blob id (shown as 32 lowercase hex
characters), a random 32-byte key and a random 24-byte file nonce, and
splits the plaintext into chunks of 65 536 bytes (`chunks = ceil(size /
65536)`, at least 1; an empty file is one empty chunk). Chunk `i` of `n`
is encrypted as

```
nonce_i     = nonce with its last four bytes XORed with i (4 BE)
aad_i       = "silver-messenger/v1/blob-chunk" || blob (ASCII) || i (4 BE) || n (4 BE)
ciphertext  = XChaCha20-Poly1305(key, nonce_i, chunk_i, aad = aad_i)
```

so a chunk cannot be moved, reordered or re-counted without the tag
failing. `sha256` is the digest of the whole plaintext; the recipient
verifies it and the announced `size` after decrypting, and rejects the file
otherwise. `name` is the sender's file name with path separators and
control characters removed; recipients must still treat it as untrusted
when choosing where to save. Files are at most 16 MiB (256 chunks). The
key is used for one file only and travels inside the session-encrypted
body, so the relay stores ciphertext it has no key for.

When the recipient advertised `padded_files`, the sender may fill the
last chunk with zero bytes up to the full 65 536 (an empty file becomes
one full chunk); `chunks` and `size` are unchanged, and the recipient
cuts the decrypted bytes to `size` before checking `sha256`. The relay
then sees file sizes in 64 KiB steps only. A recipient without the
capability requires the decrypted length to equal `size` exactly.

### 4.6 Cover traffic

```json
{ "type": "cover", "pad": "<random letters>" }
```

A message that says nothing, sent so that the relay sees traffic between
two people whether or not they are talking. It is an ordinary body in
every other way: numbered with `seq`, carried in a session when one
exists, padded like the rest, so nothing on the wire tells it from a
message. A recipient discards it after decrypting it: no history, no
receipt, no notification; its id still counts for de-duplication and its
`seq` for the sequence check. `pad` is random ASCII letters. This
implementation draws its length so the padded body takes the steps short
and medium messages do: seven in ten add no block to the framing, two in
ten add one, one in ten adds two, each plus a random remainder of a
block.

Cover is opt-in and mutual. A client advertises `cover` only while its
user has it on, and sends cover only to contacts whose last message
advertised it, so both users have agreed to the cost before a single
cover message flows, and a client that does not know the content type is
never sent it. This implementation covers a contact for ten minutes after
each message from them (cover included), at intervals drawn uniformly
from 30 seconds to three minutes, and only while connected, never from
the outbox. Two running clients therefore keep each other covered until
one of them stops, and the other falls silent within ten minutes, so at
most a handful of cover messages ever wait in an offline contact's
mailbox. `THREAT_MODEL.md` says what this hides and what it does not.

## 5. Session establishment (X3DH, and PQXDH from v3)

`A` starts a session with `B` from `B`'s bundle, which must carry prekeys.

```
EK      = fresh X25519 key pair
DH1     = X25519(IKdh_A.secret, SPK_B)
DH2     = X25519(EK.secret,     IKdh_B)
DH3     = X25519(EK.secret,     SPK_B)
DH4     = X25519(EK.secret,     OPK_B)            only if the bundle carried one
```

**v2**, when the bundle carries no ML-KEM key:

```
SK      = HKDF-SHA256(salt = 32 zero bytes,
            ikm  = 0xFF * 32 || DH1 || DH2 || DH3 [|| DH4],
            info = "silver-messenger/v2/x3dh")     -> 32 bytes
```

**v3**, when it does. `PQK_B` is the first entry of `pq_one_time` if the
relay handed one out, otherwise `pq_signed`; its id goes in `pq_prekey_id`
and `CT` in `kem_ciphertext`:

```
CT, SS  = ML-KEM-768.Encaps(PQK_B)                CT 1088 bytes, SS 32 bytes
SK      = HKDF-SHA256(salt = 32 zero bytes,
            ikm  = 0xFF * 32 || DH1 || DH2 || DH3 [|| DH4] || SS,
            info = "silver-messenger/v3/pqxdh")    -> 32 bytes
```

Both:

```
AD      = IK_A.public || IKdh_A.public || IK_B.public || IKdh_B.public     (4 × 32 bytes)
session = SHA-256("silver-messenger/v2/session-id" || 0x00 || EK.public || SPK_B)[0..16]
```

`B` computes the same `DH1..DH4` with its private `SPK_B` and `OPK_B` (the
latter looked up by `one_time_prekey_id`, and deleted once the first
message decrypts) and, in v3, `SS = ML-KEM-768.Decaps(dk, CT)` with the
decapsulation key expanded from the 64-byte seed of the key `pq_prekey_id`
names (a one-time ML-KEM key is deleted with the X25519 one); then the
same `SK`, `AD` and `session`. A header naming a one-time key `B` no longer
has, or a signed prekey it has rotated out, is undecryptable; `B` keeps
the previous signed prekeys of both kinds for three weeks after rotating
them. `EK` and `SS` are discarded by `A` after deriving `SK`. A `CT` that
was tampered with decapsulates to a different `SS` (ML-KEM rejects
implicitly), so the first message fails to decrypt and `B` keeps nothing.

Why hybrid: `SK` depends on the X25519 values *and* on `SS`, so breaking
either scheme alone opens nothing. A recording of today's traffic cannot
be read by a future quantum computer, which breaks X25519 but not ML-KEM;
a flaw found in ML-KEM leaves the session as strong as v2. The PQXDH
handshake protects the session's *start*; whether the ratchet after it is
also post-quantum depends on the body version: a v2 body's ratchet is
X25519 only, so an attacker who breaks X25519 *and* learns `SK` later can
follow it, while a v4 body refreshes an ML-KEM secret at every ratchet
step (section 6.1), so it heals against such an attacker within a round
trip. A v4 body also adds `init.identity_dh_signature` (4.2.1), since its
sealed layer is unsigned.

## 6. Double Ratchet

The construction follows the Signal specification with these functions:

```
KDF_RK(rk, dh_out) = HKDF-SHA256(salt = rk, ikm = dh_out,
                       info = "silver-messenger/v2/ratchet-root")  -> 64 bytes = rk' (32) || ck (32)
KDF_CK(ck)         = (ck' = HMAC-SHA256(ck, 0x02), mk = HMAC-SHA256(ck, 0x01))
EXPAND(mk)         = HKDF-SHA256(salt = none, ikm = mk,
                       info = "silver-messenger/v2/ratchet-message") -> 56 bytes = key (32) || nonce (24)
ENCRYPT(mk, p, ad) = XChaCha20-Poly1305(key, nonce, p, aad = ad)      with (key, nonce) = EXPAND(mk)
```

Initial state, initiator `A`: `DHs` fresh, `DHr = SPK_B`,
`(RK, CKs) = KDF_RK(SK, X25519(DHs, DHr))`, `CKr = none`, `Ns = Nr = PN = 0`.
Responder `B`: `DHs = SPK_B` key pair, `DHr = none`, `RK = SK`,
`CKs = CKr = none`. `B` cannot send until `A`'s first message arrives.

Each message is encrypted with `mk` from `KDF_CK(CKs)` under associated
data

```
ad = AD || session (16) || header.dh (32) || header.pn (4 BE) || header.n (4 BE)
```

where `header.dh = DHs.public`, `header.pn` is the length of the previous
sending chain and `header.n` the position in the current one. On receiving
a header whose `dh` differs from `DHr`, the receiver derives the keys for
the `pn - Nr` messages still missing from the old chain, then performs a DH
ratchet step: `PN = Ns; Ns = Nr = 0; DHr = header.dh;
(RK, CKr) = KDF_RK(RK, X25519(DHs, DHr)); DHs = fresh;
(RK, CKs) = KDF_RK(RK, X25519(DHs, DHr))`. Keys for messages skipped within
a chain are stored under `(dh, n)`; a message may be at most 1000 ahead of
the last one received in its chain, and at most 2000 skipped keys are kept
(oldest dropped). A message that fails to authenticate leaves the state
exactly as it was.

### 6.1 Post-quantum ratchet (v4)

The Double Ratchet above heals a compromise against a classical adversary,
because each direction change mixes a fresh X25519 output into the root
key. Against an adversary who can break X25519 it does not: such an
adversary who also learns the root key can follow the ratchet forward. The
post-quantum ratchet closes that by doing an **ML-KEM-768 step beside every
Diffie–Hellman step**, so the root key depends on a fresh ML-KEM secret at
each turn as well, and healing is post-quantum too.

Each side keeps, in addition to its DH ratchet key pair, an ML-KEM ratchet
key pair (`kem_self`) and the peer's latest ML-KEM public key
(`kem_remote`). The root KDF gains the ML-KEM secret:

```
KDF_RK_PQ(rk, dh_out, ss) = HKDF-SHA256(salt = rk, ikm = dh_out || ss,
                              info = "silver-messenger/v4/ratchet-root")  -> rk' (32) || ck (32)
```

with `ss` the 32-byte ML-KEM shared secret; a step with no ML-KEM secret
(the two bootstrap chains below) omits `ss` from the ikm and uses the same
`info`. Every v4 message header carries the sender's current ML-KEM public
key as `header.kem` (1184 bytes) and, on every chain but the first of a
direction, the ciphertext `header.kem_ct` (1088 bytes) encapsulated to the
peer's `kem_remote`; both are covered by the message's associated data, so
the relay cannot swap them undetected.

A DH+KEM ratchet step, on receiving a header with a new `dh`:

1. **Receiving chain.** If `header.kem_ct` is present, decapsulate it with
   `kem_self` to get `ss_r`; `(RK, CKr) = KDF_RK_PQ(RK, DH(DHs, header.dh), ss_r)`.
   Set `kem_remote = header.kem`, `DHr = header.dh`.
2. **Sending chain.** Fresh `DHs`, fresh `kem_self`; encapsulate to
   `kem_remote` to get `(ct_s, ss_s)`; `(RK, CKs) = KDF_RK_PQ(RK, DH(DHs, DHr), ss_s)`;
   attach `ct_s` to every message of this chain as `header.kem_ct`.

**Bootstrap.** The initiator's first sending chain and the responder's
first receiving chain have no peer ML-KEM key to encapsulate to yet, so
they are Diffie–Hellman-only (`ss` omitted) — exactly as the handshake
already bootstraps the DH ratchet against the signed prekey. The
handshake's own PQXDH secret covers that first exchange; from the first
reply on, every chain is ML-KEM-ratcheted, so a compromise heals within one
round trip against a quantum adversary too. A tampered `kem` or `kem_ct`
yields a different secret (or fails to parse) and the message does not
decrypt, leaving the session untouched, like any other tampering.

A v4 message is about 2.3 KB larger than a v2 one (the two ML-KEM fields).
This is the *dense* variant, one ML-KEM step per DH step; a *sparse*
variant that ratchets less often would shrink that, and can be adopted
later without a format change, since the fields are already per-message
optional. The reference is Signal's Sparse Post-Quantum Ratchet.

## 7. Relay wire protocol

Transport: one WebSocket per connection, path `/ws`, text frames, one JSON
object per frame with a `type` field in `snake_case`. The relay speaks
first.

### Client → relay

| `type` | Fields | Notes |
| --- | --- | --- |
| `auth` | `user_id`, `signature`, `host`? | With `host` (the relay's host name as the client connected to it, lower case, without port or IPv6 brackets): `signature = sign("silver-messenger/v2/relay-auth", host \|\| nonce)`, the bound login. Without: `sign("silver-messenger/v1/relay-auth", nonce)`, which a hostile relay could collect and present to another; accepted only while `--require-bound-auth` is off. |
| `publish` | `bundle`, `invite`? | The client's own bundle (section 2). `invite` is a token for relays that only register invited identities. |
| `lookup` | `user_id` | |
| `send` | `envelope` | |
| `ack` | `id` | The envelope with this id was received and stored; the relay may drop it. |
| `blob_put` | `blob`, `index`, `total`, `data` (b64) | Store chunk `index` of `total` of blob `blob` (section 7.5). |
| `blob_get` | `blob` | Ask for every chunk of a blob. |
| `revoke` | `revocation` | A self-signed revocation (section 10). Accepted without `auth`, since the key may be lost; a one-shot, the connection then closes. |
| `succeed` | `succession` | A cross-signed succession (section 10). Accepted without `auth`; a one-shot. |
| `log_since` | `index` | The transparency log entries after `index` (section 11), a page at a time; the client asks again from the last index it got until it reaches the head. Rate limited with `lookup`. |
| `key_packages` | `packages`, `last_resort`? | Replace the client's MLS key packages on deposit (section 13.4). Authenticated connections only, after `publish`. |
| `key_package` | `user_id` | Ask for one of `user_id`'s key packages (13.4). Only from a connection that deposited its own; rate limited with `lookup`. |
| `group_create` | `group`, `epoch`, `next` | Create the epoch sequencer entry of a group (13.5). On any connection. |
| `group_commit` | `group`, `epoch`, `token`, `next` | Move a group's sequencer entry on by one epoch (13.5). On any connection. |
| `ping` | | |

### Relay → client

| `type` | Fields | Notes |
| --- | --- | --- |
| `challenge` | `nonce` (b64, 32 bytes), `bound`? | First frame on every connection. `bound: true` says the relay takes the bound login; a client that sees it answers with `host`. Relays before 0.6.0 omit it. |
| `auth_ok` | `user_id`, `features`?, `head`? | `features` lists strings from section 7.3; absent on older relays. `head` is the transparency log's head (section 11); absent without the `transparency` feature. |
| `published` | | |
| `prekey_status` | `one_time_remaining`, `consumed`? | After `published`, only to clients whose bundle carried prekeys: how many one-time keys are on deposit and which ids were handed out since they were published. |
| `lookup_result` | `user_id`, `bundle` (or `null`), `revocation`?, `succession`?, `head`?, `logged`? | `revocation` and `succession` carry the lifecycle statements the relay holds for `user_id` (section 10), if any; older relays omit both fields. `head` is the transparency log's head at the time of the answer and `logged` where `user_id` last appears in it (section 11); absent without the `transparency` feature, `logged` also when nothing is logged for the identity. |
| `log_entries` | `entries`, `head` | In answer to `log_since`: up to 256 entries in order (section 11), and the head the relay stands at. `entries` is empty when the index asked for was the head already. |
| `sent` | `id` | The envelope is queued for delivery. |
| `rejected` | `id`, `code`, `message` | The envelope was not queued. `rate_limited` means try again later; any other code is final. |
| `deliver` | `envelope` | Delivered in mailbox order; acknowledge with `ack`. |
| `blob_ack` | `blob`, `index`, `complete` | The chunk is stored (or was already); `complete` once every chunk is. |
| `blob_rejected` | `blob`, `code`, `message` | A `blob_put` or `blob_get` for this blob failed. `rate_limited` means try again later; `not_found` on a `blob_get` means the blob is unknown, incomplete or expired. |
| `blob_chunk` | `blob`, `index`, `total`, `data` (b64) | One chunk in answer to `blob_get`; `total` says how many to expect. |
| `key_package_status` | `remaining`, `consumed`? | Answers `key_packages`: how many packages are on deposit and which refs were handed out since the last deposit (13.4). |
| `key_package_result` | `user_id`, `package` (or `null`), `last_resort`? | Answers `key_package`: one package, with `last_resort: true` when it is the one handed out again and again (13.4). |
| `group_state` | `group`, `epoch` | Answers `group_create` or `group_commit`: the entry stands at `epoch` (13.5). |
| `group_rejected` | `group`, `code`, `epoch`? | The sequencer refused: `stale` (with the epoch it stands at), `not_found`, `exists` (with the epoch), `forbidden`, `rate_limited` (13.5). |
| `pong` | | |
| `error` | `code`, `message` | Answers a frame other than `send`, `blob_put`, `blob_get`, `group_create` and `group_commit`, or reports a broken connection state. |

Error codes: `unauthenticated`, `bad_signature`, `malformed`, `too_large`,
`forbidden`, `mailbox_full`, `rate_limited`, `invite_required`,
`not_found`, `storage_full`, `stale`, `exists`, `internal`.

### 7.1 Authenticated connection

`challenge` → `auth` → `auth_ok`, then `publish` → `published`
[→ `prekey_status`]. The relay replays every queued `deliver` for the user
as soon as `auth` succeeds, so they may arrive before `published`. A newer
connection for the same user replaces the older one, which is closed.

With the bound login the relay checks that `host` is the host it was
reached as (the `Host` header of the upgrade request, which a TLS front
passes through, normalised the same way) before verifying the signature,
so a relay in the middle cannot forward a challenge from another relay and
use the answer there. The v1 login remains accepted for clients from before
0.6.0 unless the operator turns it off; a later version will refuse it by
default.

On `publish` with prekeys the relay stores the signed prekey with the
bundle and the one-time keys separately. It keeps, per user, the ids it
has handed out; a handed-out id listed again is not stored again, and an
id no longer listed is forgotten on both sides. Clients top up when
`one_time_remaining` drops below their threshold (this implementation keeps
20 on deposit and tops up below 10).

On `lookup` from a connection that published prekeys, the relay removes one
one-time key from the target's deposit and attaches it to the result.
Lookups from other connections get the bundle with `one_time` empty, and
so do lookups beyond the relay's hand-out rate for that target (30 keys an
hour by default), so nobody can empty a deposit by asking in a loop. A
session started without a one-time key loses nothing but the fourth
Diffie–Hellman term of its first message; there is no separate
last-resort prekey, since the signed prekey already plays that part and
the owner tops the deposit up on its next connection.

### 7.2 Anonymous submission connection

On a relay advertising `anonymous_send`, a connection may answer the
`challenge` with a `send`, `blob_put`, `blob_get`, `group_create` or
`group_commit` frame instead of `auth`. The connection then accepts only
those five and `ping`, answered as on an authenticated connection, under
its own rate limits (30 `send` and 600 chunks per minute by default; the
two group frames count as `send`). It never learns who the sender is.
A client uses one such connection for all its submissions, uploads and
downloads, and its authenticated connection for everything else; for TLS
the submission connection disables session resumption so the two cannot
be linked through a resumed session.

### 7.3 Features

| Feature | Meaning |
| --- | --- |
| `prekeys` | Section 7.1 prekey handling: `prekey_status`, one-time keys on lookup. |
| `anonymous_send` | Section 7.2. |
| `blobs` | Section 7.5: the relay stores encrypted file chunks. Absent when the operator set the largest blob to 0. |
| `pq_prekeys` | The relay keeps `pq_signed` and `pq_one_time` (section 2), hands out one-time ML-KEM keys on lookup and reports them in `prekey_status` (`pq_one_time_remaining`, `pq_consumed`). |
| `lifecycle` | The relay accepts `revoke` and `succeed`, keeps the statements, refuses to publish a revoked identity, and attaches the statements to `lookup_result` (section 10). Absent on relays before 0.8.0; contacts then learn only from the copy pushed inside a message. |
| `transparency` | The relay keeps the hash-chained log of section 11, tells its head in `auth_ok` and `lookup_result`, and answers `log_since`. Absent on relays before 0.8.0; clients then check nothing against a log and send no `head` in their bodies. |
| `groups` | The relay keeps MLS key packages on deposit and hands them out (`key_packages`, `key_package`) and runs the group epoch sequencer (`group_create`, `group_commit`), section 13. Absent on relays before 0.9.0; clients then show groups as unavailable on that relay. |

A relay without the field is a v1 relay: it stores bundles as v1 (dropping
`prekeys`, since it re-serialises what it parsed), so clients behind it
speak v1 to everyone. A relay with `prekeys` but not `pq_prekeys` drops the
ML-KEM keys the same way, so clients behind it speak v2. `prekey_status`
from such a relay carries no `pq_one_time_remaining`, and a client takes
its absence as "not kept here" rather than "none left".

### 7.4 Limits and abuse controls

Per authenticated connection: 60 `send`, 30 `lookup` and 600 blob chunks
(`blob_put` or chunks answered to `blob_get`) per minute (token buckets of
that burst size). Per anonymous connection: 30 `send` and 600 chunks per
minute. Per recipient: 1000 queued envelopes or 32 MiB, whichever first;
unacknowledged envelopes expire after 30 days. Blobs: at most 16 MiB of
plaintext each (the relay allows 16 MiB plus the 256 chunk tags of
ciphertext), 1 GiB in total, and each expires 30 days after its first
chunk arrived, on the same schedule as messages. Per client address (the
socket's peer, or what a trusted TLS front says in `X-Forwarded-For`): 16
open connections, 20 new identities an hour and 256 MiB of `blob_put`
data an hour; 4096 connections and 100 000 identities in total; a
connection that sends nothing for two minutes is closed (clients `ping`
every 30 seconds). Groups (section 13): one `key_packages` deposit per
connection per minute, 30 packages plus a last-resort one per identity,
4096 bytes each; `key_package` counts against the connection's `lookup`
budget and against the target's hand-out budget of 30 an hour, which it
shares with one-time prekeys; `group_create` and `group_commit` count as
`send`, and `group_create` also against the address's 20 registrations
an hour; 100 000 sequencer entries in total, each dropped after 180 days
without a commit. Relay operators can change all of these and can
require an invite token for first registrations.

### 7.5 Blob storage

A blob is a sequence of `total` ciphertext chunks (4.5) under a 32-hex-
character id, stored by whoever puts it and served to whoever asks for it
by id: the relay does not know, and does not ask, who either party is. The
id is 128 random bits and travels only inside encrypted messages, so
knowing it is the capability to fetch the ciphertext, which is useless
without the key from the same message.

* The first `blob_put` for an id fixes `total`; a later chunk with a
  different `total`, or `index >= total`, is rejected as `malformed`. Each
  chunk is at most 65 552 bytes.
* A chunk already stored is acknowledged again, not stored twice, so a
  client may resend after a reconnect.
* A chunk that would push the blob past the largest allowed size is
  rejected as `too_large`; one that would push the relay past its total
  storage as `storage_full`; on a relay that stores no blobs at all as
  `forbidden`.
* `blob_get` on a blob whose chunks have not all arrived, or that is
  unknown or expired, answers `not_found`. Otherwise every chunk is sent
  as `blob_chunk` in index order.
* Chunks and the message that names them expire independently; a client
  that fetches late may find the message but not the blob.

## 8. Client behaviour that affects interoperability

* **Choosing the body version.** A client with a session store sends a
  ratchet body when the recipient's bundle carries prekeys, and a plain v1
  body otherwise. Among ratchet bodies it sends **v4** when the bundle both
  carries `pq_signed` and advertises the `pq_ratchet` capability (section
  2); otherwise **v2**, whose handshake is still PQXDH when the bundle
  carries `pq_signed`. It must accept every kind from anyone, and a
  responder must answer a v2 or a v4 body (an initiator behind an older
  relay, or talking to an older peer, sends the older kind). An existing
  session keeps its version for its lifetime.
* **Retiring v1.** The plain v1 body has no forward secrecy and is signed
  (not deniable); it survives only to reach clients from before prekeys.
  It is scheduled to go: 0.8.0 and 0.9.0 still send it to a peer with no
  prekeys and log that it is neither forward secret nor deniable, and
  0.10.0 refuses to send it (a peer without prekeys is then unreachable
  until it updates). Receiving a v1 body stays supported longer, for
  stored history.
* **Starting a session.** A fresh lookup precedes the first message of a
  session, so the handshake uses a current signed prekey and a one-time key
  that has not been handed out before. A pinned bundle is used only when
  the relay cannot be reached. A signed prekey whose `created_at_ms` is
  more than three weeks old (the time its owner keeps the private half) is
  not used: the message goes as a plain body instead and the user is told
  that it went without forward secrecy, since a relay can serve a bundle
  for as long as it likes but cannot make a session out of it readable.
* **Repeating `init`.** The initiator includes `init` until it decrypts a
  message on that session.
* **Several sessions.** Every session with a peer is kept for receiving;
  one is active for sending. A session the peer starts becomes active on
  its first message, except when this client started one itself within the
  last ten minutes, has not heard back on it, and its own id sorts before
  the peer's: then both sides keep the one started by the lower id. At most
  five sessions per peer are kept; the least recently used go first.
* **Key change.** When a peer's `dh_public` differs from the pinned one,
  all sessions with that peer are dropped and the user is warned; the next
  message starts a new session.
* **Prekey rotation.** The signed prekey is replaced after seven days and
  kept for three weeks; a one-time key's private half is deleted when a
  session uses it or thirty days after the relay reported handing it out.
  The ML-KEM keys follow the same rules: `pq_signed` rotates and is kept
  like `signed`, and one-time ML-KEM keys are deleted like X25519 ones.
  This implementation keeps twenty one-time X25519 keys on deposit,
  topped up when the relay reports fewer than ten, and ten ML-KEM ones,
  topped up below five; a client whose prekey file predates ML-KEM keys
  adds them on its next publish, so an upgrade needs no reinstall.
* **Sequence numbers.** `seq`/`epoch` in the inner plain body are checked
  exactly as for v1 messages.
* **Capabilities.** A client records the `caps` of every message it
  accepts from a contact and sends `receipt` and `file` content only to
  contacts whose last list carried the capability. It advertises its own
  in every body it sends, receipts included.
* **Receipts.** Sent only to accepted contacts; batched for 400 ms plus a
  random delay (4.4); `read` only for messages shown while the window has
  focus, and only while the user allows it. Receipt bodies are not
  themselves acknowledged.
* **Cover traffic.** Off unless the user turns it on; advertised as
  `cover` only while on; sent (4.6) only to contacts whose last message
  advertised it, only while connected, never queued for later; discarded
  on receipt, with no receipt of its own.
* **Files.** Sent only when the recipient advertised `files` and the relay
  advertises `blobs`; padded (4.5) when it advertised `padded_files` too.
  The upload finishes (every chunk acknowledged) before the `file` message
  is sent, so a recipient never asks for an incomplete blob. Up to four
  chunks are in flight; after a reconnect, chunks not yet acknowledged are
  put again. A recipient fetches a file only when the user asks (or has
  asked for that contact's files to be fetched as they arrive), and only
  from accepted contacts; a file announced by a stranger is shown with the
  request and fetched never, so acceptance later means asking the sender
  to send it again. Saved files never overwrite: a name already taken gets
  ` (2)`, ` (3)` and so on before the extension.
* **Transport.** A client that has reached a relay host over `wss://`
  refuses to connect to that host over `ws://` from then on. A client may
  carry pins for the relay's TLS public key (the SHA-256 of the DER
  `SubjectPublicKeyInfo`, as RFC 7469); with pins set, a chain that
  carries none of the pinned keys is refused even when it validates. Both
  connections (7.1, 7.2) may go through an HTTP `CONNECT` or a SOCKS5
  proxy; through SOCKS5 the relay's name is resolved by the proxy, and
  each connection logs in to the proxy with fresh random credentials
  unless the proxy URL carries fixed ones, so that a Tor proxy gives each
  its own circuit.

## 9. What the protocol does not do

**Deniability: done for v4 sessions.** A v4 ratchet body (4.2) carries no
signature at the sealed layer, so a recipient cannot prove to a third party
who wrote it. Nothing is lost by dropping the signature: the Double
Ratchet's AEAD already authenticates the sender to the recipient, since
only the two of them hold the keys; the handshake is deniable (X3DH, and
PQXDH the same way: either party could have computed every value in it);
and the one remaining signature, `init.identity_dh_signature` (4.2.1), is
over the sender's own public key, published in every bundle and reusable,
so it says nothing about who was talked to. Either party could therefore
have produced a whole v4 transcript, which is what deniability means, the
way Signal's messages are deniable.

Two things still carry a signature. A **v1 body** has nothing else to
authenticate it, so it stays signed; it is being retired (section 8), and
a message to a peer with no prekeys is the only place it is still sent. A
**v2 body** (a session with a peer or relay that predates v4) keeps the
sealed-layer signature too; those sessions are not deniable, and a client
shows which a session is (`/session`). As v1 goes and v4 becomes the norm,
signed session messages disappear.

Sizes are padded to steps
(160 bytes for messages, 64 KiB for files between clients that support
it) rather than to one size, and cover traffic (4.6) flows only between
two contacts who both turned it on and only while both are around, so a
relay or network observer still sees when blobs travel and roughly how
big messages and blobs are, including that a blob is fetched some time
after a message is delivered; between contacts without cover it sees
when messages travel too. Receipts are delayed at random rather than
hidden. Group messages (section 13) are not deniable: MLS signs every one
with the sender's leaf key, which is the identity key.

## 10. Identity lifecycle

An identity key can be retired or replaced without word of mouth, by two
short signed statements. Each carries its own signatures, so it is trusted
however it arrived: served on a `lookup_result`, or pushed inside a message
(the `revocation` and `succession` content types, sent only to peers that
advertised the `lifecycle` capability). A contact acts on a statement only
after checking it against the key it has pinned for that identity.

### 10.1 Revocation

A **revocation** declares an identity dead.

```json
{ "identity": "<user id>", "created_at_ms": 1699999999999,
  "signature": "<b64 64 bytes>" }
```

It is self-signed by the identity it retires:
`signature = sign("silver-messenger/v4/revocation", identity || created_at_ms)`,
with `identity` the 32 raw key bytes and `created_at_ms` eight big-endian
bytes. `verify()` checks that signature. Only the key holder could have
produced a valid one, so anyone may store and relay it.

A client mints its revocation the first time it runs, while the key is
present, and keeps it aside (in the data directory and, encrypted, in the
export backup) for the day the key must be declared dead — the way an
OpenPGP revocation certificate is kept for later. It can therefore be
published even after the private key is lost, which is why the relay takes
a `revoke` frame without a login (7, pre-auth one-shot).

A relay that keeps lifecycle statements stores the revocation, disconnects
the identity if it is online, refuses any later `publish` for it
(`forbidden`, "this identity has been revoked"), and attaches it to every
`lookup_result` for it. The refusal is permanent: removing the user does
not lift it, so a revoked key can never be re-registered. A contact that
sees a valid revocation for a pinned key retires that contact, drops its
sessions, and stops sending to it.

The relay keeps a statement only for an identity registered with it (one
that has published a bundle), so it holds at most one revocation and one
succession per identity it already knows and cannot be filled with
statements about throwaway keys; a statement for an unknown identity is
refused (`forbidden`). Each accepted or refused statement also costs the
sending address one of its hourly new-identity registrations (section
7.4), since a self-authenticating frame is otherwise free to send.

### 10.2 Succession

A **succession** names a successor identity for a planned rotation, while
the old key still works.

```json
{ "old": "<user id>", "new": "<user id>", "created_at_ms": 1699999999999,
  "old_signature": "<b64 64 bytes>", "new_signature": "<b64 64 bytes>" }
```

It is *cross-signed*, the way Matrix cross-signing binds a new device key:
the old key authorises the handover and the new key accepts it, over the
same bytes `old || new || created_at_ms` (raw key bytes and eight
big-endian bytes):

* `old_signature = sign("silver-messenger/v4/succession", message)`
* `new_signature = sign("silver-messenger/v4/succession-accept", message)`

`verify()` checks both and that `old` and `new` differ, so nobody can name
someone else's key as their successor, and a rotation needs both keys'
consent. A relay keeps it under the old identity and attaches it to a
`lookup_result` for the old identity. A contact that sees a valid
succession for its pinned (old) key re-pins the contact to `new`: it moves
the conversation across, clears the pinned bundle and the verified mark,
starts message numbering afresh, and looks the new key up. The safety
number changes, so the two should compare it again, but no out-of-band step
is required to keep talking.

**A revocation is final.** A dead key cannot hand over: the relay refuses
a `succeed` whose `old` (or `new`) is revoked, and once it holds a
revocation for an identity it serves no succession for it, whichever
arrived first. A contact applies the same rule and ignores a succession
for a key it has marked revoked. Without this, whoever held a compromised
key could name their own successor and keep the victim's contacts even
after the victim revoked it. The cost falls on the owner who rotates and
then also revokes the old key: the succession already retires it, and a
contact that sees the revocation before the succession retires the
contact instead of re-pinning and needs the new id by hand. So: rotate a
key you still control, revoke a key you have lost, and do not do both.
A succession already applied is not undone by a later revocation of the
old key (the contact no longer has that key pinned); the two cases are
indistinguishable from the statements alone, and the threat model records
the race.

### 10.3 What it does not do

A revocation is permanent; a key retired by mistake is recovered by making
a new identity, as before. Both statements are entered in the transparency
log (section 11), so a relay that withholds one it holds is caught by the
next contact who tails the log (a contact still learns from the copy pushed
inside a message too, and withholding cannot forge a statement, only delay
it). Lifecycle applies to one-to-one identities; group membership is
separate.

## 11. Key transparency

The user id is the identity key and every field of a bundle is signed by
it, so a relay cannot substitute an identity or a key: a lookup for X
returns only what X signed. What a relay can still do to one person and
not another is serve a *stale* bundle (an old signed prekey whose private
half may later leak, or a stripped capability list), *withhold* a
revocation or succession, or keep two versions of its state and show each
to different people. Those are failures of freshness and consistency, which
signatures cannot catch and a transparency log can: the relay keeps an
append-only, hash-chained log of every change it serves, clients replay it
and check what they were shown against it, and every message carries the
sender's view of the log head inside its encrypted body, so a relay that
shows two people two different logs is caught by the next message between
them, with nobody reading numbers aloud. CONIKS and Signal's key
transparency are the references; with one relay per network, the clients
are the auditors, and the gossip between them is the essential part.

### 11.1 The log

An entry records one change:

```json
{ "index": 4093, "prev": "<b64 32 bytes>", "subject": "<b64 32 bytes>",
  "kind": "bundle", "leaf": "<b64 32 bytes>", "at_ms": 1700000000000 }
```

* `index` counts from 1. `prev` is the hash of the entry before; the first
  entry's is 32 zero bytes.
* `subject = SHA-256("silver-messenger/v4/transparency-subject" || id)`
  with `id` the 32 raw bytes of the identity key. Ids are random, so a
  reader learns nothing about whom an entry concerns unless it already
  knows the id; a contact computes the subject of the ids it has pinned.
* `kind` is `bundle`, `revocation` or `succession`.
* `leaf` is the hash of the bundle or statement (11.2).
* The entry's hash is
  `SHA-256("silver-messenger/v4/transparency-entry" || prev || index || subject || kind || leaf || at_ms)`,
  with `index` and `at_ms` as 8 big-endian bytes and `kind` one byte (1
  bundle, 2 revocation, 3 succession).

The **head** is `{ "index": N, "hash": <hash of entry N> }`; the empty
log's head is index 0 with 32 zero bytes. The head commits to the whole
log: whoever holds the head and replays the entries recomputes it.

### 11.2 Leaves

A **bundle's leaf** hashes everything in it that its owner signed, in a
fixed byte layout, so relay and client compute the same value whatever
version serialised the bundle, and one-time prekeys (which change with
every lookup and are not part of the stored bundle) are left out:

```
SHA-256("silver-messenger/v4/transparency-bundle"
        || user_id (32) || dh_public (32) || signature (64)
        || prekeys? : 0x00, or 0x01 || signed.id (4 BE) || signed.public (32)
                      || signed.created_at_ms (8 BE) || signed.signature (64)
                      || pq_signed? : 0x00, or 0x01 || pq.id (4 BE)
                                      || len (4 BE) || pq.public
                                      || pq.created_at_ms (8 BE) || pq.signature (64)
        || caps.len (4 BE) || (len (4 BE) || cap)*
        || caps_signature? : 0x00, or 0x01 || caps_signature (64))
```

A **revocation's leaf** is
`SHA-256("silver-messenger/v4/transparency-revocation" || identity || created_at_ms || signature)`
and a **succession's**
`SHA-256("silver-messenger/v4/transparency-succession" || old || new || created_at_ms || old_signature || new_signature)`,
integers as 8 big-endian bytes.

### 11.3 What the relay logs and serves

The relay appends, in the same database transaction as the write it
records: a bundle on `publish` when its leaf differs from the identity's
last logged bundle leaf (a reconnect that republishes the same bundle adds
nothing); every revocation and succession it accepts. Nothing is ever
removed from the log, not even when the identity is removed. A relay that
starts logging with state already in its database enters one entry per
bundle and statement it holds first, so from then on nothing it serves is
missing from the log. Restoring a backup restores the log with it; a
restore of an older backup shortens the log, which clients notice (11.4).

It advertises `transparency` (7.3), tells its head in `auth_ok` and in
every `lookup_result` together with `logged`, where the looked-up identity
last appears (its latest entry's index and leaf), and answers `log_since`
with the entries after an index, up to 256 at a time, under the lookup
rate limit.

### 11.4 What the client checks

A client keeps the head it last verified, the hash at every index of the
last 4096 entries and at every 256th before that (checkpoints), and, per
subject, where that identity last appears and its latest bundle leaf.

**Tailing.** On login, and whenever an answer or a contact's head is ahead
of its own, the client asks `log_since` from its head, page by page, and
replays: every entry must have the head's index plus one and the head's
hash as `prev`; the entry's hash becomes the new head. A page that does not
chain, or a relay that claims a head it will not hand out the entries up
to, is reported (a *fork* or *withholding*) and every answer waiting on the
replay is refused.

**A lookup.** The answer is held until the log is replayed up to the head
it came with, then checked: the bundle's leaf must be the identity's latest
logged bundle leaf (one that was never logged, or is not the latest, is
refused: a stale prekey is the attack); `logged` must be the position the
client replayed; a logged revocation must be in the answer, as must a
logged succession when no revocation is logged, and a statement served must
be the logged one. A refused answer reaches the front end as a refusal
naming the problem, and nothing is sent with the key.

**Gossip.** Every body carries the sender's verified head (4.1). On
receipt: at the same index the hashes must match; at a lower index the
hash must match the checkpoint the client holds for it, or, where it
holds none, the chain recomputed from entries fetched from the relay
between the checkpoints on either side, which must arrive at the upper
checkpoint's hash before its hash at the contact's index means anything
(a segment that does not is the relay's own doing and is reported as the
relay's fork); at a higher index the client tails to it, and the chain it
gets must pass through that head. A mismatch is a fork, reported with the
contact's name: the relay showed the two of them different logs. A relay whose head is lower than
the client's last verified head has been *rewound* (a restore of an older
backup, or a replaced log); that is reported, and the client replays the
log from the start.

Nothing here changes what a key change means (8): a contact whose key
changes is still warned about loudly, and the safety number (`/verify`) is
still the check that needs no relay at all.

### 11.5 What it does not do

There are no inclusion proofs: the log is a chain, not a tree, and a client
tails it whole, which suits a network of one relay whose log grows by one
entry per prekey rotation or lifecycle event. The relay does not sign its
heads; its word is checked against the clients', not against itself. Two
contacts who never message each other never compare heads, and a relay
that forks its log for exactly one client *and everyone that client talks
to* is caught only when one of them also talks to someone on the other
side. The log's subjects are hashed, but its timing is not: a reader sees
that some identity published at some time.

## 12. Conformance

### 12.1 Test vectors

`docs/vectors/` holds known-answer vectors for every operation in this
document: identities and every signature, the key derivations one by one,
a whole handshake (v2, v3 and v4), two round trips of the ratchet with
late and out-of-order delivery, the sealed layer (signed and deniable),
the padded body encodings, the transparency log's hashes, file chunks,
and the group extensions, link keys, join proofs and sequencer token
hashes of section 13 (the MLS messages themselves are RFC 9420's, with
its own vectors). Each case gives its inputs, every intermediate value on the way
(each Diffie–Hellman output, each KDF input and output, each AEAD's
associated data, the exact bytes under each signature) and its outputs.
Where an operation draws randomness the vector fixes it with a seeded
generator and states the order in which the operation consumes it;
`docs/vectors/README.md` has the format, the generator and that order.

`crates/silver-protocol/tests/vectors.rs` replays the vectors against this
implementation on every test run, and re-derives the intermediates by
hand from the byte layouts given here, so the vectors, the code and this
text are checked against one another. A vector that moves is a wire
change: it gets a version, a note here and a changelog entry. A second
implementation that reproduces the files conforms to the parts they
cover; what they do not cover is the client behaviour of section 8.

Two byte layouts the vectors pin that the sections above give in prose:

* The ratchet header as associated data (section 6) is `dh (32) ||
  pn (4 BE) || n (4 BE) || kem (1184, when present) || kem_ct (1088, when
  present)`, a fixed-length concatenation with no separators.
* The capability list is signed (section 2) as `dh_public (32) || caps
  joined by "\n"`, so a capability name never contains a newline.

Known and left as it is: the envelope `id` (section 3) is outside every
AEAD and signature. A relay can rename an envelope, which lets it defeat
de-duplication of that envelope or make a receipt name an id its sender
does not know, and nothing more than dropping the envelope would; the
content and the sender are unaffected. It stays for wire compatibility
and is recorded here so that nothing else comes to rely on it.

### 12.2 Formal models

`formal/` holds Verifpal models of the handshake and the ratchet: the v4
handshake (section 5 with 6.1 and 4.2.1) with and without a one-time
prekey, against an adversary that later obtains every kept key and
against one that breaks X25519 outright, plus one variant without the
key-binding signature that is expected to break; the v2 handshake with
its envelope signature; the v4 ratchet against a passive adversary that
reads both devices between two messages, against one that also breaks
X25519, and against an active one; and the v2 ratchet against the
X25519-breaking adversary, which is expected to fail where v4 holds.
`formal/expected.txt` records the outcome every query must have, the
expected failures included, `formal/check.sh` checks them, and CI runs
it on every push. `formal/README.md` maps each query to the claim in
`THREAT_MODEL.md` it backs, gives the modelling choices (ML-KEM is
Verifpal's KEM; the pinned identity keys are the only guarded values;
constants are left out), and says what the models do not cover:
sealed-sender anonymity and deniability (section 9), the transparency
log (section 11), the client's replay protection (section 8), and
anything beyond Verifpal's bound, which finds attacks within a bounded
number of sessions and proves nothing about what lies past it.

## 13. Groups (MLS)

A group is an MLS group (RFC 9420) run by the members' clients, with the
relay as a dumb delivery service: it keeps members' key packages on
deposit and hands them out like prekeys, orders commits with one counter
per group, and carries every group message inside the ordinary sealed
envelope of section 3, one per member, through that member's own mailbox.
It never parses an MLS message. One-to-one conversations stay on the
Double Ratchet; a group is whatever `/group new` made, at any size. The
reasoning behind each choice is in `docs/design/groups.md`; this section
is what is on the wire. The MLS objects themselves (`KeyPackage`,
`Welcome`, `PrivateMessage`, the tree) are RFC 9420's, TLS-serialised as
`MLSMessage` where the RFC defines that framing.

Groups need clients and a relay on 0.9.0 or later: the relay advertises
`groups` (7.3), and a client's bundle advertises `groups` in its signed
capability list (section 2) once it has key packages on deposit. Nothing
of this section is ever sent to a client that does not advertise it.

### 13.1 Ciphersuite, credentials and extensions

* **Ciphersuite**: `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519` of
  draft-ietf-mls-pq-ciphersuites, on the provisional code point OpenMLS
  assigns it, `0x004F`: X-Wing (ML-KEM-768 + X25519) as the HPKE KEM,
  AES-128-GCM, SHA-256, Ed25519 signatures. No other suite is accepted; a
  key package or a Welcome for another is refused. When the RFC assigns
  the final code point, groups are re-created under it.
* **Credential**: `basic`, whose identity is the 32-byte user id (the raw
  Ed25519 verifying key of section 1). The leaf's signature key is that
  same key. A leaf whose credential and signature key are not the same
  bytes, or whose identity is not a valid key, is refused wherever a
  leaf is seen: a key package handed out by the relay, the sender and
  every member in a Welcome, every leaf a commit adds.
* **Leaf node extension `0xF001`** (`silver_seal`, private use): the
  member's sealed-layer X25519 public key (`dh_public` of its bundle), 32
  raw bytes. Every key package and leaf carries it; a leaf without it is
  refused. It is what lets a member seal envelopes to every other member
  from the tree alone, without a lookup and without the relay in the
  loop, verified by the identity that signed the leaf.
* **Group context extension `0xF000`** (`silver_group`, private use):
  the group's metadata, agreed by every member through the group context
  and changed only by a `GroupContextExtensions` proposal an admin
  commits:

  ```text
  version (1 byte, = 1) || name length (1 byte) || name (UTF-8, at most 64 bytes, no control characters)
  || admins length in bytes (2 BE) || admins (32 bytes each, ascending, no duplicates, at least 1, at most 256)
  || invite_key (32 bytes) || created_at_ms (8 BE)
  ```

  Trailing bytes, an unknown version, an unsorted list or an empty one
  make the extension malformed and the group unusable.
* **Required capabilities**: every group's context carries a
  `RequiredCapabilities` extension listing extension types `0xF000` and
  `0xF001`, and every key package and leaf declares capabilities for the
  one ciphersuite and those two extension types (default protocol
  versions, credential types and proposal types), so a leaf that cannot
  carry them cannot be added.
* **Configuration**: the pure-ciphertext wire format policy (handshake
  messages travel as `PrivateMessage`, never `PublicMessage`); the
  ratchet tree travels inside the Welcome (`ratchet_tree` extension), so
  there is no tree service; application messages from the last three
  epochs still decrypt after a commit; a commit carries an update path
  when RFC 9420 requires one, and every member forces a self-update
  commit when its leaf is seven days old, so a compromise heals within
  the week in a quiet group.

### 13.2 The group body (v5)

A body with `v: 5` carries one MLS message for one group to one member:

```json
{ "v": 5, "group": "<b64 32 bytes>", "kind": "<kind>",
  "mls": "<b64 TLS-serialised MLSMessage>",
  "blob": { "blob": "<32 hex>", "key": "<b64 32 bytes>", "chunks": n, "size": n, "sha256": "<b64 32 bytes>" },
  "join": { "proof": "<b64 32 bytes>" } }
```

* `group`: the group id, 32 random bytes chosen by the creator; b64 in
  JSON, b58 in links and on screen.
* `kind`: `welcome` (an MLS `Welcome`), `handshake` (a `PrivateMessage`
  carrying a proposal or a commit), `message` (a `PrivateMessage`
  carrying an application message, 13.3), `join` (a `KeyPackage` from
  someone presenting an invite link, with `join`, 13.7), `rejoin` (a
  `KeyPackage` from a member that fell out of sync, 13.8).
* Exactly one of `mls` and `blob` is present. `mls` when the message is
  at most 24 576 bytes; otherwise the message is parked in the blob
  store (7.5) exactly as a padded file is (4.5: a fresh key, 64 KiB
  chunks bound to the blob id, index and count, the last chunk padded to
  a whole one), `size` is its true length, `sha256` its hash, and the
  recipient fetches and opens it before processing. Welcomes to groups
  beyond a handful of members and commits that add many take this path;
  an application message never does. A message larger than a file may be
  (16 MiB) cannot be sent.
* `join` is present exactly when `kind` is `join`.
* The body is padded to 160-byte steps like every other (section 4), so
  a short group text is the size of a short one-to-one text.
* The sealed layer (section 3) carries no signature for a v5 body, as
  for v4: the 64 signature bytes are zero and are not checked. Every
  kind is authenticated inside MLS (the sender's leaf signature on a
  `PrivateMessage`, the signature over the `GroupInfo` inside a
  `Welcome`, the key package's own signature for `join` and `rejoin`),
  and MLS's single-use message keys rule out replay. The sender id in
  the sealed prefix is set truthfully but is a hint: the receiving client
  takes the sender from MLS and ignores the hint.
* A v5 body inside a session (a ratchet body's inner body) is refused.

### 13.3 Application messages

The plaintext of a `message` is JSON:

```json
{ "id": "<random, 1 to 64 bytes>", "sent_at_ms": n, "content": { ... }, "head": { ... } }
```

`content` is a `text` or a `file` of section 4; any other kind is
ignored by members (receipts, lifecycle statements and cover traffic are
not sent in groups). `head` is the sender's last verified transparency
log head (section 11), so members compare heads across a group the way
contacts do one-to-one. `id` de-duplicates: a member remembers the last
256 ids per group and shows an id once. MLS numbers messages itself, so
there is no `seq`, and every member is a client that reads groups, so
there are no `caps`.

### 13.4 Key packages

An MLS `KeyPackage` for the suite of 13.1 with the leaf extension and
capabilities of 13.1, a 90-day lifetime, and the credential of its
owner. A client keeps twenty on deposit and makes more when fewer than
ten remain or one has expired; it keeps one more marked with the MLS
`last_resort` extension, replaced every 30 days, which the relay hands
out again and again once the others are gone. The private halves stay
with the client; a package's is deleted when a Welcome uses it.

The frames, on the authenticated connection after `publish`:

| `type` | Fields | Notes |
| --- | --- | --- |
| `key_packages` | `packages` (list of `{ref, expires_at_ms, data}`), `last_resort`? (`{ref, expires_at_ms, data}`) | Replaces the deposit: a package on deposit that is not listed is forgotten, one listed that is already there or was handed out is not stored again, as for prekeys. `ref` is the MLS `KeyPackageRef` (b64, 32 bytes), `data` the TLS-serialised `MLSMessage` holding the `KeyPackage` (b64, at most 4096 bytes), `expires_at_ms` the end of its lifetime, after which the relay drops it. At most 30 packages plus the last-resort one; an empty list clears the deposit. One deposit per connection per minute. The relay stores the bytes opaque. |
| `key_package` | `user_id` | One of `user_id`'s packages. Only from a connection that has deposited its own; counts against the connection's `lookup` budget. |

| `type` | Fields | Notes |
| --- | --- | --- |
| `key_package_status` | `remaining`, `consumed` (list of `ref`, absent when empty) | Answers `key_packages`: how many packages (the last-resort one not counted) are on deposit, and which refs were handed out since they were deposited, so the client forgets them. |
| `key_package_result` | `user_id`, `package` (`{ref, expires_at_ms, data}` or `null`), `last_resort` (absent when false) | The oldest package on deposit, removed as it is handed out, while the target's hand-out budget lasts (30 an hour, shared with one-time prekeys, 7.1); the last-resort one, never removed, when the deposit is empty or the budget is spent; `null` when the identity has neither. |

The fetcher verifies what it gets before adding: it parses the message,
checks the leaf (13.1) against the `user_id` it asked for, the
ciphersuite, and that the lifetime has not ended, and refuses to add on
any failure, naming the relay. A relay that hands out a stale package
costs the new member's first epoch some forward secrecy, as a replayed
one-time prekey does, and no more.

### 13.5 The epoch sequencer

MLS needs every member to apply the same commit for each epoch; two
commits built on the same epoch would fork the group. The relay orders
them with one entry per group it knows nothing else about:

```text
group id (32 bytes) -> { epoch (u64), next (32 bytes), created_at_ms, updated_at_ms }
```

`next` is the SHA-256 of a token that only members of the group's
current epoch can produce:

```text
token(e) = MLS-Exporter(label = "silver-messenger/v1/group-sequencer", context = group id (32 bytes), length = 32)
           of epoch e
next     = SHA-256(token(e))
```

The frames, on any connection (a client uses its anonymous connection
while it is up, so the relay does not learn which identity committed):

| `type` | Fields | Notes |
| --- | --- | --- |
| `group_create` | `group`, `epoch`, `next` (b64, 32 bytes) | Create the entry if there is none: answered `group_state` with `epoch`. Idempotent for the same three values; an entry with other values answers `exists` with its epoch. Counts as a `send` and against the address's registrations for the hour (7.4). |
| `group_commit` | `group`, `epoch`, `token`, `next` (b64, 32 bytes each) | If the entry stands at `epoch` and `SHA-256(token)` is what it holds: the entry moves to `epoch + 1` holding `next`, answered `group_state` with the new epoch. Otherwise `group_rejected`: `stale` with the epoch the entry stands at when it is not `epoch`; `forbidden` when the token does not hash to what it holds; `not_found` when there is no entry. Counts as a `send`. |

Answers: `group_state { group, epoch }` and `group_rejected { group,
code, epoch? }`, with `rate_limited` when a budget is spent and
`forbidden` from `group_create` when the relay's cap on entries (100 000
by default) is reached. An entry no commit has moved for 180 days is
dropped; a live group refreshes its entry with every commit.

How a client commits: it builds and stages the commit, reads
`token(e)` of its current epoch and `token(e + 1)` from the staged
commit's exporter (OpenMLS exposes the staged commit's secrets before
the merge), sends `group_commit`, and only on `group_state` merges the
commit and fans it out (13.6). On `stale` it discards the staged commit,
takes the winning commit from its mailbox, and rebuilds on top; the
losing side of a race is never sent. On `not_found` (the entry expired,
or the relay was restored from a backup that predates the group) any
member re-creates the entry with `group_create` for its current epoch.
On `stale` with a *lower* epoch than its own (a restored relay), the
client replays the tokens it kept (the last 64 epochs) from that epoch
forward, one accepted `group_commit` per step, until the entry catches
up. The relay verifies a hash of an exporter output: it learns nothing
that decrypts anything, a removed member cannot move the counter (it
lacks the new epoch's exporter), and a hostile relay can only refuse or
scramble the counter, a denial of service it could always cause by
dropping mail. The creator registers a new group with `group_create` at
epoch 0 before anything else is sent.

### 13.6 Delivery

A group message is one MLS ciphertext. The sender seals it once per
member other than itself, to the member's `silver_seal` key from the
tree, into an ordinary envelope (section 3) addressed to that member,
and submits the envelopes as it submits one-to-one messages, on the
anonymous connection where there is one. A commit goes to every member
of the epoch it leaves; the Welcome it makes goes to every member it
adds, alone. Each member finds the message in its own mailbox, under its
own quota and expiry, and acknowledges it as any other. The relay keeps
no membership list and no group mailbox; what fan-out shows it is a
burst of envelopes from one connection to a set of recipients, which the
threat model records.

Envelopes reach a member in its mailbox's order, which is arrival order
at the relay, so two committers' fan-outs can cross and the commit for
epoch `e + 2` can arrive before the one for `e + 1`. A client holds
handshake messages from a future epoch (at most 16, for at most ten
minutes) and retries them after each merge. A commit further ahead than
that, or a queue that fills, means a commit was missed for good: the
client marks the group out of sync and asks to rejoin (13.8).
Application messages decrypt for three epochs after the one they were
sent in; older ones are reported as unreadable, as a ratchet that moved
on would.

### 13.7 Membership: Welcome, invite links, admins

**Add.** An admin fetches one key package of the person to add
(13.4), verifies it, builds a commit with the Add, takes the sequencer
step, merges, fans the commit out and seals the Welcome to the new
member. The added member's client verifies the Welcome before joining:
the sender's leaf (13.1) and that the sender is a member and an admin
of the group's `silver_group` extension, the ciphersuite, that the
Welcome's group id equals the body's `group`, that the extension decodes,
and every member's leaf in the tree. It then joins at once in MLS terms
(the key package's secret is spent by the Welcome, and a joined group
stays in sync while the user decides) and holds the group as *invited*:
nothing of it is shown or sent until the user says yes, and saying no
drops the state, leaving the admin's group with a dead leaf until an
admin notices and removes it. A client says yes on the user's behalf
when the sender is a contact and not blocked, or when the user asked
that admin for that group by link; a Welcome from a stranger waits for
the user; one from a blocked sender is declined without a word. A
Welcome for a group the client is in already is refused; one for a
group it left, was removed from or that broke replaces what was left of
the old membership.

**Invite links.** `/group invite` prints

```text
silver://group/<group id b58>?via=<admin id b58>&key=<link key b58>[&relay=<percent-encoded url>]
```

with `key = HMAC-SHA256(invite_key, "silver-messenger/v1/group-invite" || group id)[0..16]`,
so a link does not carry the invite key and a rotated invite key
(`/group link reset`, a `GroupContextExtensions` commit with a fresh
random `invite_key`) voids every link made before. Whoever presents the
link looks the named admin up as `/add` does, makes a fresh key package
for the purpose, and sends the admin a `join` body carrying it with

```text
join.proof = HMAC-SHA256(key, "silver-messenger/v1/group-join" || group id || joiner id)
```

The admin's client checks the proof against the group's current
`invite_key` in constant time, that it is an admin of an active group,
that the joiner is not blocked and not a member, and adds the joiner as
above; members see "X joined by link". The joiner's client remembers
which admin it asked for which group and takes that admin's Welcome as
the answer. A link names one admin; if that admin is gone the link is
dead and another admin makes a new one.

**Admins.** The creator is the first admin; `/group admin add|remove`
is a `GroupContextExtensions` commit changing `admins`. The last admin
cannot be removed and cannot leave a group that still has other members
without appointing another admin first.

**Rules every member checks** before merging a commit, against the
group context of the epoch the commit leaves:

* Add proposals, Remove proposals other than a member's own (13.9), and
  `GroupContextExtensions` proposals are accepted only in a commit whose
  committer is an admin.
* Every leaf added is valid (13.1).
* The ciphersuite is unchanged, and the required capabilities still list
  `0xF000` and `0xF001`.
* After the commit `admins` is not empty and lists only members, and
  the group has at most 256 members.
* A proposal sent on its own (by reference) is accepted only when it is
  a member's Remove of its own leaf; every other proposal, and every
  external-join proposal, is refused and not stored.

A commit that breaks a rule is not merged: the member marks the group
*broken*, names the committer, and stops sending and reading it. Every
honest client applies the same rules, so they all stop at the same
epoch while the sequencer, which cannot check policy, has moved on; a
rogue member can wedge a group but cannot get an intruder's keys
accepted. Recovery is a new group made by an admin with the honest
members. A message that cannot be processed at all (a replay MLS
refuses, an unreadable message from an epoch too far back) is reported
and dropped without changing anything.

### 13.8 Out of sync and rejoin

A member falls out of sync when it misses a commit for good (a full or
expired mailbox, a lost race whose winning commit never arrived). It
notices as in 13.6, marks the group out of sync, and sends a `rejoin`
body (a fresh key package) to every admin it knows of. An admin's client
checks the key package (13.1) against the member that sent it, that the
sender is a current member, and commits a Remove of that member's old
leaf and an Add of the new key package in one commit, sending the
Welcome as for an add. The member keeps its history; the messages
between are lost, and the client says so. `/group rejoin` sends the same
request on demand.

### 13.9 Leave and remove

* **Leave.** The member sends a Remove proposal for its own leaf, as a
  `handshake` body to every other member, marks the group left, stops
  reading it and deletes its MLS state. An admin's client that receives
  the proposal commits it at once (a self-update commit that carries the
  pending proposal); until one does, the leaver is still in the tree. A
  proposal is accepted by reference only from the leaf it removes. The
  last admin of a group with other members cannot leave; the last member
  leaving deletes the group.
* **Remove.** An admin's commit with the Remove. The removed member
  receives that commit, sees it was removed, keeps its history and
  deletes its MLS state; messages sent to the group after the commit are
  not addressed to it, and MLS keys of the new epoch are not derivable
  from what it held.
* Messages that reach a client for a group it left, was removed from or
  that broke are dropped without a word.

### 13.10 Sizes

Measured with OpenMLS 0.9 on the suite of 13.1 (TLS serialisation,
before the envelope). X-Wing public keys are 1216 bytes and its
ciphertexts 1120, which is what makes commits and Welcomes large:

| Object | Size | Path |
| --- | --- | --- |
| Key package | 2680 bytes (last resort 2683) | twenty on deposit is 52 KiB |
| Application message, 11 bytes of text | 156 bytes | envelope; the padded body is 320 bytes, the size of a one-to-one text |
| Application message, 100 bytes | 246 bytes | envelope, 480-byte padded body |
| Commit adding 2, and its Welcome (3 members) | 9.4 KiB, 9.6 KiB | envelope |
| Self-update commit with path, 3 members | 6.4 KiB | envelope |
| Commit adding 15, and its Welcome (16 members) | 46 KiB, 46 KiB | blob |
| Self-update commit with path, 16 members | 15.8 KiB | envelope |
| Commit adding 255, and its Welcome (256 members) | 695 KiB, 684 KiB | blob |
| Self-update commit with path, 256 members, young tree | 161 KiB | blob |

A text to a group of N costs the sender N envelopes of 320 to 480
bytes; a commit that goes through the blob store is uploaded once and
then costs N envelopes of about 500 bytes. The relay's per-recipient
quota is unchanged, so a very active group of 256 fills an absent
member's mailbox in about a thousand messages, after which that member
rejoins on return (13.8).
