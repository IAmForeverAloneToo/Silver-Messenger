# Silver Messenger protocol

This is the wire format and the cryptography as implemented on `main`. It
is written so that a second implementation could interoperate with this one
without reading the source; where the source and this document disagree,
the source is the bug. Byte encodings, domain strings and constants are
given exactly.

Two protocol versions coexist. **v1** is the sealed-envelope format of the
first release; **v2** adds prekeys and forward-secret sessions *inside* the
same envelope, so relays and v1 clients cannot tell the two apart from the
outside. A client speaks v2 to a peer that has published prekeys and v1 to
one that has not.

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
    "one_time": [ { "id": 456, "public": "<b64>" } ]
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
* On a `publish`, `one_time` lists every one-time key the client still
  holds (at most 200). On a `lookup_result` it holds at most one, chosen
  and then forgotten by the relay, and only for clients that themselves
  published prekeys on that connection.
* Prekey ids are 32-bit, non-zero, unique per user among live keys; this
  implementation picks them at random.

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
a plain body, 2 for a ratchet body. Other values are rejected.

### 4.1 Plain body (v1)

```json
{ "sent_at_ms": 1700000000000, "epoch": 8271, "seq": 12,
  "content": { "type": "text", "body": "hello" },
  "caps": ["receipts", "files"] }
```

`seq` counts messages from this sender to this recipient from 1; `epoch` is
a random 64-bit value fixed for one installation, so a reinstall (which
restarts `seq`) is distinguishable from a replay. `seq = 0` means the sender
does not number messages. `caps` (absent or empty on clients before 0.4.0)
is described in 4.3. `content.type` is one of `text`, `receipt` (4.4) and
`file` (4.5); unknown types are rejected by this implementation, which is
why a sender only uses the latter two towards peers that advertised them.

### 4.2 Ratchet body (v2)

```json
{ "v": 2,
  "session": "<b64 16 bytes>",
  "init": { "identity_dh": "<b64 IKdh_A>", "ephemeral": "<b64 EK_A>",
            "signed_prekey_id": 123, "one_time_prekey_id": 456 },   // optional
  "message": { "header": { "dh": "<b64>", "pn": 0, "n": 3 },
               "ciphertext": "<b64>" } }
```

`message.ciphertext` decrypts (section 6) to the bytes of a **plain body**
(4.1), so everything a v1 message carries, including `seq` and `epoch`, is
carried unchanged one layer deeper. `init` is present on every message the
initiator sends until it has received a message on the session; a responder
that already has the session ignores it.

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

### 4.4 Receipts

```json
{ "type": "receipt", "kind": "delivered", "ids": ["<envelope id>", "..."] }
```

`kind` is `delivered` (the messages with these ids were decrypted and
stored) or `read` (they were shown to the user); `read` implies
`delivered`. `ids` are envelope ids the recipient of the receipt sent. A
receipt is an ordinary body, numbered with `seq` like any other, and is
carried in a session when one exists. This implementation batches ids for
400 ms and sends one receipt per peer and kind, sends `delivered` for every
stored message and `read` only while the user has not turned read receipts
off, and never sends receipts to a sender it has not accepted as a
contact. Receipts from strangers are ignored.

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

## 5. Session establishment (X3DH)

`A` starts a session with `B` from `B`'s bundle, which must carry prekeys.

```
EK      = fresh X25519 key pair
DH1     = X25519(IKdh_A.secret, SPK_B)
DH2     = X25519(EK.secret,     IKdh_B)
DH3     = X25519(EK.secret,     SPK_B)
DH4     = X25519(EK.secret,     OPK_B)            only if the bundle carried one
SK      = HKDF-SHA256(salt = 32 zero bytes,
            ikm  = 0xFF * 32 || DH1 || DH2 || DH3 [|| DH4],
            info = "silver-messenger/v2/x3dh")     -> 32 bytes
AD      = IK_A.public || IKdh_A.public || IK_B.public || IKdh_B.public     (4 × 32 bytes)
session = SHA-256("silver-messenger/v2/session-id" || 0x00 || EK.public || SPK_B)[0..16]
```

`B` computes the same `DH1..DH4` with its private `SPK_B` and `OPK_B` (the
latter looked up by `one_time_prekey_id`, and deleted once the first
message decrypts), the same `SK`, `AD` and `session`. A header naming a
one-time key `B` no longer has, or a signed prekey it has rotated out, is
undecryptable; `B` keeps the previous signed prekey for three weeks after
rotating it. `EK` is discarded by `A` after deriving `SK`.

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

## 7. Relay wire protocol

Transport: one WebSocket per connection, path `/ws`, text frames, one JSON
object per frame with a `type` field in `snake_case`. The relay speaks
first.

### Client → relay

| `type` | Fields | Notes |
| --- | --- | --- |
| `auth` | `user_id`, `signature` | `signature = sign("silver-messenger/v1/relay-auth", nonce)` over the 32-byte challenge nonce. |
| `publish` | `bundle`, `invite`? | The client's own bundle (section 2). `invite` is a token for relays that only register invited identities. |
| `lookup` | `user_id` | |
| `send` | `envelope` | |
| `ack` | `id` | The envelope with this id was received and stored; the relay may drop it. |
| `blob_put` | `blob`, `index`, `total`, `data` (b64) | Store chunk `index` of `total` of blob `blob` (section 7.5). |
| `blob_get` | `blob` | Ask for every chunk of a blob. |
| `ping` | | |

### Relay → client

| `type` | Fields | Notes |
| --- | --- | --- |
| `challenge` | `nonce` (b64, 32 bytes) | First frame on every connection. |
| `auth_ok` | `user_id`, `features`? | `features` lists strings from section 7.3; absent on older relays. |
| `published` | | |
| `prekey_status` | `one_time_remaining`, `consumed`? | After `published`, only to clients whose bundle carried prekeys: how many one-time keys are on deposit and which ids were handed out since they were published. |
| `lookup_result` | `user_id`, `bundle` (or `null`) | |
| `sent` | `id` | The envelope is queued for delivery. |
| `rejected` | `id`, `code`, `message` | The envelope was not queued. `rate_limited` means try again later; any other code is final. |
| `deliver` | `envelope` | Delivered in mailbox order; acknowledge with `ack`. |
| `blob_ack` | `blob`, `index`, `complete` | The chunk is stored (or was already); `complete` once every chunk is. |
| `blob_rejected` | `blob`, `code`, `message` | A `blob_put` or `blob_get` for this blob failed. `rate_limited` means try again later; `not_found` on a `blob_get` means the blob is unknown, incomplete or expired. |
| `blob_chunk` | `blob`, `index`, `total`, `data` (b64) | One chunk in answer to `blob_get`; `total` says how many to expect. |
| `pong` | | |
| `error` | `code`, `message` | Answers a frame other than `send`, `blob_put` and `blob_get`, or reports a broken connection state. |

Error codes: `unauthenticated`, `bad_signature`, `malformed`, `too_large`,
`forbidden`, `mailbox_full`, `rate_limited`, `invite_required`,
`not_found`, `storage_full`, `internal`.

### 7.1 Authenticated connection

`challenge` → `auth` → `auth_ok`, then `publish` → `published`
[→ `prekey_status`]. The relay replays every queued `deliver` for the user
as soon as `auth` succeeds, so they may arrive before `published`. A newer
connection for the same user replaces the older one, which is closed.

On `publish` with prekeys the relay stores the signed prekey with the
bundle and the one-time keys separately. It keeps, per user, the ids it
has handed out; a handed-out id listed again is not stored again, and an
id no longer listed is forgotten on both sides. Clients top up when
`one_time_remaining` drops below their threshold (this implementation keeps
20 on deposit and tops up below 10).

On `lookup` from a connection that published prekeys, the relay removes one
one-time key from the target's deposit and attaches it to the result.
Lookups from other connections get the bundle with `one_time` empty.

### 7.2 Anonymous submission connection

On a relay advertising `anonymous_send`, a connection may answer the
`challenge` with a `send`, `blob_put` or `blob_get` frame instead of
`auth`. The connection then accepts only those three and `ping`, answered
as on an authenticated connection, under its own rate limits (30 `send`
and 600 chunks per minute by default). It never learns who the sender is.
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

A relay without the field is a v1 relay: it stores bundles as v1 (dropping
`prekeys`, since it re-serialises what it parsed), so clients behind it
speak v1 to everyone.

### 7.4 Limits and abuse controls

Per authenticated connection: 60 `send`, 30 `lookup` and 600 blob chunks
(`blob_put` or chunks answered to `blob_get`) per minute (token buckets of
that burst size). Per anonymous connection: 30 `send` and 600 chunks per
minute. Per recipient: 1000 queued envelopes or 32 MiB, whichever first;
unacknowledged envelopes expire after 30 days. Blobs: at most 16 MiB of
plaintext each (the relay allows 16 MiB plus the 256 chunk tags of
ciphertext), 1 GiB in total, and each expires 30 days after its first
chunk arrived, on the same schedule as messages. Relay operators can
change all of these and can require an invite token for first
registrations.

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

* **Choosing v1 or v2.** A client with a session store sends a ratchet body
  when the recipient's bundle carries prekeys, and a plain body otherwise.
  It must accept both kinds from anyone.
* **Starting a session.** A fresh lookup precedes the first message of a
  session, so the handshake uses a current signed prekey and a one-time key
  that has not been handed out before. A pinned bundle is used only when
  the relay cannot be reached.
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
* **Sequence numbers.** `seq`/`epoch` in the inner plain body are checked
  exactly as for v1 messages.
* **Capabilities.** A client records the `caps` of every message it
  accepts from a contact and sends `receipt` and `file` content only to
  contacts whose last list carried the capability. It advertises its own
  in every body it sends, receipts included.
* **Receipts.** Sent only to accepted contacts; batched for 400 ms; `read`
  only for messages shown while the window has focus, and only while the
  user allows it. Receipt bodies are not themselves acknowledged.
* **Files.** Sent only when the recipient advertised `files` and the relay
  advertises `blobs`. The upload finishes (every chunk acknowledged)
  before the `file` message is sent, so a recipient never asks for an
  incomplete blob. Up to four chunks are in flight; after a reconnect,
  chunks not yet acknowledged are put again. A recipient fetches a file
  as soon as the message is decrypted, but only from accepted contacts; a
  file announced by a stranger is shown with the request and fetched
  never, so acceptance later means asking the sender to send it again.
  Saved files never overwrite: a name already taken gets ` (2)`, ` (3)`
  and so on before the extension.

## 9. What the protocol does not do

Messages are signed, so they are not deniable. Sizes are not padded and
there is no cover traffic, so a relay or network observer sees message and
blob sizes and timing, including that a small message (a receipt) tends to
follow a delivery, and that a blob is fetched shortly after a message is
delivered. Group messaging is not defined yet.
