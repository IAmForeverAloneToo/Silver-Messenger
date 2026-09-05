//! The conformance harness: replays the published test vectors in
//! `docs/vectors/*.json` against this crate and fails on any difference.
//!
//! Every file is a list of cases, each with the `inputs` another
//! implementation would start from and the `outputs` it must arrive at.
//! Where the crate draws randomness, the vector fixes it: a seed for the
//! deterministic generator below, and the documented order in which each
//! operation consumes it. Alongside the crate's own output, the harness
//! re-derives the intermediate values by hand (each Diffie–Hellman output,
//! each KDF step, each AEAD input), so a mismatch points at the step that
//! moved and the vector files double as a worked example of the protocol.
//!
//! `SILVER_WRITE_VECTORS=1 cargo test -p silver-protocol --test vectors`
//! rewrites the files from the inputs fixed here. A vector that changes is
//! a wire change: see `docs/vectors/README.md`.

use std::fmt::Debug;
use std::path::PathBuf;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use silver_protocol::blob::{BlobKey, seal_chunk};
use silver_protocol::bundle::{BUNDLE_CAPS_DOMAIN, BUNDLE_DOMAIN, capability as bundle_capability};
use silver_protocol::encoding::{b64_array, b64_opt_array, from_base64, to_base64};
use silver_protocol::envelope::{
    Body, Content, ENVELOPE_DOMAIN, Envelope, RatchetBody, ReceiptKind, Sequence, capability,
    open_bytes, seal_bytes_unsigned_with_rng, seal_bytes_with_rng,
};
use silver_protocol::identity::IdentitySecrets;
use silver_protocol::lifecycle::{
    REVOCATION_DOMAIN, Revocation, SUCCESSION_ACCEPT_DOMAIN, SUCCESSION_DOMAIN, Succession,
};
use silver_protocol::pq::{KEM_SECRET_LEN, KemPublic, KemRatchetKey, PQ_PREKEY_DOMAIN};
use silver_protocol::prekey::{PrekeySecret, Prekeys, SIGNED_PREKEY_DOMAIN};
use silver_protocol::session::{InitHeader, RatchetHeader, RatchetMessage, Session, internals};
use silver_protocol::transparency::{
    EntryKind, LogEntry, LogHead, SUBJECT_DOMAIN, replay as replay_log, subject,
};
use silver_protocol::wire::{
    AUTH_BOUND_DOMAIN, AUTH_DOMAIN, auth_signature, auth_signature_bound, normalize_host,
};
use silver_protocol::{DhPublic, Identity, KeyBundle, PqPrekeySecret, UserId, safety_number};

// ---------------------------------------------------------------------------
// The generator the vectors fix randomness with

/// SHA-256 in counter mode: block `i` is `SHA-256(seed || i)` with `i` a
/// big-endian u64 from 0, and bytes are handed out from the blocks in order.
/// Not a generator for anything but vectors: it exists so the files depend
/// on nothing but SHA-256.
struct VectorRng {
    seed: [u8; 32],
    counter: u64,
    block: [u8; 32],
    used: usize,
}

impl VectorRng {
    fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            counter: 0,
            block: [0; 32],
            used: 32,
        }
    }

    fn draw<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        self.fill_bytes(&mut out);
        out
    }
}

impl RngCore for VectorRng {
    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes(self.draw())
    }

    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes(self.draw())
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            if self.used == 32 {
                let mut h = Sha256::new();
                h.update(self.seed);
                h.update(self.counter.to_be_bytes());
                self.block = h.finalize().into();
                self.counter += 1;
                self.used = 0;
            }
            *byte = self.block[self.used];
            self.used += 1;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for VectorRng {}

// ---------------------------------------------------------------------------
// The file format and the runner

#[derive(Serialize, Deserialize)]
struct File<I, O> {
    description: String,
    cases: Vec<Case<I, O>>,
}

#[derive(Serialize, Deserialize)]
struct Case<I, O> {
    name: String,
    inputs: I,
    outputs: O,
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/vectors")
}

/// Replay every case of `file`: in check mode, from the inputs the file
/// holds (which must be the ones fixed here), comparing the outputs; with
/// `SILVER_WRITE_VECTORS` set, rewrite the file from the inputs fixed here.
fn run<I, O>(file: &str, description: &str, cases: Vec<(&str, I)>, replay: impl Fn(&I) -> O)
where
    I: Serialize + DeserializeOwned + PartialEq + Debug,
    O: Serialize + DeserializeOwned,
{
    let path = vectors_dir().join(file);
    if std::env::var_os("SILVER_WRITE_VECTORS").is_some() {
        let file = File {
            description: description.to_owned(),
            cases: cases
                .into_iter()
                .map(|(name, inputs)| {
                    let outputs = replay(&inputs);
                    Case {
                        name: name.to_owned(),
                        inputs,
                        outputs,
                    }
                })
                .collect(),
        };
        let mut text = serde_json::to_string_pretty(&file).unwrap();
        text.push('\n');
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
        return;
    }
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let loaded: File<I, O> = serde_json::from_str(&text)
        .unwrap_or_else(|e| panic!("{file} does not parse: {e} (regenerate it?)"));
    assert_eq!(
        loaded.description, description,
        "{file}: description drifted"
    );
    assert_eq!(
        loaded
            .cases
            .iter()
            .map(|c| c.name.as_str())
            .collect::<Vec<_>>(),
        cases.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
        "{file}: the cases on file are not the ones the harness fixes"
    );
    for (case, (_, inputs)) in loaded.cases.iter().zip(&cases) {
        assert_eq!(
            &case.inputs, inputs,
            "{file}#{}: inputs on file drifted from the harness",
            case.name
        );
        let actual = serde_json::to_value(replay(&case.inputs)).unwrap();
        let expected = serde_json::to_value(&case.outputs).unwrap();
        if actual != expected {
            panic!(
                "{file}#{}: outputs differ\n--- on file ---\n{}\n--- computed ---\n{}\n",
                case.name,
                serde_json::to_string_pretty(&expected).unwrap(),
                serde_json::to_string_pretty(&actual).unwrap()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Shared pieces

/// Variable-length bytes, base64 in the files.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Bytes(Vec<u8>);

impl Serialize for Bytes {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&to_base64(&self.0))
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        from_base64(&s).map(Bytes).map_err(serde::de::Error::custom)
    }
}

/// An identity's two secrets.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct Seeds {
    #[serde(with = "b64_array")]
    signing_seed: [u8; 32],
    #[serde(with = "b64_array")]
    dh_secret: [u8; 32],
}

impl Seeds {
    fn identity(&self) -> Identity {
        Identity::from_secrets(&IdentitySecrets {
            signing_seed: self.signing_seed,
            dh_secret: self.dh_secret,
        })
    }
}

/// A classical prekey's secret.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct PrekeyIn {
    id: u32,
    #[serde(with = "b64_array")]
    secret: [u8; 32],
    created_at_ms: u64,
}

impl PrekeyIn {
    fn secret(&self) -> PrekeySecret {
        PrekeySecret::from_bytes(self.id, self.secret, self.created_at_ms)
    }
}

/// An ML-KEM prekey's seed.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct PqPrekeyIn {
    id: u32,
    #[serde(with = "b64_array")]
    seed: [u8; 64],
    created_at_ms: u64,
}

impl PqPrekeyIn {
    fn secret(&self) -> PqPrekeySecret {
        PqPrekeySecret::from_seed(self.id, self.seed, self.created_at_ms)
    }
}

/// Thirty-two fixed bytes from a label, so the inputs are readable here
/// and exact in the files.
fn label32(label: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"silver-messenger test vector: ");
    h.update(label.as_bytes());
    h.finalize().into()
}

fn label64(label: &str) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&label32(&format!("{label} (1)")));
    out[32..].copy_from_slice(&label32(&format!("{label} (2)")));
    out
}

fn seeds(who: &str) -> Seeds {
    Seeds {
        signing_seed: label32(&format!("{who} signing seed")),
        dh_secret: label32(&format!("{who} dh secret")),
    }
}

fn alice() -> Seeds {
    seeds("alice")
}

fn bob() -> Seeds {
    seeds("bob")
}

fn dh(secret: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    StaticSecret::from(*secret)
        .diffie_hellman(&PublicKey::from(*public))
        .to_bytes()
}

fn dh_public(secret: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

fn xchacha_encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    XChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .unwrap()
}

fn text(s: &str) -> Content {
    Content::Text { body: s.into() }
}

// ---------------------------------------------------------------------------
// identity.json

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct IdentityIn {
    #[serde(flatten)]
    seeds: Seeds,
    /// Another identity, for the safety number.
    peer: UserId,
}

#[derive(Serialize, Deserialize)]
struct IdentityOut {
    user_id: UserId,
    dh_public: DhPublic,
    /// The identity key's signature over `dh_public` (the key bundle's).
    #[serde(with = "b64_array")]
    bundle_signature: [u8; 64],
    safety_number: String,
}

#[test]
fn identity() {
    run(
        "identity.json",
        "An identity from its two secrets: the Ed25519 signing seed (whose \
         public key, base58, is the user id) and the X25519 secret; the \
         bundle signature over the X25519 public key under the key-bundle \
         domain; the safety number of the identity and a peer.",
        vec![
            (
                "alice",
                IdentityIn {
                    seeds: alice(),
                    peer: bob().identity().user_id(),
                },
            ),
            (
                "bob",
                IdentityIn {
                    seeds: bob(),
                    peer: alice().identity().user_id(),
                },
            ),
        ],
        |input| {
            let id = input.seeds.identity();
            let bundle = id.key_bundle();
            bundle.verify().unwrap();
            assert_eq!(bundle.dh_public.0, dh_public(&input.seeds.dh_secret));
            IdentityOut {
                user_id: id.user_id(),
                dh_public: id.dh_public(),
                bundle_signature: bundle.signature,
                safety_number: safety_number(&id.user_id(), &input.peer),
            }
        },
    );
}

// ---------------------------------------------------------------------------
// signatures.json

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum SignIn {
    SignedPrekey {
        signer: Seeds,
        #[serde(flatten)]
        prekey: PrekeyIn,
    },
    PqSignedPrekey {
        signer: Seeds,
        #[serde(flatten)]
        prekey: PqPrekeyIn,
    },
    BundleCaps {
        signer: Seeds,
        caps: Vec<String>,
    },
    Revocation {
        signer: Seeds,
        created_at_ms: u64,
    },
    Succession {
        old: Seeds,
        new: Seeds,
        created_at_ms: u64,
    },
    RelayAuth {
        signer: Seeds,
        #[serde(with = "b64_array")]
        nonce: [u8; 32],
    },
    RelayAuthBound {
        signer: Seeds,
        host: String,
        #[serde(with = "b64_array")]
        nonce: [u8; 32],
    },
}

/// Every signature is Ed25519 over `domain || 0x00 || message`.
#[derive(Serialize, Deserialize)]
struct Signed {
    domain: String,
    message: Bytes,
    #[serde(with = "b64_array")]
    signature: [u8; 64],
}

impl Signed {
    /// Check that `message` under `domain` is what `signer` signed, by
    /// verifying the library's signature against the hand-built message.
    fn checked(signer: &Identity, domain: &[u8], message: Vec<u8>, signature: [u8; 64]) -> Self {
        signer
            .user_id()
            .verify(domain, &message, &signature)
            .expect("the hand-built message is not what was signed");
        assert_eq!(signer.sign(domain, &message), signature);
        Self {
            domain: String::from_utf8(domain.to_vec()).unwrap(),
            message: Bytes(message),
            signature,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum SignOut {
    SignedPrekey {
        public: DhPublic,
        #[serde(flatten)]
        signed: Signed,
    },
    PqSignedPrekey {
        public: KemPublic,
        #[serde(flatten)]
        signed: Signed,
    },
    BundleCaps {
        #[serde(flatten)]
        signed: Signed,
    },
    Revocation {
        #[serde(flatten)]
        signed: Signed,
    },
    Succession {
        old: Signed,
        new: Signed,
    },
    RelayAuth {
        #[serde(flatten)]
        signed: Signed,
    },
    RelayAuthBound {
        normalized_host: String,
        #[serde(flatten)]
        signed: Signed,
    },
}

fn be32(n: u32) -> [u8; 4] {
    n.to_be_bytes()
}

fn be64(n: u64) -> [u8; 8] {
    n.to_be_bytes()
}

#[test]
fn signatures() {
    run(
        "signatures.json",
        "Every signed statement other than the key bundle and the envelope: \
         the exact bytes signed and the domain they are signed under, \
         Ed25519 over domain || 0x00 || message.",
        vec![
            (
                "signed_prekey",
                SignIn::SignedPrekey {
                    signer: bob(),
                    prekey: PrekeyIn {
                        id: 7,
                        secret: label32("bob signed prekey 7"),
                        created_at_ms: 1_700_000_000_000,
                    },
                },
            ),
            (
                "pq_signed_prekey",
                SignIn::PqSignedPrekey {
                    signer: bob(),
                    prekey: PqPrekeyIn {
                        id: 200,
                        seed: label64("bob pq prekey 200"),
                        created_at_ms: 1_700_000_000_000,
                    },
                },
            ),
            (
                "bundle_caps",
                SignIn::BundleCaps {
                    signer: bob(),
                    caps: vec![bundle_capability::PQ_RATCHET.to_owned()],
                },
            ),
            (
                "revocation",
                SignIn::Revocation {
                    signer: alice(),
                    created_at_ms: 1_700_000_001_000,
                },
            ),
            (
                "succession",
                SignIn::Succession {
                    old: alice(),
                    new: seeds("alice successor"),
                    created_at_ms: 1_700_000_002_000,
                },
            ),
            (
                "relay_auth_v1",
                SignIn::RelayAuth {
                    signer: alice(),
                    nonce: label32("relay nonce"),
                },
            ),
            (
                "relay_auth_bound",
                SignIn::RelayAuthBound {
                    signer: alice(),
                    host: "Relay.Example:8443".into(),
                    nonce: label32("relay nonce"),
                },
            ),
        ],
        |input| match input {
            SignIn::SignedPrekey { signer, prekey } => {
                let signer = signer.identity();
                let signed = prekey.secret().signed_by(&signer);
                signed.verify(&signer.user_id()).unwrap();
                let mut message = Vec::new();
                message.extend_from_slice(&be32(prekey.id));
                message.extend_from_slice(&signed.public.0);
                message.extend_from_slice(&be64(prekey.created_at_ms));
                SignOut::SignedPrekey {
                    public: signed.public,
                    signed: Signed::checked(
                        &signer,
                        SIGNED_PREKEY_DOMAIN,
                        message,
                        signed.signature,
                    ),
                }
            }
            SignIn::PqSignedPrekey { signer, prekey } => {
                let signer = signer.identity();
                let signed = prekey.secret().signed_by(&signer);
                signed.verify(&signer.user_id()).unwrap();
                let mut message = Vec::new();
                message.extend_from_slice(&be32(prekey.id));
                message.extend_from_slice(&signed.public.0);
                message.extend_from_slice(&be64(prekey.created_at_ms));
                SignOut::PqSignedPrekey {
                    public: signed.public.clone(),
                    signed: Signed::checked(&signer, PQ_PREKEY_DOMAIN, message, signed.signature),
                }
            }
            SignIn::BundleCaps { signer, caps } => {
                let signer = signer.identity();
                let bundle = signer.key_bundle().with_caps(&signer, caps.clone());
                bundle.verify().unwrap();
                let mut message = Vec::new();
                message.extend_from_slice(&bundle.dh_public.0);
                message.extend_from_slice(caps.join("\n").as_bytes());
                SignOut::BundleCaps {
                    signed: Signed::checked(
                        &signer,
                        BUNDLE_CAPS_DOMAIN,
                        message,
                        bundle.caps_signature.unwrap(),
                    ),
                }
            }
            SignIn::Revocation {
                signer,
                created_at_ms,
            } => {
                let signer = signer.identity();
                let rev = signer.revocation(*created_at_ms);
                rev.verify().unwrap();
                let mut message = Vec::new();
                message.extend_from_slice(signer.user_id().as_bytes());
                message.extend_from_slice(&be64(*created_at_ms));
                SignOut::Revocation {
                    signed: Signed::checked(&signer, REVOCATION_DOMAIN, message, rev.signature),
                }
            }
            SignIn::Succession {
                old,
                new,
                created_at_ms,
            } => {
                let (old, new) = (old.identity(), new.identity());
                let succ = old.succeed_to(&new, *created_at_ms);
                succ.verify().unwrap();
                let mut message = Vec::new();
                message.extend_from_slice(old.user_id().as_bytes());
                message.extend_from_slice(new.user_id().as_bytes());
                message.extend_from_slice(&be64(*created_at_ms));
                SignOut::Succession {
                    old: Signed::checked(
                        &old,
                        SUCCESSION_DOMAIN,
                        message.clone(),
                        succ.old_signature,
                    ),
                    new: Signed::checked(
                        &new,
                        SUCCESSION_ACCEPT_DOMAIN,
                        message,
                        succ.new_signature,
                    ),
                }
            }
            SignIn::RelayAuth { signer, nonce } => {
                let signer = signer.identity();
                SignOut::RelayAuth {
                    signed: Signed::checked(
                        &signer,
                        AUTH_DOMAIN,
                        nonce.to_vec(),
                        auth_signature(&signer, nonce),
                    ),
                }
            }
            SignIn::RelayAuthBound {
                signer,
                host,
                nonce,
            } => {
                let signer = signer.identity();
                let normalized_host = normalize_host(host);
                let mut message = normalized_host.clone().into_bytes();
                message.extend_from_slice(nonce);
                SignOut::RelayAuthBound {
                    normalized_host,
                    signed: Signed::checked(
                        &signer,
                        AUTH_BOUND_DOMAIN,
                        message,
                        auth_signature_bound(&signer, host, nonce),
                    ),
                }
            }
        },
    );
}

// ---------------------------------------------------------------------------
// kdf.json

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum KdfIn {
    SessionId {
        ephemeral: DhPublic,
        signed_prekey: DhPublic,
    },
    HandshakeSecret {
        #[serde(with = "b64_array")]
        dh1: [u8; 32],
        #[serde(with = "b64_array")]
        dh2: [u8; 32],
        #[serde(with = "b64_array")]
        dh3: [u8; 32],
        #[serde(default, with = "b64_opt_array")]
        dh4: Option<[u8; 32]>,
        #[serde(default, with = "b64_opt_array")]
        kem: Option<[u8; 32]>,
    },
    Root {
        #[serde(with = "b64_array")]
        root: [u8; 32],
        #[serde(with = "b64_array")]
        dh: [u8; 32],
        #[serde(default, with = "b64_opt_array")]
        kem: Option<[u8; 32]>,
        pq_ratchet: bool,
    },
    Chain {
        #[serde(with = "b64_array")]
        chain: [u8; 32],
    },
    MessageKey {
        #[serde(with = "b64_array")]
        message_key: [u8; 32],
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum KdfOut {
    SessionId {
        domain: String,
        #[serde(with = "b64_array")]
        id: [u8; 16],
    },
    HandshakeSecret {
        info: String,
        /// The HKDF input keying material: 32 bytes of 0xFF, the DH
        /// outputs, then the ML-KEM secret when there is one.
        ikm: Bytes,
        #[serde(with = "b64_array")]
        secret: [u8; 32],
    },
    Root {
        info: String,
        #[serde(with = "b64_array")]
        root: [u8; 32],
        #[serde(with = "b64_array")]
        chain: [u8; 32],
    },
    Chain {
        #[serde(with = "b64_array")]
        next: [u8; 32],
        #[serde(with = "b64_array")]
        message_key: [u8; 32],
    },
    MessageKey {
        info: String,
        #[serde(with = "b64_array")]
        key: [u8; 32],
        #[serde(with = "b64_array")]
        nonce: [u8; 24],
    },
}

fn utf8(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[test]
fn kdf() {
    let l = label32;
    run(
        "kdf.json",
        "The key derivations of a session, one at a time, over arbitrary \
         inputs: the session id, the handshake secret (classical and hybrid, \
         with and without a one-time prekey), the root KDF (v2, and v4 with \
         and without an ML-KEM secret), the chain KDF, and a message key's \
         AEAD key and nonce.",
        vec![
            (
                "session_id",
                KdfIn::SessionId {
                    ephemeral: DhPublic(dh_public(&l("ephemeral"))),
                    signed_prekey: DhPublic(dh_public(&l("signed prekey"))),
                },
            ),
            (
                "x3dh_v2_no_one_time",
                KdfIn::HandshakeSecret {
                    dh1: l("dh1"),
                    dh2: l("dh2"),
                    dh3: l("dh3"),
                    dh4: None,
                    kem: None,
                },
            ),
            (
                "x3dh_v2_one_time",
                KdfIn::HandshakeSecret {
                    dh1: l("dh1"),
                    dh2: l("dh2"),
                    dh3: l("dh3"),
                    dh4: Some(l("dh4")),
                    kem: None,
                },
            ),
            (
                "pqxdh_v3_no_one_time",
                KdfIn::HandshakeSecret {
                    dh1: l("dh1"),
                    dh2: l("dh2"),
                    dh3: l("dh3"),
                    dh4: None,
                    kem: Some(l("kem secret")),
                },
            ),
            (
                "pqxdh_v3_one_time",
                KdfIn::HandshakeSecret {
                    dh1: l("dh1"),
                    dh2: l("dh2"),
                    dh3: l("dh3"),
                    dh4: Some(l("dh4")),
                    kem: Some(l("kem secret")),
                },
            ),
            (
                "root_v2",
                KdfIn::Root {
                    root: l("root"),
                    dh: l("ratchet dh"),
                    kem: None,
                    pq_ratchet: false,
                },
            ),
            (
                "root_v4_dh_only",
                KdfIn::Root {
                    root: l("root"),
                    dh: l("ratchet dh"),
                    kem: None,
                    pq_ratchet: true,
                },
            ),
            (
                "root_v4_with_kem",
                KdfIn::Root {
                    root: l("root"),
                    dh: l("ratchet dh"),
                    kem: Some(l("ratchet kem")),
                    pq_ratchet: true,
                },
            ),
            ("chain", KdfIn::Chain { chain: l("chain") }),
            (
                "message_key",
                KdfIn::MessageKey {
                    message_key: l("message key"),
                },
            ),
        ],
        |input| match input {
            KdfIn::SessionId {
                ephemeral,
                signed_prekey,
            } => {
                let id = silver_protocol::session::session_id(ephemeral, signed_prekey);
                let mut h = Sha256::new();
                h.update(internals::SESSION_ID_DOMAIN);
                h.update([0u8]);
                h.update(ephemeral.0);
                h.update(signed_prekey.0);
                assert_eq!(&h.finalize()[..16], &id);
                KdfOut::SessionId {
                    domain: utf8(internals::SESSION_ID_DOMAIN),
                    id,
                }
            }
            KdfIn::HandshakeSecret {
                dh1,
                dh2,
                dh3,
                dh4,
                kem,
            } => {
                let secret = internals::x3dh_secret(dh1, dh2, dh3, dh4.as_ref(), kem.as_ref());
                let mut ikm = vec![0xFF; 32];
                for part in [Some(dh1), Some(dh2), Some(dh3), dh4.as_ref(), kem.as_ref()]
                    .into_iter()
                    .flatten()
                {
                    ikm.extend_from_slice(part);
                }
                let info = if kem.is_some() {
                    internals::PQXDH_INFO
                } else {
                    internals::X3DH_INFO
                };
                let mut by_hand = [0u8; 32];
                Hkdf::<Sha256>::new(Some(&[0u8; 32]), &ikm)
                    .expand(info, &mut by_hand)
                    .unwrap();
                assert_eq!(by_hand, secret);
                KdfOut::HandshakeSecret {
                    info: utf8(info),
                    ikm: Bytes(ikm),
                    secret,
                }
            }
            KdfIn::Root {
                root,
                dh,
                kem,
                pq_ratchet,
            } => {
                let (new_root, chain) = internals::kdf_root(root, dh, kem.as_ref(), *pq_ratchet);
                let info = if *pq_ratchet {
                    internals::ROOT_INFO_V4
                } else {
                    internals::ROOT_INFO
                };
                let mut ikm = dh.to_vec();
                if let Some(kem) = kem {
                    ikm.extend_from_slice(kem);
                }
                let mut out = [0u8; 64];
                Hkdf::<Sha256>::new(Some(root), &ikm)
                    .expand(info, &mut out)
                    .unwrap();
                assert_eq!(&out[..32], &new_root);
                assert_eq!(&out[32..], &chain);
                KdfOut::Root {
                    info: utf8(info),
                    root: new_root,
                    chain,
                }
            }
            KdfIn::Chain { chain } => {
                let (next, message_key) = internals::kdf_chain(chain);
                let hmac = |byte: u8| -> [u8; 32] {
                    use hmac::{Hmac, Mac};
                    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(chain).unwrap();
                    mac.update(&[byte]);
                    mac.finalize().into_bytes().into()
                };
                assert_eq!(hmac(0x02), next);
                assert_eq!(hmac(0x01), message_key);
                KdfOut::Chain { next, message_key }
            }
            KdfIn::MessageKey { message_key } => {
                let material = internals::message_key_material(message_key);
                let mut by_hand = [0u8; 56];
                Hkdf::<Sha256>::new(None, message_key)
                    .expand(internals::MESSAGE_INFO, &mut by_hand)
                    .unwrap();
                assert_eq!(by_hand, material);
                KdfOut::MessageKey {
                    info: utf8(internals::MESSAGE_INFO),
                    key: material[..32].try_into().unwrap(),
                    nonce: material[32..].try_into().unwrap(),
                }
            }
        },
    );
}

// ---------------------------------------------------------------------------
// handshake.json

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct HandshakeIn {
    alice: Seeds,
    bob: Seeds,
    bob_signed_prekey: PrekeyIn,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bob_one_time_prekey: Option<PrekeyIn>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bob_pq_signed_prekey: Option<PqPrekeyIn>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bob_pq_one_time_prekey: Option<PqPrekeyIn>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    bob_caps: Vec<String>,
    /// Seed of the generator Alice's `initiate` draws from.
    #[serde(with = "b64_array")]
    rng_seed: [u8; 32],
    /// Alice's first message.
    plaintext: Bytes,
}

impl HandshakeIn {
    /// Bob's bundle as a lookup serves it: with the one-time keys that
    /// were handed out.
    fn bundle(&self) -> KeyBundle {
        let bob = self.bob.identity();
        let prekeys = Prekeys {
            signed: self.bob_signed_prekey.secret().signed_by(&bob),
            one_time: self
                .bob_one_time_prekey
                .iter()
                .map(|k| k.secret().one_time())
                .collect(),
            pq_signed: self
                .bob_pq_signed_prekey
                .as_ref()
                .map(|k| k.secret().signed_by(&bob)),
            pq_one_time: self
                .bob_pq_one_time_prekey
                .iter()
                .map(|k| k.secret().signed_by(&bob))
                .collect(),
        };
        let bundle = bob.key_bundle_with(prekeys);
        if self.bob_caps.is_empty() {
            bundle
        } else {
            bundle.with_caps(&bob, self.bob_caps.clone())
        }
    }

    /// The ML-KEM key Alice encapsulates to: the one-time one if there is
    /// one, else the signed one.
    fn bob_pq_key(&self) -> Option<PqPrekeySecret> {
        self.bob_pq_one_time_prekey
            .as_ref()
            .or(self.bob_pq_signed_prekey.as_ref())
            .map(PqPrekeyIn::secret)
    }

    fn bob_responds(&self, init: &InitHeader, pq_ratchet: bool) -> Session {
        let signed = self.bob_signed_prekey.secret();
        let one_time = self.bob_one_time_prekey.as_ref().map(PrekeyIn::secret);
        let pq = init.pq_prekey_id.map(|id| {
            let key = self.bob_pq_key().unwrap();
            assert_eq!(key.id, id);
            key
        });
        Session::respond(
            &self.bob.identity(),
            &self.alice.identity().user_id(),
            &signed,
            one_time.as_ref(),
            pq.as_ref(),
            init,
            pq_ratchet,
        )
        .unwrap()
    }
}

/// What `initiate` drew from the generator, in order.
#[derive(Serialize, Deserialize)]
struct InitiateDraws {
    #[serde(with = "b64_array")]
    ephemeral_secret: [u8; 32],
    /// The 32 bytes FIPS 203 calls `m`, for the ML-KEM encapsulation.
    #[serde(
        default,
        with = "b64_opt_array",
        skip_serializing_if = "Option::is_none"
    )]
    kem_m: Option<[u8; 32]>,
    /// The seed (`d || z`) of Alice's first ML-KEM ratchet key.
    #[serde(
        default,
        with = "b64_opt_array",
        skip_serializing_if = "Option::is_none"
    )]
    kem_ratchet_seed: Option<[u8; 64]>,
    #[serde(with = "b64_array")]
    ratchet_secret: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct HandshakeOut {
    bob_bundle: KeyBundle,
    post_quantum: bool,
    pq_ratchet: bool,
    body_version: u32,
    draws: InitiateDraws,
    #[serde(with = "b64_array")]
    dh1: [u8; 32],
    #[serde(with = "b64_array")]
    dh2: [u8; 32],
    #[serde(with = "b64_array")]
    dh3: [u8; 32],
    #[serde(
        default,
        with = "b64_opt_array",
        skip_serializing_if = "Option::is_none"
    )]
    dh4: Option<[u8; 32]>,
    #[serde(
        default,
        with = "b64_opt_array",
        skip_serializing_if = "Option::is_none"
    )]
    kem_secret: Option<[u8; 32]>,
    #[serde(with = "b64_array")]
    handshake_secret: [u8; 32],
    /// The associated data both identities are bound with.
    ad: Bytes,
    #[serde(with = "b64_array")]
    session_id: [u8; 16],
    /// Alice's first ratchet step against Bob's signed prekey.
    #[serde(with = "b64_array")]
    ratchet_dh: [u8; 32],
    #[serde(with = "b64_array")]
    root_key: [u8; 32],
    #[serde(with = "b64_array")]
    chain_key: [u8; 32],
    #[serde(with = "b64_array")]
    message_key: [u8; 32],
    /// The AEAD's associated data for the first message: ad || session id
    /// || header bytes.
    aad: Bytes,
    init: InitHeader,
    message: RatchetMessage,
}

fn header_bytes(header: &RatchetHeader) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&header.dh.0);
    out.extend_from_slice(&be32(header.pn));
    out.extend_from_slice(&be32(header.n));
    if let Some(kem) = &header.kem {
        out.extend_from_slice(&kem.0);
    }
    if let Some(ct) = &header.kem_ct {
        out.extend_from_slice(ct);
    }
    out
}

fn handshake_cases() -> Vec<(&'static str, HandshakeIn)> {
    let base = HandshakeIn {
        alice: alice(),
        bob: bob(),
        bob_signed_prekey: PrekeyIn {
            id: 1,
            secret: label32("bob signed prekey 1"),
            created_at_ms: 1_700_000_000_000,
        },
        bob_one_time_prekey: Some(PrekeyIn {
            id: 100,
            secret: label32("bob one-time prekey 100"),
            created_at_ms: 1_700_000_000_000,
        }),
        bob_pq_signed_prekey: None,
        bob_pq_one_time_prekey: None,
        bob_caps: Vec::new(),
        rng_seed: label32("handshake rng"),
        plaintext: Bytes(b"hello, bob".to_vec()),
    };
    let pq_signed = Some(PqPrekeyIn {
        id: 200,
        seed: label64("bob pq prekey 200"),
        created_at_ms: 1_700_000_000_000,
    });
    let pq_one_time = Some(PqPrekeyIn {
        id: 300,
        seed: label64("bob pq one-time prekey 300"),
        created_at_ms: 1_700_000_000_000,
    });
    vec![
        ("v2_one_time", base.clone()),
        (
            "v2_signed_only",
            HandshakeIn {
                bob_one_time_prekey: None,
                ..base.clone()
            },
        ),
        (
            "v3_pqxdh",
            HandshakeIn {
                bob_pq_signed_prekey: pq_signed.clone(),
                bob_pq_one_time_prekey: pq_one_time.clone(),
                ..base.clone()
            },
        ),
        (
            "v4_pq_ratchet",
            HandshakeIn {
                bob_pq_signed_prekey: pq_signed.clone(),
                bob_pq_one_time_prekey: pq_one_time,
                bob_caps: vec![bundle_capability::PQ_RATCHET.to_owned()],
                ..base.clone()
            },
        ),
        (
            "v4_pq_ratchet_signed_keys_only",
            HandshakeIn {
                bob_one_time_prekey: None,
                bob_pq_signed_prekey: pq_signed,
                bob_pq_one_time_prekey: None,
                bob_caps: vec![bundle_capability::PQ_RATCHET.to_owned()],
                ..base
            },
        ),
    ]
}

fn replay_handshake(input: &HandshakeIn) -> HandshakeOut {
    let alice = input.alice.identity();
    let bob = input.bob.identity();
    let bundle = input.bundle();
    bundle.verify().unwrap();

    let (mut session, init) =
        Session::initiate_with_rng(&alice, &bundle, &mut VectorRng::new(input.rng_seed)).unwrap();
    let post_quantum = input.bob_pq_key().is_some();
    let pq_ratchet = post_quantum && !input.bob_caps.is_empty();
    assert_eq!(session.is_post_quantum(), post_quantum);
    assert_eq!(session.is_pq_ratchet(), pq_ratchet);
    let message = session.encrypt(&input.plaintext.0).unwrap();

    // By hand, from the same seed, in the documented order.
    let mut rng = VectorRng::new(input.rng_seed);
    let ephemeral_secret: [u8; 32] = rng.draw();
    let kem_m: Option<[u8; 32]> = post_quantum.then(|| rng.draw());
    let kem_ratchet_seed: Option<[u8; 64]> = pq_ratchet.then(|| rng.draw());
    let ratchet_secret: [u8; 32] = rng.draw();
    assert_eq!(init.ephemeral.0, dh_public(&ephemeral_secret));
    assert_eq!(init.identity_dh, alice.dh_public());
    assert_eq!(message.header.dh.0, dh_public(&ratchet_secret));

    let spk = input.bob_signed_prekey.secret().public().0;
    let dh1 = dh(&input.alice.dh_secret, &spk);
    let dh2 = dh(&ephemeral_secret, &bob.dh_public().0);
    let dh3 = dh(&ephemeral_secret, &spk);
    let dh4 = input
        .bob_one_time_prekey
        .as_ref()
        .map(|k| dh(&ephemeral_secret, &k.secret().public().0));
    let kem_secret: Option<[u8; KEM_SECRET_LEN]> = match (&kem_m, input.bob_pq_key()) {
        (Some(m), Some(key)) => {
            let (ciphertext, secret) = key.public().encapsulate_deterministic(m).unwrap();
            assert_eq!(init.kem_ciphertext.as_deref(), Some(ciphertext.as_slice()));
            assert_eq!(init.pq_prekey_id, Some(key.id));
            assert_eq!(*key.decapsulate(&ciphertext).unwrap(), *secret);
            Some(*secret)
        }
        _ => None,
    };
    let handshake_secret =
        internals::x3dh_secret(&dh1, &dh2, &dh3, dh4.as_ref(), kem_secret.as_ref());
    let mut ad = Vec::new();
    ad.extend_from_slice(alice.user_id().as_bytes());
    ad.extend_from_slice(&alice.dh_public().0);
    ad.extend_from_slice(bob.user_id().as_bytes());
    ad.extend_from_slice(&bob.dh_public().0);
    let session_id = silver_protocol::session::session_id(&init.ephemeral, &DhPublic(spk));
    assert_eq!(session.id(), &session_id);

    let ratchet_dh = dh(&ratchet_secret, &spk);
    let (root_key, chain_key) =
        internals::kdf_root(&handshake_secret, &ratchet_dh, None, pq_ratchet);
    let (_, message_key) = internals::kdf_chain(&chain_key);
    assert_eq!(message.header.pn, 0);
    assert_eq!(message.header.n, 0);
    assert_eq!(message.header.kem_ct, None);
    assert_eq!(
        message.header.kem,
        kem_ratchet_seed.map(|seed| KemRatchetKey::from_seed(seed).public())
    );
    let mut aad = ad.clone();
    aad.extend_from_slice(&session_id);
    aad.extend_from_slice(&header_bytes(&message.header));
    let material = internals::message_key_material(&message_key);
    assert_eq!(
        xchacha_encrypt(&material[..32], &material[32..], &input.plaintext.0, &aad),
        message.ciphertext
    );

    // The key-binding signature exactly when the body is v4.
    assert_eq!(init.identity_dh_signature.is_some(), pq_ratchet);
    if let Some(signature) = &init.identity_dh_signature {
        alice
            .user_id()
            .verify(BUNDLE_DOMAIN, &init.identity_dh.0, signature)
            .unwrap();
        assert_eq!(*signature, bundle_signature(&alice));
    }

    // Bob gets the same session.
    let mut bob_session = input.bob_responds(&init, pq_ratchet);
    assert_eq!(bob_session.id(), &session_id);
    assert_eq!(*bob_session.decrypt(&message).unwrap(), input.plaintext.0);

    HandshakeOut {
        bob_bundle: bundle,
        post_quantum,
        pq_ratchet,
        body_version: session.body_version(),
        draws: InitiateDraws {
            ephemeral_secret,
            kem_m,
            kem_ratchet_seed,
            ratchet_secret,
        },
        dh1,
        dh2,
        dh3,
        dh4,
        kem_secret,
        handshake_secret,
        ad: Bytes(ad),
        session_id,
        ratchet_dh,
        root_key,
        chain_key,
        message_key,
        aad: Bytes(aad),
        init,
        message,
    }
}

fn bundle_signature(id: &Identity) -> [u8; 64] {
    id.key_bundle().signature
}

#[test]
fn handshake() {
    run(
        "handshake.json",
        "The handshake from fixed keys and a fixed generator seed: Bob's \
         bundle as served, what Alice's initiate draws and in what order, \
         every Diffie–Hellman output, the ML-KEM secret, the handshake \
         secret, the first root and chain keys, the InitHeader and Alice's \
         first message. Classical (v2), hybrid handshake with the classical \
         ratchet (v3), and the post-quantum ratchet (v4).",
        handshake_cases(),
        replay_handshake,
    );
}

// ---------------------------------------------------------------------------
// ratchet.json

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Side {
    Alice,
    Bob,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Step {
    /// `from` encrypts `plaintext`; the message gets the next index.
    Send { from: Side, plaintext: Bytes },
    /// `by` decrypts message `index`, drawing from a generator seeded with
    /// `rng_seed` if the message starts a new ratchet chain.
    Receive {
        by: Side,
        index: usize,
        #[serde(with = "b64_array")]
        rng_seed: [u8; 32],
    },
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct RatchetIn {
    handshake: HandshakeIn,
    schedule: Vec<Step>,
}

#[derive(Serialize, Deserialize)]
struct SentMessage {
    index: usize,
    from: Side,
    #[serde(flatten)]
    message: RatchetMessage,
}

/// What a ratchet step drew from the generator, in order.
#[derive(Serialize, Deserialize)]
struct StepDraws {
    index: usize,
    by: Side,
    #[serde(with = "b64_array")]
    dh_secret: [u8; 32],
    #[serde(
        default,
        with = "b64_opt_array",
        skip_serializing_if = "Option::is_none"
    )]
    kem_ratchet_seed: Option<[u8; 64]>,
    #[serde(
        default,
        with = "b64_opt_array",
        skip_serializing_if = "Option::is_none"
    )]
    kem_m: Option<[u8; 32]>,
}

#[derive(Serialize, Deserialize)]
struct RatchetOut {
    init: InitHeader,
    messages: Vec<SentMessage>,
    /// One per `receive` that started a new chain.
    ratchet_steps: Vec<StepDraws>,
}

fn ratchet_schedule() -> Vec<Step> {
    let send = |from: Side, text: &str| Step::Send {
        from,
        plaintext: Bytes(text.as_bytes().to_vec()),
    };
    let receive = |by: Side, index: usize| Step::Receive {
        by,
        index,
        rng_seed: label32(&format!("receive {index}")),
    };
    // Messages are numbered in the order they are sent: 1 a1, 2 a2, 3 b1,
    // 4 b2, 5 a3, 6 a4, 7 b3.
    vec![
        send(Side::Alice, "a1"),
        send(Side::Alice, "a2"),
        // Bob's first read: a ratchet step, his sending chain starts.
        receive(Side::Bob, 1),
        send(Side::Bob, "b1"),
        send(Side::Bob, "b2"),
        // Alice's turn: a ratchet step.
        receive(Side::Alice, 3),
        send(Side::Alice, "a3"),
        // Late messages from old chains: no step, no skip.
        receive(Side::Bob, 2),
        receive(Side::Alice, 4),
        send(Side::Alice, "a4"),
        // Out of order within the new chain: a4 before a3 leaves a
        // skipped key that a3 then uses.
        receive(Side::Bob, 6),
        receive(Side::Bob, 5),
        send(Side::Bob, "b3"),
        receive(Side::Alice, 7),
    ]
}

fn replay_ratchet(input: &RatchetIn) -> RatchetOut {
    let h = &input.handshake;
    let alice = h.alice.identity();
    let bundle = h.bundle();
    let (mut a, init) =
        Session::initiate_with_rng(&alice, &bundle, &mut VectorRng::new(h.rng_seed)).unwrap();
    let pq_ratchet = a.is_pq_ratchet();
    let mut b = h.bob_responds(&init, pq_ratchet);

    let mut messages: Vec<SentMessage> = Vec::new();
    let mut plaintexts: Vec<Vec<u8>> = Vec::new();
    let mut ratchet_steps = Vec::new();
    for step in &input.schedule {
        match step {
            Step::Send { from, plaintext } => {
                let session = match from {
                    Side::Alice => &mut a,
                    Side::Bob => &mut b,
                };
                let message = session.encrypt(&plaintext.0).unwrap();
                plaintexts.push(plaintext.0.clone());
                messages.push(SentMessage {
                    index: messages.len() + 1,
                    from: *from,
                    message,
                });
            }
            Step::Receive {
                by,
                index,
                rng_seed,
            } => {
                let sent = &messages[index - 1];
                assert_ne!(sent.from, *by, "a side cannot receive its own message");
                let session = match by {
                    Side::Alice => &mut a,
                    Side::Bob => &mut b,
                };
                let before = session.clone();
                let plaintext = session
                    .decrypt_with_rng(&sent.message, &mut VectorRng::new(*rng_seed))
                    .unwrap();
                assert_eq!(*plaintext, plaintexts[index - 1]);
                // A new chain: the next message from `by` carries the key
                // the step drew, so the draws can be checked by hand.
                if starts_new_chain(&before, &sent.message) {
                    let mut rng = VectorRng::new(*rng_seed);
                    let dh_secret: [u8; 32] = rng.draw();
                    let kem_ratchet_seed: Option<[u8; 64]> = pq_ratchet.then(|| rng.draw());
                    let kem_m: Option<[u8; 32]> =
                        (pq_ratchet && sent.message.header.kem.is_some()).then(|| rng.draw());
                    let probe = session.clone().encrypt(b"").unwrap();
                    assert_eq!(probe.header.dh.0, dh_public(&dh_secret));
                    assert_eq!(
                        probe.header.kem,
                        kem_ratchet_seed.map(|seed| KemRatchetKey::from_seed(seed).public())
                    );
                    if let (Some(m), Some(peer)) = (&kem_m, &sent.message.header.kem) {
                        let (ciphertext, _) = peer.encapsulate_deterministic(m).unwrap();
                        assert_eq!(probe.header.kem_ct, Some(ciphertext));
                    } else {
                        assert_eq!(probe.header.kem_ct, None);
                    }
                    ratchet_steps.push(StepDraws {
                        index: *index,
                        by: *by,
                        dh_secret,
                        kem_ratchet_seed,
                        kem_m,
                    });
                }
            }
        }
    }
    RatchetOut {
        init,
        messages,
        ratchet_steps,
    }
}

/// Whether `message` moves `session` to a new ratchet chain: its key is
/// not the one the session last received under. Judged from the outside,
/// the way the harness must: by probing what the session would send.
fn starts_new_chain(before: &Session, message: &RatchetMessage) -> bool {
    let mut trial = before.clone();
    // A responder that has not received yet cannot send; every first read
    // is a step. Otherwise compare the sending key before and after.
    if !trial.can_send() {
        return true;
    }
    let was = trial.clone().encrypt(b"").unwrap().header.dh;
    trial.decrypt(message).unwrap();
    trial.encrypt(b"").unwrap().header.dh != was
}

#[test]
fn ratchet() {
    let handshakes = handshake_cases();
    let pick = |name: &str| {
        handshakes
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, h)| h.clone())
            .unwrap()
    };
    run(
        "ratchet.json",
        "Two round trips of the Double Ratchet from the handshake vectors, \
         with late and out-of-order delivery: every message's header and \
         ciphertext, and what each ratchet step drew from its generator. \
         The classical ratchet (v2) and the post-quantum one (v4), whose \
         steps carry an ML-KEM key and ciphertext.",
        vec![
            (
                "v2",
                RatchetIn {
                    handshake: pick("v2_one_time"),
                    schedule: ratchet_schedule(),
                },
            ),
            (
                "v4_pq_ratchet",
                RatchetIn {
                    handshake: pick("v4_pq_ratchet"),
                    schedule: ratchet_schedule(),
                },
            ),
        ],
        replay_ratchet,
    );
}

// ---------------------------------------------------------------------------
// envelope.json

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct EnvelopeIn {
    sender: Seeds,
    recipient: Seeds,
    /// The encoded body (see body.json).
    body: Bytes,
    /// Whether the sealed layer is signed (v1/v2/v3) or deniable (v4).
    signed: bool,
    #[serde(with = "b64_array")]
    rng_seed: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct SealDraws {
    #[serde(with = "b64_array")]
    ephemeral_secret: [u8; 32],
    #[serde(with = "b64_array")]
    nonce: [u8; 24],
    /// The 16 bytes the envelope id (a version-4 UUID) is made from.
    #[serde(with = "b64_array")]
    id_bytes: [u8; 16],
}

#[derive(Serialize, Deserialize)]
struct EnvelopeOut {
    draws: SealDraws,
    #[serde(with = "b64_array")]
    shared: [u8; 32],
    kdf_info: Bytes,
    #[serde(with = "b64_array")]
    key: [u8; 32],
    aad: Bytes,
    signature_domain: String,
    /// What the sender signs: recipient id || ephemeral || nonce || body.
    signed_bytes: Bytes,
    /// Zero for a deniable body.
    #[serde(with = "b64_array")]
    signature: [u8; 64],
    /// sender id || signature || body.
    plaintext: Bytes,
    envelope: Envelope,
    opened_from: UserId,
    opened_signed: bool,
}

const ENVELOPE_KDF_INFO: &[u8] = b"silver-messenger/v1/xchacha20poly1305";

fn replay_envelope(input: &EnvelopeIn) -> EnvelopeOut {
    let sender = input.sender.identity();
    let recipient = input.recipient.identity();
    let bundle = recipient.key_bundle();
    let mut rng = VectorRng::new(input.rng_seed);
    let envelope = if input.signed {
        seal_bytes_with_rng(&sender, &bundle, &input.body.0, &mut rng)
    } else {
        seal_bytes_unsigned_with_rng(&sender, &bundle, &input.body.0, &mut rng)
    }
    .unwrap();

    let mut rng = VectorRng::new(input.rng_seed);
    let ephemeral_secret: [u8; 32] = rng.draw();
    let nonce: [u8; 24] = rng.draw();
    let id_bytes: [u8; 16] = rng.draw();
    let ephemeral_public = dh_public(&ephemeral_secret);
    assert_eq!(envelope.ephemeral_public.0, ephemeral_public);
    assert_eq!(envelope.nonce, nonce);
    assert_eq!(
        envelope.id,
        uuid::Builder::from_random_bytes(id_bytes)
            .into_uuid()
            .to_string()
    );
    assert_eq!(envelope.to, recipient.user_id());

    let shared = dh(&ephemeral_secret, &recipient.dh_public().0);
    let mut kdf_info = ENVELOPE_KDF_INFO.to_vec();
    kdf_info.extend_from_slice(&ephemeral_public);
    kdf_info.extend_from_slice(&recipient.dh_public().0);
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, &shared)
        .expand(&kdf_info, &mut key)
        .unwrap();
    let mut aad = recipient.user_id().as_bytes().to_vec();
    aad.extend_from_slice(&ephemeral_public);
    let mut signed_bytes = recipient.user_id().as_bytes().to_vec();
    signed_bytes.extend_from_slice(&ephemeral_public);
    signed_bytes.extend_from_slice(&nonce);
    signed_bytes.extend_from_slice(&input.body.0);
    let signature = if input.signed {
        sender.sign(ENVELOPE_DOMAIN, &signed_bytes)
    } else {
        [0u8; 64]
    };
    let mut plaintext = sender.user_id().as_bytes().to_vec();
    plaintext.extend_from_slice(&signature);
    plaintext.extend_from_slice(&input.body.0);
    assert_eq!(
        xchacha_encrypt(&key, &nonce, &plaintext, &aad),
        envelope.ciphertext
    );

    let opened = open_bytes(&recipient, &envelope).unwrap();
    assert_eq!(opened.from, sender.user_id());
    assert_eq!(opened.signed, input.signed);
    assert_eq!(*opened.body, input.body.0);

    EnvelopeOut {
        draws: SealDraws {
            ephemeral_secret,
            nonce,
            id_bytes,
        },
        shared,
        kdf_info: Bytes(kdf_info),
        key,
        aad: Bytes(aad),
        signature_domain: utf8(ENVELOPE_DOMAIN),
        signed_bytes: Bytes(signed_bytes),
        signature,
        plaintext: Bytes(plaintext),
        envelope,
        opened_from: opened.from,
        opened_signed: opened.signed,
    }
}

/// A v4 ratchet body with fixed, meaningless contents: the sealed layer
/// only reads its version.
fn opaque_v4_body() -> Vec<u8> {
    Body::Ratchet(RatchetBody {
        v: 4,
        session: label32("session")[..16].try_into().unwrap(),
        init: None,
        message: RatchetMessage {
            header: RatchetHeader {
                dh: DhPublic(dh_public(&label32("ratchet key"))),
                pn: 0,
                n: 3,
                kem: None,
                kem_ct: None,
            },
            ciphertext: label32("ciphertext").to_vec(),
        },
    })
    .encode()
    .unwrap()
}

#[test]
fn envelope() {
    run(
        "envelope.json",
        "The sealed-sender layer from fixed keys and a fixed generator seed: \
         what seal draws and in what order, the shared secret, the HKDF \
         info and key, the associated data, the bytes signed, the plaintext \
         layout and the envelope. A signed v1 body and a deniable v4 body.",
        vec![
            (
                "v1_signed",
                EnvelopeIn {
                    sender: alice(),
                    recipient: bob(),
                    body: Bytes(
                        Body::plain(text("hello, bob"), 1_700_000_000_000, Sequence::default())
                            .encode()
                            .unwrap(),
                    ),
                    signed: true,
                    rng_seed: label32("envelope rng"),
                },
            ),
            (
                "v4_deniable",
                EnvelopeIn {
                    sender: alice(),
                    recipient: bob(),
                    body: Bytes(opaque_v4_body()),
                    signed: false,
                    rng_seed: label32("envelope rng"),
                },
            ),
        ],
        replay_envelope,
    );
}

// ---------------------------------------------------------------------------
// body.json

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum BodyIn {
    Plain {
        content: Content,
        sent_at_ms: u64,
        epoch: u64,
        seq: u64,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        caps: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        head: Option<LogHead>,
    },
    Ratchet(RatchetBody),
}

#[derive(Serialize, Deserialize)]
struct BodyOut {
    /// The padded encoding, as text: JSON followed by spaces to a multiple
    /// of 160 bytes.
    encoded: String,
    encoded_len: usize,
}

#[test]
fn body() {
    let plain = |content: Content, caps: Vec<&str>, head: Option<LogHead>| BodyIn::Plain {
        content,
        sent_at_ms: 1_700_000_000_000,
        epoch: 0x0123_4567_89ab_cdef,
        seq: 42,
        caps: caps.into_iter().map(str::to_owned).collect(),
        head,
    };
    let alice_id = alice().identity();
    let (a, init) = Session::initiate_with_rng(
        &alice_id,
        &handshake_cases()[0].1.bundle(),
        &mut VectorRng::new(label32("body handshake rng")),
    )
    .unwrap();
    let mut a = a;
    let first = a.encrypt(b"first").unwrap();
    let head = LogHead {
        index: 12,
        hash: label32("log head"),
    };
    run(
        "body.json",
        "Bodies as encoded before sealing: JSON in the field order given, \
         padded with spaces to a multiple of 160 bytes. Plain (v1) bodies \
         for each content kind, and ratchet bodies (v2, with and without \
         the InitHeader).",
        vec![
            ("text", plain(text("hello"), vec![], None)),
            (
                "text_with_caps_and_head",
                plain(
                    text("hello"),
                    vec![
                        capability::RECEIPTS,
                        capability::FILES,
                        capability::PADDED_FILES,
                        capability::LIFECYCLE,
                    ],
                    Some(head),
                ),
            ),
            (
                "receipt",
                plain(
                    Content::Receipt {
                        kind: ReceiptKind::Read,
                        ids: vec![
                            "0f0e0d0c-0b0a-4908-8706-050403020100".into(),
                            "00000000-0000-4000-8000-000000000001".into(),
                        ],
                    },
                    vec![],
                    None,
                ),
            ),
            (
                "file",
                plain(
                    Content::File {
                        name: "notes.txt".into(),
                        size: 70_000,
                        blob: "00112233445566778899aabbccddeeff".into(),
                        key: BlobKey::from_parts(
                            label32("blob key"),
                            label32("blob nonce")[..24].try_into().unwrap(),
                        ),
                        chunks: 2,
                        sha256: label32("file hash"),
                    },
                    vec![],
                    None,
                ),
            ),
            (
                "revocation",
                plain(
                    Content::Revocation(alice_id.revocation(1_700_000_001_000)),
                    vec![],
                    None,
                ),
            ),
            (
                "succession",
                plain(
                    Content::Succession(
                        alice_id
                            .succeed_to(&seeds("alice successor").identity(), 1_700_000_002_000),
                    ),
                    vec![],
                    None,
                ),
            ),
            (
                "ratchet_v2_with_init",
                BodyIn::Ratchet(RatchetBody {
                    v: 2,
                    session: *a.id(),
                    init: Some(init.clone()),
                    message: first.clone(),
                }),
            ),
            (
                "ratchet_v2",
                BodyIn::Ratchet(RatchetBody {
                    v: 2,
                    session: *a.id(),
                    init: None,
                    message: first,
                }),
            ),
        ],
        |input| {
            let body = match input {
                BodyIn::Plain {
                    content,
                    sent_at_ms,
                    epoch,
                    seq,
                    caps,
                    head,
                } => Body::plain_with_caps_and_head(
                    content.clone(),
                    *sent_at_ms,
                    Sequence {
                        epoch: *epoch,
                        seq: *seq,
                    },
                    &caps.iter().map(String::as_str).collect::<Vec<_>>(),
                    *head,
                ),
                BodyIn::Ratchet(body) => Body::Ratchet(body.clone()),
            };
            let encoded = body.encode().unwrap();
            assert_eq!(encoded.len() % 160, 0);
            // Decoding gives the same body back.
            match (Body::decode(&encoded).unwrap(), input) {
                (
                    Body::Plain {
                        sent_at_ms,
                        sequence,
                        content,
                        caps,
                        head,
                    },
                    BodyIn::Plain {
                        content: c,
                        sent_at_ms: t,
                        epoch,
                        seq,
                        caps: cs,
                        head: h,
                    },
                ) => {
                    assert_eq!(
                        (sent_at_ms, sequence.epoch, sequence.seq),
                        (*t, *epoch, *seq)
                    );
                    assert_eq!((&content, &caps, &head), (c, cs, h));
                }
                (Body::Ratchet(decoded), BodyIn::Ratchet(body)) => assert_eq!(&decoded, body),
                _ => panic!("decoded as the other kind"),
            }
            BodyOut {
                encoded_len: encoded.len(),
                encoded: String::from_utf8(encoded).unwrap(),
            }
        },
    );
}

// ---------------------------------------------------------------------------
// transparency.json

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct EntryIn {
    #[serde(with = "b64_array")]
    subject: [u8; 32],
    kind: EntryKind,
    #[serde(with = "b64_array")]
    leaf: [u8; 32],
    at_ms: u64,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum TransparencyIn {
    Subject { user_id: UserId },
    BundleLeaf { bundle: Box<KeyBundle> },
    RevocationLeaf { revocation: Revocation },
    SuccessionLeaf { succession: Succession },
    Chain { entries: Vec<EntryIn> },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum TransparencyOut {
    Subject {
        domain: String,
        #[serde(with = "b64_array")]
        subject: [u8; 32],
    },
    BundleLeaf {
        /// The bytes hashed after the domain, in the fixed layout.
        preimage: Bytes,
        #[serde(with = "b64_array")]
        leaf: [u8; 32],
    },
    RevocationLeaf {
        #[serde(with = "b64_array")]
        leaf: [u8; 32],
    },
    SuccessionLeaf {
        #[serde(with = "b64_array")]
        leaf: [u8; 32],
    },
    Chain {
        entries: Vec<LogEntry>,
        #[serde(rename = "entry_hashes")]
        hashes: Vec<Bytes>,
        heads: Vec<LogHead>,
    },
}

/// The bundle leaf's preimage, by hand, in the layout section 11 gives.
fn bundle_leaf_preimage(bundle: &KeyBundle) -> Vec<u8> {
    let mut v = Vec::new();
    let put_var = |v: &mut Vec<u8>, bytes: &[u8]| {
        v.extend_from_slice(&be32(bytes.len() as u32));
        v.extend_from_slice(bytes);
    };
    v.extend_from_slice(bundle.user_id.as_bytes());
    v.extend_from_slice(&bundle.dh_public.0);
    v.extend_from_slice(&bundle.signature);
    match &bundle.prekeys {
        None => v.push(0),
        Some(prekeys) => {
            v.push(1);
            v.extend_from_slice(&be32(prekeys.signed.id));
            v.extend_from_slice(&prekeys.signed.public.0);
            v.extend_from_slice(&be64(prekeys.signed.created_at_ms));
            v.extend_from_slice(&prekeys.signed.signature);
            match &prekeys.pq_signed {
                None => v.push(0),
                Some(pq) => {
                    v.push(1);
                    v.extend_from_slice(&be32(pq.id));
                    put_var(&mut v, &pq.public.0);
                    v.extend_from_slice(&be64(pq.created_at_ms));
                    v.extend_from_slice(&pq.signature);
                }
            }
        }
    }
    v.extend_from_slice(&be32(bundle.caps.len() as u32));
    for cap in &bundle.caps {
        put_var(&mut v, cap.as_bytes());
    }
    match &bundle.caps_signature {
        None => v.push(0),
        Some(signature) => {
            v.push(1);
            v.extend_from_slice(signature);
        }
    }
    v
}

fn sha256_with_domain(domain: &[u8], preimage: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(preimage);
    h.finalize().into()
}

#[test]
fn transparency() {
    let alice_id = alice().identity();
    let handshakes = handshake_cases();
    let v4_bundle = handshakes
        .iter()
        .find(|(n, _)| *n == "v4_pq_ratchet")
        .unwrap()
        .1
        .bundle();
    let v2_bundle = handshakes[0].1.bundle();
    run(
        "transparency.json",
        "The transparency log's hashes: the subject an identity's entries \
         are filed under, the leaf of a bundle (one-time prekeys excluded) \
         and of each statement, and a three-entry chain with the hash and \
         head after each entry.",
        vec![
            (
                "subject",
                TransparencyIn::Subject {
                    user_id: alice_id.user_id(),
                },
            ),
            (
                "bundle_leaf_v1",
                TransparencyIn::BundleLeaf {
                    bundle: Box::new(alice_id.key_bundle()),
                },
            ),
            (
                "bundle_leaf_v2_prekeys",
                TransparencyIn::BundleLeaf {
                    bundle: Box::new(v2_bundle),
                },
            ),
            (
                "bundle_leaf_v4_pq_and_caps",
                TransparencyIn::BundleLeaf {
                    bundle: Box::new(v4_bundle),
                },
            ),
            (
                "revocation_leaf",
                TransparencyIn::RevocationLeaf {
                    revocation: alice_id.revocation(1_700_000_001_000),
                },
            ),
            (
                "succession_leaf",
                TransparencyIn::SuccessionLeaf {
                    succession: alice_id
                        .succeed_to(&seeds("alice successor").identity(), 1_700_000_002_000),
                },
            ),
            (
                "chain",
                TransparencyIn::Chain {
                    entries: vec![
                        EntryIn {
                            subject: subject(&alice_id.user_id()),
                            kind: EntryKind::Bundle,
                            leaf: label32("leaf 1"),
                            at_ms: 1_700_000_000_000,
                        },
                        EntryIn {
                            subject: subject(&bob().identity().user_id()),
                            kind: EntryKind::Bundle,
                            leaf: label32("leaf 2"),
                            at_ms: 1_700_000_000_500,
                        },
                        EntryIn {
                            subject: subject(&alice_id.user_id()),
                            kind: EntryKind::Succession,
                            leaf: label32("leaf 3"),
                            at_ms: 1_700_000_001_000,
                        },
                    ],
                },
            ),
        ],
        |input| match input {
            TransparencyIn::Subject { user_id } => {
                let s = subject(user_id);
                assert_eq!(s, sha256_with_domain(SUBJECT_DOMAIN, user_id.as_bytes()));
                TransparencyOut::Subject {
                    domain: utf8(SUBJECT_DOMAIN),
                    subject: s,
                }
            }
            TransparencyIn::BundleLeaf { bundle } => {
                let bundle: &KeyBundle = bundle;
                bundle.verify().unwrap();
                let leaf = bundle.transparency_leaf();
                let preimage = bundle_leaf_preimage(bundle);
                assert_eq!(
                    leaf,
                    sha256_with_domain(
                        silver_protocol::transparency::BUNDLE_LEAF_DOMAIN,
                        &preimage
                    )
                );
                // One-time keys are not in the leaf.
                let mut stripped = bundle.clone();
                if let Some(prekeys) = &mut stripped.prekeys {
                    prekeys.one_time.clear();
                    prekeys.pq_one_time.clear();
                }
                assert_eq!(stripped.transparency_leaf(), leaf);
                TransparencyOut::BundleLeaf {
                    preimage: Bytes(preimage),
                    leaf,
                }
            }
            TransparencyIn::RevocationLeaf { revocation } => {
                revocation.verify().unwrap();
                let mut preimage = revocation.identity.as_bytes().to_vec();
                preimage.extend_from_slice(&be64(revocation.created_at_ms));
                preimage.extend_from_slice(&revocation.signature);
                let leaf = revocation.transparency_leaf();
                assert_eq!(
                    leaf,
                    sha256_with_domain(
                        silver_protocol::transparency::REVOCATION_LEAF_DOMAIN,
                        &preimage
                    )
                );
                TransparencyOut::RevocationLeaf { leaf }
            }
            TransparencyIn::SuccessionLeaf { succession } => {
                succession.verify().unwrap();
                let mut preimage = succession.old.as_bytes().to_vec();
                preimage.extend_from_slice(succession.new.as_bytes());
                preimage.extend_from_slice(&be64(succession.created_at_ms));
                preimage.extend_from_slice(&succession.old_signature);
                preimage.extend_from_slice(&succession.new_signature);
                let leaf = succession.transparency_leaf();
                assert_eq!(
                    leaf,
                    sha256_with_domain(
                        silver_protocol::transparency::SUCCESSION_LEAF_DOMAIN,
                        &preimage
                    )
                );
                TransparencyOut::SuccessionLeaf { leaf }
            }
            TransparencyIn::Chain { entries: inputs } => {
                let mut head = LogHead::EMPTY;
                let mut entries = Vec::new();
                let mut hashes = Vec::new();
                let mut heads = Vec::new();
                for e in inputs {
                    let entry = LogEntry::after(&head, e.subject, e.kind, e.leaf, e.at_ms);
                    let mut preimage = entry.prev.to_vec();
                    preimage.extend_from_slice(&be64(entry.index));
                    preimage.extend_from_slice(&entry.subject);
                    preimage.push(match entry.kind {
                        EntryKind::Bundle => 1,
                        EntryKind::Revocation => 2,
                        EntryKind::Succession => 3,
                    });
                    preimage.extend_from_slice(&entry.leaf);
                    preimage.extend_from_slice(&be64(entry.at_ms));
                    let hash = entry.hash();
                    assert_eq!(
                        hash,
                        sha256_with_domain(silver_protocol::transparency::ENTRY_DOMAIN, &preimage)
                    );
                    head = entry.head();
                    hashes.push(Bytes(hash.to_vec()));
                    heads.push(head);
                    entries.push(entry);
                }
                assert_eq!(
                    replay_log(&LogHead::EMPTY, &entries, Some(&head)).unwrap(),
                    head
                );
                TransparencyOut::Chain {
                    entries,
                    hashes,
                    heads,
                }
            }
        },
    );
}

// ---------------------------------------------------------------------------
// blob.json

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct BlobIn {
    #[serde(with = "b64_array")]
    key: [u8; 32],
    #[serde(with = "b64_array")]
    nonce: [u8; 24],
    blob: String,
    index: u32,
    total: u32,
    plaintext: Bytes,
}

#[derive(Serialize, Deserialize)]
struct BlobOut {
    /// The file nonce with the chunk index XORed into its last four bytes.
    #[serde(with = "b64_array")]
    chunk_nonce: [u8; 24],
    /// domain || blob id || index || total.
    aad: Bytes,
    ciphertext: Bytes,
}

const BLOB_CHUNK_DOMAIN: &[u8] = b"silver-messenger/v1/blob-chunk";

#[test]
fn blob() {
    let base = BlobIn {
        key: label32("blob key"),
        nonce: label32("blob nonce")[..24].try_into().unwrap(),
        blob: "00112233445566778899aabbccddeeff".into(),
        index: 0,
        total: 2,
        plaintext: Bytes(b"the first chunk".to_vec()),
    };
    run(
        "blob.json",
        "Encrypted file chunks: the per-chunk nonce, the associated data \
         that binds a chunk to its blob and place, and the ciphertext.",
        vec![
            ("chunk_0_of_2", base.clone()),
            (
                "chunk_1_of_2",
                BlobIn {
                    index: 1,
                    plaintext: Bytes(b"the second chunk".to_vec()),
                    ..base.clone()
                },
            ),
            (
                "empty_file",
                BlobIn {
                    total: 1,
                    plaintext: Bytes(Vec::new()),
                    ..base
                },
            ),
        ],
        |input| {
            let key = BlobKey::from_parts(input.key, input.nonce);
            let ciphertext = seal_chunk(
                &key,
                &input.blob,
                input.index,
                input.total,
                &input.plaintext.0,
            )
            .unwrap();
            let mut chunk_nonce = input.nonce;
            for (n, b) in chunk_nonce[20..].iter_mut().zip(be32(input.index)) {
                *n ^= b;
            }
            let mut aad = BLOB_CHUNK_DOMAIN.to_vec();
            aad.extend_from_slice(input.blob.as_bytes());
            aad.extend_from_slice(&be32(input.index));
            aad.extend_from_slice(&be32(input.total));
            assert_eq!(
                xchacha_encrypt(&input.key, &chunk_nonce, &input.plaintext.0, &aad),
                ciphertext
            );
            BlobOut {
                chunk_nonce,
                aad: Bytes(aad),
                ciphertext: Bytes(ciphertext),
            }
        },
    );
}
