//! Groups on MLS (RFC 9420): the parts of the protocol this crate defines.
//!
//! The MLS messages themselves are opaque bytes here; the client runs them
//! through OpenMLS. This module fixes what surrounds them: the group body
//! (`v: 5`) that carries one MLS message to one member inside the ordinary
//! sealed envelope, the plaintext an application message holds, the two
//! private-use MLS extensions Silver puts in every group and every leaf, the
//! proofs behind invite links, and the labels the relay-side epoch sequencer
//! is keyed by. `docs/PROTOCOL.md` section 13 is the specification;
//! `docs/design/groups.md` the reasoning.

use hmac::{Hmac, Mac};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ProtocolError;
use crate::blob::{BlobKey, MAX_CHUNKS, chunk_count, is_valid_blob_id};
use crate::encoding::b64_array;
use crate::envelope::{Content, MAX_BODY_BYTES};
use crate::identity::{DhPublic, UserId};
use crate::transparency::LogHead;

/// The `v` of a group body.
pub const BODY_VERSION: u32 = 5;
/// An MLS message up to this size rides inside the envelope; a larger one
/// is parked in the blob store and the body carries its [`BlobRef`].
///
/// This is the *sender's* threshold, and it is what encodes rather than a
/// round number. The body is JSON with the message base64 inside it,
/// padded to 160-byte steps, and the 32 768-byte cap of section 3 falls
/// after the padding, so the most a body can carry before padding is
/// 32 640: with base64's four bytes per three and the fixed JSON around
/// it, the largest message that encodes is a little over 24 411 bytes,
/// and the exact figure depends on the kind's name. A threshold above
/// that let a commit through `fits_inline` and then fail to encode, which
/// wedged the group; 24 360 is below it for every kind and divides by
/// three, so the base64 comes out whole.
///
/// A reader applies no such limit: it takes any inline message the body
/// cap allows, so a message from a sender with an older, higher threshold
/// still reads.
pub const MAX_INLINE_MLS_BYTES: usize = 24_360;
/// Largest parked commit or Welcome. The biggest either can be is the
/// one that adds 255 members at once, about 695 KiB (section 13.10);
/// this leaves room to grow and is far below what the blob store would
/// otherwise take, which every member of the group downloads.
pub const MAX_PARKED_HANDSHAKE_BYTES: u64 = 1024 * 1024;
/// Largest parked message of any other kind. An application message
/// carries a text or a reference to a file, never the file, and a key
/// package is a few kilobytes, so none of them should be parked at all;
/// this is slack, not a budget.
pub const MAX_PARKED_BYTES: u64 = 64 * 1024;
/// Most members a client will put in, or stay in, a group.
pub const MAX_MEMBERS: usize = 256;
/// Longest group name, in bytes of UTF-8.
pub const MAX_NAME_BYTES: usize = 64;
/// Largest key package a relay stores.
pub const MAX_KEY_PACKAGE_BYTES: usize = 4096;
/// Most key packages a relay keeps on deposit for one identity, besides
/// the last-resort one.
pub const MAX_KEY_PACKAGES: usize = 30;
/// Longest message id inside a group message.
pub const MAX_ID_BYTES: usize = 64;

/// The one MLS ciphersuite: `MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519`
/// of draft-ietf-mls-pq-ciphersuites, on the provisional code point OpenMLS
/// assigns it. X-Wing (ML-KEM-768 + X25519) for HPKE, AES-128-GCM, SHA-256,
/// Ed25519 signatures with the identity key.
pub const CIPHERSUITE: u16 = 0x004F;
/// The ciphersuite's name in the draft.
pub const CIPHERSUITE_NAME: &str = "MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519";
/// Group context extension: the group's own metadata ([`SilverGroup`]).
pub const EXTENSION_GROUP: u16 = 0xF000;
/// Leaf node extension: the member's sealed-layer X25519 key, so members
/// can seal envelopes to each other without a lookup.
pub const EXTENSION_SEAL: u16 = 0xF001;
/// Leaf node extension: a linked device's certificate
/// ([`crate::device::DeviceCertificate::encode`]), so members verify a
/// device leaf from the tree alone (section 14). Absent from a primary's
/// leaf, whose signature key is the identity key.
pub const EXTENSION_DEVICE: u16 = 0xF002;
/// Declared in the capabilities of every key package and leaf from 0.10.0
/// and never carried as an extension: a leaf that declares it reads the
/// everyday content kinds of section 4.7 (edit, delete, reaction, timer)
/// in application messages. A client sends one of those to a group only
/// when every leaf in the tree declares this.
pub const EXTENSION_EVERYDAY: u16 = 0xF003;
/// The MLS exporter label of the token a committer shows the relay's
/// epoch sequencer; the context is the group id, the length 32.
pub const SEQUENCER_LABEL: &str = "silver-messenger/v1/group-sequencer";
/// Domain of the key an invite link carries, derived from the group's
/// invite key.
pub const INVITE_LINK_DOMAIN: &[u8] = b"silver-messenger/v1/group-invite";
/// Domain of the proof a join request carries, derived from the link key.
pub const JOIN_PROOF_DOMAIN: &[u8] = b"silver-messenger/v1/group-join";

/// Identifies a group: 32 random bytes chosen by its creator. Base64 in
/// JSON like every other byte string; base58 in links and on screen like
/// user ids.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GroupId(#[serde(with = "b64_array")] pub [u8; 32]);

impl GroupId {
    pub fn generate() -> Self {
        let mut id = [0u8; 32];
        OsRng.fill_bytes(&mut id);
        Self(id)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// A short prefix of the base58 form, for compact display.
    pub fn short(&self) -> String {
        self.to_string().chars().take(8).collect()
    }
}

impl std::fmt::Display for GroupId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&bs58::encode(&self.0).into_string())
    }
}

impl std::fmt::Debug for GroupId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GroupId({})", self.short())
    }
}

impl std::str::FromStr for GroupId {
    type Err = ProtocolError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // The length before the decoding, which is quadratic in it; see
        // [`crate::identity::MAX_ID_CHARS`].
        if s.len() > crate::identity::MAX_ID_CHARS {
            return Err(ProtocolError::Malformed("group id is too long".into()));
        }
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|_| ProtocolError::Malformed("group id is not base58".into()))?;
        let id: [u8; 32] = bytes
            .try_into()
            .map_err(|_| ProtocolError::Malformed("group id is not 32 bytes".into()))?;
        Ok(Self(id))
    }
}

/// What kind of MLS message a group body carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupKind {
    /// An MLS `Welcome`, sent to a member just added.
    Welcome,
    /// A `PrivateMessage` carrying a proposal or a commit.
    Handshake,
    /// A `PrivateMessage` carrying an application message: a
    /// [`GroupPlaintext`].
    Message,
    /// A `KeyPackage` from someone joining by an invite link, with a
    /// [`JoinProof`]; sent to the admin the link names.
    Join,
    /// A `KeyPackage` from a member that fell out of sync, asking an admin
    /// to remove and re-add it.
    Rejoin,
}

/// An MLS message parked in the blob store because it did not fit the
/// envelope: everything needed to fetch and open it, with the file
/// scheme of `docs/PROTOCOL.md` section 7.5.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobRef {
    pub blob: String,
    pub key: BlobKey,
    pub chunks: u32,
    pub size: u64,
    #[serde(with = "b64_array")]
    pub sha256: [u8; 32],
}

impl BlobRef {
    /// Check the reference, with `most` the largest the parked message
    /// may be for the kind of body carrying it.
    fn validate(&self, most: u64) -> Result<(), ProtocolError> {
        if !is_valid_blob_id(&self.blob) {
            return Err(ProtocolError::Malformed("bad blob id".into()));
        }
        if self.size == 0 || self.size > most {
            return Err(ProtocolError::Malformed("bad blob size".into()));
        }
        if self.chunks == 0 || self.chunks > MAX_CHUNKS || self.chunks != chunk_count(self.size) {
            return Err(ProtocolError::Malformed("bad chunk count".into()));
        }
        Ok(())
    }
}

/// The check a group name must pass when it is chosen — at creation or a
/// rename — as opposed to when it is read back. Refuses the invisible
/// characters a reaction already refuses, which would otherwise reach the
/// sidebar and the "joined" lines: a name is not refused on the reading
/// side, where it is part of a context every member has already agreed on.
pub fn check_new_name(name: &str) -> Result<(), ProtocolError> {
    if name.len() > MAX_NAME_BYTES {
        return Err(ProtocolError::Malformed("group name too long".into()));
    }
    if name.chars().any(char::is_control) {
        return Err(ProtocolError::Malformed(
            "control character in group name".into(),
        ));
    }
    if name.chars().any(crate::envelope::is_invisible) {
        return Err(ProtocolError::Malformed(
            "invisible character in group name".into(),
        ));
    }
    Ok(())
}

/// Proof that a join request came from someone holding a valid invite
/// link; see [`join_proof`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinProof {
    #[serde(with = "b64_array")]
    pub proof: [u8; 32],
}

/// A body with `v: 5`: one MLS message for one group, to one member.
///
/// Exactly one of `mls` and `blob` is present; `join` is present exactly
/// for [`GroupKind::Join`]. The sealed layer carries no signature for a
/// group body (as for v4): every kind is authenticated inside MLS.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupBody {
    pub v: u32,
    pub group: GroupId,
    pub kind: GroupKind,
    /// The TLS-serialised `MLSMessage`, when it fits.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::encoding::b64_opt"
    )]
    pub mls: Option<Vec<u8>>,
    /// Where the `MLSMessage` is parked when it does not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob: Option<BlobRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join: Option<JoinProof>,
}

impl GroupBody {
    /// A body carrying `mls` inline.
    pub fn inline(group: GroupId, kind: GroupKind, mls: Vec<u8>) -> Self {
        Self {
            v: BODY_VERSION,
            group,
            kind,
            mls: Some(mls),
            blob: None,
            join: None,
        }
    }

    /// A body whose MLS message is parked in the blob store.
    pub fn parked(group: GroupId, kind: GroupKind, blob: BlobRef) -> Self {
        Self {
            v: BODY_VERSION,
            group,
            kind,
            mls: None,
            blob: Some(blob),
            join: None,
        }
    }

    /// The same body with a join proof; only meaningful for
    /// [`GroupKind::Join`].
    pub fn with_join_proof(mut self, proof: [u8; 32]) -> Self {
        self.join = Some(JoinProof { proof });
        self
    }

    /// Whether an MLS message of `len` bytes goes inline.
    pub fn fits_inline(len: usize) -> bool {
        len <= MAX_INLINE_MLS_BYTES
    }

    /// The shape rules; called after decoding.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        let malformed = |what: &str| Err(ProtocolError::Malformed(format!("group body: {what}")));
        if self.v != BODY_VERSION {
            return malformed("wrong version");
        }
        match (&self.mls, &self.blob) {
            (Some(mls), None) => {
                if mls.is_empty() {
                    return malformed("empty message");
                }
                if mls.len() > MAX_BODY_BYTES {
                    return Err(ProtocolError::TooLarge(mls.len()));
                }
            }
            // A parked message is fetched by everyone the body reaches,
            // so what it may weigh depends on what it can be: a commit
            // or a Welcome for a group of 256, or nothing much at all.
            (None, Some(blob)) => blob.validate(match self.kind {
                GroupKind::Welcome | GroupKind::Handshake => MAX_PARKED_HANDSHAKE_BYTES,
                GroupKind::Message | GroupKind::Join | GroupKind::Rejoin => MAX_PARKED_BYTES,
            })?,
            _ => return malformed("exactly one of mls and blob"),
        }
        if (self.kind == GroupKind::Join) != self.join.is_some() {
            return malformed("join proof exactly for a join");
        }
        Ok(())
    }
}

/// What an application message says, inside the MLS ciphertext: the same
/// things a one-to-one body carries, minus the sequence (MLS numbers
/// messages itself) and the capabilities (every member is a client that
/// understands groups).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupPlaintext {
    /// Random id, for de-duplication and for the history.
    pub id: String,
    pub sent_at_ms: u64,
    /// A text or a file. Anything else is ignored by members.
    pub content: Content,
    /// The sender's last verified transparency log head, for members to
    /// compare with their own, as contacts do one-to-one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<LogHead>,
}

impl GroupPlaintext {
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.content.check()?;
        let bytes =
            serde_json::to_vec(self).map_err(|e| ProtocolError::Malformed(e.to_string()))?;
        if bytes.len() > MAX_BODY_BYTES {
            return Err(ProtocolError::TooLarge(bytes.len()));
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() > MAX_BODY_BYTES {
            return Err(ProtocolError::TooLarge(bytes.len()));
        }
        let plain: Self =
            serde_json::from_slice(bytes).map_err(|e| ProtocolError::Malformed(e.to_string()))?;
        // The same rule a one-to-one message id follows (section 4): an
        // id reaches the log and the screen through the edits, deletions
        // and reactions that name it, so it is printable ASCII and no
        // longer than a message id may be.
        if !crate::envelope::is_valid_message_id(&plain.id) {
            return Err(ProtocolError::Malformed("group message: bad id".into()));
        }
        plain.content.check()?;
        Ok(plain)
    }
}

/// The group context extension [`EXTENSION_GROUP`]: what every member
/// agrees on about the group besides its tree. Changed only by an admin's
/// `GroupContextExtensions` commit.
///
/// Encoding (`docs/PROTOCOL.md` section 13):
///
/// ```text
/// version (1 byte, = 1) || name length (1 byte) || name (UTF-8)
/// || admins length in bytes (2 bytes, big-endian) || admins (32 bytes each, ascending)
/// || invite_key (32 bytes) || created_at_ms (8 bytes, big-endian)
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SilverGroup {
    pub name: String,
    /// Sorted, without duplicates, at least one.
    pub admins: Vec<UserId>,
    /// Rotated to void every invite link made from it.
    pub invite_key: [u8; 32],
    pub created_at_ms: u64,
}

const GROUP_EXTENSION_VERSION: u8 = 1;

impl SilverGroup {
    /// A new group's extension: its creator the only admin, a fresh invite
    /// key.
    pub fn new(name: &str, creator: UserId, created_at_ms: u64) -> Result<Self, ProtocolError> {
        let mut invite_key = [0u8; 32];
        OsRng.fill_bytes(&mut invite_key);
        let group = Self {
            name: name.to_owned(),
            admins: vec![creator],
            invite_key,
            created_at_ms,
        };
        group.check()?;
        Ok(group)
    }

    pub fn is_admin(&self, user: &UserId) -> bool {
        self.admins.binary_search(user).is_ok()
    }

    /// The same group with `user` an admin.
    pub fn with_admin(&self, user: UserId) -> Self {
        let mut admins = self.admins.clone();
        if let Err(at) = admins.binary_search(&user) {
            admins.insert(at, user);
        }
        Self {
            admins,
            ..self.clone()
        }
    }

    /// The same group without `user` among the admins.
    pub fn without_admin(&self, user: &UserId) -> Self {
        Self {
            admins: self.admins.iter().copied().filter(|a| a != user).collect(),
            ..self.clone()
        }
    }

    /// The same group with a fresh invite key, so every link made from the
    /// old one stops working.
    pub fn with_new_invite_key(&self) -> Self {
        let mut invite_key = [0u8; 32];
        OsRng.fill_bytes(&mut invite_key);
        Self {
            invite_key,
            ..self.clone()
        }
    }

    fn check(&self) -> Result<(), ProtocolError> {
        // The reading side takes a name as it was written: the extension is
        // inside the group context every member agreed on, so refusing one
        // here would break a group made by an older version. What a name
        // may be when it is *chosen* is stricter; see [`check_new_name`].

        let malformed =
            |what: &str| Err(ProtocolError::Malformed(format!("group extension: {what}")));
        if self.name.len() > MAX_NAME_BYTES {
            return malformed("name too long");
        }
        if self.name.chars().any(char::is_control) {
            return malformed("control character in name");
        }
        if self.admins.is_empty() {
            return malformed("no admins");
        }
        if self.admins.len() > MAX_MEMBERS {
            return malformed("too many admins");
        }
        if self.admins.windows(2).any(|w| w[0] >= w[1]) {
            return malformed("admins not sorted");
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.check()?;
        let mut out = Vec::with_capacity(2 + self.name.len() + 2 + 32 * self.admins.len() + 40);
        out.push(GROUP_EXTENSION_VERSION);
        out.push(self.name.len() as u8);
        out.extend_from_slice(self.name.as_bytes());
        out.extend_from_slice(&((self.admins.len() * 32) as u16).to_be_bytes());
        for admin in &self.admins {
            out.extend_from_slice(admin.as_bytes());
        }
        out.extend_from_slice(&self.invite_key);
        out.extend_from_slice(&self.created_at_ms.to_be_bytes());
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let malformed = |what: &str| ProtocolError::Malformed(format!("group extension: {what}"));
        let mut reader = Reader(bytes);
        if reader.u8()? != GROUP_EXTENSION_VERSION {
            return Err(malformed("unknown version"));
        }
        let name_len = usize::from(reader.u8()?);
        let name = std::str::from_utf8(reader.take(name_len)?)
            .map_err(|_| malformed("name is not UTF-8"))?
            .to_owned();
        let admins_len = usize::from(reader.u16()?);
        if admins_len % 32 != 0 {
            return Err(malformed("admins length"));
        }
        let admins = reader
            .take(admins_len)?
            .chunks_exact(32)
            .map(|chunk| UserId::from_bytes(chunk.try_into().expect("32 bytes")))
            .collect::<Result<Vec<_>, _>>()?;
        let invite_key: [u8; 32] = reader.take(32)?.try_into().expect("32 bytes");
        let created_at_ms = reader.u64()?;
        if !reader.0.is_empty() {
            return Err(malformed("trailing bytes"));
        }
        let group = Self {
            name,
            admins,
            invite_key,
            created_at_ms,
        };
        group.check()?;
        Ok(group)
    }
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], ProtocolError> {
        if self.0.len() < n {
            return Err(ProtocolError::Malformed(
                "group extension: truncated".into(),
            ));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ProtocolError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("2 bytes"),
        ))
    }

    fn u64(&mut self) -> Result<u64, ProtocolError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }
}

/// The leaf node extension [`EXTENSION_SEAL`]: the member's sealed-layer
/// X25519 key, raw.
pub fn encode_seal_key(dh_public: &DhPublic) -> Vec<u8> {
    dh_public.0.to_vec()
}

pub fn decode_seal_key(bytes: &[u8]) -> Result<DhPublic, ProtocolError> {
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ProtocolError::Malformed("seal extension is not 32 bytes".into()))?;
    // A key of small order makes every Diffie-Hellman with it come out
    // zero, so sealing to it fails. Every group message is sealed to every
    // member, one envelope each, and a member is not free to break the
    // others: a leaf carrying such a key is refused here, where a leaf is
    // verified, rather than at the point where somebody tries to send.
    // A trial exchange decides it, which is exactly the question sealing
    // will ask later.
    let trial = x25519_dalek::StaticSecret::from([1u8; 32]);
    if !trial
        .diffie_hellman(&x25519_dalek::PublicKey::from(key))
        .was_contributory()
    {
        return Err(ProtocolError::WeakKey);
    }
    Ok(DhPublic(key))
}

type HmacSha256 = Hmac<Sha256>;

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("any key length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// The key an invite link carries: derived from the group's invite key,
/// so the link reveals nothing about it and a rotated invite key voids
/// every link.
pub fn link_key(invite_key: &[u8; 32], group: &GroupId) -> [u8; 16] {
    hmac(invite_key, &[INVITE_LINK_DOMAIN, group.as_bytes()])[..16]
        .try_into()
        .expect("16 bytes")
}

/// What a join request proves: possession of the link key, bound to the
/// group and to the joiner's identity, so a proof cannot be reused for
/// another group or by someone else.
pub fn join_proof(link_key: &[u8; 16], group: &GroupId, joiner: &UserId) -> [u8; 32] {
    hmac(
        link_key,
        &[JOIN_PROOF_DOMAIN, group.as_bytes(), joiner.as_bytes()],
    )
}

/// Check a join proof against the group's current invite key, in
/// constant time.
pub fn verify_join_proof(
    invite_key: &[u8; 32],
    group: &GroupId,
    joiner: &UserId,
    proof: &[u8; 32],
) -> bool {
    let key = link_key(invite_key, group);
    let mut mac = HmacSha256::new_from_slice(&key).expect("any key length");
    mac.update(JOIN_PROOF_DOMAIN);
    mac.update(group.as_bytes());
    mac.update(joiner.as_bytes());
    mac.verify_slice(proof).is_ok()
}

/// What the relay stores of a sequencer token: its SHA-256.
pub fn token_hash(token: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(token).into()
}

#[cfg(test)]
mod tests {

    #[test]
    fn a_group_is_named_without_invisible_characters() {
        for bad in ["Team\u{202E}", "papers\u{200B}", "\u{FEFF}quiet"] {
            assert!(check_new_name(bad).is_err(), "{bad:?} names a group");
        }
        assert!(check_new_name("the papers").is_ok());
        assert!(check_new_name(&"x".repeat(MAX_NAME_BYTES + 1)).is_err());
        assert!(check_new_name("two\nlines").is_err());

        // A group made by an older version keeps its name: the extension is
        // inside the context every member agreed on, so the reader takes it
        // as it was written.
        let alice = crate::Identity::generate().user_id();
        let group = SilverGroup::new("Team\u{202E}", alice, 1);
        assert!(group.is_ok(), "the reader's rule is looser");
    }
    /// As for a user id: the length before the quadratic decoding.
    #[test]
    fn an_overlong_group_id_costs_nothing_to_refuse() {
        use std::time::{Duration, Instant};
        let long = "z".repeat(128 * 1024);
        let started = Instant::now();
        assert!(long.parse::<GroupId>().is_err());
        let took = started.elapsed();
        assert!(
            took < Duration::from_secs(1),
            "refused in {took:?}: the length is not being checked before the decoding"
        );
        let id = GroupId::generate();
        assert_eq!(id.to_string().parse::<GroupId>().unwrap(), id);
    }

    use super::*;
    use crate::identity::Identity;

    fn ids(n: usize) -> Vec<UserId> {
        let mut ids: Vec<UserId> = (0..n).map(|_| Identity::generate().user_id()).collect();
        ids.sort();
        ids
    }

    #[test]
    fn group_ids_print_as_base58_and_parse_back() {
        let id = GroupId::generate();
        assert_eq!(id.to_string().parse::<GroupId>().unwrap(), id);
        assert!("not base58!".parse::<GroupId>().is_err());
        assert!(
            bs58::encode([1u8; 31])
                .into_string()
                .parse::<GroupId>()
                .is_err()
        );
        let json = serde_json::to_string(&id).unwrap();
        assert!(json.ends_with("=\""), "json form is base64: {json}");
        assert_eq!(serde_json::from_str::<GroupId>(&json).unwrap(), id);
        assert_eq!(id.short().len(), 8);
    }

    #[test]
    fn group_extension_round_trips_and_is_checked() {
        let admins = ids(3);
        let group = SilverGroup {
            name: "the papers".into(),
            admins: admins.clone(),
            invite_key: [9; 32],
            created_at_ms: 1_700_000_000_000,
        };
        let bytes = group.encode().unwrap();
        assert_eq!(bytes.len(), 1 + 1 + 10 + 2 + 96 + 32 + 8);
        assert_eq!(SilverGroup::decode(&bytes).unwrap(), group);
        assert!(group.is_admin(&admins[1]));
        assert!(!group.is_admin(&Identity::generate().user_id()));

        // Every rule.
        let mut unsorted = group.clone();
        unsorted.admins.swap(0, 1);
        assert!(unsorted.encode().is_err());
        let mut duplicate = group.clone();
        duplicate.admins.push(admins[2]);
        assert!(duplicate.encode().is_err());
        let none = SilverGroup {
            admins: Vec::new(),
            ..group.clone()
        };
        assert!(none.encode().is_err());
        let long = SilverGroup {
            name: "x".repeat(MAX_NAME_BYTES + 1),
            ..group.clone()
        };
        assert!(long.encode().is_err());
        let control = SilverGroup {
            name: "a\nb".into(),
            ..group.clone()
        };
        assert!(control.encode().is_err());
        assert!(SilverGroup::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(SilverGroup::decode(&trailing).is_err());
        let mut version = bytes.clone();
        version[0] = 2;
        assert!(SilverGroup::decode(&version).is_err());
        let mut bad_admin = bytes.clone();
        bad_admin[14..46].copy_from_slice(&[0xff; 32]);
        assert!(SilverGroup::decode(&bad_admin).is_err());

        // Admin changes keep the order.
        let newcomer = Identity::generate().user_id();
        let more = group.with_admin(newcomer);
        assert!(more.is_admin(&newcomer) && more.admins.len() == 4);
        assert_eq!(more.with_admin(newcomer), more);
        assert!(more.admins.windows(2).all(|w| w[0] < w[1]));
        let fewer = more.without_admin(&newcomer);
        assert_eq!(fewer, group);
        let rotated = group.with_new_invite_key();
        assert_ne!(rotated.invite_key, group.invite_key);
        assert_eq!(rotated.admins, group.admins);
    }

    #[test]
    fn a_new_group_has_its_creator_as_the_only_admin() {
        let me = Identity::generate().user_id();
        let group = SilverGroup::new("us", me, 1).unwrap();
        assert_eq!(group.admins, vec![me]);
        assert!(SilverGroup::new(&"x".repeat(65), me, 1).is_err());
    }

    #[test]
    fn group_bodies_have_one_payload_and_a_proof_only_when_joining() {
        let group = GroupId::generate();
        let inline = GroupBody::inline(group, GroupKind::Message, vec![1, 2, 3]);
        assert!(inline.validate().is_ok());
        let json = serde_json::to_string(&inline).unwrap();
        assert!(json.starts_with(r#"{"v":5,"group":""#));
        assert!(!json.contains("blob") && !json.contains("join"));
        assert_eq!(serde_json::from_str::<GroupBody>(&json).unwrap(), inline);

        let blob = BlobRef {
            blob: "00112233445566778899aabbccddeeff".into(),
            key: BlobKey::from_parts([1; 32], [2; 24]),
            chunks: 2,
            size: 70_000,
            sha256: [3; 32],
        };
        let parked = GroupBody::parked(group, GroupKind::Welcome, blob.clone());
        assert!(parked.validate().is_ok());
        let both = GroupBody {
            blob: Some(blob.clone()),
            ..inline.clone()
        };
        assert!(both.validate().is_err());
        let neither = GroupBody {
            mls: None,
            ..inline.clone()
        };
        assert!(neither.validate().is_err());
        let empty = GroupBody::inline(group, GroupKind::Message, Vec::new());
        assert!(empty.validate().is_err());
        let wrong_version = GroupBody {
            v: 4,
            ..inline.clone()
        };
        assert!(wrong_version.validate().is_err());

        let join = GroupBody::inline(group, GroupKind::Join, vec![1]);
        assert!(join.validate().is_err(), "a join needs its proof");
        assert!(join.clone().with_join_proof([7; 32]).validate().is_ok());
        assert!(inline.clone().with_join_proof([7; 32]).validate().is_err());
        let rejoin = GroupBody::inline(group, GroupKind::Rejoin, vec![1]);
        assert!(rejoin.validate().is_ok());

        // Blob references are checked like a file's.
        use crate::blob::MAX_FILE_BYTES;
        for bad in [
            BlobRef {
                blob: "../x".into(),
                ..blob.clone()
            },
            BlobRef {
                chunks: 3,
                ..blob.clone()
            },
            BlobRef {
                size: 0,
                chunks: 1,
                ..blob.clone()
            },
            BlobRef {
                size: MAX_FILE_BYTES + 1,
                chunks: MAX_CHUNKS + 1,
                ..blob.clone()
            },
        ] {
            assert!(
                GroupBody::parked(group, GroupKind::Welcome, bad)
                    .validate()
                    .is_err()
            );
        }

        // What a parked message may weigh depends on what it is. Every
        // member of the group fetches it, so a commit or a Welcome is
        // allowed what the largest of them takes and nothing else is
        // allowed even that.
        let big = |size: u64| BlobRef {
            size,
            chunks: crate::blob::chunk_count(size),
            ..blob.clone()
        };
        for kind in [GroupKind::Welcome, GroupKind::Handshake] {
            assert!(
                GroupBody::parked(group, kind, big(MAX_PARKED_HANDSHAKE_BYTES))
                    .validate()
                    .is_ok()
            );
            assert!(
                GroupBody::parked(group, kind, big(MAX_PARKED_HANDSHAKE_BYTES + 1))
                    .validate()
                    .is_err()
            );
        }
        for kind in [GroupKind::Message, GroupKind::Rejoin] {
            assert!(
                GroupBody::parked(group, kind, big(MAX_PARKED_BYTES))
                    .validate()
                    .is_ok()
            );
            assert!(
                GroupBody::parked(group, kind, big(MAX_PARKED_BYTES + 1))
                    .validate()
                    .is_err(),
                "{kind:?} has no reason to be parked at all"
            );
        }
        // The threshold is a size that encodes, not a round number: the
        // body is JSON with the message base64 inside it, padded to
        // 160-byte steps, under a cap that falls after the padding. A
        // threshold above what encodes let a commit through here and then
        // fail to encode, which wedged the group it was for.
        for kind in [
            GroupKind::Handshake,
            GroupKind::Welcome,
            GroupKind::Message,
            GroupKind::Join,
            GroupKind::Rejoin,
        ] {
            let body = GroupBody::inline(group, kind, vec![7; MAX_INLINE_MLS_BYTES]);
            let body = if kind == GroupKind::Join {
                body.with_join_proof([7; 32])
            } else {
                body
            };
            assert!(
                crate::envelope::Body::Group(body).encode().is_ok(),
                "the largest message this client sends inline encodes as {kind:?}"
            );
        }

        assert!(GroupBody::fits_inline(MAX_INLINE_MLS_BYTES));
        assert!(!GroupBody::fits_inline(MAX_INLINE_MLS_BYTES + 1));
    }

    #[test]
    fn group_plaintext_round_trips_within_the_limit() {
        let plain = GroupPlaintext {
            id: "0f0e0d0c-0b0a-4908-8706-050403020100".into(),
            sent_at_ms: 5,
            content: Content::text("hi all"),
            head: Some(LogHead {
                index: 1,
                hash: [4; 32],
            }),
        };
        let bytes = plain.encode().unwrap();
        assert_eq!(GroupPlaintext::decode(&bytes).unwrap(), plain);
        assert!(
            GroupPlaintext::decode(
                br#"{"id":"","sent_at_ms":1,"content":{"type":"text","body":"x"}}"#
            )
            .is_err()
        );
        // The content's bounds hold inside a group message too.
        assert!(
            GroupPlaintext::decode(
                br#"{"id":"m1","sent_at_ms":1,"content":{"type":"timer","seconds":99999999999}}"#
            )
            .is_err()
        );
        let big = GroupPlaintext {
            content: Content::text("x".repeat(MAX_BODY_BYTES)),
            ..plain.clone()
        };
        assert!(matches!(big.encode(), Err(ProtocolError::TooLarge(_))));
        let bad = GroupPlaintext {
            content: Content::Reaction {
                id: "m1".into(),
                emoji: "\n".into(),
            },
            ..plain
        };
        assert!(matches!(bad.encode(), Err(ProtocolError::Malformed(_))));
    }

    #[test]
    fn seal_keys_are_raw_32_bytes() {
        let id = Identity::generate();
        let bytes = encode_seal_key(&id.dh_public());
        assert_eq!(bytes.len(), 32);
        assert_eq!(decode_seal_key(&bytes).unwrap(), id.dh_public());
        assert!(decode_seal_key(&bytes[..31]).is_err());

        // Every group message is sealed to every member, so a member whose
        // leaf carries a key of small order would make sending fail for
        // everyone. The canonical small-order encodings, and the two
        // non-canonical ones, are refused where the leaf is read.
        let low_order: [[u8; 32]; 5] = [
            [0; 32],
            {
                let mut k = [0; 32];
                k[0] = 1;
                k
            },
            [
                224, 235, 122, 124, 59, 65, 184, 174, 22, 86, 227, 250, 241, 159, 196, 106, 218, 9,
                141, 235, 156, 50, 177, 253, 134, 98, 5, 22, 95, 73, 184, 0,
            ],
            [
                95, 156, 149, 188, 163, 80, 140, 36, 177, 208, 177, 85, 156, 131, 239, 91, 4, 68,
                92, 196, 88, 28, 142, 134, 216, 34, 78, 221, 208, 159, 17, 87,
            ],
            {
                let mut k = [0xff; 32];
                k[0] = 0xec;
                k[31] = 0x7f;
                k
            },
        ];
        for key in low_order {
            assert!(
                decode_seal_key(&key).is_err(),
                "a small-order seal key is refused: {key:?}"
            );
        }
    }

    #[test]
    fn join_proofs_are_bound_to_the_link_the_group_and_the_joiner() {
        let invite_key = [5u8; 32];
        let group = GroupId::generate();
        let joiner = Identity::generate().user_id();
        let key = link_key(&invite_key, &group);
        let proof = join_proof(&key, &group, &joiner);
        assert!(verify_join_proof(&invite_key, &group, &joiner, &proof));
        assert!(!verify_join_proof(&[6u8; 32], &group, &joiner, &proof));
        assert!(!verify_join_proof(
            &invite_key,
            &GroupId::generate(),
            &joiner,
            &proof
        ));
        assert!(!verify_join_proof(
            &invite_key,
            &group,
            &Identity::generate().user_id(),
            &proof
        ));
        let mut damaged = proof;
        damaged[0] ^= 1;
        assert!(!verify_join_proof(&invite_key, &group, &joiner, &damaged));
        assert_ne!(link_key(&invite_key, &GroupId::generate()), key);
        assert_eq!(token_hash(&[1; 32]).len(), 32);
        assert_ne!(token_hash(&[1; 32]), token_hash(&[2; 32]));
    }
}
