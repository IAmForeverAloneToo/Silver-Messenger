//! Groups on MLS (RFC 9420) through OpenMLS: the engine a front end drives.
//!
//! The engine holds every group's MLS state (through [`Provider`]) and the
//! client's own bookkeeping (`groups.json`): who is in each group and how
//! to seal to them, the sequencer tokens of recent epochs, handshake
//! messages held for a later epoch, and the key packages on deposit at the
//! relay. It is synchronous; the relay is talked to by the caller, in three
//! steps for anything that commits:
//!
//! 1. stage: [`Groups::stage_add`] and friends build a commit and return a
//!    [`Staged`] with the sequencer token of the epoch left and the hash of
//!    the next one;
//! 2. the caller asks the relay's sequencer (`GroupCommit`);
//! 3. on `GroupState`, [`Groups::commit_staged`] merges the commit and
//!    returns the envelopes to fan out; on `stale`, [`Groups::discard_staged`]
//!    throws it away, the winner's commit is processed when it arrives, and
//!    the caller may try again.
//!
//! Application messages need no sequencer: [`Groups::send`] returns the
//! envelopes at once. Everything received goes through [`Groups::receive`],
//! which returns [`GroupEvent`]s for the front end. `docs/PROTOCOL.md`
//! section 13 says what goes on the wire; `docs/design/groups.md` why.

pub mod link;
pub mod provider;

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;

use openmls::group::GroupId as MlsGroupId;
use openmls::prelude::*;
use openmls::treesync::RatchetTree;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use openmls_traits::storage::StorageProvider as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use silver_protocol::blob::{self, BlobKey, CHUNK_BYTES, MAX_FILE_BYTES, new_blob_id};
use silver_protocol::encoding::b64_array;
use silver_protocol::group::{
    self, BlobRef, EXTENSION_DEVICE, EXTENSION_GROUP, EXTENSION_SEAL, GroupBody, GroupId,
    GroupKind, GroupPlaintext, MAX_MEMBERS, SEQUENCER_LABEL, SilverGroup, decode_seal_key,
    encode_seal_key,
};
use silver_protocol::wire::KeyPackageDeposit;
use silver_protocol::{
    Body, Content, DeviceCertificate, DhPublic, Envelope, Identity, LogHead, UserId,
    seal_bytes_unsigned_to,
};
use tls_codec::{Deserialize as _, Serialize as _};

pub use link::GroupLink;
pub use provider::Provider;

use crate::store::Store;

/// The one ciphersuite (`docs/design/groups.md` section 4.1).
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519;
/// Key packages to keep on deposit, and when to make more.
pub const KEY_PACKAGE_TARGET: usize = 20;
pub const KEY_PACKAGE_MIN: usize = 10;
/// How long a key package is good for.
pub const KEY_PACKAGE_LIFETIME_MS: u64 = 90 * 24 * 60 * 60 * 1000;
/// How often the last-resort package is replaced.
pub const LAST_RESORT_ROTATION_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// A member whose leaf is older than this commits a self-update when it
/// next can, so a compromise heals within the week even in a quiet group.
pub const SELF_UPDATE_AFTER_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// Sequencer tokens of past epochs kept, for catching a rewound relay up.
pub const TOKENS_KEPT: usize = 64;
/// Handshake messages from a future epoch held, and for how long.
pub const HOLD_LIMIT: usize = 16;
pub const HOLD_FOR_MS: u64 = 10 * 60 * 1000;
/// Message ids remembered per group, against duplicates.
const SEEN_IDS: usize = 256;
/// Application messages from this many past epochs still decrypt.
const PAST_EPOCHS: usize = 3;

pub(crate) const GROUPS_FILE: &str = "groups.json";
pub(crate) const MLS_FILE: &str = "groups.mls";

// --- what is stored ---------------------------------------------------------

/// A leaf of the tree: the identity it belongs to, the device whose key
/// signed it (the identity's own on a primary; `docs/PROTOCOL.md` section
/// 14), and its sealing key. An identity with several devices has a leaf
/// per device; the members as shown are identities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberInfo {
    pub user: UserId,
    pub device: UserId,
    pub seal: DhPublic,
    pub admin: bool,
}

/// The distinct identities among `members`, in the order they first
/// appear.
pub fn identities(members: &[MemberInfo]) -> Vec<UserId> {
    let mut out: Vec<UserId> = Vec::new();
    for member in members {
        if !out.contains(&member.user) {
            out.push(member.user);
        }
    }
    out
}

/// Where a group stands for this client.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum GroupState {
    #[default]
    Active,
    /// A Welcome from `from` was taken (the MLS state exists, so the group
    /// stays in sync), but the user has not said yes; nothing is shown or
    /// sent until [`Groups::accept_welcome`], and
    /// [`Groups::decline_welcome`] drops it all.
    Invited { from: UserId },
    /// We asked to leave; the state is gone.
    Left,
    /// An admin removed us; the state is gone, the history stays.
    Removed { by: UserId },
    /// A commit broke the membership rules (`docs/design/groups.md` 7.6);
    /// nothing is sent or read until an admin re-creates the group.
    Broken { by: UserId, reason: String },
    /// A commit was missed for good; a rejoin request went to the admins.
    OutOfSync { since_ms: u64 },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EpochToken {
    epoch: u64,
    #[serde(with = "b64_array")]
    token: [u8; 32],
}

/// A handshake message from a later epoch than ours, kept until the
/// epochs between arrive.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Held {
    received_at_ms: u64,
    from: UserId,
    #[serde(with = "silver_protocol::encoding::b64")]
    mls: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupRecord {
    pub name: String,
    #[serde(default)]
    pub alias: Option<String>,
    pub members: Vec<MemberInfo>,
    #[serde(default)]
    pub state: GroupState,
    #[serde(default)]
    tokens: Vec<EpochToken>,
    #[serde(default)]
    held: Vec<Held>,
    /// When our leaf was last updated (a self-update, or joining).
    pub leaf_updated_ms: u64,
    pub created_at_ms: u64,
    #[serde(default)]
    pub muted: bool,
    #[serde(default)]
    seen: VecDeque<String>,
    /// The group's disappearing-message timer, in seconds; 0 for none.
    /// Set by an admin's `timer` message (`docs/design/everyday.md`).
    #[serde(default)]
    pub expire_after_s: u64,
}

impl GroupRecord {
    pub fn display_name(&self) -> &str {
        match &self.alias {
            Some(alias) => alias,
            None if self.name.is_empty() => "(unnamed group)",
            None => &self.name,
        }
    }

    pub fn is_admin(&self, user: &UserId) -> bool {
        self.members.iter().any(|m| m.user == *user && m.admin)
    }

    pub fn admins(&self) -> Vec<UserId> {
        identities(&self.members)
            .into_iter()
            .filter(|u| self.is_admin(u))
            .collect()
    }

    /// The members as identities, each once whatever its devices.
    pub fn identities(&self) -> Vec<UserId> {
        identities(&self.members)
    }

    pub fn is_member(&self, user: &UserId) -> bool {
        self.members.iter().any(|m| m.user == *user)
    }

    /// The devices `user` is in the group with.
    pub fn devices_of(&self, user: &UserId) -> Vec<UserId> {
        self.members
            .iter()
            .filter(|m| m.user == *user)
            .map(|m| m.device)
            .collect()
    }
}

/// A key package on deposit: the bytes the relay holds, and when it ends.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct KeyPackageRecord {
    #[serde(with = "b64_array")]
    r#ref: [u8; 32],
    expires_at_ms: u64,
    created_at_ms: u64,
    #[serde(with = "silver_protocol::encoding::b64")]
    data: Vec<u8>,
}

impl KeyPackageRecord {
    fn deposit(&self) -> KeyPackageDeposit {
        KeyPackageDeposit {
            r#ref: self.r#ref,
            expires_at_ms: self.expires_at_ms,
            data: self.data.clone(),
        }
    }
}

/// A Welcome taken from someone the front end has not decided to trust
/// yet; the group stands in [`GroupState::Invited`] until it does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldWelcome {
    pub group: GroupId,
    pub from: UserId,
    pub name: String,
    pub members: Vec<UserId>,
    pub received_at_ms: u64,
}

#[derive(Default, Serialize, Deserialize)]
pub(crate) struct GroupsFile {
    #[serde(default)]
    groups: BTreeMap<GroupId, GroupRecord>,
    #[serde(default)]
    key_packages: Vec<KeyPackageRecord>,
    #[serde(default)]
    last_resort: Option<KeyPackageRecord>,
    /// Groups we asked to join by link, and the admin asked: their Welcome
    /// is taken without asking the user again.
    #[serde(default)]
    joins: BTreeMap<GroupId, UserId>,
    /// Groups this account is in, as the primary named them when this
    /// device was linked (`docs/design/devices.md` section 7.4): the
    /// Welcome the primary sends for each is taken without asking, and
    /// the alias is known from the start.
    #[serde(default)]
    expected: BTreeMap<GroupId, ExpectedGroup>,
}

/// A group named at link time, before its Welcome came.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedGroup {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
}

// --- what comes out -----------------------------------------------------------

/// What a received group body turned out to be.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GroupEvent {
    /// An application message from a member.
    Message {
        group: GroupId,
        from: UserId,
        id: String,
        sent_at_ms: u64,
        content: Content,
    },
    /// A member's transparency log head, to compare with ours.
    Head { from: UserId, head: LogHead },
    /// The group changed by a commit from `by`.
    Changed {
        group: GroupId,
        by: UserId,
        change: Change,
    },
    /// The admin we asked by link answered with a Welcome: the group is
    /// active, and the user's yes was the join request.
    Joined { group: GroupId },
    /// A Welcome the caller has to vouch for; [`Groups::accept_welcome`]
    /// or [`Groups::decline_welcome`] settle it.
    Invited { held: HeldWelcome },
    /// An admin removed us.
    Removed { group: GroupId, by: UserId },
    /// A commit broke the membership rules; the group is marked broken.
    Broken {
        group: GroupId,
        by: UserId,
        reason: String,
    },
    /// Someone presented a valid invite link; an admin's client adds them
    /// with [`Groups::stage_add`].
    JoinRequest {
        group: GroupId,
        joiner: UserId,
        key_package: Vec<u8>,
    },
    /// A member proposed its own removal (it left); an admin's next commit
    /// takes it out of the tree, and an admin's client makes one at once
    /// with [`Groups::stage_self_update`].
    LeaveProposed { group: GroupId, member: UserId },
    /// A member fell out of sync and asks to be removed and re-added.
    RejoinRequest {
        group: GroupId,
        member: UserId,
        key_package: Vec<u8>,
    },
    /// A commit is missing for good; a rejoin request should go out.
    OutOfSync { group: GroupId },
    /// Something about the message was wrong; nothing was changed.
    Refused { group: GroupId, reason: String },
}

/// What a commit did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    Added(Vec<UserId>),
    Removed(Vec<UserId>),
    Left(Vec<UserId>),
    Renamed(String),
    Admins(Vec<UserId>),
    LinkReset,
    /// A member refreshed its keys, and nothing else.
    Updated,
}

/// A blob to upload before the envelopes go out.
#[derive(Clone, Debug)]
pub struct Upload {
    pub blob: String,
    pub chunks: Vec<Vec<u8>>,
}

/// Envelopes to submit, one per member, and the blobs to upload first
/// when an MLS message did not fit the envelope (a commit and its Welcome
/// can both be parked).
#[derive(Debug, Default)]
pub struct Outgoing {
    /// The message id, for an application message.
    pub id: Option<String>,
    pub envelopes: Vec<Envelope>,
    pub uploads: Vec<Upload>,
}

/// A commit built and staged, waiting for the sequencer's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Staged {
    pub group: GroupId,
    /// The epoch the commit leaves.
    pub epoch: u64,
    /// The token of that epoch, for the relay.
    pub token: [u8; 32],
    /// The hash of the next epoch's token, for the relay to keep.
    pub next: [u8; 32],
}

/// What [`Groups::create`] asks the sequencer for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Created {
    pub group: GroupId,
    pub epoch: u64,
    pub next: [u8; 32],
}

struct StagedCommitData {
    commit: Vec<u8>,
    welcome: Option<Vec<u8>>,
    /// Members before the commit, to fan the commit out to.
    recipients: Vec<MemberInfo>,
    /// Members the commit adds, to send the Welcome to.
    added: Vec<MemberInfo>,
    change: Change,
}

#[derive(Debug, thiserror::Error)]
pub enum GroupError {
    #[error("no such group")]
    NoSuchGroup,
    #[error("only an admin can do that")]
    NotAdmin,
    #[error("the group is {0}")]
    NotActive(String),
    #[error("nothing is staged for this group")]
    NothingStaged,
    #[error("a commit is already staged for this group")]
    AlreadyStaged,
    #[error("{0} is not a member")]
    NotAMember(UserId),
    #[error("{0} is a member already")]
    AlreadyAMember(UserId),
    #[error("the group is full ({MAX_MEMBERS} members)")]
    Full,
    #[error("the last admin cannot go; appoint another first")]
    LastAdmin,
    #[error("key package: {0}")]
    KeyPackage(String),
    #[error("mls: {0}")]
    Mls(String),
    #[error("{0}")]
    Protocol(#[from] silver_protocol::ProtocolError),
    #[error("{0}")]
    Storage(#[from] anyhow::Error),
}

type Result<T> = std::result::Result<T, GroupError>;

fn mls_err<E: std::fmt::Display>(e: E) -> GroupError {
    GroupError::Mls(e.to_string())
}

// --- the engine ---------------------------------------------------------------

pub struct Groups {
    store: Option<Store>,
    /// This device's keys: the identity's own on a primary.
    identity: Arc<Identity>,
    /// On a linked device, the account's certificate for these keys; the
    /// leaves this engine makes carry it, and their credential names the
    /// account.
    certificate: Option<DeviceCertificate>,
    provider: Provider,
    signer: SignatureKeyPair,
    file: GroupsFile,
    handles: HashMap<GroupId, MlsGroup>,
    staged: HashMap<GroupId, StagedCommitData>,
}

impl Groups {
    /// Load from the data directory; missing files mean no groups yet. On
    /// a linked device (`linked` in `identity.json`) the engine acts for
    /// the account.
    pub fn load(store: &Store, identity: Arc<Identity>) -> anyhow::Result<Self> {
        let file = store.load_groups()?;
        let provider = match store.load_mls()? {
            Some(bytes) => Provider::from_export(&bytes)?,
            None => Provider::new(),
        };
        let certificate = match store.load_linked()? {
            Some(linked) => {
                linked.certificate.verify()?;
                if linked.certificate.device != identity.user_id() {
                    anyhow::bail!("the link in identity.json is for another key");
                }
                Some(linked.certificate)
            }
            None => None,
        };
        let mut groups = Self::with(Some(store.clone()), identity, certificate, provider, file);
        groups.clear_all_pending()?;
        Ok(groups)
    }

    /// An engine that lives in memory only, for a primary.
    pub fn ephemeral(identity: Arc<Identity>) -> Self {
        Self::with(None, identity, None, Provider::new(), GroupsFile::default())
    }

    /// An engine in memory only for a linked device, `certificate` being
    /// the account's word for `identity`'s key.
    pub fn ephemeral_device(identity: Arc<Identity>, certificate: DeviceCertificate) -> Self {
        assert_eq!(certificate.device, identity.user_id());
        Self::with(
            None,
            identity,
            Some(certificate),
            Provider::new(),
            GroupsFile::default(),
        )
    }

    fn with(
        store: Option<Store>,
        identity: Arc<Identity>,
        certificate: Option<DeviceCertificate>,
        provider: Provider,
        file: GroupsFile,
    ) -> Self {
        let secrets = identity.to_secrets();
        let signer = SignatureKeyPair::from_raw(
            SignatureScheme::ED25519,
            secrets.signing_seed.to_vec(),
            identity.user_id().as_bytes().to_vec(),
        );
        Self {
            store,
            identity,
            certificate,
            provider,
            signer,
            file,
            handles: HashMap::new(),
            staged: HashMap::new(),
        }
    }

    /// The identity this engine acts for: this key's own on a primary,
    /// the account's on a linked device. Membership and admin rights go
    /// by it.
    pub fn account(&self) -> UserId {
        self.certificate
            .as_ref()
            .map_or_else(|| self.identity.user_id(), |c| c.account)
    }

    /// This device's own id, which its leaves are signed with.
    fn device(&self) -> UserId {
        self.identity.user_id()
    }

    /// Commits staged before a restart are gone with the process.
    fn clear_all_pending(&mut self) -> anyhow::Result<()> {
        let ids: Vec<GroupId> = self.file.groups.keys().copied().collect();
        for id in ids {
            if let Ok(group) = load_handle(&mut self.handles, &self.provider, &id) {
                if group.pending_commit().is_some() {
                    group
                        .clear_pending_commit(self.provider.storage())
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                }
            }
        }
        Ok(())
    }

    fn persist(&self) -> Result<()> {
        if let Some(store) = &self.store {
            store.save_groups(&self.file)?;
            store.save_mls(&self.provider.export())?;
        }
        Ok(())
    }

    /// This device's id; [`Groups::account`] is who it acts for.
    pub fn user_id(&self) -> UserId {
        self.identity.user_id()
    }

    /// Every group, active or not, in id order.
    pub fn list(&self) -> impl Iterator<Item = (&GroupId, &GroupRecord)> {
        self.file.groups.iter()
    }

    pub fn get(&self, group: &GroupId) -> Option<&GroupRecord> {
        self.file.groups.get(group)
    }

    /// Groups whose Welcome waits for the user's yes.
    pub fn invitations(&self) -> Vec<HeldWelcome> {
        self.file
            .groups
            .iter()
            .filter_map(|(id, r)| match r.state {
                GroupState::Invited { from } => Some(HeldWelcome {
                    group: *id,
                    from,
                    name: r.name.clone(),
                    members: r.identities(),
                    received_at_ms: r.created_at_ms,
                }),
                _ => None,
            })
            .collect()
    }

    pub fn set_alias(&mut self, group: &GroupId, alias: Option<String>) -> Result<()> {
        let record = self.record_mut(group)?;
        record.alias = alias.filter(|a| !a.trim().is_empty());
        self.persist()
    }

    /// Note the groups the account is in, as the primary named them at
    /// link time; a group already known here keeps what it has.
    pub fn expect_groups(
        &mut self,
        groups: impl IntoIterator<Item = (GroupId, ExpectedGroup)>,
    ) -> Result<()> {
        for (id, expected) in groups {
            if self.file.groups.contains_key(&id) {
                continue;
            }
            self.file.expected.insert(
                id,
                ExpectedGroup {
                    alias: expected.alias.filter(|a| !a.trim().is_empty()),
                    ..expected
                },
            );
        }
        self.persist()
    }

    /// What the primary said of `group` at link time, while its Welcome
    /// is still to come.
    pub fn expected(&self, group: &GroupId) -> Option<&ExpectedGroup> {
        self.file.expected.get(group)
    }

    /// The groups named at link time whose Welcome is still to come.
    pub fn expected_groups(&self) -> impl Iterator<Item = (&GroupId, &ExpectedGroup)> {
        self.file.expected.iter()
    }

    pub fn set_muted(&mut self, group: &GroupId, muted: bool) -> Result<()> {
        self.record_mut(group)?.muted = muted;
        self.persist()
    }

    /// The group's disappearing-message timer from now on, in seconds (0
    /// for none), as an admin set it.
    pub fn set_timer(&mut self, group: &GroupId, seconds: u64) -> Result<()> {
        self.record_mut(group)?.expire_after_s = seconds;
        self.persist()
    }

    /// Forget a group that is left, removed or broken.
    pub fn forget(&mut self, group: &GroupId) -> Result<()> {
        let record = self.record(group)?;
        if record.state == GroupState::Active {
            return Err(GroupError::NotActive("still active; leave it first".into()));
        }
        self.drop_state(group);
        self.file.groups.remove(group);
        self.persist()
    }

    fn record(&self, group: &GroupId) -> Result<&GroupRecord> {
        self.file.groups.get(group).ok_or(GroupError::NoSuchGroup)
    }

    fn record_mut(&mut self, group: &GroupId) -> Result<&mut GroupRecord> {
        self.file
            .groups
            .get_mut(group)
            .ok_or(GroupError::NoSuchGroup)
    }

    fn active(&self, group: &GroupId) -> Result<&GroupRecord> {
        let record = self.record(group)?;
        match &record.state {
            GroupState::Active => Ok(record),
            GroupState::Invited { .. } => Err(GroupError::NotActive("not accepted yet".into())),
            GroupState::Left => Err(GroupError::NotActive("left".into())),
            GroupState::Removed { .. } => {
                Err(GroupError::NotActive("one you were removed from".into()))
            }
            GroupState::Broken { .. } => Err(GroupError::NotActive("broken".into())),
            GroupState::OutOfSync { .. } => Err(GroupError::NotActive("out of sync".into())),
        }
    }

    /// Drop the MLS state of a group we are no longer in.
    fn drop_state(&mut self, group: &GroupId) {
        if let Some(mut handle) = self.handles.remove(group) {
            let _ = handle.delete(self.provider.storage());
        } else if let Ok(Some(mut handle)) = MlsGroup::load(self.provider.storage(), &mls_id(group))
        {
            let _ = handle.delete(self.provider.storage());
        }
        self.staged.remove(group);
    }

    // --- key packages -----------------------------------------------------------

    /// The credential names the account; the signature key is this
    /// device's, which on a linked device differs and is vouched for by
    /// the `silver_device` leaf extension.
    fn credential(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: BasicCredential::new(self.account().as_bytes().to_vec()).into(),
            signature_key: self.signer.public().into(),
        }
    }

    fn capabilities() -> Capabilities {
        Capabilities::new(
            None,
            Some(&[CIPHERSUITE]),
            Some(&[
                ExtensionType::Unknown(EXTENSION_GROUP),
                ExtensionType::Unknown(EXTENSION_SEAL),
                ExtensionType::Unknown(EXTENSION_DEVICE),
            ]),
            None,
            None,
        )
    }

    /// The sealing key, and on a linked device the certificate.
    fn leaf_extensions(&self) -> Extensions<LeafNode> {
        let mut extensions = vec![Extension::Unknown(
            EXTENSION_SEAL,
            UnknownExtension(encode_seal_key(&self.identity.dh_public())),
        )];
        if let Some(certificate) = &self.certificate {
            extensions.push(Extension::Unknown(
                EXTENSION_DEVICE,
                UnknownExtension(certificate.encode()),
            ));
        }
        Extensions::from_vec(extensions).expect("distinct private-use extensions")
    }

    fn new_key_package(&self, last_resort: bool, now_ms: u64) -> Result<KeyPackageRecord> {
        let mut builder = KeyPackage::builder()
            .leaf_node_capabilities(Self::capabilities())
            .leaf_node_extensions(self.leaf_extensions())
            .key_package_lifetime(Lifetime::new(KEY_PACKAGE_LIFETIME_MS / 1000));
        if last_resort {
            builder = builder.key_package_extensions(
                Extensions::single(Extension::LastResort(LastResortExtension::default()))
                    .expect("one extension"),
            );
        }
        let bundle = builder
            .build(CIPHERSUITE, &self.provider, &self.signer, self.credential())
            .map_err(mls_err)?;
        let key_package = bundle.key_package();
        let hash_ref = key_package
            .hash_ref(self.provider.crypto())
            .map_err(mls_err)?;
        let r#ref: [u8; 32] = hash_ref
            .as_slice()
            .try_into()
            .map_err(|_| GroupError::KeyPackage("hash ref is not 32 bytes".into()))?;
        let data = MlsMessageOut::from(key_package.clone())
            .tls_serialize_detached()
            .map_err(mls_err)?;
        Ok(KeyPackageRecord {
            r#ref,
            expires_at_ms: now_ms + KEY_PACKAGE_LIFETIME_MS - 60_000,
            created_at_ms: now_ms,
            data,
        })
    }

    /// The deposit to send the relay: prunes expired packages, makes new
    /// ones up to the target, rotates the last-resort one when due.
    pub fn deposit(
        &mut self,
        now_ms: u64,
    ) -> Result<(Vec<KeyPackageDeposit>, Option<KeyPackageDeposit>)> {
        let expired: Vec<KeyPackageRecord> = self
            .file
            .key_packages
            .iter()
            .filter(|p| p.expires_at_ms <= now_ms)
            .cloned()
            .collect();
        for package in &expired {
            self.delete_key_package_secret(package);
        }
        self.file.key_packages.retain(|p| p.expires_at_ms > now_ms);
        if self.file.key_packages.len() < KEY_PACKAGE_MIN {
            while self.file.key_packages.len() < KEY_PACKAGE_TARGET {
                let package = self.new_key_package(false, now_ms)?;
                self.file.key_packages.push(package);
            }
        }
        let rotate = match &self.file.last_resort {
            Some(last) => {
                last.created_at_ms + LAST_RESORT_ROTATION_MS <= now_ms
                    || last.expires_at_ms <= now_ms
            }
            None => true,
        };
        if rotate {
            if let Some(old) = self.file.last_resort.take() {
                // Its secret stays until its lifetime ends: a Welcome made
                // from it may still arrive.
                if old.expires_at_ms <= now_ms {
                    self.delete_key_package_secret(&old);
                } else {
                    self.file.key_packages.push(old);
                }
            }
            self.file.last_resort = Some(self.new_key_package(true, now_ms)?);
        }
        self.persist()?;
        Ok((
            self.file
                .key_packages
                .iter()
                .map(KeyPackageRecord::deposit)
                .collect(),
            self.file
                .last_resort
                .as_ref()
                .map(KeyPackageRecord::deposit),
        ))
    }

    /// What the relay said after a deposit: handed-out packages leave the
    /// list (their secrets stay until a Welcome uses them or they expire).
    pub fn apply_status(&mut self, consumed: &[[u8; 32]]) -> Result<bool> {
        let before = self.file.key_packages.len();
        self.file
            .key_packages
            .retain(|p| !consumed.contains(&p.r#ref));
        if self.file.key_packages.len() != before {
            self.persist()?;
        }
        Ok(self.file.key_packages.len() < KEY_PACKAGE_MIN)
    }

    /// Packages on deposit as this client last knew.
    pub fn key_packages_on_deposit(&self) -> usize {
        self.file.key_packages.len()
    }

    fn delete_key_package_secret(&self, package: &KeyPackageRecord) {
        if let Ok(kp) = parse_key_package(&package.data, self.provider.crypto()) {
            if let Ok(hash_ref) = kp.hash_ref(self.provider.crypto()) {
                let _ = self.provider.storage().delete_key_package(&hash_ref);
            }
        }
    }

    /// Parse and check a key package the relay handed out for a device of
    /// `user`'s (or `user`'s own): its leaf names that identity and is
    /// signed by it or by a device it certified, our ciphersuite, alive,
    /// with the extensions a leaf needs.
    pub fn verify_key_package(&self, user: &UserId, data: &[u8], now_ms: u64) -> Result<Vec<u8>> {
        let kp = parse_key_package(data, self.provider.crypto())?;
        verify_leaf(kp.leaf_node(), Some(user))?;
        if kp.ciphersuite() != CIPHERSUITE {
            return Err(GroupError::KeyPackage("wrong ciphersuite".into()));
        }
        let _ = now_ms;
        if kp.life_time().validate().is_err() {
            return Err(GroupError::KeyPackage("expired".into()));
        }
        Ok(data.to_vec())
    }

    // --- creating, adding, removing ----------------------------------------------

    fn group_config(&self, extension: &SilverGroup) -> Result<MlsGroupCreateConfig> {
        let context = Extensions::from_vec(vec![
            Extension::Unknown(EXTENSION_GROUP, UnknownExtension(extension.encode()?)),
            Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
                &[
                    ExtensionType::Unknown(EXTENSION_GROUP),
                    ExtensionType::Unknown(EXTENSION_SEAL),
                ],
                &[],
                &[],
            )),
        ])
        .map_err(mls_err)?;
        Ok(MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .max_past_epochs(PAST_EPOCHS)
            .with_group_context_extensions(context)
            .capabilities(Self::capabilities())
            .with_leaf_node_extensions(self.leaf_extensions())
            .map_err(mls_err)?
            .build())
    }

    fn join_config() -> MlsGroupJoinConfig {
        MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .max_past_epochs(PAST_EPOCHS)
            .build()
    }

    /// Make a group with ourselves as the only member and admin. The caller
    /// registers the returned entry with the relay's sequencer.
    pub fn create(&mut self, name: &str, now_ms: u64) -> Result<Created> {
        let me = self.account();
        let extension = SilverGroup::new(name, me, now_ms)?;
        let id = GroupId::generate();
        let config = self.group_config(&extension)?;
        let group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            mls_id(&id),
            self.credential(),
        )
        .map_err(mls_err)?;
        let token = token_of(&group, &id, self.provider.crypto())?;
        self.handles.insert(id, group);
        self.file.groups.insert(
            id,
            GroupRecord {
                name: name.to_owned(),
                alias: None,
                members: vec![MemberInfo {
                    user: me,
                    device: self.device(),
                    seal: self.identity.dh_public(),
                    admin: true,
                }],
                state: GroupState::Active,
                tokens: vec![EpochToken { epoch: 0, token }],
                held: Vec::new(),
                leaf_updated_ms: now_ms,
                created_at_ms: now_ms,
                muted: false,
                seen: VecDeque::new(),
                expire_after_s: 0,
            },
        );
        self.persist()?;
        Ok(Created {
            group: id,
            epoch: 0,
            next: group::token_hash(&token),
        })
    }

    /// The sequencer refused the creation: forget the group.
    pub fn abandon(&mut self, group: &GroupId) -> Result<()> {
        self.drop_state(group);
        self.file.groups.remove(group);
        self.persist()
    }

    /// The sequencer entry for `group` as we know it: the current epoch and
    /// the hash of its token, to re-create the entry after the relay lost
    /// it.
    pub fn sequencer_entry(&mut self, group: &GroupId) -> Result<Created> {
        self.active(group)?;
        let handle = load_handle(&mut self.handles, &self.provider, group)?;
        let epoch = handle.epoch().as_u64();
        let token = token_of(handle, group, self.provider.crypto())?;
        Ok(Created {
            group: *group,
            epoch,
            next: group::token_hash(&token),
        })
    }

    /// The token of a past epoch, for catching a rewound sequencer up:
    /// `Staged` values for each step from `from_epoch` to the current one.
    pub fn catch_up(&self, group: &GroupId, from_epoch: u64) -> Result<Vec<Staged>> {
        let record = self.record(group)?;
        let mut steps = Vec::new();
        for pair in record.tokens.windows(2) {
            if pair[0].epoch >= from_epoch && pair[1].epoch == pair[0].epoch + 1 {
                steps.push(Staged {
                    group: *group,
                    epoch: pair[0].epoch,
                    token: pair[0].token,
                    next: group::token_hash(&pair[1].token),
                });
            }
        }
        Ok(steps)
    }

    /// Stage a commit adding leaves from verified key packages
    /// ([`Groups::verify_key_package`]): an admin adds anyone (every
    /// device of an identity in one commit, as a rule), and any member
    /// adds devices of its own identity.
    pub fn stage_add(&mut self, group: &GroupId, packages: &[Vec<u8>]) -> Result<Staged> {
        let me = self.account();
        let record = self.active(group)?.clone();
        if self.staged.contains_key(group) {
            return Err(GroupError::AlreadyStaged);
        }
        let mut parsed = Vec::with_capacity(packages.len());
        let mut added: Vec<MemberInfo> = Vec::with_capacity(packages.len());
        for data in packages {
            let kp = parse_key_package(data, self.provider.crypto())?;
            let leaf = verify_leaf(kp.leaf_node(), None)?;
            if record.members.iter().any(|m| m.device == leaf.device)
                || added.iter().any(|m| m.device == leaf.device)
            {
                return Err(GroupError::AlreadyAMember(leaf.account));
            }
            added.push(MemberInfo {
                user: leaf.account,
                device: leaf.device,
                seal: leaf.seal,
                admin: record.is_admin(&leaf.account),
            });
            parsed.push(kp);
        }
        if !record.is_admin(&me) && added.iter().any(|m| m.user != me) {
            return Err(GroupError::NotAdmin);
        }
        let mut after = record.identities();
        for member in &added {
            if !after.contains(&member.user) {
                after.push(member.user);
            }
        }
        if after.len() > MAX_MEMBERS {
            return Err(GroupError::Full);
        }
        // What the commit does to the membership as identities; devices
        // of identities already in are no change in that sense.
        let new_identities: Vec<UserId> = identities(&added)
            .into_iter()
            .filter(|u| !record.is_member(u))
            .collect();
        let change = if new_identities.is_empty() {
            Change::Updated
        } else {
            Change::Added(new_identities)
        };
        self.stage(
            group,
            |builder| Ok(builder.propose_adds(parsed)),
            added,
            change,
        )
    }

    /// Stage a commit removing identities, every device of each.
    pub fn stage_remove(&mut self, group: &GroupId, users: &[UserId]) -> Result<Staged> {
        let me = self.account();
        let record = self.active(group)?.clone();
        if !record.is_admin(&me) {
            return Err(GroupError::NotAdmin);
        }
        if users.contains(&me) {
            return Err(GroupError::Mls("leave with /group leave".into()));
        }
        let remaining_admins = record
            .admins()
            .iter()
            .filter(|a| !users.contains(a))
            .count();
        if remaining_admins == 0 {
            return Err(GroupError::LastAdmin);
        }
        let mut indices = Vec::new();
        {
            let handle = load_handle(&mut self.handles, &self.provider, group)?;
            let leaves = leaves_of(handle)?;
            for user in users {
                let theirs: Vec<LeafNodeIndex> = leaves
                    .iter()
                    .filter(|(_, leaf)| leaf.account == *user)
                    .map(|(index, _)| *index)
                    .collect();
                if theirs.is_empty() {
                    return Err(GroupError::NotAMember(*user));
                }
                indices.extend(theirs);
            }
        }
        // Admins removed from the group leave the admin list with it.
        let mut extension = self.extension(group)?;
        for user in users {
            extension = extension.without_admin(user);
        }
        let change = Change::Removed(users.to_vec());
        let context = context_extensions(&extension)?;
        self.stage(
            group,
            move |builder| {
                builder
                    .propose_removals(indices)
                    .propose_group_context_extensions(context)
                    .map_err(mls_err)
            },
            Vec::new(),
            change,
        )
    }

    /// Stage a commit removing one device's leaf, the identity staying a
    /// member by its other devices: for an admin, or for any member of the
    /// device's own identity (a primary taking an unlinked device out of
    /// its groups). This device's own leaf goes with [`Groups::leave`].
    pub fn stage_remove_device(&mut self, group: &GroupId, device: &UserId) -> Result<Staged> {
        let me = self.account();
        let record = self.active(group)?.clone();
        if *device == self.device() {
            return Err(GroupError::Mls("leave with /group leave".into()));
        }
        let Some(leaf) = record.members.iter().find(|m| m.device == *device) else {
            return Err(GroupError::NotAMember(*device));
        };
        if !record.is_admin(&me) && leaf.user != me {
            return Err(GroupError::NotAdmin);
        }
        let account = leaf.user;
        let last = record.devices_of(&account).len() == 1;
        if last && account == me {
            return Err(GroupError::Mls("leave with /group leave".into()));
        }
        if last && record.is_admin(&account) && record.admins().len() == 1 {
            return Err(GroupError::LastAdmin);
        }
        let index = {
            let handle = load_handle(&mut self.handles, &self.provider, group)?;
            leaves_of(handle)?
                .into_iter()
                .find(|(_, l)| l.device == *device)
                .map(|(index, _)| index)
                .ok_or(GroupError::NotAMember(*device))?
        };
        let change = if last {
            Change::Removed(vec![account])
        } else {
            Change::Updated
        };
        if last {
            // Its identity goes with its last device; an admin leaves the
            // admin list too.
            let extension = self.extension(group)?.without_admin(&account);
            let context = context_extensions(&extension)?;
            self.stage(
                group,
                move |builder| {
                    builder
                        .propose_removals([index])
                        .propose_group_context_extensions(context)
                        .map_err(mls_err)
                },
                Vec::new(),
                change,
            )
        } else {
            self.stage(
                group,
                move |builder| Ok(builder.propose_removals([index])),
                Vec::new(),
                change,
            )
        }
    }

    /// Stage a commit that changes the group's name.
    pub fn stage_rename(&mut self, group: &GroupId, name: &str) -> Result<Staged> {
        self.stage_extension_change(
            group,
            |extension| {
                Ok(SilverGroup {
                    name: name.to_owned(),
                    ..extension
                })
            },
            Change::Renamed(name.to_owned()),
        )
    }

    /// Stage a commit that makes `user` an admin, or stops them being one.
    pub fn stage_admin(&mut self, group: &GroupId, user: UserId, admin: bool) -> Result<Staged> {
        let record = self.active(group)?.clone();
        if !record.is_member(&user) {
            return Err(GroupError::NotAMember(user));
        }
        self.stage_extension_change(
            group,
            |extension| {
                let next = if admin {
                    extension.with_admin(user)
                } else {
                    extension.without_admin(&user)
                };
                if next.admins.is_empty() {
                    return Err(GroupError::LastAdmin);
                }
                Ok(next)
            },
            Change::Admins(Vec::new()),
        )
    }

    /// Stage a commit with a fresh invite key, voiding every link.
    pub fn stage_link_reset(&mut self, group: &GroupId) -> Result<Staged> {
        self.stage_extension_change(
            group,
            |extension| Ok(extension.with_new_invite_key()),
            Change::LinkReset,
        )
    }

    fn stage_extension_change(
        &mut self,
        group: &GroupId,
        change: impl FnOnce(SilverGroup) -> Result<SilverGroup>,
        what: Change,
    ) -> Result<Staged> {
        let me = self.account();
        let record = self.active(group)?.clone();
        if !record.is_admin(&me) {
            return Err(GroupError::NotAdmin);
        }
        let extension = change(self.extension(group)?)?;
        let what = match what {
            Change::Admins(_) => Change::Admins(extension.admins.clone()),
            other => other,
        };
        let context = context_extensions(&extension)?;
        self.stage(
            group,
            move |builder| {
                builder
                    .propose_group_context_extensions(context)
                    .map_err(mls_err)
            },
            Vec::new(),
            what,
        )
    }

    /// Stage a commit that only refreshes our own leaf.
    pub fn stage_self_update(&mut self, group: &GroupId) -> Result<Staged> {
        self.active(group)?;
        self.stage(
            group,
            |builder| Ok(builder.force_self_update(true)),
            Vec::new(),
            Change::Updated,
        )
    }

    /// Groups whose leaf is due for a refresh.
    pub fn self_updates_due(&self, now_ms: u64) -> Vec<GroupId> {
        self.file
            .groups
            .iter()
            .filter(|(_, r)| {
                r.state == GroupState::Active && r.leaf_updated_ms + SELF_UPDATE_AFTER_MS <= now_ms
            })
            .map(|(id, _)| *id)
            .collect()
    }

    fn stage(
        &mut self,
        group: &GroupId,
        proposals: impl FnOnce(CommitBuilder<'_, Initial>) -> Result<CommitBuilder<'_, Initial>>,
        added: Vec<MemberInfo>,
        change: Change,
    ) -> Result<Staged> {
        if self.staged.contains_key(group) {
            return Err(GroupError::AlreadyStaged);
        }
        let recipients = self.others(group)?;
        let leaf = LeafNodeParameters::builder()
            .with_extensions(self.leaf_extensions())
            .build();
        let crypto = self.provider.crypto();
        let rand = self.provider.rand();
        let signer = &self.signer;
        let handle = self.handles.get_mut(group).ok_or(GroupError::NoSuchGroup)?;
        let epoch = handle.epoch().as_u64();
        let token = token_of(handle, group, crypto)?;
        let builder = proposals(handle.commit_builder())?.leaf_node_parameters(leaf);
        let bundle = builder
            .load_psks(self.provider.storage())
            .map_err(mls_err)?
            .build(rand, crypto, signer, |_| true)
            .map_err(mls_err)?
            .stage_commit(&self.provider)
            .map_err(mls_err)?;
        let next_token: [u8; 32] = handle
            .pending_commit()
            .ok_or_else(|| GroupError::Mls("no pending commit after staging".into()))?
            .export_secret(crypto, SEQUENCER_LABEL, group.as_bytes(), 32)
            .map_err(mls_err)?
            .try_into()
            .map_err(|_| GroupError::Mls("exporter length".into()))?;
        let (commit, welcome, _) = bundle.into_messages();
        let commit = commit.tls_serialize_detached().map_err(mls_err)?;
        let welcome = welcome
            .map(|w| w.tls_serialize_detached())
            .transpose()
            .map_err(mls_err)?;
        self.staged.insert(
            *group,
            StagedCommitData {
                commit,
                welcome,
                recipients,
                added,
                change,
            },
        );
        self.persist()?;
        Ok(Staged {
            group: *group,
            epoch,
            token,
            next: group::token_hash(&next_token),
        })
    }

    /// The sequencer accepted: merge the staged commit, record the new
    /// epoch's token, and return the envelopes to fan out (the commit to
    /// every member that was there, the Welcome to every member added).
    pub fn commit_staged(&mut self, group: &GroupId, now_ms: u64) -> Result<Outgoing> {
        let data = self.staged.remove(group).ok_or(GroupError::NothingStaged)?;
        let handle = self.handles.get_mut(group).ok_or(GroupError::NoSuchGroup)?;
        handle
            .merge_pending_commit(&self.provider)
            .map_err(mls_err)?;
        let epoch = handle.epoch().as_u64();
        let token = token_of(handle, group, self.provider.crypto())?;
        let extension = extension_of(handle.extensions())?;
        let members = members_of(handle, &extension)?;
        let record = self.record_mut(group)?;
        record.members = members;
        push_token(record, epoch, token);
        // Every commit of ours carries an update path.
        record.leaf_updated_ms = now_ms;
        if let Change::Renamed(name) = &data.change {
            record.name = name.clone();
        }
        let mut outgoing = Outgoing::default();
        if !data.recipients.is_empty() {
            let (body, upload) = self.frame(group, GroupKind::Handshake, data.commit)?;
            outgoing.uploads.extend(upload);
            outgoing
                .envelopes
                .extend(self.seal_to(&data.recipients, &body)?);
        }
        if let (Some(welcome), false) = (data.welcome, data.added.is_empty()) {
            let (body, upload) = self.frame(group, GroupKind::Welcome, welcome)?;
            outgoing.uploads.extend(upload);
            outgoing.envelopes.extend(self.seal_to(&data.added, &body)?);
        }
        self.persist()?;
        Ok(outgoing)
    }

    /// The sequencer refused: throw the staged commit away.
    pub fn discard_staged(&mut self, group: &GroupId) -> Result<()> {
        self.staged.remove(group);
        if let Some(handle) = self.handles.get_mut(group) {
            handle
                .clear_pending_commit(self.provider.storage())
                .map_err(mls_err)?;
        }
        self.persist()
    }

    pub fn has_staged(&self, group: &GroupId) -> bool {
        self.staged.contains_key(group)
    }

    // --- leaving -----------------------------------------------------------------

    /// Propose this device's own removal to the group and forget its
    /// state; an admin's next commit takes the leaf out. Returns the
    /// proposal envelopes. The identity's other devices stay members
    /// until they leave too.
    pub fn leave(&mut self, group: &GroupId) -> Result<Outgoing> {
        let me = self.account();
        let record = self.active(group)?.clone();
        let other_admins = record.admins().iter().filter(|a| **a != me).count();
        let last_leaf = record.devices_of(&me).len() == 1;
        if record.is_admin(&me) && other_admins == 0 && last_leaf && record.identities().len() > 1 {
            return Err(GroupError::LastAdmin);
        }
        let recipients = self.others(group)?;
        let mut outgoing = Outgoing::default();
        if !recipients.is_empty() {
            let handle = load_handle(&mut self.handles, &self.provider, group)?;
            let proposal = handle
                .leave_group(&self.provider, &self.signer)
                .map_err(mls_err)?
                .tls_serialize_detached()
                .map_err(mls_err)?;
            let (body, upload) = self.frame(group, GroupKind::Handshake, proposal)?;
            outgoing.uploads.extend(upload);
            outgoing.envelopes = self.seal_to(&recipients, &body)?;
        }
        self.drop_state(group);
        self.record_mut(group)?.state = GroupState::Left;
        self.persist()?;
        Ok(outgoing)
    }

    // --- sending -------------------------------------------------------------------

    /// An application message to every member.
    pub fn send(
        &mut self,
        group: &GroupId,
        content: Content,
        head: Option<LogHead>,
        now_ms: u64,
    ) -> Result<Outgoing> {
        self.active(group)?;
        let id = uuid::Uuid::new_v4().to_string();
        let plaintext = GroupPlaintext {
            id: id.clone(),
            sent_at_ms: now_ms,
            content,
            head,
        }
        .encode()?;
        let handle = load_handle(&mut self.handles, &self.provider, group)?;
        let message = handle
            .create_message(&self.provider, &self.signer, &plaintext)
            .map_err(mls_err)?
            .tls_serialize_detached()
            .map_err(mls_err)?;
        let recipients = self.others(group)?;
        let (body, upload) = self.frame(group, GroupKind::Message, message)?;
        let envelopes = self.seal_to(&recipients, &body)?;
        self.persist()?;
        Ok(Outgoing {
            id: Some(id),
            envelopes,
            uploads: upload.into_iter().collect(),
        })
    }

    /// Every leaf but this device's own: the identity's other devices
    /// get their copies like anyone else.
    fn others(&self, group: &GroupId) -> Result<Vec<MemberInfo>> {
        let me = self.device();
        Ok(self
            .record(group)?
            .members
            .iter()
            .filter(|m| m.device != me)
            .cloned()
            .collect())
    }

    /// A join request for the admin an invite link names, from a fresh key
    /// package; the caller looks the admin up and sends the envelope.
    pub fn join_request(
        &mut self,
        link: &GroupLink,
        admin: (UserId, DhPublic),
        now_ms: u64,
    ) -> Result<Outgoing> {
        let package = self.new_key_package(false, now_ms)?;
        // Kept like a deposited one, so the Welcome made from it can be read.
        self.file.key_packages.push(package.clone());
        self.file.joins.insert(link.group, link.via);
        let proof = group::join_proof(&link.key, &link.group, &self.account());
        let body =
            GroupBody::inline(link.group, GroupKind::Join, package.data).with_join_proof(proof);
        let envelope = seal_bytes_unsigned_to(
            &self.identity,
            admin.0,
            &admin.1,
            &Body::Group(body).encode()?,
        )?;
        self.persist()?;
        Ok(Outgoing {
            id: None,
            envelopes: vec![envelope],
            uploads: Vec::new(),
        })
    }

    /// A rejoin request from a fresh key package to every admin we know
    /// of, and to this identity's other devices, which may answer it too.
    pub fn rejoin_request(&mut self, group: &GroupId, now_ms: u64) -> Result<Outgoing> {
        let record = self.record(group)?.clone();
        let me = self.account();
        let device = self.device();
        let admins: Vec<MemberInfo> = record
            .members
            .iter()
            .filter(|m| m.device != device && (m.admin || m.user == me))
            .cloned()
            .collect();
        let package = self.new_key_package(false, now_ms)?;
        self.file.key_packages.push(package.clone());
        let body = GroupBody::inline(*group, GroupKind::Rejoin, package.data);
        let envelopes = self.seal_to(&admins, &body)?;
        self.record_mut(group)?.state = GroupState::OutOfSync { since_ms: now_ms };
        self.persist()?;
        Ok(Outgoing {
            id: None,
            envelopes,
            uploads: Vec::new(),
        })
    }

    /// The invite link for `group`, naming this device as the one to ask:
    /// the request comes here, whichever of the admin's devices this is.
    pub fn invite_link(&mut self, group: &GroupId, relay: Option<String>) -> Result<GroupLink> {
        if !self.active(group)?.is_admin(&self.account()) {
            return Err(GroupError::NotAdmin);
        }
        let extension = self.extension(group)?;
        Ok(GroupLink {
            group: *group,
            via: self.device(),
            key: group::link_key(&extension.invite_key, group),
            relay,
        })
    }

    fn frame(
        &self,
        group: &GroupId,
        kind: GroupKind,
        message: Vec<u8>,
    ) -> Result<(GroupBody, Option<Upload>)> {
        if GroupBody::fits_inline(message.len()) {
            return Ok((GroupBody::inline(*group, kind, message), None));
        }
        if message.len() as u64 > MAX_FILE_BYTES {
            return Err(GroupError::Mls(
                "message too large for the blob store".into(),
            ));
        }
        let key = BlobKey::generate();
        let blob = new_blob_id();
        let size = message.len() as u64;
        let sha256: [u8; 32] = Sha256::digest(&message).into();
        let total = blob::chunk_count(size);
        let mut chunks = Vec::with_capacity(total as usize);
        for (index, piece) in message.chunks(CHUNK_BYTES).enumerate() {
            // The last chunk is padded to a whole one, as files are.
            let mut plain = piece.to_vec();
            plain.resize(CHUNK_BYTES, 0);
            chunks.push(blob::seal_chunk(&key, &blob, index as u32, total, &plain)?);
        }
        let reference = BlobRef {
            blob: blob.clone(),
            key,
            chunks: total,
            size,
            sha256,
        };
        Ok((
            GroupBody::parked(*group, kind, reference),
            Some(Upload { blob, chunks }),
        ))
    }

    /// The MLS message a parked body points at, from its fetched chunks.
    pub fn open_parked(reference: &BlobRef, chunks: &[Vec<u8>]) -> Result<Vec<u8>> {
        if chunks.len() != reference.chunks as usize {
            return Err(GroupError::Mls("wrong number of chunks".into()));
        }
        let mut message = Vec::with_capacity(reference.size as usize);
        for (index, chunk) in chunks.iter().enumerate() {
            message.extend(blob::open_chunk(
                &reference.key,
                &reference.blob,
                index as u32,
                reference.chunks,
                chunk,
            )?);
        }
        message.truncate(reference.size as usize);
        let sha256: [u8; 32] = Sha256::digest(&message).into();
        if sha256 != reference.sha256 {
            return Err(GroupError::Mls(
                "the parked message does not match its hash".into(),
            ));
        }
        Ok(message)
    }

    /// Seal `body` to each leaf: to its device, under its sealing key.
    fn seal_to(&self, members: &[MemberInfo], body: &GroupBody) -> Result<Vec<Envelope>> {
        let bytes = Body::Group(body.clone()).encode()?;
        members
            .iter()
            .map(|m| {
                Ok(seal_bytes_unsigned_to(
                    &self.identity,
                    m.device,
                    &m.seal,
                    &bytes,
                )?)
            })
            .collect()
    }

    // --- receiving -----------------------------------------------------------------

    /// Handle a group body addressed to us. `mls` is the MLS message, inline
    /// or fetched from the blob store ([`Groups::open_parked`]). `from` is
    /// the sealed layer's unauthenticated sender hint.
    pub fn receive(
        &mut self,
        from: UserId,
        body: &GroupBody,
        mls: &[u8],
        now_ms: u64,
    ) -> Result<Vec<GroupEvent>> {
        let group = body.group;
        let events = match body.kind {
            GroupKind::Welcome => self.receive_welcome(group, from, mls, now_ms)?,
            GroupKind::Handshake | GroupKind::Message => {
                self.receive_protocol_message(group, from, mls, now_ms)?
            }
            GroupKind::Join => self.receive_join(group, body, mls, now_ms)?,
            GroupKind::Rejoin => self.receive_rejoin(group, mls, now_ms)?,
        };
        self.persist()?;
        Ok(events)
    }

    fn receive_welcome(
        &mut self,
        group: GroupId,
        from: UserId,
        mls: &[u8],
        now_ms: u64,
    ) -> Result<Vec<GroupEvent>> {
        let previous = self.file.groups.get(&group).cloned();
        if let Some(record) = &previous {
            if matches!(
                record.state,
                GroupState::Active | GroupState::Invited { .. }
            ) {
                return Ok(vec![GroupEvent::Refused {
                    group,
                    reason: "a Welcome to a group we are in".into(),
                }]);
            }
            // Out of sync, removed, left or broken: whatever state is left
            // of the old membership goes; this Welcome starts afresh.
            self.drop_state(&group);
        }
        let welcome = parse_welcome(mls)?;
        let staged =
            StagedWelcome::new_from_welcome(&self.provider, &Self::join_config(), welcome, None)
                .map_err(mls_err)?;
        let sender = staged.welcome_sender().map_err(mls_err)?;
        let inviter = verify_leaf(sender, None)?;
        let context = staged.group_context();
        if context.ciphersuite() != CIPHERSUITE {
            return Err(GroupError::KeyPackage("wrong ciphersuite".into()));
        }
        if context.group_id().as_slice() != group.as_bytes() {
            return Err(GroupError::Mls("the Welcome names another group".into()));
        }
        let extension = extension_of(context.extensions())?;
        let me = self.account();
        // An admin adds anyone; one's own identity's device adds one's own.
        let inviter_in = staged
            .members()
            .any(|m| m.signature_key.as_slice() == inviter.device.as_bytes());
        if !inviter_in || !(extension.is_admin(&inviter.account) || inviter.account == me) {
            return Err(GroupError::Mls(
                "the Welcome does not come from an admin".into(),
            ));
        }
        let _ = from;
        // No second yes from the user for the answer to a join request we
        // sent this admin (by either id the link named), for a group the
        // primary named when this device was linked, or for one's own
        // identity's other device adding this one.
        let asked = self
            .file
            .joins
            .get(&group)
            .is_some_and(|via| *via == inviter.account || *via == inviter.device);
        let expected = self.file.expected.remove(&group);
        let ours = inviter.account == me;
        let taken = asked || expected.is_some() || ours;
        // Join now, so the group stays in sync while the user decides; the
        // key package that let us in is spent by this.
        let handle = staged.into_group(&self.provider).map_err(mls_err)?;
        let members = members_of(&handle, &extension)?;
        let epoch = handle.epoch().as_u64();
        let token = token_of(&handle, &group, self.provider.crypto())?;
        self.forget_spent_key_packages();
        self.handles.insert(group, handle);
        let record = GroupRecord {
            name: extension.name.clone(),
            alias: previous
                .as_ref()
                .and_then(|r| r.alias.clone())
                .or(expected.and_then(|e| e.alias)),
            members: members.clone(),
            state: if taken {
                GroupState::Active
            } else {
                GroupState::Invited {
                    from: inviter.account,
                }
            },
            tokens: vec![EpochToken { epoch, token }],
            held: Vec::new(),
            leaf_updated_ms: now_ms,
            created_at_ms: now_ms,
            muted: previous.as_ref().is_some_and(|r| r.muted),
            // A timer set while this device was last in the group stands
            // until an admin says otherwise; a newcomer is told the
            // group's timer by whoever added it.
            expire_after_s: previous.as_ref().map_or(0, |r| r.expire_after_s),
            seen: previous.map(|r| r.seen).unwrap_or_default(),
        };
        self.file.groups.insert(group, record);
        if taken {
            self.file.joins.remove(&group);
            self.persist()?;
            return Ok(vec![GroupEvent::Joined { group }]);
        }
        Ok(vec![GroupEvent::Invited {
            held: HeldWelcome {
                group,
                from: inviter.account,
                name: extension.name,
                members: identities(&members),
                received_at_ms: now_ms,
            },
        }])
    }

    /// Key packages whose secret is gone were used by a Welcome; drop them
    /// from the deposit list.
    fn forget_spent_key_packages(&mut self) {
        let crypto = self.provider.crypto();
        let storage = self.provider.storage();
        self.file.key_packages.retain(|p| {
            parse_key_package(&p.data, crypto)
                .and_then(|kp| kp.hash_ref(crypto).map_err(mls_err))
                .map(|r| {
                    storage
                        .key_package::<_, KeyPackageBundle>(&r)
                        .ok()
                        .flatten()
                        .is_some()
                })
                .unwrap_or(false)
        });
    }

    /// Say yes to an invitation: the group becomes active.
    pub fn accept_welcome(&mut self, group: &GroupId) -> Result<()> {
        let record = self.record_mut(group)?;
        match record.state {
            GroupState::Invited { .. } => record.state = GroupState::Active,
            _ => return Err(GroupError::NotActive("not an invitation".into())),
        }
        self.persist()
    }

    /// Say no: the state goes, and the group with it. The admin's group
    /// keeps a dead leaf until they notice and remove it.
    pub fn decline_welcome(&mut self, group: &GroupId) -> Result<()> {
        if !matches!(self.record(group)?.state, GroupState::Invited { .. }) {
            return Err(GroupError::NotActive("not an invitation".into()));
        }
        self.drop_state(group);
        self.file.groups.remove(group);
        self.persist()
    }

    fn receive_protocol_message(
        &mut self,
        group: GroupId,
        from: UserId,
        mls: &[u8],
        now_ms: u64,
    ) -> Result<Vec<GroupEvent>> {
        match self.record(&group)?.state {
            GroupState::Active | GroupState::Invited { .. } | GroupState::OutOfSync { .. } => {}
            // Left, removed or broken: what was in flight when that
            // happened (the commit taking a leaver out, a message sent
            // before the removal reached its sender) is expected and says
            // nothing new.
            _ => return Ok(Vec::new()),
        }
        let mut events = self.process_one(group, from, mls, now_ms)?;
        // Held messages may be readable now.
        let mut progressed = true;
        while progressed {
            progressed = false;
            let held: Vec<Held> = std::mem::take(&mut self.record_mut(&group)?.held);
            for item in held {
                if item.received_at_ms + HOLD_FOR_MS <= now_ms {
                    continue;
                }
                let before = self.record(&group)?.held.len();
                let more = self.process_one(group, item.from, &item.mls, now_ms)?;
                if self.record(&group)?.held.len() == before {
                    progressed = true;
                }
                events.extend(more);
            }
        }
        Ok(events)
    }

    fn process_one(
        &mut self,
        group: GroupId,
        from: UserId,
        mls: &[u8],
        now_ms: u64,
    ) -> Result<Vec<GroupEvent>> {
        let message =
            MlsMessageIn::tls_deserialize_exact(mls).map_err(|e| GroupError::Mls(e.to_string()))?;
        let protocol: ProtocolMessage = message
            .try_into_protocol_message()
            .map_err(|e| GroupError::Mls(e.to_string()))?;
        if protocol.group_id().as_slice() != group.as_bytes() {
            return Ok(vec![GroupEvent::Refused {
                group,
                reason: "the message names another group".into(),
            }]);
        }
        let message_epoch = protocol.epoch().as_u64();
        let is_handshake = protocol.is_handshake_message();
        let me = self.identity.user_id();
        let crypto = self.provider.crypto();
        let handle = load_handle(&mut self.handles, &self.provider, &group)?;
        let our_epoch = handle.epoch().as_u64();
        if is_handshake && message_epoch > our_epoch {
            // From the future: hold it, unless the hold queue is full.
            let record = self
                .file
                .groups
                .get_mut(&group)
                .ok_or(GroupError::NoSuchGroup)?;
            record
                .held
                .retain(|h| h.received_at_ms + HOLD_FOR_MS > now_ms);
            if record.held.len() >= HOLD_LIMIT || message_epoch > our_epoch + HOLD_LIMIT as u64 {
                record.state = GroupState::OutOfSync { since_ms: now_ms };
                return Ok(vec![GroupEvent::OutOfSync { group }]);
            }
            record.held.push(Held {
                received_at_ms: now_ms,
                from,
                mls: mls.to_vec(),
            });
            return Ok(Vec::new());
        }
        let processed = match handle.process_message(&self.provider, protocol) {
            Ok(processed) => processed,
            Err(e) => {
                return Ok(vec![GroupEvent::Refused {
                    group,
                    reason: format!("could not read a group message: {e}"),
                }]);
            }
        };
        let sender_index = match processed.sender() {
            Sender::Member(index) => Some(*index),
            _ => None,
        };
        let sender = match sender_index.map(|i| leaf_at(handle, i)) {
            Some(leaf) => leaf?.account,
            None => {
                return Ok(vec![GroupEvent::Refused {
                    group,
                    reason: "a message from outside the group".into(),
                }]);
            }
        };
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(application) => {
                let plain = GroupPlaintext::decode(&application.into_bytes())?;
                let record = self
                    .file
                    .groups
                    .get_mut(&group)
                    .ok_or(GroupError::NoSuchGroup)?;
                if record.seen.contains(&plain.id) {
                    return Ok(Vec::new());
                }
                record.seen.push_back(plain.id.clone());
                while record.seen.len() > SEEN_IDS {
                    record.seen.pop_front();
                }
                let mut events = Vec::new();
                if let Some(head) = plain.head {
                    events.push(GroupEvent::Head { from: sender, head });
                }
                events.push(GroupEvent::Message {
                    group,
                    from: sender,
                    id: plain.id,
                    sent_at_ms: plain.sent_at_ms,
                    content: plain.content,
                });
                Ok(events)
            }
            ProcessedMessageContent::ProposalMessage(proposal) => {
                // Only a leaf's own leave is proposed by reference; admins
                // commit it next.
                let ours = match proposal.proposal() {
                    Proposal::Remove(remove) => Some(remove.removed()) == sender_index,
                    _ => false,
                };
                if !ours {
                    return Ok(vec![GroupEvent::Refused {
                        group,
                        reason: "a proposal only an admin's commit may make".into(),
                    }]);
                }
                handle
                    .store_pending_proposal(self.provider.storage(), *proposal)
                    .map_err(mls_err)?;
                Ok(vec![GroupEvent::LeaveProposed {
                    group,
                    member: sender,
                }])
            }
            ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                Ok(vec![GroupEvent::Refused {
                    group,
                    reason: "external joins are not allowed".into(),
                }])
            }
            ProcessedMessageContent::OwnPendingCommit
            | ProcessedMessageContent::OwnPrivateMessage => {
                // Our own message came back to us; nothing to do.
                Ok(Vec::new())
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                let extension_before = extension_of(handle.extensions())?;
                let verdict = check_commit(handle, &staged, &sender, &extension_before);
                match verdict {
                    Err(reason) => {
                        let record = self
                            .file
                            .groups
                            .get_mut(&group)
                            .ok_or(GroupError::NoSuchGroup)?;
                        record.state = GroupState::Broken {
                            by: sender,
                            reason: reason.clone(),
                        };
                        Ok(vec![GroupEvent::Broken {
                            group,
                            by: sender,
                            reason,
                        }])
                    }
                    Ok(change) => {
                        let removed_us = staged.self_removed();
                        let extension_after = extension_of(staged.group_context().extensions())?;
                        // Our own pending commit, if any, lost the race.
                        if handle.pending_commit().is_some() {
                            handle
                                .clear_pending_commit(self.provider.storage())
                                .map_err(mls_err)?;
                            self.staged.remove(&group);
                        }
                        handle
                            .merge_staged_commit(&self.provider, *staged)
                            .map_err(mls_err)?;
                        let mut events = Vec::new();
                        if removed_us {
                            self.drop_state(&group);
                            let record = self
                                .file
                                .groups
                                .get_mut(&group)
                                .ok_or(GroupError::NoSuchGroup)?;
                            record.state = GroupState::Removed { by: sender };
                            events.push(GroupEvent::Removed { group, by: sender });
                            return Ok(events);
                        }
                        let epoch = handle.epoch().as_u64();
                        let token = token_of(handle, &group, crypto)?;
                        let members = members_of(handle, &extension_after)?;
                        let record = self
                            .file
                            .groups
                            .get_mut(&group)
                            .ok_or(GroupError::NoSuchGroup)?;
                        let before = record.identities();
                        record.members = members;
                        record.name = extension_after.name.clone();
                        if matches!(record.state, GroupState::OutOfSync { .. }) {
                            record.state = GroupState::Active;
                        }
                        push_token(record, epoch, token);
                        let after = record.identities();
                        for change in describe(
                            change,
                            &before,
                            &after,
                            &extension_before,
                            &extension_after,
                            me,
                        ) {
                            events.push(GroupEvent::Changed {
                                group,
                                by: sender,
                                change,
                            });
                        }
                        Ok(events)
                    }
                }
            }
        }
    }

    fn receive_join(
        &mut self,
        group: GroupId,
        body: &GroupBody,
        mls: &[u8],
        now_ms: u64,
    ) -> Result<Vec<GroupEvent>> {
        let Some(proof) = body.join else {
            return Ok(vec![GroupEvent::Refused {
                group,
                reason: "a join request without its proof".into(),
            }]);
        };
        let record = match self.file.groups.get(&group) {
            Some(record) if record.state == GroupState::Active => record.clone(),
            _ => return Ok(Vec::new()),
        };
        if !record.is_admin(&self.account()) {
            return Ok(Vec::new());
        }
        let kp = parse_key_package(mls, self.provider.crypto())?;
        let leaf = verify_leaf(kp.leaf_node(), None)?;
        let joiner = leaf.account;
        let extension = self.extension(&group)?;
        if !group::verify_join_proof(&extension.invite_key, &group, &joiner, &proof.proof) {
            return Ok(vec![GroupEvent::Refused {
                group,
                reason: format!("{} presented a link that is not valid", joiner.short()),
            }]);
        }
        // A device already in asks for nothing; an identity's further
        // device may join by the link like anyone.
        if record.members.iter().any(|m| m.device == leaf.device) {
            return Ok(Vec::new());
        }
        let _ = now_ms;
        Ok(vec![GroupEvent::JoinRequest {
            group,
            joiner,
            key_package: mls.to_vec(),
        }])
    }

    fn receive_rejoin(
        &mut self,
        group: GroupId,
        mls: &[u8],
        _now_ms: u64,
    ) -> Result<Vec<GroupEvent>> {
        let record = match self.file.groups.get(&group) {
            Some(record) if record.state == GroupState::Active => record.clone(),
            _ => return Ok(Vec::new()),
        };
        let me = self.account();
        let kp = parse_key_package(mls, self.provider.crypto())?;
        let leaf = verify_leaf(kp.leaf_node(), None)?;
        // An admin answers anyone's; one's own identity's other device
        // answers one's own.
        if !record.is_admin(&me) && leaf.account != me {
            return Ok(Vec::new());
        }
        if !record.members.iter().any(|m| m.device == leaf.device) {
            return Ok(vec![GroupEvent::Refused {
                group,
                reason: format!(
                    "{} asked to rejoin a group they are not in",
                    leaf.account.short()
                ),
            }]);
        }
        Ok(vec![GroupEvent::RejoinRequest {
            group,
            member: leaf.account,
            key_package: mls.to_vec(),
        }])
    }

    /// Stage a commit that removes the leaf a rejoin request came from
    /// and adds it back from the fresh key package; `member` is the
    /// identity the request named.
    pub fn stage_rejoin(
        &mut self,
        group: &GroupId,
        member: UserId,
        key_package: &[u8],
    ) -> Result<Staged> {
        let me = self.account();
        let record = self.active(group)?.clone();
        if !record.is_admin(&me) && member != me {
            return Err(GroupError::NotAdmin);
        }
        let kp = parse_key_package(key_package, self.provider.crypto())?;
        let leaf = verify_leaf(kp.leaf_node(), Some(&member))?;
        let index = {
            let handle = load_handle(&mut self.handles, &self.provider, group)?;
            leaves_of(handle)?
                .into_iter()
                .find(|(_, l)| l.device == leaf.device)
                .map(|(index, _)| index)
                .ok_or(GroupError::NotAMember(member))?
        };
        let was_admin = record.is_admin(&member);
        let added = vec![MemberInfo {
            user: leaf.account,
            device: leaf.device,
            seal: leaf.seal,
            admin: was_admin,
        }];
        self.stage(
            group,
            move |builder| Ok(builder.propose_removals([index]).propose_adds([kp])),
            added,
            Change::Updated,
        )
    }

    /// Ask that a group be marked out of sync (a commit was missed for
    /// good).
    pub fn mark_out_of_sync(&mut self, group: &GroupId, now_ms: u64) -> Result<()> {
        self.record_mut(group)?.state = GroupState::OutOfSync { since_ms: now_ms };
        self.persist()
    }

    fn extension(&mut self, group: &GroupId) -> Result<SilverGroup> {
        let handle = load_handle(&mut self.handles, &self.provider, group)?;
        extension_of(handle.extensions())
    }

    /// The MLS storage, for tests.
    #[doc(hidden)]
    pub fn provider(&self) -> &Provider {
        &self.provider
    }
}

// --- helpers -------------------------------------------------------------------

fn mls_id(group: &GroupId) -> MlsGroupId {
    MlsGroupId::from_slice(group.as_bytes())
}

/// The MLS handle of `group`, loaded from storage the first time.
fn load_handle<'a>(
    handles: &'a mut HashMap<GroupId, MlsGroup>,
    provider: &Provider,
    group: &GroupId,
) -> Result<&'a mut MlsGroup> {
    if !handles.contains_key(group) {
        let loaded = MlsGroup::load(provider.storage(), &mls_id(group))
            .map_err(mls_err)?
            .ok_or(GroupError::NoSuchGroup)?;
        handles.insert(*group, loaded);
    }
    Ok(handles.get_mut(group).expect("just inserted"))
}

fn token_of(handle: &MlsGroup, group: &GroupId, crypto: &impl OpenMlsCrypto) -> Result<[u8; 32]> {
    handle
        .export_secret(crypto, SEQUENCER_LABEL, group.as_bytes(), 32)
        .map_err(mls_err)?
        .try_into()
        .map_err(|_| GroupError::Mls("exporter length".into()))
}

fn push_token(record: &mut GroupRecord, epoch: u64, token: [u8; 32]) {
    record.tokens.retain(|t| t.epoch < epoch);
    record.tokens.push(EpochToken { epoch, token });
    while record.tokens.len() > TOKENS_KEPT {
        record.tokens.remove(0);
    }
}

fn parse_key_package(data: &[u8], crypto: &impl OpenMlsCrypto) -> Result<KeyPackage> {
    let message = MlsMessageIn::tls_deserialize_exact(data)
        .map_err(|e| GroupError::KeyPackage(e.to_string()))?;
    let MlsMessageBodyIn::KeyPackage(kp) = message.extract() else {
        return Err(GroupError::KeyPackage("not a key package".into()));
    };
    kp.validate(crypto, ProtocolVersion::Mls10)
        .map_err(|e| GroupError::KeyPackage(e.to_string()))
}

fn parse_welcome(data: &[u8]) -> Result<Welcome> {
    let message =
        MlsMessageIn::tls_deserialize_exact(data).map_err(|e| GroupError::Mls(e.to_string()))?;
    match message.extract() {
        MlsMessageBodyIn::Welcome(welcome) => Ok(welcome),
        _ => Err(GroupError::Mls("not a Welcome".into())),
    }
}

/// The identity a credential and signature key stand for: the credential's
/// identity must be the signature key, and a valid user id.
/// What a verified leaf says: whose it is, which device signed it, and
/// how to seal to it.
#[derive(Clone, Debug)]
struct Leaf {
    account: UserId,
    device: UserId,
    seal: DhPublic,
}

/// The identity a leaf belongs to (`docs/PROTOCOL.md` section 13.1 and
/// 14): the credential names it; the signature key is that identity's
/// own, or a device key the leaf's `silver_device` certificate binds to
/// it, signed by the identity.
fn identity_of(leaf: &LeafNode) -> Result<(UserId, UserId)> {
    let bytes: [u8; 32] = leaf
        .credential()
        .serialized_content()
        .try_into()
        .map_err(|_| GroupError::KeyPackage("credential is not a user id".into()))?;
    let account = UserId::from_bytes(bytes)
        .map_err(|_| GroupError::KeyPackage("credential is not a valid key".into()))?;
    let signature_key = leaf.signature_key().as_slice();
    if signature_key == bytes.as_slice() {
        return Ok((account, account));
    }
    let Some(extension) = leaf.extensions().unknown(EXTENSION_DEVICE) else {
        return Err(GroupError::KeyPackage(
            "credential and signature key differ, and no device certificate says why".into(),
        ));
    };
    let certificate = DeviceCertificate::decode(&extension.0)
        .map_err(|e| GroupError::KeyPackage(format!("device certificate: {e}")))?;
    if certificate.account != account || certificate.device.as_bytes() != signature_key {
        return Err(GroupError::KeyPackage(
            "the device certificate is not for this leaf".into(),
        ));
    }
    certificate
        .verify()
        .map_err(|_| GroupError::KeyPackage("the device certificate does not verify".into()))?;
    Ok((account, certificate.device))
}

/// Check a leaf: identity as above (`expected`'s, when given), and the
/// sealing key present.
fn verify_leaf(leaf: &LeafNode, expected: Option<&UserId>) -> Result<Leaf> {
    let (account, device) = identity_of(leaf)?;
    if let Some(expected) = expected {
        if account != *expected {
            return Err(GroupError::KeyPackage("signed by another identity".into()));
        }
    }
    let seal = leaf
        .extensions()
        .unknown(EXTENSION_SEAL)
        .ok_or_else(|| GroupError::KeyPackage("no sealing key in the leaf".into()))?;
    let seal = decode_seal_key(&seal.0)?;
    Ok(Leaf {
        account,
        device,
        seal,
    })
}

/// The leaf at `index` in `tree`, found by the signature key OpenMLS
/// reports for the member there (every leaf's is distinct).
fn leaf_in(tree: &RatchetTree, member: &Member) -> Result<Leaf> {
    let leaf = tree
        .leaves()
        .find(|l| l.signature_key().as_slice() == member.signature_key.as_slice())
        .ok_or_else(|| GroupError::Mls("a member without a leaf".into()))?;
    verify_leaf(leaf, None)
}

/// The leaf at `index`, verified.
fn leaf_at(handle: &MlsGroup, index: LeafNodeIndex) -> Result<Leaf> {
    let member = handle
        .member_at(index)
        .ok_or_else(|| GroupError::Mls("nobody at that leaf".into()))?;
    leaf_in(&handle.export_ratchet_tree(), &member)
}

/// Every leaf of the tree with its index, verified.
fn leaves_of(handle: &MlsGroup) -> Result<Vec<(LeafNodeIndex, Leaf)>> {
    let tree = handle.export_ratchet_tree();
    handle
        .members()
        .map(|member| Ok((member.index, leaf_in(&tree, &member)?)))
        .collect()
}

fn extension_of(extensions: &Extensions<GroupContext>) -> Result<SilverGroup> {
    let raw = extensions
        .unknown(EXTENSION_GROUP)
        .ok_or_else(|| GroupError::Mls("the group has no silver extension".into()))?;
    Ok(SilverGroup::decode(&raw.0)?)
}

fn context_extensions(extension: &SilverGroup) -> Result<Extensions<GroupContext>> {
    Extensions::from_vec(vec![
        Extension::Unknown(EXTENSION_GROUP, UnknownExtension(extension.encode()?)),
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[
                ExtensionType::Unknown(EXTENSION_GROUP),
                ExtensionType::Unknown(EXTENSION_SEAL),
            ],
            &[],
            &[],
        )),
    ])
    .map_err(mls_err)
}

/// Every leaf of the tree with its sealing key, admins marked.
fn members_of(handle: &MlsGroup, extension: &SilverGroup) -> Result<Vec<MemberInfo>> {
    let mut members = Vec::new();
    for (_, leaf) in leaves_of(handle)? {
        members.push(MemberInfo {
            user: leaf.account,
            device: leaf.device,
            seal: leaf.seal,
            admin: extension.is_admin(&leaf.account),
        });
    }
    Ok(members)
}

/// The membership rules of `docs/design/groups.md` 7.6, with devices
/// (`docs/design/devices.md` 6.3), checked on a commit from `committer`
/// against the group as it stood before: an admin adds and removes
/// anyone, any member adds and removes leaves of its own identity, and
/// only an admin changes the settings. `Ok` says what the commit does to
/// the membership as identities.
fn check_commit(
    handle: &MlsGroup,
    staged: &StagedCommit,
    committer: &UserId,
    before: &SilverGroup,
) -> std::result::Result<Change, String> {
    let admin = before.is_admin(committer);
    let adds: Vec<Leaf> = staged
        .add_proposals()
        .map(|p| verify_leaf(p.add_proposal().key_package().leaf_node(), None))
        .collect::<Result<_>>()
        .map_err(|e| format!("an added leaf is not valid: {e}"))?;
    let leaves = leaves_of(handle).map_err(|e| e.to_string())?;
    // Leaves removed: whose, and whether by the leaf's own proposal.
    let mut removed_indices = Vec::new();
    let mut removed: Vec<(UserId, bool)> = Vec::new();
    for proposal in staged.remove_proposals() {
        let index = proposal.remove_proposal().removed();
        let who = leaves
            .iter()
            .find(|(i, _)| *i == index)
            .map(|(_, leaf)| leaf.account)
            .ok_or_else(|| "a removal of nobody".to_owned())?;
        let by_self = matches!(proposal.sender(), Sender::Member(i) if *i == index);
        removed_indices.push(index);
        removed.push((who, by_self));
    }
    let changes_context = staged
        .queued_proposals()
        .any(|p| matches!(p.proposal(), Proposal::GroupContextExtensions(_)));
    let context = staged.group_context();
    if !admin && adds.iter().any(|leaf| leaf.account != *committer) {
        return Err(format!(
            "{} added members without being an admin",
            committer.short()
        ));
    }
    if !admin && removed.iter().any(|(who, _)| who != committer) {
        return Err(format!(
            "{} removed members without being an admin",
            committer.short()
        ));
    }
    if changes_context && !admin {
        return Err(format!(
            "{} changed the group's settings without being an admin",
            committer.short()
        ));
    }
    if context.ciphersuite() != CIPHERSUITE {
        return Err("the commit changes the ciphersuite".into());
    }
    let after = extension_of(context.extensions()).map_err(|e| e.to_string())?;
    let required = context
        .extensions()
        .required_capabilities()
        .map(|r| r.extension_types().to_vec())
        .unwrap_or_default();
    if !required.contains(&ExtensionType::Unknown(EXTENSION_GROUP))
        || !required.contains(&ExtensionType::Unknown(EXTENSION_SEAL))
    {
        return Err("the commit drops the required extensions".into());
    }
    if after.admins.is_empty() {
        return Err("the commit leaves the group without an admin".into());
    }
    // The membership as identities, before and after.
    let mut ids_before: Vec<UserId> = Vec::new();
    for (_, leaf) in &leaves {
        if !ids_before.contains(&leaf.account) {
            ids_before.push(leaf.account);
        }
    }
    let mut ids_after: Vec<UserId> = Vec::new();
    for (index, leaf) in &leaves {
        if !removed_indices.contains(index) && !ids_after.contains(&leaf.account) {
            ids_after.push(leaf.account);
        }
    }
    for leaf in &adds {
        if !ids_after.contains(&leaf.account) {
            ids_after.push(leaf.account);
        }
    }
    if after.admins.iter().any(|a| !ids_after.contains(a)) {
        return Err("the commit names an admin who is not a member".into());
    }
    if ids_after.len() > MAX_MEMBERS {
        return Err("the commit makes the group too large".into());
    }
    let added: Vec<UserId> = ids_after
        .iter()
        .filter(|u| !ids_before.contains(u))
        .copied()
        .collect();
    let gone: Vec<UserId> = ids_before
        .iter()
        .filter(|u| !ids_after.contains(u))
        .copied()
        .collect();
    // An identity whose every leaf went by its own proposals left; the
    // rest were removed.
    let (left, removed_ids): (Vec<UserId>, Vec<UserId>) = gone.into_iter().partition(|u| {
        removed
            .iter()
            .filter(|(who, _)| who == u)
            .all(|(_, by_self)| *by_self)
    });
    if !added.is_empty() {
        Ok(Change::Added(added))
    } else if !removed_ids.is_empty() {
        Ok(Change::Removed(removed_ids))
    } else if !left.is_empty() {
        Ok(Change::Left(left))
    } else {
        // A device came or went, the settings changed, or a leaf was
        // refreshed; `describe` tells the settings apart.
        Ok(Change::Updated)
    }
}

/// What to tell the front end about a commit, from the before and after.
fn describe(
    change: Change,
    before: &[UserId],
    after: &[UserId],
    ext_before: &SilverGroup,
    ext_after: &SilverGroup,
    me: UserId,
) -> Vec<Change> {
    let mut changes = Vec::new();
    match change {
        Change::Added(_) | Change::Removed(_) | Change::Left(_) => changes.push(change),
        _ => {}
    }
    let _ = (before, after, me);
    if ext_before.name != ext_after.name {
        changes.push(Change::Renamed(ext_after.name.clone()));
    }
    if ext_before.admins != ext_after.admins {
        changes.push(Change::Admins(ext_after.admins.clone()));
    }
    if ext_before.invite_key != ext_after.invite_key {
        changes.push(Change::LinkReset);
    }
    if changes.is_empty() {
        changes.push(Change::Updated);
    }
    changes
}

impl Store {
    pub(crate) fn load_groups(&self) -> anyhow::Result<GroupsFile> {
        self.read_json_or_default(GROUPS_FILE)
    }

    /// Whether any group is known here, in whatever state.
    pub(crate) fn has_groups(&self) -> anyhow::Result<bool> {
        let file = self.load_groups()?;
        Ok(!file.groups.is_empty() || !file.expected.is_empty())
    }

    pub(crate) fn save_groups(&self, file: &GroupsFile) -> anyhow::Result<()> {
        self.write_json_private(GROUPS_FILE, file)
    }

    pub(crate) fn load_mls(&self) -> anyhow::Result<Option<Vec<u8>>> {
        self.read_private_file(MLS_FILE)
    }

    pub(crate) fn save_mls(&self, bytes: &[u8]) -> anyhow::Result<()> {
        self.write_private_file(MLS_FILE, bytes)
    }
}

#[cfg(test)]
mod tests;
