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
use silver_protocol::blob::{self, BlobKey, CHUNK_BYTES, new_blob_id};
use silver_protocol::device::MAX_DEVICES;
use silver_protocol::encoding::b64_array;
use silver_protocol::group::{
    self, BlobRef, EXTENSION_DEVICE, EXTENSION_EVERYDAY, EXTENSION_GROUP, EXTENSION_SEAL,
    GroupBody, GroupId, GroupKind, GroupPlaintext, MAX_KEY_PACKAGES, MAX_MEMBERS, MAX_PARKED_BYTES,
    MAX_PARKED_HANDSHAKE_BYTES, REJOIN_PROOF_DOMAIN, SEQUENCER_LABEL, SilverGroup, decode_seal_key,
    encode_seal_key, rejoin_statement,
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
/// Invitations waiting for an answer at once.
///
/// A Welcome needs no permission from the person it invites, and the
/// last-resort key package is reusable, so a stranger can send as many as
/// it likes for group ids it invents. Each one is a full MLS tree on
/// disk. Beyond this many, another is refused until one is answered.
pub const MAX_INVITATIONS: usize = 20;
/// Join requests one invite link is answered for before the admin has to
/// reset it ([`LinkUses`]).
pub const MAX_LINK_JOINS: u32 = 32;
/// Handshake messages from a future epoch held, and for how long.
pub const HOLD_LIMIT: usize = 16;
/// Most bytes held for one group at a time. Nothing held has been read
/// yet, so this is what an unauthenticated sender can make a client keep
/// in memory and write into `groups.json`. Only a message that fitted
/// inside its envelope is held, so the count already bounds this; saying
/// it as bytes as well keeps the bound if either constant moves, and
/// leaves honest commits, which are far smaller, room to cross. Sixteen
/// of the largest message that fits an envelope is a little under this.
pub const HOLD_BYTES: usize = 384 * 1024;
pub const HOLD_FOR_MS: u64 = 10 * 60 * 1000;
/// How long the commits the relay's sequencer says we are missing have to
/// arrive before the group counts as out of sync; also how long a
/// handshake from a later epoch waits before this client asks the
/// sequencer where the group stands.
///
/// A commit race lost honestly leaves the loser one epoch behind for as
/// long as the winner's commit takes to arrive, which is seconds; a
/// commit missed for good leaves it there. Only the sequencer's word,
/// given twice this far apart, tells the two apart without trusting a
/// header anyone can write.
pub const BEHIND_GRACE_MS: u64 = 2 * 60 * 1000;
/// At most one self-update this often on the strength of a handshake
/// from a later epoch: that is an unauthenticated hint, and the
/// self-update that asks the sequencer is a commit to every member.
pub const PROBE_EVERY_MS: u64 = 60 * 60 * 1000;
/// How long a join request this client sent stays answerable by a
/// Welcome taken without asking the user again.
pub const JOIN_ANSWER_FOR_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// Identities remembered per group as removed from it.
const REMOVED_KEPT: usize = MAX_MEMBERS;
/// Revoked devices remembered.
const REVOKED_KEPT: usize = 4096;
/// Groups forgotten or declined whose last epoch is remembered.
const FORGOTTEN_KEPT: usize = 256;
/// Message ids remembered per group, against duplicates.
const SEEN_IDS: usize = 256;
/// Application messages from this many past epochs still decrypt.
const PAST_EPOCHS: usize = 3;
/// How far out of order one sender's application messages may arrive and
/// still be read, and how many of theirs may be skipped.
///
/// A relay drains a mailbox in whatever order it was filled and a client
/// may fetch two of them at once, so messages from one sender do overtake
/// each other; OpenMLS's default tolerance of five generations is well
/// under what that produces in a busy group, and past it a message is
/// reported unreadable rather than late. Sixty-four matches the ratchet's
/// window for one-to-one conversations (`docs/design/groups.md` section
/// 4.2). The cost is that a decryption secret is kept until it is used or
/// the window passes it, so forward secrecy within an epoch lags by up to
/// that many messages from the same sender.
const OUT_OF_ORDER: u32 = 64;
const FORWARD_DISTANCE: u32 = 1000;

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

/// The short forms of `ids`, for a message that names members.
fn short_list(ids: &[UserId]) -> String {
    ids.iter()
        .map(|u| format!("{}…", u.short()))
        .collect::<Vec<_>>()
        .join(", ")
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
    /// This account was named an admin by the Welcome that brought it in,
    /// rather than by a commit somebody made after it joined.
    ///
    /// A Welcome's `silver_group` extension is written by whoever built
    /// the Welcome, so "you are an admin here" is the inviter's own word.
    /// A hostile contact can therefore hand somebody a group in which
    /// they are an admin, and every automatic thing an admin's client
    /// does — answering a join request with a commit and a Welcome,
    /// re-adding a member who says it is out of sync — becomes work the
    /// inviter can ask for at will (SM-G-06). Such a group does the
    /// admin's work only when the user asks for it.
    #[serde(default)]
    pub conferred_admin: bool,
    /// How often the group's current invite link has been answered, and
    /// which link that was; see [`LinkUses`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_uses: Option<LinkUses>,
    /// This admin device's own secret for the group's invite links.
    ///
    /// Links used to be derived from an invite key in the group context,
    /// which every member reads — so any member, and a member removed
    /// later, could make a valid link and have the admin's client add
    /// whoever presented it. The secret now lives here only, on
    /// the admin device that made the link, which is the device the link
    /// names; `/group link reset` replaces it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    link_secret: Option<LinkSecret>,
    /// Identities this client saw removed from the group, most recent
    /// last. A link presented by one of them is shown to the admin rather
    /// than answered: whoever removed them meant them out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed: Vec<UserId>,
    /// The relay's sequencer said the group stands past our epoch; see
    /// [`Groups::sequencer_ahead`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    behind: Option<Behind>,
    /// When a handshake from beyond our epoch was last refused or held: a
    /// reason to ask the sequencer, never one to change state by itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ahead_seen_ms: Option<u64>,
}

/// An invite-link secret. Kept out of `Debug`, which reaches logs.
#[derive(Clone, Serialize, Deserialize)]
struct LinkSecret {
    #[serde(with = "b64_array")]
    key: [u8; 32],
}

impl std::fmt::Debug for LinkSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LinkSecret(..)")
    }
}

/// The sequencer's word that the group is ahead of us, and since when.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct Behind {
    epoch: u64,
    since_ms: u64,
}

/// A group forgotten or declined, and the newest epoch this client knew
/// of it, so that an old Welcome replayed for it is not taken again.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Forgotten {
    group: GroupId,
    epoch: u64,
}

/// What one invite link has cost this admin so far.
///
/// A link is a key, not a ticket: everyone who holds it presents the same
/// proof, and each valid one an admin sees is a commit and a Welcome
/// sealed to every member. Left unbounded, a link that leaks — posted in
/// a channel, forwarded past the room it was meant for — is a stranger's
/// switch for the admin's client, up to the group's whole capacity
/// (SM-G-13). So the uses are counted, and past [`MAX_LINK_JOINS`] the
/// admin is asked to reset the link rather than the requests being
/// answered. The count is against the link it was for, so
/// `/group link reset` starts it again.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LinkUses {
    #[serde(with = "b64_array")]
    pub link: [u8; 16],
    pub used: u32,
}

/// A group alias as it is stored: only what a terminal will draw, and no
/// more of it than fits a name.
///
/// An alias is the user's own word for a group — typed here, or synced
/// from another of their devices — so this is not defence against a
/// peer. It is defence against a paste: `display_name()` reaches the
/// reader's compose prompt, which is the one peer-influenced string the
/// interface writes without going through the cell buffer, and an alias
/// carrying an escape sequence would arrive there intact.
fn clean_alias(alias: Option<String>) -> Option<String> {
    alias
        .map(|a| crate::files::printable(&a, crate::files::MAX_ALIAS_CHARS))
        .filter(|a| !a.is_empty())
}

impl GroupRecord {
    /// The alias if one is set, otherwise the group's name.
    ///
    /// The alias is reduced to what can be seen even if the file on disk
    /// says otherwise, exactly as a contact's is: it reaches window
    /// titles, notifications and the reader's compose prompt, not only
    /// the cell buffer, and a file written by an older version may hold
    /// one that was never filtered. The group *name* needs no filtering
    /// here — `SilverGroup::check` refuses control characters in it on
    /// every receive path — but it costs nothing to pass both through
    /// the same door.
    pub fn display_name(&self) -> String {
        match clean_alias(self.alias.clone()) {
            Some(alias) => alias,
            None if self.name.is_empty() => "(unnamed group)".to_owned(),
            None => crate::files::printable(&self.name, silver_protocol::group::MAX_NAME_BYTES),
        }
    }

    pub fn is_admin(&self, user: &UserId) -> bool {
        self.members.iter().any(|m| m.user == *user && m.admin)
    }

    /// The group reached `epoch`: what said it was behind is settled as
    /// far as that goes.
    fn caught_up(&mut self, epoch: u64) {
        if self.behind.is_some_and(|b| epoch >= b.epoch) {
            self.behind = None;
        }
        if self.held.is_empty() {
            self.ahead_seen_ms = None;
        }
    }

    /// The newest epoch this record knew.
    fn last_epoch(&self) -> Option<u64> {
        self.tokens.iter().map(|t| t.epoch).max()
    }

    /// Note what a commit did to who is in: identities removed are
    /// remembered, and one added again is no longer held against them.
    fn note_change(&mut self, change: &Change) {
        match change {
            Change::Removed(users) => {
                for user in users {
                    self.removed.retain(|u| u != user);
                    self.removed.push(*user);
                }
                while self.removed.len() > REMOVED_KEPT {
                    self.removed.remove(0);
                }
            }
            Change::Added(users) => self.removed.retain(|u| !users.contains(u)),
            _ => {}
        }
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
    /// is taken without asking the user again, for
    /// [`JOIN_ANSWER_FOR_MS`] after the request.
    #[serde(default)]
    joins: BTreeMap<GroupId, UserId>,
    /// When each request in `joins` went out. A request from a version
    /// that did not record it counts as expired: its Welcome is an
    /// ordinary invitation.
    #[serde(default)]
    joins_at: BTreeMap<GroupId, u64>,
    /// Devices whose revocation this client was told of
    /// ([`Groups::note_revoked_devices`]): no Welcome from one is taken,
    /// and no request from one is answered.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    revoked: Vec<UserId>,
    /// Groups forgotten or declined, with the last epoch known of each.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    forgotten: Vec<Forgotten>,
    /// Groups this account is in, as the primary named them when this
    /// device was linked (`docs/design/devices.md` section 7.4): the
    /// Welcome the primary sends for each is taken without asking, and
    /// the alias is known from the start.
    #[serde(default)]
    expected: BTreeMap<GroupId, ExpectedGroup>,
}

impl GroupsFile {
    /// Each group's name as shown, by id.
    pub(crate) fn names(&self) -> BTreeMap<GroupId, String> {
        self.groups
            .iter()
            .map(|(id, r)| (*id, r.display_name()))
            .collect()
    }
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
    /// An application message from a member: a text, a file, an edit, a
    /// deletion or a reaction (whether `from` may edit or delete the
    /// message named is the caller's to check against its history); a
    /// timer comes as [`GroupEvent::TimerSet`] instead.
    Message {
        group: GroupId,
        from: UserId,
        id: String,
        sent_at_ms: u64,
        content: Content,
    },
    /// An admin set the group's disappearing-message timer (section
    /// 13.3), applied to the record already; `changed` is false for a
    /// repeat of the value that stood, as a newcomer is told it.
    TimerSet {
        group: GroupId,
        by: UserId,
        seconds: u64,
        changed: bool,
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
    /// with [`Groups::stage_add`] — unless `removed_before`: this client
    /// saw the joiner removed from the group, and letting them back in is
    /// the user's decision (`/group add`), not the link's.
    JoinRequest {
        group: GroupId,
        joiner: UserId,
        key_package: Vec<u8>,
        removed_before: bool,
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
    /// What the commit fans out, framed and sealed while it was staged.
    ///
    /// Everything that can fail does so here, before the caller takes the
    /// staged commit to the sequencer: framing refuses a message too large
    /// to encode, and sealing refuses a member whose leaf carries a key
    /// nothing can be sealed to. Doing either after the sequencer has
    /// moved would leave the group at an epoch whose commit no member ever
    /// receives — every later commit refused as stale, waiting for one
    /// that does not exist.
    outgoing: Outgoing,
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
    /// A kind of message not every member's client reads (section
    /// 13.3): the members whose client is older. Nothing was sent.
    #[error("not sent: the client of {} is older and would not read it", short_list(.0))]
    OlderMembers(Vec<UserId>),
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
    /// Whether the leaves this engine makes declare the everyday
    /// extension type (`docs/PROTOCOL.md` section 13.3); always, except
    /// where a test stands in for a client from before 0.10.0.
    declare_everyday: bool,
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
            declare_everyday: true,
        }
    }

    /// Whether the key packages and leaf updates this engine makes from
    /// now on declare the everyday extension type. On by default; off
    /// only in a test that stands in for a member on 0.9.0, whose leaf
    /// does not declare it, to see what its peers withhold.
    pub fn declare_everyday(&mut self, declare: bool) {
        self.declare_everyday = declare;
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
            if let Ok(group) = load_handle(&mut self.handles, &self.provider, &id)
                && group.pending_commit().is_some()
            {
                group
                    .clear_pending_commit(self.provider.storage())
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
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
        record.alias = clean_alias(alias);
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
                    alias: clean_alias(expected.alias),
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
        self.remember_forgotten(group);
        self.drop_state(group);
        self.file.groups.remove(group);
        self.persist()
    }

    /// Keep the last epoch known of a group about to be dropped from the
    /// list, so that a Welcome made before then is not taken again.
    ///
    /// The last-resort key package is not spent by the Welcome that uses
    /// it, so whoever can deliver an old Welcome — the relay, at the
    /// least — could otherwise bring a group back after the user left it,
    /// was removed or declined, at an epoch long gone.
    fn remember_forgotten(&mut self, group: &GroupId) {
        let Some(epoch) = self
            .file
            .groups
            .get(group)
            .and_then(GroupRecord::last_epoch)
        else {
            return;
        };
        self.file.forgotten.retain(|f| f.group != *group);
        self.file.forgotten.push(Forgotten {
            group: *group,
            epoch,
        });
        while self.file.forgotten.len() > FORGOTTEN_KEPT {
            self.file.forgotten.remove(0);
        }
    }

    /// The newest epoch this client knew of `group`, in its record or
    /// after it forgot it.
    fn last_known_epoch(&self, group: &GroupId) -> Option<u64> {
        let kept = self
            .file
            .groups
            .get(group)
            .and_then(GroupRecord::last_epoch);
        let forgotten = self
            .file
            .forgotten
            .iter()
            .filter(|f| f.group == *group)
            .map(|f| f.epoch)
            .max();
        kept.max(forgotten)
    }

    /// Note devices whose revocation this client has seen (an account's
    /// signed word, checked by the caller): a Welcome from one is not
    /// taken, a join or rejoin request from one is not answered, and
    /// their leaves are listed by [`Groups::revoked_leaves`] until a
    /// commit takes them out.
    ///
    /// A revoked device keeps its keys, and its certificate still
    /// verifies; only the revocation says it is no longer the account's.
    pub fn note_revoked_devices(
        &mut self,
        devices: impl IntoIterator<Item = UserId>,
    ) -> Result<()> {
        let mut changed = false;
        for device in devices {
            if !self.file.revoked.contains(&device) {
                self.file.revoked.push(device);
                changed = true;
            }
        }
        if !changed {
            return Ok(());
        }
        while self.file.revoked.len() > REVOKED_KEPT {
            self.file.revoked.remove(0);
        }
        self.persist()
    }

    pub fn is_revoked_device(&self, device: &UserId) -> bool {
        self.file.revoked.contains(device)
    }

    /// Leaves of revoked devices still in an active group, which this
    /// account may take out ([`Groups::stage_remove_device`]): any as an
    /// admin, its own devices' otherwise. A front end tries one per pass
    /// until none is left, so a removal that lost a commit race, or was
    /// not tried because another commit was staged, is not forgotten.
    pub fn revoked_leaves(&self) -> Vec<(GroupId, UserId)> {
        let me = self.account();
        let device = self.device();
        let mut out = Vec::new();
        for (id, record) in &self.file.groups {
            if record.state != GroupState::Active {
                continue;
            }
            let admin = record.is_admin(&me);
            for member in &record.members {
                if member.device != device
                    && self.file.revoked.contains(&member.device)
                    && (admin || member.user == me)
                {
                    out.push((*id, member.device));
                }
            }
        }
        out
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
    /// Invitations waiting for the user to accept or decline.
    fn invitations_held(&self) -> usize {
        self.file
            .groups
            .values()
            .filter(|r| matches!(r.state, GroupState::Invited { .. }))
            .count()
    }

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

    /// What a leaf of this engine's declares: the extension types it
    /// reads, the everyday one among them (section 13.3) so that peers
    /// know an edit, a deletion, a reaction or a timer is read here.
    fn capabilities(&self) -> Capabilities {
        let mut extensions = vec![
            ExtensionType::Unknown(EXTENSION_GROUP),
            ExtensionType::Unknown(EXTENSION_SEAL),
            ExtensionType::Unknown(EXTENSION_DEVICE),
        ];
        if self.declare_everyday {
            extensions.push(ExtensionType::Unknown(EXTENSION_EVERYDAY));
        }
        Capabilities::new(None, Some(&[CIPHERSUITE]), Some(&extensions), None, None)
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
        let mut capabilities = self.capabilities();
        if last_resort {
            // A key package may only carry an extension its own leaf says
            // it supports. Without this the last-resort package failed
            // every adder's validation, and the relay's fallback for a
            // drained deposit could never be used.
            let mut extensions = capabilities.extensions().to_vec();
            extensions.push(ExtensionType::LastResort);
            capabilities =
                Capabilities::new(None, Some(&[CIPHERSUITE]), Some(&extensions), None, None);
        }
        let mut builder = KeyPackage::builder()
            .leaf_node_capabilities(capabilities)
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
        // Join and rejoin requests each add a package to this list, and
        // the relay refuses a deposit above its cap *whole*: past the cap
        // nothing was deposited at all, and a member who drove a victim
        // out of sync a dozen times left it unable to deposit until the
        // packages expired, up to ninety days later. The oldest go, their
        // secrets with them (SM-G-11).
        while self.file.key_packages.len() > MAX_KEY_PACKAGES {
            let oldest = self
                .file
                .key_packages
                .iter()
                .enumerate()
                .min_by_key(|(_, p)| p.created_at_ms)
                .map(|(i, _)| i);
            let Some(index) = oldest else { break };
            let package = self.file.key_packages.remove(index);
            self.delete_key_package_secret(&package);
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
        if let Ok(kp) = parse_key_package(&package.data, self.provider.crypto())
            && let Ok(hash_ref) = kp.hash_ref(self.provider.crypto())
        {
            let _ = self.provider.storage().delete_key_package(&hash_ref);
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
            .sender_ratchet_configuration(sender_ratchet())
            .with_group_context_extensions(context)
            .capabilities(self.capabilities())
            .with_leaf_node_extensions(self.leaf_extensions())
            .map_err(mls_err)?
            .build())
    }

    fn join_config() -> MlsGroupJoinConfig {
        MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .max_past_epochs(PAST_EPOCHS)
            .sender_ratchet_configuration(sender_ratchet())
            .build()
    }

    /// Make a group with ourselves as the only member and admin. The caller
    /// registers the returned entry with the relay's sequencer.
    pub fn create(&mut self, name: &str, now_ms: u64) -> Result<Created> {
        self.create_with_id(GroupId::generate(), name, now_ms)
    }

    /// [`Groups::create`] under a chosen id: a group id is no secret, and
    /// the tests stand in for whoever reuses one.
    fn create_with_id(&mut self, id: GroupId, name: &str, now_ms: u64) -> Result<Created> {
        group::check_new_name(name)?;
        let me = self.account();
        let extension = SilverGroup::new(name, me, now_ms)?;
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
                // The creator's own group: admin because it made it.
                conferred_admin: false,
                link_uses: None,
                link_secret: None,
                removed: Vec::new(),
                behind: None,
                ahead_seen_ms: None,
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
            if self.is_revoked_device(&leaf.device) {
                return Err(GroupError::KeyPackage(format!(
                    "the device {}… was unlinked from its account",
                    leaf.device.short()
                )));
            }
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
        // Admins removed from the group leave the admin list with it, and
        // so do admins whose own leave this commit carries.
        let mut extension = self.extension(group)?;
        for user in users {
            extension = extension.without_admin(user);
        }
        let staying = self.members_after(group, &indices, true)?;
        let extension = without_departed_admins(extension, &staying);
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
            let staying = self.members_after(group, &[index], record.is_admin(&me))?;
            let extension = self.extension(group)?.without_admin(&account);
            let extension = without_departed_admins(extension, &staying);
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
        group::check_new_name(name)?;
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
        // An admin who left may still be named until an admin's commit
        // drops them; taking them off the list is always allowed.
        let named = self.extension(group)?.admins.contains(&user);
        if !record.is_member(&user) && (admin || !named) {
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

    /// A fresh invite-link secret for this device, voiding every link it
    /// made for `group` before; returns the new link. No commit: the
    /// secret is this device's own (see [`GroupRecord`]'s
    /// `link_secret`), so another admin's links are theirs to reset.
    pub fn reset_link(&mut self, group: &GroupId, relay: Option<String>) -> Result<GroupLink> {
        if !self.active(group)?.is_admin(&self.account()) {
            return Err(GroupError::NotAdmin);
        }
        let key = self.random_32()?;
        let record = self.record_mut(group)?;
        record.link_secret = Some(LinkSecret { key });
        record.link_uses = None;
        self.persist()?;
        self.invite_link(group, relay)
    }

    fn random_32(&self) -> Result<[u8; 32]> {
        self.provider
            .rand()
            .random_array::<32>()
            .map_err(|e| GroupError::Mls(format!("no randomness: {e:?}")))
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
        // The commit consumes the stored proposals, a leaver's Remove
        // among them, and anyone it leaves outside the group leaves the
        // admin list with it.
        let staying = self.members_after(group, &[], true)?;
        let extension = without_departed_admins(extension, &staying);
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
        let admin = self.active(group)?.is_admin(&self.account());
        // An admin's refresh is what commits a leave, so it also takes the
        // leavers — and any admin who left before and is still named —
        // off the admin list. Left named, a leaver became "an admin who is
        // not a member" in every later commit, and every reader marked the
        // group broken at the next one.
        let context = if admin {
            let extension = self.extension(group)?;
            let staying = self.members_after(group, &[], true)?;
            let pruned = without_departed_admins(extension.clone(), &staying);
            if pruned == extension {
                None
            } else {
                Some(context_extensions(&pruned)?)
            }
        } else {
            None
        };
        self.stage(
            group,
            // A non-admin's refresh leaves the stored proposal queue
            // alone. OpenMLS consumes it by default, so a leaver's Remove
            // sitting in this client's queue rode along in a weekly
            // refresh nobody asked for — and every receiver then saw a
            // non-admin removing a member, marked the group broken, and
            // named the honest refresher (SM-G-03). Committing a leave is
            // an admin's job, which is where the queue is consumed.
            move |builder| {
                let builder = builder
                    .force_self_update(true)
                    .consume_proposal_store(admin);
                match context {
                    Some(context) => builder
                        .propose_group_context_extensions(context)
                        .map_err(mls_err),
                    None => Ok(builder),
                }
            },
            Vec::new(),
            Change::Updated,
        )
    }

    /// Groups whose leaf is due for a refresh: by age, or because the
    /// leaf in the tree does not declare what this client reads (it was
    /// made by an earlier version), which peers would take as a reason
    /// to withhold an edit or a reaction — or because the group may have
    /// moved on without us, and a self-update is how this client asks
    /// the relay's sequencer where it stands ([`Groups::sequencer_ahead`]).
    pub fn self_updates_due(&mut self, now_ms: u64) -> Vec<GroupId> {
        let active: Vec<GroupId> = self
            .file
            .groups
            .iter()
            .filter(|(_, r)| r.state == GroupState::Active)
            .map(|(id, _)| *id)
            .collect();
        let mut due = Vec::new();
        for id in active {
            let record = &self.file.groups[&id];
            let by_age = record.leaf_updated_ms.saturating_add(SELF_UPDATE_AFTER_MS) <= now_ms;
            // The sequencer said we are behind: ask again once the commits
            // between have had time to arrive.
            let confirm = record
                .behind
                .is_some_and(|b| b.since_ms.saturating_add(BEHIND_GRACE_MS) <= now_ms);
            // A handshake from a later epoch is anyone's to write, so it
            // only prompts the question, and not more often than
            // `PROBE_EVERY_MS`.
            let probe = record.ahead_seen_ms.is_some_and(|seen| {
                seen.saturating_add(BEHIND_GRACE_MS) <= now_ms
                    && record.leaf_updated_ms.saturating_add(PROBE_EVERY_MS) <= now_ms
            });
            let behind = self.declare_everyday
                && load_handle(&mut self.handles, &self.provider, &id)
                    .ok()
                    .and_then(|h| h.own_leaf_node().map(declares_everyday))
                    .is_some_and(|declares| !declares);
            if by_age || behind || confirm || probe {
                due.push(id);
            }
        }
        due
    }

    /// Mark every active group's leaf as due for a refresh, so the next
    /// self-update pass commits a leaf carrying what this identity holds
    /// now — after a rekey, its new sealing key
    /// (`docs/design/dh-rotation.md` section 6). Returns how many groups
    /// that is.
    pub fn mark_leaves_stale(&mut self) -> Result<usize> {
        let mut n = 0;
        for record in self.file.groups.values_mut() {
            if record.state == GroupState::Active {
                record.leaf_updated_ms = 0;
                n += 1;
            }
        }
        if n > 0 {
            self.persist()?;
        }
        Ok(n)
    }

    /// The members whose client is older than this kind of message: the
    /// identities with a leaf in the tree that does not declare the
    /// everyday extension type. Empty when an edit, a deletion, a
    /// reaction or a timer can go to the group.
    pub fn members_without_everyday(&mut self, group: &GroupId) -> Result<Vec<UserId>> {
        let handle = load_handle(&mut self.handles, &self.provider, group)?;
        let mut older = Vec::new();
        for (_, leaf) in leaves_of(handle)? {
            if !leaf.everyday && !older.contains(&leaf.account) {
                older.push(leaf.account);
            }
        }
        Ok(older)
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
        // The refreshed leaf declares what this client reads now, not
        // what it read when it joined.
        let leaf = LeafNodeParameters::builder()
            .with_capabilities(self.capabilities())
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
        // Frame and seal now, while nothing has moved: the sequencer has
        // not been asked and the commit is not merged, so a failure here
        // is a staged commit the caller discards and nothing else.
        let mut outgoing = Outgoing::default();
        if !recipients.is_empty() {
            let (body, upload) = self.frame(group, GroupKind::Handshake, commit)?;
            outgoing.uploads.extend(upload);
            outgoing.envelopes.extend(self.seal_to(&recipients, &body)?);
        }
        if let (Some(welcome), false) = (welcome, added.is_empty()) {
            let (body, upload) = self.frame(group, GroupKind::Welcome, welcome)?;
            outgoing.uploads.extend(upload);
            outgoing.envelopes.extend(self.seal_to(&added, &body)?);
        }
        self.staged
            .insert(*group, StagedCommitData { outgoing, change });
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
        let account = self.account();
        let record = self.record_mut(group)?;
        record.members = members;
        push_token(record, epoch, token);
        // The sequencer took a commit at our epoch, so nothing had moved
        // past it: whatever said otherwise is answered.
        record.behind = None;
        record.ahead_seen_ms = None;
        // Every commit of ours carries an update path.
        record.leaf_updated_ms = now_ms;
        if let Change::Renamed(name) = &data.change {
            record.name = name.clone();
        }
        record.note_change(&data.change);
        if !record.is_admin(&account) {
            record.link_secret = None;
            record.link_uses = None;
        }
        self.persist()?;
        Ok(data.outgoing)
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

    /// An application message to every member. An edit, a deletion, a
    /// reaction or a timer goes only when every leaf declares the
    /// everyday extension type (section 13.3); otherwise nothing is sent
    /// and the error names the members whose client is older, since one
    /// of theirs would report an unreadable message instead.
    pub fn send(
        &mut self,
        group: &GroupId,
        content: Content,
        head: Option<LogHead>,
        now_ms: u64,
    ) -> Result<Outgoing> {
        self.active(group)?;
        if crate::everyday::needs_capability(&content).is_some() {
            let older = self.members_without_everyday(group)?;
            if !older.is_empty() {
                return Err(GroupError::OlderMembers(older));
            }
        }
        // The timer is a setting of the group's: an admin's to set, and
        // set here as it goes out.
        let timer = match content {
            Content::Timer { seconds } => {
                if !self.record(group)?.is_admin(&self.account()) {
                    return Err(GroupError::NotAdmin);
                }
                Some(seconds)
            }
            _ => None,
        };
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
        if let Some(seconds) = timer {
            self.record_mut(group)?.expire_after_s = seconds;
        }
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
        // Requests no Welcome answered in time are no use kept.
        let joins_at = &mut self.file.joins_at;
        joins_at.retain(|_, at| at.saturating_add(JOIN_ANSWER_FOR_MS) > now_ms);
        self.file
            .joins
            .retain(|group, _| joins_at.contains_key(group));
        self.file.joins.insert(link.group, link.via);
        self.file.joins_at.insert(link.group, now_ms);
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
    ///
    /// The request is signed with this device's identity key over the
    /// group, the new key package and the HPKE key of the leaf it asks to
    /// replace (`silver_protocol::group::rejoin_statement`): the key
    /// package alone is public, and anyone could have sent it.
    pub fn rejoin_request(&mut self, group: &GroupId, now_ms: u64) -> Result<Outgoing> {
        let record = self.record(group)?.clone();
        match record.state {
            GroupState::Active | GroupState::OutOfSync { .. } => {}
            GroupState::Invited { .. } => {
                return Err(GroupError::NotActive("not accepted yet".into()));
            }
            _ => return Err(GroupError::NotActive("not one we are in".into())),
        }
        let leaf_key = {
            let handle = load_handle(&mut self.handles, &self.provider, group)?;
            handle
                .member_at(handle.own_leaf_index())
                .ok_or_else(|| GroupError::Mls("no leaf of our own in the group".into()))?
                .encryption_key
        };
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
        let statement = rejoin_statement(group, &package.r#ref, &leaf_key);
        let signature = self.identity.sign(REJOIN_PROOF_DOMAIN, &statement);
        let body =
            GroupBody::inline(*group, GroupKind::Rejoin, package.data).with_rejoin_proof(signature);
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
    ///
    /// The link key comes from this device's own link secret, made the
    /// first time a link is asked for and kept only here: a link works
    /// with the admin device that made it and no other, and no member can
    /// derive one from what the group shares.
    pub fn invite_link(&mut self, group: &GroupId, relay: Option<String>) -> Result<GroupLink> {
        if !self.active(group)?.is_admin(&self.account()) {
            return Err(GroupError::NotAdmin);
        }
        let secret = match &self.record(group)?.link_secret {
            Some(secret) => secret.key,
            None => {
                let key = self.random_32()?;
                self.record_mut(group)?.link_secret = Some(LinkSecret { key });
                self.persist()?;
                key
            }
        };
        Ok(GroupLink {
            group: *group,
            via: self.device(),
            key: group::link_key(&secret, group),
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
        // The same bound the readers apply (protocol section 13.2), so a
        // message that would be refused as malformed is never built.
        let most = match kind {
            GroupKind::Welcome | GroupKind::Handshake => MAX_PARKED_HANDSHAKE_BYTES,
            GroupKind::Message | GroupKind::Join | GroupKind::Rejoin => MAX_PARKED_BYTES,
        };
        if message.len() as u64 > most {
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
            GroupKind::Welcome => self.receive_welcome(group, from, mls, now_ms),
            GroupKind::Handshake | GroupKind::Message => {
                self.receive_protocol_message(group, from, mls, now_ms)
            }
            GroupKind::Join => self.receive_join(group, body, mls, now_ms),
            GroupKind::Rejoin => self.receive_rejoin(group, body, mls),
        };
        // Persisted whatever happened. A commit merged, or a message key
        // consumed, and then something afterwards failing used to leave
        // the MLS state advanced in memory and not on disk: a crash then
        // restored a state before the commit, or one in which a
        // ciphertext already read would decrypt again (SM-G-12).
        self.persist()?;
        events
    }

    fn receive_welcome(
        &mut self,
        group: GroupId,
        from: UserId,
        mls: &[u8],
        now_ms: u64,
    ) -> Result<Vec<GroupEvent>> {
        // Read before anything is given up. A body that is not a Welcome
        // at all used to be enough to delete an out-of-sync member's
        // state — which might still have recovered from held messages —
        // and a group id is known to anyone who was ever in the group or
        // held an invite link (SM-G-10).
        let welcome = parse_welcome(mls)?;
        let previous = self.file.groups.get(&group).cloned();
        let me = self.account();
        if let Some(record) = &previous {
            match record.state {
                GroupState::Active => {
                    return Ok(vec![GroupEvent::Refused {
                        group,
                        reason: "a Welcome to a group we are in".into(),
                    }]);
                }
                // The client joins as the Welcome arrives so that the
                // group stays in sync while the user decides, which takes
                // the id: a second Welcome cannot be read without
                // throwing the first away, and throwing it away on the
                // word of whoever sent the second is how an id anyone can
                // learn would decide which group this is. Declining the
                // invitation makes room for another.
                GroupState::Invited { from } => {
                    return Ok(vec![GroupEvent::Refused {
                        group,
                        reason: format!(
                            "another Welcome to a group {} already invited us to; decline that invitation first",
                            from.short()
                        ),
                    }]);
                }
                // Out of sync, removed, left or broken: the Welcome may
                // start the group afresh, but only once it is known to
                // come from someone this record says may do that (below).
                _ => {}
            }
        }
        // Staged beside the state the record still has: nothing of the old
        // membership goes until the checks below have passed, so a
        // Welcome from the wrong sender costs nothing but its own reading.
        let staged =
            StagedWelcome::build_from_welcome(&self.provider, &Self::join_config(), welcome)
                .map_err(mls_err)?
                .replace_old_group()
                .build()
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
        let welcome_epoch = context.epoch().as_u64();
        let extension = extension_of(context.extensions())?;
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
        // A device its account unlinked keeps its keys and a certificate
        // that still verifies; its Welcome is no one's word any more —
        // least of all this account's own, which would be taken without
        // asking.
        if self.is_revoked_device(&inviter.device) {
            return Ok(vec![GroupEvent::Refused {
                group,
                reason: format!(
                    "a Welcome from {}…, a device its account unlinked",
                    inviter.device.short()
                ),
            }]);
        }
        // A group this client already knows is replaced only by one of the
        // admins it last knew there, or by this account's own device. The
        // Welcome's own admin list is whatever its author wrote, so going
        // by it let anyone who knew the id put a group of theirs in this
        // one's place — its history, its name and alias — after a single
        // envelope had made the member look out of sync.
        if let Some(record) = &previous
            && inviter.account != me
            && !record.is_admin(&inviter.account)
        {
            return Ok(vec![GroupEvent::Refused {
                group,
                reason: format!(
                    "a Welcome from {}…, who was not an admin of this group; /group forget it to take invitations from others",
                    inviter.account.short()
                ),
            }]);
        }
        // Nothing older than what this client already knew: a Welcome made
        // from the last-resort key package can be read again after the
        // group was left, lost or declined (see `remember_forgotten`).
        if self
            .last_known_epoch(&group)
            .is_some_and(|known| welcome_epoch <= known)
        {
            return Ok(vec![GroupEvent::Refused {
                group,
                reason: format!(
                    "a Welcome for epoch {welcome_epoch}, which this client has seen before"
                ),
            }]);
        }
        // No second yes from the user for the answer to a join request we
        // sent this admin (by either id the link named) not long ago, for
        // a group the primary named when this device was linked, or for
        // one's own identity's other device adding this one.
        let asked_at = self.file.joins_at.get(&group).copied();
        let asked = asked_at.is_some_and(|at| at.saturating_add(JOIN_ANSWER_FOR_MS) > now_ms)
            && self
                .file
                .joins
                .get(&group)
                .is_some_and(|via| *via == inviter.account || *via == inviter.device);
        let ours = inviter.account == me;
        // A group named at link time is one this account's primary said it
        // would put this device in (section 14.7), so only the account
        // itself fills the promise — and until it does, neither the group
        // nor the name it was promised under is given away. The admin
        // check above is no help here: it reads the Welcome's own
        // extension, which whoever built the Welcome wrote, and a group
        // id is known to anyone who ever held an invite link or was once
        // a member. A Welcome from anyone else is an ordinary invitation,
        // shown under the name its own author chose, waiting for the
        // user.
        let expected = if ours {
            self.file.expected.remove(&group)
        } else {
            None
        };
        let taken = asked || ours;
        // Invitations nobody has answered are a stranger's to make: a
        // Welcome needs no permission, and the last-resort key package is
        // reusable, so without a cap one sender could leave this client
        // holding a full MLS tree per invented group id, each rewritten
        // to disk on every group event (SM-G-05).
        if !taken && self.invitations_held() >= MAX_INVITATIONS {
            return Ok(vec![GroupEvent::Refused {
                group,
                reason: format!(
                    "{MAX_INVITATIONS} invitations are already waiting; answer one before another arrives"
                ),
            }]);
        }
        // Whatever is left of the old membership goes now; this Welcome
        // starts afresh.
        if previous.is_some() {
            self.drop_state(&group);
        }
        // Join now, so the group stays in sync while the user decides; the
        // key package that let us in is spent by this.
        let mut handle = staged.into_group(&self.provider).map_err(mls_err)?;
        // Everything from here either finishes or takes the group's
        // storage with it: `into_group` persists the tree, and a failure
        // after it used to leave those entries behind for good, with no
        // record naming them (SM-G-05).
        let members = match members_of(&handle, &extension) {
            Ok(members) => members,
            Err(e) => {
                let _ = handle.delete(self.provider.storage());
                return Err(e);
            }
        };
        let epoch = handle.epoch().as_u64();
        let token = match token_of(&handle, &group, self.provider.crypto()) {
            Ok(token) => token,
            Err(e) => {
                let _ = handle.delete(self.provider.storage());
                return Err(e);
            }
        };
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
            // Admin because the Welcome said so, and the Welcome is the
            // inviter's to write. Not so when this account added itself.
            conferred_admin: !ours && extension.is_admin(&me),
            // Nothing has been asked of this device's copy of the link.
            link_uses: None,
            link_secret: None,
            removed: previous
                .as_ref()
                .map(|r| r.removed.clone())
                .unwrap_or_default(),
            behind: None,
            ahead_seen_ms: None,
            seen: previous.map(|r| r.seen).unwrap_or_default(),
        };
        self.file.groups.insert(group, record);
        if taken {
            self.file.joins.remove(&group);
            self.file.joins_at.remove(&group);
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
        self.remember_forgotten(group);
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
        let mut events = self.process_one(group, from, mls, now_ms, now_ms)?;
        // Held messages may be readable now.
        let mut progressed = true;
        while progressed {
            progressed = false;
            let held: Vec<Held> = std::mem::take(&mut self.record_mut(&group)?.held);
            for item in held {
                if item.received_at_ms.saturating_add(HOLD_FOR_MS) <= now_ms {
                    continue;
                }
                let before = self.record(&group)?.held.len();
                // Held again, if it is still from the future, under the
                // time it first arrived: a fresh time on every pass kept
                // a message that never became readable held for ever.
                // And one that fails is that one's failure: the rest of
                // the queue, already taken out, would otherwise be lost
                // with it.
                match self.process_one(group, item.from, &item.mls, item.received_at_ms, now_ms) {
                    Ok(more) => events.extend(more),
                    Err(e) => events.push(GroupEvent::Refused {
                        group,
                        reason: format!("a held group message could not be read: {e}"),
                    }),
                }
                if self.record(&group)?.held.len() == before {
                    progressed = true;
                }
            }
        }
        Ok(events)
    }

    /// Read one MLS message. `received_at_ms` is when it first arrived,
    /// which a message held for a later epoch keeps.
    fn process_one(
        &mut self,
        group: GroupId,
        from: UserId,
        mls: &[u8],
        received_at_ms: u64,
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
        let account = self.account();
        let crypto = self.provider.crypto();
        let handle = load_handle(&mut self.handles, &self.provider, &group)?;
        let our_epoch = handle.epoch().as_u64();
        if is_handshake && message_epoch > our_epoch {
            // From the future: hold it, unless the hold queue is full.
            // Nothing has been decrypted yet — the epoch and the content
            // type are plaintext header fields anyone can write — so what
            // is held is unauthenticated bytes, kept in memory and written
            // into `groups.json` on every later group event. Only a
            // message small enough to have travelled inside its envelope
            // is held, and the queue has a size as well as a count: a
            // member who parks a large one in the blob store gets no
            // room at all.
            let record = self
                .file
                .groups
                .get_mut(&group)
                .ok_or(GroupError::NoSuchGroup)?;
            record
                .held
                .retain(|h| h.received_at_ms.saturating_add(HOLD_FOR_MS) > now_ms);
            // Whatever happens to it, the group may have moved on without
            // us; the sequencer is asked (`self_updates_due`).
            if record.ahead_seen_ms.is_none() {
                record.ahead_seen_ms = Some(now_ms);
            }
            let bytes: usize = record.held.iter().map(|h| h.mls.len()).sum();
            if record.held.len() >= HOLD_LIMIT
                || too_far_ahead(our_epoch, message_epoch)
                || !GroupBody::fits_inline(mls.len())
                || bytes + mls.len() > HOLD_BYTES
            {
                // Dropped, and nothing else. This used to put the group out
                // of sync, and since the header is anyone's to write, one
                // envelope from a stranger stopped a member sending and
                // started a rejoin that could hand the group to a Welcome
                // of the stranger's. Going out of sync now takes
                // the relay's sequencer's word ([`Groups::sequencer_ahead`])
                // or a commit OpenMLS could attribute (below).
                return Ok(vec![GroupEvent::Refused {
                    group,
                    reason: format!(
                        "a change for epoch {message_epoch}, ahead of ours ({our_epoch}), could not be kept for later"
                    ),
                }]);
            }
            record.held.push(Held {
                received_at_ms,
                from,
                mls: mls.to_vec(),
            });
            return Ok(Vec::new());
        }
        let processed = match handle.process_message(&self.provider, protocol) {
            Ok(processed) => processed,
            Err(e) => {
                // A commit at our own epoch that will not stage — one
                // referencing a proposal this client never received, say
                // — means the group has moved on without us. Refusing it
                // and saying nothing left the group stuck for good; going
                // out of sync starts the recovery that is already there
                // (SM-G-03). Only a commit that got as far as staging
                // counts: by then OpenMLS has decrypted it with this
                // epoch's keys and checked a member's signature on it,
                // where anything before that is a header anyone can write.
                // An invitation is never put out of sync: it waits for the
                // user, and coming back into sync would make it a group
                // they never said yes to.
                let authenticated = matches!(e, ProcessMessageError::InvalidCommit(_));
                if authenticated && is_handshake && message_epoch == our_epoch {
                    let record = self
                        .file
                        .groups
                        .get_mut(&group)
                        .ok_or(GroupError::NoSuchGroup)?;
                    if matches!(record.state, GroupState::Active) {
                        record.state = GroupState::OutOfSync { since_ms: now_ms };
                        return Ok(vec![
                            GroupEvent::Refused {
                                group,
                                reason: format!("a change to the group could not be applied: {e}"),
                            },
                            GroupEvent::OutOfSync { group },
                        ]);
                    }
                }
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
        let Some(index) = sender_index else {
            return Ok(vec![GroupEvent::Refused {
                group,
                reason: "a message from outside the group".into(),
            }]);
        };
        // Who sent it is the credential OpenMLS checked the signature
        // against: the leaf at that index *in the message's own epoch*.
        // An application message may come from up to `PAST_EPOCHS` epochs
        // back, and reading the index in today's tree named whoever holds
        // that slot now — a removed member's last words shown as those of
        // the member who took its place. Every leaf that was ever
        // in the tree passed `verify_leaf` as it came in (the Welcome's
        // member list, `check_commit`), so its credential names an
        // account that leaf was checked to belong to.
        let sender = match account_of(processed.credential()) {
            Ok(sender) => sender,
            Err(e) => {
                return Ok(vec![GroupEvent::Refused {
                    group,
                    reason: format!("a message whose sender cannot be told: {e}"),
                }]);
            }
        };
        if processed.epoch().as_u64() == our_epoch && leaf_at(handle, index)?.account != sender {
            return Ok(vec![GroupEvent::Refused {
                group,
                reason: "a message whose sender does not match its leaf".into(),
            }]);
        }
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
                // A gossiped log head is checked against our own chain and
                // can raise a fork alarm, so it counts only from a group
                // the user is actually in: an invitation nobody has
                // accepted is a stranger's Welcome, and its messages are
                // not a reason to tell the user their relay is showing two
                // views of the log (SM-G-13).
                if let Some(head) = plain.head
                    && matches!(record.state, GroupState::Active)
                {
                    events.push(GroupEvent::Head { from: sender, head });
                }
                if let Content::Timer { seconds } = plain.content {
                    // The timer is a setting of the group's: an admin's
                    // word, applied here; anyone else's counts for nothing.
                    if !record.is_admin(&sender) {
                        events.push(GroupEvent::Refused {
                            group,
                            reason: format!(
                                "{}… set a timer without being an admin",
                                sender.short()
                            ),
                        });
                        return Ok(events);
                    }
                    let changed = record.expire_after_s != seconds;
                    record.expire_after_s = seconds;
                    events.push(GroupEvent::TimerSet {
                        group,
                        by: sender,
                        seconds,
                        changed,
                    });
                    return Ok(events);
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
                        // The tree after the commit must still read. If it
                        // does not, the commit that made it is the fault
                        // and its committer is named: returning an error
                        // here left the group in a state where every
                        // later commit failed and the *next* committer,
                        // an honest one, was blamed (SM-G-04).
                        let members = match members_of(handle, &extension_after) {
                            Ok(members) => members,
                            Err(e) => {
                                let reason = format!("the tree it left cannot be read: {e}");
                                let record = self
                                    .file
                                    .groups
                                    .get_mut(&group)
                                    .ok_or(GroupError::NoSuchGroup)?;
                                record.state = GroupState::Broken {
                                    by: sender,
                                    reason: reason.clone(),
                                };
                                return Ok(vec![GroupEvent::Broken {
                                    group,
                                    by: sender,
                                    reason,
                                }]);
                            }
                        };
                        let record = self
                            .file
                            .groups
                            .get_mut(&group)
                            .ok_or(GroupError::NoSuchGroup)?;
                        let before = record.identities();
                        record.members = members;
                        record.name = extension_after.name.clone();
                        // Back in step. An invitation stays one: only the
                        // user's yes makes it a group they are in.
                        if matches!(record.state, GroupState::OutOfSync { .. }) {
                            record.state = GroupState::Active;
                        }
                        push_token(record, epoch, token);
                        record.caught_up(epoch);
                        record.note_change(&change);
                        // An admin no more: the links this device made stop
                        // working, now and if it is made one again.
                        if !record.is_admin(&account) {
                            record.link_secret = None;
                            record.link_uses = None;
                        }
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
        // The link is this device's: its key comes from the secret only
        // this device holds. No link made here, no valid proof.
        let Some(secret) = record.link_secret.as_ref().map(|s| s.key) else {
            return Ok(vec![GroupEvent::Refused {
                group,
                reason: format!(
                    "{} presented a link this device did not make",
                    joiner.short()
                ),
            }]);
        };
        if !group::verify_join_proof(&secret, &group, &joiner, &proof.proof) {
            return Ok(vec![GroupEvent::Refused {
                group,
                reason: format!("{} presented a link that is not valid", joiner.short()),
            }]);
        }
        if self.is_revoked_device(&leaf.device) {
            return Ok(vec![GroupEvent::Refused {
                group,
                reason: format!(
                    "{} asked to join from a device their account unlinked",
                    joiner.short()
                ),
            }]);
        }
        // A member asks for nothing, whichever of its devices presents the
        // link (`docs/PROTOCOL.md` section 13.7). A member's further
        // device is brought in by its own primary, not by the link, so
        // answering one here would only spend the link's uses on people
        // already in.
        if record.members.iter().any(|m| m.user == joiner) {
            return Ok(Vec::new());
        }
        // What this link has cost so far. Anyone holding it can ask, and
        // each ask is a commit and a Welcome to every member, so a link
        // that has done its round is spent until the admin resets it.
        let link = group::link_key(&secret, &group);
        let uses = self
            .file
            .groups
            .get_mut(&group)
            .ok_or(GroupError::NoSuchGroup)?
            .link_uses
            .get_or_insert(LinkUses { link, used: 0 });
        if uses.link != link {
            *uses = LinkUses { link, used: 0 };
        }
        if uses.used >= MAX_LINK_JOINS {
            return Ok(vec![GroupEvent::Refused {
                group,
                reason: format!(
                    "{} presented the invite link, which has been used {MAX_LINK_JOINS} times already: /group link reset makes a new one",
                    joiner.short()
                ),
            }]);
        }
        uses.used += 1;
        let _ = now_ms;
        Ok(vec![GroupEvent::JoinRequest {
            group,
            joiner,
            key_package: mls.to_vec(),
            // Someone removed them; a link they kept from before does not
            // overrule that by itself.
            removed_before: record.removed.contains(&joiner),
        }])
    }

    fn receive_rejoin(
        &mut self,
        group: GroupId,
        body: &GroupBody,
        mls: &[u8],
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
        if self.is_revoked_device(&leaf.device) {
            return Ok(vec![GroupEvent::Refused {
                group,
                reason: format!(
                    "{} asked to rejoin from a device their account unlinked",
                    leaf.account.short()
                ),
            }]);
        }
        // The key package is public — the relay hands it to anyone, and
        // every Add commit carries one — so it says nothing about who sent
        // the request. Answering it as it was let anyone have this client
        // remove a member's leaf and add one back that the member may not
        // be able to use. The request has to be signed by the
        // device whose leaf it replaces, over that leaf as it stands now:
        // which also makes a request good once, since the re-added leaf
        // has another key.
        let Some(proof) = body.rejoin else {
            return Ok(vec![GroupEvent::Refused {
                group,
                reason: format!(
                    "{} asked to rejoin without signing the request (an older client?); /group add them again if they are out of sync",
                    leaf.account.short()
                ),
            }]);
        };
        let crypto = self.provider.crypto();
        let reference: [u8; 32] = kp
            .hash_ref(crypto)
            .map_err(mls_err)?
            .as_slice()
            .try_into()
            .map_err(|_| GroupError::KeyPackage("hash ref is not 32 bytes".into()))?;
        let leaf_key = {
            let handle = load_handle(&mut self.handles, &self.provider, &group)?;
            handle
                .members()
                .find(|m| m.signature_key.as_slice() == leaf.device.as_bytes())
                .map(|m| m.encryption_key)
                .ok_or(GroupError::NotAMember(leaf.account))?
        };
        let statement = rejoin_statement(&group, &reference, &leaf_key);
        if leaf
            .device
            .verify(REJOIN_PROOF_DOMAIN, &statement, &proof.signature)
            .is_err()
        {
            return Ok(vec![GroupEvent::Refused {
                group,
                reason: format!(
                    "a rejoin request for {} that their device did not sign for the leaf it has now",
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
        if self.is_revoked_device(&leaf.device) {
            return Err(GroupError::KeyPackage(format!(
                "the device {}… was unlinked from its account",
                leaf.device.short()
            )));
        }
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

    /// The user says the group is out of sync (`/group rejoin` does this
    /// through [`Groups::rejoin_request`]). Only a group the user is in
    /// can be: an invitation waits for the user's yes whatever happens to
    /// it, and nothing else is in step to begin with.
    pub fn mark_out_of_sync(&mut self, group: &GroupId, now_ms: u64) -> Result<()> {
        let record = self.record_mut(group)?;
        if record.state != GroupState::Active {
            return Err(GroupError::NotActive(
                "not one that can fall out of sync".into(),
            ));
        }
        record.state = GroupState::OutOfSync { since_ms: now_ms };
        self.persist()
    }

    /// The relay's sequencer refused one of our commits as stale and
    /// stands at epoch `theirs`. If that is past ours, the group moved on
    /// without us: a commit race lost (the winner's commit is on its way)
    /// or a commit missed for good. The first answer is noted; a second
    /// one, [`BEHIND_GRACE_MS`] later with this client still short of
    /// that epoch, puts the group out of sync and returns
    /// [`GroupEvent::OutOfSync`], and the usual rejoin follows.
    ///
    /// This is the one way a group falls out of sync on someone else's
    /// word, and that someone is the relay, which could stop the group
    /// anyway by refusing every commit; a handshake's header, which
    /// anyone can write, only prompts the question
    /// ([`Groups::self_updates_due`]).
    pub fn sequencer_ahead(
        &mut self,
        group: &GroupId,
        theirs: u64,
        now_ms: u64,
    ) -> Result<Vec<GroupEvent>> {
        if self.record(group)?.state != GroupState::Active {
            return Ok(Vec::new());
        }
        let ours = load_handle(&mut self.handles, &self.provider, group)?
            .epoch()
            .as_u64();
        let record = self.record_mut(group)?;
        if theirs <= ours {
            return Ok(Vec::new());
        }
        let events = match record.behind {
            Some(behind) if behind.since_ms.saturating_add(BEHIND_GRACE_MS) <= now_ms => {
                record.behind = None;
                record.state = GroupState::OutOfSync { since_ms: now_ms };
                vec![GroupEvent::OutOfSync { group: *group }]
            }
            Some(behind) => {
                record.behind = Some(Behind {
                    epoch: behind.epoch.max(theirs),
                    ..behind
                });
                Vec::new()
            }
            None => {
                record.behind = Some(Behind {
                    epoch: theirs,
                    since_ms: now_ms,
                });
                Vec::new()
            }
        };
        self.persist()?;
        Ok(events)
    }

    fn extension(&mut self, group: &GroupId) -> Result<SilverGroup> {
        let handle = load_handle(&mut self.handles, &self.provider, group)?;
        extension_of(handle.extensions())
    }

    /// The identities still members after a commit that removes the leaves
    /// at `removing` and, when it consumes the stored proposals (as an
    /// admin's does), the leaves whose own Remove is stored (they left).
    fn members_after(
        &mut self,
        group: &GroupId,
        removing: &[LeafNodeIndex],
        consume: bool,
    ) -> Result<Vec<UserId>> {
        let handle = load_handle(&mut self.handles, &self.provider, group)?;
        let mut gone: Vec<LeafNodeIndex> = removing.to_vec();
        if consume {
            for queued in handle.pending_proposals() {
                if let Proposal::Remove(remove) = queued.proposal() {
                    gone.push(remove.removed());
                }
            }
        }
        let mut staying = Vec::new();
        for (index, leaf) in leaves_of(handle)? {
            if !gone.contains(&index) && !staying.contains(&leaf.account) {
                staying.push(leaf.account);
            }
        }
        Ok(staying)
    }

    /// The MLS storage, for tests.
    #[doc(hidden)]
    pub fn provider(&self) -> &Provider {
        &self.provider
    }
}

// --- helpers -------------------------------------------------------------------

/// How far out of order application messages from one sender are read.
/// Set on both the create and the join config, so it holds whether we made
/// the group or were invited to it.
fn sender_ratchet() -> SenderRatchetConfiguration {
    SenderRatchetConfiguration::new(OUT_OF_ORDER, FORWARD_DISTANCE)
}

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
    /// The leaf declares the everyday extension type: its client reads
    /// an edit, a deletion, a reaction and a timer (section 13.3).
    everyday: bool,
}

/// Whether `leaf` declares the everyday extension type.
fn declares_everyday(leaf: &LeafNode) -> bool {
    leaf.capabilities()
        .extensions()
        .contains(&ExtensionType::Unknown(EXTENSION_EVERYDAY))
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

/// The account a credential names: what a message's sender is taken to
/// be once OpenMLS has checked the signature against the leaf that
/// carried that credential in the message's epoch.
fn account_of(credential: &Credential) -> Result<UserId> {
    let bytes: [u8; 32] = credential
        .serialized_content()
        .try_into()
        .map_err(|_| GroupError::KeyPackage("credential is not a user id".into()))?;
    UserId::from_bytes(bytes)
        .map_err(|_| GroupError::KeyPackage("credential is not a valid key".into()))
}

/// Whether a handshake for `theirs` is further ahead of `ours` than any
/// hold queue would bridge. Saturating: a Welcome's epoch is whatever its
/// author wrote, and `ours + HOLD_LIMIT` overflowing panicked a release
/// build, which checks overflow.
fn too_far_ahead(ours: u64, theirs: u64) -> bool {
    theirs > ours.saturating_add(HOLD_LIMIT as u64)
}

/// Check a leaf: identity as above (`expected`'s, when given), and the
/// sealing key present.
fn verify_leaf(leaf: &LeafNode, expected: Option<&UserId>) -> Result<Leaf> {
    let (account, device) = identity_of(leaf)?;
    if let Some(expected) = expected
        && account != *expected
    {
        return Err(GroupError::KeyPackage("signed by another identity".into()));
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
        everyday: declares_everyday(leaf),
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

/// `extension` without the admins who are not among `members`, unless
/// that would leave nobody (which the readers refuse anyway).
fn without_departed_admins(extension: SilverGroup, members: &[UserId]) -> SilverGroup {
    if !extension.admins.iter().any(|a| members.contains(a)) {
        return extension;
    }
    let departed: Vec<UserId> = extension
        .admins
        .iter()
        .filter(|a| !members.contains(a))
        .copied()
        .collect();
    departed
        .iter()
        .fold(extension, |extension, admin| extension.without_admin(admin))
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
    // A member's own Remove is the honest way to leave, and OpenMLS's
    // commit builder consumes the stored proposal queue, so whoever
    // commits next carries it whether they meant to or not. Refusing
    // that made a non-admin's weekly self-update break the group and
    // blame the non-admin (SM-G-03).
    if !admin
        && removed
            .iter()
            .any(|(who, by_self)| who != committer && !by_self)
    {
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
    // Whose every leaf went by its own proposal: they left. An admin who
    // leaves is still named in the extension until an admin's commit
    // takes them out, and a member's self-update cannot touch the
    // extension — so requiring every admin to be a member broke the
    // group and blamed the honest committer (SM-G-03). That holds in the
    // leave commit and in every commit after it until an admin drops the
    // name (an admin's own commits do, `without_departed_admins`): a
    // commit that carried a leave without dropping the name, from an
    // older client, otherwise broke the group at the next commit anyone
    // made. What no commit may do is name somebody
    // outside the group who was not named before.
    let left_by_self: Vec<UserId> = removed
        .iter()
        .filter(|(_, by_self)| *by_self)
        .map(|(who, _)| *who)
        .filter(|who| {
            removed
                .iter()
                .filter(|(other, _)| other == who)
                .all(|(_, by_self)| *by_self)
        })
        .collect();
    let departed_admin = |a: &UserId| {
        before.admins.contains(a) && (!ids_before.contains(a) || left_by_self.contains(a))
    };
    if after
        .admins
        .iter()
        .any(|a| !ids_after.contains(a) && !departed_admin(a))
    {
        return Err("the commit names an admin who is not a member".into());
    }
    if ids_after.len() > MAX_MEMBERS {
        return Err("the commit makes the group too large".into());
    }
    // Every leaf in the tree after this commit, and how many each
    // identity has. A member could otherwise fill the tree with
    // self-certified "device" leaves of its own: the cap on identities
    // did not cap leaves, and every leaf costs every member a sealed
    // envelope per message and a place in every commit and Welcome
    // (SM-G-08).
    let leaves_after = leaves
        .iter()
        .filter(|(index, _)| !removed_indices.contains(index))
        .map(|(_, leaf)| leaf.account)
        .chain(adds.iter().map(|leaf| leaf.account));
    let mut per_identity: HashMap<UserId, usize> = HashMap::new();
    let mut total = 0usize;
    for account in leaves_after {
        *per_identity.entry(account).or_default() += 1;
        total += 1;
    }
    if let Some((who, count)) = per_identity.iter().find(|(_, n)| **n > MAX_DEVICES) {
        return Err(format!(
            "the commit gives {} {count} leaves, more than the {MAX_DEVICES} an account may link",
            who.short()
        ));
    }
    if total > MAX_MEMBERS * MAX_DEVICES {
        return Err("the commit puts more leaves in the tree than the group allows".into());
    }
    // The committer's own new leaf, and any leaf an Update proposal
    // carries, go through the same rule as an added one: without this a
    // member could self-update to a leaf with no sealing key (which makes
    // every later `leaves_of` fail, wedging the group and blaming the
    // next committer) or to a credential naming another identity it holds
    // (SM-G-04).
    let mut updated: Vec<(LeafNode, Option<UserId>)> = Vec::new();
    if let Some(leaf) = staged.update_path_leaf_node() {
        updated.push((leaf.clone(), Some(*committer)));
    }
    for proposal in staged.update_proposals() {
        updated.push((proposal.update_proposal().leaf_node().clone(), None));
    }
    for (leaf, expected) in &updated {
        let fresh = verify_leaf(leaf, expected.as_ref())
            .map_err(|e| format!("an updated leaf is not valid: {e}"))?;
        // And it stays the leaf it was: a leaf may be refreshed, not
        // handed to another identity or another device of one.
        let same = leaves
            .iter()
            .any(|(_, old)| old.account == fresh.account && old.device == fresh.device);
        if !same {
            return Err(format!(
                "the commit changes a leaf's identity to {}",
                fresh.account.short()
            ));
        }
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
