#![forbid(unsafe_code)]
//! Client core for Silver Messenger: everything a front end needs except the UI.
//!
//! * [`Store`] – on-disk identity, contacts, config and message history.
//! * [`SessionStore`] – forward-secret sessions and the prekeys peers start
//!   them against.
//! * [`Client`] – a background task that keeps a relay connection alive,
//!   authenticates, publishes our key bundle, decrypts inbound envelopes and
//!   reports everything as [`ClientEvent`]s.

pub mod backup;
pub mod connection;
pub mod cover;
pub mod devices;
pub mod everyday;
pub mod export;
pub mod files;
pub mod groups;
pub mod invite;
pub mod keystore;
pub mod linking;
mod outbox;
pub mod proxy;
pub mod receipts;
pub mod sequence;
pub mod sessions;
pub mod store;
mod submitter;
mod tail;
pub mod tls;
pub mod transparency;
pub mod update;
pub mod vault;

pub use backup::{BackupPayload, export_backup, import_backup, read_backup};
pub use connection::{
    Client, ClientError, ClientEvent, DEFAULT_RELAY_URL, Delivery, KeyPackageStatus, Lookup,
    Progress, SequencerAnswer, TransparencyEvent, observe_relay,
};
pub use cover::CoverSchedule;
pub use devices::{DeviceState, DevicesFile, Linked, SharedDevices};
pub use files::{FileInfo, human_size};
pub use groups::{
    Change, ExpectedGroup, GroupError, GroupEvent, GroupLink, GroupRecord, GroupState, Groups,
    HeldWelcome, MemberInfo, Outgoing, Staged,
};
pub use invite::InviteLink;
pub use linking::{
    DeviceLink, Imported, LinkError, Provisioning, Snapshot, SnapshotGroup, Taken, fetch_snapshot,
    take_link,
};
pub use proxy::Proxy;
pub use receipts::ReceiptQueue;
pub use sessions::{SessionError, SessionInfo, SessionStore, SharedSessions};
pub use transparency::{Discrepancy, LogStore, SharedLog};

/// What this client understands beyond plain text, advertised inside every
/// body it sends; see [`silver_protocol::envelope::capability`]. Cover
/// traffic (`cover`) is advertised on top of these only while the user has
/// it on ([`Client::set_cover`]).
pub const CAPABILITIES: &[&str] = &[
    silver_protocol::envelope::capability::RECEIPTS,
    silver_protocol::envelope::capability::FILES,
    silver_protocol::envelope::capability::PADDED_FILES,
    silver_protocol::envelope::capability::LIFECYCLE,
    silver_protocol::envelope::capability::EDITS,
    silver_protocol::envelope::capability::REACTIONS,
    silver_protocol::envelope::capability::TIMERS,
];

/// Signed protocol capabilities this client advertises in its published key
/// bundle, so peers know before the first message that it reads the
/// protocol-v4 (post-quantum, deniable) ratchet; see
/// [`silver_protocol::bundle::capability`].
pub const BUNDLE_CAPABILITIES: &[&str] = &[silver_protocol::bundle::capability::PQ_RATCHET];
pub use silver_protocol as protocol;
pub use store::{
    Config, Contact, ContactRequest, Conversation, Deletion, Direction, HeldMessage, HistoryEntry,
    Protection, Reaction, Store,
};
pub use tls::{ConnectOptions, Observed, Pin};
pub use vault::{FileCipher, VaultError};
