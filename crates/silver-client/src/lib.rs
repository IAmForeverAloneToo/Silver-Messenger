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
pub mod files;
pub mod invite;
pub mod keystore;
mod outbox;
pub mod proxy;
pub mod receipts;
pub mod sequence;
pub mod sessions;
pub mod store;
mod submitter;
pub mod tls;
pub mod vault;

pub use backup::{BackupPayload, export_backup, import_backup, read_backup};
pub use connection::{Client, ClientError, ClientEvent, DEFAULT_RELAY_URL, Delivery, Progress};
pub use files::{FileInfo, human_size};
pub use invite::InviteLink;
pub use proxy::Proxy;
pub use receipts::ReceiptQueue;
pub use sessions::{SessionError, SessionInfo, SessionStore, SharedSessions};

/// What this client understands beyond plain text, advertised inside every
/// body it sends; see [`silver_protocol::envelope::capability`].
pub const CAPABILITIES: &[&str] = &[
    silver_protocol::envelope::capability::RECEIPTS,
    silver_protocol::envelope::capability::FILES,
];
pub use silver_protocol as protocol;
pub use store::{
    Config, Contact, ContactRequest, Direction, HeldMessage, HistoryEntry, Protection, Store,
};
pub use tls::ConnectOptions;
pub use vault::{FileCipher, VaultError};
