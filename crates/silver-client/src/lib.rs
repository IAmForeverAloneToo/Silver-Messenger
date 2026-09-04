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
mod outbox;
pub mod proxy;
pub mod sequence;
pub mod sessions;
pub mod store;
mod submitter;
pub mod tls;
pub mod vault;

pub use backup::{BackupPayload, export_backup, import_backup, read_backup};
pub use connection::{Client, ClientError, ClientEvent, DEFAULT_RELAY_URL, Delivery};
pub use proxy::Proxy;
pub use sessions::{SessionError, SessionInfo, SessionStore, SharedSessions};
pub use silver_protocol as protocol;
pub use store::{Config, Contact, ContactRequest, Direction, HeldMessage, HistoryEntry, Store};
pub use tls::ConnectOptions;
pub use vault::{FileCipher, VaultError};
