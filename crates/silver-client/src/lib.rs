//! Client core for Silver Messenger: everything a front end needs except the UI.
//!
//! * [`Store`] – on-disk identity, contacts, config and message history.
//! * [`Client`] – a background task that keeps a relay connection alive,
//!   authenticates, publishes our key bundle, decrypts inbound envelopes and
//!   reports everything as [`ClientEvent`]s.

pub mod backup;
pub mod connection;
mod outbox;
pub mod proxy;
pub mod sequence;
pub mod store;
pub mod tls;
pub mod vault;

pub use backup::{BackupPayload, export_backup, import_backup, read_backup};
pub use connection::{Client, ClientError, ClientEvent, DEFAULT_RELAY_URL};
pub use proxy::Proxy;
pub use silver_protocol as protocol;
pub use store::{Config, Contact, Direction, HistoryEntry, Store};
pub use tls::ConnectOptions;
pub use vault::{FileCipher, VaultError};
