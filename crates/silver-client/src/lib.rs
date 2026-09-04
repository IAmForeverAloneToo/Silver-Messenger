//! Client core for Silver Message: everything a front end needs except the UI.
//!
//! * [`Store`] – on-disk identity, contacts, config and message history.
//! * [`Client`] – a background task that keeps a relay connection alive,
//!   authenticates, publishes our key bundle, decrypts inbound envelopes and
//!   reports everything as [`ClientEvent`]s.

pub mod connection;
pub mod store;
pub mod tls;

pub use connection::{Client, ClientError, ClientEvent, DEFAULT_RELAY_URL};
pub use silver_protocol as protocol;
pub use store::{Config, Contact, Direction, HistoryEntry, Store};
pub use tls::ConnectOptions;
