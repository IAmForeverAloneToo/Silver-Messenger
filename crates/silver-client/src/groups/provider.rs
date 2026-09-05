//! The OpenMLS provider: RustCrypto for the cryptography and randomness,
//! and an in-memory storage whose whole map is written to the data
//! directory after every change, encrypted like the sessions file when
//! the directory is protected.
//!
//! OpenMLS deletes what it no longer needs from the map (spent key package
//! secrets, old epoch keys), and the next write drops them from the file;
//! at-rest forward secrecy is therefore best effort, as for `sessions.json`.

use std::collections::HashMap;

use openmls_memory_storage::MemoryStorage;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};
use silver_protocol::encoding::{from_base64, to_base64};

/// What [`Provider::export`] writes: every entry of the storage map.
#[derive(Default, Serialize, Deserialize)]
struct MlsFile {
    entries: Vec<(String, String)>,
}

pub struct Provider {
    crypto: RustCrypto,
    storage: MemoryStorage,
}

impl Provider {
    pub fn new() -> Self {
        Self {
            crypto: RustCrypto::default(),
            storage: MemoryStorage::default(),
        }
    }

    /// A provider whose storage holds what [`Provider::export`] wrote.
    pub fn from_export(bytes: &[u8]) -> anyhow::Result<Self> {
        let file: MlsFile = serde_json::from_slice(bytes)?;
        let mut map = HashMap::with_capacity(file.entries.len());
        for (key, value) in file.entries {
            map.insert(from_base64(&key)?, from_base64(&value)?);
        }
        let storage = MemoryStorage::default();
        *storage.values.write().unwrap_or_else(|e| e.into_inner()) = map;
        Ok(Self {
            crypto: RustCrypto::default(),
            storage,
        })
    }

    /// The storage map as bytes, for the data directory.
    pub fn export(&self) -> Vec<u8> {
        let values = self
            .storage
            .values
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let mut entries: Vec<(String, String)> = values
            .iter()
            .map(|(k, v)| (to_base64(k), to_base64(v)))
            .collect();
        entries.sort();
        serde_json::to_vec(&MlsFile { entries }).expect("strings serialize")
    }

    /// How many entries the storage holds; for tests.
    pub fn entries(&self) -> usize {
        self.storage
            .values
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }
}

impl Default for Provider {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenMlsProvider for Provider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}
