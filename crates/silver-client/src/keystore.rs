//! The operating system's key store, where the key that wraps the data
//! key lives when no passphrase is set: the Credential Manager on Windows,
//! the Keychain on macOS, the Secret Service (GNOME Keyring, KWallet) on
//! Linux. A copied data directory is then unreadable without this
//! computer's account, and nothing is asked at start.
//!
//! The store is not always there: a headless Linux box has no Secret
//! Service, and a container has nothing at all. [`available`] says, and
//! the client falls back to plain files with a warning.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use anyhow::Context;
use keyring::Entry;
use rand::RngCore;
use rand::rngs::OsRng;
use silver_protocol::encoding::{from_base64, to_base64};
use zeroize::Zeroizing;

/// The service every entry is filed under.
const SERVICE: &str = "silver-messenger";

/// An in-memory stand-in for tests, so they never touch a real key chain.
static TEST_STORE: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);

fn test_store() -> MutexGuard<'static, Option<HashMap<String, String>>> {
    TEST_STORE.lock().unwrap_or_else(|e| e.into_inner())
}

fn entry(name: &str) -> anyhow::Result<Entry> {
    Entry::new(SERVICE, name).context("naming the key store entry")
}

fn decode(text: &str) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let bytes =
        Zeroizing::new(from_base64(text.trim()).context("the key store entry is not base64")?);
    let key: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .context("the key store entry has the wrong size")?;
    Ok(Zeroizing::new(key))
}

/// Whether a key store answers at all: an entry that does not exist must
/// come back as "no entry", not as a failure to reach the store.
pub fn available() -> bool {
    if test_store().is_some() {
        return true;
    }
    match entry("probe").and_then(|e| match e.get_password() {
        Ok(_) | Err(keyring::Error::NoEntry) => Ok(true),
        Err(e) => Err(e.into()),
    }) {
        Ok(_) => true,
        Err(e) => {
            tracing::debug!("no usable key store: {e:#}");
            false
        }
    }
}

/// The wrapping key kept under `name`, if the store has one.
pub fn load(name: &str) -> anyhow::Result<Option<Zeroizing<[u8; 32]>>> {
    if let Some(map) = test_store().as_ref() {
        return map.get(name).map(|t| decode(t)).transpose();
    }
    let text = match entry(name)?.get_password() {
        Ok(text) => Zeroizing::new(text),
        Err(keyring::Error::NoEntry) => return Ok(None),
        Err(e) => return Err(e).context("reading the key store"),
    };
    decode(&text).map(Some)
}

/// Make a fresh wrapping key and keep it under `name`.
pub fn create(name: &str) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(key.as_mut_slice());
    let text = to_base64(key.as_slice());
    if let Some(map) = test_store().as_mut() {
        map.insert(name.to_owned(), text);
        return Ok(key);
    }
    entry(name)?
        .set_password(&text)
        .context("writing to the key store")?;
    Ok(key)
}

/// Forget the key under `name`; a missing one is fine.
pub fn delete(name: &str) -> anyhow::Result<()> {
    if let Some(map) = test_store().as_mut() {
        map.remove(name);
        return Ok(());
    }
    match entry(name)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e).context("removing from the key store"),
    }
}

/// Route every entry to an in-memory store for the rest of the process:
/// for tests, which must not touch the developer's key chain.
#[doc(hidden)]
pub fn use_mock_store() {
    let mut store = test_store();
    if store.is_none() {
        *store = Some(HashMap::new());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_kept_and_forgotten() {
        use_mock_store();
        assert!(available());
        assert!(load("data-key-test").unwrap().is_none());
        let key = create("data-key-test").unwrap();
        assert_eq!(load("data-key-test").unwrap().unwrap(), key);
        delete("data-key-test").unwrap();
        assert!(load("data-key-test").unwrap().is_none());
        delete("data-key-test").unwrap();
    }
}
