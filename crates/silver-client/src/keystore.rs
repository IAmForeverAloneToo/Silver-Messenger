//! The operating system's key store, where the key that wraps the data
//! key lives when no passphrase is set: the Credential Manager on Windows,
//! the Keychain on macOS, the Secret Service (GNOME Keyring, KWallet) on
//! Linux. A copied data directory is then unreadable without this
//! computer's account, and nothing is asked at start.
//!
//! The store is not always there: a headless Linux box has no Secret
//! Service, and a container has nothing at all. [`available`] says, and
//! the client falls back to plain files with a warning.
//!
//! Each entry is the base64 of a 32-byte key, filed under the service
//! [`SERVICE`] and the name the vault gives it, exactly where the keyring
//! 3 crate filed it for clients up to 0.19: a generic credential
//! `<name>.silver-messenger` on Windows, a generic password in the login
//! keychain on macOS, and an item in the default collection of the Secret
//! Service everywhere else (`secret_service.rs`).

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use anyhow::Context;
use rand::RngCore;
use rand::rngs::OsRng;
use silver_protocol::encoding::{from_base64, to_base64};
use zeroize::Zeroizing;

#[cfg(all(unix, not(target_os = "macos")))]
mod secret_service;
#[cfg(all(unix, not(target_os = "macos")))]
use secret_service as platform;

/// The service every entry is filed under.
const SERVICE: &str = "silver-messenger";

/// An in-memory stand-in for tests, so they never touch a real key chain.
static TEST_STORE: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);

fn test_store() -> MutexGuard<'static, Option<HashMap<String, String>>> {
    TEST_STORE.lock().unwrap_or_else(|e| e.into_inner())
}

/// Windows and macOS: the native store through keyring-core.
#[cfg(any(windows, target_os = "macos"))]
mod platform {
    use std::sync::LazyLock;

    use anyhow::Context;
    use keyring_core::{Entry, Error};
    use zeroize::Zeroizing;

    use super::SERVICE;

    /// keyring-core's default store, set once; what went wrong if it could
    /// not be.
    static STORE: LazyLock<Result<(), String>> = LazyLock::new(|| {
        #[cfg(windows)]
        let store = windows_native_keyring_store::Store::new();
        #[cfg(target_os = "macos")]
        let store = apple_native_keyring_store::keychain::Store::new();
        let store = store.map_err(|e| e.to_string())?;
        keyring_core::set_default_store(store);
        Ok(())
    });

    fn entry(name: &str) -> anyhow::Result<Entry> {
        if let Err(e) = &*STORE {
            anyhow::bail!("opening the key store: {e}");
        }
        Entry::new(SERVICE, name).context("naming the key store entry")
    }

    pub fn probe() -> anyhow::Result<()> {
        get("probe").map(|_| ())
    }

    pub fn get(name: &str) -> anyhow::Result<Option<Zeroizing<String>>> {
        match entry(name)?.get_password() {
            Ok(text) => Ok(Some(Zeroizing::new(text))),
            Err(Error::NoEntry) => Ok(None),
            Err(e) => Err(e).context("reading the key store"),
        }
    }

    pub fn set(name: &str, text: &str) -> anyhow::Result<()> {
        entry(name)?
            .set_password(text)
            .context("writing to the key store")
    }

    pub fn remove(name: &str) -> anyhow::Result<()> {
        match entry(name)?.delete_credential() {
            Ok(()) | Err(Error::NoEntry) => Ok(()),
            Err(e) => Err(e).context("removing from the key store"),
        }
    }
}

/// Anywhere else there is no key store to use.
#[cfg(not(any(unix, windows)))]
mod platform {
    use zeroize::Zeroizing;

    const NONE: &str = "this platform has no key store the client can use";

    pub fn probe() -> anyhow::Result<()> {
        anyhow::bail!(NONE)
    }

    pub fn get(_: &str) -> anyhow::Result<Option<Zeroizing<String>>> {
        anyhow::bail!(NONE)
    }

    pub fn set(_: &str, _: &str) -> anyhow::Result<()> {
        anyhow::bail!(NONE)
    }

    pub fn remove(_: &str) -> anyhow::Result<()> {
        anyhow::bail!(NONE)
    }
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
    match platform::probe() {
        Ok(()) => true,
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
    match platform::get(name)? {
        Some(text) => decode(&text).map(Some),
        None => Ok(None),
    }
}

/// Make a fresh wrapping key and keep it under `name`.
pub fn create(name: &str) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(key.as_mut_slice());
    let text = Zeroizing::new(to_base64(key.as_slice()));
    if let Some(map) = test_store().as_mut() {
        map.insert(name.to_owned(), text.to_string());
        return Ok(key);
    }
    platform::set(name, &text)?;
    Ok(key)
}

/// Forget the key under `name`; a missing one is fine.
pub fn delete(name: &str) -> anyhow::Result<()> {
    if let Some(map) = test_store().as_mut() {
        map.remove(name);
        return Ok(());
    }
    platform::remove(name)
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
