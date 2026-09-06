//! Encryption at rest for the data directory.
//!
//! A passphrase unlocks a random 256-bit data key kept in `vault.json`: the
//! passphrase is stretched with Argon2id and the result wraps the data key
//! with XChaCha20-Poly1305. Every file is then encrypted with the data key
//! and bound to its own name, so files cannot be swapped for one another.
//! Line-oriented files (history) encrypt each line separately, so appending
//! stays cheap.

use std::fmt;

use anyhow::{Context, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use silver_protocol::encoding::{b64, b64_array, b64_opt, from_base64, to_base64};
use zeroize::Zeroizing;

const VAULT_AAD: &[u8] = b"silver-messenger/v1/vault";
pub(crate) const FILE_MAGIC: &[u8; 4] = b"SMV1";
/// Prefix of an encrypted line in a line-oriented file.
pub const LINE_PREFIX: &str = "enc:";
/// `Kdf::algorithm` when the data key is wrapped under a random key kept
/// in the operating system's key store rather than under a passphrase.
pub const KEYSTORE_ALGORITHM: &str = "os-keystore";
const PASSPHRASE_ALGORITHM: &str = "argon2id";

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("wrong passphrase")]
    WrongPassphrase,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Argon2id parameters and salt used to stretch the passphrase.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Kdf {
    pub algorithm: String,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    #[serde(with = "b64_array")]
    pub salt: [u8; 16],
}

impl Kdf {
    /// 64 MiB, 3 passes: a few hundred milliseconds on a laptop.
    pub fn default_params() -> Self {
        Self::with_params(64 * 1024, 3, 1)
    }

    /// Cheap parameters for tests only.
    #[doc(hidden)]
    pub fn fast() -> Self {
        Self::with_params(8 * 1024, 1, 1)
    }

    fn with_params(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Self {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        Self {
            algorithm: PASSPHRASE_ALGORITHM.into(),
            m_cost_kib,
            t_cost,
            p_cost,
            salt,
        }
    }

    /// No stretching: the wrapping key comes from the key store. The salt
    /// doubles as the name the key is stored under.
    pub fn keystore() -> Self {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        Self {
            algorithm: KEYSTORE_ALGORITHM.into(),
            m_cost_kib: 0,
            t_cost: 0,
            p_cost: 0,
            salt,
        }
    }

    pub fn is_keystore(&self) -> bool {
        self.algorithm == KEYSTORE_ALGORITHM
    }

    /// The name the key store keeps this vault's wrapping key under.
    pub fn keystore_name(&self) -> String {
        let hex: String = self.salt.iter().map(|b| format!("{b:02x}")).collect();
        format!("data-key-{hex}")
    }
}

/// Contents of `vault.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultFile {
    pub version: u32,
    pub kdf: Kdf,
    /// `nonce || XChaCha20-Poly1305(data key)` under the stretched passphrase.
    #[serde(with = "b64")]
    pub wrapped_key: Vec<u8>,
    /// The data key the directory is being moved off, wrapped under the
    /// same new key-encryption key. Present only while a rotation is under
    /// way: it says that some files are still under the old key and that
    /// reading them is expected. When the last one has been rewritten the
    /// field goes, and with it the old key.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "b64_opt")]
    pub previous_key: Option<Vec<u8>>,
}

/// The unlocked data key, and — during a rotation — the one before it.
pub struct FileCipher {
    key: Zeroizing<[u8; 32]>,
    previous: Option<Zeroizing<[u8; 32]>>,
}

impl fmt::Debug for FileCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FileCipher(..)")
    }
}

impl FileCipher {
    /// Make a fresh data key wrapped under `passphrase`.
    pub fn create(passphrase: &str, kdf: Kdf) -> anyhow::Result<(VaultFile, Self)> {
        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(key.as_mut_slice());
        let kek = derive(&kdf, passphrase)?;
        let wrapped_key = seal(&kek, VAULT_AAD, key.as_slice());
        Ok((
            VaultFile {
                version: 1,
                kdf,
                wrapped_key,
                previous_key: None,
            },
            Self {
                key,
                previous: None,
            },
        ))
    }

    /// Recover the data key from `vault` with `passphrase`.
    pub fn unlock(vault: &VaultFile, passphrase: &str) -> Result<Self, VaultError> {
        if vault.version != 1 || vault.kdf.algorithm != PASSPHRASE_ALGORITHM {
            return Err(anyhow::anyhow!("unsupported vault format").into());
        }
        let kek = derive(&vault.kdf, passphrase)?;
        Self::unwrap(vault, &kek)
    }

    /// Make a fresh data key wrapped under `kek`, a random key the caller
    /// keeps in the operating system's key store.
    pub fn create_with_kek(kek: &[u8; 32]) -> (VaultFile, Self) {
        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(key.as_mut_slice());
        let cipher = Self {
            key,
            previous: None,
        };
        let vault = cipher.wrap_under_kek(kek, Kdf::keystore());
        (vault, cipher)
    }

    /// Recover the data key from a key-store vault with its `kek`.
    pub fn unlock_with_kek(vault: &VaultFile, kek: &[u8; 32]) -> Result<Self, VaultError> {
        if vault.version != 1 || !vault.kdf.is_keystore() {
            return Err(anyhow::anyhow!("unsupported vault format").into());
        }
        Self::unwrap(vault, kek)
    }

    fn unwrap(vault: &VaultFile, kek: &[u8; 32]) -> Result<Self, VaultError> {
        let unwrap_one = |wrapped: &[u8]| -> Result<Zeroizing<[u8; 32]>, VaultError> {
            let key = open(kek, VAULT_AAD, wrapped).ok_or(VaultError::WrongPassphrase)?;
            let key: [u8; 32] = key
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("vault holds a key of the wrong size"))?;
            Ok(Zeroizing::new(key))
        };
        Ok(Self {
            key: unwrap_one(&vault.wrapped_key)?,
            previous: vault.previous_key.as_deref().map(unwrap_one).transpose()?,
        })
    }

    /// A fresh data key to move the directory onto, with the current one
    /// kept alongside so files still under it can be read while they are
    /// rewritten. [`VaultFile::previous_key`] says the same on disk.
    pub fn rotating(&self) -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(key.as_mut_slice());
        Self {
            key,
            previous: Some(self.key.clone()),
        }
    }

    /// The same key with the rotation finished: nothing is left under the
    /// old one, so it is dropped.
    pub fn settled(&self) -> Self {
        Self {
            key: self.key.clone(),
            previous: None,
        }
    }

    /// The same data key wrapped under `passphrase` instead: files need no
    /// rewriting when the protection changes.
    pub fn wrap_under_passphrase(&self, passphrase: &str, kdf: Kdf) -> anyhow::Result<VaultFile> {
        let kek = derive(&kdf, passphrase)?;
        Ok(self.wrapped(kdf, &kek))
    }

    /// The same data key wrapped under a key-store `kek`.
    pub fn wrap_under_kek(&self, kek: &[u8; 32], kdf: Kdf) -> VaultFile {
        self.wrapped(kdf, kek)
    }

    /// Both keys wrapped under `kek`, so a rotation left half-done is
    /// still readable: whichever key a file is under is in the vault.
    fn wrapped(&self, kdf: Kdf, kek: &[u8; 32]) -> VaultFile {
        VaultFile {
            version: 1,
            kdf,
            wrapped_key: seal(kek, VAULT_AAD, self.key.as_slice()),
            previous_key: self
                .previous
                .as_ref()
                .map(|old| seal(kek, VAULT_AAD, old.as_slice())),
        }
    }

    pub fn is_encrypted(bytes: &[u8]) -> bool {
        bytes.starts_with(FILE_MAGIC)
    }

    /// Encrypt a whole file; `name` is bound as associated data.
    pub fn encrypt(&self, name: &str, plaintext: &[u8]) -> Vec<u8> {
        let mut out = FILE_MAGIC.to_vec();
        out.extend(seal(&self.key, name.as_bytes(), plaintext));
        out
    }

    pub fn decrypt(&self, name: &str, bytes: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let body = bytes
            .strip_prefix(FILE_MAGIC)
            .context("file is not encrypted")?;
        open(&self.key, name.as_bytes(), body)
            .or_else(|| self.previous(name.as_bytes(), body))
            .with_context(|| format!("could not decrypt {name}: wrong key or damaged file"))
    }

    /// The same bytes under the key a rotation is moving off, if there is
    /// one. A file not yet rewritten is under it and is not damaged.
    fn previous(&self, aad: &[u8], body: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        open(self.previous.as_ref()?, aad, body)
    }

    /// Encrypt one line of a line-oriented file.
    pub fn encrypt_line(&self, name: &str, line: &str) -> String {
        format!(
            "{LINE_PREFIX}{}",
            to_base64(&seal(&self.key, name.as_bytes(), line.as_bytes()))
        )
    }

    pub fn decrypt_line(&self, name: &str, line: &str) -> anyhow::Result<String> {
        let body = line
            .strip_prefix(LINE_PREFIX)
            .context("line is not encrypted")?;
        let bytes = from_base64(body.trim()).context("encrypted line is not base64")?;
        let plain = open(&self.key, name.as_bytes(), &bytes)
            .or_else(|| self.previous(name.as_bytes(), &bytes))
            .with_context(|| format!("could not decrypt a line of {name}"))?;
        String::from_utf8(plain.to_vec()).context("decrypted line is not UTF-8")
    }
}

/// Most a stored `Kdf` may ask for. The parameters live outside the AEAD
/// — they are what the key to check the AEAD is made from — so a file
/// handed to somebody, or a real one edited in place, can name any cost
/// the `argon2` crate accepts, which is up to 4 TiB of memory. These are
/// far above the defaults (64 MiB, 3 passes, 1 lane) and far below what
/// takes a machine down.
const MAX_M_COST_KIB: u32 = 1024 * 1024;
const MAX_T_COST: u32 = 16;
const MAX_P_COST: u32 = 8;

fn derive(kdf: &Kdf, passphrase: &str) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    if passphrase.is_empty() {
        bail!("the passphrase must not be empty");
    }
    if kdf.m_cost_kib > MAX_M_COST_KIB || kdf.t_cost > MAX_T_COST || kdf.p_cost > MAX_P_COST {
        bail!(
            "the file asks for more work than this program will do to open it \
             ({} KiB of memory, {} passes, {} lanes; the most are {MAX_M_COST_KIB}, \
             {MAX_T_COST} and {MAX_P_COST})",
            kdf.m_cost_kib,
            kdf.t_cost,
            kdf.p_cost
        );
    }
    let params = Params::new(kdf.m_cost_kib, kdf.t_cost, kdf.p_cost, Some(32))
        .map_err(|e| anyhow::anyhow!("invalid KDF parameters: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), &kdf.salt, out.as_mut_slice())
        .map_err(|e| anyhow::anyhow!("stretching the passphrase failed: {e}"))?;
    Ok(out)
}

/// `nonce || ciphertext`.
fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption cannot fail");
    let mut out = nonce.to_vec();
    out.extend(ciphertext);
    out
}

fn open(key: &[u8; 32], aad: &[u8], bytes: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let (nonce, ciphertext) = bytes.split_first_chunk::<24>()?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
        .map(Zeroizing::new)
}

/// Encrypt `plaintext` directly under a passphrase (no vault involved), for
/// self-contained files such as backups. Returns `nonce || ciphertext`.
pub fn encrypt_with_passphrase(
    passphrase: &str,
    kdf: &Kdf,
    aad: &[u8],
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let key = derive(kdf, passphrase)?;
    Ok(seal(&key, aad, plaintext))
}

/// Inverse of [`encrypt_with_passphrase`].
pub fn decrypt_with_passphrase(
    passphrase: &str,
    kdf: &Kdf,
    aad: &[u8],
    bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let key = derive(kdf, passphrase)?;
    open(&key, aad, bytes).ok_or(VaultError::WrongPassphrase)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The work the parameters ask for is what makes the key to check the
    /// AEAD, so they cannot be authenticated and a file can name any cost
    /// at all. One that names more than this program will do is refused,
    /// rather than asking the allocator for it and being killed.
    #[test]
    fn a_file_cannot_ask_for_more_work_than_the_program_will_do() {
        let (mut vault, _) = FileCipher::create("hunter2", Kdf::fast()).unwrap();
        assert!(FileCipher::unlock(&vault, "hunter2").is_ok());
        let sane = vault.kdf.clone();
        for kdf in [
            Kdf {
                m_cost_kib: u32::MAX,
                ..sane.clone()
            },
            Kdf {
                t_cost: 1_000_000,
                ..sane.clone()
            },
            Kdf {
                p_cost: 4096,
                ..sane.clone()
            },
        ] {
            vault.kdf = kdf;
            let refusal = FileCipher::unlock(&vault, "hunter2").unwrap_err();
            assert!(
                refusal.to_string().contains("more work"),
                "{refusal} should have been a refusal to do the work"
            );
        }
    }

    /// A rotation is readable from either side while it runs: the vault
    /// carries both keys, so a file already rewritten and one not yet are
    /// both opened by the cipher the vault yields.
    #[test]
    fn a_rotation_reads_what_is_under_either_key() {
        let (vault, old) = FileCipher::create("hunter2", Kdf::fast()).unwrap();
        let before = old.encrypt("contacts.json", b"[1]");
        let line_before = old.encrypt_line("history/x.jsonl", "old");

        let rotating = old.rotating();
        let vault = rotating
            .wrap_under_passphrase("hunter2", vault.kdf)
            .unwrap();
        assert!(vault.previous_key.is_some());
        let rotating = FileCipher::unlock(&vault, "hunter2").unwrap();
        let after = rotating.encrypt("contacts.json", b"[2]");
        assert_eq!(
            rotating
                .decrypt("contacts.json", &before)
                .unwrap()
                .as_slice(),
            b"[1]"
        );
        assert_eq!(
            rotating
                .decrypt("contacts.json", &after)
                .unwrap()
                .as_slice(),
            b"[2]"
        );
        assert_eq!(
            rotating
                .decrypt_line("history/x.jsonl", &line_before)
                .unwrap(),
            "old"
        );

        // Once the last file has moved the old key goes, and with it what
        // an old copy of the vault plus the old passphrase could open.
        let settled = rotating.settled();
        assert!(
            settled
                .wrap_under_passphrase("hunter2", vault.kdf)
                .unwrap()
                .previous_key
                .is_none()
        );
        assert_eq!(
            settled.decrypt("contacts.json", &after).unwrap().as_slice(),
            b"[2]"
        );
        assert!(settled.decrypt("contacts.json", &before).is_err());
    }

    #[test]
    fn vault_round_trips_and_rejects_wrong_passphrase() {
        let (vault, cipher) = FileCipher::create("hunter2", Kdf::fast()).unwrap();
        let json = serde_json::to_string(&vault).unwrap();
        let vault: VaultFile = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            FileCipher::unlock(&vault, "hunter3"),
            Err(VaultError::WrongPassphrase)
        ));
        let again = FileCipher::unlock(&vault, "hunter2").unwrap();

        let blob = cipher.encrypt("contacts.json", b"[]");
        assert!(FileCipher::is_encrypted(&blob));
        assert_eq!(
            again.decrypt("contacts.json", &blob).unwrap().as_slice(),
            b"[]"
        );
        // Bound to the file name.
        assert!(again.decrypt("identity.json", &blob).is_err());

        let line = cipher.encrypt_line("history/x.jsonl", "{\"a\":1}");
        assert!(line.starts_with(LINE_PREFIX));
        assert_eq!(
            again.decrypt_line("history/x.jsonl", &line).unwrap(),
            "{\"a\":1}"
        );
        assert!(again.decrypt_line("history/y.jsonl", &line).is_err());
    }

    #[test]
    fn empty_passphrase_is_refused() {
        assert!(FileCipher::create("", Kdf::fast()).is_err());
    }

    #[test]
    fn the_data_key_moves_between_a_key_store_key_and_a_passphrase() {
        let kek = [9u8; 32];
        let (vault, cipher) = FileCipher::create_with_kek(&kek);
        assert!(vault.kdf.is_keystore());
        assert!(vault.kdf.keystore_name().starts_with("data-key-"));
        let blob = cipher.encrypt("contacts.json", b"[1]");
        let again = FileCipher::unlock_with_kek(&vault, &kek).unwrap();
        assert_eq!(
            again.decrypt("contacts.json", &blob).unwrap().as_slice(),
            b"[1]"
        );
        assert!(FileCipher::unlock_with_kek(&vault, &[8u8; 32]).is_err());
        assert!(
            FileCipher::unlock(&vault, "hunter2").is_err(),
            "not a passphrase vault"
        );
        // Rewrapped under a passphrase, the files stay as they are.
        let rewrapped = cipher
            .wrap_under_passphrase("hunter2", Kdf::fast())
            .unwrap();
        let by_passphrase = FileCipher::unlock(&rewrapped, "hunter2").unwrap();
        assert_eq!(
            by_passphrase
                .decrypt("contacts.json", &blob)
                .unwrap()
                .as_slice(),
            b"[1]"
        );
        assert!(FileCipher::unlock_with_kek(&rewrapped, &kek).is_err());
        // And back.
        let back = by_passphrase.wrap_under_kek(&kek, Kdf::keystore());
        let by_kek = FileCipher::unlock_with_kek(&back, &kek).unwrap();
        assert_eq!(
            by_kek.decrypt("contacts.json", &blob).unwrap().as_slice(),
            b"[1]"
        );
    }
}
