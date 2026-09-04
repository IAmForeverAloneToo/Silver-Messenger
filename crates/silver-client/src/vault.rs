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
use silver_protocol::encoding::{b64, b64_array, from_base64, to_base64};
use zeroize::Zeroizing;

const VAULT_AAD: &[u8] = b"silver-messenger/v1/vault";
const FILE_MAGIC: &[u8; 4] = b"SMV1";
/// Prefix of an encrypted line in a line-oriented file.
pub const LINE_PREFIX: &str = "enc:";

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
            algorithm: "argon2id".into(),
            m_cost_kib,
            t_cost,
            p_cost,
            salt,
        }
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
}

/// The unlocked data key.
pub struct FileCipher {
    key: Zeroizing<[u8; 32]>,
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
            },
            Self { key },
        ))
    }

    /// Recover the data key from `vault` with `passphrase`.
    pub fn unlock(vault: &VaultFile, passphrase: &str) -> Result<Self, VaultError> {
        if vault.version != 1 || vault.kdf.algorithm != "argon2id" {
            return Err(anyhow::anyhow!("unsupported vault format").into());
        }
        let kek = derive(&vault.kdf, passphrase)?;
        let key = open(&kek, VAULT_AAD, &vault.wrapped_key).ok_or(VaultError::WrongPassphrase)?;
        let key: [u8; 32] = key
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("vault holds a key of the wrong size"))?;
        Ok(Self {
            key: Zeroizing::new(key),
        })
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
            .with_context(|| format!("could not decrypt {name}: wrong key or damaged file"))
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
            .with_context(|| format!("could not decrypt a line of {name}"))?;
        String::from_utf8(plain.to_vec()).context("decrypted line is not UTF-8")
    }
}

fn derive(kdf: &Kdf, passphrase: &str) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    if passphrase.is_empty() {
        bail!("the passphrase must not be empty");
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
}
