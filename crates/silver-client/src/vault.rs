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
use hmac::{Hmac, Mac};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use silver_protocol::encoding::{b64, b64_array, b64_opt, from_base64, to_base64};
use zeroize::Zeroizing;

const VAULT_AAD: &[u8] = b"silver-messenger/v1/vault";
/// Associated data for the naming key, so that it and the data key cannot
/// be swapped for one another inside the vault.
const NAMING_AAD: &[u8] = b"silver-messenger/v1/vault/naming";
/// In front of the id when naming a history file, so that this use of the
/// naming key stands apart from any other.
const HISTORY_NAME_DOMAIN: &[u8] = b"silver-messenger/v1/history-name\0";
pub(crate) const FILE_MAGIC: &[u8; 4] = b"SMV1";
/// A file that carries the generation it was written at, in the eight
/// bytes after this. Its own magic rather than a flag inside the first,
/// so a reader knows the shape before it has decrypted anything.
pub(crate) const GENERATION_MAGIC: &[u8; 4] = b"SMV2";
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
    /// Which version of `state` belongs to this directory, or `None` in a
    /// directory written before rollback binding existed.
    ///
    /// This is the one number that anchors the rest, and it sits in the
    /// clear because `vault.json` is read before there is a key to read
    /// anything with. It says how many times the directory has been
    /// written and nothing else -- no name, no id -- which the
    /// modification times already say. Everything that would name
    /// something is in `state`, encrypted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_generation: Option<u64>,
    /// The key history file names are MACed under (SM-C-25), wrapped
    /// under the same key-encryption key as the data key.
    ///
    /// A key of its own, and kept here rather than derived from the data
    /// key, because the data key rotates: a passphrase set or dropped
    /// moves every file onto a fresh one, and a name derived from it
    /// would rename every conversation on disk each time. It is also not
    /// in `state`, so that losing that record does not lose the names —
    /// the files would still decrypt and nobody would know which was
    /// which. Wrapping it here means a rotation re-wraps it and leaves it
    /// alone.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "b64_opt")]
    pub wrapped_naming_key: Option<Vec<u8>>,
}

/// A file that opened, and the generation it says it was written at.
pub struct OpenedFile {
    /// `None` for a file bound to its name alone, which is every file in
    /// a directory that has not adopted rollback binding.
    pub generation: Option<u64>,
    pub plain: Zeroizing<Vec<u8>>,
}

/// The unlocked data key, the key history names are MACed under, and —
/// during a rotation — the data key before it.
pub struct FileCipher {
    key: Zeroizing<[u8; 32]>,
    previous: Option<Zeroizing<[u8; 32]>>,
    naming_key: Zeroizing<[u8; 32]>,
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
        let naming_key = fresh_naming_key();
        Ok((
            VaultFile {
                version: 1,
                kdf,
                wrapped_key,
                previous_key: None,
                // A fresh directory has no `state` yet; the store writes
                // one and stamps this on the first write.
                state_generation: None,
                wrapped_naming_key: Some(seal(&kek, NAMING_AAD, naming_key.as_slice())),
            },
            Self {
                key,
                previous: None,
                naming_key,
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
            naming_key: fresh_naming_key(),
        };
        // A fresh directory, so no `state` to point at yet.
        let vault = cipher.wrap_under_kek(kek, Kdf::keystore(), None);
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
        // A vault written before history names moved has no naming key,
        // and gets one now: it has no history under a MACed name to
        // orphan, so a fresh key costs nothing. It reaches the file at
        // the next write of the vault, which the adoption does.
        let naming_key = match &vault.wrapped_naming_key {
            Some(wrapped) => {
                let key = open(kek, NAMING_AAD, wrapped).ok_or(VaultError::WrongPassphrase)?;
                let key: [u8; 32] = key
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("vault holds a naming key of the wrong size"))?;
                Zeroizing::new(key)
            }
            None => fresh_naming_key(),
        };
        Ok(Self {
            key: unwrap_one(&vault.wrapped_key)?,
            previous: vault.previous_key.as_deref().map(unwrap_one).transpose()?,
            naming_key,
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
            // Unchanged by a rotation, which is the point of keeping it
            // apart from the data key: the files keep their names.
            naming_key: self.naming_key.clone(),
        }
    }

    /// The same key with the rotation finished: nothing is left under the
    /// old one, so it is dropped.
    pub fn settled(&self) -> Self {
        Self {
            key: self.key.clone(),
            previous: None,
            naming_key: self.naming_key.clone(),
        }
    }

    /// The same data key wrapped under `passphrase` instead: files need no
    /// rewriting when the protection changes.
    ///
    /// `state_generation` is the directory's, carried over from the vault
    /// being replaced. It is a parameter rather than something this
    /// forgets so that changing the protection cannot quietly detach a
    /// directory from its own anchor.
    pub fn wrap_under_passphrase(
        &self,
        passphrase: &str,
        kdf: Kdf,
        state_generation: Option<u64>,
    ) -> anyhow::Result<VaultFile> {
        let kek = derive(&kdf, passphrase)?;
        Ok(self.wrapped(kdf, &kek, state_generation))
    }

    /// The same data key wrapped under a key-store `kek`.
    pub fn wrap_under_kek(
        &self,
        kek: &[u8; 32],
        kdf: Kdf,
        state_generation: Option<u64>,
    ) -> VaultFile {
        self.wrapped(kdf, kek, state_generation)
    }

    /// Both keys wrapped under `kek`, so a rotation left half-done is
    /// still readable: whichever key a file is under is in the vault.
    fn wrapped(&self, kdf: Kdf, kek: &[u8; 32], state_generation: Option<u64>) -> VaultFile {
        VaultFile {
            version: 1,
            kdf,
            wrapped_key: seal(kek, VAULT_AAD, self.key.as_slice()),
            previous_key: self
                .previous
                .as_ref()
                .map(|old| seal(kek, VAULT_AAD, old.as_slice())),
            state_generation,
            wrapped_naming_key: Some(seal(kek, NAMING_AAD, self.naming_key.as_slice())),
        }
    }

    /// What the history of `id` is filed under.
    ///
    /// `history/<user id>.jsonl` named the contact in the file name, so a
    /// directory listing was the contact and group list and the
    /// modification times were the activity times, with every file
    /// encrypted (SM-C-25). A MAC of the id under the naming key says
    /// nothing to somebody without it, and is the same name every time
    /// for the client that has it.
    ///
    /// What is *not* hidden, and is documented rather than padded: how
    /// many conversations there are, how big each is, and when each was
    /// last written. Padding history to hide lengths from somebody who
    /// already has the directory is a lot of disk for an attacker who, in
    /// the cases that matter, also has the key.
    pub fn history_name(&self, id: &str) -> String {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(self.naming_key.as_slice())
            .expect("HMAC takes a key of any length");
        mac.update(HISTORY_NAME_DOMAIN);
        mac.update(id.as_bytes());
        mac.finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    pub fn is_encrypted(bytes: &[u8]) -> bool {
        bytes.starts_with(FILE_MAGIC) || bytes.starts_with(GENERATION_MAGIC)
    }

    /// Encrypt a whole file bound to its name alone.
    ///
    /// The shape written before generations existed, and the one a
    /// directory with no rollback binding still uses.
    pub fn encrypt(&self, name: &str, plaintext: &[u8]) -> Vec<u8> {
        let mut out = FILE_MAGIC.to_vec();
        out.extend(seal(&self.key, name.as_bytes(), plaintext));
        out
    }

    /// Encrypt a whole file at generation `at`.
    ///
    /// The generation goes in the header in the clear *and* into the
    /// associated data. In the clear so that a reader knows which
    /// generation to check the tag against without being told — otherwise
    /// losing the record of what was written would leave every file
    /// undecryptable, and a directory that opens for nobody is a worse
    /// answer than one whose past cannot be proved. In the associated
    /// data so the header cannot lie: change the number and the tag
    /// fails.
    ///
    /// It is not a secret. It counts writes, which the modification times
    /// and the anchor in `vault.json` already say.
    pub fn encrypt_at(&self, name: &str, at: u64, plaintext: &[u8]) -> Vec<u8> {
        let mut out = GENERATION_MAGIC.to_vec();
        out.extend_from_slice(&at.to_be_bytes());
        out.extend(seal(&self.key, &file_aad(name, Some(at)), plaintext));
        out
    }

    /// Decrypt a whole file of either shape, saying which generation it
    /// claims. The claim is checked by the tag, so it is the file's own
    /// and not something an editor could put there.
    pub fn open_file(&self, name: &str, bytes: &[u8]) -> anyhow::Result<OpenedFile> {
        if let Some(rest) = bytes.strip_prefix(GENERATION_MAGIC) {
            let (at, body) = rest
                .split_at_checked(8)
                .context("file is too short to carry a generation")?;
            let at = u64::from_be_bytes(at.try_into().expect("split at eight"));
            let aad = file_aad(name, Some(at));
            let plain = open(&self.key, &aad, body)
                .or_else(|| self.previous(&aad, body))
                .with_context(|| format!("could not decrypt {name}: wrong key or damaged file"))?;
            return Ok(OpenedFile {
                generation: Some(at),
                plain,
            });
        }
        Ok(OpenedFile {
            generation: None,
            plain: self.decrypt(name, bytes)?,
        })
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
        self.encrypt_line_at(name, None, line)
    }

    /// Encrypt the line at index `at` of a line-oriented file.
    ///
    /// The index is bound in, so a line cannot be moved, dropped or
    /// repeated without the line it lands on failing to decrypt. `None`
    /// is the shape written before this existed.
    pub fn encrypt_line_at(&self, name: &str, at: Option<u64>, line: &str) -> String {
        format!(
            "{LINE_PREFIX}{}",
            to_base64(&seal(&self.key, &file_aad(name, at), line.as_bytes()))
        )
    }

    pub fn decrypt_line(&self, name: &str, line: &str) -> anyhow::Result<String> {
        self.decrypt_line_at(name, None, line)
    }

    /// Decrypt the line that must be at index `at`.
    pub fn decrypt_line_at(
        &self,
        name: &str,
        at: Option<u64>,
        line: &str,
    ) -> anyhow::Result<String> {
        let body = line
            .strip_prefix(LINE_PREFIX)
            .context("line is not encrypted")?;
        let bytes = from_base64(body.trim()).context("encrypted line is not base64")?;
        let aad = file_aad(name, at);
        let plain = open(&self.key, &aad, &bytes)
            .or_else(|| self.previous(&aad, &bytes))
            .with_context(|| match at {
                Some(at) => format!("could not decrypt line {at} of {name}"),
                None => format!("could not decrypt a line of {name}"),
            })?;
        String::from_utf8(plain.to_vec()).context("decrypted line is not UTF-8")
    }
}

/// What a file's contents are bound to: its name, and where it stands.
///
/// The name alone stops one file being read as another. The generation --
/// a write counter for a whole file, a line index for a line -- stops an
/// older copy of the *same* file being read as the current one, which the
/// name cannot do because an older copy has the right name.
///
/// The separator is a byte that cannot appear in a name, so
/// `("a", Some(1))` and `("a\u{1}1", None)` are different associated
/// data rather than the same bytes twice.
fn file_aad(name: &str, at: Option<u64>) -> Vec<u8> {
    match at {
        None => name.as_bytes().to_vec(),
        Some(at) => {
            let mut aad = Vec::with_capacity(name.len() + 9);
            aad.extend_from_slice(name.as_bytes());
            aad.push(0);
            aad.extend_from_slice(&at.to_be_bytes());
            aad
        }
    }
}

/// A random key for MACing history file names.
fn fresh_naming_key() -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(key.as_mut_slice());
    key
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
            .wrap_under_passphrase("hunter2", vault.kdf, None)
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
                .wrap_under_passphrase("hunter2", vault.kdf, None)
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
            .wrap_under_passphrase("hunter2", Kdf::fast(), None)
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
        let back = by_passphrase.wrap_under_kek(&kek, Kdf::keystore(), None);
        let by_kek = FileCipher::unlock_with_kek(&back, &kek).unwrap();
        assert_eq!(
            by_kek.decrypt("contacts.json", &blob).unwrap().as_slice(),
            b"[1]"
        );
    }
}
