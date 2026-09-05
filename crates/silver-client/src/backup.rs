//! Identity backup and restore.
//!
//! A backup is one self-contained file holding the identity keys, the
//! contact list and nothing else, encrypted under a passphrase of its own
//! (Argon2id and XChaCha20-Poly1305, like the vault). Restoring it onto a
//! fresh installation gives back the same user id and contacts; message
//! numbering starts a new epoch, so contacts see a reinstall rather than
//! replays.

use std::fs;
use std::path::Path;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use silver_protocol::encoding::b64;
use silver_protocol::{Identity, IdentitySecrets, Revocation, now_ms};
use zeroize::Zeroizing;

use crate::store::{Contact, Store};
use crate::vault::{Kdf, VaultError, decrypt_with_passphrase, encrypt_with_passphrase};

const FORMAT: &str = "silver-messenger-backup";
const BACKUP_AAD: &[u8] = b"silver-messenger/v1/backup";

/// What a backup file looks like on disk.
#[derive(Serialize, Deserialize)]
struct BackupFile {
    format: String,
    version: u32,
    kdf: Kdf,
    #[serde(with = "b64")]
    ciphertext: Vec<u8>,
}

/// The decrypted contents of a backup.
#[derive(Serialize, Deserialize)]
pub struct BackupPayload {
    pub created_at_ms: u64,
    pub identity: IdentitySecrets,
    pub contacts: Vec<Contact>,
    /// The pre-signed revocation certificate, kept alongside the key so the
    /// identity can be declared dead after a loss. Optional for backups
    /// written before lifecycle statements existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation: Option<Revocation>,
}

/// Write the store's identity and contacts to `path`, encrypted under
/// `passphrase`.
pub fn export_backup(store: &Store, path: &Path, passphrase: &str) -> anyhow::Result<()> {
    export_backup_with(store, path, passphrase, Kdf::default_params())
}

#[doc(hidden)]
pub fn export_backup_with(
    store: &Store,
    path: &Path,
    passphrase: &str,
    kdf: Kdf,
) -> anyhow::Result<()> {
    if !store.has_identity() {
        bail!("there is no identity to back up yet");
    }
    let (identity, _) = store.load_or_create_identity()?;
    let now = now_ms();
    let payload = BackupPayload {
        created_at_ms: now,
        identity: identity.to_secrets(),
        contacts: store.load_contacts()?,
        revocation: Some(store.load_or_create_revocation(&identity, now)?),
    };
    let plaintext = Zeroizing::new(serde_json::to_vec(&payload)?);
    let ciphertext = encrypt_with_passphrase(passphrase, &kdf, BACKUP_AAD, &plaintext)?;
    let file = BackupFile {
        format: FORMAT.into(),
        version: 1,
        kdf,
        ciphertext,
    };
    fs::write(path, serde_json::to_string_pretty(&file)?)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Decrypt a backup file.
pub fn read_backup(path: &Path, passphrase: &str) -> Result<BackupPayload, VaultError> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))
        .map_err(VaultError::Other)?;
    let file: BackupFile = serde_json::from_str(&text)
        .context("this is not a Silver Messenger backup file")
        .map_err(VaultError::Other)?;
    if file.format != FORMAT || file.version != 1 {
        return Err(anyhow::anyhow!("unsupported backup format").into());
    }
    let plaintext = decrypt_with_passphrase(passphrase, &file.kdf, BACKUP_AAD, &file.ciphertext)?;
    serde_json::from_slice(&plaintext)
        .context("backup contents are damaged")
        .map_err(VaultError::Other)
}

/// Install a backup's identity and contacts into `store`. Refuses to replace
/// an existing identity unless `force` is set. Message numbering starts
/// over with a fresh epoch.
pub fn import_backup(store: &Store, payload: BackupPayload, force: bool) -> anyhow::Result<()> {
    if store.has_identity() && !force {
        bail!("this data directory already has an identity; pass --force to replace it");
    }
    let identity = Identity::from_secrets(&payload.identity);
    store.save_identity(&identity)?;
    // Restore the pre-signed revocation so a key lost after this restore can
    // still be declared dead. A backup that predates lifecycle statements
    // carries none; mint a fresh one from the restored key instead.
    match payload.revocation {
        Some(revocation) if revocation.identity == identity.user_id() => {
            store.save_revocation(&revocation)?;
        }
        _ => {
            store.load_or_create_revocation(&identity, payload.created_at_ms)?;
        }
    }
    // Sessions and prekeys belong to the installation, not the identity:
    // peers will be told to start over.
    store.clear_sessions()?;
    let contacts: Vec<Contact> = payload
        .contacts
        .into_iter()
        .map(|mut c| {
            c.sent_seq = 0;
            c
        })
        .collect();
    store.save_contacts(&contacts)?;
    let mut config = store.load_config()?;
    config.send_epoch = None;
    store.save_config(&config)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use silver_protocol::Identity;

    #[test]
    fn backup_round_trips_into_a_fresh_store() {
        let source_dir = tempfile::tempdir().unwrap();
        let source = Store::open(source_dir.path()).unwrap();
        let (identity, _) = source.load_or_create_identity().unwrap();
        let peer = Identity::generate();
        let mut contact = Contact::new(peer.user_id());
        contact.alias = Some("peer".into());
        contact.sent_seq = 9;
        source.save_contacts(&[contact]).unwrap();

        let file = source_dir.path().join("backup.json");
        export_backup_with(&source, &file, "backup pass", Kdf::fast()).unwrap();
        let raw = fs::read_to_string(&file).unwrap();
        assert!(raw.contains(FORMAT));
        assert!(!raw.contains("signing_seed") && !raw.contains("peer"));

        assert!(matches!(
            read_backup(&file, "wrong"),
            Err(VaultError::WrongPassphrase)
        ));
        let payload = read_backup(&file, "backup pass").unwrap();
        assert_eq!(payload.contacts.len(), 1);
        // The pre-signed revocation travels with the identity.
        let backed_up = payload.revocation.clone().expect("revocation in backup");
        assert_eq!(backed_up.identity, identity.user_id());
        assert!(backed_up.verify().is_ok());

        let target_dir = tempfile::tempdir().unwrap();
        let target = Store::open(target_dir.path()).unwrap();
        import_backup(&target, payload, false).unwrap();
        let (restored, created) = target.load_or_create_identity().unwrap();
        assert!(!created);
        assert_eq!(restored.user_id(), identity.user_id());
        // The restored store carries the same certificate, so a key lost
        // after this restore can still be revoked.
        let restored_rev = target.revocation().unwrap().expect("restored revocation");
        assert_eq!(restored_rev, backed_up);
        let contacts = target.load_contacts().unwrap();
        assert_eq!(contacts[0].alias.as_deref(), Some("peer"));
        assert_eq!(contacts[0].sent_seq, 0);

        // A second import needs --force.
        let payload = read_backup(&file, "backup pass").unwrap();
        assert!(import_backup(&target, payload, false).is_err());
        let payload = read_backup(&file, "backup pass").unwrap();
        import_backup(&target, payload, true).unwrap();
    }
}
