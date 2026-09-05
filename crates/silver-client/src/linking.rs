//! Linking a device to an identity (`docs/PROTOCOL.md` section 14,
//! `docs/design/devices.md` section 7).
//!
//! The new device prints a [`DeviceLink`], `silver://link/<device
//! id>?secret=…&relay=…`, with a one-time secret, and waits. The primary,
//! handed the link, certifies the device and sends it a provisioning
//! message ([`Provisioning`]): the certificate, the account, the device
//! list and revocations, and the reference of a [`Snapshot`], a file on
//! the relay's blob store with the contacts, the blocked ids, the groups
//! and the recent history. The message is sealed under a key derived from
//! the link's secret, so only the device that printed the link reads it,
//! whoever else was handed the device id. The device takes it
//! ([`take_link`]), publishes its bundle as the account's device, and
//! fetches the snapshot ([`fetch_snapshot`]).

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use silver_protocol::blob::MAX_FILE_BYTES;
use silver_protocol::device::{
    LINK_SECRET_BYTES, MAX_DEVICES, Provision, link_key, open_provision, seal_provision,
};
use silver_protocol::envelope::ReceiptKind;
use silver_protocol::group::GroupId;
use silver_protocol::{DeviceCertificate, DeviceRevocation, KeyBundle, UserId};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::connection::{Client, ClientError, ClientEvent};
use crate::devices::Linked;
use crate::files::FileInfo;
use crate::invite::{percent_decode, percent_encode};
use crate::store::{Contact, HistoryEntry, Store};

pub const SCHEME: &str = "silver://link/";
/// How long a link is good for.
pub const LINK_LIFETIME: Duration = Duration::from_secs(10 * 60);
/// Days of history a snapshot carries unless told otherwise.
pub const DEFAULT_HISTORY_DAYS: u32 = 30;
const SNAPSHOT_FORMAT: &str = "silver-messenger-snapshot";
const SNAPSHOT_VERSION: u32 = 1;
const DAY_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LinkError {
    #[error("not a device link (expected silver://link/<device id>?secret=…&relay=…)")]
    NotALink,
    #[error("the link does not name a valid device id")]
    BadDevice,
    #[error("the link carries no usable secret")]
    BadSecret,
    #[error("the link names no relay")]
    NoRelay,
    /// The message was sealed under another secret, or for another device:
    /// not this link's.
    #[error("the provisioning message is not for this link")]
    NotForThisLink,
    #[error("the provisioning message does not hold up: {0}")]
    Malformed(String),
    #[error("the link expired before the primary answered")]
    Expired,
    #[error("this client keeps no device state")]
    NoDeviceState,
    #[error("{0}")]
    Client(String),
    #[error("the client task has stopped")]
    Stopped,
}

impl From<ClientError> for LinkError {
    fn from(e: ClientError) -> Self {
        match e {
            ClientError::Stopped => Self::Stopped,
            other => Self::Client(other.to_string()),
        }
    }
}

/// What the new device prints: its id, a one-time secret, the relay it
/// registered with, and what it would like to be called.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceLink {
    pub device: UserId,
    pub secret: [u8; LINK_SECRET_BYTES],
    pub relay: String,
    pub name: Option<String>,
}

impl fmt::Debug for DeviceLink {
    /// Without the secret: a debug log is not the place for it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceLink")
            .field("device", &self.device)
            .field("relay", &self.relay)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl DeviceLink {
    /// A link for `device`, with a fresh secret.
    pub fn new(device: UserId, relay: String, name: Option<String>) -> Self {
        let mut secret = [0u8; LINK_SECRET_BYTES];
        OsRng.fill_bytes(&mut secret);
        Self {
            device,
            secret,
            relay,
            name: name.filter(|n| !n.trim().is_empty()),
        }
    }

    /// Whether `text` is a device link rather than a contact or group
    /// link.
    pub fn looks_like(text: &str) -> bool {
        text.trim()
            .get(..SCHEME.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(SCHEME))
    }

    /// The key the provisioning message is sealed under.
    pub fn key(&self) -> [u8; 32] {
        link_key(&self.secret)
    }
}

impl fmt::Display for DeviceLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{SCHEME}{}?secret={}&relay={}",
            self.device,
            bs58::encode(self.secret).into_string(),
            percent_encode(&self.relay)
        )?;
        if let Some(name) = &self.name {
            write!(f, "&name={}", percent_encode(name))?;
        }
        Ok(())
    }
}

impl FromStr for DeviceLink {
    type Err = LinkError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let text = text.trim();
        let rest = text
            .get(..SCHEME.len())
            .filter(|head| head.eq_ignore_ascii_case(SCHEME))
            .map(|_| &text[SCHEME.len()..])
            .ok_or(LinkError::NotALink)?;
        let (id_part, query) = match rest.split_once('?') {
            Some((id, query)) => (id, Some(query)),
            None => (rest, None),
        };
        let device: UserId = id_part
            .trim_end_matches('/')
            .parse()
            .map_err(|_| LinkError::BadDevice)?;
        let mut secret = None;
        let mut relay = None;
        let mut name = None;
        for (key, value) in query
            .into_iter()
            .flat_map(|q| q.split('&'))
            .filter_map(|pair| pair.split_once('='))
        {
            match key {
                "secret" => {
                    let bytes = bs58::decode(value)
                        .into_vec()
                        .map_err(|_| LinkError::BadSecret)?;
                    secret = Some(
                        <[u8; LINK_SECRET_BYTES]>::try_from(bytes)
                            .map_err(|_| LinkError::BadSecret)?,
                    );
                }
                "relay" => {
                    let decoded = percent_decode(value);
                    if !decoded.is_empty() {
                        relay = Some(decoded);
                    }
                }
                "name" => {
                    let decoded = percent_decode(value);
                    if !decoded.trim().is_empty() {
                        name = Some(decoded);
                    }
                }
                _ => {}
            }
        }
        Ok(Self {
            device,
            secret: secret.ok_or(LinkError::BadSecret)?,
            relay: relay.ok_or(LinkError::NoRelay)?,
            name,
        })
    }
}

/// The provisioning message's plaintext: what the primary tells the new
/// device. The contacts and the history come separately, in the
/// [`Snapshot`] the reference names, since a body holds 32 KiB and a
/// pinned bundle is kilobytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provisioning {
    pub account: UserId,
    /// The account's certificate for the device the link named.
    pub certificate: DeviceCertificate,
    /// The account's device list as it is published from now on, the new
    /// device on it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<DeviceCertificate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked: Vec<DeviceRevocation>,
    /// The snapshot on the blob store, when there is anything to send.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<FileInfo>,
}

impl Provisioning {
    /// Seal for the device `link` names, under the link's key.
    pub fn seal(&self, link: &DeviceLink) -> Result<Provision, LinkError> {
        let plaintext =
            serde_json::to_vec(self).map_err(|e| LinkError::Malformed(e.to_string()))?;
        seal_provision(&link.key(), &link.device, &plaintext)
            .map_err(|e| LinkError::Malformed(e.to_string()))
    }

    /// Open what `from` sent to the device that printed `link`. Refused
    /// unless it was sealed under the link's secret for the link's device
    /// (anyone who saw the device id can send something; only the primary
    /// that was handed the link seals with its secret), and unless it
    /// names `from` as the account, certifies the link's device for that
    /// account, and lists that account's devices and revocations alone.
    pub fn open(
        link: &DeviceLink,
        from: &UserId,
        provision: &Provision,
    ) -> Result<Self, LinkError> {
        let plaintext = open_provision(&link.key(), &link.device, provision)
            .map_err(|_| LinkError::NotForThisLink)?;
        let this: Self =
            serde_json::from_slice(&plaintext).map_err(|e| LinkError::Malformed(e.to_string()))?;
        this.check(link, from)?;
        Ok(this)
    }

    fn check(&self, link: &DeviceLink, from: &UserId) -> Result<(), LinkError> {
        let malformed = |what: &str| Err(LinkError::Malformed(what.to_owned()));
        if self.account != *from {
            return malformed("it names an account other than its sender");
        }
        if self.certificate.verify().is_err() {
            return malformed("the certificate does not verify");
        }
        if self.certificate.account != self.account {
            return malformed("the certificate is another account's");
        }
        if self.certificate.device != link.device {
            return malformed("the certificate is for another device");
        }
        if self.devices.len() > MAX_DEVICES {
            return malformed("it lists more devices than an account has");
        }
        for device in &self.devices {
            if device.verify().is_err() || device.account != self.account {
                return malformed("a listed device is not the account's");
            }
        }
        for revocation in &self.revoked {
            if revocation.verify().is_err() || revocation.account != self.account {
                return malformed("a revocation is not the account's");
            }
        }
        if let Some(snapshot) = &self.snapshot
            && let Err(e) = snapshot.check()
        {
            return Err(LinkError::Malformed(format!("the snapshot reference: {e}")));
        }
        Ok(())
    }
}

/// A contact as the snapshot carries it: what the owner decided about
/// them, not what this device's stream with them stands at.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotContact {
    pub user: UserId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<KeyBundle>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub verified: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub auto_files: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub revoked: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caps: Vec<String>,
}

impl From<&Contact> for SnapshotContact {
    fn from(contact: &Contact) -> Self {
        Self {
            user: contact.user_id,
            alias: contact.alias.clone(),
            bundle: contact.bundle.clone(),
            verified: contact.verified,
            auto_files: contact.auto_files,
            revoked: contact.revoked,
            caps: contact.caps.clone(),
        }
    }
}

impl SnapshotContact {
    /// The contact as this device starts with it: sequence numbers from
    /// nothing, since every device numbers its own stream.
    pub fn into_contact(self) -> Contact {
        let mut contact = Contact::new(self.user);
        contact.alias = self.alias;
        contact.bundle = self.bundle;
        contact.verified = self.verified;
        contact.auto_files = self.auto_files;
        contact.revoked = self.revoked;
        contact.caps = self.caps;
        contact
    }
}

/// A group the account is in, as the snapshot names it: the new device
/// joins it once the primary adds its leaf (section 6.3), and knows the
/// alias from the start.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotGroup {
    pub id: GroupId,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
}

/// One line of history with the furthest receipt it got, which a
/// [`HistoryEntry`] on disk carries in a later line.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotEntry {
    #[serde(flatten)]
    pub entry: HistoryEntry,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<ReceiptKind>,
}

impl From<HistoryEntry> for SnapshotEntry {
    fn from(entry: HistoryEntry) -> Self {
        let receipt = entry.receipt;
        Self { entry, receipt }
    }
}

/// What came along with a link: how many contacts and lines of history.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Imported {
    pub contacts: usize,
    pub messages: usize,
}

/// Everything a new device is given besides its certificate: one JSON
/// document, sent as a padded file (section 7.4).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    format: String,
    version: u32,
    pub created_at_ms: u64,
    #[serde(default)]
    pub contacts: Vec<SnapshotContact>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked: Vec<UserId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<SnapshotGroup>,
    /// Per contact, oldest first.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub history: BTreeMap<UserId, Vec<SnapshotEntry>>,
    /// Per group, oldest first.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub group_history: BTreeMap<GroupId, Vec<SnapshotEntry>>,
}

impl Snapshot {
    /// Gather from `store`: every contact and blocked id, `groups` as
    /// given, and the last `days` days of history with each contact and
    /// each of the groups (`days` 0: no history).
    pub fn gather(
        store: &Store,
        groups: &[SnapshotGroup],
        days: u32,
        now_ms: u64,
    ) -> anyhow::Result<Self> {
        let since = now_ms.saturating_sub(u64::from(days) * DAY_MS);
        let recent = |entries: Vec<HistoryEntry>| -> Vec<SnapshotEntry> {
            if days == 0 {
                return Vec::new();
            }
            entries
                .into_iter()
                .filter(|e| e.timestamp_ms >= since)
                .map(SnapshotEntry::from)
                .collect()
        };
        let contacts = store.load_contacts()?;
        let mut history = BTreeMap::new();
        for contact in &contacts {
            let entries = recent(store.load_history(&contact.user_id)?);
            if !entries.is_empty() {
                history.insert(contact.user_id, entries);
            }
        }
        let mut group_history = BTreeMap::new();
        for group in groups {
            let entries = recent(store.load_group_history(&group.id)?);
            if !entries.is_empty() {
                group_history.insert(group.id, entries);
            }
        }
        Ok(Self {
            format: SNAPSHOT_FORMAT.to_owned(),
            version: SNAPSHOT_VERSION,
            created_at_ms: now_ms,
            contacts: contacts.iter().map(SnapshotContact::from).collect(),
            blocked: store.load_blocked()?,
            groups: groups.to_vec(),
            history,
            group_history,
        })
    }

    /// Whether there is anything to send at all.
    pub fn is_empty(&self) -> bool {
        self.contacts.is_empty()
            && self.blocked.is_empty()
            && self.groups.is_empty()
            && self.history.is_empty()
            && self.group_history.is_empty()
    }

    /// Lines of history, over every conversation.
    pub fn message_count(&self) -> usize {
        self.history.values().map(Vec::len).sum::<usize>()
            + self.group_history.values().map(Vec::len).sum::<usize>()
    }

    /// The document as bytes, cut to what a file may be: the oldest
    /// lines go first, whatever conversation they are in.
    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        self.to_bytes_within(MAX_FILE_BYTES as usize)
    }

    /// [`Snapshot::to_bytes`] under a cap of `cap` bytes.
    pub fn to_bytes_within(&self, cap: usize) -> anyhow::Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() <= cap {
            return Ok(bytes);
        }
        let mut cut = self.clone();
        // Every line, newest first, with what it costs; the base is the
        // document without any of them, which must fit on its own.
        let mut lines: Vec<(u64, usize)> = Vec::new();
        for entry in cut
            .history
            .values()
            .chain(cut.group_history.values())
            .flatten()
        {
            lines.push((
                entry.entry.timestamp_ms,
                serde_json::to_vec(entry)?.len() + 1,
            ));
        }
        lines.sort_by_key(|(at, _)| std::cmp::Reverse(*at));
        let base = {
            let mut empty = cut.clone();
            empty.history.clear();
            empty.group_history.clear();
            serde_json::to_vec(&empty)?.len()
        };
        if base > cap {
            anyhow::bail!(
                "the contacts alone are {} bytes, more than a snapshot may be",
                base
            );
        }
        // Keys and brackets of the conversations that stay: a bound.
        let overhead = 80 * (cut.history.len() + cut.group_history.len());
        let mut total = base + overhead;
        let mut oldest_kept = u64::MAX;
        for (at, size) in &lines {
            if total + size > cap {
                break;
            }
            total += size;
            oldest_kept = *at;
        }
        loop {
            let keep = |entries: &mut Vec<SnapshotEntry>| {
                entries.retain(|e| e.entry.timestamp_ms >= oldest_kept);
            };
            cut.history.values_mut().for_each(keep);
            cut.group_history.values_mut().for_each(keep);
            cut.history.retain(|_, entries| !entries.is_empty());
            cut.group_history.retain(|_, entries| !entries.is_empty());
            let bytes = serde_json::to_vec(&cut)?;
            if bytes.len() <= cap {
                return Ok(bytes);
            }
            // The bound was optimistic; drop the oldest of what is kept
            // and measure again.
            let next = cut
                .history
                .values()
                .chain(cut.group_history.values())
                .flatten()
                .map(|e| e.entry.timestamp_ms)
                .filter(|at| *at > oldest_kept)
                .min();
            match next {
                Some(at) => oldest_kept = at,
                None => {
                    cut.history.clear();
                    cut.group_history.clear();
                    return Ok(serde_json::to_vec(&cut)?);
                }
            }
        }
    }

    /// Parse what [`Snapshot::to_bytes`] wrote.
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let this: Self = serde_json::from_slice(bytes)?;
        if this.format != SNAPSHOT_FORMAT || this.version != SNAPSHOT_VERSION {
            anyhow::bail!("not a snapshot this version reads");
        }
        Ok(this)
    }

    /// Take the contacts, the blocked ids and the history into `store`,
    /// on a device that starts from nothing: a contact already there is
    /// replaced, a line already in a history is left alone. The groups
    /// are for the caller, who hands them to the groups engine.
    pub fn import(&self, store: &Store) -> anyhow::Result<Imported> {
        let mut contacts = store.load_contacts()?;
        for contact in &self.contacts {
            contacts.retain(|c| c.user_id != contact.user);
            contacts.push(contact.clone().into_contact());
        }
        store.save_contacts(&contacts)?;
        let mut blocked = store.load_blocked()?;
        for id in &self.blocked {
            if !blocked.contains(id) {
                blocked.push(*id);
            }
        }
        store.save_blocked(&blocked)?;
        let mut messages = 0;
        for (peer, entries) in &self.history {
            let known: HashSet<String> = store
                .load_history(peer)?
                .into_iter()
                .map(|e| e.id)
                .collect();
            for line in entries {
                if known.contains(&line.entry.id) {
                    continue;
                }
                store.append_history(peer, &line.entry)?;
                if let Some(receipt) = line.receipt {
                    store.append_receipt(
                        peer,
                        receipt,
                        std::slice::from_ref(&line.entry.id),
                        line.entry.timestamp_ms,
                    )?;
                }
                messages += 1;
            }
        }
        for (group, entries) in &self.group_history {
            let known: HashSet<String> = store
                .load_group_history(group)?
                .into_iter()
                .map(|e| e.id)
                .collect();
            for line in entries {
                if known.contains(&line.entry.id) {
                    continue;
                }
                store.append_group_history(group, &line.entry)?;
                messages += 1;
            }
        }
        Ok(Imported {
            contacts: self.contacts.len(),
            messages,
        })
    }
}

/// What taking a link came to: whose device this is now, and the
/// snapshot to fetch, if the primary sent one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Taken {
    pub account: UserId,
    pub certificate: DeviceCertificate,
    pub snapshot: Option<FileInfo>,
}

/// On the device that printed `link`: wait for the primary's provisioning
/// message until `deadline`, ignoring everything else that arrives
/// (including messages sealed under another secret, from whoever saw the
/// device id), take it, and publish this device's bundle as the account's.
/// The device is linked once this returns; the snapshot is fetched
/// separately ([`fetch_snapshot`]), so a snapshot that cannot be had
/// leaves the link standing.
pub async fn take_link(
    client: &Client,
    events: &mut mpsc::Receiver<ClientEvent>,
    link: &DeviceLink,
    deadline: tokio::time::Instant,
) -> Result<Taken, LinkError> {
    let devices = client.devices().ok_or(LinkError::NoDeviceState)?.clone();
    let provisioning = loop {
        let event = tokio::time::timeout_at(deadline, events.recv())
            .await
            .map_err(|_| LinkError::Expired)?
            .ok_or(LinkError::Stopped)?;
        match event {
            ClientEvent::Provision { from, provision } => {
                match Provisioning::open(link, &from, &provision) {
                    Ok(provisioning) => break provisioning,
                    Err(e) => debug!("a provisioning message from {}… ignored: {e}", from.short()),
                }
            }
            ClientEvent::Disconnected { reason, retry_in } => {
                warn!(
                    "relay connection lost while waiting for the link ({reason}); retrying in {retry_in:?}"
                );
            }
            _ => {}
        }
    };
    let linked = Linked {
        account: provisioning.account,
        certificate: provisioning.certificate.clone(),
    };
    devices
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .adopt(
            linked,
            provisioning.devices.clone(),
            provisioning.revoked.clone(),
        )
        .map_err(|e| LinkError::Client(e.to_string()))?;
    client.republish().await?;
    Ok(Taken {
        account: provisioning.account,
        certificate: provisioning.certificate,
        snapshot: provisioning.snapshot,
    })
}

/// Fetch the snapshot `info` names from the relay and parse it.
pub async fn fetch_snapshot(client: &Client, info: &FileInfo) -> Result<Snapshot, LinkError> {
    let bytes = client.download_bytes(info).await?;
    Snapshot::from_bytes(&bytes).map_err(|e| LinkError::Client(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Direction;
    use silver_protocol::Identity;

    fn link_for(device: &Identity) -> DeviceLink {
        DeviceLink::new(
            device.user_id(),
            "wss://relay.example.org/ws".into(),
            Some("laptop".into()),
        )
    }

    #[test]
    fn links_round_trip_and_show_everything_but_the_secret() {
        let laptop = Identity::generate();
        let link = link_for(&laptop);
        let text = link.to_string();
        assert!(text.starts_with("silver://link/"));
        assert!(DeviceLink::looks_like(&text));
        assert!(!crate::invite::InviteLink::looks_like(&text) || text.contains("link"));
        assert_eq!(text.parse::<DeviceLink>().unwrap(), link);
        assert!(text.contains("&name=laptop"));
        let nameless = DeviceLink {
            name: None,
            ..link.clone()
        };
        assert_eq!(
            nameless.to_string().parse::<DeviceLink>().unwrap(),
            nameless
        );
        // Two links for one device differ in their secret, and the secret
        // stays out of the debug form.
        let other = link_for(&laptop);
        assert_ne!(other.secret, link.secret);
        assert_ne!(other.key(), link.key());
        let shown = format!("{link:?}");
        assert!(
            shown.contains("laptop") && !shown.contains(&bs58::encode(link.secret).into_string())
        );

        assert_eq!(
            "silver://add/x".parse::<DeviceLink>(),
            Err(LinkError::NotALink)
        );
        assert_eq!(
            "silver://link/not-an-id?secret=1&relay=x".parse::<DeviceLink>(),
            Err(LinkError::BadDevice)
        );
        assert_eq!(
            format!("silver://link/{}?relay=wss://r/ws", laptop.user_id()).parse::<DeviceLink>(),
            Err(LinkError::BadSecret)
        );
        assert_eq!(
            format!(
                "silver://link/{}?secret=111&relay=wss://r/ws",
                laptop.user_id()
            )
            .parse::<DeviceLink>(),
            Err(LinkError::BadSecret),
            "a secret of the wrong length"
        );
        let secret = bs58::encode(link.secret).into_string();
        assert_eq!(
            format!("silver://link/{}?secret={secret}", laptop.user_id()).parse::<DeviceLink>(),
            Err(LinkError::NoRelay)
        );
    }

    #[test]
    fn a_provisioning_message_opens_for_its_link_alone() {
        let alice = Identity::generate();
        let laptop = Identity::generate();
        let phone = Identity::generate();
        let link = link_for(&laptop);
        let certificate = alice
            .certify_device(&laptop.user_id(), "laptop", 1)
            .unwrap();
        let provisioning = Provisioning {
            account: alice.user_id(),
            certificate: certificate.clone(),
            devices: vec![
                certificate.clone(),
                alice.certify_device(&phone.user_id(), "phone", 2).unwrap(),
            ],
            revoked: vec![alice.revoke_device(&Identity::generate().user_id(), 3)],
            snapshot: None,
        };
        let sealed = provisioning.seal(&link).unwrap();
        assert_eq!(
            Provisioning::open(&link, &alice.user_id(), &sealed).unwrap(),
            provisioning
        );
        // Another secret, or another device's link, does not open it.
        let other = link_for(&laptop);
        assert_eq!(
            Provisioning::open(&other, &alice.user_id(), &sealed),
            Err(LinkError::NotForThisLink)
        );
        let phones = DeviceLink {
            device: phone.user_id(),
            ..link.clone()
        };
        assert_eq!(
            Provisioning::open(&phones, &alice.user_id(), &sealed),
            Err(LinkError::NotForThisLink)
        );
        // Sent by someone other than the account it names.
        let mallory = Identity::generate();
        assert!(matches!(
            Provisioning::open(&link, &mallory.user_id(), &sealed),
            Err(LinkError::Malformed(_))
        ));
        // Mallory, who saw the device id and guessed nothing, seals a
        // message under her own secret: not this link's.
        let hers = mallory
            .certify_device(&laptop.user_id(), "stolen", 1)
            .unwrap();
        let forged = Provisioning {
            account: mallory.user_id(),
            certificate: hers.clone(),
            devices: vec![],
            revoked: vec![],
            snapshot: None,
        }
        .seal(&other)
        .unwrap();
        assert_eq!(
            Provisioning::open(&link, &mallory.user_id(), &forged),
            Err(LinkError::NotForThisLink)
        );
        // Under the right secret, a certificate for another device, or
        // another account's devices, is refused as malformed.
        let wrong_device = Provisioning {
            certificate: alice.certify_device(&phone.user_id(), "phone", 2).unwrap(),
            ..provisioning.clone()
        }
        .seal(&link)
        .unwrap();
        assert!(matches!(
            Provisioning::open(&link, &alice.user_id(), &wrong_device),
            Err(LinkError::Malformed(_))
        ));
        let foreign_list = Provisioning {
            devices: vec![mallory.certify_device(&phone.user_id(), "x", 2).unwrap()],
            ..provisioning.clone()
        }
        .seal(&link)
        .unwrap();
        assert!(matches!(
            Provisioning::open(&link, &alice.user_id(), &foreign_list),
            Err(LinkError::Malformed(_))
        ));
    }

    fn entry(id: &str, at: u64, direction: Direction, text: &str) -> HistoryEntry {
        HistoryEntry {
            id: id.into(),
            direction,
            timestamp_ms: at,
            text: text.into(),
            receipt: None,
            file: None,
            from: None,
        }
    }

    #[test]
    fn a_snapshot_carries_the_last_days_and_is_cut_to_fit() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let bob = Identity::generate().user_id();
        let carol = Identity::generate().user_id();
        let mallory = Identity::generate().user_id();
        let mut contact = Contact::new(bob);
        contact.alias = Some("bob".into());
        contact.verified = true;
        contact.sent_seq = 9;
        contact.auto_files = true;
        contact.caps = vec!["files".into()];
        let mut second = Contact::new(carol);
        second.revoked = true;
        store.save_contacts(&[contact, second]).unwrap();
        store.save_blocked(&[mallory]).unwrap();
        let now = 100 * DAY_MS;
        // Bob: an old line, and two recent ones, one read.
        store
            .append_history(
                &bob,
                &entry("old", now - 40 * DAY_MS, Direction::Received, "old"),
            )
            .unwrap();
        store
            .append_history(
                &bob,
                &entry("a", now - 2 * DAY_MS, Direction::Sent, "hello"),
            )
            .unwrap();
        store
            .append_receipt(&bob, ReceiptKind::Read, &["a".into()], now - DAY_MS)
            .unwrap();
        store
            .append_history(&bob, &entry("b", now - DAY_MS, Direction::Received, "hi"))
            .unwrap();
        let group = GroupId::generate();
        store
            .append_group_history(
                &group,
                &entry("g", now - 3 * DAY_MS, Direction::Sent, "team"),
            )
            .unwrap();
        let groups = vec![SnapshotGroup {
            id: group,
            name: "team".into(),
            alias: Some("work".into()),
        }];

        let snapshot = Snapshot::gather(&store, &groups, 30, now).unwrap();
        assert_eq!(snapshot.contacts.len(), 2);
        assert_eq!(snapshot.blocked, vec![mallory]);
        assert_eq!(snapshot.groups, groups);
        assert_eq!(snapshot.message_count(), 3, "the old line stays behind");
        let lines = &snapshot.history[&bob];
        assert_eq!(lines[0].entry.id, "a");
        assert_eq!(lines[0].receipt, Some(ReceiptKind::Read));
        assert_eq!(lines[1].receipt, None);
        assert!(!snapshot.is_empty());
        // No days: no history at all.
        let none = Snapshot::gather(&store, &groups, 0, now).unwrap();
        assert_eq!(none.message_count(), 0);
        assert!(none.history.is_empty() && none.group_history.is_empty());

        // The bytes round-trip, and a cap cuts the oldest lines first.
        let bytes = snapshot.to_bytes().unwrap();
        let back = Snapshot::from_bytes(&bytes).unwrap();
        assert_eq!(back.message_count(), 3);
        let base = {
            let mut empty = snapshot.clone();
            empty.history.clear();
            empty.group_history.clear();
            serde_json::to_vec(&empty).unwrap().len()
        };
        let cut = Snapshot::from_bytes(&snapshot.to_bytes_within(base + 250).unwrap()).unwrap();
        assert!(
            cut.message_count() < 3 && cut.message_count() >= 1,
            "{}",
            cut.message_count()
        );
        let newest_kept = cut
            .history
            .values()
            .chain(cut.group_history.values())
            .flatten()
            .map(|e| e.entry.timestamp_ms)
            .min()
            .unwrap();
        assert!(
            newest_kept >= now - 2 * DAY_MS,
            "the group line, the oldest, went first"
        );
        assert_eq!(cut.contacts.len(), 2, "contacts are never cut");
        assert!(
            Snapshot::from_bytes(&snapshot.to_bytes_within(base).unwrap())
                .unwrap()
                .message_count()
                == 0
        );
        assert!(
            snapshot.to_bytes_within(10).is_err(),
            "contacts that do not fit are an error"
        );
        assert!(
            Snapshot::from_bytes(b"{\"format\":\"other\",\"version\":1,\"created_at_ms\":0}")
                .is_err()
        );

        // Imported into a fresh store: the contacts start their streams
        // from nothing, the receipts are on the lines, and importing
        // again adds nothing.
        let target_dir = tempfile::tempdir().unwrap();
        let target = Store::open(target_dir.path()).unwrap();
        let imported = back.import(&target).unwrap();
        assert_eq!(
            imported,
            Imported {
                contacts: 2,
                messages: 3
            }
        );
        let contacts = target.load_contacts().unwrap();
        let bob_c = contacts.iter().find(|c| c.user_id == bob).unwrap();
        assert_eq!(bob_c.alias.as_deref(), Some("bob"));
        assert!(bob_c.verified && bob_c.auto_files && bob_c.supports("files"));
        assert_eq!(bob_c.sent_seq, 0);
        assert!(bob_c.received.is_none());
        assert!(
            contacts
                .iter()
                .find(|c| c.user_id == carol)
                .unwrap()
                .revoked
        );
        assert_eq!(target.load_blocked().unwrap(), vec![mallory]);
        let history = target.load_history(&bob).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].id, "a");
        assert_eq!(history[0].receipt, Some(ReceiptKind::Read));
        assert_eq!(history[0].text, "hello");
        assert_eq!(history[1].receipt, None);
        assert_eq!(target.load_group_history(&group).unwrap().len(), 1);
        let again = back.import(&target).unwrap();
        assert_eq!(again.messages, 0);
        assert_eq!(target.load_history(&bob).unwrap().len(), 2);
        assert_eq!(target.load_contacts().unwrap().len(), 2);
    }
}
