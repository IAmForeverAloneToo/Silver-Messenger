//! One account's devices, as one of them keeps them (`docs/PROTOCOL.md`
//! section 14, `docs/design/devices.md`).
//!
//! A device is a key pair of its own certified by the identity key, which
//! stays on the **primary**; a **linked device** holds its own keys and the
//! certificate. The primary keeps the list it publishes in its bundle and
//! the revocations it issued (`devices.json`); a linked device keeps its
//! certificate under `linked` in `identity.json` and the list as the
//! primary last synced it. Both use the same [`DeviceState`], which says
//! who the account's other devices are, so a message can go to every one
//! of them.

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use silver_protocol::device::MAX_DEVICES;
use silver_protocol::device::Sync;
use silver_protocol::{Content, DeviceCertificate, DeviceRevocation, UserId};

use crate::store::Store;

/// What a linked device holds about its account: the account's id and
/// the certificate the account signed for this device's key. Kept in
/// `identity.json` under `linked`; absent on a primary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Linked {
    pub account: UserId,
    pub certificate: DeviceCertificate,
}

/// `devices.json`: the account's linked devices and the revocations its
/// primary issued, as this device last knew them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicesFile {
    #[serde(default)]
    pub devices: Vec<DeviceCertificate>,
    #[serde(default)]
    pub revoked: Vec<DeviceRevocation>,
}

/// The device state shared between the connection task and the front end.
pub type SharedDevices = Arc<Mutex<DeviceState>>;

/// This device's view of its account's devices.
pub struct DeviceState {
    store: Option<Store>,
    me: UserId,
    linked: Option<Linked>,
    list: DevicesFile,
}

impl DeviceState {
    /// Load from the data directory: `linked` from `identity.json`, the
    /// list from `devices.json` (missing files mean a primary with no
    /// devices).
    pub fn load(store: &Store, me: UserId) -> anyhow::Result<Self> {
        let linked = store.load_linked()?;
        if let Some(linked) = &linked {
            check_linked(linked, &me)?;
        }
        Ok(Self {
            store: Some(store.clone()),
            me,
            linked,
            list: store.load_devices()?,
        })
    }

    /// State that lives in memory only: a primary with no devices, or a
    /// linked device with `linked`.
    pub fn ephemeral(me: UserId, linked: Option<Linked>) -> anyhow::Result<Self> {
        if let Some(linked) = &linked {
            check_linked(linked, &me)?;
        }
        Ok(Self {
            store: None,
            me,
            linked,
            list: DevicesFile::default(),
        })
    }

    pub fn shared(self) -> SharedDevices {
        Arc::new(Mutex::new(self))
    }

    /// This device's id.
    pub fn me(&self) -> UserId {
        self.me
    }

    /// The account: this device's own id on a primary, the primary's on a
    /// linked device.
    pub fn account(&self) -> UserId {
        self.linked.as_ref().map_or(self.me, |l| l.account)
    }

    pub fn is_linked(&self) -> bool {
        self.linked.is_some()
    }

    pub fn linked(&self) -> Option<&Linked> {
        self.linked.as_ref()
    }

    /// This device's certificate, on a linked device; a primary has none.
    pub fn certificate(&self) -> Option<&DeviceCertificate> {
        self.linked.as_ref().map(|l| &l.certificate)
    }

    /// The account's linked devices, in ascending device id order.
    pub fn devices(&self) -> &[DeviceCertificate] {
        &self.list.devices
    }

    /// The revocations the account issued.
    pub fn revoked(&self) -> &[DeviceRevocation] {
        &self.list.revoked
    }

    pub fn is_revoked(&self, device: &UserId) -> bool {
        self.list.revoked.iter().any(|r| r.device == *device)
    }

    /// The account's other devices, from this one's point of view: the
    /// listed devices on a primary; the primary and the other listed
    /// devices on a linked one.
    pub fn siblings(&self) -> Vec<UserId> {
        let mut out: Vec<UserId> = self
            .list
            .devices
            .iter()
            .map(|d| d.device)
            .filter(|d| *d != self.me)
            .collect();
        if let Some(linked) = &self.linked {
            out.insert(0, linked.account);
        }
        out
    }

    /// Whether `id` is one of this account's devices: the account itself,
    /// this device, or a listed one.
    pub fn is_ours(&self, id: &UserId) -> bool {
        *id == self.me || *id == self.account() || self.list.devices.iter().any(|d| d.device == *id)
    }

    /// Whether the primary may link `device`: not on a linked device, not
    /// this key, not a device already listed or revoked, not a ninth.
    pub fn can_link(&self, device: &UserId) -> anyhow::Result<()> {
        if self.linked.is_some() {
            anyhow::bail!("only the primary links devices");
        }
        if *device == self.me {
            anyhow::bail!("an account is not its own device");
        }
        if self.is_revoked(device) {
            anyhow::bail!("that device was revoked; a device does not come back");
        }
        if self.list.devices.iter().any(|d| d.device == *device) {
            anyhow::bail!("that device is linked already");
        }
        if self.list.devices.len() >= MAX_DEVICES {
            anyhow::bail!("an account links at most {MAX_DEVICES} devices");
        }
        Ok(())
    }

    /// The primary adds a device it certified. Refused for a linked device,
    /// a certificate that is not this account's, one for this key, a
    /// device already listed or revoked, or a ninth device.
    pub fn link(&mut self, certificate: DeviceCertificate) -> anyhow::Result<()> {
        certificate.verify()?;
        if certificate.account != self.me {
            anyhow::bail!("the certificate is for another account");
        }
        self.can_link(&certificate.device)?;
        self.list.devices.push(certificate);
        self.list.devices.sort_by_key(|d| d.device);
        self.persist()
    }

    /// A device in waiting takes its link: from now on this key is
    /// `linked`'s account's device, with the account's list as the
    /// primary sent it. Refused on a device that is linked already, and
    /// on an identity with devices of its own, which is an account and
    /// does not become a device.
    pub fn adopt(
        &mut self,
        linked: Linked,
        devices: Vec<DeviceCertificate>,
        revoked: Vec<DeviceRevocation>,
    ) -> anyhow::Result<()> {
        if self.linked.is_some() {
            anyhow::bail!("this device is linked already");
        }
        if !self.list.devices.is_empty() {
            anyhow::bail!("an identity with devices of its own does not become a device");
        }
        check_linked(&linked, &self.me)?;
        let list = checked_list(&linked.account, devices, revoked)?;
        // The link first: a list without it would read as this key's own
        // devices on the next start.
        if let Some(store) = &self.store {
            store.save_linked(Some(&linked))?;
        }
        self.linked = Some(linked);
        self.list = list;
        self.persist()
    }

    /// The primary records a revocation it signed and drops the device.
    pub fn revoke(&mut self, revocation: DeviceRevocation) -> anyhow::Result<()> {
        if self.linked.is_some() {
            anyhow::bail!("only the primary revokes devices");
        }
        revocation.verify()?;
        if revocation.account != self.me {
            anyhow::bail!("the revocation is for another account");
        }
        self.list.devices.retain(|d| d.device != revocation.device);
        if !self.is_revoked(&revocation.device) {
            self.list.revoked.push(revocation);
        }
        self.persist()
    }

    /// Take the list as the primary synced it. Every certificate must be
    /// the account's and verify, as must every revocation. Returns the
    /// devices newly revoked by it, whose sessions the caller drops.
    pub fn set_list(
        &mut self,
        devices: Vec<DeviceCertificate>,
        revoked: Vec<DeviceRevocation>,
    ) -> anyhow::Result<Vec<UserId>> {
        let list = checked_list(&self.account(), devices, revoked)?;
        let new: Vec<UserId> = list
            .revoked
            .iter()
            .map(|r| r.device)
            .filter(|d| !self.is_revoked(d))
            .collect();
        self.list = list;
        self.persist()?;
        Ok(new)
    }

    /// The `sync` content that tells the account's other devices the list.
    pub fn sync_content(&self) -> Content {
        Content::Sync(Sync::Devices {
            devices: self.list.devices.clone(),
            revoked: self.list.revoked.clone(),
        })
    }

    fn persist(&self) -> anyhow::Result<()> {
        match &self.store {
            Some(store) => store.save_devices(&self.list),
            None => Ok(()),
        }
    }
}

/// A list as `account`'s primary sent it, checked: at most [`MAX_DEVICES`],
/// every certificate and revocation verifying and the account's, the
/// devices in ascending id order without doubles.
fn checked_list(
    account: &UserId,
    devices: Vec<DeviceCertificate>,
    revoked: Vec<DeviceRevocation>,
) -> anyhow::Result<DevicesFile> {
    if devices.len() > MAX_DEVICES {
        anyhow::bail!("more than {MAX_DEVICES} devices");
    }
    for certificate in &devices {
        certificate.verify()?;
        if certificate.account != *account {
            anyhow::bail!("a listed device is another account's");
        }
    }
    for revocation in &revoked {
        revocation.verify()?;
        if revocation.account != *account {
            anyhow::bail!("a revocation is another account's");
        }
    }
    let mut devices = devices;
    devices.sort_by_key(|d| d.device);
    devices.dedup_by_key(|d| d.device);
    Ok(DevicesFile { devices, revoked })
}

fn check_linked(linked: &Linked, me: &UserId) -> anyhow::Result<()> {
    linked.certificate.verify()?;
    if linked.certificate.device != *me {
        anyhow::bail!("the certificate in identity.json is for another key");
    }
    if linked.certificate.account != linked.account {
        anyhow::bail!("the certificate in identity.json names another account");
    }
    Ok(())
}

/// Who a content goes to, given the recipient account's devices and one's
/// own (`docs/design/devices.md` section 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spread {
    /// Every device of the recipient's, and a `sync sent` copy to every
    /// device of one's own.
    Everywhere,
    /// Every device of the recipient's; nothing to one's own.
    TheirDevices,
    /// The one device of theirs they last wrote from, or their primary.
    LastDevice,
    /// The one device addressed, whoever it is.
    Addressed,
}

/// How far `content` spreads.
pub fn spread_of(content: &Content) -> Spread {
    match content {
        Content::Text { .. } | Content::File { .. } => Spread::Everywhere,
        Content::Receipt { .. }
        | Content::Revocation(_)
        | Content::Succession(_)
        | Content::DeviceRevocation(_) => Spread::TheirDevices,
        Content::Cover { .. } => Spread::LastDevice,
        Content::Sync(_) | Content::Provision(_) => Spread::Addressed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use silver_protocol::Identity;

    fn certified(account: &Identity, device: &Identity, name: &str) -> DeviceCertificate {
        account.certify_device(&device.user_id(), name, 1).unwrap()
    }

    #[test]
    fn a_primary_links_and_revokes_within_the_rules() {
        let alice = Identity::generate();
        let laptop = Identity::generate();
        let phone = Identity::generate();
        let mut state = DeviceState::ephemeral(alice.user_id(), None).unwrap();
        assert!(!state.is_linked());
        assert_eq!(state.account(), alice.user_id());
        assert!(state.siblings().is_empty());
        assert!(state.is_ours(&alice.user_id()));
        assert!(!state.is_ours(&laptop.user_id()));

        state.link(certified(&alice, &laptop, "laptop")).unwrap();
        state.link(certified(&alice, &phone, "phone")).unwrap();
        let mut expected = vec![laptop.user_id(), phone.user_id()];
        expected.sort();
        assert_eq!(state.siblings(), expected);
        assert!(state.is_ours(&laptop.user_id()));
        assert_eq!(state.devices().len(), 2);
        assert!(
            state
                .devices()
                .windows(2)
                .all(|w| w[0].device < w[1].device)
        );
        // Not twice, not itself, not another account's, not beyond eight.
        assert!(state.link(certified(&alice, &laptop, "again")).is_err());
        assert!(alice.certify_device(&alice.user_id(), "me", 1).is_err());
        let other = Identity::generate();
        assert!(state.link(certified(&other, &laptop, "theirs")).is_err());
        for _ in 0..6 {
            state
                .link(certified(&alice, &Identity::generate(), "more"))
                .unwrap();
        }
        assert!(
            state
                .link(certified(&alice, &Identity::generate(), "ninth"))
                .is_err()
        );

        state
            .revoke(alice.revoke_device(&laptop.user_id(), 2))
            .unwrap();
        assert!(state.is_revoked(&laptop.user_id()));
        assert!(!state.siblings().contains(&laptop.user_id()));
        assert!(state.link(certified(&alice, &laptop, "back")).is_err());
        assert_eq!(state.revoked().len(), 1);
        // Said again: nothing doubled.
        state
            .revoke(alice.revoke_device(&laptop.user_id(), 3))
            .unwrap();
        assert_eq!(state.revoked().len(), 1);
        assert!(
            state
                .revoke(other.revoke_device(&phone.user_id(), 3))
                .is_err()
        );
        assert!(matches!(
            state.sync_content(),
            Content::Sync(Sync::Devices { devices, revoked })
                if devices.len() == 7 && revoked.len() == 1
        ));
    }

    #[test]
    fn a_linked_device_knows_its_account_and_takes_the_synced_list() {
        let alice = Identity::generate();
        let laptop = Identity::generate();
        let phone = Identity::generate();
        let certificate = certified(&alice, &laptop, "laptop");
        let linked = Linked {
            account: alice.user_id(),
            certificate: certificate.clone(),
        };
        let mut state = DeviceState::ephemeral(laptop.user_id(), Some(linked.clone())).unwrap();
        assert!(state.is_linked());
        assert_eq!(state.account(), alice.user_id());
        assert_eq!(state.certificate(), Some(&certificate));
        assert_eq!(state.siblings(), vec![alice.user_id()]);
        assert!(state.is_ours(&alice.user_id()) && state.is_ours(&laptop.user_id()));
        assert!(state.link(certified(&alice, &phone, "phone")).is_err());
        assert!(
            state
                .revoke(alice.revoke_device(&phone.user_id(), 1))
                .is_err()
        );

        let newly = state
            .set_list(
                vec![certified(&alice, &phone, "phone"), certificate.clone()],
                vec![],
            )
            .unwrap();
        assert!(newly.is_empty());
        let mut siblings = state.siblings();
        siblings.sort();
        let mut expected = vec![alice.user_id(), phone.user_id()];
        expected.sort();
        assert_eq!(siblings, expected);
        let newly = state
            .set_list(
                vec![certificate.clone()],
                vec![alice.revoke_device(&phone.user_id(), 2)],
            )
            .unwrap();
        assert_eq!(newly, vec![phone.user_id()]);
        assert!(state.is_revoked(&phone.user_id()));
        assert_eq!(state.siblings(), vec![alice.user_id()]);
        // Another account's list or statements are refused whole.
        let other = Identity::generate();
        assert!(
            state
                .set_list(vec![certified(&other, &phone, "x")], vec![])
                .is_err()
        );
        assert!(
            state
                .set_list(vec![], vec![other.revoke_device(&phone.user_id(), 3)])
                .is_err()
        );
        // The certificate must be this key's and the account's.
        assert!(DeviceState::ephemeral(phone.user_id(), Some(linked)).is_err());
    }

    #[test]
    fn a_device_in_waiting_adopts_its_link_once() {
        let alice = Identity::generate();
        let laptop = Identity::generate();
        let phone = Identity::generate();
        let certificate = certified(&alice, &laptop, "laptop");
        let linked = Linked {
            account: alice.user_id(),
            certificate: certificate.clone(),
        };
        let mut state = DeviceState::ephemeral(laptop.user_id(), None).unwrap();
        assert!(state.can_link(&phone.user_id()).is_ok());
        // Another key's certificate, or a list of another account's, is
        // refused and leaves the device as it was.
        let others = Linked {
            account: alice.user_id(),
            certificate: certified(&alice, &phone, "phone"),
        };
        assert!(state.adopt(others, vec![], vec![]).is_err());
        let mallory = Identity::generate();
        assert!(
            state
                .adopt(
                    linked.clone(),
                    vec![certified(&mallory, &phone, "phone")],
                    vec![]
                )
                .is_err()
        );
        assert!(!state.is_linked());

        state
            .adopt(
                linked.clone(),
                vec![certificate.clone(), certified(&alice, &phone, "phone")],
                vec![alice.revoke_device(&Identity::generate().user_id(), 2)],
            )
            .unwrap();
        assert!(state.is_linked());
        assert_eq!(state.account(), alice.user_id());
        assert_eq!(state.certificate(), Some(&certificate));
        assert_eq!(state.devices().len(), 2);
        assert_eq!(state.revoked().len(), 1);
        let mut siblings = state.siblings();
        siblings.sort();
        let mut expected = vec![alice.user_id(), phone.user_id()];
        expected.sort();
        assert_eq!(siblings, expected);
        // Once: a linked device does not take another link, and a
        // primary with devices does not become a device.
        assert!(state.adopt(linked.clone(), vec![], vec![]).is_err());
        assert!(state.can_link(&phone.user_id()).is_err());
        let mut primary = DeviceState::ephemeral(alice.user_id(), None).unwrap();
        primary.link(certificate.clone()).unwrap();
        let bob = Identity::generate();
        let bobs = Linked {
            account: bob.user_id(),
            certificate: bob.certify_device(&alice.user_id(), "x", 1).unwrap(),
        };
        assert!(primary.adopt(bobs, vec![], vec![]).is_err());
    }

    #[test]
    fn contents_spread_as_the_design_says() {
        use silver_protocol::envelope::ReceiptKind;
        assert_eq!(
            spread_of(&Content::Text { body: "x".into() }),
            Spread::Everywhere
        );
        assert_eq!(
            spread_of(&Content::Receipt {
                kind: ReceiptKind::Read,
                ids: vec![]
            }),
            Spread::TheirDevices
        );
        assert_eq!(
            spread_of(&Content::Cover { pad: "x".into() }),
            Spread::LastDevice
        );
        let alice = Identity::generate();
        assert_eq!(
            spread_of(&Content::DeviceRevocation(
                alice.revoke_device(&Identity::generate().user_id(), 1)
            )),
            Spread::TheirDevices
        );
        assert_eq!(
            spread_of(&Content::Sync(Sync::Read {
                peer: alice.user_id(),
                ids: vec![]
            })),
            Spread::Addressed
        );
    }
}
