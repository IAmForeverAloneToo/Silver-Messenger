//! Devices in the terminal client (`docs/design/devices.md` section 8.3):
//! the `/devices` commands, what this identity's other devices say (the
//! `sync` events), a newly linked device added to every group and an
//! unlinked one taken out, and a linked device that leaves.

use std::collections::HashSet;

use silver_client::linking::{DEFAULT_HISTORY_DAYS, Snapshot, SnapshotGroup};
use silver_client::{DeviceLink, DeviceState, GroupState};
use silver_protocol::device::{ContactAction, MAX_DEVICE_NAME_BYTES, Sync};
use silver_protocol::group::GroupId;
use silver_protocol::wire::feature;
use silver_protocol::{DeviceCertificate, DeviceRevocation};

use super::groups::Purpose;
use super::*;

/// A newly linked device deposits its key packages once it connects;
/// the primary asks for them again this often, this many times, before
/// giving up on a group.
const DEVICE_JOIN_RETRY: Duration = Duration::from_secs(5);
const DEVICE_JOIN_ATTEMPTS: u32 = 12;
/// How long a leaving device waits for the relay to take its word to the
/// primary before it wipes itself anyway.
const LEAVE_PATIENCE: Duration = Duration::from_secs(15);

impl App {
    /// Read the device state, when the client keeps one.
    pub(super) fn with_devices<T>(&self, f: impl FnOnce(&DeviceState) -> T) -> Option<T> {
        self.client
            .devices()
            .map(|shared| f(&shared.lock().unwrap_or_else(|e| e.into_inner())))
    }

    /// Whether this identity has other devices to keep informed.
    fn has_siblings(&self) -> bool {
        self.with_devices(|d| !d.siblings().is_empty())
            .unwrap_or(false)
    }

    /// Tell this identity's other devices something, when there are any.
    pub(super) fn sync(&self, sync: Sync) {
        if !self.has_siblings() {
            return;
        }
        let client = self.client.clone();
        tokio::spawn(async move {
            if let Err(e) = client.send_sync(sync).await {
                tracing::debug!("telling our devices: {e}");
            }
        });
    }

    /// A contact list change, for this identity's other devices.
    pub(super) fn sync_contact(&self, action: ContactAction) {
        self.sync(Sync::Contact { action });
    }

    /// The linked devices in the order the list shows them.
    fn device_list(&self) -> Vec<DeviceCertificate> {
        self.with_devices(|d| d.devices().to_vec())
            .unwrap_or_default()
    }

    /// The device `n` names in the list, as `/devices` numbers them.
    fn device_at(&self, arg: Option<&&str>) -> Option<DeviceCertificate> {
        let n: usize = arg?.parse().ok()?;
        n.checked_sub(1)
            .and_then(|i| self.device_list().get(i).cloned())
    }

    fn device_name_of(&self, device: &UserId) -> String {
        self.with_devices(|d| d.name_of(device).map(|n| n.to_owned()))
            .flatten()
            .map(|n| silver_client::files::printable(&n, MAX_DEVICE_NAME_BYTES))
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| format!("{}…", device.short()))
    }

    // --- commands ------------------------------------------------------------

    pub(super) fn cmd_devices(&mut self, args: &[&str]) {
        let usage = "Usage: /devices · link <link> [days] · remove <n> · name <n> <name> · leave";
        match args.first().map(|s| s.to_ascii_lowercase()).as_deref() {
            None | Some("list") => self.devices_list(),
            Some("link") => self.devices_link(&args[1..]),
            Some("remove") | Some("unlink") => self.devices_remove(&args[1..]),
            Some("name") | Some("rename") => self.devices_name(&args[1..]),
            Some("leave") => self.devices_leave(&args[1..]),
            Some("join") => self.devices_join(),
            _ => self.toast(usage),
        }
    }

    /// `/devices join`: add every linked device to the groups it is not
    /// in yet, for one that had no key packages when it was linked.
    fn devices_join(&mut self) {
        if self.linked {
            self.toast("Run /devices join on your primary.");
            return;
        }
        let devices = self.device_list();
        if devices.is_empty() {
            self.toast("No linked devices.");
            return;
        }
        for device in devices {
            self.add_device_to_groups(device.device, 1);
        }
        self.toast("Adding your devices to the groups they are not in yet…");
    }

    fn devices_list(&mut self) {
        let Some((linked, account, list, revoked)) = self.with_devices(|d| {
            (
                d.linked().cloned(),
                d.account(),
                d.devices().to_vec(),
                d.revoked().len(),
            )
        }) else {
            self.toast("This client keeps no devices.");
            return;
        };
        match linked {
            Some(linked) => {
                let own = &linked.certificate;
                self.system(
                    Level::Info,
                    format!(
                        "This is the device \"{}\" of {account}, linked {}.",
                        silver_client::files::printable(&own.name, MAX_DEVICE_NAME_BYTES),
                        crate::ui::clock(own.created_at_ms)
                    ),
                );
                self.system(Level::Info, "The identity's devices:");
                self.system(Level::Info, format!("  the primary  {account}"));
                for device in list.iter().filter(|d| d.device != own.device) {
                    self.system(
                        Level::Info,
                        format!(
                            "  {}  linked {}  {}",
                            self.device_name_of(&device.device),
                            crate::ui::clock(device.created_at_ms),
                            device.device
                        ),
                    );
                }
                self.system(
                    Level::Info,
                    "Devices are linked, named and removed on the primary; /devices leave unlinks this one.",
                );
            }
            None if list.is_empty() => {
                self.system(
                    Level::Info,
                    format!(
                        "No linked devices. To use this identity ({account}) on another computer, run silver --link there with an empty data directory and give the link it prints to /devices link here."
                    ),
                );
            }
            None => {
                self.system(
                    Level::Info,
                    format!("This is your primary ({account}). Linked devices:"),
                );
                for (i, device) in list.iter().enumerate() {
                    self.system(
                        Level::Info,
                        format!(
                            "  {}. {}  linked {}  {}",
                            i + 1,
                            self.device_name_of(&device.device),
                            crate::ui::clock(device.created_at_ms),
                            device.device
                        ),
                    );
                }
                self.system(
                    Level::Info,
                    "/devices remove <n> unlinks one, /devices name <n> <name> renames it.",
                );
            }
        }
        if revoked > 0 {
            self.system(
                Level::Info,
                format!(
                    "{revoked} device(s) were unlinked before; a device does not come back, it is linked anew."
                ),
            );
        }
        self.select(0);
    }

    /// `/devices link <link> [days]`: take a device in, with a snapshot of
    /// the contacts, the groups and the last `days` days of history.
    fn devices_link(&mut self, args: &[&str]) {
        if self.linked {
            self.toast("Only your primary links devices; run /devices link there.");
            return;
        }
        let Some(text) = args.first() else {
            self.toast("Usage: /devices link <link> [days of history, default 30]");
            return;
        };
        if !self.client.relay_supports(feature::DEVICES) {
            self.system(
                Level::Warn,
                "This relay does not keep devices; it needs Silver Messenger 0.9.0 or later.",
            );
            self.toast("The relay is too old for devices; see System.");
            return;
        }
        let link: DeviceLink = match text.parse() {
            Ok(link) => link,
            Err(e) => {
                self.toast(format!("Not a device link: {e}"));
                return;
            }
        };
        let days = match args.get(1) {
            None => DEFAULT_HISTORY_DAYS,
            Some(d) => match d.parse::<u32>() {
                Ok(days) => days,
                Err(_) => {
                    self.toast("The second argument is the days of history to send (0 for none).");
                    return;
                }
            },
        };
        if link.relay.trim_end_matches('/') != self.relay_url.trim_end_matches('/') {
            self.system(
                Level::Warn,
                format!(
                    "The link names the relay {}, but you are on {}. A device must register with your relay: run silver --link --relay {} on it and try again.",
                    link.relay, self.relay_url, self.relay_url
                ),
            );
            self.toast("That device is on another relay; see System.");
            return;
        }
        if let Err(e) = self
            .with_devices(|d| d.can_link(&link.device))
            .unwrap_or_else(|| Ok(()))
        {
            self.toast(format!("Cannot link that device: {e}"));
            return;
        }
        let name = link
            .name
            .clone()
            .map(|n| silver_client::files::printable(&n, MAX_DEVICE_NAME_BYTES))
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| format!("device {}", self.device_list().len() + 1));
        let groups: Vec<SnapshotGroup> = self
            .groups
            .list()
            .filter(|(_, r)| r.state == GroupState::Active)
            .map(|(id, r)| SnapshotGroup {
                id: *id,
                name: r.name.clone(),
                alias: r.alias.clone(),
                expire_after_s: r.expire_after_s,
            })
            .collect();
        let snapshot = match Snapshot::gather(&self.store, &groups, days, now_ms()) {
            Ok(snapshot) => snapshot,
            Err(e) => {
                self.toast(format!("Could not gather the snapshot: {e}"));
                return;
            }
        };
        let bytes = if snapshot.is_empty() {
            None
        } else {
            match snapshot.to_bytes() {
                Ok(bytes) => Some(bytes),
                Err(e) => {
                    self.toast(format!("Could not make the snapshot: {e}"));
                    return;
                }
            }
        };
        self.system(
            Level::Info,
            format!(
                "Linking \"{name}\"… it gets your {} contact(s), {} group(s) and {} message(s) of the last {days} day(s).",
                snapshot.contacts.len(),
                snapshot.groups.len(),
                snapshot.message_count()
            ),
        );
        self.toast(format!("Linking {name}…"));
        let client = self.client.clone();
        let tx = self.internal_tx.clone();
        tokio::spawn(async move {
            let snapshot = match bytes {
                Some(bytes) => match client.upload_bytes("snapshot", bytes, true).await {
                    Ok(info) => Some(info),
                    Err(e) => {
                        let _ = tx
                            .send(Internal::DeviceLinked {
                                name,
                                result: Err(format!(
                                    "the snapshot could not be put on the relay: {e}"
                                )),
                            })
                            .await;
                        return;
                    }
                },
                None => None,
            };
            let result = client
                .link_device(&link, &name, snapshot)
                .await
                .map_err(|e| e.to_string());
            let _ = tx.send(Internal::DeviceLinked { name, result }).await;
        });
        // The outcome is a note in System; show where it lands.
        self.select(0);
    }

    pub(super) fn on_device_linked(
        &mut self,
        name: String,
        result: Result<DeviceCertificate, String>,
    ) {
        match result {
            Ok(certificate) => {
                self.system(
                    Level::Info,
                    format!(
                        "Linked the device \"{name}\" ({}…). It has your contacts and history; your groups follow now.",
                        certificate.device.short()
                    ),
                );
                self.toast(format!("Linked {name}."));
                self.add_device_to_groups(certificate.device, 1);
            }
            Err(e) => {
                self.system(Level::Warn, format!("Could not link \"{name}\": {e}"));
                self.toast(format!("Could not link {name}; see System."));
            }
        }
    }

    /// Ask the relay for one key package of `device`'s per group this
    /// identity is in, to add its leaf to each.
    fn add_device_to_groups(&mut self, device: UserId, attempt: u32) {
        let groups: Vec<GroupId> = self
            .groups
            .list()
            .filter(|(_, r)| {
                r.state == GroupState::Active
                    && r.is_member(&self.account)
                    && !r.members.iter().any(|m| m.device == device)
            })
            .map(|(id, _)| *id)
            .collect();
        if groups.is_empty() {
            return;
        }
        let client = self.client.clone();
        let tx = self.internal_tx.clone();
        tokio::spawn(async move {
            if attempt > 1 {
                tokio::time::sleep(DEVICE_JOIN_RETRY).await;
            }
            let mut packages = Vec::new();
            for group in groups {
                let result = client
                    .key_package_for(device)
                    .await
                    .map_err(|e| e.to_string());
                packages.push((group, result));
            }
            let _ = tx
                .send(Internal::DeviceKeyPackages {
                    device,
                    attempt,
                    packages,
                })
                .await;
        });
    }

    pub(super) fn on_device_key_packages(
        &mut self,
        device: UserId,
        attempt: u32,
        packages: Vec<(GroupId, KeyPackageAnswer)>,
    ) {
        let name = self.device_name_of(&device);
        let mut waiting = false;
        for (group, answer) in packages {
            if self.groups.has_staged(&group) {
                waiting = true;
                continue;
            }
            let package = match answer {
                Ok(Some((package, _))) => package,
                // Not deposited yet: the device deposits once it connects.
                Ok(None) => {
                    waiting = true;
                    continue;
                }
                Err(e) => {
                    tracing::warn!("key package for a device of ours: {e}");
                    waiting = true;
                    continue;
                }
            };
            let verified = match self.groups.verify_key_package(
                &self.account,
                &package.data,
                now_ms(),
            ) {
                Ok(bytes) => bytes,
                Err(e) => {
                    self.system(
                        Level::Warn,
                        format!(
                            "The relay handed out a key package for your device \"{name}\" that does not check out ({e}); it was not added to {}.",
                            self.group_name(&group)
                        ),
                    );
                    continue;
                }
            };
            match self.groups.stage_add(&group, &[verified]) {
                Ok(staged) => self.run_staged(staged, Purpose::Device(device)),
                Err(e) => tracing::warn!("adding a device of ours to a group: {e}"),
            }
        }
        if waiting && attempt < DEVICE_JOIN_ATTEMPTS {
            self.add_device_to_groups(device, attempt + 1);
        } else if waiting {
            self.system(
                Level::Warn,
                format!(
                    "Your device \"{name}\" could not be added to every group: it has no key packages on the relay yet. Once it has connected, /devices join adds it."
                ),
            );
        }
    }

    /// `/devices remove <n>`: unlink a device.
    fn devices_remove(&mut self, args: &[&str]) {
        if self.linked {
            self.toast("Only your primary unlinks devices; /devices leave unlinks this one.");
            return;
        }
        let Some(device) = self.device_at(args.first()) else {
            self.toast("Usage: /devices remove <n> (as /devices numbers them)");
            return;
        };
        let name = self.device_name_of(&device.device);
        self.toast(format!("Unlinking {name}…"));
        self.revoke_device(device.device, name);
        self.select(0);
    }

    fn revoke_device(&mut self, device: UserId, name: String) {
        let client = self.client.clone();
        let tx = self.internal_tx.clone();
        tokio::spawn(async move {
            let result = client
                .revoke_device(device)
                .await
                .map_err(|e| e.to_string());
            let _ = tx
                .send(Internal::DeviceRevoked {
                    device,
                    name,
                    result,
                })
                .await;
        });
    }

    pub(super) fn on_device_revoked(
        &mut self,
        device: UserId,
        name: String,
        result: Result<DeviceRevocation, String>,
    ) {
        let revocation = match result {
            Ok(revocation) => revocation,
            Err(e) => {
                self.system(Level::Warn, format!("Could not unlink \"{name}\": {e}"));
                self.toast(format!("Could not unlink {name}; see System."));
                return;
            }
        };
        self.system(
            Level::Info,
            format!(
                "Unlinked \"{name}\" ({}…): the relay refuses it from now on, your contacts are told, and it leaves your groups.",
                device.short()
            ),
        );
        self.toast(format!("Unlinked {name}."));
        // Contacts whose client understands devices get the statement
        // inside a message now; the relay serves it to the rest with
        // their next lookup.
        let peers: Vec<UserId> = self
            .contacts
            .iter()
            .filter(|c| !c.revoked && c.supports(capability::DEVICES))
            .map(|c| c.user_id)
            .collect();
        for peer in peers {
            self.send_content_to(peer, Content::DeviceRevocation(revocation.clone()));
        }
        // Its leaf goes from every group it is in.
        let groups: Vec<GroupId> = self
            .groups
            .list()
            .filter(|(_, r)| {
                r.state == GroupState::Active && r.members.iter().any(|m| m.device == device)
            })
            .map(|(id, _)| *id)
            .collect();
        for group in groups {
            if self.groups.has_staged(&group) {
                continue;
            }
            match self.groups.stage_remove_device(&group, &device) {
                Ok(staged) => self.run_staged(staged, Purpose::Device(device)),
                Err(e) => tracing::warn!("taking an unlinked device out of a group: {e}"),
            }
        }
    }

    /// `/devices name <n> <name>`: rename a device.
    fn devices_name(&mut self, args: &[&str]) {
        if self.linked {
            self.toast("Devices are named on your primary: /devices name <n> <name> there.");
            return;
        }
        let Some(device) = self.device_at(args.first()) else {
            self.toast("Usage: /devices name <n> <name>");
            return;
        };
        let name = silver_client::files::printable(&args[1..].join(" "), MAX_DEVICE_NAME_BYTES);
        if name.is_empty() {
            self.toast("Usage: /devices name <n> <name>");
            return;
        }
        let client = self.client.clone();
        let tx = self.internal_tx.clone();
        let device = device.device;
        tokio::spawn(async move {
            let result = client
                .rename_device(device, &name)
                .await
                .map_err(|e| e.to_string());
            let _ = tx.send(Internal::DeviceRenamed { device, result }).await;
        });
    }

    pub(super) fn on_device_renamed(
        &mut self,
        device: UserId,
        result: Result<DeviceCertificate, String>,
    ) {
        match result {
            Ok(certificate) => self.toast(format!(
                "Device {}… is now called \"{}\".",
                device.short(),
                silver_client::files::printable(&certificate.name, MAX_DEVICE_NAME_BYTES)
            )),
            Err(e) => self.toast(format!("Could not rename the device: {e}")),
        }
    }

    /// `/devices leave confirm`: this device asks its primary to unlink
    /// it, then erases what it holds.
    fn devices_leave(&mut self, args: &[&str]) {
        if !self.linked {
            self.toast(
                "This is your primary; it does not leave. /devices remove <n> unlinks a device, /revoke retires the identity.",
            );
            return;
        }
        let confirmed = matches!(
            args.first().map(|a| a.to_ascii_lowercase()).as_deref(),
            Some("confirm") | Some("yes")
        );
        if !confirmed {
            self.system(
                Level::Warn,
                "This unlinks this device: it asks your primary to revoke it, then erases the keys, contacts and history here (files saved in downloads/ stay). To use this identity here again, link the computer anew. Run /devices leave confirm to go ahead.",
            );
            self.toast("Type /devices leave confirm to unlink this device.");
            return;
        }
        if self.leaving.is_some() {
            return;
        }
        self.leaving = Some((HashSet::new(), Instant::now()));
        self.system(Level::Warn, "Leaving: telling the primary…");
        let client = self.client.clone();
        let tx = self.internal_tx.clone();
        tokio::spawn(async move {
            let ids = match client.send_sync(Sync::Leave).await {
                Ok(envelopes) => envelopes.into_iter().map(|e| e.id).collect(),
                Err(e) => {
                    tracing::warn!("asking the primary to unlink this device: {e}");
                    Vec::new()
                }
            };
            let _ = tx.send(Internal::LeaveQueued { ids }).await;
        });
    }

    pub(super) fn on_leave_queued(&mut self, ids: Vec<String>) {
        let Some((waiting, _)) = &mut self.leaving else {
            return;
        };
        waiting.extend(ids);
        if waiting.is_empty() {
            self.finish_leave(false);
        }
    }

    /// The relay took an envelope: one of the leave's, maybe.
    pub(super) fn on_leave_sent(&mut self, id: &str) {
        let done = match &mut self.leaving {
            Some((waiting, _)) => {
                waiting.remove(id);
                waiting.is_empty()
            }
            None => false,
        };
        if done {
            self.finish_leave(true);
        }
    }

    /// A leave still waiting for the relay after long enough goes ahead
    /// without its word.
    pub(super) fn tick_leave(&mut self) {
        if self.leaving.as_ref().is_some_and(|(waiting, since)| {
            !waiting.is_empty() && since.elapsed() >= LEAVE_PATIENCE
        }) {
            self.finish_leave(false);
        }
    }

    fn finish_leave(&mut self, told: bool) {
        self.leaving = None;
        match self.store.wipe() {
            Ok(()) => {
                self.wiped = Some(if told {
                    "This device is unlinked: the primary was told, and the keys, contacts and history here are erased.".to_owned()
                } else {
                    "The keys, contacts and history here are erased. The primary could not be told; remove this device there with /devices remove.".to_owned()
                });
                self.should_quit = true;
            }
            Err(e) => {
                self.system(
                    Level::Warn,
                    format!("Could not erase the data directory: {e}"),
                );
                self.toast("Could not erase the data directory; see System.");
            }
        }
    }

    // --- what the other devices say --------------------------------------------

    pub(super) fn on_sync(&mut self, device: UserId, sync: Sync) {
        match sync {
            // A sibling's "delete for me" is applied where deletions are
            // (docs/design/everyday.md); nothing here does yet.
            Sync::Remove { .. } => {}
            Sync::Sent {
                peer,
                id,
                sent_at_ms,
                content,
            } => {
                if self.known_ids.contains(&id) || self.contact_index(&peer).is_none() {
                    return;
                }
                let Some(text) = line_text(&content) else {
                    return;
                };
                self.record(
                    peer,
                    ChatLine {
                        id,
                        direction: Direction::Sent,
                        timestamp_ms: claimed_time(sent_at_ms),
                        text,
                        delivered: true,
                        failed: false,
                        receipt: None,
                        file: None,
                        pending: None,
                        sender: None,
                    },
                );
                if self.selected_contact().map(|c| c.user_id) == Some(peer) {
                    self.scroll = 0;
                }
            }
            Sync::Received {
                from,
                id,
                sent_at_ms,
                content,
            } => {
                if self.known_ids.contains(&id) || self.blocked.contains(&from) {
                    return;
                }
                let Some(index) = self.contact_index(&from) else {
                    // The primary holds a stranger's message as a request
                    // and passes the contact on once accepted.
                    return;
                };
                let Some(text) = line_text(&content) else {
                    return;
                };
                let (text, pending) = match FileInfo::from_content(&content) {
                    Some(info) => match info.check() {
                        Ok(()) if self.contacts[index].auto_files => (text, Some(info)),
                        Ok(()) => (format!("{text} · /get to fetch"), Some(info)),
                        Err(e) => (format!("{text} · refused: {e}"), None),
                    },
                    None => (text, None),
                };
                let name = self.contact_name(&from);
                self.record(
                    from,
                    ChatLine {
                        id: id.clone(),
                        direction: Direction::Received,
                        timestamp_ms: claimed_time(sent_at_ms),
                        text,
                        delivered: true,
                        failed: false,
                        receipt: None,
                        file: None,
                        pending,
                        sender: None,
                    },
                );
                // The primary sends the receipts; here it is shown or not.
                let shown =
                    self.selected_contact().map(|c| c.user_id) == Some(from) && self.focused;
                if !shown {
                    self.notifier.announce(&format!("New message from {name}"));
                    self.unread.entry(from).or_default().push(id);
                }
            }
            Sync::Read { peer, ids, .. } => {
                if let Some(unread) = self.unread.get_mut(&peer) {
                    unread.retain(|i| !ids.contains(i));
                }
            }
            Sync::Contact { action } => self.apply_contact_action(action),
            Sync::Devices { devices, .. } => {
                if self.linked {
                    // The client applied the list; this device's own name
                    // may have changed with it.
                    self.device_name = self
                        .with_devices(|d| d.certificate().map(|c| c.name.clone()))
                        .flatten();
                    self.system(
                        Level::Info,
                        format!(
                            "The primary updated the device list: {} device(s) besides it.",
                            devices.len()
                        ),
                    );
                }
            }
            Sync::Leave => {
                if self.linked {
                    return;
                }
                let name = self.device_name_of(&device);
                self.system(
                    Level::Info,
                    format!("Your device \"{name}\" asked to be unlinked; unlinking it."),
                );
                self.revoke_device(device, name);
            }
        }
    }

    /// A contact list change made on another device of this identity.
    fn apply_contact_action(&mut self, action: ContactAction) {
        match action {
            ContactAction::Add {
                user,
                alias,
                bundle,
            } => {
                if user == self.account || self.blocked.contains(&user) {
                    return;
                }
                match self.contact_index(&user) {
                    Some(index) => {
                        if alias.is_some() {
                            self.contacts[index].alias = alias;
                        }
                        if self.contacts[index].bundle.is_none() {
                            self.contacts[index].bundle = bundle.map(|b| *b);
                        }
                        self.persist_contacts();
                    }
                    None => {
                        let mut contact = Contact::new(user);
                        contact.alias = alias;
                        contact.bundle = bundle.map(|b| *b);
                        let name = contact.display_name();
                        self.contacts.push(contact);
                        self.threads.entry(user).or_default();
                        self.persist_contacts();
                        // Their messages held here as a request, if any,
                        // move into the chat as they did there.
                        if let Some(index) = self.requests.iter().position(|r| r.from == user) {
                            self.take_request(index);
                        }
                        self.system(
                            Level::Info,
                            format!("Added {name} ({user}) on another of your devices."),
                        );
                    }
                }
            }
            ContactAction::Remove { user } => {
                if let Some(index) = self.contact_index(&user) {
                    let removed = self.contacts.remove(index);
                    self.threads.remove(&user);
                    self.unread.remove(&user);
                    self.persist_contacts();
                    if self.selected >= self.pane_count() {
                        self.select(0);
                    }
                    self.system(
                        Level::Info,
                        format!(
                            "Removed {} on another of your devices.",
                            removed.display_name()
                        ),
                    );
                }
            }
            ContactAction::Alias { user, alias } => {
                if let Some(index) = self.contact_index(&user) {
                    self.contacts[index].alias = alias
                        .map(|a| silver_client::files::printable(&a, MAX_ALIAS_CHARS))
                        .filter(|a| !a.is_empty());
                    self.persist_contacts();
                }
            }
            ContactAction::Verify { user, verified } => {
                if let Some(index) = self.contact_index(&user) {
                    self.contacts[index].verified = verified;
                    self.persist_contacts();
                }
            }
            ContactAction::Block { user } => {
                if let Some(index) = self.contact_index(&user) {
                    self.contacts.remove(index);
                    self.threads.remove(&user);
                    self.unread.remove(&user);
                    self.persist_contacts();
                }
                if let Some(index) = self.requests.iter().position(|r| r.from == user) {
                    self.requests.remove(index);
                    self.persist_requests();
                }
                if !self.blocked.contains(&user) {
                    self.blocked.push(user);
                    self.persist_blocked();
                }
                self.client.forget_sessions(&user);
                if self.selected >= self.pane_count() {
                    self.select(0);
                }
            }
            ContactAction::Unblock { user } => {
                self.blocked.retain(|b| *b != user);
                self.persist_blocked();
            }
            ContactAction::Files { user, auto } => {
                if let Some(index) = self.contact_index(&user) {
                    self.contacts[index].auto_files = auto;
                    self.persist_contacts();
                }
            }
        }
    }

    /// `/session`'s word on a contact's devices: how many, and how the
    /// messages to each are protected.
    pub(super) fn device_sessions_line(&self, contact: &Contact) -> Option<String> {
        let devices: Vec<UserId> = contact
            .bundle
            .as_ref()
            .map(|b| b.devices.iter().map(|d| d.device).collect())
            .unwrap_or_default();
        if devices.is_empty() {
            return None;
        }
        let name = contact.display_name();
        let under_session = devices
            .iter()
            .filter(|d| self.client.session_info(d).is_some())
            .count();
        Some(format!(
            "{name} has {} linked device(s); every message goes to each under a session of its own ({under_session} established so far), and each device's messages count as {name}'s.",
            devices.len()
        ))
    }
}

/// The line a sent or received copy shows, for a text or a file.
fn line_text(content: &Content) -> Option<String> {
    match content {
        Content::Text { body, .. } => Some(body.clone()),
        Content::File { .. } => {
            FileInfo::from_content(content).map(|i| format!("[file] {}", i.label()))
        }
        _ => None,
    }
}
