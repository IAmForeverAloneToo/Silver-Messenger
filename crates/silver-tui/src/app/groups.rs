//! Groups in the terminal client: the panes, the commands, and the flows
//! between the groups engine (synchronous, owned by the app) and the relay
//! (asynchronous, through the client). Anything that commits goes: stage
//! in the engine, ask the sequencer in a task, then merge or discard when
//! the answer comes back as an [`Internal`] event.

use std::path::PathBuf;

use silver_client::groups::{
    Change, Created, GroupEvent, GroupLink, GroupState, Groups, Outgoing, Staged,
};
use silver_client::{ClientError, GroupError, KeyPackageStatus, SequencerAnswer};
use silver_protocol::bundle::capability as bundle_capability;
use silver_protocol::group::{GroupBody, GroupId};
use silver_protocol::wire::{KeyPackageDeposit, feature};

use super::*;

/// Why a commit was staged: what to say when the sequencer answers.
#[derive(Clone, Debug)]
pub(super) enum Purpose {
    Create,
    Add(Vec<UserId>),
    /// An add for someone who presented a valid invite link.
    Join(UserId),
    Remove(Vec<UserId>),
    Rename(String),
    Admin {
        user: UserId,
        admin: bool,
    },
    LinkReset,
    Refresh,
    Rejoin(UserId),
}

/// Key package deposits wait this long after the relay said the deposit
/// ran low, since a relay takes one deposit a minute.
const REDEPOSIT_AFTER: Duration = Duration::from_secs(61);
/// How often groups due for a self-update are looked for.
const MAINTENANCE_EVERY: Duration = Duration::from_secs(60);

impl App {
    // --- panes ---------------------------------------------------------------

    /// The group whose pane is selected, if a group's is.
    pub fn selected_group(&self) -> Option<GroupId> {
        let index = self.selected.checked_sub(1 + self.contacts.len())?;
        self.group_list.get(index).copied()
    }

    /// The pane index of `group`, if it is listed.
    fn group_pane(&self, group: &GroupId) -> Option<usize> {
        self.group_list
            .iter()
            .position(|g| g == group)
            .map(|i| i + 1 + self.contacts.len())
    }

    /// The groups the chat list shows: everything but invitations, oldest
    /// first.
    pub(super) fn refresh_group_list(&mut self) {
        let mut groups: Vec<(u64, GroupId)> = self
            .groups
            .list()
            .filter(|(_, r)| !matches!(r.state, GroupState::Invited { .. }))
            .map(|(id, r)| (r.created_at_ms, *id))
            .collect();
        groups.sort();
        self.group_list = groups.into_iter().map(|(_, id)| id).collect();
        for group in &self.group_list {
            self.group_threads.entry(*group).or_default();
        }
        self.selected = self.selected.min(self.pane_count() - 1);
    }

    pub fn group_name(&self, group: &GroupId) -> String {
        self.groups
            .get(group)
            .map(|r| r.display_name().to_owned())
            .unwrap_or_else(|| format!("group {}…", group.short()))
    }

    /// What a group's row and title say after the name.
    pub fn group_state_label(&self, group: &GroupId) -> Option<&'static str> {
        match self.groups.get(group)?.state {
            GroupState::Active => None,
            GroupState::Invited { .. } => Some("invited"),
            GroupState::Left => Some("left"),
            GroupState::Removed { .. } => Some("removed"),
            GroupState::Broken { .. } => Some("broken"),
            GroupState::OutOfSync { .. } => Some("out of sync"),
        }
    }

    /// Members of a group as shown: the count and whether we are an admin.
    pub fn group_title(&self, group: &GroupId) -> String {
        let name = self.group_name(group);
        let Some(record) = self.groups.get(group) else {
            return format!(" # {name} ");
        };
        let mut parts = vec![
            format!("# {name}"),
            format!("{} members", record.members.len()),
        ];
        if record.is_admin(&self.me) {
            parts.push("you are an admin".into());
        }
        if let Some(state) = self.group_state_label(group) {
            parts.push(state.into());
        }
        format!(" {} ", parts.join(" · "))
    }

    /// A member's name as the group pane shows it.
    pub fn member_name(&self, user: &UserId) -> String {
        if *user == self.me {
            "you".into()
        } else {
            self.contact_name(user)
        }
    }

    /// Group invitations waiting for a yes or a no, for the Requests pane.
    pub fn invitations(&self) -> Vec<silver_client::HeldWelcome> {
        self.groups.invitations()
    }

    // --- commands ------------------------------------------------------------

    pub(super) fn cmd_group(&mut self, args: &[&str]) {
        let usage = "Usage: /group new <name> · add <contact> · remove <member> · leave · members · invite [copy] · join <link> · link reset · admin add|remove <member> · rename <name> · info · rejoin · forget";
        let Some(sub) = args.first().map(|s| s.to_ascii_lowercase()) else {
            self.toast(usage);
            return;
        };
        let rest = &args[1..];
        match sub.as_str() {
            "new" | "create" => self.group_new(&rest.join(" ")),
            "add" => self.group_add(rest),
            "remove" | "kick" => self.group_remove(rest),
            "leave" => self.group_leave(),
            "members" | "who" => self.group_members(),
            "invite" | "link"
                if rest
                    .first()
                    .is_some_and(|a| a.eq_ignore_ascii_case("reset")) =>
            {
                self.group_link_reset()
            }
            "invite" | "link" if rest.first().is_some_and(|a| a.eq_ignore_ascii_case("copy")) => {
                self.group_invite_copy()
            }
            "invite" | "link" => self.group_invite(),
            "join" => self.group_join(rest),
            "admin" => self.group_admin(rest),
            "rename" | "name" => self.group_rename(&rest.join(" ")),
            "info" => self.group_info(),
            "rejoin" | "resync" => self.group_rejoin(),
            "forget" => self.group_forget(),
            _ => self.toast(usage),
        }
    }

    /// The selected group, or a toast saying to select one.
    fn group_here(&mut self) -> Option<GroupId> {
        let group = self.selected_group();
        if group.is_none() {
            self.toast("Select a group first (or /group new <name> to make one).");
        }
        group
    }

    fn relay_serves_groups(&mut self) -> bool {
        if self.client.relay_supports(feature::GROUPS) {
            return true;
        }
        if self.connection != Connection::Connected {
            self.toast("Not connected; groups need the relay.");
        } else {
            self.system(
                Level::Warn,
                "This relay does not serve groups; it needs Silver Messenger 0.9.0 or later.",
            );
            self.toast("The relay is too old for groups; see System.");
        }
        false
    }

    fn group_new(&mut self, name: &str) {
        let name = name.trim();
        if name.is_empty() {
            self.toast("Usage: /group new <name>");
            return;
        }
        if !self.relay_serves_groups() {
            return;
        }
        match self.groups.create(name, now_ms()) {
            Ok(created) => {
                self.refresh_group_list();
                self.run_create(created);
            }
            Err(e) => self.toast(format!("Could not create the group: {e}")),
        }
    }

    /// A contact by alias, id or unique id prefix.
    fn resolve_contact(&self, who: &str) -> Option<usize> {
        let who = who.trim();
        if who.is_empty() {
            return None;
        }
        if let Some(i) = self.contacts.iter().position(|c| {
            c.alias
                .as_deref()
                .is_some_and(|a| a.eq_ignore_ascii_case(who))
        }) {
            return Some(i);
        }
        if let Ok(id) = who.parse::<UserId>() {
            return self.contact_index(&id);
        }
        let matches: Vec<usize> = self
            .contacts
            .iter()
            .enumerate()
            .filter(|(_, c)| c.user_id.to_string().starts_with(who))
            .map(|(i, _)| i)
            .collect();
        match matches.as_slice() {
            [one] => Some(*one),
            _ => None,
        }
    }

    /// A member of `group` by alias, id or unique id prefix.
    fn resolve_member(&self, group: &GroupId, who: &str) -> Option<UserId> {
        let record = self.groups.get(group)?;
        let who = who.trim();
        let by_alias = self
            .contacts
            .iter()
            .find(|c| {
                c.alias
                    .as_deref()
                    .is_some_and(|a| a.eq_ignore_ascii_case(who))
            })
            .map(|c| c.user_id)
            .filter(|id| record.members.iter().any(|m| m.user == *id));
        if by_alias.is_some() {
            return by_alias;
        }
        if let Ok(id) = who.parse::<UserId>() {
            return record.members.iter().find(|m| m.user == id).map(|m| m.user);
        }
        let matches: Vec<UserId> = record
            .members
            .iter()
            .filter(|m| m.user.to_string().starts_with(who))
            .map(|m| m.user)
            .collect();
        match matches.as_slice() {
            [one] => Some(*one),
            _ => None,
        }
    }

    fn group_add(&mut self, args: &[&str]) {
        let Some(group) = self.group_here() else {
            return;
        };
        if args.is_empty() {
            self.toast("Usage: /group add <contact alias or id>");
            return;
        }
        if !self.relay_serves_groups() {
            return;
        }
        let Some(index) = self.resolve_contact(&args.join(" ")) else {
            self.toast("No such contact; /add them first.");
            return;
        };
        let contact = &self.contacts[index];
        let name = contact.display_name();
        let user = contact.user_id;
        if contact.revoked {
            self.toast(format!("{name}'s identity is revoked."));
            return;
        }
        if !contact
            .bundle
            .as_ref()
            .is_some_and(|b| b.advertises(bundle_capability::GROUPS))
        {
            self.system(
                Level::Warn,
                format!(
                    "{name}'s client has not shown that it takes part in groups: it needs Silver Messenger 0.9.0 or later, and to have connected since updating. /refresh asks the relay again."
                ),
            );
            self.toast(format!("{name} cannot be added to groups yet; see System."));
            return;
        }
        if self.groups.has_staged(&group) {
            self.toast("A change to this group is on its way; try again in a moment.");
            return;
        }
        let client = self.client.clone();
        let tx = self.internal_tx.clone();
        self.toast(format!("Asking the relay for {name}'s key package…"));
        tokio::spawn(async move {
            let result = client
                .key_package_for(user)
                .await
                .map_err(|e| e.to_string());
            let _ = tx
                .send(Internal::KeyPackageFor {
                    group,
                    user,
                    result,
                })
                .await;
        });
    }

    pub(super) fn on_key_package_for(
        &mut self,
        group: GroupId,
        user: UserId,
        result: Result<Option<(KeyPackageDeposit, bool)>, String>,
    ) {
        let name = self.contact_name(&user);
        let package = match result {
            Ok(Some((package, _))) => package,
            Ok(None) => {
                self.toast(format!(
                    "{name} has no key package on the relay; they need to connect once with a client that takes part in groups."
                ));
                return;
            }
            Err(e) => {
                self.toast(format!("Could not get {name}'s key package: {e}"));
                return;
            }
        };
        let verified = match self
            .groups
            .verify_key_package(&user, &package.data, now_ms())
        {
            Ok(bytes) => bytes,
            Err(e) => {
                self.system(
                    Level::Warn,
                    format!(
                        "The relay handed out a key package for {name} that does not check out ({e}); nobody was added."
                    ),
                );
                self.toast(format!("{name}'s key package is not valid; see System."));
                return;
            }
        };
        match self.groups.stage_add(&group, &[verified]) {
            Ok(staged) => self.run_staged(staged, Purpose::Add(vec![user])),
            Err(e) => self.toast(format!("Could not add {name}: {e}")),
        }
    }

    fn group_remove(&mut self, args: &[&str]) {
        let Some(group) = self.group_here() else {
            return;
        };
        if args.is_empty() {
            self.toast("Usage: /group remove <member>");
            return;
        }
        let Some(user) = self.resolve_member(&group, &args.join(" ")) else {
            self.toast("No such member; /group members lists them.");
            return;
        };
        match self.groups.stage_remove(&group, &[user]) {
            Ok(staged) => self.run_staged(staged, Purpose::Remove(vec![user])),
            Err(e) => self.toast(format!("Could not remove {}: {e}", self.member_name(&user))),
        }
    }

    fn group_leave(&mut self) {
        let Some(group) = self.group_here() else {
            return;
        };
        let name = self.group_name(&group);
        match self.groups.leave(&group) {
            Ok(outgoing) => {
                self.note_in_group(
                    group,
                    "you left; an admin's next change takes you out of the tree",
                );
                self.fan_out(group, outgoing, None, None);
                self.toast(format!(
                    "Left {name}. /group forget removes it from the list."
                ));
            }
            Err(e) => self.toast(format!("Could not leave: {e}")),
        }
    }

    fn group_members(&mut self) {
        let Some(group) = self.group_here() else {
            return;
        };
        let Some(record) = self.groups.get(&group).cloned() else {
            return;
        };
        let name = self.group_name(&group);
        self.system(
            Level::Info,
            format!("{name}: {} member(s)", record.members.len()),
        );
        for member in &record.members {
            let who = self.member_name(&member.user);
            let verified = self
                .contact_index(&member.user)
                .is_some_and(|i| self.contacts[i].verified);
            let mut notes = Vec::new();
            if member.admin {
                notes.push("admin");
            }
            if verified {
                notes.push("verified");
            }
            let notes = if notes.is_empty() {
                String::new()
            } else {
                format!(" ({})", notes.join(", "))
            };
            self.system(Level::Info, format!("  {who}{notes}  {}", member.user));
        }
        self.select(0);
    }

    fn group_invite(&mut self) {
        let Some(group) = self.group_here() else {
            return;
        };
        match self
            .groups
            .invite_link(&group, Some(self.relay_url.clone()))
        {
            Ok(link) => {
                let text = link.to_string();
                let name = self.group_name(&group);
                self.system(
                    Level::Info,
                    format!("Invite link for {name} (anyone with it can ask you to add them; /group link reset voids it): {text}"),
                );
                match crate::qr::render(&text) {
                    Ok(rows) => {
                        for row in rows {
                            self.system(Level::Code, row);
                        }
                    }
                    Err(e) => self.system(Level::Warn, format!("No QR code: {e}")),
                }
                self.select(0);
            }
            Err(GroupError::NotAdmin) => self.toast("Only an admin can make an invite link."),
            Err(e) => self.toast(format!("No link: {e}")),
        }
    }

    /// `/group invite copy`: the link on the clipboard instead of the screen.
    fn group_invite_copy(&mut self) {
        let Some(group) = self.group_here() else {
            return;
        };
        match self
            .groups
            .invite_link(&group, Some(self.relay_url.clone()))
        {
            Ok(link) => {
                let name = self.group_name(&group);
                self.copy_text(&link.to_string(), &format!("the invite link for {name}"));
            }
            Err(GroupError::NotAdmin) => self.toast("Only an admin can make an invite link."),
            Err(e) => self.toast(format!("No link: {e}")),
        }
    }

    fn group_link_reset(&mut self) {
        let Some(group) = self.group_here() else {
            return;
        };
        match self.groups.stage_link_reset(&group) {
            Ok(staged) => self.run_staged(staged, Purpose::LinkReset),
            Err(e) => self.toast(format!("Could not reset the link: {e}")),
        }
    }

    fn group_join(&mut self, args: &[&str]) {
        let Some(text) = args.first() else {
            self.toast("Usage: /group join <link>");
            return;
        };
        let link: GroupLink = match text.parse() {
            Ok(link) => link,
            Err(e) => {
                self.toast(format!("Not a group link: {e}"));
                return;
            }
        };
        if !self.relay_serves_groups() {
            return;
        }
        if self.groups.get(&link.group).is_some() {
            self.toast("You are in this group already (or were; /group forget it first).");
            return;
        }
        if let Some(relay) = &link.relay
            && silver_protocol::wire::url_host(relay)
                != silver_protocol::wire::url_host(&self.relay_url)
        {
            self.system(
                Level::Warn,
                format!("The link names another relay ({relay}). Relays do not talk to each other, so the admin has to be on yours."),
            );
        }
        let via = link.via;
        let client = self.client.clone();
        let tx = self.internal_tx.clone();
        self.toast("Looking the admin up…");
        tokio::spawn(async move {
            let result = client.lookup(via).await.map_err(|e| e.to_string());
            let _ = tx.send(Internal::GroupJoinLookup { link, result }).await;
        });
    }

    pub(super) fn on_group_join_lookup(
        &mut self,
        link: GroupLink,
        result: Result<Option<KeyBundle>, String>,
    ) {
        let bundle = match result {
            Ok(Some(bundle)) => bundle,
            Ok(None) => {
                self.toast("The admin the link names has no key on this relay.");
                return;
            }
            Err(e) => {
                self.toast(format!("Could not look the admin up: {e}"));
                return;
            }
        };
        match self
            .groups
            .join_request(&link, (link.via, bundle.dh_public), now_ms())
        {
            Ok(outgoing) => {
                self.fan_out(link.group, outgoing, None, None);
                self.system(
                    Level::Info,
                    format!(
                        "Asked {} to add you to the group; their client answers when it is running.",
                        self.contact_name(&link.via)
                    ),
                );
                self.toast("Join request sent.");
            }
            Err(e) => self.toast(format!("Could not ask to join: {e}")),
        }
    }

    fn group_admin(&mut self, args: &[&str]) {
        let Some(group) = self.group_here() else {
            return;
        };
        let (admin, who) = match args {
            [verb, who @ ..] if !who.is_empty() && verb.eq_ignore_ascii_case("add") => {
                (true, who.join(" "))
            }
            [verb, who @ ..] if !who.is_empty() && verb.eq_ignore_ascii_case("remove") => {
                (false, who.join(" "))
            }
            _ => {
                self.toast("Usage: /group admin add|remove <member>");
                return;
            }
        };
        let Some(user) = self.resolve_member(&group, &who) else {
            self.toast("No such member; /group members lists them.");
            return;
        };
        match self.groups.stage_admin(&group, user, admin) {
            Ok(staged) => self.run_staged(staged, Purpose::Admin { user, admin }),
            Err(e) => self.toast(format!("Could not change admins: {e}")),
        }
    }

    fn group_rename(&mut self, name: &str) {
        let Some(group) = self.group_here() else {
            return;
        };
        let name = name.trim();
        if name.is_empty() {
            self.toast("Usage: /group rename <name>");
            return;
        }
        match self.groups.stage_rename(&group, name) {
            Ok(staged) => self.run_staged(staged, Purpose::Rename(name.to_owned())),
            Err(e) => self.toast(format!("Could not rename: {e}")),
        }
    }

    fn group_info(&mut self) {
        let Some(group) = self.group_here() else {
            return;
        };
        let Some(record) = self.groups.get(&group).cloned() else {
            return;
        };
        let name = self.group_name(&group);
        let state = self.group_state_label(&group).unwrap_or("active");
        let admins: Vec<String> = record
            .admins()
            .iter()
            .map(|a| self.member_name(a))
            .collect();
        self.system(
            Level::Info,
            format!(
                "{name}: id {group}, {} member(s), admin(s) {}, {state}. Messages are encrypted with MLS on the ML-KEM-768 + X25519 hybrid suite; every member's client checks every change against the group's rules.",
                record.members.len(),
                admins.join(", ")
            ),
        );
        self.select(0);
    }

    fn group_rejoin(&mut self) {
        let Some(group) = self.group_here() else {
            return;
        };
        match self.groups.rejoin_request(&group, now_ms()) {
            Ok(outgoing) => {
                self.note_in_group(group, "asked the admins to remove and re-add you");
                self.fan_out(group, outgoing, None, None);
            }
            Err(e) => self.toast(format!("Could not ask to rejoin: {e}")),
        }
    }

    fn group_forget(&mut self) {
        let Some(group) = self.group_here() else {
            return;
        };
        let name = self.group_name(&group);
        match self.groups.forget(&group) {
            Ok(()) => {
                self.group_threads.remove(&group);
                self.group_unread.remove(&group);
                self.refresh_group_list();
                self.select(0);
                self.toast(format!("Forgot {name}; its history stays on disk."));
            }
            Err(e) => self.toast(format!("Cannot forget it: {e}")),
        }
    }

    /// `/accept g<n>`: say yes to an invitation.
    pub(super) fn accept_invitation(&mut self, n: usize) {
        let invitations = self.invitations();
        let Some(held) = n.checked_sub(1).and_then(|i| invitations.get(i)).cloned() else {
            self.toast("No such invitation; the Requests pane numbers them g1, g2…");
            return;
        };
        match self.groups.accept_welcome(&held.group) {
            Ok(()) => {
                self.refresh_group_list();
                self.note_in_group(
                    held.group,
                    &format!("{} added you", self.member_name(&held.from)),
                );
                if let Some(pane) = self.group_pane(&held.group) {
                    self.select(pane);
                }
                self.system(
                    Level::Info,
                    format!("Joined {} ({} members).", held.name, held.members.len()),
                );
            }
            Err(e) => self.toast(format!("Could not join: {e}")),
        }
    }

    pub(super) fn cmd_decline(&mut self, args: &[&str]) {
        let Some(n) = args
            .first()
            .and_then(|a| a.trim_start_matches(['g', 'G']).parse::<usize>().ok())
        else {
            self.toast("Usage: /decline g<n> (see the Requests pane)");
            return;
        };
        let invitations = self.invitations();
        let Some(held) = n.checked_sub(1).and_then(|i| invitations.get(i)).cloned() else {
            self.toast("No such invitation; the Requests pane numbers them g1, g2…");
            return;
        };
        match self.groups.decline_welcome(&held.group) {
            Ok(()) => {
                self.refresh_group_list();
                self.toast(format!("Declined {}.", held.name));
            }
            Err(e) => self.toast(format!("Could not decline: {e}")),
        }
    }

    // --- flows ---------------------------------------------------------------

    fn run_create(&mut self, created: Created) {
        let client = self.client.clone();
        let tx = self.internal_tx.clone();
        tokio::spawn(async move {
            let answer = client
                .group_create(created)
                .await
                .map_err(|e| e.to_string());
            let _ = tx
                .send(Internal::GroupSequenced {
                    group: created.group,
                    purpose: Purpose::Create,
                    answer,
                })
                .await;
        });
    }

    fn run_staged(&mut self, staged: Staged, purpose: Purpose) {
        let client = self.client.clone();
        let tx = self.internal_tx.clone();
        tokio::spawn(async move {
            let answer = client.group_commit(staged).await.map_err(|e| e.to_string());
            let _ = tx
                .send(Internal::GroupSequenced {
                    group: staged.group,
                    purpose,
                    answer,
                })
                .await;
        });
    }

    /// Upload what needs uploading, then queue every envelope; the outcome
    /// comes back as [`Internal::GroupSent`].
    fn fan_out(
        &mut self,
        group: GroupId,
        outgoing: Outgoing,
        id: Option<String>,
        text: Option<String>,
    ) {
        let envelope_ids: Vec<String> = outgoing.envelopes.iter().map(|e| e.id.clone()).collect();
        if let Some(message) = &id {
            for envelope in &envelope_ids {
                self.group_envelopes
                    .insert(envelope.clone(), (group, message.clone()));
            }
            self.group_outstanding
                .insert(message.clone(), envelope_ids.len());
        }
        let client = self.client.clone();
        let tx = self.internal_tx.clone();
        tokio::spawn(async move {
            let mut result: Result<(), ClientError> = Ok(());
            for upload in outgoing.uploads {
                if let Err(e) = client.upload_chunks(upload.blob, upload.chunks).await {
                    result = Err(e);
                    break;
                }
            }
            if result.is_ok() {
                for envelope in outgoing.envelopes {
                    if let Err(e) = client.submit_envelope(envelope).await {
                        result = Err(e);
                        break;
                    }
                }
            }
            let _ = tx
                .send(Internal::GroupSent {
                    group,
                    id,
                    text,
                    result: result.map_err(|e| e.to_string()),
                })
                .await;
        });
    }

    pub(super) fn on_group_sequenced(
        &mut self,
        group: GroupId,
        purpose: Purpose,
        answer: Result<SequencerAnswer, String>,
    ) {
        let name = self.group_name(&group);
        match (purpose, answer) {
            (Purpose::Create, Ok(SequencerAnswer::Stands(_))) => {
                if let Some(pane) = self.group_pane(&group) {
                    self.select(pane);
                }
                self.system(
                    Level::Info,
                    format!(
                        "Created {name}. /group add <contact> adds people, /group invite makes a link."
                    ),
                );
                self.toast(format!("Created {name}."));
            }
            (Purpose::Create, answer) => {
                let _ = self.groups.abandon(&group);
                self.group_threads.remove(&group);
                self.refresh_group_list();
                self.toast(format!(
                    "The relay refused the group: {}",
                    describe_answer(&answer)
                ));
            }
            (purpose, Ok(SequencerAnswer::Stands(_))) => match self
                .groups
                .commit_staged(&group, now_ms())
            {
                Ok(outgoing) => {
                    let note = match &purpose {
                        Purpose::Add(users) => format!("you added {}", self.names(users)),
                        Purpose::Join(user) => format!("{} joined by link", self.member_name(user)),
                        Purpose::Remove(users) => format!("you removed {}", self.names(users)),
                        Purpose::Rename(new) => format!("you renamed the group to {new}"),
                        Purpose::Admin { user, admin: true } => {
                            format!("you made {} an admin", self.member_name(user))
                        }
                        Purpose::Admin { user, admin: false } => {
                            format!("{} is no longer an admin", self.member_name(user))
                        }
                        Purpose::LinkReset => {
                            "you reset the invite link; old links are void".into()
                        }
                        Purpose::Refresh => String::new(),
                        Purpose::Rejoin(user) => format!("you re-added {}", self.member_name(user)),
                        Purpose::Create => unreachable!("handled above"),
                    };
                    if !note.is_empty() {
                        self.note_in_group(group, &note);
                    }
                    if let Purpose::LinkReset = purpose {
                        self.group_invite_after_reset(group);
                    }
                    self.fan_out(group, outgoing, None, None);
                }
                Err(e) => self.toast(format!("Could not apply the change to {name}: {e}")),
            },
            (purpose, answer) => {
                let _ = self.groups.discard_staged(&group);
                let what = match &purpose {
                    Purpose::Refresh => return, // quiet; tried again later
                    Purpose::Join(user) | Purpose::Rejoin(user) => {
                        format!("adding {}", self.member_name(user))
                    }
                    _ => "the change".to_owned(),
                };
                self.toast(format!(
                    "{name}: {what} did not go through ({}); the group moved on, try again.",
                    describe_answer(&answer)
                ));
            }
        }
    }

    fn group_invite_after_reset(&mut self, group: GroupId) {
        if let Ok(link) = self
            .groups
            .invite_link(&group, Some(self.relay_url.clone()))
        {
            self.system(Level::Info, format!("The new invite link: {link}"));
        }
    }

    fn names(&self, users: &[UserId]) -> String {
        users
            .iter()
            .map(|u| self.member_name(u))
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub(super) fn on_group_sent(
        &mut self,
        group: GroupId,
        id: Option<String>,
        text: Option<String>,
        result: Result<(), String>,
    ) {
        match result {
            Ok(()) => {
                if let (Some(id), Some(text)) = (id, text) {
                    let delivered = self.group_outstanding.get(&id).is_none_or(|n| *n == 0);
                    self.record_group(
                        group,
                        ChatLine {
                            id,
                            direction: Direction::Sent,
                            timestamp_ms: now_ms(),
                            text,
                            delivered,
                            failed: false,
                            receipt: None,
                            file: None,
                            pending: None,
                            sender: None,
                        },
                    );
                    self.scroll = 0;
                }
            }
            Err(e) => {
                let name = self.group_name(&group);
                self.toast(format!("Not sent to {name}: {e}"));
                self.system(Level::Warn, format!("Message to {name} not sent: {e}"));
            }
        }
    }

    /// One envelope of a group message was accepted by the relay.
    pub(super) fn on_group_envelope_done(&mut self, envelope_id: &str, accepted: bool) -> bool {
        let Some((group, message)) = self.group_envelopes.remove(envelope_id) else {
            return false;
        };
        let done = match self.group_outstanding.get_mut(&message) {
            Some(n) => {
                *n = n.saturating_sub(1);
                *n == 0
            }
            None => true,
        };
        if !accepted {
            let name = self.group_name(&group);
            self.system(
                Level::Warn,
                format!("One member of {name} could not be reached by the relay; the others got the message."),
            );
        }
        if done {
            self.group_outstanding.remove(&message);
            if let Some(line) = self.group_line_mut(&group, &message) {
                line.delivered = true;
            }
        }
        true
    }

    // --- sending -------------------------------------------------------------

    pub(super) fn send_group_text(&mut self, group: GroupId, text: String) {
        self.send_group_content(group, Content::Text { body: text.clone() }, text);
    }

    fn send_group_content(&mut self, group: GroupId, content: Content, shown: String) {
        let head = self.client.gossip_head();
        match self.groups.send(&group, content, head, now_ms()) {
            Ok(outgoing) => {
                let id = outgoing.id.clone();
                self.group_new_marker = None;
                self.fan_out(group, outgoing, id, Some(shown));
            }
            Err(e) => {
                let name = self.group_name(&group);
                self.toast(format!("Not sent to {name}: {e}"));
            }
        }
    }

    /// `/send <path>` in a group pane.
    pub(super) fn send_group_file(&mut self, group: GroupId, args: &[&str]) {
        if args.is_empty() {
            self.toast("Usage: /send <path to file>");
            return;
        }
        if !self.client.relay_supports(feature::BLOBS) {
            self.toast("The relay does not store files.");
            return;
        }
        if self
            .groups
            .get(&group)
            .is_none_or(|r| r.state != GroupState::Active)
        {
            self.toast("This group is not active.");
            return;
        }
        let path = commands::expand_home(&args.join(" "));
        let client = self.client.clone();
        let tx = self.internal_tx.clone();
        let (ptx, prx) = mpsc::channel::<Progress>(16);
        self.toast(format!("Sending {}…", path.display()));
        tokio::spawn(async move {
            let result = with_progress(
                &tx,
                prx,
                &format!("Sending {}", path.display()),
                client.upload_file(&path, true, Some(ptx)),
            )
            .await
            .map_err(|e| e.to_string());
            let _ = tx.send(Internal::GroupUploaded { group, result }).await;
        });
    }

    pub(super) fn on_group_uploaded(&mut self, group: GroupId, result: Result<FileInfo, String>) {
        match result {
            Ok(info) => {
                let shown = format!("[file] {}", info.label());
                self.send_group_content(group, info.into_content(), shown);
            }
            Err(e) => self.toast(format!("File not sent: {e}")),
        }
    }

    /// `/get [all]` in a group pane.
    pub(super) fn group_get(&mut self, group: GroupId, all: bool) {
        let waiting: Vec<(String, FileInfo)> = self
            .group_threads
            .get(&group)
            .map(|lines| {
                lines
                    .iter()
                    .rev()
                    .filter_map(|l| l.pending.clone().map(|p| (l.id.clone(), p)))
                    .collect()
            })
            .unwrap_or_default();
        if waiting.is_empty() {
            self.toast("No file is waiting in this group.");
            return;
        }
        let chosen = if all { waiting.len() } else { 1 };
        for (id, info) in waiting.into_iter().take(chosen) {
            self.start_group_download(group, id, info);
        }
    }

    fn start_group_download(&mut self, group: GroupId, id: String, info: FileInfo) {
        let label = info.label();
        if let Some(line) = self.group_line_mut(&group, &id) {
            line.pending = None;
            line.text = format!("[file] {label} · receiving…");
        }
        let client = self.client.clone();
        let tx = self.internal_tx.clone();
        let dir = self.store.downloads_dir();
        let quota = self.downloads_quota;
        let (ptx, prx) = mpsc::channel::<Progress>(16);
        tokio::spawn(async move {
            let result = with_progress(
                &tx,
                prx,
                &format!("Receiving {label}"),
                client.download_file(&info, &dir, quota, Some(ptx)),
            )
            .await
            .map_err(|e| e.to_string());
            let _ = tx
                .send(Internal::GroupDownloaded {
                    group,
                    id,
                    info,
                    result,
                })
                .await;
        });
    }

    pub(super) fn on_group_downloaded(
        &mut self,
        group: GroupId,
        id: String,
        info: FileInfo,
        result: Result<PathBuf, String>,
    ) {
        let label = info.label();
        let text = match &result {
            Ok(path) => format!("[file] {label} {} {}", self.glyphs.arrow, path.display()),
            Err(e) => format!(
                "[file] {label} {} {e} · /get tries again",
                self.glyphs.failed
            ),
        };
        if let Some(line) = self.group_line_mut(&group, &id) {
            line.text = text.clone();
            match &result {
                Ok(path) => {
                    line.file = Some(path.clone());
                    line.pending = None;
                }
                Err(_) => line.pending = Some(info),
            }
        }
        if let Err(e) = self.store.append_group_text(&group, &id, &text) {
            self.toast(format!("Could not save history: {e}"));
        }
        match result {
            Ok(path) => self.toast(format!("Saved {}. /open opens it.", path.display())),
            Err(e) => self.toast(format!("Could not fetch {label}: {e}")),
        }
    }

    // --- receiving -----------------------------------------------------------

    /// A group body arrived (as [`ClientEvent::Group`]).
    pub(super) fn on_group_body(&mut self, from: UserId, id: String, body: Box<GroupBody>) {
        if self.known_ids.contains(&id) {
            return; // re-delivered
        }
        self.known_ids.insert(id);
        match (&body.mls, &body.blob) {
            (Some(mls), _) => {
                let mls = mls.clone();
                self.take_group_message(from, &body, &mls);
            }
            (None, Some(reference)) => {
                let client = self.client.clone();
                let tx = self.internal_tx.clone();
                let reference = reference.clone();
                tokio::spawn(async move {
                    let chunks = client
                        .download_chunks(reference.blob.clone(), reference.chunks)
                        .await
                        .map_err(|e| e.to_string());
                    let _ = tx.send(Internal::GroupParked { from, body, chunks }).await;
                });
            }
            _ => {}
        }
    }

    pub(super) fn on_group_parked(
        &mut self,
        from: UserId,
        body: Box<GroupBody>,
        chunks: Result<Vec<Vec<u8>>, String>,
    ) {
        let Some(reference) = &body.blob else {
            return;
        };
        let opened: Result<Vec<u8>, GroupError> = match chunks {
            Ok(chunks) => Groups::open_parked(reference, &chunks),
            Err(e) => Err(GroupError::Mls(e)),
        };
        let mls = match opened {
            Ok(mls) => mls,
            Err(e) => {
                let name = self.group_name(&body.group);
                self.system(
                    Level::Warn,
                    format!("A large message for {name} could not be fetched from the relay: {e}"),
                );
                return;
            }
        };
        self.take_group_message(from, &body, &mls);
    }

    fn take_group_message(&mut self, from: UserId, body: &GroupBody, mls: &[u8]) {
        match self.groups.receive(from, body, mls, now_ms()) {
            Ok(events) => self.apply_group_events(events),
            Err(e) => {
                let name = self.group_name(&body.group);
                self.system(
                    Level::Warn,
                    format!("A group message for {name} could not be handled: {e}"),
                );
            }
        }
    }

    fn apply_group_events(&mut self, events: Vec<GroupEvent>) {
        for event in events {
            match event {
                GroupEvent::Message {
                    group,
                    from,
                    id,
                    sent_at_ms,
                    content,
                } => {
                    if self.blocked.contains(&from) {
                        continue;
                    }
                    if !self.group_list.contains(&group) {
                        continue; // an invitation not accepted yet
                    }
                    let (text, pending) = match content {
                        Content::Text { body } => (body, None),
                        Content::File { .. } => {
                            let info = FileInfo::from_content(&content).expect("file content");
                            match info.check() {
                                Ok(()) => (
                                    format!("[file] {} · /get to fetch", info.label()),
                                    Some(info),
                                ),
                                Err(e) => (format!("[file] {} · refused: {e}", info.label()), None),
                            }
                        }
                        _ => continue,
                    };
                    let name = self.member_name(&from);
                    let group_name = self.group_name(&group);
                    let shown = self.selected_group() == Some(group) && self.focused;
                    self.record_group(
                        group,
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
                            sender: Some(from),
                        },
                    );
                    if !shown {
                        self.notifier
                            .announce(&format!("New message from {name} in {group_name}"));
                        self.group_unread.entry(group).or_default().push(id);
                    }
                }
                GroupEvent::Head { from, head } => {
                    let client = self.client.clone();
                    tokio::spawn(async move {
                        let _ = client.note_peer_head(from, head).await;
                    });
                }
                GroupEvent::Changed { group, by, change } => {
                    let text = self.describe_change(&by, &change);
                    self.note_in_group(group, &text);
                }
                GroupEvent::Joined { group } => {
                    self.refresh_group_list();
                    self.note_in_group(group, "you joined by the link");
                    let name = self.group_name(&group);
                    let members = self.groups.get(&group).map_or(0, |r| r.members.len());
                    self.system(Level::Info, format!("Joined {name} ({members} members)."));
                    self.notifier.announce(&format!("Joined {name}"));
                    self.group_unread
                        .entry(group)
                        .or_default()
                        .push(String::new());
                }
                GroupEvent::Invited { held } => {
                    let inviter = self.member_name(&held.from);
                    let trusted = self.contact_index(&held.from).is_some()
                        && !self.blocked.contains(&held.from);
                    if trusted {
                        match self.groups.accept_welcome(&held.group) {
                            Ok(()) => {
                                self.refresh_group_list();
                                self.note_in_group(held.group, &format!("{inviter} added you"));
                                self.system(
                                    Level::Info,
                                    format!(
                                        "{inviter} added you to the group {} ({} members).",
                                        held.name,
                                        held.members.len()
                                    ),
                                );
                                self.notifier
                                    .announce(&format!("{inviter} added you to {}", held.name));
                                self.group_unread
                                    .entry(held.group)
                                    .or_default()
                                    .push(String::new());
                            }
                            Err(e) => self.toast(format!("Could not join {}: {e}", held.name)),
                        }
                    } else if self.blocked.contains(&held.from) {
                        let _ = self.groups.decline_welcome(&held.group);
                    } else {
                        self.system(
                            Level::Info,
                            format!(
                                "{inviter} ({}) invites you to the group {} ({} members); the Requests pane has it (/accept g1 or /decline g1).",
                                held.from, held.name, held.members.len()
                            ),
                        );
                        self.notifier.announce(&format!("Invited to {}", held.name));
                    }
                }
                GroupEvent::Removed { group, by } => {
                    let text = format!("{} removed you", self.member_name(&by));
                    self.note_in_group(group, &text);
                    let name = self.group_name(&group);
                    self.system(Level::Info, format!("You were removed from {name}."));
                }
                GroupEvent::Broken { group, by, reason } => {
                    let who = self.member_name(&by);
                    self.note_in_group(group, &format!("broken: {reason}; nothing is sent or read until an admin makes the group anew"));
                    let name = self.group_name(&group);
                    self.system(
                        Level::Warn,
                        format!("{name} is broken: {who}'s client sent a change that breaks the group's rules ({reason}). The honest members stopped at the same point; an admin has to make the group anew and add everyone but {who}."),
                    );
                    self.toast(format!("{name} is broken; see System."));
                }
                GroupEvent::JoinRequest {
                    group,
                    joiner,
                    key_package,
                } => {
                    if self.blocked.contains(&joiner) {
                        continue;
                    }
                    if self.groups.has_staged(&group) {
                        self.toast(format!(
                            "{} asked to join {} while a change was on its way; they will have to ask again.",
                            self.member_name(&joiner),
                            self.group_name(&group)
                        ));
                        continue;
                    }
                    match self.groups.stage_add(&group, &[key_package]) {
                        Ok(staged) => self.run_staged(staged, Purpose::Join(joiner)),
                        Err(e) => {
                            self.toast(format!("Could not add {}: {e}", self.member_name(&joiner)))
                        }
                    }
                }
                GroupEvent::RejoinRequest {
                    group,
                    member,
                    key_package,
                } => {
                    if self.groups.has_staged(&group) {
                        continue;
                    }
                    match self.groups.stage_rejoin(&group, member, &key_package) {
                        Ok(staged) => self.run_staged(staged, Purpose::Rejoin(member)),
                        Err(e) => self.toast(format!(
                            "Could not re-add {}: {e}",
                            self.member_name(&member)
                        )),
                    }
                }
                GroupEvent::OutOfSync { group } => {
                    self.note_in_group(
                        group,
                        "out of sync: a change was missed; asking the admins to re-add you",
                    );
                    match self.groups.rejoin_request(&group, now_ms()) {
                        Ok(outgoing) => self.fan_out(group, outgoing, None, None),
                        Err(e) => self.toast(format!("Could not ask to rejoin: {e}")),
                    }
                }
                GroupEvent::Refused { group, reason } => {
                    let name = self.group_name(&group);
                    self.system(Level::Warn, format!("{name}: {reason}"));
                }
            }
        }
    }

    fn describe_change(&self, by: &UserId, change: &Change) -> String {
        let who = self.member_name(by);
        match change {
            Change::Added(users) => format!("{who} added {}", self.names(users)),
            Change::Removed(users) => format!("{who} removed {}", self.names(users)),
            Change::Left(users) => format!("{} left", self.names(users)),
            Change::Renamed(name) => format!("{who} renamed the group to {name}"),
            Change::Admins(admins) => format!("{who} set the admins to {}", self.names(admins)),
            Change::LinkReset => format!("{who} reset the invite link"),
            Change::Updated => format!("{who} refreshed their keys"),
        }
    }

    /// A note in a group's conversation about the group itself.
    fn note_in_group(&mut self, group: GroupId, text: &str) {
        self.record_group(
            group,
            ChatLine {
                id: uuid::Uuid::new_v4().to_string(),
                direction: Direction::Received,
                timestamp_ms: now_ms(),
                text: format!("· {text}"),
                delivered: true,
                failed: false,
                receipt: None,
                file: None,
                pending: None,
                sender: None,
            },
        );
    }

    fn record_group(&mut self, group: GroupId, line: ChatLine) {
        let entry = HistoryEntry {
            id: line.id.clone(),
            direction: line.direction,
            timestamp_ms: line.timestamp_ms,
            text: line.text.clone(),
            receipt: None,
            file: line.pending.clone(),
            from: line.sender,
        };
        if let Err(e) = self.store.append_group_history(&group, &entry) {
            self.toast(format!("Could not save history: {e}"));
        }
        self.known_ids.insert(line.id.clone());
        self.group_threads.entry(group).or_default().push(line);
    }

    pub(super) fn group_line_mut(&mut self, group: &GroupId, id: &str) -> Option<&mut ChatLine> {
        self.group_threads
            .get_mut(group)
            .and_then(|lines| lines.iter_mut().rev().find(|l| l.id == id))
    }

    // --- upkeep --------------------------------------------------------------

    /// Put key packages on deposit (after connecting, and again when the
    /// relay said they ran low).
    pub(super) fn deposit_key_packages(&mut self) {
        if !self.client.relay_supports(feature::GROUPS) {
            return;
        }
        self.key_packages_due = None;
        let (packages, last_resort) = match self.groups.deposit(now_ms()) {
            Ok(deposit) => deposit,
            Err(e) => {
                self.system(Level::Warn, format!("Could not make key packages: {e}"));
                return;
            }
        };
        let client = self.client.clone();
        let tx = self.internal_tx.clone();
        tokio::spawn(async move {
            let result = client
                .deposit_key_packages(packages, last_resort)
                .await
                .map_err(|e| e.to_string());
            let _ = tx.send(Internal::KeyPackages { result }).await;
        });
    }

    pub(super) fn on_key_packages(&mut self, result: Result<KeyPackageStatus, String>) {
        match result {
            Ok(status) => match self.groups.apply_status(&status.consumed) {
                Ok(true) => self.key_packages_due = Some(Instant::now() + REDEPOSIT_AFTER),
                Ok(false) => {}
                Err(e) => self.toast(format!("Could not record key packages: {e}")),
            },
            Err(e) => {
                tracing::warn!("key package deposit refused: {e}");
                self.key_packages_due = Some(Instant::now() + REDEPOSIT_AFTER);
            }
        }
    }

    /// Once a tick: a deposit that fell due, and one self-update that is.
    pub(super) fn maintain_groups(&mut self) {
        if self.connection != Connection::Connected {
            return;
        }
        if self.key_packages_due.is_some_and(|at| Instant::now() >= at) {
            self.deposit_key_packages();
        }
        if self.last_group_maintenance.elapsed() < MAINTENANCE_EVERY {
            return;
        }
        self.last_group_maintenance = Instant::now();
        let due = self.groups.self_updates_due(now_ms());
        if let Some(group) = due.into_iter().find(|g| !self.groups.has_staged(g)) {
            if let Ok(staged) = self.groups.stage_self_update(&group) {
                self.run_staged(staged, Purpose::Refresh);
            }
        }
    }
}

fn describe_answer(answer: &Result<SequencerAnswer, String>) -> String {
    match answer {
        Ok(SequencerAnswer::Stands(e)) => format!("it stands at epoch {e}"),
        Ok(SequencerAnswer::Stale(e)) => format!("the relay has it at epoch {e}"),
        Ok(SequencerAnswer::Exists(e)) => format!("the relay knows it at epoch {e}"),
        Ok(SequencerAnswer::NotFound) => "the relay does not know the group".into(),
        Ok(SequencerAnswer::Forbidden) => "the relay refused".into(),
        Ok(SequencerAnswer::RateLimited) => "too many changes at once".into(),
        Ok(SequencerAnswer::Other(what)) => what.clone(),
        Err(e) => e.clone(),
    }
}
