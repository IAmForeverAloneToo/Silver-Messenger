//! `silver --link`: make this data directory a device of an identity kept
//! on another computer (`docs/design/devices.md` section 7.1).
//!
//! The device registers with the relay, prints a link and a QR code of
//! it, and waits for the primary to take the link in (`/devices link`).
//! Once the provisioning message is here the device is linked, fetches
//! the snapshot with the contacts and history, and exits; `silver` then
//! starts as that device.

use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use silver_client::linking::LINK_LIFETIME;
use silver_client::{
    Client, ClientEvent, ConnectOptions, DeviceLink, ExpectedGroup, Groups, LinkError, Store,
    fetch_snapshot, take_link,
};
use silver_protocol::Identity;
use tokio::sync::mpsc;

use crate::qr;

/// How long the relay gets to take this device's bundle before the link
/// can be printed.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

pub async fn run(
    store: Store,
    identity: Identity,
    relay_url: String,
    options: ConnectOptions,
    name: Option<String>,
) -> anyhow::Result<()> {
    if !store.is_unused()? {
        bail!(
            "this data directory is in use (it has contacts, history or a link already); \
             a device starts from an empty one: pass --data-dir with a new directory"
        );
    }
    let identity = Arc::new(identity);
    let (client, mut events) = Client::spawn(relay_url.clone(), identity.clone(), options)?;
    println!("Registering this device with {relay_url}…");
    if let Err(e) = connected(&mut events).await {
        client.shutdown().await;
        return Err(e);
    }
    let link = DeviceLink::new(identity.user_id(), relay_url, name);
    let text = link.to_string();
    println!();
    println!("On the device that holds your identity, run");
    println!();
    println!("  /devices link {text}");
    println!();
    println!("or scan this code with it:");
    println!();
    match qr::render(&text) {
        Ok(rows) => {
            for row in rows {
                println!("  {row}");
            }
        }
        Err(e) => println!("  (the QR code could not be drawn: {e})"),
    }
    println!();
    println!(
        "The link is good for ten minutes and one use; it is the key to this device, so hand it \
         to your own primary alone."
    );
    println!("Waiting for the primary…");
    let deadline = tokio::time::Instant::now() + LINK_LIFETIME;
    let taken = match take_link(&client, &mut events, &link, deadline).await {
        Ok(taken) => taken,
        Err(LinkError::Expired) => {
            client.shutdown().await;
            bail!(
                "no answer within ten minutes; the link is void. Run silver --link again for a \
                 new one."
            );
        }
        Err(e) => {
            client.shutdown().await;
            return Err(e.into());
        }
    };
    println!(
        "Linked: this is the device \"{}\" of {} from now on.",
        silver_client::files::printable(&taken.certificate.name, 40),
        taken.account
    );
    match taken.snapshot {
        Some(info) => match fetch_snapshot(&client, &info).await {
            Ok(snapshot) => {
                let imported = snapshot.import(&store)?;
                if !snapshot.groups.is_empty() {
                    Groups::load(&store, identity.clone())?.expect_groups(
                        snapshot.groups.iter().map(|g| {
                            (
                                g.id,
                                ExpectedGroup {
                                    name: g.name.clone(),
                                    alias: g.alias.clone(),
                                },
                            )
                        }),
                    )?;
                }
                println!(
                    "{} contact(s), {} group(s) and {} message(s) of history came along.",
                    imported.contacts,
                    snapshot.groups.len(),
                    imported.messages
                );
            }
            Err(e) => {
                eprintln!(
                    "The contacts and history could not be fetched ({e}). The device is linked \
                     all the same; add contacts with /add, or link again from an empty directory."
                );
            }
        },
        None => println!("The primary sent no contacts or history."),
    }
    client.shutdown().await;
    println!("Run silver to start.");
    Ok(())
}

/// Wait for the relay to take this device's bundle, saying why when it
/// cannot be reached.
async fn connected(events: &mut mpsc::Receiver<ClientEvent>) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
    loop {
        let event = tokio::time::timeout_at(deadline, events.recv())
            .await
            .map_err(|_| anyhow::anyhow!("the relay could not be reached within a minute"))?
            .ok_or_else(|| anyhow::anyhow!("the connection task stopped"))?;
        match event {
            ClientEvent::Connected { .. } => return Ok(()),
            ClientEvent::Disconnected { reason, retry_in } => {
                eprintln!(
                    "Not connected ({reason}); trying again in {}s.",
                    retry_in.as_secs()
                );
            }
            _ => {}
        }
    }
}
