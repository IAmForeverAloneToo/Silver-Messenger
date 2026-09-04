//! Silver Messenger terminal client.

mod app;
mod ui;

use std::path::PathBuf;
use std::sync::Arc;

use std::io::IsTerminal;

use anyhow::{Context, bail};
use clap::Parser;
use ratatui::crossterm::event::{
    DisableBracketedPaste, DisableFocusChange, DisableMouseCapture, EnableBracketedPaste,
    EnableFocusChange, EnableMouseCapture,
};
use ratatui::crossterm::execute;
use silver_client::{
    Client, ConnectOptions, DEFAULT_RELAY_URL, Proxy, SessionStore, Store, VaultError,
};
use tracing_subscriber::EnvFilter;

/// End-to-end encrypted messaging in your terminal.
#[derive(Parser, Debug)]
#[command(name = "silver", version, about)]
struct Args {
    /// Relay WebSocket URL, e.g. ws://relay.example.org:7777/ws. Remembered
    /// for later runs.
    #[arg(long, env = "SILVER_RELAY")]
    relay: Option<String>,

    /// PEM file with extra trusted root certificates, for a wss:// relay
    /// behind a private CA. Remembered for later runs.
    #[arg(long, env = "SILVER_CA_CERT")]
    ca_cert: Option<PathBuf>,

    /// HTTP CONNECT proxy to reach the relay through, e.g.
    /// http://proxy.corp:3128. Remembered. Defaults to $HTTPS_PROXY.
    #[arg(long, env = "SILVER_PROXY")]
    proxy: Option<String>,

    /// Invite token, for relays that only register invited identities.
    /// Remembered for later runs.
    #[arg(long, env = "SILVER_INVITE")]
    invite: Option<String>,

    /// Directory for keys, contacts and history (default: platform data dir).
    #[arg(long, env = "SILVER_DATA_DIR")]
    data_dir: Option<PathBuf>,

    /// Print your user id and exit.
    #[arg(long)]
    print_id: bool,

    /// Protect keys, contacts and history with a passphrase (asks for it),
    /// then exit. The passphrase is asked for at every start.
    #[arg(long)]
    set_passphrase: bool,

    /// Remove the passphrase and store everything unencrypted again, then
    /// exit.
    #[arg(long)]
    remove_passphrase: bool,

    /// Write an encrypted backup of your identity and contacts to this file
    /// (asks for a passphrase for the file), then exit.
    #[arg(long, value_name = "FILE")]
    export_backup: Option<PathBuf>,

    /// Restore identity and contacts from a backup file into the data
    /// directory, then exit. Refuses to replace an existing identity unless
    /// --force is given.
    #[arg(long, value_name = "FILE")]
    import_backup: Option<PathBuf>,

    /// With --import-backup: replace the identity already in the data
    /// directory.
    #[arg(long)]
    force: bool,

    /// Submit messages on the authenticated relay connection even when the
    /// relay offers a separate anonymous one (which hides the sender from
    /// the relay). Useful behind networks that allow one connection only.
    #[arg(long, env = "SILVER_SUBMIT_AUTHENTICATED")]
    submit_authenticated: bool,

    /// Leave the mouse to the terminal (no wheel scrolling in the chat, but
    /// text can be selected without holding Shift).
    #[arg(long, env = "SILVER_NO_MOUSE")]
    no_mouse: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if args.data_dir.is_none() {
        Store::migrate_legacy_dir();
    }
    let data_dir = args
        .data_dir
        .or_else(Store::default_dir)
        .context("could not determine a data directory; pass --data-dir")?;
    let mut store = Store::open(&data_dir)?;
    if store.is_locked() {
        unlock(&mut store)?;
    }
    if args.set_passphrase {
        if store.has_passphrase() {
            bail!("a passphrase is already set; run --remove-passphrase first to change it");
        }
        let passphrase = new_passphrase()?;
        store.set_passphrase(&passphrase)?;
        println!(
            "Keys, contacts and history in {} are now encrypted.",
            data_dir.display()
        );
        return Ok(());
    }
    if args.remove_passphrase {
        if !store.has_passphrase() {
            bail!("no passphrase is set");
        }
        store.remove_passphrase()?;
        println!(
            "Passphrase removed; files in {} are stored unencrypted again.",
            data_dir.display()
        );
        return Ok(());
    }

    if let Some(path) = args.import_backup {
        let passphrase = backup_passphrase("Backup passphrase: ")?;
        let payload = silver_client::read_backup(&path, &passphrase)?;
        let user_id = silver_protocol::Identity::from_secrets(&payload.identity).user_id();
        silver_client::import_backup(&store, payload, args.force)?;
        println!("Restored identity {user_id} into {}.", data_dir.display());
        return Ok(());
    }

    let (identity, created) = store.load_or_create_identity()?;
    if created {
        offer_passphrase(&mut store)?;
    }
    if let Some(path) = args.export_backup {
        let passphrase = match passphrase_from_env_backup() {
            Some(p) => p,
            None => {
                println!("Choose a passphrase for the backup file; it is needed to restore it.");
                new_passphrase()?
            }
        };
        silver_client::export_backup(&store, &path, &passphrase)?;
        println!(
            "Backup of identity {} and {} contact(s) written to {}.",
            identity.user_id(),
            store.load_contacts()?.len(),
            path.display()
        );
        return Ok(());
    }
    if args.print_id {
        println!("{}", identity.user_id());
        return Ok(());
    }

    let mut config = store.load_config()?;
    if args.relay.is_some()
        || args.ca_cert.is_some()
        || args.proxy.is_some()
        || args.invite.is_some()
    {
        if let Some(relay) = args.relay {
            config.relay_url = Some(relay);
        }
        if let Some(ca_cert) = args.ca_cert {
            config.ca_cert = Some(ca_cert);
        }
        if let Some(proxy) = args.proxy {
            config.proxy = Some(proxy);
        }
        if let Some(invite) = args.invite {
            config.invite_token = Some(invite);
        }
        store.save_config(&config)?;
    }
    let send_epoch = store.ensure_send_epoch(&mut config)?;
    let sessions = SessionStore::load(&store, identity.user_id())
        .context("loading sessions and prekeys")?
        .shared();
    let options = ConnectOptions {
        extra_ca_certs: config.ca_cert.iter().cloned().collect(),
        proxy: config.proxy.clone().or_else(Proxy::url_from_env),
        outbox_path: Some(store.outbox_path()),
        outbox_cipher: store.cipher(),
        invite_token: config.invite_token.clone(),
        sessions: Some(sessions),
        submit_authenticated: args.submit_authenticated,
    };
    let relay_url = config
        .relay_url
        .clone()
        .unwrap_or_else(|| DEFAULT_RELAY_URL.to_owned());

    // The terminal belongs to the UI, so logs go to a file, and only on request.
    if let Ok(filter) = std::env::var("SILVER_LOG") {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(data_dir.join("silver.log"))?;
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new(filter))
            .with_writer(file)
            .with_ansi(false)
            .init();
    }

    let (client, events) = Client::spawn(relay_url.clone(), Arc::new(identity), options)?;
    let app = app::App::new(store, client, relay_url, created, send_epoch)?;

    let terminal = ratatui::init();
    let mut stdout = std::io::stdout();
    // Best effort: a terminal that lacks one of these just ignores it.
    let _ = execute!(stdout, EnableBracketedPaste, EnableFocusChange);
    if !args.no_mouse {
        let _ = execute!(stdout, EnableMouseCapture);
    }
    let result = app.run(terminal, events).await;
    let _ = execute!(
        stdout,
        DisableMouseCapture,
        DisableFocusChange,
        DisableBracketedPaste
    );
    ratatui::restore();
    result
}

/// `SILVER_PASSPHRASE` in the environment stands in for typing it, for
/// scripts and tests.
fn passphrase_from_env() -> Option<String> {
    std::env::var("SILVER_PASSPHRASE").ok()
}

/// `SILVER_BACKUP_PASSPHRASE` stands in for typing the backup passphrase.
fn passphrase_from_env_backup() -> Option<String> {
    std::env::var("SILVER_BACKUP_PASSPHRASE").ok()
}

fn backup_passphrase(prompt: &str) -> anyhow::Result<String> {
    match passphrase_from_env_backup() {
        Some(p) => Ok(p),
        None => Ok(rpassword::prompt_password(prompt)?),
    }
}

fn unlock(store: &mut Store) -> anyhow::Result<()> {
    if let Some(passphrase) = passphrase_from_env() {
        return store.unlock(&passphrase).map_err(Into::into);
    }
    for attempt in 1..=3 {
        let passphrase = rpassword::prompt_password("Passphrase: ")?;
        match store.unlock(&passphrase) {
            Ok(()) => return Ok(()),
            Err(VaultError::WrongPassphrase) if attempt < 3 => {
                eprintln!("Wrong passphrase, try again.");
            }
            Err(e) => return Err(e.into()),
        }
    }
    bail!("too many failed attempts")
}

fn new_passphrase() -> anyhow::Result<String> {
    if let Some(passphrase) = passphrase_from_env() {
        if passphrase.is_empty() {
            bail!("SILVER_PASSPHRASE is set but empty");
        }
        return Ok(passphrase);
    }
    loop {
        let first = rpassword::prompt_password("New passphrase: ")?;
        if first.is_empty() {
            bail!("the passphrase must not be empty");
        }
        let second = rpassword::prompt_password("Repeat passphrase: ")?;
        if first == second {
            return Ok(first);
        }
        eprintln!("They do not match; try again.");
    }
}

/// First run: offer to protect the brand-new data directory.
fn offer_passphrase(store: &mut Store) -> anyhow::Result<()> {
    if let Some(passphrase) = passphrase_from_env() {
        if !passphrase.is_empty() {
            store.set_passphrase(&passphrase)?;
        }
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        return Ok(());
    }
    println!("This is a new identity. You can protect your keys, contacts and history");
    println!("with a passphrase that is asked for at every start. Leave it empty for none;");
    println!("you can add one later with --set-passphrase.");
    let first = rpassword::prompt_password("Passphrase (optional): ")?;
    if first.is_empty() {
        return Ok(());
    }
    let second = rpassword::prompt_password("Repeat passphrase: ")?;
    if first != second {
        bail!("the passphrases do not match; start again");
    }
    store.set_passphrase(&first)?;
    println!("Encrypted. Keep the passphrase safe: without it this identity cannot be recovered.");
    Ok(())
}
