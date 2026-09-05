#![deny(unsafe_code)]
//! Silver Messenger terminal client.

mod app;
mod clipboard;
mod commands;
mod glyphs;
mod notify;
mod qr;
mod theme;
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
    Client, ConnectOptions, DEFAULT_RELAY_URL, InviteLink, Pin, Protection, Proxy, SessionStore,
    Store, VaultError, keystore,
};
use tracing_subscriber::EnvFilter;

use crate::app::{AtRest, Exit};

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

    /// Proxy to reach the relay through: http://proxy.corp:3128 (HTTP
    /// CONNECT) or socks5://127.0.0.1:9050 (SOCKS5, e.g. Tor). Remembered.
    /// Defaults to $HTTPS_PROXY, else $ALL_PROXY.
    #[arg(long, env = "SILVER_PROXY")]
    proxy: Option<String>,

    /// Pin the relay's TLS public key (sha256:<hex>, as --print-pin shows
    /// it): a wss:// connection is refused unless the relay presents a
    /// pinned key. Remembered; give it again to add another.
    #[arg(long, env = "SILVER_PIN", value_name = "PIN")]
    pin: Option<String>,

    /// Connect to the relay once, print the pin of the key it presents and
    /// whether its certificate is trusted, then exit.
    #[arg(long)]
    print_pin: bool,

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

    /// Print your invite link (`silver://add/<id>?relay=...`) and exit.
    #[arg(long)]
    print_invite: bool,

    /// Protect keys, contacts and history with a passphrase (asks for it),
    /// then exit. The passphrase is asked for at every start.
    #[arg(long)]
    set_passphrase: bool,

    /// Remove the passphrase, then exit. The files stay encrypted under a
    /// key in this computer's key store where there is one, and are stored
    /// unencrypted otherwise.
    #[arg(long)]
    remove_passphrase: bool,

    /// Keep keys, contacts and history as plain files rather than encrypting
    /// them with a key from this computer's key store. Remembered; a
    /// passphrase still works.
    #[arg(long)]
    no_keystore: bool,

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

    /// Ask the releases page once whether a newer version exists, print
    /// the answer, and exit. Never happens by itself: the request shows
    /// GitHub this computer's address. Goes through --proxy / --ca-cert
    /// from this command line (or the environment), and touches no data.
    #[arg(long)]
    check_release: bool,

    /// Submit messages on the authenticated relay connection even when the
    /// relay offers a separate anonymous one (which hides the sender from
    /// the relay). Useful behind networks that allow one connection only.
    #[arg(long, env = "SILVER_SUBMIT_AUTHENTICATED")]
    submit_authenticated: bool,

    /// Leave the mouse to the terminal (no wheel scrolling in the chat, but
    /// text can be selected without holding Shift).
    #[arg(long, env = "SILVER_NO_MOUSE")]
    no_mouse: bool,

    /// Draw marks in ASCII (v, vv, x, ..) for terminals whose fonts lack
    /// the Unicode ones, such as the classic Windows console. Chosen by
    /// itself where the terminal is known; /marks changes it for good.
    #[arg(long, env = "SILVER_ASCII")]
    ascii: bool,

    /// Colours: dark (default), light for a light background, or mono for
    /// none at all (NO_COLOR does the same). /theme changes it for good.
    #[arg(long, env = "SILVER_THEME", value_name = "NAME")]
    theme: Option<String>,
}

/// Passphrases handed over in the environment (scripts, tests), taken out
/// of it before anything else runs so that no child process (the file
/// opener, say) and no other reader of the environment sees them.
struct EnvSecrets {
    passphrase: Option<String>,
    backup_passphrase: Option<String>,
}

impl EnvSecrets {
    #[allow(unsafe_code)]
    fn take() -> Self {
        let passphrase = std::env::var("SILVER_PASSPHRASE").ok();
        let backup_passphrase = std::env::var("SILVER_BACKUP_PASSPHRASE").ok();
        // SAFETY: this runs first thing in `main`, before the runtime and
        // therefore before any other thread exists, so nothing can be
        // reading the environment while it changes.
        unsafe {
            std::env::remove_var("SILVER_PASSPHRASE");
            std::env::remove_var("SILVER_BACKUP_PASSPHRASE");
        }
        Self {
            passphrase,
            backup_passphrase,
        }
    }
}

fn main() -> anyhow::Result<()> {
    let secrets = EnvSecrets::take();
    harden_process();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run(secrets))
}

/// Keep the keys in memory out of core dumps and away from other
/// processes of the same user: no core file, and on Linux no ptrace.
fn harden_process() {
    #[cfg(unix)]
    {
        let _ = rlimit::setrlimit(rlimit::Resource::CORE, 0, 0);
    }
    #[cfg(target_os = "linux")]
    {
        let _ = nix::sys::prctl::set_dumpable(false);
    }
}

async fn run(secrets: EnvSecrets) -> anyhow::Result<()> {
    let args = Args::parse();

    if args.check_release {
        return check_release(&args).await;
    }

    if args.data_dir.is_none() {
        Store::migrate_legacy_dir();
    }
    let data_dir = args
        .data_dir
        .or_else(Store::default_dir)
        .context("could not determine a data directory; pass --data-dir")?;
    let mut store = Store::open(&data_dir)?;
    open_protected(&mut store, &secrets)?;
    if args.set_passphrase {
        if store.has_passphrase() {
            bail!("a passphrase is already set; run --remove-passphrase first to change it");
        }
        let passphrase = new_passphrase(&secrets)?;
        store.set_passphrase(&passphrase)?;
        println!(
            "Keys, contacts and history in {} are now encrypted under your passphrase.",
            data_dir.display()
        );
        return Ok(());
    }
    if args.remove_passphrase {
        if !store.has_passphrase() {
            bail!("no passphrase is set");
        }
        match store.remove_passphrase()? {
            Protection::Keystore => println!(
                "Passphrase removed; files in {} stay encrypted under a key in this computer's key store.",
                data_dir.display()
            ),
            _ => println!(
                "Passphrase removed; files in {} are stored unencrypted again.",
                data_dir.display()
            ),
        }
        return Ok(());
    }

    if let Some(path) = args.import_backup {
        let passphrase = backup_passphrase(&secrets, "Backup passphrase: ")?;
        let payload = silver_client::read_backup(&path, &passphrase)?;
        let user_id = silver_protocol::Identity::from_secrets(&payload.identity).user_id();
        silver_client::import_backup(&store, payload, args.force)?;
        println!("Restored identity {user_id} into {}.", data_dir.display());
        return Ok(());
    }

    let (mut identity, mut created) = store.load_or_create_identity()?;
    if created {
        offer_passphrase(&mut store, &secrets)?;
    }
    if let Some(path) = args.export_backup {
        let passphrase = match &secrets.backup_passphrase {
            Some(p) => p.clone(),
            None => {
                println!("Choose a passphrase for the backup file; it is needed to restore it.");
                new_passphrase(&EnvSecrets {
                    passphrase: None,
                    backup_passphrase: None,
                })?
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
    if args.print_invite {
        let relay = args.relay.clone().or_else(|| config.relay_url.clone());
        println!("{}", InviteLink::new(identity.user_id(), relay));
        return Ok(());
    }
    if args.relay.is_some()
        || args.ca_cert.is_some()
        || args.proxy.is_some()
        || args.pin.is_some()
        || args.invite.is_some()
        || args.no_keystore
    {
        if let Some(relay) = args.relay {
            refuse_downgrade(&config, &relay)?;
            config.relay_url = Some(relay);
        }
        if let Some(ca_cert) = args.ca_cert {
            config.ca_cert = Some(ca_cert);
        }
        if let Some(proxy) = args.proxy {
            Proxy::parse(&proxy)?;
            config.proxy = Some(proxy);
        }
        if let Some(pin) = args.pin {
            let pin = Pin::parse(&pin)?.to_hex();
            if !config.relay_pins.contains(&pin) {
                config.relay_pins.push(pin);
            }
        }
        if let Some(invite) = args.invite {
            config.invite_token = Some(invite);
        }
        if args.no_keystore {
            config.os_keystore = false;
        }
        store.save_config(&config)?;
    }
    if args.no_keystore && store.protection() == Protection::Keystore {
        store.remove_protection()?;
        println!(
            "Files in {} are stored unencrypted again (--no-keystore).",
            data_dir.display()
        );
    }
    // Protected at rest by default: with no passphrase, the data key goes
    // into this computer's key store.
    let at_rest = match store.protection() {
        Protection::Passphrase => AtRest::Passphrase,
        Protection::Keystore => AtRest::Keystore,
        Protection::None if !config.os_keystore => {
            AtRest::Plain("os_keystore is off in config.json".into())
        }
        Protection::None if keystore::available() => match store.protect_with_keystore() {
            Ok(()) => AtRest::Keystore,
            Err(e) => AtRest::Plain(format!("the key store could not be used ({e:#})")),
        },
        Protection::None => AtRest::Plain(
            "this computer has no key store the client can use (on Linux that is a Secret \
             Service such as GNOME Keyring or KWallet)"
                .into(),
        ),
    };
    let send_epoch = store.ensure_send_epoch(&mut config)?;
    let relay_url = config
        .relay_url
        .clone()
        .unwrap_or_else(|| DEFAULT_RELAY_URL.to_owned());
    // The config file may have been edited by hand; the rule holds anyway.
    refuse_downgrade(&config, &relay_url)?;
    let pins = config
        .relay_pins
        .iter()
        .map(|p| Pin::parse(p))
        .collect::<anyhow::Result<Vec<_>>>()
        .context("relay_pins in config.json")?;
    let proxy = config.proxy.clone().or_else(Proxy::url_from_env);

    if args.print_pin {
        let options = ConnectOptions {
            extra_ca_certs: config.ca_cert.iter().cloned().collect(),
            proxy,
            ..Default::default()
        };
        let observed = silver_client::observe_relay(&relay_url, &options).await?;
        println!("{relay_url} presents the key {}", observed.pins[0]);
        match &observed.trusted {
            Ok(()) => println!("Its certificate is trusted by this computer."),
            Err(e) => println!("Its certificate is NOT trusted by this computer: {e}"),
        }
        for pin in &observed.pins[1..] {
            println!("Issuer key in its chain: {pin}");
        }
        println!(
            "This is what answered right now; compare it with the pin the relay's operator \
             published before trusting it. To pin it: silver --pin {}",
            observed.pins[0]
        );
        return Ok(());
    }

    // The terminal belongs to the UI, so logs go to a file, and only on
    // request; the file is the user's alone.
    if let Ok(filter) = std::env::var("SILVER_LOG") {
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(data_dir.join("silver.log"))?;
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new(filter))
            .with_writer(file)
            .with_ansi(false)
            .init();
    }

    let marks = if args.ascii {
        glyphs::Marks::Ascii
    } else {
        glyphs::Marks::parse(&config.marks).unwrap_or(glyphs::Marks::Auto)
    };
    let theme = theme::choose(
        args.theme.as_deref(),
        &config.theme,
        std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()),
    );

    // The client runs until it quits or locks; a lock drops everything that
    // holds keys and starts over from the passphrase.
    loop {
        let sessions = SessionStore::load(&store, identity.user_id())
            .context("loading sessions and prekeys")?
            .shared();
        let options = ConnectOptions {
            extra_ca_certs: config.ca_cert.iter().cloned().collect(),
            proxy: proxy.clone(),
            pins: pins.clone(),
            outbox_path: Some(store.outbox_path()),
            outbox_cipher: store.cipher(),
            invite_token: config.invite_token.clone(),
            sessions: Some(sessions),
            submit_authenticated: args.submit_authenticated,
            groups: false,
            transparency: Some(
                silver_client::LogStore::load(Some(store.transparency_path()), store.cipher())
                    .context("loading the relay's key log")?
                    .shared(),
            ),
        };
        let (client, events) = Client::spawn(relay_url.clone(), Arc::new(identity), options)?;
        let app = app::App::new(
            store,
            client,
            relay_url.clone(),
            created,
            send_epoch,
            glyphs::Glyphs::for_marks(marks),
            theme::Theme::named(theme),
            at_rest.clone(),
        )?;

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
        match result? {
            Exit::Quit => return Ok(()),
            Exit::Lock => {
                // `app` is gone, and with it the client, the identity, the
                // sessions and the data key.
                println!("Locked. The passphrase opens it again; Ctrl-C quits.");
                store = Store::open(&data_dir)?;
                unlock(&mut store, &secrets)?;
                identity = store.load_or_create_identity()?.0;
                created = false;
            }
        }
    }
}

/// `--check-release`: one request to the releases page, then a line.
async fn check_release(args: &Args) -> anyhow::Result<()> {
    use silver_client::update::{RELEASES_API, compare, latest_release};
    use std::cmp::Ordering;

    let options = ConnectOptions {
        extra_ca_certs: args.ca_cert.iter().cloned().collect(),
        proxy: args.proxy.clone().or_else(Proxy::url_from_env),
        ..Default::default()
    };
    let current = env!("CARGO_PKG_VERSION");
    let release = latest_release(RELEASES_API, &options)
        .await
        .context("asking the releases page")?;
    match compare(release.version(), current) {
        Some(Ordering::Greater) => println!(
            "Silver Messenger {} is available; this is {current}.\n{}",
            release.version(),
            release.url
        ),
        Some(Ordering::Equal) => println!("Silver Messenger {current} is the newest release."),
        Some(Ordering::Less) => println!(
            "This is Silver Messenger {current}; the newest release is {}.",
            release.version()
        ),
        None => println!(
            "The newest release is called {}; this is {current}.\n{}",
            release.tag, release.url
        ),
    }
    Ok(())
}

/// A relay once reached over `wss://` is not talked to over `ws://`.
fn refuse_downgrade(config: &silver_client::Config, url: &str) -> anyhow::Result<()> {
    match config.downgrade(url) {
        Some(host) => bail!(
            "{host} was reached over wss:// before; refusing to talk to it over plain ws://. \
             Use a wss:// URL, or remove the host from secure_hosts in config.json if the \
             relay really stopped offering TLS."
        ),
        None => Ok(()),
    }
}

/// Unlock the directory by whatever protects it.
fn open_protected(store: &mut Store, secrets: &EnvSecrets) -> anyhow::Result<()> {
    match store.protection() {
        Protection::None => Ok(()),
        Protection::Keystore => store.unlock_with_keystore(),
        Protection::Passphrase => unlock(store, secrets),
    }
}

fn backup_passphrase(secrets: &EnvSecrets, prompt: &str) -> anyhow::Result<String> {
    match &secrets.backup_passphrase {
        Some(p) => Ok(p.clone()),
        None => Ok(rpassword::prompt_password(prompt)?),
    }
}

fn unlock(store: &mut Store, secrets: &EnvSecrets) -> anyhow::Result<()> {
    if let Some(passphrase) = &secrets.passphrase {
        return store.unlock(passphrase).map_err(Into::into);
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

fn new_passphrase(secrets: &EnvSecrets) -> anyhow::Result<String> {
    if let Some(passphrase) = &secrets.passphrase {
        if passphrase.is_empty() {
            bail!("SILVER_PASSPHRASE is set but empty");
        }
        return Ok(passphrase.clone());
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
fn offer_passphrase(store: &mut Store, secrets: &EnvSecrets) -> anyhow::Result<()> {
    if let Some(passphrase) = &secrets.passphrase {
        if !passphrase.is_empty() {
            store.set_passphrase(passphrase)?;
        }
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        return Ok(());
    }
    println!("This is a new identity. You can protect your keys, contacts and history");
    println!("with a passphrase that is asked for at every start.");
    if keystore::available() {
        println!(
            "Leave it empty to encrypt them with a key kept in this computer's key store instead;"
        );
        println!("you can add a passphrase later with --set-passphrase.");
    } else {
        println!("Leave it empty for none; you can add one later with --set-passphrase.");
    }
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
