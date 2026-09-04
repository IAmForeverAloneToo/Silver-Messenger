#![forbid(unsafe_code)]
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context as _;
use clap::Parser;
use silver_relay::tls::{self, CertStore};
use silver_relay::{
    DEFAULT_LISTEN, DEFAULT_MESSAGE_TTL, Limits, Policy, RelayState, expire_periodically, serve,
};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

/// Self-hosted Silver Messenger relay. Stores and forwards encrypted envelopes;
/// never sees plaintext.
#[derive(Parser, Debug)]
#[command(name = "silver-relay", version, about)]
struct Args {
    /// Address to listen on, e.g. 0.0.0.0:7777
    #[arg(long, env = "SILVER_RELAY_LISTEN", default_value = DEFAULT_LISTEN)]
    listen: String,

    /// Directory for the database. Defaults to systemd's STATE_DIRECTORY when
    /// set, otherwise ./silver-relay-data.
    #[arg(long, env = "SILVER_RELAY_DATA")]
    data_dir: Option<PathBuf>,

    /// Keep everything in memory only (lost on exit).
    #[arg(long, env = "SILVER_RELAY_EPHEMERAL")]
    ephemeral: bool,

    /// Days an unacknowledged message is kept before it is deleted.
    #[arg(long, env = "SILVER_RELAY_TTL_DAYS", default_value_t = DEFAULT_MESSAGE_TTL.as_secs() / 86_400)]
    message_ttl_days: u64,

    /// Maximum queued messages per recipient.
    #[arg(long, env = "SILVER_RELAY_MAX_MESSAGES", default_value_t = Limits::default().max_messages)]
    max_mailbox_messages: u64,

    /// Maximum queued bytes per recipient, in MiB.
    #[arg(long, env = "SILVER_RELAY_MAX_MIB", default_value_t = Limits::default().max_bytes / (1024 * 1024))]
    max_mailbox_mib: u64,

    /// Messages one connection may submit per minute.
    #[arg(long, env = "SILVER_RELAY_SENDS_PER_MINUTE", default_value_t = Policy::default().sends_per_minute)]
    sends_per_minute: u32,

    /// Key lookups one connection may make per minute.
    #[arg(long, env = "SILVER_RELAY_LOOKUPS_PER_MINUTE", default_value_t = Policy::default().lookups_per_minute)]
    lookups_per_minute: u32,

    /// Only register new identities that present this invite token
    /// (clients pass it with --invite). Existing identities are unaffected.
    #[arg(long, env = "SILVER_RELAY_INVITE_TOKEN")]
    invite_token: Option<String>,

    /// Messages a connection that never authenticates may submit per
    /// minute. Such connections let senders stay unknown to the relay;
    /// 0 turns them off.
    #[arg(long, env = "SILVER_RELAY_ANONYMOUS_SENDS_PER_MINUTE", default_value_t = Policy::default().anonymous_sends_per_minute)]
    anonymous_sends_per_minute: u32,

    /// Largest encrypted file to store, in MiB; 0 turns file transfer off.
    #[arg(long, env = "SILVER_RELAY_MAX_BLOB_MIB", default_value_t = Policy::default().max_blob_mib)]
    max_blob_mib: u32,

    /// Encrypted file bytes to keep in total, in MiB. Files expire with
    /// messages after --message-ttl-days.
    #[arg(long, env = "SILVER_RELAY_BLOB_STORAGE_MIB", default_value_t = Policy::default().blob_storage_mib)]
    blob_storage_mib: u32,

    /// Open connections one client address may hold at once.
    #[arg(long, env = "SILVER_RELAY_CONNECTIONS_PER_ADDRESS", default_value_t = Policy::default().connections_per_address)]
    connections_per_address: u32,

    /// Open connections in total.
    #[arg(long, env = "SILVER_RELAY_MAX_CONNECTIONS", default_value_t = Policy::default().max_connections)]
    max_connections: u32,

    /// Seconds a connection may stay silent before it is closed. Clients
    /// ping every 30 seconds.
    #[arg(long, env = "SILVER_RELAY_IDLE_TIMEOUT_SECS", default_value_t = Policy::default().idle_timeout.as_secs())]
    idle_timeout_secs: u64,

    /// New identities one address may register per hour.
    #[arg(long, env = "SILVER_RELAY_REGISTRATIONS_PER_HOUR", default_value_t = Policy::default().registrations_per_hour)]
    registrations_per_hour: u32,

    /// Identities the relay keeps at most; 0 for no cap.
    #[arg(long, env = "SILVER_RELAY_MAX_IDENTITIES", default_value_t = Policy::default().max_identities)]
    max_identities: u64,

    /// File bytes one address may upload per hour, in MiB.
    #[arg(long, env = "SILVER_RELAY_BLOB_MIB_PER_ADDRESS_PER_HOUR", default_value_t = Policy::default().blob_mib_per_address_per_hour)]
    blob_mib_per_address_per_hour: u32,

    /// Addresses of TLS fronts (Caddy, nginx) whose X-Forwarded-For header
    /// names the real client, comma separated. By default the loopback
    /// addresses are trusted, which is where the installer puts Caddy.
    #[arg(long, env = "SILVER_RELAY_TRUSTED_PROXY", value_delimiter = ',')]
    trusted_proxy: Vec<IpAddr>,

    /// Write user ids into the log as they are. Without this the log names
    /// clients by a pseudonym that holds for one run of the relay, so the
    /// journal is not a record of who used it.
    #[arg(long, env = "SILVER_RELAY_LOG_IDS")]
    log_ids: bool,

    /// Refuse the older login that signs the challenge alone; clients from
    /// 0.6.0 on sign the relay's host too, so a hostile relay cannot
    /// collect logins for this one. Off by default so older clients can
    /// still connect.
    #[arg(long, env = "SILVER_RELAY_REQUIRE_BOUND_AUTH")]
    require_bound_auth: bool,

    /// One-time prekeys handed out for one user per hour, at most; lookups
    /// beyond that get the bundle without one.
    #[arg(long, env = "SILVER_RELAY_ONE_TIME_PREKEYS_PER_USER_PER_HOUR", default_value_t = Policy::default().one_time_prekeys_per_user_per_hour)]
    one_time_prekeys_per_user_per_hour: u32,

    /// Serve TLS on --listen with this certificate chain (PEM); the files
    /// are re-read when they change, so a renewal needs no restart.
    #[arg(
        long,
        env = "SILVER_RELAY_TLS_CERT",
        requires = "tls_key",
        conflicts_with = "acme_domain"
    )]
    tls_cert: Option<PathBuf>,
    /// The PEM private key belonging to --tls-cert.
    #[arg(long, env = "SILVER_RELAY_TLS_KEY", requires = "tls_cert")]
    tls_key: Option<PathBuf>,
    /// Obtain and renew a certificate for this name from an ACME certificate
    /// authority (Let's Encrypt unless --acme-directory says otherwise) and
    /// serve TLS on --listen, which must be reachable at the name on port
    /// 443. Using the authority means agreeing to its terms. May be given
    /// more than once, or comma-separated.
    #[arg(long, env = "SILVER_RELAY_ACME_DOMAIN", value_delimiter = ',')]
    acme_domain: Vec<String>,
    /// An address the certificate authority may write to about the
    /// certificate (expiry warnings), for --acme-domain.
    #[arg(long, env = "SILVER_RELAY_ACME_EMAIL")]
    acme_email: Option<String>,
    /// The ACME directory to use. Let's Encrypt's staging directory,
    /// https://acme-staging-v02.api.letsencrypt.org/directory, issues
    /// untrusted certificates without rate limits, for trying things out.
    #[arg(long, env = "SILVER_RELAY_ACME_DIRECTORY", default_value = silver_relay::acme::DEFAULT_DIRECTORY)]
    acme_directory: String,
    /// Where the ACME account, the certificate key and the certificate are
    /// kept (default: acme/ under the data directory). Required with
    /// --ephemeral, since the key must outlive a restart for the
    /// certificate to stay valid.
    #[arg(long, env = "SILVER_RELAY_ACME_CACHE")]
    acme_cache: Option<PathBuf>,
    /// A root certificate (PEM) to trust for the ACME directory, for a
    /// private certificate authority.
    #[arg(long, env = "SILVER_RELAY_ACME_ROOT")]
    acme_root: Option<PathBuf>,

    /// Serve Prometheus metrics at /metrics on this address, e.g.
    /// 127.0.0.1:9107. For loopback or a private network only: the
    /// numbers describe how the relay is used.
    #[arg(long, env = "SILVER_RELAY_METRICS_LISTEN")]
    metrics_listen: Option<String>,

    /// Log lines as text, or as one JSON object per line for a log
    /// collector.
    #[arg(long, env = "SILVER_RELAY_LOG_FORMAT", value_enum, default_value_t = LogFormat::Text)]
    log_format: LogFormat,

    /// Answer `silver-relay admin` on this Unix socket, created readable by
    /// the relay's user only. Off unless given.
    #[arg(long, env = "SILVER_RELAY_ADMIN_SOCKET")]
    admin_socket: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Ask or tell a running relay something over its admin socket.
    Admin {
        /// The socket the relay was started with (--admin-socket).
        #[arg(long, default_value = silver_relay::admin::DEFAULT_SOCKET)]
        socket: PathBuf,
        #[command(subcommand)]
        action: AdminAction,
    },
    /// Write a backup of the whole database to FILE: through the admin
    /// socket while the relay runs, or straight from the data directory
    /// while it is stopped. The file is checked before it gets its name.
    /// It holds what the database holds, so keep it as private.
    Backup {
        /// Where to write the backup; created readable by its owner only.
        file: PathBuf,
        /// The running relay's admin socket. Without this flag the default
        /// socket is used when it exists, and the database is read directly
        /// otherwise.
        #[arg(long)]
        socket: Option<PathBuf>,
        /// The data directory, for a backup with the relay stopped.
        /// Defaults as for the relay itself.
        #[arg(long, env = "SILVER_RELAY_DATA")]
        data_dir: Option<PathBuf>,
    },
    /// Load a backup into the data directory, with the relay stopped. The
    /// file is checked first; a database already there is refused unless
    /// --replace moves it aside.
    Restore {
        /// The backup to load, as `silver-relay backup` wrote it.
        file: PathBuf,
        /// The data directory. Defaults as for the relay itself.
        #[arg(long, env = "SILVER_RELAY_DATA")]
        data_dir: Option<PathBuf>,
        /// Move an existing database aside (to relay.redb.before-restore-<time>)
        /// and restore over it.
        #[arg(long)]
        replace: bool,
    },
}

/// The data directory as the relay resolves it: the flag, else systemd's
/// STATE_DIRECTORY, else ./silver-relay-data.
fn data_dir(given: Option<PathBuf>) -> PathBuf {
    given
        .or_else(|| std::env::var_os("STATE_DIRECTORY").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("./silver-relay-data"))
}

#[cfg(unix)]
async fn live_backup(
    socket: &std::path::Path,
    file: &std::path::Path,
) -> anyhow::Result<(silver_relay::backup::Header, silver_relay::backup::Summary)> {
    silver_relay::admin::download(socket, file).await
}

#[cfg(not(unix))]
async fn live_backup(
    socket: &std::path::Path,
    _file: &std::path::Path,
) -> anyhow::Result<(silver_relay::backup::Header, silver_relay::backup::Summary)> {
    anyhow::bail!(
        "{} is a Unix socket, which this system has none of; stop the relay and back up its data directory",
        socket.display()
    )
}

async fn run_backup(
    file: PathBuf,
    socket: Option<PathBuf>,
    data_dir_flag: Option<PathBuf>,
) -> anyhow::Result<()> {
    let explicit = socket.is_some();
    let socket = socket.unwrap_or_else(|| PathBuf::from(silver_relay::admin::DEFAULT_SOCKET));
    let (header, summary, source) = if socket.exists() {
        let (header, summary) = live_backup(&socket, &file).await?;
        (
            header,
            summary,
            format!("the relay at {}", socket.display()),
        )
    } else if explicit {
        anyhow::bail!(
            "no relay is answering at {}; without --socket the database is read directly, which needs the relay stopped",
            socket.display()
        );
    } else {
        let dir = data_dir(data_dir_flag);
        let source = format!("the database in {}", dir.display());
        let dest = file.clone();
        let (header, summary) = tokio::task::spawn_blocking(move || {
            silver_relay::backup::offline(&dir, &dest, silver_protocol::now_ms())
        })
        .await??;
        (header, summary, source)
    };
    println!(
        "backup written to {}: {} identities, {} messages, {} files in {} records ({}), from {source}, schema version {}",
        file.display(),
        summary.identities,
        summary.messages,
        summary.blobs,
        summary.records,
        bytes_text(summary.bytes),
        header.schema
    );
    Ok(())
}

fn run_restore(file: PathBuf, data_dir_flag: Option<PathBuf>, replace: bool) -> anyhow::Result<()> {
    let dir = data_dir(data_dir_flag);
    let restored =
        silver_relay::backup::restore(&dir, &file, replace, silver_protocol::now_ms() / 1000)?;
    println!(
        "restored {} into {}: {} identities, {} messages, {} files in {} records; taken {} by silver-relay {}, schema version {}",
        file.display(),
        dir.display(),
        restored.summary.identities,
        restored.summary.messages,
        restored.summary.blobs,
        restored.summary.records,
        ms_text(restored.header.taken_at_ms),
        restored.header.relay,
        restored.header.schema
    );
    if let Some(aside) = restored.replaced {
        println!(
            "the database that was there is at {}; delete it once the relay runs as expected",
            aside.display()
        );
    }
    println!("start the relay to serve it");
    Ok(())
}

#[derive(clap::Subcommand, Debug)]
enum AdminAction {
    /// Counters, store numbers, the certificate, the invite policy.
    Status,
    /// Every identity by its log pseudonym, largest mailbox first.
    Identities,
    /// Delete an identity's bundle, prekeys and mailbox and disconnect it.
    /// WHO is a pseudonym from the listing or a full id.
    Evict { who: String },
    /// Refuse an address (an IP) or an identity (a pseudonym or an id)
    /// from now on, across restarts.
    Ban {
        target: String,
        /// Why, for the listing.
        #[arg(long, default_value = "")]
        note: String,
    },
    /// Lift a ban.
    Unban { target: String },
    /// The bans in force.
    Bans,
    /// Require this token from new identities from now on, or a fresh
    /// random one when none is given; printed, and kept across restarts.
    InviteSet { token: Option<String> },
    /// Require no token from now on, kept across restarts.
    InviteOff,
    /// Forget the runtime choice; the token from the command line or the
    /// environment applies again.
    InviteReset,
}

fn ms_text(ms: u64) -> String {
    let secs = ms / 1000;
    let now = silver_protocol::now_ms() / 1000;
    let ago = now.saturating_sub(secs);
    match ago {
        0..=119 => format!("{ago}s ago"),
        120..=7199 => format!("{}m ago", ago / 60),
        7200..=172_799 => format!("{}h ago", ago / 3600),
        _ => format!("{}d ago", ago / 86_400),
    }
}

fn bytes_text(bytes: u64) -> String {
    match bytes {
        0..=1023 => format!("{bytes} B"),
        1024..=1_048_575 => format!("{:.1} KiB", bytes as f64 / 1024.0),
        _ => format!("{:.1} MiB", bytes as f64 / 1_048_576.0),
    }
}

/// Run one admin action against the socket and print the answer.
async fn run_admin(socket: PathBuf, action: AdminAction) -> anyhow::Result<()> {
    use silver_relay::admin::{Evicted, InviteToken, Status, request};
    use silver_relay::{BanRow, IdentityRow};
    let ban_path = |target: &str| {
        if target.parse::<IpAddr>().is_ok() {
            format!("/bans/address/{target}")
        } else {
            format!("/bans/identity/{target}")
        }
    };
    let (status, body) = match &action {
        AdminAction::Status => request(&socket, "GET", "/status", "").await?,
        AdminAction::Identities => request(&socket, "GET", "/identities", "").await?,
        AdminAction::Evict { who } => {
            request(&socket, "POST", &format!("/evict/{who}"), "").await?
        }
        AdminAction::Ban { target, note } => {
            request(&socket, "POST", &ban_path(target), note).await?
        }
        AdminAction::Unban { target } => request(&socket, "DELETE", &ban_path(target), "").await?,
        AdminAction::Bans => request(&socket, "GET", "/bans", "").await?,
        AdminAction::InviteSet { token } => {
            request(&socket, "POST", "/invite", token.as_deref().unwrap_or("")).await?
        }
        AdminAction::InviteOff => request(&socket, "DELETE", "/invite", "").await?,
        AdminAction::InviteReset => request(&socket, "POST", "/invite/reset", "").await?,
    };
    if !(200..300).contains(&status) {
        let text = match &body {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        anyhow::bail!("the relay answered {status}: {text}");
    }
    match action {
        AdminAction::Status => {
            let s: Status = serde_json::from_value(body)?;
            println!(
                "silver-relay {} up {}h{:02}m",
                s.version,
                s.uptime_secs / 3600,
                (s.uptime_secs % 3600) / 60
            );
            println!(
                "connections: {} open from {} addresses; {} identities online",
                s.counters.open_connections, s.counters.addresses, s.online
            );
            println!(
                "refused: {} connections, {} registrations, {} uploads, {} logins; {} closed idle; {} anonymous submissions",
                s.counters.refused_connections,
                s.counters.refused_registrations,
                s.counters.refused_uploads,
                s.auth_failures,
                s.counters.idle_closed,
                s.anonymous_submissions
            );
            println!(
                "store: {} identities, {} messages in {} mailboxes ({}), {} files ({})",
                s.stats.bundles,
                s.stats.messages,
                s.stats.mailboxes,
                bytes_text(s.stats.bytes),
                s.stats.blobs,
                bytes_text(s.stats.blob_bytes)
            );
            println!(
                "registration: {}",
                if s.invite_required {
                    "invite token required"
                } else {
                    "open"
                }
            );
            if let Some(tls) = s.tls {
                match tls.certificate_expires_at_ms {
                    Some(at) => println!(
                        "certificate: expires in {}d; {} failed renewals",
                        (at / 1000).saturating_sub(silver_protocol::now_ms() / 1000) / 86_400,
                        tls.acme_failures
                    ),
                    None => println!(
                        "certificate: none yet; {} failed attempts",
                        tls.acme_failures
                    ),
                }
            }
        }
        AdminAction::Identities => {
            let rows: Vec<IdentityRow> = serde_json::from_value(body)?;
            if rows.is_empty() {
                println!("no identities");
                return Ok(());
            }
            println!(
                "{:<14} {:<7} {:>8} {:>10} {:>9} {:>6} {:<12} flags",
                "who", "online", "messages", "bytes", "prekeys", "pq", "published"
            );
            for r in rows {
                println!(
                    "{:<14} {:<7} {:>8} {:>10} {:>9} {:>6} {:<12} {}",
                    r.who,
                    if r.online { "yes" } else { "no" },
                    r.messages,
                    bytes_text(r.bytes),
                    r.one_time_prekeys,
                    r.pq_one_time_prekeys,
                    r.signed_prekey_at_ms
                        .map(ms_text)
                        .unwrap_or_else(|| "never".into()),
                    [(r.post_quantum, "post-quantum"), (r.banned, "banned")]
                        .into_iter()
                        .filter(|(on, _)| *on)
                        .map(|(_, flag)| flag)
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
        AdminAction::Evict { .. } => {
            let e: Evicted = serde_json::from_value(body)?;
            println!(
                "evicted {}: {} messages ({}), {} prekeys, bundle {}",
                e.who,
                e.removed.messages,
                bytes_text(e.removed.bytes),
                e.removed.prekeys,
                if e.removed.had_bundle {
                    "removed"
                } else {
                    "was not there"
                }
            );
        }
        AdminAction::Ban { target, .. } => println!("banned {target}"),
        AdminAction::Unban { target } => println!("unbanned {target}"),
        AdminAction::Bans => {
            let rows: Vec<BanRow> = serde_json::from_value(body)?;
            if rows.is_empty() {
                println!("no bans");
            }
            for r in rows {
                println!("{:<40} {:<10} {}", r.target, ms_text(r.since_ms), r.note);
            }
        }
        AdminAction::InviteSet { .. } => {
            let t: InviteToken = serde_json::from_value(body)?;
            println!(
                "new identities must now present: {}",
                t.token.unwrap_or_default()
            );
        }
        AdminAction::InviteOff => println!("new identities need no invite token now"),
        AdminAction::InviteReset => {
            let t: InviteToken = serde_json::from_value(body)?;
            println!(
                "runtime choice forgotten; {}",
                match t.token {
                    Some(_) => "the configured token applies",
                    None => "no token is configured, so registration is open",
                }
            );
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum LogFormat {
    Text,
    Json,
}

/// How the relay's listener is protected.
enum Transport {
    Plain,
    Files { cert: PathBuf, key: PathBuf },
    Acme(silver_relay::acme::AcmeConfig),
}

impl Transport {
    fn from_args(args: &Args, data_dir: Option<&PathBuf>) -> anyhow::Result<Self> {
        if let (Some(cert), Some(key)) = (&args.tls_cert, &args.tls_key) {
            return Ok(Self::Files {
                cert: cert.clone(),
                key: key.clone(),
            });
        }
        if args.acme_domain.is_empty() {
            return Ok(Self::Plain);
        }
        let cache = match (&args.acme_cache, data_dir) {
            (Some(cache), _) => cache.clone(),
            (None, Some(dir)) => dir.join("acme"),
            (None, None) => anyhow::bail!(
                "--acme-domain with --ephemeral needs --acme-cache: the certificate key and the ACME account must survive a restart"
            ),
        };
        Ok(Self::Acme(silver_relay::acme::AcmeConfig {
            domains: args
                .acme_domain
                .iter()
                .map(|d| d.trim().to_ascii_lowercase())
                .filter(|d| !d.is_empty())
                .collect(),
            directory: args.acme_directory.clone(),
            // An empty SILVER_RELAY_ACME_EMAIL (a container's unset
            // variable) means none.
            contact: args
                .acme_email
                .clone()
                .filter(|email| !email.trim().is_empty()),
            cache,
            root: args.acme_root.clone(),
        }))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = Args::parse();
    // The subcommands: one line on stderr and a failing exit status when
    // they fail, as a command-line tool should; not the debug rendering a
    // crashed relay gets.
    let outcome = match args.command.take() {
        Some(Command::Admin { socket, action }) => Some(run_admin(socket, action).await),
        Some(Command::Backup {
            file,
            socket,
            data_dir,
        }) => Some(run_backup(file, socket, data_dir).await),
        Some(Command::Restore {
            file,
            data_dir,
            replace,
        }) => Some(run_restore(file, data_dir, replace)),
        None => None,
    };
    if let Some(outcome) = outcome {
        if let Err(e) = outcome {
            eprintln!("error: {e:#}");
            std::process::exit(1);
        }
        return Ok(());
    }
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    match args.log_format {
        LogFormat::Text => tracing_subscriber::fmt().with_env_filter(filter).init(),
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init(),
    }
    let limits = Limits {
        max_messages: args.max_mailbox_messages,
        max_bytes: args.max_mailbox_mib * 1024 * 1024,
    };
    let policy = Policy {
        sends_per_minute: args.sends_per_minute,
        lookups_per_minute: args.lookups_per_minute,
        invite_token: args.invite_token.clone().filter(|t| !t.trim().is_empty()),
        anonymous_sends_per_minute: args.anonymous_sends_per_minute,
        max_blob_mib: args.max_blob_mib,
        blob_storage_mib: args.blob_storage_mib,
        connections_per_address: args.connections_per_address,
        max_connections: args.max_connections,
        idle_timeout: Duration::from_secs(args.idle_timeout_secs.max(1)),
        registrations_per_hour: args.registrations_per_hour,
        max_identities: args.max_identities,
        blob_mib_per_address_per_hour: args.blob_mib_per_address_per_hour,
        trusted_proxies: args.trusted_proxy.clone(),
        log_ids: args.log_ids,
        require_bound_auth: args.require_bound_auth,
        one_time_prekeys_per_user_per_hour: args.one_time_prekeys_per_user_per_hour,
        ..Policy::default()
    };
    if policy.require_bound_auth {
        info!("only the bound login is accepted; clients before 0.6.0 cannot connect");
    }
    if policy.log_ids {
        info!("user ids are written to the log as they are (--log-ids)");
    }
    info!(
        "limits: {} connections per address, {} in total, idle after {}s, {} registrations per address per hour, {} identities at most, {} MiB of uploads per address per hour",
        policy.connections_per_address,
        policy.max_connections,
        policy.idle_timeout.as_secs(),
        policy.registrations_per_hour,
        policy.max_identities,
        policy.blob_mib_per_address_per_hour
    );
    if policy.invite_token.is_some() {
        info!("registration requires an invite token");
    }
    if policy.anonymous_sends_per_minute == 0 {
        info!("anonymous submission is off; senders submit on their own connection");
    }
    let data_dir = (!args.ephemeral).then(|| data_dir(args.data_dir.clone()));
    let transport = Transport::from_args(&args, data_dir.as_ref())?;
    let state = if args.ephemeral {
        info!("running with in-memory state; nothing is persisted");
        RelayState::with_store_and_policy(silver_relay::Store::in_memory()?, limits, policy.clone())
    } else {
        let dir = data_dir.clone().expect("a data directory unless ephemeral");
        let path = silver_relay::backup::database_path(&dir);
        let state = RelayState::open_with(&path, limits, policy.clone())?;
        let stats = state.stats();
        info!(
            "database {} (schema version {}; {} bundles, {} messages in {} mailboxes)",
            path.display(),
            silver_relay::SCHEMA_VERSION,
            stats.bundles,
            stats.messages,
            stats.mailboxes
        );
        state
    };

    let ttl = Duration::from_secs(args.message_ttl_days * 86_400);
    tokio::spawn(expire_periodically(
        state.clone(),
        ttl,
        Duration::from_secs(3600),
    ));

    // One certificate store for the TLS listener and the metrics, which
    // report the certificate's expiry.
    let cert_store = match transport {
        Transport::Plain => None,
        _ => Some(CertStore::new()),
    };
    if let Some(socket) = &args.admin_socket {
        #[cfg(unix)]
        {
            info!("administration on {}", socket.display());
            let admin =
                silver_relay::admin::serve_unix(socket.clone(), state.clone(), cert_store.clone());
            tokio::spawn(async move {
                if let Err(e) = admin.await {
                    tracing::error!("admin socket: {e:#}");
                }
            });
        }
        #[cfg(not(unix))]
        anyhow::bail!(
            "--admin-socket {} needs a Unix socket, which this system has none of",
            socket.display()
        );
    }
    if let Some(metrics_addr) = &args.metrics_listen {
        let metrics_listener = TcpListener::bind(metrics_addr)
            .await
            .with_context(|| format!("binding the metrics listener {metrics_addr}"))?;
        info!(
            "metrics at http://{}/metrics",
            metrics_listener.local_addr()?
        );
        tokio::spawn(silver_relay::metrics::serve(
            metrics_listener,
            state.clone(),
            cert_store.clone(),
        ));
    }

    let listener = TcpListener::bind(&args.listen).await?;
    let addr = listener.local_addr()?;
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
        info!("shutting down");
    };
    let path = silver_protocol::wire::WS_PATH;
    match transport {
        Transport::Plain => {
            info!("relay listening on ws://{addr}{path}");
            serve(listener, state, shutdown).await
        }
        Transport::Files { cert, key } => {
            let store = cert_store
                .clone()
                .expect("a certificate store whenever TLS is on");
            let loaded = tls::load_pem(&cert, &key)?;
            info!(
                "relay listening on wss://{addr}{path} with the certificate for {} from {}, valid until {}",
                tls::dns_names(&loaded.cert[0]).join(", "),
                cert.display(),
                tls::expiry_text(&loaded.cert[0])
            );
            store.set_current(loaded);
            tokio::spawn(tls::watch_files(
                store.clone(),
                cert,
                key,
                tls::FILE_CHECK_EVERY,
            ));
            let config = tls::server_config(store)?;
            tls::serve_tls(listener.into_std()?, config, state, shutdown).await
        }
        Transport::Acme(acme) => {
            let store = cert_store
                .clone()
                .expect("a certificate store whenever TLS is on");
            info!(
                "relay listening on wss://{addr}{path}; certificate for {} from {}, kept in {}",
                acme.domains.join(", "),
                acme.directory,
                acme.cache.display()
            );
            // The listener must be up before the order: validation connects
            // to it. Until the first certificate arrives, handshakes fail.
            let config = tls::server_config(store.clone())?;
            tokio::spawn(silver_relay::acme::run(acme, store));
            tls::serve_tls(listener.into_std()?, config, state, shutdown).await
        }
    }
}
