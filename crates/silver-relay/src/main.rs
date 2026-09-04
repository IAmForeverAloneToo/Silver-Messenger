#![forbid(unsafe_code)]
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let limits = Limits {
        max_messages: args.max_mailbox_messages,
        max_bytes: args.max_mailbox_mib * 1024 * 1024,
    };
    let policy = Policy {
        sends_per_minute: args.sends_per_minute,
        lookups_per_minute: args.lookups_per_minute,
        invite_token: args.invite_token.filter(|t| !t.trim().is_empty()),
        anonymous_sends_per_minute: args.anonymous_sends_per_minute,
        max_blob_mib: args.max_blob_mib,
        blob_storage_mib: args.blob_storage_mib,
        connections_per_address: args.connections_per_address,
        max_connections: args.max_connections,
        idle_timeout: Duration::from_secs(args.idle_timeout_secs.max(1)),
        registrations_per_hour: args.registrations_per_hour,
        max_identities: args.max_identities,
        blob_mib_per_address_per_hour: args.blob_mib_per_address_per_hour,
        trusted_proxies: args.trusted_proxy,
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
    let state = if args.ephemeral {
        info!("running with in-memory state; nothing is persisted");
        RelayState::with_store_and_policy(silver_relay::Store::in_memory()?, limits, policy.clone())
    } else {
        let dir = args
            .data_dir
            .or_else(|| std::env::var_os("STATE_DIRECTORY").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("./silver-relay-data"));
        let path = dir.join("relay.redb");
        let state = RelayState::open_with(&path, limits, policy.clone())?;
        let stats = state.stats();
        info!(
            "database {} ({} bundles, {} messages in {} mailboxes)",
            path.display(),
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

    let listener = TcpListener::bind(&args.listen).await?;
    let addr = listener.local_addr()?;
    info!(
        "relay listening on ws://{addr}{}",
        silver_protocol::wire::WS_PATH
    );

    serve(listener, state, async {
        let _ = tokio::signal::ctrl_c().await;
        info!("shutting down");
    })
    .await
}
