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
    };
    if policy.invite_token.is_some() {
        info!("registration requires an invite token");
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
