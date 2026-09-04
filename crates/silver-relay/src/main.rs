use clap::Parser;
use silver_relay::{DEFAULT_LISTEN, RelayState, serve};
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let listener = TcpListener::bind(&args.listen).await?;
    let addr = listener.local_addr()?;
    info!(
        "relay listening on ws://{addr}{}",
        silver_protocol::wire::WS_PATH
    );

    serve(listener, RelayState::new(), async {
        let _ = tokio::signal::ctrl_c().await;
        info!("shutting down");
    })
    .await
}
