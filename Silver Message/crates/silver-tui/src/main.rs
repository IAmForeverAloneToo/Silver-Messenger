//! Silver Message terminal client.

mod app;
mod ui;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use silver_client::{Client, DEFAULT_RELAY_URL, Store};
use tracing_subscriber::EnvFilter;

/// End-to-end encrypted messaging in your terminal.
#[derive(Parser, Debug)]
#[command(name = "silver", version, about)]
struct Args {
    /// Relay WebSocket URL, e.g. ws://relay.example.org:7777/ws. Remembered
    /// for later runs.
    #[arg(long, env = "SILVER_RELAY")]
    relay: Option<String>,

    /// Directory for keys, contacts and history (default: platform data dir).
    #[arg(long, env = "SILVER_DATA_DIR")]
    data_dir: Option<PathBuf>,

    /// Print your user id and exit.
    #[arg(long)]
    print_id: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let data_dir = args
        .data_dir
        .or_else(Store::default_dir)
        .context("could not determine a data directory; pass --data-dir")?;
    let store = Store::open(&data_dir)?;

    let (identity, created) = store.load_or_create_identity()?;
    if args.print_id {
        println!("{}", identity.user_id());
        return Ok(());
    }

    let mut config = store.load_config()?;
    if let Some(relay) = args.relay {
        config.relay_url = Some(relay);
        store.save_config(&config)?;
    }
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

    let (client, events) = Client::spawn(relay_url.clone(), Arc::new(identity));
    let app = app::App::new(store, client, relay_url, created)?;

    let terminal = ratatui::init();
    let result = app.run(terminal, events).await;
    ratatui::restore();
    result
}
