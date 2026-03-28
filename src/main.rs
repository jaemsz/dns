mod blacklist;
mod config;
mod resolver;
mod server;

use crate::blacklist::{build_blocklist, spawn_refresh_task, SharedBlocklist};
use crate::config::Config;
use crate::resolver::UpstreamResolver;
use crate::server::DnsServer;
use arc_swap::ArcSwap;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize structured logging (controlled by RUST_LOG env var, defaults to info)
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("dns_filter=info,warn")),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Config path from first CLI arg or default "config.toml"
    let config_path = std::env::args()
        .nth(1)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(Config::default_path);

    let config = Arc::new(Config::load(&config_path)?);
    info!("Configuration loaded from {}", config_path.display());

    // Build initial blocklist — must succeed before accepting queries
    info!("Downloading and building initial blocklist...");
    let initial_state = build_blocklist(&config.blocklist).await;
    info!(
        domains = initial_state.domain_count,
        wildcards = initial_state.wildcard_count,
        errors = initial_state.source_errors.len(),
        "Initial blocklist ready"
    );
    if !initial_state.source_errors.is_empty() {
        for err in &initial_state.source_errors {
            tracing::warn!("Blocklist source error: {err}");
        }
    }

    // Wrap in ArcSwap for lock-free hot-reload
    let shared_blocklist: SharedBlocklist = Arc::new(ArcSwap::from(initial_state));

    // Spawn background refresh task
    spawn_refresh_task(config.blocklist.clone(), Arc::clone(&shared_blocklist));

    // Build upstream resolver
    let resolver = Arc::new(UpstreamResolver::new(
        &config.upstream.resolvers,
        config.upstream.timeout_ms,
    )?);
    info!(
        resolvers = ?config.upstream.resolvers,
        "Upstream resolvers configured"
    );

    // Build server
    let server = Arc::new(DnsServer::new(
        Arc::clone(&config),
        Arc::clone(&resolver),
        Arc::clone(&shared_blocklist),
    ));

    // Graceful shutdown on Ctrl-C / SIGTERM
    let shutdown = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
        info!("Shutdown signal received, stopping...");
    };

    tokio::select! {
        result = Arc::clone(&server).run_udp() => {
            if let Err(e) = result {
                tracing::error!("UDP server exited with error: {e}");
                return Err(e);
            }
        },
        _ = shutdown => {
            info!("Shutting down cleanly");
        }
    }

    Ok(())
}
