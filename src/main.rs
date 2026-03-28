mod blacklist;
mod config;
mod query_log;
mod resolver;
mod server;

use crate::blacklist::{build_blocklist, spawn_refresh_task, SharedBlocklist};
use crate::config::Config;
use crate::query_log::QueryLogger;
use crate::resolver::UpstreamResolver;
use crate::server::DnsServer;
use arc_swap::ArcSwap;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Explicitly install the ring crypto provider before any rustls code runs.
    // Required when multiple rustls-compatible providers are present in the dep tree
    // (e.g. ring via tokio-rustls and aws-lc-rs via reqwest), since rustls 0.23
    // cannot auto-select in that case.
    tokio_rustls::rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("Failed to install ring crypto provider (already installed?)"))?;

    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("dns_filter=info,warn")),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config_path = std::env::args()
        .nth(1)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(Config::default_path);

    let config = Arc::new(Config::load(&config_path)?);
    info!("Configuration loaded from {}", config_path.display());

    // Build initial blocklist before accepting any queries
    info!("Downloading and building initial blocklist...");
    let initial_state = build_blocklist(&config.blocklist).await;
    info!(
        domains = initial_state.domain_count,
        wildcards = initial_state.wildcard_count,
        errors = initial_state.source_errors.len(),
        "Initial blocklist ready"
    );
    for err in &initial_state.source_errors {
        tracing::warn!("Blocklist source error: {err}");
    }

    let shared_blocklist: SharedBlocklist = Arc::new(ArcSwap::from(initial_state));
    spawn_refresh_task(config.blocklist.clone(), Arc::clone(&shared_blocklist));

    let resolver = Arc::new(UpstreamResolver::new(
        &config.upstream.resolvers,
        config.upstream.timeout_ms,
    )?);
    info!(
        resolvers = ?config.upstream.resolvers.iter().map(|r| format!("{} ({})", r.addr, r.tls_name)).collect::<Vec<_>>(),
        "Upstream DoT resolvers configured"
    );

    let local_resolver = if let Some(addr) = config.upstream.local_resolver {
        info!(addr = %addr, "Local resolver configured — local queries bypass blocklist");
        Some(Arc::new(UpstreamResolver::new_local(addr, config.upstream.timeout_ms)?))
    } else {
        None
    };

    let logger = if config.logging.enabled {
        let l = QueryLogger::new(&config.logging)?;
        info!(
            db_path = %config.logging.db_path,
            retention_days = config.logging.retention_days,
            "Query logging enabled"
        );
        Some(l)
    } else {
        None
    };

    let server = Arc::new(DnsServer::new(
        Arc::clone(&config),
        Arc::clone(&resolver),
        local_resolver,
        Arc::clone(&shared_blocklist),
        logger,
    ));

    // Build TlsAcceptor for the DoT listener if configured
    let dot_acceptor = if let Some(dot_cfg) = &config.server.dot {
        Some((build_tls_acceptor(dot_cfg)?, dot_cfg.listen))
    } else {
        info!("DoT server not configured — skipping DoT listener");
        None
    };

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
        result = async {
            if let Some((acceptor, listen)) = dot_acceptor {
                Arc::clone(&server).run_dot(acceptor, listen).await
            } else {
                // No DoT configured: this branch never resolves
                std::future::pending::<anyhow::Result<()>>().await
            }
        } => {
            if let Err(e) = result {
                tracing::error!("DoT server exited with error: {e}");
                return Err(e);
            }
        },
        _ = shutdown => {
            info!("Shutting down cleanly");
        }
    }

    Ok(())
}

/// Load a PEM certificate chain and private key and build a rustls TlsAcceptor.
fn build_tls_acceptor(
    dot_cfg: &crate::config::DotConfig,
) -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    use rustls_pemfile::{certs, private_key};
    use std::fs::File;
    use std::io::BufReader;

    // Load certificate chain
    let cert_file = File::open(&dot_cfg.cert_pem)
        .map_err(|e| anyhow::anyhow!("Cannot open cert_pem {}: {e}", dot_cfg.cert_pem))?;
    let cert_chain: Vec<_> = certs(&mut BufReader::new(cert_file))
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("Failed to parse cert_pem: {e}"))?;
    if cert_chain.is_empty() {
        anyhow::bail!("No certificates found in {}", dot_cfg.cert_pem);
    }

    // Load private key
    let key_file = File::open(&dot_cfg.key_pem)
        .map_err(|e| anyhow::anyhow!("Cannot open key_pem {}: {e}", dot_cfg.key_pem))?;
    let private_key = private_key(&mut BufReader::new(key_file))
        .map_err(|e| anyhow::anyhow!("Failed to parse key_pem: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("No private key found in {}", dot_cfg.key_pem))?;

    let tls_config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|e| anyhow::anyhow!("TLS config error: {e}"))?;

    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(tls_config)))
}
