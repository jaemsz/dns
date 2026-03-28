use serde::Deserialize;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub upstream: UpstreamConfig,
    pub blocklist: BlocklistConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "LoggingConfig::default_db_path")]
    pub db_path: String,
    #[serde(default = "LoggingConfig::default_retention_days")]
    pub retention_days: u64,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            db_path: Self::default_db_path(),
            retention_days: Self::default_retention_days(),
        }
    }
}

impl LoggingConfig {
    fn default_db_path() -> String {
        "query_log.db".to_string()
    }
    fn default_retention_days() -> u64 {
        7
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub listen_udp: SocketAddr,
    /// DoT (DNS-over-TLS) listener. Optional — disabled if absent.
    pub dot: Option<DotConfig>,
    #[allow(dead_code)]
    pub udp_payload_size: u16,
    /// Log every DNS query to stdout. Defaults to false.
    #[serde(default)]
    pub debug: bool,
}

/// Incoming DNS-over-TLS server configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct DotConfig {
    /// Address to bind the DoT listener, e.g. "0.0.0.0:853"
    pub listen: SocketAddr,
    /// Path to PEM-encoded certificate chain (server cert + intermediates)
    pub cert_pem: String,
    /// Path to PEM-encoded private key
    pub key_pem: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfig {
    /// Upstream DoT resolvers, in priority order (rotated with failover).
    pub resolvers: Vec<UpstreamResolverEntry>,
    pub timeout_ms: u64,
    /// Original VPC/system DNS resolver for local queries (plain UDP).
    /// Local queries (from 127.0.0.1) bypass the blocklist and use this resolver.
    pub local_resolver: Option<SocketAddr>,
}

/// A single upstream DoT resolver.
#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamResolverEntry {
    /// IP:port, e.g. "8.8.8.8:853"
    pub addr: SocketAddr,
    /// TLS SNI name for certificate validation, e.g. "dns.google"
    pub tls_name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlocklistConfig {
    pub sources: Vec<BlocklistSource>,
    pub refresh_interval_secs: u64,
    pub block_response: BlockResponse,
    pub sinkhole_ipv4: Ipv4Addr,
    pub sinkhole_ipv6: Ipv6Addr,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlocklistSource {
    pub url: String,
    pub format: SourceFormat,
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SourceFormat {
    Hosts,
    Domains,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum BlockResponse {
    Nxdomain,
    Sinkhole,
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read config file {}: {e}", path.display()))?;
        let config: Config = toml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("Failed to parse config: {e}"))?;
        Ok(config)
    }

    pub fn default_path() -> PathBuf {
        PathBuf::from("config.toml")
    }
}
