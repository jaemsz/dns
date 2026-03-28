use serde::Deserialize;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub upstream: UpstreamConfig,
    pub blocklist: BlocklistConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub listen_udp: SocketAddr,
    #[allow(dead_code)]
    pub listen_tcp: Option<SocketAddr>,
    #[allow(dead_code)]
    pub udp_payload_size: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfig {
    pub resolvers: Vec<SocketAddr>,
    pub timeout_ms: u64,
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
