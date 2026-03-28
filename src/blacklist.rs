use crate::config::{BlocklistConfig, BlocklistSource, SourceFormat};
use ahash::AHashSet;
use arc_swap::ArcSwap;
use bloomfilter::Bloom;
use std::sync::Arc;
use tracing::{info, warn};

/// Immutable blocklist state, built fresh on every refresh and atomically swapped in.
pub struct BlacklistState {
    /// Probabilistic pre-filter: fast "definitely NOT blocked" check.
    /// ~0.1% false positive rate keeps the HashSet out of the hot path for
    /// the vast majority of queries which go to legitimate domains.
    bloom: Bloom<str>,
    /// Exact domain match set (lowercase, no trailing dot). O(1) lookup.
    exact: AHashSet<String>,
    /// Parent-domain wildcard set: "evil.com" here blocks any "*.evil.com".
    wildcards: AHashSet<String>,

    pub domain_count: usize,
    pub wildcard_count: usize,
    pub source_errors: Vec<String>,
}

impl BlacklistState {
    /// Returns true if the domain should be blocked.
    pub fn is_blocked(&self, domain: &str) -> bool {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();

        // Fast path: bloom says "definitely not here" → allow immediately
        if !self.bloom.check(domain.as_str()) {
            return false;
        }

        // Exact match
        if self.exact.contains(&domain) {
            return true;
        }

        // Wildcard: walk up labels. "a.b.evil.com" checks "b.evil.com", "evil.com".
        // Bounded at 10 labels to prevent CPU exhaustion from adversarial inputs.
        let labels: Vec<&str> = domain.splitn(10, '.').collect();
        for i in 1..labels.len() {
            let parent = labels[i..].join(".");
            if self.wildcards.contains(&parent) {
                return true;
            }
        }

        false
    }
}

/// Shared handle to the live blocklist. ArcSwap gives lock-free reads and
/// atomic writer updates — no RwLock contention on the hot query path.
pub type SharedBlocklist = Arc<ArcSwap<BlacklistState>>;

/// Downloads all enabled sources and builds a fresh BlacklistState.
pub async fn build_blocklist(cfg: &BlocklistConfig) -> Arc<BlacklistState> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .user_agent("dns-filter/0.1 (blocklist-fetcher)")
        .build()
        .expect("reqwest client build failed");

    let mut exact: AHashSet<String> = AHashSet::with_capacity(5_000_000);
    let mut wildcards: AHashSet<String> = AHashSet::new();
    let mut errors: Vec<String> = Vec::new();

    for source in &cfg.sources {
        if !source.enabled {
            continue;
        }
        info!(url = %source.url, "Fetching blocklist source");
        match fetch_and_parse(&client, source).await {
            Ok((src_exact, src_wild)) => {
                info!(
                    url = %source.url,
                    exact = src_exact.len(),
                    wildcards = src_wild.len(),
                    "Source loaded"
                );
                exact.extend(src_exact);
                wildcards.extend(src_wild);
            }
            Err(e) => {
                let msg = format!("Failed to load {}: {e}", source.url);
                warn!("{}", msg);
                errors.push(msg);
            }
        }
    }

    // Size bloom filter for all entries with 0.1% false positive rate
    let total = (exact.len() + wildcards.len()).max(1);
    let mut bloom = Bloom::new_for_fp_rate(total, 0.001);
    for d in &exact {
        bloom.set(d.as_str());
    }
    for d in &wildcards {
        bloom.set(d.as_str());
    }

    let domain_count = exact.len();
    let wildcard_count = wildcards.len();
    info!(domain_count, wildcard_count, "Blocklist built");

    Arc::new(BlacklistState {
        bloom,
        exact,
        wildcards,
        domain_count,
        wildcard_count,
        source_errors: errors,
    })
}

async fn fetch_and_parse(
    client: &reqwest::Client,
    source: &BlocklistSource,
) -> anyhow::Result<(Vec<String>, Vec<String>)> {
    let resp = client.get(&source.url).send().await?;
    // Guard against oversized responses (max 50MB)
    if let Some(len) = resp.content_length() {
        if len > 50 * 1024 * 1024 {
            anyhow::bail!("Response too large ({len} bytes), skipping");
        }
    }
    let text = resp.text().await?;

    let mut exact = Vec::new();
    let mut wildcards = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        // Strip inline comments
        let line = match line.find('#') {
            Some(pos) => line[..pos].trim(),
            None => line,
        };
        if line.is_empty() {
            continue;
        }

        match source.format {
            SourceFormat::Hosts => {
                // Format: "0.0.0.0 ads.example.com" or "127.0.0.1 ads.example.com"
                let mut parts = line.split_whitespace();
                let _ip = match parts.next() {
                    Some(ip) => ip,
                    None => continue,
                };
                let domain = match parts.next() {
                    Some(d) => d.to_ascii_lowercase(),
                    None => continue,
                };
                // Skip well-known non-domain entries
                if matches!(
                    domain.as_str(),
                    "localhost" | "0.0.0.0" | "broadcasthost" | "local"
                ) {
                    continue;
                }
                // Skip entries that look like IP addresses
                if domain.parse::<std::net::IpAddr>().is_ok() {
                    continue;
                }
                exact.push(domain);
            }
            SourceFormat::Domains => {
                // One domain per line; wildcard lines start with "*."
                if let Some(parent) = line.strip_prefix("*.") {
                    wildcards.push(parent.to_ascii_lowercase());
                } else {
                    exact.push(line.to_ascii_lowercase());
                }
            }
        }
    }

    Ok((exact, wildcards))
}

/// Spawn a background task that periodically rebuilds and hot-swaps the blocklist.
pub fn spawn_refresh_task(
    cfg: BlocklistConfig,
    shared: SharedBlocklist,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let interval = std::time::Duration::from_secs(cfg.refresh_interval_secs);
        loop {
            tokio::time::sleep(interval).await;
            info!("Refreshing blocklist...");
            let new_state = build_blocklist(&cfg).await;
            shared.store(new_state);
            info!("Blocklist hot-swapped successfully");
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state(exact: &[&str], wildcards: &[&str]) -> BlacklistState {
        let mut exact_set: AHashSet<String> = AHashSet::new();
        let mut wildcard_set: AHashSet<String> = AHashSet::new();

        for d in exact {
            exact_set.insert(d.to_string());
        }
        for d in wildcards {
            wildcard_set.insert(d.to_string());
        }

        let total = (exact_set.len() + wildcard_set.len()).max(1);
        let mut bloom = Bloom::new_for_fp_rate(total, 0.001);
        for d in &exact_set {
            bloom.set(d.as_str());
        }
        for d in &wildcard_set {
            bloom.set(d.as_str());
        }

        BlacklistState {
            bloom,
            exact: exact_set,
            wildcards: wildcard_set,
            domain_count: exact.len(),
            wildcard_count: wildcards.len(),
            source_errors: vec![],
        }
    }

    #[test]
    fn exact_match_blocked() {
        let state = make_state(&["ads.evil.com"], &[]);
        assert!(state.is_blocked("ads.evil.com"));
        assert!(state.is_blocked("ads.evil.com.")); // trailing dot
        assert!(!state.is_blocked("good.com"));
    }

    #[test]
    fn wildcard_match_blocked() {
        let state = make_state(&[], &["evil.com"]);
        assert!(state.is_blocked("sub.evil.com"));
        assert!(state.is_blocked("deep.sub.evil.com"));
        assert!(!state.is_blocked("evil.com")); // exact not matched by wildcard
        assert!(!state.is_blocked("notevil.com"));
    }

    #[test]
    fn case_insensitive() {
        let state = make_state(&["ADS.EVIL.COM"], &[]);
        assert!(state.is_blocked("ADS.EVIL.COM"));
        assert!(state.is_blocked("ads.evil.com"));
        assert!(state.is_blocked("Ads.Evil.Com"));
    }

    #[test]
    fn legitimate_domain_allowed() {
        let state = make_state(&["ads.example.com"], &["tracker.io"]);
        assert!(!state.is_blocked("google.com"));
        assert!(!state.is_blocked("github.com"));
        assert!(!state.is_blocked("example.com"));
    }
}
