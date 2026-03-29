# dns

A DNS filtering server written in Rust that blocks malicious and ad-serving domains using crowd-sourced blocklists. Queries are forwarded to upstream resolvers over DNS-over-TLS (DoT) for encrypted resolution. Includes a DoT listener for encrypted client connections (e.g. from [dns-proxy](https://github.com/jaemsz/dns-proxy/)).

## Features

- **Domain blocking** — Downloads and merges blocklists from GitHub (StevenBlack, HaGezi). Lookups use a Bloom filter + HashSet for fast, memory-efficient matching with exact and wildcard support.
- **DNS-over-TLS** — All upstream queries are encrypted (Google DNS, Cloudflare). Incoming DoT listener on port 853 for encrypted client connections.
- **Hot-reload** — Blocklist refreshes daily and swaps in atomically (lock-free via ArcSwap). No downtime, no query drops.
- **Local query bypass** — Queries from localhost skip the blocklist and use the original VPC DNS resolver, so EC2 services like SSM and metadata work normally.
- **Query logging** — Stores 7 days of queries in SQLite (WAL mode, batched async writes). Records domain, query type, source IP, action (allowed/blocked/local), and resolved IP.
- **Block responses** — Configurable: NXDOMAIN (domain doesn't exist) or sinkhole (returns 0.0.0.0).

## Architecture

```
Client (UDP :53) ──────────────────┐
                                   ▼
dns-proxy (macOS) ── DoT :853 ──> dns (EC2)
                                   │
                         ┌─────────┴─────────┐
                         ▼                   ▼
                   Blocklist check     Local bypass
                   (Bloom + HashSet)   (VPC DNS)
                         │                   │
                    blocked?                 │
                   ┌──┴──┐                  │
                   ▼     ▼                  ▼
              NXDOMAIN  Sinkhole      VPC resolver
                                     (plain UDP)
                   allowed?
                      │
                      ▼
               Upstream DoT
          (Google DNS, Cloudflare)
                      │
                      ▼
                 SQLite log
```

## Prerequisites

- AWS EC2 instance running Ubuntu
- Rust toolchain (`rustup`, `cargo`)

## Build

```bash
cargo build --release
```

## Install on AWS EC2

The install script handles everything: stops systemd-resolved, captures the original VPC DNS, creates a system user, installs the binary, generates a self-signed TLS cert, and starts the service.

```bash
# Build first
cargo build --release

# Generate TLS cert for DoT listener
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
  -days 365 -nodes -subj "/CN=dns-filter"

# Install (requires root)
sudo ./install.sh
```

### What install.sh does

1. Stops and disables `systemd-resolved` to free port 53
2. Captures the original VPC DNS resolver (typically `x.x.x.2`) for local query bypass
3. Sets `/etc/resolv.conf` to `127.0.0.1` and marks it immutable
4. Creates a `dns-filter` system user
5. Copies the binary, config, and TLS certs to `/opt/dns-filter/`
6. Grants `CAP_NET_BIND_SERVICE` so the binary can bind ports 53/853 without root
7. Updates config.toml for production (port 53, port 853, VPC DNS, db path)
8. Creates and starts a systemd service with security hardening

### Systemd service

The service runs as the unprivileged `dns-filter` user with:
- `ProtectSystem=strict` — read-only filesystem except `/opt/dns-filter`
- `ProtectHome=true` — no access to home directories
- `NoNewPrivileges=true`
- Auto-restart on failure (5s delay)

```bash
# Service management
sudo systemctl status dns-filter
sudo systemctl restart dns-filter
sudo journalctl -u dns-filter -f
```

## Configuration

Edit `/opt/dns-filter/config.toml` (or `config.toml` for local development):

```toml
[server]
listen_udp = "0.0.0.0:53"
debug      = true                # log every query to stdout

[server.dot]
listen   = "0.0.0.0:853"
cert_pem = "cert.pem"
key_pem  = "key.pem"

[upstream]
timeout_ms = 3000
local_resolver = "172.31.0.2:53" # auto-set by install.sh

[[upstream.resolvers]]
addr     = "8.8.8.8:853"
tls_name = "dns.google"

[[upstream.resolvers]]
addr     = "1.1.1.1:853"
tls_name = "cloudflare-dns.com"

[logging]
enabled        = true
db_path        = "/opt/dns-filter/query_log.db"
retention_days = 7

[blocklist]
refresh_interval_secs = 86400
block_response        = "nxdomain"   # or "sinkhole"
sinkhole_ipv4         = "0.0.0.0"
sinkhole_ipv6         = "::"

[[blocklist.sources]]
url     = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
format  = "hosts"
enabled = true

[[blocklist.sources]]
url     = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt"
format  = "domains"
enabled = true

[[blocklist.sources]]
url     = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.txt"
format  = "domains"
enabled = true
```

## Verify

```bash
# Should resolve normally
dig @127.0.0.1 google.com

# Should return NXDOMAIN (blocked)
dig @127.0.0.1 ads.facebook.com

# Test DoT listener
kdig @127.0.0.1#853 +tls google.com
```

## Query log

The SQLite database at `/opt/dns-filter/query_log.db` stores all queries. Use the [dns-web](https://github.com/jaemsz/dns-web/) dashboard to view and filter the logs, or query directly:

```bash
sqlite3 /opt/dns-filter/query_log.db "SELECT * FROM query_log ORDER BY ts DESC LIMIT 10;"
```

## Run locally (development)

```bash
# Uses dev ports 5353/8853 from config.toml
sudo cargo run -- config.toml
dig @127.0.0.1 -p 5353 google.com
```

## Uninstall

```bash
sudo systemctl stop dns-filter
sudo systemctl disable dns-filter
sudo rm /etc/systemd/system/dns-filter.service
sudo systemctl daemon-reload
sudo rm -rf /opt/dns-filter
sudo userdel dns-filter

# Restore systemd-resolved
sudo chattr -i /etc/resolv.conf
sudo systemctl enable systemd-resolved
sudo systemctl start systemd-resolved
sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
```
