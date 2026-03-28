#!/usr/bin/env bash
set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/dns-filter"
SERVICE_NAME="dns-filter"
SERVICE_USER="dns-filter"
BINARY_NAME="dns-filter"

# ── Preflight checks ─────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root (sudo ./install.sh)"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ ! -f "$SCRIPT_DIR/target/release/$BINARY_NAME" ]]; then
    echo "Release binary not found. Building..."
    cd "$SCRIPT_DIR"
    cargo build --release
fi

if [[ ! -f "$SCRIPT_DIR/config.toml" ]]; then
    echo "Error: config.toml not found in $SCRIPT_DIR"
    exit 1
fi

# ── Stop and disable systemd-resolved (frees port 53) ────────────────────────
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    echo "Stopping and disabling systemd-resolved to free port 53..."
    systemctl stop systemd-resolved
    systemctl disable systemd-resolved
fi

# Replace the symlink /etc/resolv.conf with a static file pointing to localhost
rm -f /etc/resolv.conf
cat > /etc/resolv.conf <<EOF
# Managed by dns-filter install script
nameserver 127.0.0.1
nameserver 8.8.8.8
EOF

# Prevent NetworkManager or cloud-init from overwriting resolv.conf
if command -v chattr &>/dev/null; then
    chattr +i /etc/resolv.conf 2>/dev/null || true
fi

# ── Create service user (no login, no home) ───────────────────────────────────
if ! id "$SERVICE_USER" &>/dev/null; then
    echo "Creating service user: $SERVICE_USER"
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

# ── Install files ─────────────────────────────────────────────────────────────
echo "Installing to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

cp "$SCRIPT_DIR/target/release/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
cp "$SCRIPT_DIR/config.toml" "$INSTALL_DIR/config.toml"

# Copy TLS certs if they exist
if [[ -f "$SCRIPT_DIR/cert.pem" ]]; then
    cp "$SCRIPT_DIR/cert.pem" "$INSTALL_DIR/cert.pem"
fi
if [[ -f "$SCRIPT_DIR/key.pem" ]]; then
    cp "$SCRIPT_DIR/key.pem" "$INSTALL_DIR/key.pem"
    chmod 640 "$INSTALL_DIR/key.pem"
fi

chown -R "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR"
chmod 755 "$INSTALL_DIR/$BINARY_NAME"

# Grant port-binding capability so the binary can use ports 53/853 without root
setcap cap_net_bind_service+ep "$INSTALL_DIR/$BINARY_NAME"

# ── Update config.toml to use production ports ────────────────────────────────
sed -i 's/listen_udp\s*=\s*"0\.0\.0\.0:5353"/listen_udp = "0.0.0.0:53"/' "$INSTALL_DIR/config.toml"
sed -i 's/listen\s*=\s*"0\.0\.0\.0:8853"/listen   = "0.0.0.0:853"/' "$INSTALL_DIR/config.toml"

# ── Create systemd unit ──────────────────────────────────────────────────────
echo "Creating systemd service: $SERVICE_NAME"
cat > /etc/systemd/system/${SERVICE_NAME}.service <<EOF
[Unit]
Description=DNS Filtering Server (DoT)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/$BINARY_NAME $INSTALL_DIR/config.toml
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/
ReadWritePaths=$INSTALL_DIR
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true

# Allow binding to privileged ports via ambient capabilities
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

# ── Enable and start ─────────────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"

# ── Verify ────────────────────────────────────────────────────────────────────
sleep 2
echo ""
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo "=== Installation complete ==="
else
    echo "=== WARNING: Service failed to start ==="
    echo "Check logs: sudo journalctl -u $SERVICE_NAME -n 20"
fi
echo ""
echo "  Binary:  $INSTALL_DIR/$BINARY_NAME"
echo "  Config:  $INSTALL_DIR/config.toml"
echo "  Service: $SERVICE_NAME"
echo ""
echo "Useful commands:"
echo "  sudo systemctl status $SERVICE_NAME    # check status"
echo "  sudo journalctl -u $SERVICE_NAME -f    # follow logs"
echo "  sudo systemctl restart $SERVICE_NAME   # restart after config change"
echo "  dig @127.0.0.1 google.com              # test query"
