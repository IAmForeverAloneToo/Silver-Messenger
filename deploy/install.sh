#!/usr/bin/env bash
# Install or update the Silver Message relay on a Linux server (Debian/Ubuntu
# or Fedora/RHEL family) and run it as a hardened systemd service.
#
# One-liner, as root:
#   curl -fsSL https://raw.githubusercontent.com/IAmForeverAloneToo/Silver-Messanger/main/deploy/install.sh | bash
#
# Re-running it pulls the latest code, rebuilds, and restarts the service.
#
# Environment overrides:
#   SILVER_RELAY_LISTEN  address:port to listen on   (default 0.0.0.0:7777; only used on first install)
#   SILVER_BRANCH        git branch to deploy         (default main)
#   SILVER_REPO          git repository URL
#   SILVER_SRC_DIR       where the source is checked out (default /opt/silver-messanger)
set -euo pipefail

REPO_URL="${SILVER_REPO:-https://github.com/IAmForeverAloneToo/Silver-Messanger.git}"
BRANCH="${SILVER_BRANCH:-main}"
SRC_DIR="${SILVER_SRC_DIR:-/opt/silver-messanger}"
LISTEN="${SILVER_RELAY_LISTEN:-0.0.0.0:7777}"
SERVICE_USER=silver
BIN=/usr/local/bin/silver-relay
UNIT=/etc/systemd/system/silver-relay.service
ENV_DIR=/etc/silver-relay
ENV_FILE="$ENV_DIR/relay.env"

log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run this script as root"
command -v systemctl >/dev/null || die "this script expects a systemd-based distribution"

# --- 1. build dependencies ----------------------------------------------------
log "Installing build dependencies"
if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq build-essential curl git pkg-config ca-certificates
elif command -v dnf >/dev/null; then
    dnf install -y -q gcc make curl git pkgconf-pkg-config ca-certificates
else
    die "unsupported distribution: need apt-get or dnf"
fi

# --- 2. swap on small machines ------------------------------------------------
# A release build of the relay peaks at roughly 500 MB; give 1 GB boxes headroom.
mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
if [ "$mem_mb" -lt 2048 ] && [ ! -f /swapfile ]; then
    log "Adding a 2 GB swap file (machine has ${mem_mb} MB of RAM)"
    fallocate -l 2G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
    chmod 600 /swapfile
    mkswap -q /swapfile
    swapon /swapfile
    grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >>/etc/fstab
fi

# --- 3. rust toolchain --------------------------------------------------------
export CARGO_HOME="${CARGO_HOME:-/root/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-/root/.rustup}"
export PATH="$CARGO_HOME/bin:$PATH"
if ! command -v cargo >/dev/null; then
    log "Installing Rust (rustup, minimal profile)"
    curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --no-modify-path
fi

# --- 4. source ----------------------------------------------------------------
if [ -d "$SRC_DIR/.git" ]; then
    log "Updating $SRC_DIR from $BRANCH"
    git -C "$SRC_DIR" fetch -q origin "$BRANCH"
    git -C "$SRC_DIR" checkout -q -B "$BRANCH" "origin/$BRANCH"
else
    log "Cloning $REPO_URL ($BRANCH) into $SRC_DIR"
    git clone -q --branch "$BRANCH" "$REPO_URL" "$SRC_DIR"
fi
log "Deploying commit $(git -C "$SRC_DIR" rev-parse --short HEAD)"

# --- 5. build -----------------------------------------------------------------
log "Building the relay (this takes a few minutes on a small VPS)"
(cd "$SRC_DIR" && cargo build --release -p silver-relay)
install -m 755 "$SRC_DIR/target/release/silver-relay" "$BIN.new"
mv -f "$BIN.new" "$BIN"

# --- 6. service user, config, unit -------------------------------------------
log "Installing the systemd service"
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi
mkdir -p "$ENV_DIR"
if [ ! -f "$ENV_FILE" ]; then
    printf 'SILVER_RELAY_LISTEN=%s\nRUST_LOG=info\n' "$LISTEN" >"$ENV_FILE"
fi
chmod 640 "$ENV_FILE"
chgrp "$SERVICE_USER" "$ENV_FILE"
install -D -m 644 "$SRC_DIR/deploy/silver-relay.service" "$UNIT"
systemctl daemon-reload
systemctl enable -q silver-relay
systemctl restart silver-relay

# --- 7. firewall --------------------------------------------------------------
listen=$(sed -n 's/^SILVER_RELAY_LISTEN=//p' "$ENV_FILE")
port="${listen##*:}"
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
    log "Opening port $port/tcp in ufw"
    ufw allow "$port/tcp" >/dev/null
fi
if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    log "Opening port $port/tcp in firewalld"
    firewall-cmd -q --permanent --add-port="$port/tcp"
    firewall-cmd -q --reload
fi

# --- 8. health check ----------------------------------------------------------
log "Checking the relay"
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
if ! curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1; then
    journalctl -u silver-relay -n 30 --no-pager || true
    die "the relay did not come up; see the log above"
fi

public_ip=$(curl -fsS -4 --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')
cat <<MSG

Silver Message relay is running.

  service:  systemctl status silver-relay
  logs:     journalctl -u silver-relay -f
  config:   $ENV_FILE
  update:   re-run this script

Clients connect with:

  silver --relay ws://$public_ip:$port/ws

If the port is not reachable from outside, also allow $port/tcp in your
hosting provider's firewall (for example the Vultr firewall group).
MSG
