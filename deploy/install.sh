#!/usr/bin/env bash
# Install or update the Silver Messenger relay on a Linux server (Debian/Ubuntu
# or Fedora/RHEL family) and run it as a hardened systemd service.
#
# Two ways to use it:
#
#   * Prebuilt (what the "Deploy relay" GitHub workflow does): put a
#     `silver-relay` binary and `silver-relay.service` next to this script and
#     run it. The server needs no compiler and no access to the repository.
#
#   * From source: with nothing next to it, the script installs Rust, clones
#     the repository and builds the relay. The repository must be reachable
#     from the server (public, or SILVER_REPO carrying credentials).
#
#     Download it, check it against the release's SHA256SUMS, then run it,
#     rather than piping it from the network into a shell:
#       curl -fsSLO https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/latest/download/install.sh
#       curl -fsSLO https://github.com/IAmForeverAloneToo/Silver-Messenger/releases/latest/download/SHA256SUMS
#       grep ' install.sh$' SHA256SUMS | sha256sum -c -
#       sudo bash install.sh
#
# Re-running it updates the relay and restarts the service.
#
# Environment overrides:
#   SILVER_RELAY_LISTEN  address:port to listen on (only used on first install).
#                        The default is 0.0.0.0:7777 with SILVER_DOMAIN set or
#                        SILVER_ALLOW_PLAINTEXT=1, and 127.0.0.1:7777 without
#                        either: a public port with no TLS is not something to
#                        get by accident.
#   SILVER_DOMAIN        hostname that points at this server. The relay then
#                        serves TLS on port 443 itself, with a Let's Encrypt
#                        certificate it obtains and renews, so clients use
#                        wss://<domain>/ws. Remembered.
#   SILVER_EMAIL         address Let's Encrypt may write to about the certificate
#                        (optional; only used with SILVER_DOMAIN)
#   SILVER_TLS           builtin (default for new installs) or caddy: a Caddy front
#                        as the installer set up before 0.7.0. An install that
#                        already runs Caddy keeps it unless SILVER_TLS=builtin is
#                        given, which switches it over and stops Caddy.
#   SILVER_BINARY        path to a prebuilt relay binary (default: silver-relay next to this script)
#   SILVER_BRANCH        git branch to deploy         (default main)
#   SILVER_REPO          git repository URL
#   SILVER_SRC_DIR       where the source is checked out (default /opt/silver-messenger)
#   SILVER_ALLOW_PLAINTEXT=1
#                        allow a listener on a public address without TLS. Set
#                        SILVER_DOMAIN instead unless the relay sits behind a
#                        TLS front you run yourself; without a domain and
#                        without this the listener is 127.0.0.1.
#   SILVER_PUBLIC_IP     the address to print in the "clients connect with"
#                        line. Without it the script uses the machine's own
#                        first address and does not ask anyone on the internet.
#
# A private repository: SILVER_REPO=https://<token>@github.com/<owner>/<repo>.git
# works, but git writes that URL into $SILVER_SRC_DIR/.git/config, so the
# token sits in a file on the server for as long as the checkout does. A
# deploy key or the "Deploy relay" workflow leaves nothing behind.
set -euo pipefail

REPO_URL="${SILVER_REPO:-https://github.com/IAmForeverAloneToo/Silver-Messenger.git}"
BRANCH="${SILVER_BRANCH:-main}"
SRC_DIR="${SILVER_SRC_DIR:-/opt/silver-messenger}"
LISTEN="${SILVER_RELAY_LISTEN:-}"
SERVICE_USER=silver
BIN=/usr/local/bin/silver-relay
UNIT=/etc/systemd/system/silver-relay.service
ENV_DIR=/etc/silver-relay
ENV_FILE="$ENV_DIR/relay.env"

# When run as a file (not piped), look for a prebuilt binary next to it.
HERE=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
fi
PREBUILT="${SILVER_BINARY:-${HERE:+$HERE/silver-relay}}"

log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# What to listen on when nothing says. With a domain the relay serves TLS on
# 443 itself (section 7 rewrites this). Without one, a public address would
# be plaintext WebSocket, which the README does not offer as a default and
# which nobody should get by accident: loopback unless the operator asks for
# more (SM-S-03).
if [ -z "$LISTEN" ]; then
    if [ -n "${SILVER_DOMAIN:-}" ] || [ "${SILVER_ALLOW_PLAINTEXT:-}" = 1 ]; then
        LISTEN=0.0.0.0:7777
    else
        LISTEN=127.0.0.1:7777
    fi
fi
case "$LISTEN" in
    127.0.0.1:* | localhost:* | '[::1]':*) ;;
    *)
        if [ -z "${SILVER_DOMAIN:-}" ] && [ "${SILVER_ALLOW_PLAINTEXT:-}" != 1 ]; then
            die "SILVER_RELAY_LISTEN=$LISTEN is a public address with no TLS. Set SILVER_DOMAIN=<hostname> so the relay serves wss:// itself, or SILVER_ALLOW_PLAINTEXT=1 if something in front of it terminates TLS."
        fi
        ;;
esac

[ "$(id -u)" -eq 0 ] || die "run this script as root"
command -v systemctl >/dev/null || die "this script expects a systemd-based distribution"
command -v curl >/dev/null || die "curl is required"

if [ -n "$PREBUILT" ] && [ -f "$PREBUILT" ]; then
    # ------------------------------------------------------------------ prebuilt
    log "Installing prebuilt relay from $PREBUILT"
    UNIT_SRC="${SILVER_UNIT:-$(dirname "$PREBUILT")/silver-relay.service}"
    [ -f "$UNIT_SRC" ] || die "expected the unit file at $UNIT_SRC"
    install -m 755 "$PREBUILT" "$BIN.new"
else

    # ---- 1. build dependencies ----------------------------------------------------
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

    # ---- 2. swap on small machines ------------------------------------------------
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

    # ---- 3. rust toolchain --------------------------------------------------------
    export CARGO_HOME="${CARGO_HOME:-/root/.cargo}"
    export RUSTUP_HOME="${RUSTUP_HOME:-/root/.rustup}"
    export PATH="$CARGO_HOME/bin:$PATH"
    if ! command -v cargo >/dev/null; then
        log "Installing Rust (rustup, minimal profile)"
        # rustup-init itself, from the Rust project's own host, checked
        # against the SHA-256 it publishes next to it, rather than piping
        # sh.rustup.rs into a shell unchecked (SM-S-03).
        case "$(uname -m)" in
            x86_64)          rust_triple=x86_64-unknown-linux-gnu ;;
            aarch64 | arm64) rust_triple=aarch64-unknown-linux-gnu ;;
            *) die "no rustup build for $(uname -m); install Rust yourself and re-run" ;;
        esac
        rust_url="https://static.rust-lang.org/rustup/dist/$rust_triple/rustup-init"
        tmp=$(mktemp -d)
        curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/rustup-init" "$rust_url"
        curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/rustup-init.sha256" "$rust_url.sha256"
        # The published file is "<hash>  rustup-init"; check it where the
        # download is, whatever path it names.
        (cd "$tmp" && printf '%s  rustup-init\n' "$(cut -d' ' -f1 rustup-init.sha256)" | sha256sum -c -) ||
            die "rustup-init does not match the checksum static.rust-lang.org publishes for it"
        chmod +x "$tmp/rustup-init"
        "$tmp/rustup-init" -y --profile minimal --no-modify-path
        rm -rf "$tmp"
    fi

    # ---- 4. source ----------------------------------------------------------------
    # The repository used to be checked out under a misspelled name.
    if [ ! -d "$SRC_DIR" ] && [ -d /opt/silver-messanger ]; then
        mv /opt/silver-messanger "$SRC_DIR"
    fi
    if [ -d "$SRC_DIR/.git" ]; then
        log "Updating $SRC_DIR from $BRANCH"
        git -C "$SRC_DIR" fetch -q origin "$BRANCH"
        git -C "$SRC_DIR" checkout -q -B "$BRANCH" "origin/$BRANCH"
    else
        log "Cloning $REPO_URL ($BRANCH) into $SRC_DIR"
        git clone -q --branch "$BRANCH" "$REPO_URL" "$SRC_DIR" ||
            die "clone failed. Is the repository public? For a private one either run the Deploy relay workflow, or set SILVER_REPO=https://<token>@github.com/<owner>/<repo>.git"
    fi
    log "Deploying commit $(git -C "$SRC_DIR" rev-parse --short HEAD)"

    # ---- 5. build -----------------------------------------------------------------
    log "Building the relay (this takes a few minutes on a small VPS)"
    (cd "$SRC_DIR" && cargo build --release -p silver-relay)
    install -m 755 "$SRC_DIR/target/release/silver-relay" "$BIN.new"
    UNIT_SRC="$SRC_DIR/deploy/silver-relay.service"

fi
mv -f "$BIN.new" "$BIN"

# --- 6. service user, config, unit -------------------------------------------
log "Installing the systemd service"
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi
mkdir -p "$ENV_DIR"
if [ ! -f "$ENV_FILE" ]; then
    printf 'SILVER_RELAY_LISTEN=%s\nRUST_LOG=info\n# silver-relay admin ... talks to the relay here (root, or the silver user):\nSILVER_RELAY_ADMIN_SOCKET=/run/silver-relay/admin.sock\n# Uncomment to only let people with this token register new identities:\n# SILVER_RELAY_INVITE_TOKEN=change-me\n# Messages an unauthenticated connection may submit per minute (0 turns anonymous submission off):\n# SILVER_RELAY_ANONYMOUS_SENDS_PER_MINUTE=30\n# Encrypted files: largest file in MiB (0 turns file transfer off) and total storage in MiB:\n# SILVER_RELAY_MAX_BLOB_MIB=16\n# SILVER_RELAY_BLOB_STORAGE_MIB=1024\n# Prometheus metrics on a private address (never the public one), and JSON logs for a collector:\n# SILVER_RELAY_METRICS_LISTEN=127.0.0.1:9107\n# SILVER_RELAY_LOG_FORMAT=json\n' "$LISTEN" >"$ENV_FILE"
fi
# Installs from before 0.7.0 have no admin socket configured; add it.
if ! grep -q '^SILVER_RELAY_ADMIN_SOCKET=' "$ENV_FILE"; then
    echo 'SILVER_RELAY_ADMIN_SOCKET=/run/silver-relay/admin.sock' >>"$ENV_FILE"
fi
chmod 640 "$ENV_FILE"
chgrp "$SERVICE_USER" "$ENV_FILE"
install -D -m 644 "$UNIT_SRC" "$UNIT"
# A nightly backup into the state directory (deploy/silver-relay-backup.*),
# when the units came along with the service file.
UNIT_DIR=$(dirname "$UNIT_SRC")
BACKUP_TIMER=0
if [ -f "$UNIT_DIR/silver-relay-backup.service" ] && [ -f "$UNIT_DIR/silver-relay-backup.timer" ]; then
    install -D -m 644 "$UNIT_DIR/silver-relay-backup.service" /etc/systemd/system/silver-relay-backup.service
    install -D -m 644 "$UNIT_DIR/silver-relay-backup.timer" /etc/systemd/system/silver-relay-backup.timer
    BACKUP_TIMER=1
fi
systemctl daemon-reload
systemctl enable -q silver-relay
systemctl restart silver-relay
if [ "$BACKUP_TIMER" = 1 ]; then
    systemctl enable -q --now silver-relay-backup.timer
fi

# --- 7. HTTPS ------------------------------------------------------------------
DOMAIN="${SILVER_DOMAIN:-$(sed -n 's/^SILVER_DOMAIN=//p' "$ENV_FILE")}"
# Which way TLS is done: the relay itself, or Caddy in front. An install
# that already has the installer's Caddyfile keeps Caddy unless told otherwise.
CADDY_MARK="Managed by the Silver Messenger relay installer"
if [ -z "${SILVER_TLS:-}" ]; then
    if grep -qs "$CADDY_MARK" /etc/caddy/Caddyfile 2>/dev/null && systemctl is-enabled -q caddy 2>/dev/null; then
        SILVER_TLS=caddy
    else
        SILVER_TLS=builtin
    fi
fi
set_env() { # set_env KEY VALUE: set or replace KEY in the relay's environment file
    # Written with awk rather than sed: a value is operator-supplied and a
    # sed replacement reads & and the delimiter, so a domain with one in it
    # corrupted the file (SM-S-03).
    if grep -q "^$1=" "$ENV_FILE"; then
        awk -v key="$1" -v value="$2" \
            'index($0, key "=") == 1 { print key "=" value; next } { print }' \
            "$ENV_FILE" >"$ENV_FILE.new"
        cat "$ENV_FILE.new" >"$ENV_FILE"   # keep the mode and the group
        rm -f "$ENV_FILE.new"
    else
        echo "$1=$2" >>"$ENV_FILE"
    fi
}
unset_env() { sed -i "/^$1=/d" "$ENV_FILE"; }

if [ -n "$DOMAIN" ] && [ "$SILVER_TLS" = builtin ]; then
    log "Setting up HTTPS for $DOMAIN in the relay itself"
    if grep -qs "$CADDY_MARK" /etc/caddy/Caddyfile 2>/dev/null; then
        log "Stopping the Caddy front the installer set up earlier; the relay takes over port 443"
        systemctl disable -q --now caddy 2>/dev/null || true
    fi
    set_env SILVER_DOMAIN "$DOMAIN"
    set_env SILVER_RELAY_LISTEN 0.0.0.0:443
    set_env SILVER_RELAY_ACME_DOMAIN "$DOMAIN"
    # The name a bound login must carry. The ACME domain gives the same
    # answer, but saying it here keeps it right if the domain moves.
    set_env SILVER_RELAY_HOST "$DOMAIN"
    if [ -n "${SILVER_EMAIL:-}" ]; then
        set_env SILVER_RELAY_ACME_EMAIL "$SILVER_EMAIL"
    fi
    unset_env SILVER_TLS
    echo "SILVER_TLS=builtin" >>"$ENV_FILE"
    systemctl restart silver-relay
elif [ -n "$DOMAIN" ]; then
    log "Setting up HTTPS for $DOMAIN with Caddy"
    if ! command -v caddy >/dev/null; then
        if command -v apt-get >/dev/null; then
            apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https gnupg
            curl -fsSL 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' |
                gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
            curl -fsSL 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
                >/etc/apt/sources.list.d/caddy-stable.list
            apt-get update -qq
            apt-get install -y -qq caddy
        elif command -v dnf >/dev/null; then
            dnf install -y -q caddy
        fi
    fi
    command -v caddy >/dev/null || die "could not install Caddy; see https://caddyserver.com/docs/install"

    # The relay listens only locally; Caddy terminates TLS and proxies the WebSocket.
    set_env SILVER_RELAY_LISTEN 127.0.0.1:7777
    set_env SILVER_DOMAIN "$DOMAIN"
    # Behind a front the relay obtains no certificate, so this is the only
    # place it learns the name clients reach it by; a bound login (protocol
    # section 7.1) is checked against it.
    set_env SILVER_RELAY_HOST "$DOMAIN"
    unset_env SILVER_RELAY_ACME_DOMAIN
    unset_env SILVER_RELAY_ACME_EMAIL
    unset_env SILVER_TLS
    echo "SILVER_TLS=caddy" >>"$ENV_FILE"
    mkdir -p /etc/caddy
    cat >/etc/caddy/Caddyfile <<CADDY
# Managed by the Silver Messenger relay installer.
$DOMAIN {
    # Keep the same private key across certificate renewals, so that
    # clients that pin the relay's key (silver --pin) keep working.
    tls {
        reuse_private_keys
    }
    reverse_proxy 127.0.0.1:7777
}
CADDY
    systemctl enable -q caddy
    systemctl restart caddy
    systemctl restart silver-relay
fi

# --- 8. firewall --------------------------------------------------------------
listen=$(sed -n 's/^SILVER_RELAY_LISTEN=//p' "$ENV_FILE")
port="${listen##*:}"
if [ -n "$DOMAIN" ] && [ "$SILVER_TLS" = caddy ]; then
    open_ports="80/tcp 443/tcp"
elif [ -n "$DOMAIN" ]; then
    # The relay validates its certificate over TLS on 443 (RFC 8737); no port 80.
    open_ports="443/tcp"
else
    open_ports="$port/tcp"
fi
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
    log "Opening $open_ports in ufw"
    for p in $open_ports; do ufw allow "$p" >/dev/null; done
    if [ -n "$DOMAIN" ] && [ "$port" != 443 ] && ufw status | grep -q "^$port/tcp"; then
        ufw delete allow "$port/tcp" >/dev/null
    fi
fi
if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
    log "Opening $open_ports in firewalld"
    for p in $open_ports; do firewall-cmd -q --permanent --add-port="$p"; done
    if [ -n "$DOMAIN" ] && [ "$port" != 443 ]; then
        firewall-cmd -q --permanent --remove-port="$port/tcp" || true
    fi
    firewall-cmd -q --reload
fi

# --- 9. health check ----------------------------------------------------------
log "Checking the relay"
if [ -n "$DOMAIN" ] && [ "$SILVER_TLS" = builtin ]; then
    # Before the first certificate arrives the handshake fails; the listener
    # itself is up as soon as the port accepts.
    local_check() { (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; }
else
    local_check() { curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1; }
fi
for _ in $(seq 1 10); do
    if local_check; then
        break
    fi
    sleep 1
done
if ! local_check; then
    journalctl -u silver-relay -n 30 --no-pager || true
    die "the relay did not come up; see the log above"
fi

if [ -n "$DOMAIN" ]; then
    relay_url="wss://$DOMAIN/ws"
    log "Checking https://$DOMAIN (the first certificate can take a moment)"
    https_ok=0
    for _ in $(seq 1 30); do
        if curl -fsS "https://$DOMAIN/healthz" >/dev/null 2>&1; then
            https_ok=1
            break
        fi
        sleep 2
    done
    if [ "$SILVER_TLS" = builtin ]; then
        tls_log="journalctl -u silver-relay -f"
        reach="port 443"
    else
        tls_log="journalctl -u caddy -f"
        reach="ports 80 and 443"
    fi
    if [ "$https_ok" != 1 ]; then
        cat <<WARN

warning: https://$DOMAIN is not answering yet. Make sure the DNS record for
$DOMAIN points at this server and that $reach is open in your hosting
provider's firewall. The certificate request is retried; watch it with:
  $tls_log
WARN
    fi
    extra="  tls:      $tls_log"
else
    # The machine's own address. Asking a third party what it is would tell
    # that third party this host runs a relay, which is nobody's business
    # (SM-S-03); SILVER_PUBLIC_IP says it outright behind NAT.
    public_ip="${SILVER_PUBLIC_IP:-$(hostname -I | awk '{print $1}')}"
    relay_url="ws://$public_ip:$port/ws"
    extra=""
    reach="$port/tcp"
fi

cat <<MSG

Silver Messenger relay is running.

  service:  systemctl status silver-relay
  logs:     journalctl -u silver-relay -f
  config:   $ENV_FILE
  admin:    silver-relay admin status
  backups:  nightly into /var/lib/silver-relay/backups (systemctl list-timers silver-relay-backup.timer)
  update:   re-run this script
  guide:    docs/OPERATING.md in the repository
$extra
Clients connect with:

  silver --relay $relay_url

If it is not reachable from outside, also allow $reach in your hosting
provider's firewall (for example the Vultr firewall group).
MSG
