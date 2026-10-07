#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="veyra"
APP_USER="veyra"
APP_GROUP="veyra"
APP_ROOT="/opt/veyra"
ETC_ROOT="/etc/veyra"
DATA_ROOT="/var/lib/veyra"
WEB_ROOT="/var/www/veyra"
SERVICE_NAME="veyra-api"
DEFAULT_API_PORT="4000"
API_PORT=""
PUBLIC_PORT=""
# Dynamic ports are selected from this non-privileged range only.
# 80/443 and other common service ports are intentionally excluded.
DYNAMIC_PORT_MIN=20000
DYNAMIC_PORT_MAX=59999


PORT=""
DOMAIN="_"
ENVIRONMENT="production"
NON_INTERACTIVE="false"
FORCE_PORT=""
FORCE_API_PORT=""
INSTALL_SOURCE=""
TLS_CERT=""
TLS_KEY=""
ADMIN_EMAIL="${VEYRA_ADMIN_EMAIL:-}"

log(){ printf '\033[1;36m[VEYRA]\033[0m %s\n' "$*"; }
warn(){ printf '\033[1;33m[WARN]\033[0m %s\n' "$*" >&2; }
die(){ printf '\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

usage(){
  cat <<USAGE
Veyra installer

Usage:
  sudo ./installer/install.sh [options]

Options:
  --port PORT              Public Nginx port. If omitted, an available port is selected.
  --domain HOST            Nginx server_name (default: _)
  --dev-mode               Development mode: if SMTP is not configured, verification codes are written to the
                           service log (journalctl -u veyra-api) instead of being emailed. Never use in production.
  --tls-cert FILE          PEM certificate (chain) to serve HTTPS directly from Nginx. Requires --tls-key.
  --tls-key FILE           PEM private key for --tls-cert.
  --admin-email ADDRESS    Only this address may become the first administrator (recommended).
  --non-interactive        Never prompt. Production mode requires SMTP variables in environment.
  --source DIR             Veyra source directory (default: auto-detected project root).
  --help                   Show this help.

Environment variables for production SMTP:
  VEYRA_SMTP_HOST, VEYRA_SMTP_PORT, VEYRA_SMTP_USER, VEYRA_SMTP_PASSWORD, VEYRA_SMTP_FROM
  VEYRA_SMTP_TLS (tls = implicit TLS/465, starttls = 587; default chosen from the port)
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) [[ $# -ge 2 ]] || die "--port requires a value"; FORCE_PORT="$2"; shift 2;;
    --api-port) [[ $# -ge 2 ]] || die "--api-port requires a value"; FORCE_API_PORT="$2"; shift 2;;
    --domain) [[ $# -ge 2 ]] || die "--domain requires a value"; DOMAIN="$2"; shift 2;;
    --dev-mode) ENVIRONMENT="development"; shift;;
    --non-interactive) NON_INTERACTIVE="true"; shift;;
    --tls-cert) [[ $# -ge 2 ]] || die "--tls-cert requires a file"; TLS_CERT="$2"; shift 2;;
    --tls-key) [[ $# -ge 2 ]] || die "--tls-key requires a file"; TLS_KEY="$2"; shift 2;;
    --admin-email) [[ $# -ge 2 ]] || die "--admin-email requires an address"; ADMIN_EMAIL="$2"; shift 2;;
    --source) [[ $# -ge 2 ]] || die "--source requires a directory"; INSTALL_SOURCE="$2"; shift 2;;
    --help|-h) usage; exit 0;;
    *) die "Unknown option: $1";;
  esac
done

[[ $EUID -eq 0 ]] || die "Run this installer as root: sudo ./installer/install.sh"
command -v systemctl >/dev/null || die "systemd is required."

if [[ -z "$INSTALL_SOURCE" ]]; then
  INSTALL_SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi
INSTALL_SOURCE="$(realpath "$INSTALL_SOURCE")"
[[ -f "$INSTALL_SOURCE/Cargo.toml" ]] || die "Invalid Veyra source directory: $INSTALL_SOURCE"
[[ -f "$INSTALL_SOURCE/frontend/package.json" ]] || die "Veyra frontend is missing."
. /etc/os-release
[[ "${ID:-}" == "ubuntu" ]] || die "This installer currently supports Ubuntu only. Detected: ${ID:-unknown}"
[[ "${VERSION_ID:-}" == "24.04" ]] || warn "Veyra is tested by this installer on Ubuntu 24.04; detected ${PRETTY_NAME:-unknown}."

port_in_use(){
  local p="$1"
  ss -H -lntu "sport = :$p" 2>/dev/null | grep -q .
}

validate_port(){
  local p="$1" label="${2:-port}"
  [[ "$p" =~ ^[0-9]+$ ]] || die "$label must be a numeric TCP/UDP port."
  (( p >= 1 && p <= 65535 )) || die "$label must be between 1 and 65535."
}

validate_hostname(){
  local value="$1"
  [[ "$value" == "_" ]] && return 0
  ((${#value} <= 253)) || die "Invalid hostname: too long."
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* && "$value" != *' '* && "$value" != *$'\t'* ]] || die "Invalid hostname: whitespace/newlines are not allowed."
  [[ "$value" =~ ^[A-Za-z0-9_.:-]+$ ]] || die "Invalid hostname/IP: unsupported characters."
  [[ "$value" != .* && "$value" != *..* && "$value" != *.-* && "$value" != *-. ]] || die "Invalid hostname/IP."
}

validate_email(){
  local value="$1"
  ((${#value} <= 254)) || die "Invalid email address: too long."
  [[ "$value" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die "Invalid email address."
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || die "Invalid email address."
}

validate_path_input(){
  local value="$1" label="${2:-path}"
  [[ -n "$value" ]] || die "$label must not be empty."
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || die "$label contains forbidden newline characters."
}

validate_config_text(){
  local value="$1" label="${2:-value}"
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || die "$label contains forbidden newline characters."
}

validate_path_input "$INSTALL_SOURCE" "Source path"
validate_hostname "$DOMAIN"
[[ -z "$ADMIN_EMAIL" ]] || validate_email "$ADMIN_EMAIL"
[[ -z "$FORCE_PORT" ]] || validate_port "$FORCE_PORT" "Public port"
[[ -z "$FORCE_API_PORT" ]] || validate_port "$FORCE_API_PORT" "API port"
if [[ -n "$TLS_CERT" || -n "$TLS_KEY" ]]; then
  [[ -n "$TLS_CERT" && -n "$TLS_KEY" ]] || die "--tls-cert and --tls-key must be supplied together."
  validate_path_input "$TLS_CERT" "TLS certificate path"
  validate_path_input "$TLS_KEY" "TLS private key path"
  [[ -f "$TLS_CERT" && -r "$TLS_CERT" ]] || die "TLS certificate is not a readable regular file: $TLS_CERT"
  [[ -f "$TLS_KEY" && -r "$TLS_KEY" ]] || die "TLS private key is not a readable regular file: $TLS_KEY"
  TLS_CERT="$(realpath -e "$TLS_CERT")"
  TLS_KEY="$(realpath -e "$TLS_KEY")"
fi

random_free_port() {
  local exclude="${1:-}"
  local attempts=0
  local p
  while (( attempts < 500 )); do
    p="$(shuf -i "${DYNAMIC_PORT_MIN}-${DYNAMIC_PORT_MAX}" -n 1)"
    if [[ -n "$exclude" && "$p" == "$exclude" ]]; then
      ((attempts++))
      continue
    fi
    if ! port_in_use "$p"; then
      printf '%s' "$p"
      return 0
    fi
    ((attempts++))
  done
  return 1
}

scan_dynamic_ports() {
  log "Scanning TCP/UDP listening ports on IPv4 and IPv6 before selecting Veyra ports..."
  local count
  count="$(ss -H -lntu 2>/dev/null | wc -l || true)"
  log "Detected $count listening TCP/UDP socket(s)."
}

assert_selected_port_free(){
  local p="$1" label="$2"
  if port_in_use "$p"; then
    die "Selected $label port $p is already in use by a TCP/UDP listener on IPv4 or IPv6."
  fi
}

select_port(){
  scan_dynamic_ports

  if [[ -n "$FORCE_PORT" ]]; then
    validate_port "$FORCE_PORT" "Public port"
    PUBLIC_PORT="$FORCE_PORT"
    PORT="$PUBLIC_PORT"
  else
    PUBLIC_PORT="$(random_free_port)" || die "Could not find a free public port in ${DYNAMIC_PORT_MIN}-${DYNAMIC_PORT_MAX}."
    PORT="$PUBLIC_PORT"
  fi

  if [[ -n "$FORCE_API_PORT" ]]; then
    validate_port "$FORCE_API_PORT" "API port"
    API_PORT="$FORCE_API_PORT"
  else
    API_PORT="$(random_free_port "$PUBLIC_PORT")" || die "Could not find a free API port in ${DYNAMIC_PORT_MIN}-${DYNAMIC_PORT_MAX}."
  fi
  DEFAULT_API_PORT="$API_PORT"

  [[ "$PUBLIC_PORT" != "$API_PORT" ]] || die "Public and API ports must be different."
  if [[ -z "$FORCE_PORT" ]]; then
    [[ "$PUBLIC_PORT" != "80" && "$PUBLIC_PORT" != "443" ]] || die "Random public port selection returned a forbidden port."
  fi
  assert_selected_port_free "$PUBLIC_PORT" "public/Nginx"
  assert_selected_port_free "$API_PORT" "API"

  log "Selected public/Nginx port: ${PUBLIC_PORT}/tcp"
  log "Selected API port: 127.0.0.1:${API_PORT}"
}

package_manager_busy(){
  local lock
  for lock in \
    /var/lib/dpkg/lock-frontend \
    /var/lib/dpkg/lock \
    /var/lib/apt/lists/lock \
    /var/cache/apt/archives/lock; do
    if fuser "$lock" >/dev/null 2>&1; then return 0; fi
  done
  pgrep -x apt >/dev/null 2>&1 && return 0
  pgrep -x apt-get >/dev/null 2>&1 && return 0
  pgrep -x dpkg >/dev/null 2>&1 && return 0
  pgrep -x unattended-upgrade >/dev/null 2>&1 && return 0
  return 1
}

wait_for_package_manager(){
  local timeout="${VEYRA_APT_WAIT_TIMEOUT:-900}"
  local start elapsed
  if ! package_manager_busy; then return 0; fi

  warn "Ubuntu package manager is currently busy."
  log "Waiting up to ${timeout}s for apt/dpkg/unattended-upgrades to finish."
  log "Veyra will never delete apt/dpkg lock files."

  start="$(date +%s)"
  while package_manager_busy; do
    elapsed=$(( $(date +%s) - start ))
    if (( elapsed >= timeout )); then
      die "Package manager is still busy after ${timeout}s. Let Ubuntu finish its update and rerun the installer."
    fi
    sleep 5
  done
  log "Package manager is available."
}

apt_run(){
  local attempt
  for attempt in 1 2 3; do
    wait_for_package_manager
    if "$@"; then return 0; fi
    warn "Package operation failed (attempt ${attempt}/3); waiting before retry..."
    sleep 5
  done
  die "Package operation failed after 3 attempts: $*"
}

install_packages(){
  log "Installing system dependencies..."
  export DEBIAN_FRONTEND=noninteractive
  apt_run apt-get update -y
  apt_run apt-get install -y --no-install-recommends \
    build-essential pkg-config libssl-dev ca-certificates curl git nginx postgresql postgresql-contrib \
    openssl jq rsync
}

version_ge(){
  dpkg --compare-versions "$1" ge "$2"
}

install_node(){
  local current=""
  if command -v node >/dev/null 2>&1; then current="$(node -p 'process.versions.node')"; fi
  if [[ -n "$current" ]] && version_ge "$current" "20.19.0"; then
    log "Node.js $current is suitable."
    return
  fi
  log "Installing Node.js 22.x..."
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
  apt_run apt-get install -y nodejs
  node -p 'process.version'
}

install_rust(){
  export PATH="/root/.cargo/bin:$PATH"

  if command -v rustup >/dev/null 2>&1; then
    log "Updating Rust stable toolchain..."
    rustup toolchain install stable --profile minimal --no-self-update
    rustup default stable >/dev/null
  elif [[ -x /root/.cargo/bin/rustup ]]; then
    export PATH="/root/.cargo/bin:$PATH"
    /root/.cargo/bin/rustup toolchain install stable --profile minimal --no-self-update
    /root/.cargo/bin/rustup default stable >/dev/null
  else
    log "Installing Rust stable toolchain..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
    export PATH="/root/.cargo/bin:$PATH"
  fi

  command -v cargo >/dev/null || die "Rust installation failed."
  command -v rustc >/dev/null || die "Rust compiler installation failed."
  log "Using: $(rustc --version)"
  log "Using: $(cargo --version)"
}

cargo_stable(){
  export PATH="/root/.cargo/bin:$PATH"
  if command -v rustup >/dev/null 2>&1; then
    rustup run stable cargo "$@"
  else
    cargo "$@"
  fi
}

ensure_user(){
  if ! getent group "$APP_GROUP" >/dev/null 2>&1; then
    groupadd --system "$APP_GROUP"
  fi
  if ! id "$APP_USER" >/dev/null 2>&1; then
    useradd --system --gid "$APP_GROUP" --home "$APP_ROOT" --shell /usr/sbin/nologin "$APP_USER"
  else
    usermod --gid "$APP_GROUP" "$APP_USER"
  fi
  install -d -o "$APP_USER" -g "$APP_GROUP" "$APP_ROOT" "$DATA_ROOT" "$DATA_ROOT/tmp" "$ETC_ROOT" "$WEB_ROOT"
}

random_secret(){ openssl rand -base64 48 | tr -d '\n'; }
random_password(){ openssl rand -base64 30 | tr -d '/+=' | cut -c1-24; }

setup_database(){
  log "Configuring PostgreSQL..."
  systemctl enable --now postgresql
  local dbpass
  dbpass="$(random_password)"
  sudo -u postgres psql -v ON_ERROR_STOP=1 <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${APP_USER}') THEN
    CREATE ROLE ${APP_USER} LOGIN PASSWORD '${dbpass}';
  ELSE
    ALTER ROLE ${APP_USER} WITH LOGIN PASSWORD '${dbpass}';
  END IF;
END
\$\$;
SELECT 'CREATE DATABASE ${APP_USER} OWNER ${APP_USER}'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${APP_USER}')\gexec
SQL
  DATABASE_URL="postgres://${APP_USER}:${dbpass}@127.0.0.1:5432/${APP_USER}"
  printf '%s\n' "$DATABASE_URL" > "$ETC_ROOT/.database_url"
  chmod 600 "$ETC_ROOT/.database_url"
}

configure_env(){
  log "Creating protected Veyra configuration..."
  local master_key=""
  if [[ -f "$ETC_ROOT/veyra.env" ]]; then
    master_key="$(awk -F= '/^VEYRA_MASTER_ENCRYPTION_KEY=/{sub(/^VEYRA_MASTER_ENCRYPTION_KEY=/,""); print; exit}' "$ETC_ROOT/veyra.env")"
  fi
  [[ -n "$master_key" ]] || master_key="$(random_secret)"
  local dburl
  dburl="$(cat "$ETC_ROOT/.database_url")"

  SMTP_HOST="${VEYRA_SMTP_HOST:-}"
  SMTP_PORT="${VEYRA_SMTP_PORT:-587}"
  SMTP_USER="${VEYRA_SMTP_USER:-}"
  SMTP_PASSWORD="${VEYRA_SMTP_PASSWORD:-}"
  SMTP_FROM="${VEYRA_SMTP_FROM:-Veyra <no-reply@example.com>}"
  SMTP_TLS_VALUE="${VEYRA_SMTP_TLS:-}"
  if [[ -f "$ETC_ROOT/veyra.env" ]]; then
    [[ -n "$SMTP_HOST" ]] || SMTP_HOST="$(awk -F= '/^SMTP_HOST=/{sub(/^SMTP_HOST=/,""); print; exit}' "$ETC_ROOT/veyra.env")"
    [[ "$SMTP_PORT" != "587" ]] || SMTP_PORT="$(awk -F= '/^SMTP_PORT=/{sub(/^SMTP_PORT=/,""); print; exit}' "$ETC_ROOT/veyra.env")"
    [[ -n "$SMTP_USER" ]] || SMTP_USER="$(awk -F= '/^SMTP_USER=/{sub(/^SMTP_USER=/,""); print; exit}' "$ETC_ROOT/veyra.env")"
    [[ -n "$SMTP_PASSWORD" ]] || SMTP_PASSWORD="$(awk -F= '/^SMTP_PASSWORD=/{sub(/^SMTP_PASSWORD=/,""); print; exit}' "$ETC_ROOT/veyra.env")"
    if [[ "$SMTP_FROM" == "Veyra <no-reply@example.com>" ]]; then SMTP_FROM="$(awk -F= '/^SMTP_FROM=/{sub(/^SMTP_FROM=/,""); print; exit}' "$ETC_ROOT/veyra.env")"; fi
    if [[ -z "$SMTP_TLS_VALUE" ]]; then SMTP_TLS_VALUE="$(awk -F= '/^SMTP_TLS=/{sub(/^SMTP_TLS=/,"" ); print; exit}' "$ETC_ROOT/veyra.env")"; fi
  fi
  validate_config_text "$SMTP_HOST" "SMTP host"
  validate_config_text "$SMTP_USER" "SMTP username"
  validate_config_text "$SMTP_PASSWORD" "SMTP password"
  validate_config_text "$SMTP_FROM" "SMTP sender"
  validate_port "$SMTP_PORT" "SMTP port"
  [[ -z "$SMTP_HOST" ]] || validate_hostname "$SMTP_HOST"
  [[ "$SMTP_FROM" == *"<"* && "$SMTP_FROM" == *">"* ]] && sender_email="${SMTP_FROM##*<}" && sender_email="${sender_email%%>*}" || sender_email="$SMTP_FROM"
  [[ -z "$sender_email" ]] || validate_email "$sender_email"

  if [[ "$ENVIRONMENT" == "production" && -z "$SMTP_HOST" ]]; then
    warn "SMTP is not configured."
    warn "Recipient OTP delivery requires SMTP in production."
    warn "For testing, rerun with: sudo ./installer/install.sh --dev-mode"
    die "Production installation cannot continue without SMTP configuration."
  fi

  local public_host="$DOMAIN"
  if [[ "$public_host" == "_" ]]; then
    public_host="$(hostname -I 2>/dev/null | awk '{print $1}')"
    [[ -n "$public_host" ]] || public_host="127.0.0.1"
  fi
  validate_hostname "$public_host"
  local scheme="http"
  [[ -n "$TLS_CERT" ]] && scheme="https"
  if [[ "$scheme" == "http" && "$ENVIRONMENT" == "production" ]]; then
    warn "Serving over plain HTTP: session cookies will not be marked Secure and traffic is not encrypted."
    warn "Use --tls-cert/--tls-key, or terminate TLS in a reverse proxy in front of this Nginx."
  fi
  local public_url="$scheme://$public_host:$PORT"
  if [[ -z "$ADMIN_EMAIL" && -f "$ETC_ROOT/veyra.env" ]]; then
    ADMIN_EMAIL="$(awk -F= '/^VEYRA_ADMIN_EMAIL=/{sub(/^VEYRA_ADMIN_EMAIL=/,""); print; exit}' "$ETC_ROOT/veyra.env")"
  fi
  if [[ -z "$ADMIN_EMAIL" ]]; then
    warn "No --admin-email given: the FIRST account registered on this server becomes the administrator."
  fi

  cat > "$ETC_ROOT/veyra.env" <<EOF_ENV
DATABASE_URL=$dburl
VEYRA_BIND=127.0.0.1:$API_PORT
VEYRA_PUBLIC_BASE_URL=$public_url
VEYRA_DATA_DIR=$DATA_ROOT
VEYRA_MASTER_ENCRYPTION_KEY=$master_key
STORAGE_DRIVER=local
S3_ENDPOINT=
S3_BUCKET=
S3_REGION=us-east-1
S3_ACCESS_KEY=
S3_SECRET_KEY=
MAX_UPLOAD_BYTES=5368709120
OTP_TTL_MINUTES=10
SESSION_TTL_HOURS=24
VEYRA_ENV=$ENVIRONMENT
VEYRA_TRUST_PROXY=true
VEYRA_ADMIN_EMAIL=$ADMIN_EMAIL
RUST_LOG=info
SMTP_HOST=$SMTP_HOST
SMTP_PORT=$SMTP_PORT
SMTP_TLS=$SMTP_TLS_VALUE
SMTP_USER=$SMTP_USER
SMTP_PASSWORD=$SMTP_PASSWORD
SMTP_FROM=$SMTP_FROM
EOF_ENV
  chmod 600 "$ETC_ROOT/veyra.env"
  chown root:"$APP_GROUP" "$ETC_ROOT/veyra.env"
}

verify_source_dependencies(){
  [[ -f "$APP_ROOT/core/Cargo.toml" ]] || die "Missing core/Cargo.toml"
  [[ -f "$APP_ROOT/api/Cargo.toml" ]] || die "Missing api/Cargo.toml"
  grep -q 'serde_json' "$APP_ROOT/core/Cargo.toml" || die "veyra-core is missing serde_json dependency."
  grep -Eq '^bls12_381[[:space:]]*=[[:space:]]*"0\.8' "$APP_ROOT/api/Cargo.toml" || die "veyra-api is missing bls12_381 dependency."
}

build_app(){
  log "Copying source into $APP_ROOT..."
  rsync -a --delete \
    --exclude target --exclude node_modules --exclude data --exclude .git \
    "$INSTALL_SOURCE/" "$APP_ROOT/"
  chown -R "$APP_USER:$APP_GROUP" "$APP_ROOT" "$DATA_ROOT" "$WEB_ROOT"
  verify_source_dependencies

  log "Building Veyra API..."
  cd "$APP_ROOT"
  export PATH="/root/.cargo/bin:$PATH"
  # The project is intentionally built with the Rust stable toolchain installed above.
  # Do not reuse an incompatible lockfile generated by an older Cargo release.
  cargo_stable build --release

  log "Building Veyra frontend..."
  cd "$APP_ROOT/frontend"
  npm ci --no-audit --no-fund
  npm run build

  rm -rf "$WEB_ROOT"/*
  cp -a dist/. "$WEB_ROOT/"
  chown -R "$APP_USER:$APP_GROUP" "$WEB_ROOT"
}

configure_systemd(){
  log "Installing systemd service..."
  cat > "/etc/systemd/system/$SERVICE_NAME.service" <<EOF_UNIT
[Unit]
Description=Veyra Secure File Transfer API
After=network-online.target postgresql.service
Wants=network-online.target
Requires=postgresql.service

[Service]
Type=simple
User=$APP_USER
Group=$APP_GROUP
WorkingDirectory=$APP_ROOT
EnvironmentFile=$ETC_ROOT/veyra.env
ExecStart=$APP_ROOT/target/release/veyra-api
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
UMask=0077
ReadWritePaths=$DATA_ROOT
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF_UNIT
  systemctl daemon-reload
  systemctl enable --now "$SERVICE_NAME"
}

configure_nginx(){
  if [[ "$PUBLIC_PORT" == "80" || "$PUBLIC_PORT" == "443" ]]; then
  die "Refusing to bind Veyra public port $PUBLIC_PORT; privileged/common ports are excluded."
fi
if [[ "$PUBLIC_PORT" == "$API_PORT" ]]; then
  die "Public and API ports must be different."
fi
log "Configuring Nginx on TCP port $PUBLIC_PORT..."
  local listen_directive="listen $PUBLIC_PORT;"
  local listen6_directive="listen [::]:$PUBLIC_PORT;"
  local tls_block=""
  local hsts_header=""
  if [[ -n "$TLS_CERT" ]]; then
    listen_directive="listen $PUBLIC_PORT ssl;"
    listen6_directive="listen [::]:$PUBLIC_PORT ssl;"
    tls_block="ssl_certificate $TLS_CERT;
    ssl_certificate_key $TLS_KEY;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:veyra_tls:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;"
    hsts_header='add_header Strict-Transport-Security "max-age=31536000" always;'
  fi
  cat > /etc/nginx/sites-available/veyra <<EOF_NGINX
# Link tokens travel in URL paths: never write them to the access log.
map \$request_uri \$veyra_logged_uri {
    ~^/api/v1/download/[^/]+(?<rest>.*)\$ "/api/v1/download/[redacted]\$rest";
    default \$request_uri;
}
log_format veyra '\$remote_addr [\$time_local] "\$request_method \$veyra_logged_uri" \$status \$body_bytes_sent';

limit_req_zone \$binary_remote_addr zone=veyra_auth:10m rate=10r/m;
limit_req_zone \$binary_remote_addr zone=veyra_code:10m rate=20r/m;
limit_req_zone \$binary_remote_addr zone=veyra_api:10m rate=300r/m;

server {
    $listen_directive
    $listen6_directive
    server_name $DOMAIN;
    $tls_block

    access_log /var/log/nginx/veyra.access.log veyra;
    root $WEB_ROOT;
    index index.html;
    client_max_body_size 5G;
    server_tokens off;

    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Content-Security-Policy "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'" always;
    $hsts_header

    location ~ ^/api/v1/auth/(login|register)\$ {
        limit_req zone=veyra_auth burst=5 nodelay;
        limit_req_status 429;
        proxy_pass http://127.0.0.1:$DEFAULT_API_PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location ~ ^/api/v1/download/[^/]+/(request-verification|verify)\$ {
        limit_req zone=veyra_code burst=5 nodelay;
        limit_req_status 429;
        proxy_pass http://127.0.0.1:$DEFAULT_API_PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /api/ {
        limit_req zone=veyra_api burst=60 nodelay;
        limit_req_status 429;
        proxy_pass http://127.0.0.1:$DEFAULT_API_PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_request_buffering off;
        proxy_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    location = /health { proxy_pass http://127.0.0.1:$DEFAULT_API_PORT; }

    location / {
        try_files \$uri \$uri/ /index.html;
    }
}
EOF_NGINX
  ln -sfn /etc/nginx/sites-available/veyra /etc/nginx/sites-enabled/veyra
  rm -f /etc/nginx/sites-enabled/default
  nginx -t
  systemctl enable --now nginx
  systemctl reload nginx
}

configure_firewall(){
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    log "Opening TCP/$PORT in UFW..."
    ufw allow "$PORT/tcp" >/dev/null
  fi
}

health_check(){
  log "Running service health checks..."
  systemctl is-active --quiet "$SERVICE_NAME" || { journalctl -u "$SERVICE_NAME" -n 80 --no-pager; die "Veyra API service failed to start."; }
  systemctl is-active --quiet nginx || die "Nginx is not active."
  local ok="false"
  for _ in $(seq 1 30); do
    if curl -fsS "http://127.0.0.1:$DEFAULT_API_PORT/health" | jq -e '.status == "ok"' >/dev/null 2>&1; then ok="true"; break; fi
    sleep 1
  done
  [[ "$ok" == "true" ]] || { journalctl -u "$SERVICE_NAME" -n 80 --no-pager; die "Veyra API health check failed."; }
  curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null || die "Nginx public health check failed."
}

write_control_script(){
  cat > /usr/local/bin/veyractl <<'EOF_CTL'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-status}" in
  status) systemctl --no-pager status veyra-api nginx ;;
  logs) journalctl -u veyra-api -n 200 --no-pager ;;
  restart) systemctl restart veyra-api nginx ;;
  health) API_PORT="$(awk -F= '/^VEYRA_BIND=/{sub(/^VEYRA_BIND=127.0.0.1:/,""); print; exit}' /etc/veyra/veyra.env)"; curl -fsS "http://127.0.0.1:${API_PORT}/health"; echo ;;
  update)
    public_port="$(awk '/^[[:space:]]*listen[[:space:]]+[0-9]+([[:space:]]+ssl)?;/{gsub(";",""); print $2; exit}' /etc/nginx/sites-available/veyra)"
    api_port="$(awk -F= '/^VEYRA_BIND=/{sub(/^127\.0\.0\.1:/,"",$2); print $2; exit}' /etc/veyra/veyra.env)"
    domain="$(awk '/^[[:space:]]*server_name[[:space:]]+/{gsub(";",""); print $2; exit}' /etc/nginx/sites-available/veyra)"
    [[ "$public_port" =~ ^[0-9]+$ && "$api_port" =~ ^[0-9]+$ ]] || { echo "Could not determine existing Veyra ports safely." >&2; exit 1; }
    args=(--source /opt/veyra --port "$public_port" --api-port "$api_port" --domain "$domain" --non-interactive)
    if grep -qE '^VEYRA_ENV=development$' /etc/veyra/veyra.env; then
      args+=(--dev-mode)
    fi
    if grep -qE '^[[:space:]]*listen[[:space:]]+[0-9]+[[:space:]]+ssl;' /etc/nginx/sites-available/veyra; then
      cert="$(awk '/^[[:space:]]*ssl_certificate[[:space:]]+/{gsub(";",""); print $2; exit}' /etc/nginx/sites-available/veyra)"
      key="$(awk '/^[[:space:]]*ssl_certificate_key[[:space:]]+/{gsub(";",""); print $2; exit}' /etc/nginx/sites-available/veyra)"
      [[ -n "$cert" && -n "$key" ]] || { echo "Existing TLS configuration is incomplete; refusing upgrade." >&2; exit 1; }
      args+=(--tls-cert "$cert" --tls-key "$key")
    fi
    exec /opt/veyra/installer/install.sh "${args[@]}"
    ;;
  *) echo "Usage: veyractl {status|logs|restart|health|update}"; exit 2;;
esac
EOF_CTL
  chmod 755 /usr/local/bin/veyractl
}

stop_existing_veyra(){
  if systemctl list-unit-files "${SERVICE_NAME}.service" --no-legend 2>/dev/null | grep -q "^${SERVICE_NAME}\.service"; then
    if systemctl is-active --quiet "$SERVICE_NAME"; then
      log "Stopping existing Veyra API service for safe upgrade..."
      systemctl stop "$SERVICE_NAME"
    fi
  fi
  if [[ -e /etc/nginx/sites-enabled/veyra ]] && systemctl is-active --quiet nginx 2>/dev/null; then
    log "Stopping existing Nginx instance so the preserved public port can be reconfigured safely..."
    systemctl stop nginx
  fi
}

install_packages
install_node
install_rust
stop_existing_veyra
select_port
ensure_user
setup_database
configure_env
build_app
configure_systemd
configure_nginx
configure_firewall
write_control_script
health_check

PUBLIC_HOST="$DOMAIN"
if [[ "$PUBLIC_HOST" == "_" ]]; then
  PUBLIC_HOST="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [[ -n "$PUBLIC_HOST" ]] || PUBLIC_HOST="127.0.0.1"
fi

scheme_summary="http"
[[ -n "$TLS_CERT" ]] && scheme_summary="https"

cat <<SUMMARY

Veyra installation completed successfully.

Public URL:       ${scheme_summary:-http}://$PUBLIC_HOST:$PUBLIC_PORT
Public port:      $PUBLIC_PORT/tcp
API (localhost):  127.0.0.1:$DEFAULT_API_PORT
Web root:         $WEB_ROOT
Data directory:   $DATA_ROOT
Config:           $ETC_ROOT/veyra.env
Service:          $SERVICE_NAME

Useful commands:
  sudo veyractl status
  sudo veyractl health
  sudo veyractl logs
  sudo veyractl restart

First user registration:
  The first registered account (or the --admin-email address, if set) becomes the administrator.
  Attributes for restricted transfers are managed in the web UI under Admin.

Environment: $ENVIRONMENT
SUMMARY
