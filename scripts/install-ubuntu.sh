#!/usr/bin/env bash
set -Eeuo pipefail

VERSION="0.4.0"
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_ROOT=/var/backups/saguaro-installer
LOG_FILE=/var/log/saguaro-install.log
ADMIN_NETWORK=""
CLIENT_NETWORK=""
DHCP_INTERFACE=""
DHCP_SUBNET=""
DHCP_POOL_START=""
DHCP_POOL_END=""
DHCP_ROUTER=""
DNS_DOMAIN="home.arpa"
SERVER_NAME="$(hostname -f 2>/dev/null || hostname)"
CA_NAME="Saguaro Internal CA"
CA_DNS=""
DEB_SOURCE=""
ENABLE_SURICATA=false
NON_INTERACTIVE=false
ENABLE_FIREWALL=true
ENABLE_DOCKER=false
ENABLE_STEP_CA=true
ENABLE_MONITORING=true
DRY_RUN=false

usage() {
  cat <<'EOF'
Saguaro Network Appliance installer for Ubuntu 24.04 LTS or newer.

Installs: PostgreSQL, Kea DHCP (PostgreSQL backend), Unbound resolver,
PowerDNS authoritative (PostgreSQL backend), Kea DDNS integration, step-ca,
Nginx, nftables host firewall and the Saguaro control plane.

Usage: sudo ./scripts/install-ubuntu.sh [options]

  --admin-network CIDR       IPv4 network allowed to access HTTPS/SSH (required non-interactively)
  --client-network CIDR      IPv4 network allowed to query DNS (default: admin network)
  --server-name FQDN         GUI hostname (default: current FQDN)
  --dns-domain DOMAIN        Local DNS domain (default: home.arpa)
  --dhcp-interface NAME      Interface on which Kea DHCPv4 will listen
  --dhcp-subnet CIDR         Initial DHCP subnet, e.g. 192.168.10.0/24
  --dhcp-pool START-END      Initial pool, e.g. 192.168.10.100-192.168.10.200
  --dhcp-router IP           Default gateway offered to clients
  --ca-name NAME             Internal CA display name
  --ca-dns FQDN              Step CA name (default: ca.<dns-domain>)
  --deb PATH|URL             Install the prebuilt saguaro .deb (from CI) instead of
                             building from source on this host (recommended; avoids
                             installing a Go toolchain on the appliance)
  --with-suricata            Install the Suricata security package (needs >= 8 GB RAM
                             and >= 4 cores; enable IDS/IPS later from the GUI, W9)
  --with-docker              Install Docker (off by default: it manipulates netfilter)
  --without-step-ca          Do not initialize Step CA
  --without-monitoring       Do not install node exporter
  --without-firewall         Do not configure nftables (not recommended)
  --non-interactive          Fail instead of prompting
  --dry-run                  Print mutating commands without executing them
  -h, --help                 Show help

If DHCP parameters are omitted, Kea is installed but kept disabled until configured.
EOF
}

die() { echo "ERROR: $*" >&2; exit 1; }
log() { printf '[%s] %s\n' "$(date --iso-8601=seconds)" "$*" | tee -a "$LOG_FILE"; }
run() { if $DRY_RUN; then printf 'DRY-RUN:'; printf ' %q' "$@"; printf '\n'; else "$@"; fi; }

while (($#)); do
  case "$1" in
    --admin-network) ADMIN_NETWORK=${2:?}; shift 2 ;;
    --client-network) CLIENT_NETWORK=${2:?}; shift 2 ;;
    --server-name) SERVER_NAME=${2:?}; shift 2 ;;
    --dns-domain) DNS_DOMAIN=${2:?}; shift 2 ;;
    --dhcp-interface) DHCP_INTERFACE=${2:?}; shift 2 ;;
    --dhcp-subnet) DHCP_SUBNET=${2:?}; shift 2 ;;
    --dhcp-pool) IFS=- read -r DHCP_POOL_START DHCP_POOL_END <<<"${2:?}"; shift 2 ;;
    --dhcp-router) DHCP_ROUTER=${2:?}; shift 2 ;;
    --ca-name) CA_NAME=${2:?}; shift 2 ;;
    --ca-dns) CA_DNS=${2:?}; shift 2 ;;
    --deb) DEB_SOURCE=${2:?}; shift 2 ;;
    --with-suricata) ENABLE_SURICATA=true; shift ;;
    --with-docker) ENABLE_DOCKER=true; shift ;;
    --without-step-ca) ENABLE_STEP_CA=false; shift ;;
    --without-monitoring) ENABLE_MONITORING=false; shift ;;
    --without-firewall) ENABLE_FIREWALL=false; shift ;;
    --non-interactive) NON_INTERACTIVE=true; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
done

[[ ${EUID} -eq 0 ]] || die "Run this installer as root."
[[ -r /etc/os-release ]] || die "Cannot identify operating system."
source /etc/os-release
[[ ${ID:-} == ubuntu ]] || die "Only Ubuntu is supported."
major=${VERSION_ID%%.*}
(( major >= 24 )) || die "Ubuntu 24.04 LTS or newer is required."
[[ $(dpkg --print-architecture) =~ ^(amd64|arm64)$ ]] || die "Supported architectures: amd64, arm64."
[[ $SERVER_NAME =~ ^[A-Za-z0-9.-]+$ ]] || die "Invalid server name."
[[ $DNS_DOMAIN =~ ^[A-Za-z0-9.-]+$ ]] || die "Invalid DNS domain."
CA_DNS=${CA_DNS:-ca.$DNS_DOMAIN}

if [[ -z $ADMIN_NETWORK ]] && ! $NON_INTERACTIVE; then
  read -r -p "Management network CIDR allowed to access GUI and SSH: " ADMIN_NETWORK
fi
# nftables set generation in this version targets IPv4 networks.
[[ $ADMIN_NETWORK =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]] || die "A valid IPv4 --admin-network CIDR is required."
CLIENT_NETWORK=${CLIENT_NETWORK:-$ADMIN_NETWORK}
[[ $CLIENT_NETWORK =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]] || die "Invalid IPv4 --client-network CIDR."

dhcp_fields=0
for value in "$DHCP_INTERFACE" "$DHCP_SUBNET" "$DHCP_POOL_START" "$DHCP_POOL_END" "$DHCP_ROUTER"; do [[ -n $value ]] && ((dhcp_fields+=1)); done
[[ $dhcp_fields -eq 0 || $dhcp_fields -eq 5 ]] || die "Provide all DHCP options or none of them."
if ((dhcp_fields == 5)); then
  ip link show "$DHCP_INTERFACE" >/dev/null 2>&1 || die "DHCP interface does not exist: $DHCP_INTERFACE"
  [[ $DHCP_SUBNET =~ ^[0-9.]+/[0-9]{1,2}$ ]] || die "Initial installer currently accepts an IPv4 DHCP subnet."
  [[ $DHCP_POOL_START =~ ^[0-9.]+$ && $DHCP_POOL_END =~ ^[0-9.]+$ && $DHCP_ROUTER =~ ^[0-9.]+$ ]] || die "Invalid DHCP IPv4 values."
fi

# Reverse zone is derived automatically for /24 subnets only in this version.
REVERSE_ZONE=""
if ((dhcp_fields == 5)) && [[ ${DHCP_SUBNET#*/} == 24 ]]; then
  IFS=. read -r o1 o2 o3 _ <<<"${DHCP_SUBNET%/*}"
  REVERSE_ZONE="$o3.$o2.$o1.in-addr.arpa"
fi

mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"
chmod 0600 "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1
trap 'rc=$?; echo "Installer failed at line ${LINENO} (exit ${rc}). Existing configuration backup: ${BACKUP_DIR:-not-created}" >&2' ERR

BACKUP_DIR="$BACKUP_ROOT/$(date +%Y%m%dT%H%M%S)"
log "Saguaro installer ${VERSION}; Ubuntu ${VERSION_ID}; backup ${BACKUP_DIR}"

# Hardware profile: small fanless boxes (N100/Celeron/arm64, 2-4 GB RAM) are
# first-class targets for Infrastructure/Server mode. Detect and adapt instead
# of assuming desktop-class hardware.
CPU_CORES=$(nproc)
MEM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
log "Hardware: ${CPU_CORES} CPU cores, ${MEM_MB} MB RAM, $(dpkg --print-architecture)"
LOW_SPEC=false
if (( MEM_MB < 3500 || CPU_CORES < 4 )); then
  LOW_SPEC=true
  log "NOTE: low-spec profile detected. DHCP/DNS/CA/proxy/WireGuard are fully supported; do NOT enable Suricata IDS/IPS on this hardware — use Unbound RPZ filtering instead. Journald size will be capped."
fi
if $LOW_SPEC && ! $DRY_RUN; then
  install -d /etc/systemd/journald.conf.d
  cat >/etc/systemd/journald.conf.d/saguaro.conf <<'EOF'
[Journal]
SystemMaxUse=512M
EOF
  systemctl restart systemd-journald
fi
run mkdir -p "$BACKUP_DIR"
for path in /etc/kea /etc/unbound /etc/powerdns /etc/nginx /etc/step-ca /etc/saguaro /etc/nftables.conf; do
  if [[ -e $path ]]; then run cp -a "$path" "$BACKUP_DIR/"; fi
done

export DEBIAN_FRONTEND=noninteractive
run apt-get update
base_packages=(ca-certificates curl gpg openssl jq age dnsutils
  postgresql postgresql-client
  kea-dhcp4-server kea-dhcp-ddns-server kea-admin kea-ctrl-agent
  unbound dns-root-data pdns-server pdns-backend-pgsql
  nginx nftables certbot wireguard-tools)
# Without a prebuilt package we must build on the host (needs Ubuntu's Go 1.22;
# go.mod dependencies are pinned to stay compatible with it).
[[ -z $DEB_SOURCE ]] && base_packages+=(golang-go)
if $ENABLE_SURICATA; then
  # Hardware profile rule (§2.1): no Suricata below 8 GB RAM / 4 cores.
  if (( MEM_MB < 7500 || CPU_CORES < 4 )); then
    die "--with-suricata requires >= 8 GB RAM and >= 4 cores (detected ${MEM_MB} MB, ${CPU_CORES} cores); use RPZ filtering instead."
  fi
  base_packages+=(suricata suricata-update)
fi
$ENABLE_DOCKER && base_packages+=(docker.io docker-compose-v2)
$ENABLE_MONITORING && base_packages+=(prometheus-node-exporter)
log "Installing Ubuntu packages"
run apt-get install -y --no-install-recommends "${base_packages[@]}"

# UFW conflicts with natively managed nftables rulesets; the appliance uses one
# firewall engine only. Remove it even when --without-firewall is chosen.
if dpkg -s ufw >/dev/null 2>&1; then
  log "Removing UFW (replaced by nftables)"
  run systemctl disable --now ufw 2>/dev/null || true
  run apt-get purge -y ufw
fi

if $ENABLE_STEP_CA; then
  log "Configuring official Smallstep repository"
  run install -m 0755 -d /etc/apt/keyrings
  if [[ ! -s /etc/apt/keyrings/smallstep.asc ]] && ! $DRY_RUN; then
    curl -fsSL https://packages.smallstep.com/keys/apt/repo-signing-key.gpg -o /etc/apt/keyrings/smallstep.asc
    chmod 0644 /etc/apt/keyrings/smallstep.asc
  fi
  if ! $DRY_RUN; then
    cat >/etc/apt/sources.list.d/smallstep.sources <<'EOF'
Types: deb
URIs: https://packages.smallstep.com/stable/debian
Suites: debs
Components: main
Signed-By: /etc/apt/keyrings/smallstep.asc
EOF
  fi
  run apt-get update
  run apt-get install -y --no-install-recommends step-cli step-ca
fi

log "Configuring PostgreSQL roles and databases"
run systemctl enable --now postgresql
KEA_DB_PASSWORD=""
PDNS_DB_PASSWORD=""
PDNS_API_KEY=""
KEA_API_PASSWORD=""
TSIG_SECRET=""
if ! $DRY_RUN; then
  KEA_DB_PASSWORD=$(openssl rand -base64 24 | tr -d '=+/')
  PDNS_DB_PASSWORD=$(openssl rand -base64 24 | tr -d '=+/')
  PDNS_API_KEY=$(openssl rand -base64 24 | tr -d '=+/')
  KEA_API_PASSWORD=$(openssl rand -base64 24 | tr -d '=+/')
  TSIG_SECRET=$(openssl rand -base64 32)
  for role in saguaro kea pdns; do
    runuser -u postgres -- psql -v ON_ERROR_STOP=1 -tAc \
      "SELECT 1 FROM pg_roles WHERE rolname='${role}'" | grep -q 1 || \
      runuser -u postgres -- psql -v ON_ERROR_STOP=1 -c "CREATE ROLE ${role} LOGIN"
  done
  runuser -u postgres -- psql -v ON_ERROR_STOP=1 -c "ALTER ROLE kea WITH LOGIN PASSWORD '${KEA_DB_PASSWORD}'"
  runuser -u postgres -- psql -v ON_ERROR_STOP=1 -c "ALTER ROLE pdns WITH LOGIN PASSWORD '${PDNS_DB_PASSWORD}'"
  for db in saguaro kea pdns; do
    runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_database WHERE datname='${db}'" | grep -q 1 || \
      runuser -u postgres -- createdb -O "${db}" "${db}"
  done
  # audit_log is owned by postgres with INSERT/SELECT-only grants: the saguaro
  # role cannot update, delete or drop it — append-only enforced by the DB.
  # The partitioned events table is created by the application itself (the
  # saguaro role must own it to manage monthly partitions and retention).
  runuser -u postgres -- psql -v ON_ERROR_STOP=1 -d saguaro <<'EOF'
CREATE TABLE IF NOT EXISTS audit_log (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  ts TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
  old_value JSONB, new_value JSONB,
  result TEXT NOT NULL, remote_ip INET,
  config_version INT, correlation_id UUID
);
GRANT SELECT, INSERT ON audit_log TO saguaro;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO saguaro;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM saguaro;
EOF
fi

log "Initializing Kea database schema"
if ! $DRY_RUN; then
  if ! runuser -u postgres -- psql -d kea -tAc "SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='lease4'" | grep -q 1; then
    kea-admin db-init pgsql -u kea -p "$KEA_DB_PASSWORD" -n kea -h 127.0.0.1
  fi
  # The GUI manages host reservations directly in Kea's hosts table (Kea
  # reads the PG host backend per DHCP transaction — no premium hooks needed).
  runuser -u postgres -- psql -v ON_ERROR_STOP=1 -d kea <<'EOF'
GRANT SELECT, INSERT, UPDATE, DELETE ON hosts TO saguaro;
GRANT USAGE, SELECT ON SEQUENCE hosts_host_id_seq TO saguaro;
GRANT SELECT ON lease4 TO saguaro;
EOF
fi

log "Initializing PowerDNS database schema"
if ! $DRY_RUN; then
  # Qualify by public schema: information_schema itself contains a standard
  # view named "domains", so an unqualified check is always true and the real
  # schema load would be skipped, leaving PowerDNS with no tables.
  if ! runuser -u postgres -- psql -d pdns -tAc "SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='domains'" | grep -q 1; then
    PDNS_SCHEMA=$(ls /usr/share/pdns-backend-pgsql/schema/schema.pgsql.sql /usr/share/doc/pdns-backend-pgsql/schema.pgsql.sql 2>/dev/null | head -1)
    [[ -n $PDNS_SCHEMA ]] || die "PowerDNS PostgreSQL schema file not found."
    runuser -u postgres -- psql -v ON_ERROR_STOP=1 -d pdns -f "$PDNS_SCHEMA"
    runuser -u postgres -- psql -v ON_ERROR_STOP=1 -d pdns -c "GRANT ALL ON ALL TABLES IN SCHEMA public TO pdns; GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO pdns"
  fi
fi

if [[ -n $DEB_SOURCE ]]; then
  log "Installing Saguaro control plane package: $DEB_SOURCE"
  DEB_PATH=$DEB_SOURCE
  if [[ $DEB_SOURCE =~ ^https?:// ]]; then
    DEB_PATH=$(mktemp --suffix=.deb /tmp/saguaro-XXXXXX)
    run curl -fsSL -o "$DEB_PATH" "$DEB_SOURCE"
  fi
  [[ $DEB_PATH == /* ]] || DEB_PATH="$(pwd)/$DEB_PATH"
  [[ -s $DEB_PATH ]] || $DRY_RUN || die "Package not found: $DEB_PATH"
  # apt (not dpkg -i) so declared dependencies resolve; postinst creates the
  # saguaro user and directories, units land in /usr/lib/systemd/system.
  run apt-get install -y "$DEB_PATH"
else
  log "Building Saguaro control plane from source (no --deb given; prefer the CI-built package)"
  run install -d -m 0755 /usr/lib/saguaro
  if ! $DRY_RUN; then
    (cd "$SOURCE_DIR" && go test ./... \
      && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /usr/lib/saguaro/saguaro ./cmd/saguaro \
      && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /usr/lib/saguaro/saguaro-eventd ./cmd/saguaro-eventd)
  fi
  run install -m 0644 "$SOURCE_DIR/packaging/systemd/saguaro.service" /etc/systemd/system/saguaro.service
  run install -m 0644 "$SOURCE_DIR/packaging/systemd/saguaro-eventd.service" /etc/systemd/system/saguaro-eventd.service
fi
run useradd --system --home-dir /var/lib/saguaro --shell /usr/sbin/nologin saguaro 2>/dev/null || true
run install -d -o saguaro -g saguaro -m 0700 /var/lib/saguaro
run install -d -o saguaro -g saguaro -m 0750 /var/log/saguaro
run install -d -o root -g saguaro -m 0750 /etc/saguaro

ADMIN_PASSWORD_FILE=/etc/saguaro/bootstrap-admin-password
if [[ ! -s $ADMIN_PASSWORD_FILE ]] && ! $DRY_RUN; then
  umask 0077
  openssl rand -base64 30 >"$ADMIN_PASSWORD_FILE"
fi
if ! $DRY_RUN; then
  # Low-spec devices get a shorter event retention (monthly partitions).
  EVENT_RETENTION=$($LOW_SPEC && echo 3 || echo 6)
  # The admin password reaches the service through systemd LoadCredential only;
  # the environment file carries no secrets that other components do not need.
  cat >/etc/saguaro/saguaro.env <<EOF
SAGUARO_LISTEN=127.0.0.1:9080
SAGUARO_DATA_DIR=/var/lib/saguaro
SAGUARO_ADMIN_USER=admin
SAGUARO_SECURE_COOKIE=true
SAGUARO_DB_DSN=postgres:///saguaro?host=/var/run/postgresql
SAGUARO_KEA_DB_DSN=postgres:///kea?host=/var/run/postgresql
SAGUARO_EVENT_RETENTION_MONTHS=${EVENT_RETENTION}
SAGUARO_SECRET_KEY_FILE=/etc/saguaro/secret.key
SAGUARO_PDNS_API_URL=http://127.0.0.1:8081
SAGUARO_PDNS_API_KEY=${PDNS_API_KEY}
SAGUARO_KEA_API_URL=http://127.0.0.1:8000
SAGUARO_KEA_API_USER=saguaro
SAGUARO_KEA_API_PASSWORD=${KEA_API_PASSWORD}
EOF
  chown root:root "$ADMIN_PASSWORD_FILE"
  chmod 0600 "$ADMIN_PASSWORD_FILE"
  chown root:saguaro /etc/saguaro/saguaro.env
  chmod 0640 /etc/saguaro/saguaro.env
  # AES-256 key for secrets the GUI stores (e.g. the SMTP password),
  # per the spec: /etc/saguaro/secret.key, root:saguaro 0640.
  if [[ ! -s /etc/saguaro/secret.key ]]; then
    umask 0027
    openssl rand -base64 32 >/etc/saguaro/secret.key
    chown root:saguaro /etc/saguaro/secret.key
    chmod 0640 /etc/saguaro/secret.key
  fi
fi

log "Generating encrypted-backup key material"
if [[ ! -s /etc/saguaro/backup.agekey ]] && ! $DRY_RUN; then
  umask 0077
  age-keygen -o /etc/saguaro/backup.agekey 2>/dev/null
  age-keygen -y /etc/saguaro/backup.agekey >/etc/saguaro/backup-recipient.txt
  chmod 0600 /etc/saguaro/backup.agekey
  chmod 0644 /etc/saguaro/backup-recipient.txt
fi

log "Disabling systemd-resolved so Unbound can own port 53"
if ! $DRY_RUN; then
  # On systemd 255 (Ubuntu 24.04) DNSStubListener=no does not free the
  # 127.0.0.54 stub, so Unbound cannot bind 0.0.0.0:53. Disable resolved
  # entirely — the appliance runs its own resolver — and point resolv.conf
  # at Unbound with a static file.
  systemctl disable --now systemd-resolved 2>/dev/null || true
  rm -f /etc/resolv.conf
  printf 'nameserver 127.0.0.1\noptions edns0 trust-ad\n' >/etc/resolv.conf
  chattr +i /etc/resolv.conf 2>/dev/null || true
fi

log "Configuring Unbound resolver"
if ! $DRY_RUN; then
  cat >/etc/unbound/unbound.conf.d/saguaro.conf <<EOF
# Managed by Saguaro. Manual changes may be replaced.
server:
  interface: 0.0.0.0
  access-control: 0.0.0.0/0 refuse
  access-control: 127.0.0.0/8 allow
  access-control: ${CLIENT_NETWORK} allow
  prefetch: yes
  cache-min-ttl: 60
  # local zones are served by PowerDNS on the loopback interface
  do-not-query-localhost: no
  domain-insecure: "${DNS_DOMAIN}."
  local-zone: "${DNS_DOMAIN}." nodefault
EOF
  if [[ -n $REVERSE_ZONE ]]; then
    cat >>/etc/unbound/unbound.conf.d/saguaro.conf <<EOF
  domain-insecure: "${REVERSE_ZONE}."
  local-zone: "${REVERSE_ZONE}." nodefault
EOF
  fi
  cat >>/etc/unbound/unbound.conf.d/saguaro.conf <<EOF
stub-zone:
  name: "${DNS_DOMAIN}."
  stub-addr: 127.0.0.1@5300
EOF
  if [[ -n $REVERSE_ZONE ]]; then
    cat >>/etc/unbound/unbound.conf.d/saguaro.conf <<EOF
stub-zone:
  name: "${REVERSE_ZONE}."
  stub-addr: 127.0.0.1@5300
EOF
  fi
  # Bootstrap the DNSSEC root trust anchor. Ubuntu's unbound references
  # /var/lib/unbound/root.key, and unbound-checkconf (and unbound itself)
  # fail if it does not exist yet. Minimized installs with
  # --no-install-recommends omit unbound-anchor, so fall back to the anchor
  # shipped by dns-root-data.
  install -d -o unbound -g unbound /var/lib/unbound
  if command -v unbound-anchor >/dev/null 2>&1; then
    runuser -u unbound -- "$(command -v unbound-anchor)" -a /var/lib/unbound/root.key || true
  elif [[ -f /usr/share/dns/root.key ]]; then
    install -o unbound -g unbound -m 0644 /usr/share/dns/root.key /var/lib/unbound/root.key
  fi
  unbound-checkconf
fi

log "Configuring PowerDNS authoritative server"
if ! $DRY_RUN; then
  # The whole file is managed: PowerDNS refuses duplicate settings, so merging
  # with the distribution default is not safe.
  cat >/etc/powerdns/pdns.conf <<EOF
# Managed by Saguaro. Manual changes may be replaced.
setuid=pdns
setgid=pdns
local-address=127.0.0.1
local-port=5300
launch=gpgsql
gpgsql-host=127.0.0.1
gpgsql-dbname=pdns
gpgsql-user=pdns
gpgsql-password=${PDNS_DB_PASSWORD}
api=yes
api-key=${PDNS_API_KEY}
webserver=yes
webserver-address=127.0.0.1
webserver-port=8081
dnsupdate=yes
allow-dnsupdate-from=127.0.0.1/32
include-dir=/etc/powerdns/pdns.d
EOF
  chown root:pdns /etc/powerdns/pdns.conf
  chmod 0640 /etc/powerdns/pdns.conf
  rm -f /etc/powerdns/pdns.d/*.conf 2>/dev/null || true
  # apt auto-starts pdns with the default (backend-less) config, so it may be
  # in a crash-loop and rate-limited; clear that before starting with our config.
  systemctl reset-failed pdns 2>/dev/null || true
  systemctl restart pdns
fi

log "Creating local DNS zones and DDNS TSIG key"
if ! $DRY_RUN; then
  if ! pdnsutil list-zone "$DNS_DOMAIN" >/dev/null 2>&1; then
    pdnsutil create-zone "$DNS_DOMAIN" "ns1.$DNS_DOMAIN"
  fi
  if [[ -n $REVERSE_ZONE ]] && ! pdnsutil list-zone "$REVERSE_ZONE" >/dev/null 2>&1; then
    pdnsutil create-zone "$REVERSE_ZONE" "ns1.$DNS_DOMAIN"
  fi
  if ! pdnsutil list-tsig-keys 2>/dev/null | grep -q '^kea-ddns\.'; then
    pdnsutil import-tsig-key kea-ddns hmac-sha256 "$TSIG_SECRET"
  else
    # Reuse the existing key so reruns stay idempotent.
    TSIG_SECRET=$(pdnsutil list-tsig-keys | awk '/^kea-ddns\./ {print $3}')
  fi
  pdnsutil set-meta "$DNS_DOMAIN" TSIG-ALLOW-DNSUPDATE kea-ddns
  [[ -n $REVERSE_ZONE ]] && pdnsutil set-meta "$REVERSE_ZONE" TSIG-ALLOW-DNSUPDATE kea-ddns
  # pdnsutil wrote the new zones straight to the database; the running server
  # was started earlier with an empty zone cache, so make it pick them up now.
  pdns_control rediscover >/dev/null 2>&1 || systemctl reload pdns || true
fi

log "Configuring Kea DHCP with PostgreSQL backend"
if ! $DRY_RUN; then
  umask 0077
  printf '%s\n' "$KEA_API_PASSWORD" >/etc/kea/api-password
  chown root:_kea /etc/kea/api-password
  chmod 0640 /etc/kea/api-password
  cat >/etc/kea/kea-ctrl-agent.conf <<EOF
{
  "Control-agent": {
    "http-host": "127.0.0.1",
    "http-port": 8000,
    "authentication": {
      "type": "basic",
      "clients": [ { "user": "saguaro", "password-file": "/etc/kea/api-password" } ]
    },
    "control-sockets": {
      "dhcp4": { "socket-type": "unix", "socket-name": "/run/kea/kea4-ctrl-socket" },
      "d2":    { "socket-type": "unix", "socket-name": "/run/kea/kea-ddns-ctrl-socket" }
    }
  }
}
EOF
  reverse_ddns_domains=""
  if [[ -n $REVERSE_ZONE ]]; then
    reverse_ddns_domains="{ \"name\": \"${REVERSE_ZONE}.\", \"key-name\": \"kea-ddns\", \"dns-servers\": [ { \"ip-address\": \"127.0.0.1\", \"port\": 5300 } ] }"
  fi
  cat >/etc/kea/kea-dhcp-ddns.conf <<EOF
{
  "DhcpDdns": {
    "ip-address": "127.0.0.1",
    "port": 53001,
    "control-socket": { "socket-type": "unix", "socket-name": "/run/kea/kea-ddns-ctrl-socket" },
    "tsig-keys": [ { "name": "kea-ddns", "algorithm": "HMAC-SHA256", "secret": "${TSIG_SECRET}" } ],
    "forward-ddns": { "ddns-domains": [ {
      "name": "${DNS_DOMAIN}.",
      "key-name": "kea-ddns",
      "dns-servers": [ { "ip-address": "127.0.0.1", "port": 5300 } ] } ] },
    "reverse-ddns": { "ddns-domains": [ ${reverse_ddns_domains} ] }
  }
}
EOF
  chown root:_kea /etc/kea/kea-ctrl-agent.conf /etc/kea/kea-dhcp-ddns.conf
  chmod 0640 /etc/kea/kea-ctrl-agent.conf /etc/kea/kea-dhcp-ddns.conf
fi
if ((dhcp_fields == 5)) && ! $DRY_RUN; then
  # lease_cmds is an open-source hook shipped with Ubuntu's Kea packages; the
  # GUI uses lease4-get-all through the control agent for the lease view.
  KEA_HOOKS_DIR=$(ls -d /usr/lib/*/kea/hooks 2>/dev/null | head -1)
  [[ -n $KEA_HOOKS_DIR ]] || die "Kea hooks directory not found."
  cat >/etc/kea/kea-dhcp4.conf <<EOF
{
  "Dhcp4": {
    "interfaces-config": { "interfaces": [ "${DHCP_INTERFACE}" ] },
    "control-socket": { "socket-type": "unix", "socket-name": "/run/kea/kea4-ctrl-socket" },
    "hooks-libraries": [ { "library": "${KEA_HOOKS_DIR}/libdhcp_lease_cmds.so" } ],
    "lease-database": { "type": "postgresql", "name": "kea", "user": "kea", "password": "${KEA_DB_PASSWORD}", "host": "127.0.0.1" },
    "hosts-database": { "type": "postgresql", "name": "kea", "user": "kea", "password": "${KEA_DB_PASSWORD}", "host": "127.0.0.1" },
    "valid-lifetime": 3600,
    "renew-timer": 900,
    "rebind-timer": 1800,
    "early-global-reservations-lookup": true,
    "dhcp-ddns": { "enable-updates": true, "server-ip": "127.0.0.1", "server-port": 53001 },
    "ddns-qualifying-suffix": "${DNS_DOMAIN}.",
    "subnet4": [ {
      "id": 1,
      "subnet": "${DHCP_SUBNET}",
      "pools": [ { "pool": "${DHCP_POOL_START} - ${DHCP_POOL_END}" } ],
      "option-data": [
        { "name": "routers", "data": "${DHCP_ROUTER}" },
        { "name": "domain-name-servers", "data": "${DHCP_ROUTER}" },
        { "name": "domain-name", "data": "${DNS_DOMAIN}" }
      ],
      "reservations": []
    } ],
    "loggers": [ { "name": "kea-dhcp4", "severity": "INFO", "output-options": [ { "output": "syslog" } ] } ]
  }
}
EOF
  # _kea owns the file so the GUI's subnet transaction can persist the
  # running config via the core config-write API command.
  chown _kea:_kea /etc/kea/kea-dhcp4.conf
  chmod 0640 /etc/kea/kea-dhcp4.conf
  kea-dhcp4 -t /etc/kea/kea-dhcp4.conf
fi

if $ENABLE_STEP_CA; then
  log "Initializing Step CA"
  run useradd --system --home-dir /etc/step-ca --shell /usr/sbin/nologin step-ca 2>/dev/null || true
  run install -d -o step-ca -g step-ca -m 0700 /etc/step-ca
  if [[ ! -s /etc/step-ca/config/ca.json ]] && ! $DRY_RUN; then
    umask 0077
    openssl rand -base64 36 >/etc/step-ca/password
    chown step-ca:step-ca /etc/step-ca/password
    runuser -u step-ca -- env STEPPATH=/etc/step-ca step ca init --name "$CA_NAME" --dns "$CA_DNS" --dns localhost --address 127.0.0.1:9000 --provisioner admin --password-file /etc/step-ca/password --provisioner-password-file /etc/step-ca/password --acme
  fi
  if ! $DRY_RUN; then
    cat >/etc/systemd/system/step-ca-saguaro.service <<'EOF'
[Unit]
Description=Saguaro internal Step CA
After=network-online.target
Wants=network-online.target
[Service]
User=step-ca
Group=step-ca
Environment=STEPPATH=/etc/step-ca
ExecStart=/usr/bin/step-ca /etc/step-ca/config/ca.json --password-file /etc/step-ca/password
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/step-ca
UMask=0077
[Install]
WantedBy=multi-user.target
EOF
  fi
fi

log "Configuring Nginx reverse proxy"
if ! $DRY_RUN; then
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 30 -subj "/CN=${SERVER_NAME}" -addext "subjectAltName=DNS:${SERVER_NAME}" -keyout /etc/saguaro/bootstrap-tls.key -out /etc/saguaro/bootstrap-tls.crt
  chmod 0600 /etc/saguaro/bootstrap-tls.key
  cat >/etc/nginx/sites-available/saguaro <<EOF
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${SERVER_NAME};
    ssl_certificate /etc/saguaro/bootstrap-tls.crt;
    ssl_certificate_key /etc/saguaro/bootstrap-tls.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    location / {
        proxy_pass http://127.0.0.1:9080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_http_version 1.1;
    }
}
EOF
  ln -sfn /etc/nginx/sites-available/saguaro /etc/nginx/sites-enabled/saguaro
  rm -f /etc/nginx/sites-enabled/default
  nginx -t
  # apt starts nginx with the default config (port 80 only); enable --now on an
  # already-running unit does not re-read config, so reload to pick up the
  # 443 vhost.
  systemctl reload nginx || systemctl restart nginx
fi

if [[ -z $DEB_SOURCE ]]; then
  log "Installing backup job and firewall adapter"
  run install -m 0755 "$SOURCE_DIR/scripts/saguaro-backup.sh" /usr/sbin/saguaro-backup
  run install -m 0755 "$SOURCE_DIR/scripts/saguaro-firewall" /usr/sbin/saguaro-firewall
  run install -m 0755 "$SOURCE_DIR/scripts/saguaro-ids" /usr/sbin/saguaro-ids
  run install -m 0755 "$SOURCE_DIR/scripts/saguaro-rpz" /usr/sbin/saguaro-rpz
  run install -m 0755 "$SOURCE_DIR/scripts/saguaro-proxy" /usr/sbin/saguaro-proxy
  run install -m 0755 "$SOURCE_DIR/scripts/saguaro-cert" /usr/sbin/saguaro-cert
  run install -m 0755 "$SOURCE_DIR/scripts/saguaro-vpn" /usr/sbin/saguaro-vpn
  run install -m 0755 "$SOURCE_DIR/scripts/saguaro-backup-config" /usr/sbin/saguaro-backup-config
  run install -m 0755 "$SOURCE_DIR/scripts/saguaro-wan" /usr/sbin/saguaro-wan
  run install -m 0644 "$SOURCE_DIR/packaging/systemd/saguaro-wan-check.service" /etc/systemd/system/saguaro-wan-check.service
  run install -m 0644 "$SOURCE_DIR/packaging/systemd/saguaro-wan-check.timer" /etc/systemd/system/saguaro-wan-check.timer
  run install -m 0644 "$SOURCE_DIR/packaging/systemd/saguaro-cert-renew.service" /etc/systemd/system/saguaro-cert-renew.service
  run install -m 0644 "$SOURCE_DIR/packaging/systemd/saguaro-cert-renew.timer" /etc/systemd/system/saguaro-cert-renew.timer
  run install -m 0440 "$SOURCE_DIR/packaging/sudoers/saguaro-adapter" /etc/sudoers.d/saguaro-adapter
  run install -m 0644 "$SOURCE_DIR/packaging/systemd/saguaro-backup.service" /etc/systemd/system/saguaro-backup.service
  run install -m 0644 "$SOURCE_DIR/packaging/systemd/saguaro-backup.timer" /etc/systemd/system/saguaro-backup.timer
fi

if $ENABLE_FIREWALL; then
  log "Configuring nftables host firewall"
  if ! $DRY_RUN; then
    dhcp_rule=""
    ((dhcp_fields == 5)) && dhcp_rule="    iifname \"${DHCP_INTERFACE}\" udp dport 67 accept"
    cat >/etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
# Managed by Saguaro. The GUI extends this ruleset through saguaro-agent;
# the same table gains forward/NAT chains when gateway mode is enabled.
flush ruleset
table inet saguaro {
  set mgmt4 { type ipv4_addr; flags interval; elements = { ${ADMIN_NETWORK} } }
  set clients4 { type ipv4_addr; flags interval; elements = { ${CLIENT_NETWORK} } }

  chain input {
    type filter hook input priority filter; policy drop;
    ct state established,related accept
    ct state invalid drop
    iif "lo" accept
    ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded, parameter-problem } accept
    ip6 nexthdr ipv6-icmp accept
    ip saddr @mgmt4 tcp dport { 22, 443 } accept
    ip saddr @clients4 udp dport 53 accept
    ip saddr @clients4 tcp dport 53 accept
${dhcp_rule}
    counter log prefix "SNA-INPUT-DROP " drop
  }

  chain forward {
    type filter hook forward priority filter; policy drop;
  }
}
EOF
    nft -c -f /etc/nftables.conf
    nft -f /etc/nftables.conf
  fi
  run systemctl enable nftables
fi

run systemctl daemon-reload
services=(postgresql unbound pdns nginx saguaro saguaro-eventd saguaro-backup.timer saguaro-cert-renew.timer kea-ctrl-agent)
((dhcp_fields == 5)) && services+=(kea-dhcp4-server kea-dhcp-ddns-server)
$ENABLE_DOCKER && services+=(docker)
$ENABLE_MONITORING && services+=(prometheus-node-exporter)
$ENABLE_STEP_CA && services+=(step-ca-saguaro)
for unit in "${services[@]}"; do run systemctl enable --now "$unit"; done

if ! $DRY_RUN; then
  curl --fail --silent http://127.0.0.1:9080/api/health | jq -e '.status == "ok"' >/dev/null
  # Unit-level verification; the control plane keeps probing these continuously
  # (background health sweep + GET /api/health/deep after login).
  for unit in "${services[@]}"; do
    systemctl is-active --quiet "$unit" || log "WARNING: unit is not active: $unit"
  done
  unbound-checkconf
  pdnsutil check-all-zones || true
  nginx -t
  ((dhcp_fields == 5)) && kea-dhcp4 -t /etc/kea/kea-dhcp4.conf
  dig +short +time=3 @127.0.0.1 "ns1.${DNS_DOMAIN}" SOA >/dev/null || true
fi

log "Installation complete"
cat <<EOF

Saguaro URL: https://${SERVER_NAME}/
Administrator: admin
Bootstrap password: ${ADMIN_PASSWORD_FILE}
Installer backup: ${BACKUP_DIR}

IMPORTANT — copy /etc/saguaro/backup.agekey to OFFLINE storage now.
Backups are encrypted to its public key; without this key a restore is
impossible, and with it an attacker can read every backup.

The initial HTTPS certificate is a 30-day bootstrap certificate. Replace it from
Certificates using Step CA for internal names or Let's Encrypt for public names.
Firewall: $($ENABLE_FIREWALL && echo "nftables active — SSH/HTTPS restricted to ${ADMIN_NETWORK}, DNS to ${CLIENT_NETWORK}" || echo "not configured (--without-firewall)").
Kea DHCP is $([[ $dhcp_fields -eq 5 ]] && echo enabled || echo 'installed but disabled').
EOF
