# SNA — Saguaro Network Appliance: analiza i plan pune instalacije

Datum: 2026-07-17 · Autor: analiza projekta (firewall/appliance perspektiva)
Referenca: SNA specifikacija (načini rada, modularnost, logging, mail, RBAC, razvojni redoslijed)

---

## 1. Analiza postojećeg stanja repozitorija

Repozitorij sadrži milestone 0.1: Go control-plane (`cmd/saguaro/main.go`), Ubuntu installer
(`scripts/install-ubuntu.sh`), backup skriptu, systemd unite i dokumentaciju. Kvaliteta
temelja je natprosječna (atomski state, audit, hardening systemd unita, transakcijski
adapter-ugovor), ali postoje **tri međusobno nekonzistentna izvora istine** o komponentama:

| Funkcija | SNA specifikacija | README.md | install-ubuntu.sh (stvarno) |
|---|---|---|---|
| GUI/API | Laravel | Go control-plane | Go control-plane |
| Baza | PostgreSQL | SQLite → PostgreSQL za HA | JSON state datoteka |
| DNS resolver | Unbound | Technitium | BIND9 |
| Autoritativni DNS | PowerDNS | Technitium | BIND9 |
| DHCP | Kea + PostgreSQL | Kea + Control Agent | Kea + memfile, bez ctrl-agent konfiguracije |
| Host firewall | nftables | — | UFW |
| VPN | WireGuard/OpenVPN/IPsec | — | nema |
| IDS/IPS | Suricata | — | nema |
| Mail | SMTP relay korisnika | — | nema |
| Event collector | PostgreSQL event baza | — | nema |

### 1.1 Ključne odluke — **POTVRĐENO 2026-07-17**: Go, Unbound+PowerDNS, nftables

1. **GUI stack: ostati na Go.** Postojeća Go jezgra je već napisana, single-binary,
   bez PHP-FPM/Composer ovisnosti, ima manju površinu napada i lakši update. Laravel iz
   specifikacije zamijeniti Go-om je ispravna inženjerska odluka za appliance.
2. **DNS: Unbound (resolver) + PowerDNS auth (PostgreSQL backend).** BIND9 iz installera
   izbaciti — nema API pogodan za GUI. Technitium izbaciti — .NET runtime i dupliciranje
   funkcija. PowerDNS ima HTTP API i PG backend (izravno odgovara specifikaciji), Unbound
   ima RPZ za kasniji DNS filtering.
3. **Firewall: nftables od prvog dana, i u Infrastructure modu.** UFW izbaciti. UFW je
   frontend nad iptables-nft i sukobljava se s nativnim nftables pravilima koja Gateway mod
   kasnije zahtijeva. Host-firewall u Infrastructure modu i puni firewall u Gateway modu
   moraju biti **isti engine s istim generatorom pravila** — inače se modularnost ruši.
4. **Baza: PostgreSQL odmah**, ne SQLite. Kea hosts/leases, PowerDNS zone, event baza,
   audit i konfiguracijska baza dijele isti PG klaster — to je preduvjet za event collector,
   retenciju i izvještaje iz specifikacije.
5. **Docker izbaciti iz default installa.** Na firewall appliance-u Docker manipulira
   iptables/nftables lancima i ruši determinizam pravila. Ostaviti kao opt-in samo u
   Server modu.

### 1.2 Sigurnosni nalazi u postojećem kodu (popraviti prije produkcije)

| # | Nalaz | Lokacija | Rizik | Preporuka |
|---|---|---|---|---|
| S1 | Backup arhivira **privatne ključeve step-ca u čistom tar.gz** | `scripts/saguaro-backup.sh` | kompromitacija cijele interne PKI iz backupa | šifrirati backup (age/GPG), CA ključeve u zaseban paket sa zasebnim ključem, sukladno specifikaciji |
| S2 | Admin lozinka u plaintextu u `saguaro.env` + `bootstrap-admin-password` | installer | čitljiva grupi saguaro | systemd `LoadCredential=`, hash umjesto lozinke, prisilna promjena pri prvom loginu |
| S3 | KDF je ručni HMAC-SHA256 loop | `main.go:224` | slabiji od standarda | Argon2id (`golang.org/x/crypto/argon2`) uz migraciju |
| S4 | Sesije samo u RAM-u | `main.go` | svi korisnici izbačeni pri restartu; nema revokacije kroz audit | sesije u PG s expiry i audit vezom |
| S5 | Nema CSRF tokena (oslanja se samo na SameSite=Strict) | `main.go` | prihvatljivo za 0.1, ne za produkciju | double-submit CSRF token |
| S6 | Nema rate-limita na login (samo sleep 350 ms) | `main.go:167` | online brute-force | exponential backoff + lockout + audit event `Security` |
| — | **Status 2026-07-18:** S1–S6, S8 i S9 riješeni. S5: CSRF token vezan uz sesiju (double-submit; `saguaro_csrf` kolačić + `X-CSRF-Token` header, SHA-256 hash u session zapisu, provjera u auth middlewareu za sve ne-GET zahtjeve). S6: eksponencijalni lockout po IP-u i po korisničkom imenu (5 slobodnih pokušaja, zatim 30 s → ×2 do 15 min; 429 + `Retry-After`; audit događaj `login-lockout` sa severity `security`). Otvoreno: S7 (.deb u CI) i S10. | `cmd/saguaro/{main,ratelimit,sessions}.go` | — | — |
| S7 | `go build` na produkcijskom serveru (golang-go u base paketima) | installer | toolchain na appliance-u, nepredvidive verzije | build artefakt (.deb) u CI, installer instalira paket |
| S8 | Kea ctrl-agent instaliran, ali neaktiviran i nezaštićen default config | installer | ako se kasnije uključi bez auth → nekontrolirani API | eksplicitno konfigurirati na 127.0.0.1 + basic auth |
| S9 | UFW `--force enable` bez provjere postojeće SSH sesije izvan admin mreže | installer | lockout | prijeći na nftables + confirm-or-rollback mehanizam (vidi §4.2) |
| S10 | Health check `curl` ide na HTTP (`http://127.0.0.1:9080`) — OK jer loopback, ali `SAGUARO_SECURE_COOKIE=true` znači da login preko curl-a ne prolazi test sesije | installer | slaba dubina health checka | health endpoint bez auth + dubinski check kroz adapter |

### 1.3 Što je u projektu već ispravno postavljeno (zadržati)

- Transakcijski tok promjene: Inspect → Validate → Backup → Apply → Verify → Rollback
  (`internal/adapters/README.md`) — identičan konfiguracijskom tijeku iz specifikacije.
- systemd hardening (`NoNewPrivileges`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`).
- Eksplicitna zabrana blanket sudo-a (`packaging/sudoers/saguaro-adapter`).
- Politika: DHCP se ne pokreće ako parametri nisu zadani (sprječava drugi DHCP na mreži).
- Audit log s actor/action/target/result/remoteIP — proširiti na shemu iz specifikacije
  (correlation ID, stara/nova vrijednost, verzija konfiguracije).

---

## 2. Ciljana arhitektura pune instalacije

```
                        ┌──────────────────────────────────────────┐
                        │  saguaro (Go, 127.0.0.1:9080, bez root)  │
                        │  GUI + API + RBAC + audit + scheduler    │
                        └───────┬──────────────────┬───────────────┘
                                │ unix socket      │ SQL
                        ┌───────▼────────┐  ┌──────▼───────────────┐
                        │ saguaro-agent  │  │ PostgreSQL 16        │
                        │ (root, fiksne  │  │  db: saguaro (config,│
                        │  operacije)    │  │  audit, events)      │
                        └───┬────────────┘  │  db: kea  db: pdns   │
        ┌───────────┬───────┼──────┬────────┴──────────┬───────────┘
        ▼           ▼       ▼      ▼                   ▼
   nftables      netplan  Kea    Unbound:53      PowerDNS:5300
   (host+gw fw)  (mreža)  (PG)   (resolver,RPZ)  (auth, PG, API)
        │                   │
        ▼                   ▼
   Suricata (IDS af-packet / IPS NFQUEUE)   kea-dhcp-ddns ──TSIG──▶ PowerDNS
        
   step-ca (ACME interno) ─▶ NGINX (GUI + reverse proxy)
   WireGuard / OpenVPN / strongSwan
   saguaro-eventd (journald + eve.json → PG events) ─▶ mail alerting
```

Privilegijska granica: `saguaro` (web) nikad ne izvršava shell; sve mutacije idu kroz
`saguaro-agent` (root, zaseban binarni servis, unix socket s peer-credential provjerom,
fiksni katalog operacija) — točno kako specifikacija traži ("Backend agent — zaseban
privilegirani servis").

### 2.1 Hardverski profili — SNA ne smije pretpostavljati Core i5

Ciljni hardver ide od pasivno hlađenih mini-PC-jeva (Celeron/N100, stari Atom,
arm64/RPi) do pravih appliance kutija. Odabir komponenti to već podržava: Go
control-plane je jedan binary bez runtimea, Kea/Unbound/PowerDNS/nftables su
lagani, Docker je opt-in, a ELK je svjesno izbačen. Jedina stvarno skupa
komponenta je **Suricata** — i zato je modul, ne jezgra.

| Profil | Tipičan hardver | RAM | Podržani načini rada |
|---|---|---|---|
| **A — Minimal** | N100/Celeron, arm64, stari mini-PC, 2 jezgre | 2–4 GB | Infrastructure / Server: DHCP, DNS, DDNS, step-ca, NGINX, WireGuard, RPZ filtering, mail, backup. **Suricata isključena.** |
| **B — Standard** | 4 jezgre (i3/N305/Ryzen embedded) | 8 GB | + Gateway: nftables NAT/routing na ~1 Gbit, IDS na odabranim VLAN-ovima |
| **C — Full UTM** | 6–8+ jezgri (i5 klasa i više), NVMe | 16 GB+ | + IPS inline, Multi-WAN, puna retencija logova, izvještaji |

Orijentacijska potrošnja po modulu (idle → radno): jezgra + PostgreSQL
~250–500 MB; Kea + Unbound + PowerDNS ~150–250 MB; NGINX + step-ca ~50–100 MB;
WireGuard zanemarivo (kernel); **Suricata 1–4 GB+ RAM i jezgre proporcionalno
prometu i broju pravila** — na 2 jezgre IDS otima kapacitet svemu ostalom.

Pravila koja iz toga slijede:

1. **Hardver je ovisnost modula**, isto kao broj NIC-ova: GUI treba reći
   "IDS/IPS nije dostupan: uređaj ima 4 GB RAM-a, potrebno je najmanje 8 GB"
   umjesto da dopusti uključivanje koje ubije DHCP i DNS.
2. Installer na profilu A postavlja manju retenciju logova (journald
   `SystemMaxUse`, manje particije eventa) i ne nudi Security paket.
3. RPZ DNS filtering je jeftina alternativa IPS-u i radi i na profilu A —
   to je zadana "security" razina za slab hardver.
4. Argon2id (64 MiB po pokušaju prijave) je prihvatljiv i na 2 GB uređaju jer
   je GUI administratorski (1–2 istovremene prijave); S6 rate-limit dodatno
   ograničava paralelne pokušaje, dakle i memorijski trošak napadača.
5. `go build` na appliance-u (nalaz S7) najviše boli baš na slabom hardveru —
   prebuilt .deb rješava i to.
6. arm64 je ravnopravna arhitektura (installer je već provjerava).

Portovi (Infrastructure mode):

| Port | Servis | Bind/izloženost |
|---|---|---|
| 443/tcp | NGINX → GUI | samo management mreža (nftables set `@mgmt`) |
| 53/udp+tcp | Unbound | klijentske mreže |
| 67/udp | Kea DHCPv4 | LAN interface |
| 5300 | PowerDNS auth | 127.0.0.1 |
| 8000 | Kea ctrl-agent | 127.0.0.1 |
| 8081 | PowerDNS API | 127.0.0.1 |
| 9000 | step-ca | 127.0.0.1 (+ mgmt za ACME klijente po potrebi) |
| 9080 | saguaro GUI backend | 127.0.0.1 |
| 51820/udp | WireGuard | WAN (tek u Gateway modu) |

---

## 3. Točan redoslijed pune instalacije

Redoslijed je dizajniran tako da je **nakon svake faze sustav u konzistentnom, produkcijski
upotrebljivom stanju** i da nijedna faza ne zahtijeva rušenje prethodne.

```
Faza 0  OS priprema i hardening
Faza 1  PostgreSQL + Saguaro jezgra (GUI, RBAC, audit, backup, mail, eventd)
Faza 2  Mrežna osnova (netplan) + nftables host firewall  ← zamjenjuje UFW
Faza 3  Kea DHCP (PG backend + ctrl-agent)
Faza 4  Unbound + PowerDNS + DHCP-DNS integracija (DDNS)
Faza 5  step-ca + ACME + zamjena bootstrap GUI certifikata
Faza 6  NGINX reverse proxy (objava servisa)
Faza 7  WireGuard remote access
--- do ovdje: Infrastructure mode, SNA 1.0/1.5 ---
Faza 8  Gateway mode (routing, NAT, zone, port forwarding)
Faza 9  Suricata IDS (14 dana) → IPS ; Unbound RPZ filtering
Faza 10 Multi-WAN, IPsec/OpenVPN, izvještaji
```

### Faza 0 — OS priprema

```bash
# Ubuntu Server 24.04 LTS, minimalna instalacija
# Particioniranje: / (25G), /var/log (10G, zaseban — limit logova iz specifikacije),
# /var/lib/postgresql (ostatak), swap po RAM-u
timedatectl set-timezone Europe/Zagreb
apt-get update && apt-get -y full-upgrade
apt-get install -y chrony unattended-upgrades
# SSH hardening
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/;s/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl reload ssh
```

Provjera faze 0: `timedatectl` (NTP sync yes), `ssh -o PasswordAuthentication=yes` odbijen.

### Faza 1 — PostgreSQL + Saguaro jezgra

```bash
apt-get install -y postgresql-16
sudo -u postgres psql <<'SQL'
CREATE ROLE saguaro LOGIN;
CREATE ROLE kea LOGIN;
CREATE ROLE pdns LOGIN;
CREATE DATABASE saguaro OWNER saguaro;
CREATE DATABASE kea OWNER kea;
CREATE DATABASE pdns OWNER pdns;
SQL
```

`pg_hba.conf` — samo lokalni peer/scram pristup:

```
local  saguaro  saguaro                 peer
local  kea      kea                     peer
local  pdns     pdns                    peer
host   all      all      127.0.0.1/32   scram-sha-256
```

Saguaro event shema (minimalna, prema specifikaciji logova):

```sql
CREATE TABLE events (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  ts TIMESTAMPTZ NOT NULL,
  module TEXT NOT NULL,          -- dhcp|dns|firewall|vpn|ids|...
  severity TEXT NOT NULL CHECK (severity IN
    ('info','notice','warning','error','critical','security')),
  host TEXT, username TEXT,
  src_ip INET, dst_ip INET, mac MACADDR, iface TEXT,
  action TEXT, result TEXT, message TEXT NOT NULL,
  device_id BIGINT, rule_id BIGINT,
  raw JSONB, correlation_id UUID
) PARTITION BY RANGE (ts);        -- mjesečne particije → retencija = DROP PARTITION

CREATE TABLE audit_log (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  ts TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
  old_value JSONB, new_value JSONB,
  result TEXT NOT NULL, remote_ip INET,
  config_version INT, correlation_id UUID
);
REVOKE DELETE, UPDATE ON audit_log FROM saguaro;   -- append-only i za aplikaciju
```

Mail modul (konfiguracija u GUI-ju, lozinka šifrirana AES-256-GCM ključem iz
`/etc/saguaro/secret.key`, root:saguaro 0640):

```
SMTP server:  smtp.smtp2go.com   Port: 587   TLS: STARTTLS
From:         sna@saguaro.info
Agregacija:   prvi event odmah, duplikati 10 min, zatim sažetak
```

Provjera faze 1: `curl -fsS https://<fqdn>/api/health`, test mail iz GUI-ja,
`sudo -u saguaro psql -c 'select 1'`.

### Faza 2 — Mreža + nftables host firewall

Netplan (Infrastructure mode — jedan interface):

```yaml
# /etc/netplan/10-saguaro.yaml
network:
  version: 2
  ethernets:
    enp2s0:
      addresses: [192.168.200.2/24]
      routes: [{to: default, via: 192.168.200.1}]
      nameservers: {addresses: [127.0.0.1], search: [example.internal]}
```

nftables host politika — **isti skelet koji kasnije proširuje Gateway mod**:

```
# /etc/nftables.conf (upravlja Saguaro; fragmenti u /etc/saguaro/nft/)
flush ruleset
table inet saguaro {
  set mgmt   { type ipv4_addr; flags interval; elements = { 192.168.200.0/24 } }
  set lan    { type ipv4_addr; flags interval; elements = { 192.168.200.0/24 } }

  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    ct state invalid drop
    iif "lo" accept
    ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded } accept
    ip saddr @mgmt tcp dport { 22, 443 } accept
    ip saddr @lan  meta l4proto { tcp, udp } th dport 53 accept
    iifname "enp2s0" udp dport 67 accept
    log prefix "SNA-INPUT-DROP " group 0 counter
  }
  chain forward { type filter hook forward priority 0; policy drop; }  # prazno do Gateway moda
}
```

Aktivacija sa zaštitom od lockouta (mehanizam iz specifikacije, 120 s):

```bash
nft -c -f /etc/nftables.candidate   # validacija bez primjene
cp /etc/nftables.conf /etc/nftables.rollback
nft -f /etc/nftables.candidate
systemd-run --on-active=120s --unit=sna-fw-rollback \
  sh -c '[ -f /run/saguaro/fw-confirmed ] || nft -f /etc/nftables.rollback'
# GUI gumb "Veza radi — potvrdi" → touch /run/saguaro/fw-confirmed && systemctl stop sna-fw-rollback.timer
apt-get purge -y ufw
```

Provjera faze 2: nova SSH sesija iz mgmt mreže radi, `nft list ruleset`,
namjerno ne potvrditi jednu promjenu i verificirati automatski rollback.

### Faza 3 — Kea DHCP (PostgreSQL + ctrl-agent)

```bash
apt-get install -y kea-dhcp4-server kea-dhcp-ddns-server kea-ctrl-agent kea-admin
sudo -u kea kea-admin db-init pgsql -u kea -n kea    # inicijalizacija sheme
```

```jsonc
// /etc/kea/kea-dhcp4.conf
{ "Dhcp4": {
  "interfaces-config": { "interfaces": [ "enp2s0" ] },
  "control-socket": { "socket-type": "unix", "socket-name": "/run/kea/kea4-ctrl-socket" },
  "lease-database": { "type": "postgresql", "name": "kea", "user": "kea", "host": "" },
  "hosts-database": { "type": "postgresql", "name": "kea", "user": "kea", "host": "" },
  "valid-lifetime": 3600, "renew-timer": 900, "rebind-timer": 1800,
  "early-global-reservations-lookup": true,
  "dhcp-ddns": { "enable-updates": true },
  "ddns-qualifying-suffix": "example.internal.",
  "subnet4": [ {
    "id": 1, "subnet": "192.168.200.0/24",
    "pools": [ { "pool": "192.168.200.100 - 192.168.200.200" } ],
    "option-data": [
      { "name": "routers",             "data": "192.168.200.1" },
      { "name": "domain-name-servers", "data": "192.168.200.2" },
      { "name": "domain-name",         "data": "example.internal" } ] } ],
  "loggers": [ { "name": "kea-dhcp4", "severity": "INFO",
                 "output-options": [ { "output": "syslog" } ] } ]
} }
```

```jsonc
// /etc/kea/kea-ctrl-agent.conf — API za GUI, samo loopback + auth (nalaz S8)
{ "Control-agent": {
  "http-host": "127.0.0.1", "http-port": 8000,
  "authentication": { "type": "basic",
    "clients": [ { "user": "saguaro", "password-file": "/etc/kea/api-password" } ] },
  "control-sockets": {
    "dhcp4": { "socket-type": "unix", "socket-name": "/run/kea/kea4-ctrl-socket" },
    "d2":    { "socket-type": "unix", "socket-name": "/run/kea/kea-ddns-ctrl-socket" } }
} }
```

Provjera faze 3: `kea-dhcp4 -t /etc/kea/kea-dhcp4.conf`, testni lease
(`perfdhcp -4 -r 1 -R 1 enp2s0` iz test VLAN-a ili stvarni klijent), lease vidljiv u
`SELECT * FROM lease4;`, API: `curl -u saguaro:*** -X POST -H 'Content-Type: application/json' -d '{"command":"lease4-get-all"}' 127.0.0.1:8000`.

### Faza 4 — Unbound + PowerDNS + DDNS integracija

```bash
apt-get install -y unbound pdns-server pdns-backend-pgsql
sudo -u pdns psql pdns < /usr/share/pdns-backend-pgsql/schema/schema.pgsql.sql
```

```ini
# /etc/powerdns/pdns.conf — autoritativni, samo loopback
local-address=127.0.0.1
local-port=5300
launch=gpgsql
gpgsql-host=/var/run/postgresql
gpgsql-dbname=pdns
gpgsql-user=pdns
api=yes
api-key=<random-iz-saguaro-secreta>
webserver-address=127.0.0.1
webserver-port=8081
dnsupdate=yes                      # RFC2136 za Kea DDNS
allow-dnsupdate-from=127.0.0.1/32
```

```
# /etc/unbound/unbound.conf.d/saguaro.conf — resolver prema klijentima
server:
  interface: 192.168.200.2
  interface: 127.0.0.1
  access-control: 192.168.200.0/24 allow
  access-control: 127.0.0.0/8 allow
  cache-min-ttl: 60
  prefetch: yes
  # lokalne zone delegiraju na PowerDNS
  domain-insecure: "example.internal."
  domain-insecure: "200.168.192.in-addr.arpa."
  local-zone: "example.internal." nodefault
stub-zone:
  name: "example.internal."
  stub-addr: 127.0.0.1@5300
stub-zone:
  name: "200.168.192.in-addr.arpa."
  stub-addr: 127.0.0.1@5300
```

Zone i TSIG (Saguaro to radi kroz PowerDNS API; ručno za bootstrap):

```bash
pdnsutil create-zone example.internal ns1.example.internal
pdnsutil create-zone 200.168.192.in-addr.arpa ns1.example.internal
pdnsutil generate-tsig-key kea-ddns hmac-sha256
pdnsutil set-meta example.internal TSIG-ALLOW-DNSUPDATE kea-ddns
pdnsutil set-meta 200.168.192.in-addr.arpa TSIG-ALLOW-DNSUPDATE kea-ddns
```

```jsonc
// /etc/kea/kea-dhcp-ddns.conf
{ "DhcpDdns": {
  "ip-address": "127.0.0.1", "port": 53001,
  "control-socket": { "socket-type": "unix", "socket-name": "/run/kea/kea-ddns-ctrl-socket" },
  "tsig-keys": [ { "name": "kea-ddns", "algorithm": "HMAC-SHA256", "secret": "<tajna>" } ],
  "forward-ddns": { "ddns-domains": [ { "name": "example.internal.",
      "key-name": "kea-ddns", "dns-servers": [ { "ip-address": "127.0.0.1", "port": 5300 } ] } ] },
  "reverse-ddns": { "ddns-domains": [ { "name": "200.168.192.in-addr.arpa.",
      "key-name": "kea-ddns", "dns-servers": [ { "ip-address": "127.0.0.1", "port": 5300 } ] } ] }
} }
```

Provjera faze 4: `dig @192.168.200.2 google.com` (rekurzija), `dig @192.168.200.2
server1.example.internal` (stub → PowerDNS), novi DHCP klijent dobije lease → `dig
+short <hostname>.example.internal` i PTR se automatski pojave, `pdnsutil check-all-zones`.

### Faza 5 — step-ca + ACME

Postojeći installer korak je dobar; dopune: ACME provisioner već uključen
(`--acme`), GUI certifikat se odmah zamjenjuje internim:

```bash
step ca certificate saguaro.example.internal /etc/saguaro/gui.crt /etc/saguaro/gui.key \
  --ca-url https://127.0.0.1:9000 --root /etc/step-ca/certs/root_ca.crt
# obnova: systemd timer `step ca renew --daemon` ili ACME klijent (certbot/lego) prema step-ca
```

CA backup politika (nalaz S1): root CA ključ **offline** nakon izdavanja intermediate;
`/etc/step-ca/secrets` ide isključivo u zasebni, age-šifrirani paket:

```bash
age -r <recovery-public-key> -o ca-secrets-$(date +%F).tar.gz.age ca-secrets.tar.gz
```

Provjera faze 5: `step ca health`, GUI dostupan bez browser upozorenja na stroju s
instaliranim root certom, `step certificate inspect /etc/saguaro/gui.crt`.

### Faza 6 — NGINX reverse proxy

Postojeći vhost iz installera je ispravan skelet; Saguaro generira dodatne published
servise iz deklarativnog modela u `/etc/nginx/saguaro/*.conf`, uvijek kroz
`nginx -t` → reload → health-check → rollback.

```nginx
# primjer published servisa (generira wizard)
server {
    listen 443 ssl;
    http2 on;
    server_name app1.example.internal;
    ssl_certificate     /etc/saguaro/certs/app1.crt;   # step-ca ACME
    ssl_certificate_key /etc/saguaro/certs/app1.key;
    add_header X-Content-Type-Options nosniff always;
    location / {
        proxy_pass http://192.168.200.15:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Upgrade $http_upgrade;      # WebSocket
        proxy_set_header Connection "upgrade";
    }
}
```

### Faza 7 — WireGuard remote access

```bash
apt-get install -y wireguard
wg genkey | tee /etc/wireguard/server.key | wg pubkey > /etc/wireguard/server.pub
```

```ini
# /etc/wireguard/wg0.conf
[Interface]
Address = 10.99.0.1/24
ListenPort = 51820
PrivateKey = <server.key>

[Peer]   # generira VPN wizard po korisniku
PublicKey = <peer-pub>
AllowedIPs = 10.99.0.10/32
```

U Infrastructure modu (SNA nije gateway) specifikacija ispravno traži vanjski port
forward: na postojećem firewallu (OPNsense/Sophos) proslijediti UDP 51820 → SNA, a u
nftables input lancu otvoriti `udp dport 51820 accept`. Klijentski profil dobiva
`AllowedIPs = 192.168.200.0/24, 10.99.0.0/24`.

Provjera faze 7: `wg show` (handshake), ping s VPN klijenta na LAN resurs, DNS upit
kroz tunel na 192.168.200.2.

--- **Kraj Infrastructure faza — sustav je produkcijski SNA 1.5** ---

### Faza 8 — Gateway mode (uključuje se wizardom, ne reinstalacijom)

Preduvjeti (validira wizard): ≥ 2 fizička interfacea, definiran WAN, potvrda da
uzvodni firewall/router prelazi u bridge ili se uklanja.

```yaml
# netplan proširenje
network:
  version: 2
  ethernets:
    wan0: {dhcp4: true}                      # ili statički od ISP-a
    lan0: {addresses: [192.168.200.1/24]}
  vlans:
    lan0.20: {id: 20, link: lan0, addresses: [192.168.20.1/24]}   # DMZ primjer
```

```
# nftables proširenja (isti table inet saguaro)
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    ct state invalid drop
    iifname "lan0" oifname "wan0" accept                  # LAN → Internet
    iifname "lan0.20" oifname "wan0" tcp dport { 80, 443 } accept  # DMZ ograničeno
    ct status dnat accept                                  # port forwardi
    log prefix "SNA-FWD-DROP " group 0 counter
  }

table ip saguaro-nat {
  map port_forward { type inet_service : ipv4_addr . inet_service }
  chain prerouting {
    type nat hook prerouting priority dstnat;
    iifname "wan0" dnat ip addr . port to tcp dport map @port_forward
  }
  chain postrouting {
    type nat hook postrouting priority srcnat;
    oifname "wan0" masquerade
  }
}
```

```bash
# routing
sysctl -w net.ipv4.ip_forward=1   # trajno u /etc/sysctl.d/90-saguaro.conf, ali
# postavlja ga isključivo Gateway modul — Infrastructure mode drži 0
```

Provjera faze 8: klijent iz LAN-a izlazi na Internet, `nft list map ip saguaro-nat
port_forward`, traceroute pokazuje SNA kao gateway, DMZ VLAN ne može na LAN.

### Faza 9 — Suricata IDS → IPS + DNS filtering

```bash
apt-get install -y suricata
suricata-update enable-source et/open && suricata-update
```

IDS (prvih 14 dana, af-packet, bez utjecaja na promet):

```yaml
# /etc/suricata/suricata.yaml (ključni dijelovi)
af-packet:
  - interface: lan0
    cluster-id: 99
    defrag: yes
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types: [alert, anomaly, dns, tls, http, flow]
```

IPS prijelaz (samo nakon pregleda false-positive alarma; NFQUEUE iz nftables, u prvom
koraku samo WAN → objavljeni servisi, točno prema specifikaciji):

```
# u chain forward, PRIJE accept pravila za objavljene servise:
iifname "wan0" ct status dnat queue num 0 bypass
```

```bash
suricata -q 0 --runmode workers   # NFQUEUE mod; "bypass" = fail-open ako Suricata padne
```

`bypass` je svjesna odluka: pad IPS-a ne smije srušiti objavljene servise; eventd na
pad Suricate šalje CRITICAL mail ("IPS servis ugašen" iz specifikacije).

DNS filtering (Unbound RPZ):

```
# /etc/unbound/unbound.conf.d/rpz.conf
rpz:
  name: saguaro-blocklist
  zonefile: /var/lib/unbound/rpz-saguaro.zone   # generira Saguaro iz threat lista
  rpz-log: yes
  rpz-log-name: saguaro-rpz
  rpz-action-override: nxdomain
```

Provjera faze 9: `suricata -T -c /etc/suricata/suricata.yaml`, testni alert
(`curl http://testmynids.org/uid/index.html` → alert u eve.json → red u `events`
tablici → mail `[SNA][SECURITY]`), RPZ: `dig blokirana-domena` vraća NXDOMAIN i event.

### Faza 10 — Multi-WAN, IPsec, OpenVPN, izvještaji

- Multi-WAN: policy routing (`ip rule` + zasebne routing tablice po WAN-u), health-check
  ping/HTTP po WAN-u iz saguaro-agenta, failover mijenja default rutu + eventd alert.
- strongSwan za site-to-site (IKEv2, VTI/XFRM interface da se uklopi u nftables zone).
- OpenVPN samo kao kompatibilnost za klijente koji ne mogu WireGuard.
- Dnevni/tjedni izvještaji: SQL agregati nad `events` particijama, slanje kroz postojeći
  mail modul.

---

## 4. Wizardi (GUI vodiči)

Svaki wizard završava standardnim tijekom: **Pregled promjena → Validate → Apply →
Health-check → Potvrda ili automatski rollback**. Nijedan wizard ne piše konfiguraciju
izravno — sve ide kroz saguaro-agent transakciju.

| # | Wizard | Koraci | Ključne validacije |
|---|---|---|---|
| W1 | **Initial Setup** (prva prijava) | 1. odabir načina rada (Infrastructure/Gateway/Full/Server) 2. hostname+domena 3. mgmt mreža 4. admin lozinka+MFA 5. SMTP 6. backup cilj | mod određuje koje su daljnje sekcije GUI-ja vidljive; obavezna promjena bootstrap lozinke |
| W2 | **DHCP mreža** | interface → subnet → pool → gateway/DNS/NTP opcije → (opc.) DDNS | preklapanje subneta/poolova, pool unutar subneta, gateway u subnetu, upozorenje ako na mreži već postoji DHCP (probe DHCPDISCOVER) |
| W3 | **DHCP rezervacija** | odabir uređaja iz leaseova ili ručni MAC → IP → hostname → (opc.) DNS zapis | IP izvan poola ili unutar uz upozorenje, duplikat MAC/IP, hostname RFC-valjan |
| W4 | **DNS zona** | tip (forward/reverse) → ime → NS/SOA → default zapisi | koliziju s postojećom zonom, reverse automatski iz DHCP subneta |
| W5 | **Publish service** (reverse proxy) | ime servisa → upstream IP:port → hostname → TLS izvor (step-ca ACME / LE / vlastiti) → access politika | upstream reachability probe, DNS zapis se nudi automatski, `nginx -t` |
| W6 | **Certifikat** | interni (step-ca) / javni (LE DNS-01) → SAN-ovi → deploy cilj | zabrana javnog certa za privatna imena/IP (već u README politici) |
| W7 | **VPN korisnik** | korisnik → AllowedIPs profil (puni tunel / split) → QR kod / .conf download | jedinstvena peer adresa, rok valjanosti, automatski DNS push |
| W8 | **Gateway conversion** | provjera preduvjeta (2+ NIC) → WAN config → LAN plan → pregled novih nftables pravila → apply s 120 s confirm-or-rollback | eksplicitno upozorenje o promjeni topologije; ne dopušta ako je aktivan samo 1 NIC |
| W9 | **IPS enablement** | prikaz IDS statistike zadnjih 14 dana → izbor zona (prvo samo WAN→published) → drop policy → apply | odbija se ako IDS nije radio min. konfigurirani period ili ima nepregledanih HIGH alarma; gumb "Emergency IPS off" uvijek vidljiv |
| W10 | **Mail alerting** | SMTP postavke → test mail → pravila (event → primatelj → odmah/dnevno) | test mora proći prije spremanja pravila |
| W11 | **Backup/Restore** | cilj (lokalno/SFTP/S3) → raspored → šifriranje (obavezno) → restore drill podsjetnik | restore drill svakih 90 dana generira Warning ako nije izveden |
| W12 | **Multi-WAN** | drugi WAN → težine/failover → health-check cilj → test failovera | zahtijeva Gateway mod; simulacija ispada prije produkcijske aktivacije |

Primjer poruke o nedostupnoj funkciji (obrazac iz specifikacije, implementirati kao
`dependency` polje na modulu):

> IPS način nije dostupan jer uređaj ne radi kao gateway. Suricatu možete uključiti u
> IDS načinu ako mrežni switch šalje promet na mirror port. → gumb: *Uključi IDS*

---

## 5. Matrica modula i ovisnosti (implementacijski model)

Svaki modul u konfiguracijskoj bazi: `state ∈ {not_installed, disabled, active, error}`,
`depends_on[]`, `mode_mask` (u kojim je načinima rada dozvoljen). Disable **nikad ne
briše** konfiguraciju — samo zaustavlja unit i uklanja generirane fragmente; enable
regenerira iz baze + validira.

| Modul | depends_on | Infrastructure | Gateway | Full | Server |
|---|---|:-:|:-:|:-:|:-:|
| core (GUI, PG, audit, mail, backup) | — | ✔ | ✔ | ✔ | ✔ |
| host-firewall (nftables input) | core | ✔ | ✔ | ✔ | ✔ |
| dhcp | interface | ✔ | ✔ | ✔ | ✖ |
| dns-resolver | — | ✔ | ✔ | ✔ | ✔ |
| dns-auth | postgresql | ✔ | ✔ | ✔ | ✔ |
| ddns | dhcp + dns-auth | ✔ | ✔ | ✔ | ✖ |
| step-ca | — | ✔ | ✔ | ✔ | ✔ |
| reverse-proxy | — | ✔ | ✔ | ✔ | ✔ |
| wireguard | host-firewall (+vanjski PF u Infra) | ✔ | ✔ | ✔ | ✖ |
| gateway (routing, NAT) | ≥2 NIC, host-firewall | ✖ | ✔ | ✔ | ✖ |
| port-forward | gateway | ✖ | ✔ | ✔ | ✖ |
| ids | interface/mirror | ✔ | ✔ | ✔ | ✖ |
| ips | gateway + ids(period) | ✖ | ✔ | ✔ | ✖ |
| dns-filter (RPZ) | dns-resolver | ✔ | ✔ | ✔ | ✔ |
| multi-wan | gateway + 2×WAN | ✖ | ✔ | ✔ | ✖ |
| ipsec/openvpn | gateway ili PF | ✖ | ✔ | ✔ | ✖ |

---

## 6. Završna checklista prije predaje korisniku (bilo koji mod)

1. `systemctl --failed` prazan; svi Saguaro moduli u očekivanom stanju na dashboardu.
2. Restart cijelog appliance-a → svi servisi se sami dižu, mail "sustav dostupan nakon
   restarta" NIJE poslan kao CRITICAL (poslan je samo Notice).
3. Backup → prijenos na drugi stroj → **restore drill** → GUI login i DHCP/DNS rade.
4. Namjerno srušiti Kea (`systemctl kill`) → CRITICAL mail u <1 min, dashboard ERROR.
5. Popuniti DHCP pool >80% u test mreži → Warning mail jednom dnevno, ne spam.
6. Audit: promjena rezervacije vidljiva sa starom i novom vrijednosti; pokušaj brisanja
   audita kao `network-operator` odbijen i sam zabilježen kao Security event.
7. Iz ne-mgmt mreže: 443 i 22 nedostupni; 53 dostupan samo klijentskim mrežama.
8. Log particije: simulirati 80% popunjenosti → Warning; audit log preskočen pri
   automatskom čišćenju.
