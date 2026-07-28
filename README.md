# Saguaro Network Control

Saguaro Network Control je mali web control-plane za centralno upravljanje lokalnim i udaljenim DHCP, DNS, PKI i reverse-proxy servisima na Ubuntu 24.04 LTS ili novijem LTS-u.

## Trenutačno stanje

Milestone `0.1` sadrži funkcionalnu Go jezgru, prijavu, perzistentni audit, health API,
inventar servisa i početni responsivni GUI. Izvršavanje privilegiranih operacija je
namjerno onemogućeno dok se ne implementiraju i testiraju transakcijski adapteri.

Za razvoj:

```bash
make run
```

Otvorite `http://127.0.0.1:9080`. Razvojni način isključuje `Secure` cookie samo kroz
Makefile; produkcija se objavljuje isključivo iza HTTPS-a.

## Ubuntu instalacija

Na čistom Ubuntu 24.04 LTS serveru dohvatite repozitorij, pregledajte plan s
`--dry-run`, pa pokrenite instalaciju:

```bash
# 1. dohvat repozitorija
sudo apt-get update && sudo apt-get install -y git
git clone https://github.com/saguarogit-cmzk/SGSU.git
cd SGSU

# 2. prvo pregled plana (ništa se ne mijenja)
sudo ./scripts/install-ubuntu.sh --dry-run --admin-network 192.168.10.0/24 --client-network 192.168.10.0/24

# 3. stvarna instalacija (prilagodi parametre svojoj mreži)
sudo ./scripts/install-ubuntu.sh \
  --admin-network 192.168.10.0/24 \
  --client-network 192.168.10.0/24 \
  --server-name saguaro.example.internal \
  --dns-domain example.internal \
  --dhcp-interface enp1s0 \
  --dhcp-subnet 192.168.10.0/24 \
  --dhcp-pool 192.168.10.100-192.168.10.200 \
  --dhcp-router 192.168.10.1
```

Preporučeno je dodati `--deb <putanja-ili-URL>` s gotovim `saguaro_*.deb` paketom
koji builda CI (GitHub Actions, `.github/workflows/build-deb.yml`; artefakti za
amd64 i arm64, uz release na `v*` tagove). Tada se na uređaj ne instalira Go
toolchain niti se builda iz izvornog koda — bitno na slabijem hardveru. Bez
`--deb` installer i dalje builda lokalno (fallback za offline instalacije).
Paket se može ručno složiti i na bilo kojem Linuxu sa `scripts/build-deb.sh`.

Najprije je preporučeno pregledati plan s `--dry-run`. Ako se DHCP parametri izostave,
Kea se instalira, ali se ne pokreće. To sprječava slučajno pokretanje drugog DHCP
servera na produkcijskoj mreži.

Installer radi kopiju postojećih konfiguracija u `/var/backups/saguaro-installer`,
postavlja PostgreSQL, Kea (PostgreSQL backend), Unbound, PowerDNS, DDNS integraciju,
internu Step CA, Nginx, nftables host firewall, šifrirani dnevni backup i node
exporter. Inicijalna administratorska lozinka sprema se u
`/etc/saguaro/bootstrap-admin-password` i servisu se predaje isključivo kroz systemd
`LoadCredential`. Ključ za dešifriranje backupa (`/etc/saguaro/backup.agekey`) odmah
nakon instalacije kopirajte na offline medij.

## Oporavak nakon kvara (DR)

Kompletan DR se vodi iz GUI-ja (modul **Backup**):

1. **Priprema (na uređaju koji radi):** iz *Lokalne kopije* preuzmi arhive (`.age`), a iz
   *Ključ za oporavak (DR)* preuzmi `backup.agekey`. Čuvaj ih **offline i odvojeno** —
   ključ dešifrira sve backupe, tretiraj ga kao master lozinku.
2. **Oporavak (novi/zamjenski uređaj):** instaliraj Ubuntu → pokreni `install-ubuntu.sh`
   (koraci gore) → u GUI-ju **Backup → Uvezi ključ** (zalijepi spremljeni ključ) → stavi
   arhivu u `/var/backups/saguaro/` → **Vrati iz ove kopije**. Vraćaju se konfiguracija,
   baze (DHCP leaseovi / DNS zapisi / eventi) i interni CA; servisi se ponovno pokreću.

## Potvrđeni sastav komponenti

Odluke potvrđene 2026-07-17 (vidi `docs/SNA-FULL-INSTALL.md`):

- **Go control-plane**: single-binary GUI/API bez vanjskog runtimea (odbačen Laravel).
- **PostgreSQL**: konfiguracijska baza, event baza te backend za Kea i PowerDNS.
- **Kea DHCP 2.6+**: DHCPv4/DHCPv6, subneti, poolovi, rezervacije i lease pregled preko Control Agenta.
- **Unbound**: rekurzivni resolver prema klijentima, s RPZ filtriranjem u kasnijoj fazi.
- **PowerDNS Authoritative**: lokalne forward/reverse zone u PostgreSQL-u, upravljanje preko HTTP API-ja (odbačeni BIND9 i Technitium).
- **nftables**: jedini firewall engine — host firewall odmah, gateway/NAT kasnije istim generatorom pravila (odbačen UFW).
- **Smallstep step-ca**: interna privatna CA za `.home.arpa`, privatne domene, uređaje i interne aplikacije.
- **Let's Encrypt**: javno valjani certifikati samo za javno dokazive domene, preferirano DNS-01 challengeom.
- **Nginx**: reverse proxy za interne aplikacije, s konfiguracijom generiranom iz deklarativnog modela.
- **Saguaro agent**: mali lokalni agent na svakom upravljanom čvoru; control-plane mu šalje potpisane, ograničene zadatke.

## Sigurnosni model

GUI nikada ne izvršava proizvoljne shell naredbe. Svaka promjena prolazi slijed:

1. provjera ovlasti (RBAC),
2. validacija modela i preflight provjera ciljnog servisa,
3. snimka prethodne konfiguracije,
4. atomska primjena,
5. health-check,
6. automatski rollback kod greške,
7. nepromjenjiv audit zapis.

Udaljeni agenti koriste mTLS certifikate izdane iz interne step-ca. Tajne se ne spremaju u logove, a API tokeni se spremaju šifrirano. Početne uloge su `admin`, `network-operator`, `dns-operator`, `auditor` i `read-only`.

## Funkcije prvog izdanja

### Dashboard

- status svih lokalnih i udaljenih čvorova,
- stanje Kea, Technitium, step-ca i Nginx servisa,
- upozorenja za istek certifikata, pun DHCP pool i neuspjeli backup,
- zadnje promjene i rezultat primjene.

### DHCP

- subneti, poolovi, gateway, DNS/NTP opcije,
- statičke rezervacije i uvoz/izvoz CSV-a,
- aktivni leaseovi, iskorištenost poola i pretraga po MAC/IP/hostnameu,
- HA status i kontrolirano prebacivanje,
- provjera preklapanja mreža i poolova prije spremanja.

### DNS

- forward i reverse zone,
- A/AAAA/CNAME/MX/TXT/SRV/PTR zapisi,
- split-horizon prikazi,
- conditional forwarding i block liste,
- opcionalno automatsko stvaranje A/PTR zapisa iz DHCP rezervacija,
- DNSSEC status i siguran postupak rotacije ključeva.

### Certifikati

- interna step-ca za privatna imena i IP SAN-ove,
- Let's Encrypt ACME za javne FQDN-ove,
- DNS-01 integracije za wildcard certifikate,
- inventar, obnova, upozorenja i kontrolirani deploy na Nginx,
- zabrana pokušaja izdavanja javnog certifikata za privatne nazive/IP adrese.

### Reverse proxy

- aplikacija, upstream, hostname, TLS politika i access politika,
- WebSocket i standardni sigurnosni headeri,
- provjera `nginx -t` prije reload-a,
- automatski rollback ako novi virtual host nije zdrav.

## Faze implementacije

1. **Temelj**: login, MFA/WebAuthn, RBAC, audit, inventar čvorova, backup i health dashboard.
2. **Kea + Technitium**: puni CRUD, validacija, leaseovi, zone i zapisi.
3. **PKI + Nginx**: step-ca enrollment, ACME DNS-01, cert inventory i proxy aplikacije.
4. **Operativa**: HA, scheduled backup/restore drill, notifikacije, metrics i upgrade workflow.

## Predložena instalacija

Produkcijski installer treba biti idempotentan Debian paket ili Ansible kolekcija, ne `curl | bash`. Instalacija provjerava OS, portove, DNS rezoluciju i vrijeme; zatim instalira samo odabrane komponente. Zadani bind GUI-ja je na management adresu, ne na sve interfejse. Bootstrap administrator dobiva jednokratni token koji se mora odmah zamijeniti.

## Važne odluke

- Control-plane može upravljati postojećim servisima bez njihove reinstalacije.
- Lokalni način koristi Unix socket/loopback; udaljeni način koristi mTLS agent.
- PostgreSQL je zadana baza od prve instalacije: dijele je konfiguracija, event
  collector, Kea (leaseovi i rezervacije) i PowerDNS (zone), što je preduvjet za
  retenciju logova i izvještaje.
- Konfiguracija u bazi je željeno stanje, ali se prije svake promjene čita i uspoređuje stvarno stanje kako se ručne izmjene ne bi tiho pregazile.

## Granice prve verzije

Prva verzija ne treba biti generički SSH panel, firewall manager ni IPAM zamjena. Fokus ostaje na DHCP-u, DNS-u, certifikatima i reverse proxyju. Za ozbiljniji IPAM kasnije se može dodati integracija s NetBoxom.
