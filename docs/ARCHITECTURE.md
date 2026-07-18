# Arhitektura

```text
Administrator browser
        |
      HTTPS
        |
Saguaro control-plane ---- audit/desired state/events ---- PostgreSQL
        |                                                  (i Kea/PowerDNS backend)
        +---- localhost adapter ---- lokalni servisi
        |
        +---- mTLS task API ---- Saguaro agent na udaljenom čvoru
                                      |-- Kea Control Agent (127.0.0.1:8000, basic auth)
                                      |-- PowerDNS HTTP API (127.0.0.1:8081)
                                      |-- Unbound (unbound-control)
                                      |-- nftables renderer (nft -c validacija)
                                      |-- step-ca / ACME client
                                      `-- ograničeni Nginx renderer
```

## Komponente

Control-plane sadrži API, ugrađeni web UI, autentikaciju, RBAC, audit, scheduler, inventar i orkestraciju promjena. Agent poznaje samo unaprijed definirane operacije i nikada ne prihvaća proizvoljnu naredbu. Adapteri pretvaraju kanonski Saguaro model u API pozive pojedinog proizvoda.

## Tok promjene

Zahtjev dobiva `change_id`. Orkestrator zaključava cilj, čita trenutno stanje i provjerava očekivanu reviziju. Nakon validacije sprema šifriranu snimku, primjenjuje promjenu i pokreće servisni i funkcionalni health-check. Tek tada promjena postaje uspješna; inače slijedi rollback.

## Mrežni portovi

- `443/tcp`: administratorski GUI/API (po mogućnosti samo management VLAN ili VPN)
- `9443/tcp`: agent task API preko mTLS-a, ili outbound-only agent kanal
- Kea/Technitium/step-ca administrativni API-ji ostaju na loopbacku gdje je moguće

Za lokacije iza NAT-a preporučen je outbound-only agent koji periodično preuzima potpisane zadatke, čime se izbjegava otvaranje ulaznog management porta.

## Backup

Backup obuhvaća bazu control-planea, konfiguracije servisa, DNS zone, Kea konfiguraciju i PKI podatke. Privatni CA ključevi zahtijevaju zasebnu šifriranu kopiju i dokumentiran restore postupak. Backup bez periodičnog restore testa ne smatra se provjerenim.
