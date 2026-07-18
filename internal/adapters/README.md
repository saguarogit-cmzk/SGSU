# Privileged adapters

Production adapters implement a fixed transaction contract:

1. `Inspect` reads actual state and its revision.
2. `Validate` validates canonical input and renders to a temporary directory.
3. `Backup` stores the current configuration with checksums.
4. `Apply` atomically replaces managed fragments only.
5. `Verify` runs native checks and a functional health probe.
6. `Rollback` restores the snapshot if apply or verification fails.

Planned native validators are `unbound-checkconf`, `pdnsutil check-all-zones`,
Kea `config-test` (`kea-dhcp4 -t`), `nft -c -f`, `step ca health` and `nginx -t`.
The control-plane never accepts an arbitrary executable or shell fragment from an
API request.
