package main

import (
	"net/http"
	"strings"

	"saguaro.local/network-manager/internal/adapters/nftgen"
)

// The device-access matrix answers "which zone may reach which appliance
// service" explicitly, instead of the two blanket management toggles. Its main
// job is making "the WAN side must not reach the GUI or SSH" a visible,
// verifiable setting rather than something an operator has to remember.

// accessZone is one row offered to the GUI: a zone plus the interface it lands
// on, so the operator can see what a row actually controls.
type accessZone struct {
	Zone      string `json:"zone"`
	Label     string `json:"label"`
	Interface string `json:"interface"`
	Kind      string `json:"kind"`
	// Untrusted marks zones where allowing management is dangerous (the WAN),
	// so the GUI can warn the way the reference appliances do.
	Untrusted bool `json:"untrusted,omitempty"`
}

// accessZones lists the rows for the current configuration: the WAN and LAN
// pseudo-zones, every configured firewall zone, and the VPN tunnel when one is
// running.
func (a *app) accessZones(cfg nftgen.Config) []accessZone {
	var out []accessZone
	if cfg.WANInterface != "" {
		out = append(out, accessZone{Zone: "wan", Label: "WAN (internet)", Interface: cfg.WANInterface, Kind: "wan", Untrusted: true})
	}
	if cfg.LANInterface != "" {
		out = append(out, accessZone{Zone: "lan", Label: "LAN", Interface: cfg.LANInterface, Kind: "lan"})
	}
	for _, z := range cfg.Zones {
		if z.Kind == "wan" {
			continue
		}
		out = append(out, accessZone{Zone: z.Name, Label: strings.ToUpper(z.Name), Interface: z.IfaceName(), Kind: z.Kind})
	}
	if iface, _, _ := a.openvpnFirewall(); iface != "" {
		out = append(out, accessZone{Zone: "vpn", Label: "VPN (klijenti na daljinu)", Interface: iface, Kind: "vpn"})
	}
	return out
}

// defaultACLs derives a matrix from the settings currently in force, so the
// first time the page is opened it shows what the appliance actually does
// today rather than an empty grid the operator would have to guess at.
func (a *app) defaultACLs(cfg nftgen.Config, zones []accessZone) []nftgen.ServiceACL {
	internal := map[string]bool{}
	for _, n := range nftgen.ZoneNetworks(cfg.Zones) {
		internal[n] = true
	}
	out := make([]nftgen.ServiceACL, 0, len(zones))
	for _, z := range zones {
		row := nftgen.ServiceACL{Zone: z.Zone}
		switch z.Kind {
		case "wan":
			row.HTTPS, row.SSH = cfg.MgmtOnWAN, cfg.MgmtOnWAN
			row.Ping = true
		case "lan":
			row.HTTPS, row.SSH = cfg.MgmtOnLAN, cfg.MgmtOnLAN
			row.DNS, row.Ping = true, true
			row.DHCP = cfg.DHCPInterface == "" || cfg.DHCPInterface == z.Interface
		case "vpn":
			row.DNS, row.Ping = true, true
		default:
			// Internal zones already had resolver access through internal4.
			row.DNS, row.Ping = true, true
			row.DHCP = cfg.DHCPInterface == z.Interface
		}
		out = append(out, row)
	}
	return out
}

// apiDeviceAccessGet returns the zone rows plus the effective matrix.
func (a *app) apiDeviceAccessGet(w http.ResponseWriter, r *http.Request) {
	cfg, configured := a.getGateway()
	zones := a.accessZones(cfg)
	acls := cfg.ServiceACLs
	derived := false
	if len(acls) == 0 {
		acls = a.defaultACLs(cfg, zones)
		derived = true
	} else {
		// Keep the matrix aligned with the zones that exist now: add rows for
		// new zones (denied by default) and drop rows for deleted ones.
		byZone := map[string]nftgen.ServiceACL{}
		for _, r := range acls {
			byZone[r.Zone] = r
		}
		acls = acls[:0]
		for _, z := range zones {
			if row, ok := byZone[z.Zone]; ok {
				acls = append(acls, row)
			} else {
				acls = append(acls, nftgen.ServiceACL{Zone: z.Zone})
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"configured": configured, "zones": zones, "acls": acls, "derived": derived,
		"adminNetwork": cfg.AdminNetwork,
	})
}

// apiDeviceAccessPut stores the matrix. Validation rejects a matrix that would
// leave the appliance unreachable; applying it still goes through the firewall
// transaction with its confirm-or-rollback window.
func (a *app) apiDeviceAccessPut(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ACLs         []nftgen.ServiceACL `json:"acls"`
		AdminNetwork *string             `json:"adminNetwork,omitempty"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	cfg, ok := a.getGateway()
	if !ok {
		writeError(w, http.StatusConflict, "gateway nije konfiguriran")
		return
	}
	known := map[string]bool{}
	for _, z := range a.accessZones(cfg) {
		known[z.Zone] = true
	}
	clean := make([]nftgen.ServiceACL, 0, len(in.ACLs))
	for _, row := range in.ACLs {
		row.Zone = strings.TrimSpace(row.Zone)
		if !known[row.Zone] {
			writeError(w, http.StatusBadRequest, "nepoznata zona: "+row.Zone)
			return
		}
		clean = append(clean, row)
	}
	cfg.ServiceACLs = clean
	if in.AdminNetwork != nil {
		cfg.AdminNetwork = strings.TrimSpace(*in.AdminNetwork)
	}
	if err := cfg.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.setGateway(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist device access")
		return
	}
	wanMgmt := false
	for _, row := range clean {
		if row.Zone == "wan" && (row.HTTPS || row.SSH) {
			wanMgmt = true
		}
	}
	a.recordSev(r, a.actor(r), "device-access", "firewall", "success", "security",
		map[string]any{"rows": len(clean), "mgmtFromWan": wanMgmt})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "acls": clean,
		"note": "Spremljeno. Primijeni firewall (Gateway → Primijeni) da pravila stupe na snagu."})
}
