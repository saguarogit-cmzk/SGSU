package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"saguaro.local/network-manager/internal/adapters/dnszones"
	"saguaro.local/network-manager/internal/adapters/nftgen"
	"saguaro.local/network-manager/internal/adapters/vlangen"
)

const stagedVLANNetplanName = "staged-vlan-netplan.yaml"
const stagedDNSZonesName = "staged-dns-zones.conf"

func defaultRunDNSZones(ctx context.Context, action string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "sudo", "-n", "/usr/sbin/saguaro-dns", action).CombinedOutput()
}

// The Firewall objects (aliases) and rules are stored inside the firewall
// (gateway) nftgen.Config because nftables is generated as one holistic
// ruleset. These handlers edit just the Aliases/Rules fields; applying them
// regenerates the whole ruleset through the same 120 s confirm/rollback path.

// tunnelNets collects the local/remote subnet pairs of active VPN tunnels
// (WireGuard site-to-site and IPsec) for the forward-chain accept rules.
func (a *app) tunnelNets() []nftgen.TunnelNet {
	var out []nftgen.TunnelNet
	if s := a.getS2S(); s.Enabled {
		for _, site := range s.Sites {
			if len(s.LocalNetworks) == 0 || len(site.RemoteNetworks) == 0 {
				continue
			}
			out = append(out, nftgen.TunnelNet{Local: s.LocalNetworks, Remote: site.RemoteNetworks})
		}
	}
	if ip := a.getIPsec(); ip.Enabled {
		for _, conn := range ip.Connections {
			if len(conn.LocalSubnets) == 0 || len(conn.RemoteSubnets) == 0 {
				continue
			}
			out = append(out, nftgen.TunnelNet{Local: conn.LocalSubnets, Remote: conn.RemoteSubnets})
		}
	}
	return out
}

// pbrUplinks derives the per-WAN conntrack marks for Dual-WAN policy routing
// from the enabled Multi-WAN uplinks (mark = uplink index + 1).
func (a *app) pbrUplinks() []nftgen.PBRUplink {
	var out []nftgen.PBRUplink
	if w := a.getWAN(); w.Enabled {
		for i, u := range w.Uplinks {
			out = append(out, nftgen.PBRUplink{Interface: u.Interface, Mark: i + 1})
		}
	}
	return out
}

// firewallConfig returns the stored firewall config augmented with the active
// tunnel subnets and Dual-WAN PBR marks so the generated ruleset lets tunnel
// traffic through and marks connections per uplink.
func (a *app) firewallConfig() (nftgen.Config, bool) {
	cfg, ok := a.getGateway()
	cfg.TunnelNets = a.tunnelNets()
	cfg.PBRUplinks = a.pbrUplinks()
	return cfg, ok
}

// apiFirewallTest simulates a packet against the custom rules and reports which
// rule matches and whether it passes — no kernel involvement.
func (a *app) apiFirewallTest(w http.ResponseWriter, r *http.Request) {
	var in nftgen.Packet
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	cfg, _ := a.getGateway()
	writeJSON(w, http.StatusOK, cfg.EvaluateForward(in))
}

// apiFirewallCounters reads live packet/byte counters from the running ruleset
// and maps them to each custom rule by its comment (the rule name, which the
// generator writes as `comment "<name> [category]"`). Best effort: if the
// ruleset is not loaded yet it returns an empty map, not an error.
func (a *app) apiFirewallCounters(w http.ResponseWriter, r *http.Request) {
	empty := map[string]any{"counters": map[string]any{}}
	out, err := a.runFirewall(r.Context(), "counters")
	if err != nil {
		writeJSON(w, http.StatusOK, empty)
		return
	}
	var dump struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal(out, &dump) != nil {
		writeJSON(w, http.StatusOK, empty)
		return
	}
	counters := map[string]map[string]int64{}
	for _, entry := range dump.Nftables {
		raw, ok := entry["rule"]
		if !ok {
			continue
		}
		var rule struct {
			Comment string                       `json:"comment"`
			Expr    []map[string]json.RawMessage `json:"expr"`
		}
		if json.Unmarshal(raw, &rule) != nil || rule.Comment == "" {
			continue
		}
		// The generator appends " [category]" to the rule name in the comment;
		// strip it back off to recover the name the GUI keys counters by.
		name := rule.Comment
		if i := strings.Index(name, " ["); i >= 0 {
			name = name[:i]
		}
		for _, ex := range rule.Expr {
			craw, ok := ex["counter"]
			if !ok {
				continue
			}
			var c struct {
				Packets int64 `json:"packets"`
				Bytes   int64 `json:"bytes"`
			}
			if json.Unmarshal(craw, &c) == nil {
				counters[name] = map[string]int64{"packets": c.Packets, "bytes": c.Bytes}
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"counters": counters})
}

func (a *app) apiFirewallGet(w http.ResponseWriter, _ *http.Request) {
	cfg, ok := a.getGateway()
	aliases := cfg.Aliases
	if aliases == nil {
		aliases = []nftgen.Alias{}
	}
	rules := cfg.Rules
	if rules == nil {
		rules = []nftgen.Rule{}
	}
	zones := cfg.Zones
	if zones == nil {
		zones = []nftgen.Zone{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"aliases": aliases, "rules": rules, "zones": zones,
		// "configured" means a base gateway config exists that the ruleset can be
		// generated from. ClientNetwork is the universally required field; the
		// admin network is now optional (management can be bound to WAN/LAN), so
		// keying off it would wrongly report a working gateway as unconfigured.
		"configured": ok && cfg.ClientNetwork != "", "gatewayEnabled": cfg.GatewayEnabled,
		"pending": firewallPending(),
	})
}

// apiFirewallZonesPut replaces the zone definitions. Zones drive the inter-zone
// forward policy (DMZ/guest isolation); applying the firewall regenerates the
// whole ruleset.
func (a *app) apiFirewallZonesPut(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Zones []nftgen.Zone `json:"zones"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	cfg, _ := a.getGateway()
	cfg.Zones = in.Zones
	if err := cfg.ValidateObjects(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.setGateway(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist firewall zones")
		return
	}
	a.record(r, a.actor(r), "firewall-zones", "objects", "success", map[string]any{"count": len(in.Zones)})
	writeJSON(w, http.StatusOK, map[string]any{"zones": cfg.Zones})
}

// apiFirewallVLANsApply creates (or removes) the 802.1Q sub-interfaces backing
// the tagged zones via a generated netplan. Applying with no VLAN zones writes
// an empty netplan, cleaning up any previously created Saguaro VLANs.
func (a *app) apiFirewallVLANsApply(w http.ResponseWriter, r *http.Request) {
	cfg, _ := a.getGateway()
	yaml, err := vlangen.Generate(cfg.Zones)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	staged := filepath.Join(filepath.Dir(a.store.path), stagedVLANNetplanName)
	if err := os.WriteFile(staged, []byte(yaml), 0600); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot write staged VLAN netplan")
		return
	}
	if out, err := a.runNet(r.Context(), "vlan-apply"); err != nil {
		a.recordSev(r, a.actor(r), "zone-vlans", "netplan", "failed", "security",
			map[string]any{"error": err.Error(), "output": truncate(string(out), 300)})
		writeError(w, http.StatusBadGateway, "apply failed: "+truncate(string(out), 300))
		return
	}
	vlanCount := 0
	for _, z := range cfg.Zones {
		if z.VLANID > 0 {
			vlanCount++
		}
	}
	a.recordSev(r, a.actor(r), "zone-vlans", "netplan", "success", "security",
		map[string]any{"vlans": vlanCount})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "vlans": vlanCount})
}

// apiFirewallDNSApply grants the internal zones access to the Unbound resolver
// (Unbound already listens on all interfaces, so only an access-control allow is
// needed). With no eligible zones it removes the drop-in.
func (a *app) apiFirewallDNSApply(w http.ResponseWriter, r *http.Request) {
	cfg, _ := a.getGateway()
	eligible := 0
	for _, z := range cfg.Zones {
		if z.Kind != "wan" && z.Network != "" {
			eligible++
		}
	}
	if eligible == 0 {
		if out, err := a.runDNSZones(r.Context(), "zone-access-disable"); err != nil {
			writeError(w, http.StatusBadGateway, "disable failed: "+truncate(string(out), 300))
			return
		}
		a.record(r, a.actor(r), "zone-dns", "unbound", "success", map[string]any{"zones": 0})
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "zones": 0})
		return
	}
	conf := dnszones.GenerateAccessConf(cfg.Zones)
	staged := filepath.Join(filepath.Dir(a.store.path), stagedDNSZonesName)
	if err := os.WriteFile(staged, []byte(conf), 0600); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot write staged DNS zones drop-in")
		return
	}
	if out, err := a.runDNSZones(r.Context(), "zone-access-apply"); err != nil {
		a.recordSev(r, a.actor(r), "zone-dns", "unbound", "failed", "warning",
			map[string]any{"error": err.Error(), "output": truncate(string(out), 300)})
		writeError(w, http.StatusBadGateway, "apply failed: "+truncate(string(out), 300))
		return
	}
	a.record(r, a.actor(r), "zone-dns", "unbound", "success", map[string]any{"zones": eligible})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "zones": eligible})
}

func (a *app) apiFirewallAliasesPut(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Aliases []nftgen.Alias `json:"aliases"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	cfg, _ := a.getGateway()
	cfg.Aliases = in.Aliases
	if err := cfg.ValidateObjects(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.setGateway(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist firewall aliases")
		return
	}
	a.record(r, a.actor(r), "firewall-aliases", "objects", "success", map[string]any{"count": len(in.Aliases)})
	writeJSON(w, http.StatusOK, map[string]any{"aliases": cfg.Aliases})
}

func (a *app) apiFirewallRulesPut(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Rules []nftgen.Rule `json:"rules"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	cfg, _ := a.getGateway()
	cfg.Rules = in.Rules
	if err := cfg.ValidateObjects(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.setGateway(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist firewall rules")
		return
	}
	a.record(r, a.actor(r), "firewall-rules", "objects", "success", map[string]any{"count": len(in.Rules)})
	writeJSON(w, http.StatusOK, map[string]any{"rules": cfg.Rules})
}

// apiFirewallApply regenerates the full ruleset (base + aliases + rules) and
// applies it with the confirm-or-rollback window, like the gateway apply.
func (a *app) apiFirewallApply(w http.ResponseWriter, r *http.Request) {
	cfg, ok := a.firewallConfig()
	if !ok || cfg.ClientNetwork == "" {
		writeError(w, http.StatusConflict, "configure the Gateway (client network) before applying firewall rules")
		return
	}
	text, err := cfg.Generate()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	staged := filepath.Join(filepath.Dir(a.store.path), stagedRulesetName)
	if err := os.WriteFile(staged, []byte(text), 0644); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot write staged ruleset")
		return
	}
	if out, err := a.runFirewall(r.Context(), "apply"); err != nil {
		a.recordSev(r, a.actor(r), "firewall-apply", "nftables", "failed", "security",
			map[string]any{"error": err.Error(), "output": truncate(string(out), 300)})
		writeError(w, http.StatusBadGateway, "apply failed: "+truncate(string(out), 300))
		return
	}
	a.recordSev(r, a.actor(r), "firewall-apply", "nftables", "success", "security",
		map[string]any{"aliases": len(cfg.Aliases), "rules": len(cfg.Rules), "confirmWindowSeconds": 120})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "confirmWindowSeconds": 120,
		"message": "ruleset applied; confirm within 120 seconds or it rolls back automatically"})
}
