package main

import (
	"net/http"
	"os"
	"path/filepath"

	"saguaro.local/network-manager/internal/adapters/nftgen"
)

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
	writeJSON(w, http.StatusOK, map[string]any{
		"aliases": aliases, "rules": rules,
		"configured": ok && cfg.AdminNetwork != "", "gatewayEnabled": cfg.GatewayEnabled,
		"pending": firewallPending(),
	})
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
	if !ok || cfg.AdminNetwork == "" {
		writeError(w, http.StatusConflict, "configure the Gateway (management/client networks) before applying firewall rules")
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
