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
	cfg, ok := a.getGateway()
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
