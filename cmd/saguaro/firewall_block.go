package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"saguaro.local/network-manager/internal/adapters/nftgen"
)

// The one-click "block IP" action maintains a single host alias and one
// top-priority drop rule that references it. The rule lands in the forward
// chain, so it drops the offender's transited traffic without ever touching the
// input chain that carries management access -- blocking can't lock the admin out.
const blocklistAlias = "blocklist"
const blockRuleName = "Auto-blokada"

// blocklistIPs returns the IPs currently in the auto-blocklist alias.
func (a *app) blocklistIPs() []string {
	cfg, ok := a.getGateway()
	if !ok {
		return nil
	}
	for _, al := range cfg.Aliases {
		if al.Name == blocklistAlias {
			return append([]string(nil), al.Values...)
		}
	}
	return nil
}

func (a *app) apiFirewallBlocklist(w http.ResponseWriter, _ *http.Request) {
	ips := a.blocklistIPs()
	if ips == nil {
		ips = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ips": ips})
}

// applyAndConfirm regenerates the ruleset from the stored config, loads it, and
// immediately confirms it. Block/unblock must take effect permanently at once --
// a security block must never auto-revert after the 120 s confirm window.
func (a *app) applyAndConfirm(r *http.Request) error {
	cfg, ok := a.firewallConfig()
	if !ok {
		return fmt.Errorf("gateway is not configured")
	}
	text, err := cfg.Generate()
	if err != nil {
		return err
	}
	staged := filepath.Join(filepath.Dir(a.store.path), stagedRulesetName)
	if err := os.WriteFile(staged, []byte(text), 0644); err != nil {
		return fmt.Errorf("cannot stage ruleset")
	}
	if out, err := a.runFirewall(r.Context(), "apply"); err != nil {
		return fmt.Errorf("apply failed: %s", truncate(string(out), 200))
	}
	if out, err := a.runFirewall(r.Context(), "confirm"); err != nil {
		return fmt.Errorf("confirm failed: %s", truncate(string(out), 200))
	}
	return nil
}

func (a *app) apiFirewallBlockIP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IP string `json:"ip"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	ip := strings.TrimSpace(in.IP)
	if p := net.ParseIP(ip); p == nil || p.To4() == nil {
		writeError(w, http.StatusBadRequest, "block target must be an IPv4 address")
		return
	}
	cfg, ok := a.getGateway()
	if !ok || cfg.ClientNetwork == "" {
		writeError(w, http.StatusConflict, "configure the Gateway before blocking traffic")
		return
	}
	// Add to the blocklist alias, creating it as a host alias if absent.
	foundAlias, already := false, false
	for i := range cfg.Aliases {
		if cfg.Aliases[i].Name == blocklistAlias {
			foundAlias = true
			for _, v := range cfg.Aliases[i].Values {
				if v == ip {
					already = true
				}
			}
			if !already {
				cfg.Aliases[i].Values = append(cfg.Aliases[i].Values, ip)
			}
		}
	}
	if !foundAlias {
		cfg.Aliases = append(cfg.Aliases, nftgen.Alias{Name: blocklistAlias, Type: "host", Values: []string{ip}})
	}
	// Ensure the top-priority, logged drop rule exists.
	hasRule := false
	for _, ru := range cfg.Rules {
		if ru.Name == blockRuleName {
			hasRule = true
		}
	}
	if !hasRule {
		rule := nftgen.Rule{Name: blockRuleName, Action: "drop", Proto: "any",
			SrcAlias: blocklistAlias, Category: "other", Log: true, Enabled: true}
		cfg.Rules = append([]nftgen.Rule{rule}, cfg.Rules...)
	}
	if err := a.setGateway(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist blocklist")
		return
	}
	if err := a.applyAndConfirm(r); err != nil {
		a.recordSev(r, a.actor(r), "firewall-block-ip", "nftables", "failed", "security",
			map[string]any{"ip": ip, "error": err.Error()})
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	a.recordSev(r, a.actor(r), "firewall-block-ip", "nftables", "success", "security",
		map[string]any{"ip": ip})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ip": ip, "ips": a.blocklistIPs()})
}

func (a *app) apiFirewallUnblockIP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IP string `json:"ip"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	ip := strings.TrimSpace(in.IP)
	cfg, ok := a.getGateway()
	if !ok {
		writeError(w, http.StatusConflict, "gateway is not configured")
		return
	}
	// Remove the IP; if the blocklist becomes empty, drop the alias and its rule
	// together so no rule is left referencing a non-existent set.
	empty := false
	for i := range cfg.Aliases {
		if cfg.Aliases[i].Name == blocklistAlias {
			kept := cfg.Aliases[i].Values[:0]
			for _, v := range cfg.Aliases[i].Values {
				if v != ip {
					kept = append(kept, v)
				}
			}
			cfg.Aliases[i].Values = kept
			empty = len(kept) == 0
		}
	}
	if empty {
		var al []nftgen.Alias
		for _, x := range cfg.Aliases {
			if x.Name != blocklistAlias {
				al = append(al, x)
			}
		}
		cfg.Aliases = al
		var ru []nftgen.Rule
		for _, x := range cfg.Rules {
			if x.Name != blockRuleName {
				ru = append(ru, x)
			}
		}
		cfg.Rules = ru
	}
	if err := a.setGateway(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist blocklist")
		return
	}
	if err := a.applyAndConfirm(r); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	a.recordSev(r, a.actor(r), "firewall-unblock-ip", "nftables", "success", "security",
		map[string]any{"ip": ip})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ips": a.blocklistIPs()})
}
