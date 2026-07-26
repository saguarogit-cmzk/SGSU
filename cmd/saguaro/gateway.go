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

	"saguaro.local/network-manager/internal/adapters/nftgen"
)

const stagedRulesetName = "staged-nftables.conf"
const firewallPendingFlag = "/run/saguaro/firewall-pending"

// runFirewall executes the root adapter through sudo; tests replace it.
func defaultRunFirewall(ctx context.Context, action string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "sudo", "-n", "/usr/sbin/saguaro-firewall", action).CombinedOutput()
}

func (a *app) getGateway() (nftgen.Config, bool) {
	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	if a.store.data.Gateway == nil {
		return nftgen.Config{}, false
	}
	cfg := *a.store.data.Gateway
	cfg.PortForwards = append([]nftgen.PortForward(nil), cfg.PortForwards...)
	cfg.Aliases = append([]nftgen.Alias(nil), cfg.Aliases...)
	cfg.Rules = append([]nftgen.Rule(nil), cfg.Rules...)
	cfg.SNATRules = append([]nftgen.SNATRule(nil), cfg.SNATRules...)
	return cfg, true
}

func (a *app) setGateway(cfg nftgen.Config) error {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	a.store.data.Gateway = &cfg
	return a.store.saveLocked()
}

// nic is one entry from `ip -json addr show`.
type nic struct {
	Name      string   `json:"name"`
	State     string   `json:"state"`
	Addresses []string `json:"addresses"`
}

func listNICs(ctx context.Context) ([]nic, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ip", "-json", "addr", "show").Output()
	if err != nil {
		return nil, err
	}
	var raw []struct {
		Ifname    string `json:"ifname"`
		Operstate string `json:"operstate"`
		AddrInfo  []struct {
			Local     string `json:"local"`
			Prefixlen int    `json:"prefixlen"`
			Family    string `json:"family"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, err
	}
	var out2 []nic
	for _, r := range raw {
		if r.Ifname == "lo" {
			continue
		}
		n := nic{Name: r.Ifname, State: strings.ToLower(r.Operstate)}
		for _, ai := range r.AddrInfo {
			if ai.Family == "inet" {
				n.Addresses = append(n.Addresses, ai.Local)
			}
		}
		out2 = append(out2, n)
	}
	return out2, nil
}

func firewallPending() bool {
	_, err := os.Stat(firewallPendingFlag)
	return err == nil
}

func (a *app) apiGatewayGet(w http.ResponseWriter, r *http.Request) {
	cfg, configured := a.getGateway()
	nics, err := listNICs(r.Context())
	if err != nil {
		nics = []nic{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"config": cfg, "configured": configured, "nics": nics, "pending": firewallPending(),
	})
}

func (a *app) apiGatewayPut(w http.ResponseWriter, r *http.Request) {
	var in nftgen.Config
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	if err := in.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// In router mode the appliance sits behind another gateway and must not do
	// WAN routing/NAT. Enabling gateway mode requires the "gateway" profile.
	if in.GatewayEnabled && a.getProfile() != profileGateway {
		writeError(w, http.StatusConflict,
			"deployment mode is 'router'; switch System profile to Gateway to enable WAN/NAT")
		return
	}
	// The gateway form does not carry firewall aliases/rules or the IPS toggle;
	// keep the fields the Firewall and IDS pages own so saving the gateway never
	// wipes them. Losing IPSEnabled here would silently drop the NFQUEUE rule and
	// disable inline IPS on the next apply while the IDS page still reads "ips".
	if cur, ok := a.getGateway(); ok {
		in.Aliases, in.Rules, in.Zones, in.IPSEnabled = cur.Aliases, cur.Rules, cur.Zones, cur.IPSEnabled
		in.GeoCountries = cur.GeoCountries
	}
	if err := a.setGateway(in); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist gateway configuration")
		return
	}
	a.record(r, a.actor(r), "gateway-config", "firewall", "success", map[string]any{
		"gateway": in.GatewayEnabled, "wan": in.WANInterface, "lan": in.LANInterface,
		"nat": in.NATEnabled, "portForwards": len(in.PortForwards)})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *app) apiGatewayPreview(w http.ResponseWriter, r *http.Request) {
	cfg, ok := a.firewallConfig()
	if !ok {
		writeError(w, http.StatusBadRequest, "gateway is not configured yet")
		return
	}
	text, err := cfg.Generate()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ruleset": text})
}

// apiGatewayApply stages the generated ruleset and calls the root adapter,
// which loads it with a 120 s confirm-or-rollback window.
func (a *app) apiGatewayApply(w http.ResponseWriter, r *http.Request) {
	cfg, ok := a.firewallConfig()
	if !ok {
		writeError(w, http.StatusBadRequest, "gateway is not configured yet")
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
		map[string]any{"gateway": cfg.GatewayEnabled, "confirmWindowSeconds": 120})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "confirmWindowSeconds": 120,
		"message": "ruleset applied; confirm within 120 seconds or it rolls back automatically"})
}

func (a *app) apiGatewayConfirm(w http.ResponseWriter, r *http.Request) {
	if out, err := a.runFirewall(r.Context(), "confirm"); err != nil {
		writeError(w, http.StatusBadGateway, "confirm failed: "+truncate(string(out), 300))
		return
	}
	a.recordSev(r, a.actor(r), "firewall-confirm", "nftables", "success", "security", nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *app) apiGatewayRollback(w http.ResponseWriter, r *http.Request) {
	if out, err := a.runFirewall(r.Context(), "rollback"); err != nil {
		writeError(w, http.StatusBadGateway, "rollback failed: "+truncate(string(out), 300))
		return
	}
	a.recordSev(r, a.actor(r), "firewall-rollback", "nftables", "success", "security", nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
