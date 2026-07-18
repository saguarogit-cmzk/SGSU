package main

import (
	"context"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// controllableServices is the fixed set the GUI can start/stop/restart. The
// keys mirror the allow-list in /usr/sbin/saguaro-svc, which owns the real
// key->unit mapping; the control plane only ever passes a key.
var controllableServices = []struct{ Key, Name string }{
	{"postgresql", "PostgreSQL"},
	{"unbound", "Unbound (resolver)"},
	{"pdns", "PowerDNS (authoritative)"},
	{"kea-dhcp4", "Kea DHCPv4"},
	{"kea-ddns", "Kea DDNS"},
	{"kea-ctrl-agent", "Kea Control Agent"},
	{"nginx", "Nginx (GUI / proxy)"},
	{"nftables", "nftables (firewall)"},
	{"suricata", "Suricata IDS/IPS"},
	{"strongswan", "IPsec (strongSwan)"},
	{"wg-vpn", "WireGuard VPN"},
	{"wg-s2s", "WireGuard Site-to-Site"},
	{"step-ca", "Step CA"},
	{"saguaro-eventd", "Event Collector"},
}

var controllableSet = func() map[string]bool {
	m := map[string]bool{}
	for _, s := range controllableServices {
		m[s.Key] = true
	}
	return m
}()

var svcActions = map[string]bool{"start": true, "stop": true, "restart": true}

func defaultRunSvc(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	full := append([]string{"-n", "/usr/sbin/saguaro-svc"}, args...)
	return exec.CommandContext(ctx, "sudo", full...).CombinedOutput()
}

// apiSvcCtlList returns the controllable services with their current state in a
// single adapter call (statusall).
func (a *app) apiSvcCtlList(w http.ResponseWriter, r *http.Request) {
	states := map[string]string{}
	if out, err := a.runSvc(r.Context(), "statusall"); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			f := strings.Fields(line)
			if len(f) == 2 {
				states[f[0]] = f[1]
			}
		}
	}
	list := make([]map[string]any, 0, len(controllableServices))
	for _, s := range controllableServices {
		state := states[s.Key]
		if state == "" {
			state = "unknown"
		}
		list = append(list, map[string]any{"key": s.Key, "name": s.Name, "state": state})
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *app) apiSvcCtlAction(w http.ResponseWriter, r *http.Request) {
	key, action := r.PathValue("key"), r.PathValue("action")
	if !controllableSet[key] {
		writeError(w, http.StatusNotFound, "unknown service")
		return
	}
	if !svcActions[action] {
		writeError(w, http.StatusBadRequest, "action must be start, stop or restart")
		return
	}
	out, err := a.runSvc(r.Context(), action, key)
	state := strings.TrimSpace(string(out))
	if err != nil {
		a.recordSev(r, a.actor(r), "service-"+action, key, "failed", "warning",
			map[string]any{"output": truncate(string(out), 300)})
		writeError(w, http.StatusBadGateway, action+" failed: "+truncate(string(out), 300))
		return
	}
	a.recordSev(r, a.actor(r), "service-"+action, key, "success", "warning", map[string]any{"state": state})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "key": key, "action": action, "state": state})
}
