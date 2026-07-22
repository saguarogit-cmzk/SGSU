package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"

	"saguaro.local/network-manager/internal/adapters/wancfg"
)

const stagedWANNetplanName = "staged-wan-netplan.yaml"

// getWANs returns the configured WAN interfaces, migrating the legacy single
// WANConfig into the list on first read.
func (a *app) getWANs() []wancfg.WAN {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	if len(a.store.data.WANConfigs) == 0 && a.store.data.WANConfig != nil {
		a.store.data.WANConfigs = []wancfg.WAN{*a.store.data.WANConfig}
		a.store.data.WANConfig = nil
		_ = a.store.saveLocked()
	}
	return append([]wancfg.WAN(nil), a.store.data.WANConfigs...)
}

func (a *app) setWANs(wans []wancfg.WAN) error {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	a.store.data.WANConfigs = wans
	a.store.data.WANConfig = nil
	return a.store.saveLocked()
}

// defaultRoute is one entry from `ip -json route show default`.
type defaultRoute struct {
	Dev      string `json:"dev"`
	Gateway  string `json:"gateway"`
	Protocol string `json:"protocol"`
	Metric   int    `json:"metric"`
}

func defaultReadDefaultRoutes(ctx context.Context) ([]defaultRoute, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ip", "-json", "route", "show", "default").Output()
	if err != nil {
		return nil, err
	}
	var routes []defaultRoute
	if err := json.Unmarshal(out, &routes); err != nil {
		return nil, err
	}
	return routes, nil
}

// detectWANs infers the uplinks the box already has from its live default
// routes. Applying this form rewrites the whole WAN netplan, so opening it on a
// blank row invites an operator to wipe an uplink they were never shown -- on an
// appliance reached through one of those uplinks, that is the session as well.
// Whatever the store knows still wins; this only fills in an empty store.
func (a *app) detectWANs(ctx context.Context) []wancfg.WAN {
	routes, err := a.readDefaultRoutes(ctx)
	if err != nil {
		return nil
	}
	addrs := map[string][]string{}
	if nics, err := a.readInterfaces(ctx); err == nil {
		for _, n := range nics {
			addrs[n.Name] = n.Addresses
		}
	}
	seen := map[string]bool{}
	var out []wancfg.WAN
	for _, r := range routes {
		if r.Dev == "" || r.Gateway == "" || seen[r.Dev] {
			continue
		}
		seen[r.Dev] = true
		wan := wancfg.WAN{Interface: r.Dev, Metric: r.Metric, DNS: []string{}, Aliases: []string{}}
		if r.Protocol == "dhcp" {
			wan.Mode = "dhcp"
		} else {
			// A route the kernel did not learn from DHCP means static addressing;
			// carry the address across so the row round-trips unchanged.
			wan.Mode = "static"
			wan.Gateway = r.Gateway
			if list := addrs[r.Dev]; len(list) > 0 {
				wan.Address = list[0]
			}
		}
		if wan.Validate() != nil {
			continue
		}
		out = append(out, wan)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Metric < out[j].Metric })
	return out
}

func (a *app) apiWANConfigGet(w http.ResponseWriter, r *http.Request) {
	wans := a.getWANs()
	// Nothing stored yet: show what the box actually runs, falling back to the
	// gateway's WAN interface only when even the routing table has nothing.
	if len(wans) == 0 {
		wans = a.detectWANs(r.Context())
	}
	if len(wans) == 0 {
		iface := ""
		if gw, ok := a.getGateway(); ok {
			iface = gw.WANInterface
		}
		wans = []wancfg.WAN{{Interface: iface, Mode: "dhcp", Metric: 100, DNS: []string{}, Aliases: []string{}}}
	}
	for i := range wans {
		if wans[i].DNS == nil {
			wans[i].DNS = []string{}
		}
		if wans[i].Aliases == nil {
			wans[i].Aliases = []string{}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"wans": wans})
}

// apiWANConfigApply validates the WAN list, renders one combined netplan and
// applies it through the root adapter.
func (a *app) apiWANConfigApply(w http.ResponseWriter, r *http.Request) {
	var in struct {
		WANs []wancfg.WAN `json:"wans"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	if len(in.WANs) == 0 {
		writeError(w, http.StatusBadRequest, "at least one WAN interface is required")
		return
	}
	yaml, err := wancfg.GenerateNetplanMulti(in.WANs)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	staged := filepath.Join(filepath.Dir(a.store.path), stagedWANNetplanName)
	if err := os.WriteFile(staged, []byte(yaml), 0600); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot write staged WAN netplan")
		return
	}
	if out, err := a.runNet(r.Context(), "wan-apply"); err != nil {
		a.recordSev(r, a.actor(r), "wan-config", "netplan", "failed", "security",
			map[string]any{"error": err.Error(), "output": truncate(string(out), 300)})
		writeError(w, http.StatusBadGateway, "apply failed: "+truncate(string(out), 300))
		return
	}
	if err := a.setWANs(in.WANs); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist WAN configuration")
		return
	}
	a.recordSev(r, a.actor(r), "wan-config", "netplan", "success", "security",
		map[string]any{"interfaces": len(in.WANs)})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "wans": in.WANs})
}
