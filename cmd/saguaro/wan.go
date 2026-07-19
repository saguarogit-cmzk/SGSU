package main

import (
	"net/http"
	"os"
	"path/filepath"

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

func (a *app) apiWANConfigGet(w http.ResponseWriter, _ *http.Request) {
	wans := a.getWANs()
	// Seed a first WAN from the gateway's WAN interface if nothing is configured.
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
