package main

import (
	"net/http"
	"os"
	"path/filepath"

	"saguaro.local/network-manager/internal/adapters/wancfg"
)

const stagedWANNetplanName = "staged-wan-netplan.yaml"

func (a *app) getWANCfg() (wancfg.WAN, bool) {
	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	if a.store.data.WANConfig == nil {
		return wancfg.WAN{}, false
	}
	cfg := *a.store.data.WANConfig
	cfg.DNS = append([]string(nil), cfg.DNS...)
	return cfg, true
}

func (a *app) setWANCfg(cfg wancfg.WAN) error {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	a.store.data.WANConfig = &cfg
	return a.store.saveLocked()
}

func (a *app) apiWANConfigGet(w http.ResponseWriter, _ *http.Request) {
	cfg, ok := a.getWANCfg()
	if cfg.Interface == "" {
		if gw, gok := a.getGateway(); gok {
			cfg.Interface = gw.WANInterface
		}
	}
	if cfg.Mode == "" {
		cfg.Mode = "dhcp"
	}
	if cfg.DNS == nil {
		cfg.DNS = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"config": cfg, "configured": ok})
}

// apiWANConfigApply validates the addressing, renders and stages the netplan,
// then applies it through the root adapter.
func (a *app) apiWANConfigApply(w http.ResponseWriter, r *http.Request) {
	var in wancfg.WAN
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	if in.Interface == "" {
		if gw, ok := a.getGateway(); ok {
			in.Interface = gw.WANInterface
		}
	}
	if err := in.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	yaml, err := in.GenerateNetplan()
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
		a.recordSev(r, a.actor(r), "wan-config", in.Interface, "failed", "security",
			map[string]any{"error": err.Error(), "output": truncate(string(out), 300)})
		writeError(w, http.StatusBadGateway, "apply failed: "+truncate(string(out), 300))
		return
	}
	if err := a.setWANCfg(in); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist WAN configuration")
		return
	}
	a.recordSev(r, a.actor(r), "wan-config", in.Interface, "success", "security",
		map[string]any{"mode": in.Mode, "address": in.Address})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "config": in})
}
