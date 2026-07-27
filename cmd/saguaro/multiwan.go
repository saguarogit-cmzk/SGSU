package main

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"saguaro.local/network-manager/internal/adapters/multiwan"
)

const stagedWANName = "staged-wan.spec"
const stagedWANModeName = "staged-wan.mode"

func defaultRunWAN(ctx context.Context, action string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "sudo", "-n", "/usr/sbin/saguaro-wan", action).CombinedOutput()
}

func (a *app) getWAN() multiwan.Config {
	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	if a.store.data.MultiWAN == nil {
		return multiwan.Config{Uplinks: []multiwan.Uplink{}}
	}
	cfg := *a.store.data.MultiWAN
	cfg.Uplinks = append([]multiwan.Uplink(nil), cfg.Uplinks...)
	return cfg
}

func (a *app) setWAN(cfg multiwan.Config) error {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	a.store.data.MultiWAN = &cfg
	return a.store.saveLocked()
}

func (a *app) apiWANGet(w http.ResponseWriter, _ *http.Request) {
	cfg := a.getWAN()
	if cfg.Uplinks == nil {
		cfg.Uplinks = []multiwan.Uplink{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": cfg.Enabled, "mode": cfg.GenerateMode(), "uplinks": cfg.Uplinks,
		"pending": wanPending()})
}

func (a *app) apiWANApply(w http.ResponseWriter, r *http.Request) {
	var in multiwan.Config
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	if err := in.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Multi-WAN is a gateway feature; it only makes sense once routing is on.
	if in.Enabled {
		gw, ok := a.getGateway()
		if !ok || !gw.GatewayEnabled {
			writeError(w, http.StatusConflict, "multi-WAN requires gateway mode (W8) first")
			return
		}
	}
	if !in.Enabled {
		if out, err := a.runWAN(r.Context(), "disable"); err != nil {
			writeError(w, http.StatusBadGateway, "disable failed: "+truncate(string(out), 300))
			return
		}
		if err := a.setWAN(in); err != nil {
			writeError(w, http.StatusInternalServerError, "cannot persist multi-WAN configuration")
			return
		}
		// Remove the per-uplink connmark mangle chain now that multi-WAN is off.
		a.syncFirewallForWAN(r)
		a.recordSev(r, a.actor(r), "multiwan-config", "routing", "success", "warning", map[string]any{"enabled": false})
		writeJSON(w, http.StatusOK, in)
		return
	}
	spec, err := in.GenerateSpec()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	staged := filepath.Join(filepath.Dir(a.store.path), stagedWANName)
	if err := os.WriteFile(staged, []byte(spec), 0644); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot write staged spec")
		return
	}
	stagedMode := filepath.Join(filepath.Dir(a.store.path), stagedWANModeName)
	if err := os.WriteFile(stagedMode, []byte(in.GenerateMode()+"\n"), 0644); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot write staged mode")
		return
	}
	if out, err := a.runWAN(r.Context(), "apply"); err != nil {
		a.recordSev(r, a.actor(r), "multiwan-config", "routing", "failed", "security", map[string]any{"error": truncate(string(out), 300)})
		writeError(w, http.StatusBadGateway, "apply failed: "+truncate(string(out), 300))
		return
	}
	if err := a.setWAN(in); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist multi-WAN configuration")
		return
	}
	// Regenerate the firewall so the per-uplink connmark mangle chain is added.
	// Without it replies leave via the wrong WAN (asymmetric routing) and TCP over
	// the secondary uplink breaks -- the manual "re-apply firewall" step, automated.
	a.syncFirewallForWAN(r)
	a.recordSev(r, a.actor(r), "multiwan-config", "routing", "success", "security", map[string]any{"uplinks": len(in.Uplinks)})
	writeJSON(w, http.StatusOK, map[string]any{"config": in, "confirmWindowSeconds": 120,
		"message": "multi-WAN applied; confirm within 120 seconds or it rolls back automatically"})
}

func wanPending() bool {
	_, err := os.Stat("/run/saguaro/wan-pending")
	return err == nil
}

// syncFirewallForWAN regenerates the firewall so the per-uplink connmark mangle
// chain matches the current multi-WAN state (added when enabled, removed when
// disabled) -- symmetric routing depends on it. Best-effort: the WAN routes are
// already applied, so a firewall hiccup is logged, not fatal to the WAN change.
func (a *app) syncFirewallForWAN(r *http.Request) {
	if _, ok := a.firewallConfig(); !ok {
		return
	}
	if err := a.applyAndConfirm(r); err != nil {
		a.recordSev(r, a.actor(r), "multiwan-fwsync", "nftables", "failed", "warning",
			map[string]any{"error": err.Error()})
	}
}

func (a *app) apiWANConfirm(w http.ResponseWriter, r *http.Request) {
	if out, err := a.runWAN(r.Context(), "confirm"); err != nil {
		writeError(w, http.StatusBadGateway, "confirm failed: "+truncate(string(out), 200))
		return
	}
	a.recordSev(r, a.actor(r), "multiwan-confirm", "routing", "success", "security", nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *app) apiWANRollback(w http.ResponseWriter, r *http.Request) {
	if out, err := a.runWAN(r.Context(), "disable"); err != nil {
		writeError(w, http.StatusBadGateway, "rollback failed: "+truncate(string(out), 200))
		return
	}
	cfg := a.getWAN()
	cfg.Enabled = false
	_ = a.setWAN(cfg)
	a.recordSev(r, a.actor(r), "multiwan-rollback", "routing", "success", "security", nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
