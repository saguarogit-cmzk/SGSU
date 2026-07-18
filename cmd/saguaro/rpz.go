package main

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	rpzmod "saguaro.local/network-manager/internal/adapters/rpz"
)

const (
	stagedRPZZoneName = "staged-rpz.zone"
	stagedRPZConfName = "staged-rpz.conf"
	rpzZonePath       = "/var/lib/unbound/saguaro-rpz.zone"
)

func defaultRunRPZ(ctx context.Context, action string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "sudo", "-n", "/usr/sbin/saguaro-rpz", action).CombinedOutput()
}

func (a *app) getRPZ() rpzmod.Config {
	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	if a.store.data.RPZ == nil {
		return rpzmod.Config{Domains: []string{}, Feeds: []string{}}
	}
	cfg := *a.store.data.RPZ
	cfg.Domains = append([]string(nil), cfg.Domains...)
	cfg.Feeds = append([]string(nil), cfg.Feeds...)
	return cfg
}

func (a *app) setRPZ(cfg rpzmod.Config) error {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	a.store.data.RPZ = &cfg
	return a.store.saveLocked()
}

func (a *app) apiRPZGet(w http.ResponseWriter, _ *http.Request) {
	cfg := a.getRPZ()
	if cfg.Domains == nil {
		cfg.Domains = []string{}
	}
	if cfg.Feeds == nil {
		cfg.Feeds = []string{}
	}
	writeJSON(w, http.StatusOK, cfg)
}

// apiRPZApply saves the configuration, stages zone + Unbound drop-in and
// applies through the root adapter. RPZ has no hardware gate — it is the
// security tier for low-spec devices.
func (a *app) apiRPZApply(w http.ResponseWriter, r *http.Request) {
	var in rpzmod.Config
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	normalized := make([]string, 0, len(in.Domains))
	for _, d := range in.Domains {
		nd, err := rpzmod.NormalizeDomain(d)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		normalized = append(normalized, nd)
	}
	in.Domains = normalized
	if err := in.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !in.Enabled {
		if out, err := a.runRPZ(r.Context(), "disable"); err != nil {
			writeError(w, http.StatusBadGateway, "disable failed: "+truncate(string(out), 300))
			return
		}
		if err := a.setRPZ(in); err != nil {
			writeError(w, http.StatusInternalServerError, "cannot persist RPZ configuration")
			return
		}
		a.recordSev(r, a.actor(r), "rpz-disable", "unbound", "success", "warning", nil)
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	zone, err := in.GenerateZone(time.Now().Unix())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	conf, err := in.GenerateConf(rpzZonePath)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	dir := filepath.Dir(a.store.path)
	if err := os.WriteFile(filepath.Join(dir, stagedRPZZoneName), []byte(zone), 0644); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot write staged zone")
		return
	}
	if err := os.WriteFile(filepath.Join(dir, stagedRPZConfName), []byte(conf), 0644); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot write staged config")
		return
	}
	if out, err := a.runRPZ(r.Context(), "apply"); err != nil {
		a.recordSev(r, a.actor(r), "rpz-apply", "unbound", "failed", "security",
			map[string]any{"error": err.Error(), "output": truncate(string(out), 300)})
		writeError(w, http.StatusBadGateway, "apply failed: "+truncate(string(out), 300))
		return
	}
	if err := a.setRPZ(in); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist RPZ configuration")
		return
	}
	a.recordSev(r, a.actor(r), "rpz-apply", "unbound", "success", "security",
		map[string]any{"domains": len(in.Domains), "feeds": len(in.Feeds)})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "domains": len(in.Domains), "feeds": len(in.Feeds)})
}
