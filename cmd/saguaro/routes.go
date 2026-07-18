package main

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	routesmod "saguaro.local/network-manager/internal/adapters/routes"
)

const stagedRoutesName = "staged-routes.spec"

func defaultRunRoute(ctx context.Context, action string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "sudo", "-n", "/usr/sbin/saguaro-route", action).CombinedOutput()
}

func (a *app) getRoutes() routesmod.Config {
	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	if a.store.data.Routes == nil {
		return routesmod.Config{Routes: []routesmod.Route{}}
	}
	cfg := *a.store.data.Routes
	cfg.Routes = append([]routesmod.Route(nil), cfg.Routes...)
	return cfg
}

func (a *app) setRoutes(cfg routesmod.Config) error {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	a.store.data.Routes = &cfg
	return a.store.saveLocked()
}

func (a *app) apiRoutesGet(w http.ResponseWriter, _ *http.Request) {
	cfg := a.getRoutes()
	if cfg.Routes == nil {
		cfg.Routes = []routesmod.Route{}
	}
	writeJSON(w, http.StatusOK, cfg)
}

// apiRoutesPut replaces the full static-route set transactionally: validate,
// stage the spec, apply via the adapter, then persist. An empty set flushes.
func (a *app) apiRoutesPut(w http.ResponseWriter, r *http.Request) {
	var in routesmod.Config
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	if in.Routes == nil {
		in.Routes = []routesmod.Route{}
	}
	if err := in.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(in.Routes) == 0 {
		if out, err := a.runRoute(r.Context(), "flush"); err != nil {
			writeError(w, http.StatusBadGateway, "flush failed: "+truncate(string(out), 300))
			return
		}
		if err := a.setRoutes(in); err != nil {
			writeError(w, http.StatusInternalServerError, "cannot persist routes")
			return
		}
		a.recordSev(r, a.actor(r), "routes-apply", "routing", "success", "warning", map[string]any{"routes": 0})
		writeJSON(w, http.StatusOK, in)
		return
	}
	spec, err := in.GenerateSpec()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	staged := filepath.Join(filepath.Dir(a.store.path), stagedRoutesName)
	if err := os.WriteFile(staged, []byte(spec), 0644); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot write staged route spec")
		return
	}
	if out, err := a.runRoute(r.Context(), "apply"); err != nil {
		a.recordSev(r, a.actor(r), "routes-apply", "routing", "failed", "security", map[string]any{"error": truncate(string(out), 300)})
		writeError(w, http.StatusBadGateway, "apply failed: "+truncate(string(out), 300))
		return
	}
	if err := a.setRoutes(in); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist routes")
		return
	}
	a.recordSev(r, a.actor(r), "routes-apply", "routing", "success", "security", map[string]any{"routes": len(in.Routes)})
	writeJSON(w, http.StatusOK, in)
}
