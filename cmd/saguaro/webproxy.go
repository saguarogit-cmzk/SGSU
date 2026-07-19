package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"saguaro.local/network-manager/internal/adapters/squidcfg"
)

func errFromOutput(msg string, out []byte, err error) error {
	if s := truncate(string(out), 300); s != "" {
		return fmt.Errorf("%s: %s", msg, s)
	}
	return fmt.Errorf("%s: %w", msg, err)
}

func defaultRunWebProxy(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	full := append([]string{"-n", "/usr/sbin/saguaro-webproxy"}, args...)
	return exec.CommandContext(ctx, "sudo", full...).CombinedOutput()
}

func (a *app) getWebProxy() squidcfg.Config {
	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	if a.store.data.WebProxy == nil {
		return squidcfg.Config{FilterPort: squidcfg.DefaultFilterPort, BannedSites: []string{}, ExceptionSites: []string{}}
	}
	cfg := *a.store.data.WebProxy
	cfg.BannedSites = append([]string(nil), cfg.BannedSites...)
	cfg.ExceptionSites = append([]string(nil), cfg.ExceptionSites...)
	return cfg
}

func (a *app) setWebProxy(cfg squidcfg.Config) error {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	a.store.data.WebProxy = &cfg
	return a.store.saveLocked()
}

func (a *app) applyWebProxy(ctx context.Context, cfg squidcfg.Config) error {
	if !cfg.Enabled {
		if out, err := a.runWebProxy(ctx, "disable"); err != nil {
			return errFromOutput("disable failed", out, err)
		}
		return nil
	}
	dropin, err := cfg.GenerateSquidDropIn()
	if err != nil {
		return err
	}
	banned, err := cfg.GenerateBanned()
	if err != nil {
		return err
	}
	exc, err := cfg.GenerateExceptions()
	if err != nil {
		return err
	}
	dir := filepath.Dir(a.store.path)
	if err := os.WriteFile(filepath.Join(dir, "staged-squid.conf"), []byte(dropin), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "staged-e2g-banned"), []byte(banned), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "staged-e2g-exceptions"), []byte(exc), 0644); err != nil {
		return err
	}
	filter := "0"
	if cfg.Filtering {
		filter = "1"
	}
	if out, err := a.runWebProxy(ctx, "apply", strconv.Itoa(cfg.FilterPortOrDefault()), filter); err != nil {
		return errFromOutput("apply failed", out, err)
	}
	return nil
}

func (a *app) apiWebProxyGet(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.getWebProxy())
}

func (a *app) apiWebProxyPut(w http.ResponseWriter, r *http.Request) {
	var in squidcfg.Config
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	if in.BannedSites == nil {
		in.BannedSites = []string{}
	}
	if in.ExceptionSites == nil {
		in.ExceptionSites = []string{}
	}
	if err := in.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.applyWebProxy(r.Context(), in); err != nil {
		a.recordSev(r, a.actor(r), "webproxy-apply", "squid", "failed", "warning", map[string]any{"error": err.Error()})
		writeError(w, http.StatusBadGateway, friendlyError(err, "Web proxy"))
		return
	}
	if err := a.setWebProxy(in); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist web proxy configuration")
		return
	}
	a.recordSev(r, a.actor(r), "webproxy-apply", "squid", "success", "warning",
		map[string]any{"enabled": in.Enabled, "filtering": in.Filtering, "port": in.FilterPortOrDefault()})
	writeJSON(w, http.StatusOK, in)
}
