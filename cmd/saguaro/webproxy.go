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
	cfg.SpliceSites = append([]string(nil), cfg.SpliceSites...)
	return cfg
}

// bumpCAPath is where the adapter publishes the public SSL-bump CA for download.
const bumpCAPath = "/var/lib/saguaro/webproxy-bump-ca.crt"

// apiWebProxyCA serves the public SSL-bump CA certificate so operators can
// distribute it to client devices (which must trust it for HTTPS interception).
func (a *app) apiWebProxyCA(w http.ResponseWriter, _ *http.Request) {
	pem, err := os.ReadFile(bumpCAPath)
	if err != nil {
		writeError(w, http.StatusNotFound, "SSL-bump CA not generated yet — enable SSL-bump first")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="saguaro-web-proxy-ca.crt"`)
	_, _ = w.Write(pem)
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
	// SSL-bump needs its CA and cert-generator DB in place before squid -k parse
	// validates the config that references them.
	if cfg.SSLBump {
		if out, err := a.runWebProxy(ctx, "bump-ca"); err != nil {
			return errFromOutput("SSL-bump CA setup failed", out, err)
		}
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
	// Flatten the stored config and add the catalog of built-in categories so the
	// GUI can render a toggle per category alongside the enabled keys.
	writeJSON(w, http.StatusOK, struct {
		squidcfg.Config
		CategoryCatalog []squidcfg.Category `json:"categoryCatalog"`
	}{a.getWebProxy(), squidcfg.Categories()})
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
	if in.SpliceSites == nil {
		in.SpliceSites = []string{}
	}
	if in.Categories == nil {
		in.Categories = []string{}
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
