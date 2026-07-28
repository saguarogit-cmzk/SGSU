package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const stagedDNSForwardName = "staged-dns-forward.conf"

var tlsAuthNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// dnsUpstream is one encrypted (DoT) upstream resolver.
type dnsUpstream struct {
	Address string `json:"address"` // IPv4 or IPv6
	Port    int    `json:"port"`    // 0 -> 853
	Name    string `json:"name"`    // TLS auth name (cert/SNI), e.g. cloudflare-dns.com
}

// dnsForwardConfig forwards all recursion to encrypted upstreams over DNS-over-TLS.
// (Unbound is a native DoT client; DoH upstream is not supported by Unbound.)
type dnsForwardConfig struct {
	Enabled   bool          `json:"enabled"`
	Upstreams []dnsUpstream `json:"upstreams"`
}

func (c dnsForwardConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if len(c.Upstreams) == 0 {
		return fmt.Errorf("at least one upstream is required")
	}
	for _, u := range c.Upstreams {
		if net.ParseIP(strings.TrimSpace(u.Address)) == nil {
			return fmt.Errorf("invalid upstream address %q", u.Address)
		}
		if u.Port < 0 || u.Port > 65535 {
			return fmt.Errorf("upstream port out of range")
		}
		if u.Name != "" && !tlsAuthNameRe.MatchString(strings.ToLower(strings.TrimSpace(u.Name))) {
			return fmt.Errorf("invalid TLS auth name %q", u.Name)
		}
	}
	return nil
}

// GenerateConf renders the Unbound drop-in that forwards "." over DoT. The
// cert bundle lets Unbound authenticate the upstream's certificate.
func (c dnsForwardConfig) GenerateConf() string {
	var b strings.Builder
	b.WriteString("# Managed by Saguaro. Encrypted DNS upstream (DNS-over-TLS).\n")
	b.WriteString("server:\n")
	b.WriteString("  tls-cert-bundle: \"/etc/ssl/certs/ca-certificates.crt\"\n")
	b.WriteString("forward-zone:\n")
	b.WriteString("  name: \".\"\n")
	b.WriteString("  forward-tls-upstream: yes\n")
	for _, u := range c.Upstreams {
		port := u.Port
		if port == 0 {
			port = 853
		}
		line := fmt.Sprintf("  forward-addr: %s@%d", strings.TrimSpace(u.Address), port)
		if n := strings.ToLower(strings.TrimSpace(u.Name)); n != "" {
			line += "#" + n
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

func defaultRunDNSForward(ctx context.Context, action string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "sudo", "-n", "/usr/sbin/saguaro-dns", action).CombinedOutput()
}

func (a *app) getDNSForward() dnsForwardConfig {
	a.store.mu.RLock()
	defer a.store.mu.RUnlock()
	if a.store.data.DNSForward == nil {
		return dnsForwardConfig{Upstreams: []dnsUpstream{}}
	}
	cfg := *a.store.data.DNSForward
	cfg.Upstreams = append([]dnsUpstream(nil), cfg.Upstreams...)
	return cfg
}

func (a *app) setDNSForward(cfg dnsForwardConfig) error {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	a.store.data.DNSForward = &cfg
	return a.store.saveLocked()
}

func (a *app) apiDNSForwardGet(w http.ResponseWriter, _ *http.Request) {
	cfg := a.getDNSForward()
	if cfg.Upstreams == nil {
		cfg.Upstreams = []dnsUpstream{}
	}
	writeJSON(w, http.StatusOK, cfg)
}

// apiDNSForwardApply validates and installs (or removes) the DoT upstream
// drop-in, then reloads Unbound via the adapter (which reverts on a failed
// unbound-checkconf).
func (a *app) apiDNSForwardApply(w http.ResponseWriter, r *http.Request) {
	var in dnsForwardConfig
	if err := decodeJSON(w, r, &in); err != nil {
		return
	}
	if err := in.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !in.Enabled {
		if out, err := a.runDNSForward(r.Context(), "forward-disable"); err != nil {
			writeError(w, http.StatusBadGateway, "disable failed: "+truncate(string(out), 300))
			return
		}
		if err := a.setDNSForward(in); err != nil {
			writeError(w, http.StatusInternalServerError, "cannot persist DNS forward configuration")
			return
		}
		a.record(r, a.actor(r), "dns-forward", "unbound", "success", map[string]any{"enabled": false})
		writeJSON(w, http.StatusOK, in)
		return
	}
	staged := filepath.Join(filepath.Dir(a.store.path), stagedDNSForwardName)
	if err := os.WriteFile(staged, []byte(in.GenerateConf()), 0600); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot write staged forward drop-in")
		return
	}
	if out, err := a.runDNSForward(r.Context(), "forward-apply"); err != nil {
		a.recordSev(r, a.actor(r), "dns-forward", "unbound", "failed", "warning",
			map[string]any{"error": truncate(string(out), 300)})
		writeError(w, http.StatusBadGateway, "apply failed: "+truncate(string(out), 300))
		return
	}
	if err := a.setDNSForward(in); err != nil {
		writeError(w, http.StatusInternalServerError, "cannot persist DNS forward configuration")
		return
	}
	a.record(r, a.actor(r), "dns-forward", "unbound", "success", map[string]any{"upstreams": len(in.Upstreams)})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "upstreams": len(in.Upstreams)})
}
