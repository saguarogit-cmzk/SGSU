package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// checkResult is the outcome of one component health probe. Status values
// match the service.Status vocabulary shown in the GUI.
type checkResult struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"` // healthy | error | not-configured | unknown
	Detail    string    `json:"detail,omitempty"`
	LatencyMs int64     `json:"latencyMs"`
	CheckedAt time.Time `json:"checkedAt"`
}

func result(id, status, detail string, started time.Time) checkResult {
	return checkResult{ID: id, Status: status, Detail: detail, LatencyMs: time.Since(started).Milliseconds(), CheckedAt: time.Now().UTC()}
}

// checkPostgres pings the session database; without a DSN the appliance runs
// the development file store and PostgreSQL is reported as not configured.
func (a *app) checkPostgres(ctx context.Context) checkResult {
	started := time.Now()
	pg, ok := a.sessions.(*pgSessions)
	if !ok {
		return result("postgresql", "not-configured", "file session store (no SAGUARO_DB_DSN)", started)
	}
	if err := pg.db.PingContext(ctx); err != nil {
		return result("postgresql", "error", err.Error(), started)
	}
	return result("postgresql", "healthy", "ping ok", started)
}

// checkUnbound verifies the resolver accepts TCP connections on port 53.
// A full recursive query is deliberately avoided: on an isolated network it
// would fail even though the resolver itself is perfectly healthy.
func (a *app) checkUnbound(ctx context.Context) checkResult {
	started := time.Now()
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", a.resolverAddr)
	if err != nil {
		return result("unbound", "error", err.Error(), started)
	}
	conn.Close()
	return result("unbound", "healthy", "tcp connect "+a.resolverAddr, started)
}

// checkPDNS calls the PowerDNS HTTP API with the configured key.
func (a *app) checkPDNS(ctx context.Context) checkResult {
	started := time.Now()
	if a.pdnsURL == "" || a.pdnsKey == "" {
		return result("pdns", "not-configured", "SAGUARO_PDNS_API_URL/KEY not set", started)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(a.pdnsURL, "/")+"/api/v1/servers/localhost", nil)
	if err != nil {
		return result("pdns", "error", err.Error(), started)
	}
	req.Header.Set("X-API-Key", a.pdnsKey)
	resp, err := healthHTTP.Do(req)
	if err != nil {
		return result("pdns", "error", err.Error(), started)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusOK:
		var info struct {
			Version string `json:"version"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&info)
		return result("pdns", "healthy", "API ok, version "+info.Version, started)
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return result("pdns", "error", "API key rejected", started)
	default:
		return result("pdns", "error", fmt.Sprintf("API returned HTTP %d", resp.StatusCode), started)
	}
}

// checkKea sends status-get for one Kea service (dhcp4 or d2) through the
// control agent using HTTP basic auth.
func (a *app) checkKea(ctx context.Context, id, service string) checkResult {
	started := time.Now()
	if a.keaURL == "" || a.keaUser == "" || a.keaPass == "" {
		return result(id, "not-configured", "SAGUARO_KEA_API_URL/USER/PASSWORD not set", started)
	}
	payload, _ := json.Marshal(map[string]any{"command": "status-get", "service": []string{service}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.keaURL, bytes.NewReader(payload))
	if err != nil {
		return result(id, "error", err.Error(), started)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(a.keaUser, a.keaPass)
	resp, err := healthHTTP.Do(req)
	if err != nil {
		return result(id, "error", err.Error(), started)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return result(id, "error", "control agent rejected credentials", started)
	}
	if resp.StatusCode != http.StatusOK {
		return result(id, "error", fmt.Sprintf("control agent returned HTTP %d", resp.StatusCode), started)
	}
	var answers []struct {
		Result int    `json:"result"`
		Text   string `json:"text"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&answers); err != nil || len(answers) == 0 {
		return result(id, "error", "unparseable control agent response", started)
	}
	if answers[0].Result != 0 {
		return result(id, "error", fmt.Sprintf("%s: %s", service, answers[0].Text), started)
	}
	return result(id, "healthy", service+" status ok", started)
}

// checkSystemdUnit asks systemd for the unit's active state. On hosts without
// systemctl (development) the state is unknown rather than an error.
func checkSystemdUnit(ctx context.Context, id, unit string) checkResult {
	started := time.Now()
	if _, err := exec.LookPath("systemctl"); err != nil {
		return result(id, "unknown", "systemctl not available", started)
	}
	out, err := exec.CommandContext(ctx, "systemctl", "is-active", unit).Output()
	state := strings.TrimSpace(string(out))
	if err != nil && state == "" {
		return result(id, "error", err.Error(), started)
	}
	if state == "active" {
		return result(id, "healthy", unit+" active", started)
	}
	return result(id, "error", unit+" is "+state, started)
}

var healthHTTP = &http.Client{Timeout: 5 * time.Second}

// runHealthChecks probes every component in parallel and pushes the outcome
// into the service table the dashboard reads.
func (a *app) runHealthChecks(ctx context.Context) []checkResult {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	checks := map[string]func(context.Context) checkResult{
		"postgresql": a.checkPostgres,
		"unbound":    a.checkUnbound,
		"pdns":       a.checkPDNS,
		"kea":        func(ctx context.Context) checkResult { return a.checkKea(ctx, "kea", "dhcp4") },
		"kea-ddns":   func(ctx context.Context) checkResult { return a.checkKea(ctx, "kea-ddns", "d2") },
		"step-ca":    func(ctx context.Context) checkResult { return checkSystemdUnit(ctx, "step-ca", "step-ca-saguaro") },
		"nginx":      func(ctx context.Context) checkResult { return checkSystemdUnit(ctx, "nginx", "nginx") },
		"nftables":   func(ctx context.Context) checkResult { return checkSystemdUnit(ctx, "nftables", "nftables") },
	}
	var (
		mu  sync.Mutex
		out []checkResult
		wg  sync.WaitGroup
	)
	for _, fn := range checks {
		wg.Add(1)
		go func(fn func(context.Context) checkResult) {
			defer wg.Done()
			r := fn(ctx)
			mu.Lock()
			out = append(out, r)
			mu.Unlock()
		}(fn)
	}
	wg.Wait()
	a.store.setServiceStatuses(out)
	return out
}

// runHealthCheck probes a single service by ID; ok is false for unknown IDs.
func (a *app) runHealthCheck(ctx context.Context, id string) (checkResult, bool) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	var r checkResult
	switch id {
	case "postgresql":
		r = a.checkPostgres(ctx)
	case "unbound":
		r = a.checkUnbound(ctx)
	case "pdns":
		r = a.checkPDNS(ctx)
	case "kea":
		r = a.checkKea(ctx, "kea", "dhcp4")
	case "kea-ddns":
		r = a.checkKea(ctx, "kea-ddns", "d2")
	case "step-ca":
		r = checkSystemdUnit(ctx, "step-ca", "step-ca-saguaro")
	case "nginx":
		r = checkSystemdUnit(ctx, "nginx", "nginx")
	case "nftables":
		r = checkSystemdUnit(ctx, "nftables", "nftables")
	default:
		return checkResult{}, false
	}
	a.store.setServiceStatuses([]checkResult{r})
	return r, true
}

func (s *store) setServiceStatuses(results []checkResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	byID := map[string]checkResult{}
	for _, r := range results {
		byID[r.ID] = r
	}
	changed := false
	for i := range s.data.Services {
		if r, ok := byID[s.data.Services[i].ID]; ok && s.data.Services[i].Status != r.Status {
			s.data.Services[i].Status = r.Status
			changed = true
		}
	}
	if changed {
		_ = s.saveLocked()
	}
}
