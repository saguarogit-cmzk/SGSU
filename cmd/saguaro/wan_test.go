package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWANConfigApply(t *testing.T) {
	srv, c, a := newTestServer(t)
	var calls []string
	a.runNet = func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		return []byte("ok"), nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	body := `{"interface":"enp1s0","mode":"static","address":"203.0.113.5/24","gateway":"203.0.113.1","dns":["1.1.1.1"]}`
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/wan/apply", body); r.StatusCode != http.StatusOK {
		t.Fatalf("wan apply: got %d", r.StatusCode)
	}
	if len(calls) != 1 || calls[0] != "wan-apply" {
		t.Fatalf("adapter call wrong: %v", calls)
	}
	staged := filepath.Join(filepath.Dir(a.store.path), stagedWANNetplanName)
	yaml, err := os.ReadFile(staged)
	if err != nil || !strings.Contains(string(yaml), "203.0.113.5/24") || !strings.Contains(string(yaml), "via: 203.0.113.1") {
		t.Fatalf("staged netplan wrong: %v %s", err, yaml)
	}
	if cfg, ok := a.getWANCfg(); !ok || cfg.Mode != "static" {
		t.Fatalf("wan config not persisted: %+v", cfg)
	}
	// invalid static address rejected before the adapter runs
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/wan/apply",
		`{"interface":"enp1s0","mode":"static","address":"203.0.113.5","gateway":"203.0.113.1"}`); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad address: got %d, want 400", r.StatusCode)
	}
}

func TestWANConfigRequiresRole(t *testing.T) {
	srv, admin, a := newTestServer(t)
	a.runNet = func(context.Context, ...string) ([]byte, error) { return nil, nil }
	if r := doLogin(t, srv, admin, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("admin login: %d", r.StatusCode)
	}
	createUser(t, srv, admin, a, "auditor1", roleAuditor)
	aud := loginAs(t, srv, "auditor1", operatorPassword)
	if r := reqJSON(t, srv, aud, http.MethodGet, "/api/wan", ""); r.StatusCode != http.StatusOK {
		t.Fatalf("auditor get: got %d, want 200", r.StatusCode)
	}
	if r := reqJSON(t, srv, aud, http.MethodPost, "/api/wan/apply", `{"interface":"enp1s0","mode":"dhcp"}`); r.StatusCode != http.StatusForbidden {
		t.Fatalf("auditor apply: got %d, want 403", r.StatusCode)
	}
}
