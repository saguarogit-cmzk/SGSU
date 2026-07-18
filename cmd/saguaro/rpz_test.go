package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRPZApplyAndDisable(t *testing.T) {
	srv, c, a := newTestServer(t)
	var calls []string
	a.runRPZ = func(_ context.Context, action string) ([]byte, error) {
		calls = append(calls, action)
		return []byte("ok"), nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}

	// Invalid domain refused before anything runs.
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/rpz/apply", `{"enabled":true,"domains":["not a domain"],"feeds":[]}`); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad domain: got %d, want 400", r.StatusCode)
	}
	if len(calls) != 0 {
		t.Fatal("adapter must not run on validation failure")
	}

	// Apply writes staged zone + conf and calls the adapter.
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/rpz/apply", `{"enabled":true,"domains":["Ads.Example.COM","tracker.net"],"feeds":["https://feeds.example.org/list.rpz"]}`); r.StatusCode != http.StatusOK {
		t.Fatalf("apply: got %d", r.StatusCode)
	}
	dir := filepath.Dir(a.store.path)
	zone, err := os.ReadFile(filepath.Join(dir, stagedRPZZoneName))
	if err != nil || !strings.Contains(string(zone), "ads.example.com CNAME .") {
		t.Fatalf("staged zone wrong: %v %s", err, zone)
	}
	conf, err := os.ReadFile(filepath.Join(dir, stagedRPZConfName))
	if err != nil || !strings.Contains(string(conf), "saguaro-rpz-feed-1") {
		t.Fatalf("staged conf wrong: %v %s", err, conf)
	}
	if cfg := a.getRPZ(); !cfg.Enabled || len(cfg.Domains) != 2 || cfg.Domains[0] != "ads.example.com" {
		t.Fatalf("persisted config wrong: %+v", cfg)
	}

	// Disable path calls the adapter with disable.
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/rpz/apply", `{"enabled":false,"domains":[],"feeds":[]}`); r.StatusCode != http.StatusOK {
		t.Fatalf("disable: got %d", r.StatusCode)
	}
	if strings.Join(calls, ",") != "apply,disable" {
		t.Fatalf("adapter call sequence wrong: %v", calls)
	}
	if a.getRPZ().Enabled {
		t.Fatal("config must record disabled state")
	}
}

func TestRPZRequiresDNSRole(t *testing.T) {
	srv, admin, a := newTestServer(t)
	a.runRPZ = func(_ context.Context, _ string) ([]byte, error) { return nil, nil }
	if r := doLogin(t, srv, admin, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("admin login: %d", r.StatusCode)
	}
	createUser(t, srv, admin, a, "netonly", roleNetworkOperator)
	netop := loginAs(t, srv, "netonly", operatorPassword)
	if r := reqJSON(t, srv, netop, http.MethodPost, "/api/rpz/apply", `{"enabled":true,"domains":["x.example.com"],"feeds":[]}`); r.StatusCode != http.StatusForbidden {
		t.Fatalf("network-operator rpz apply: got %d, want 403", r.StatusCode)
	}
	createUser(t, srv, admin, a, "dnsguy", roleDNSOperator)
	dns := loginAs(t, srv, "dnsguy", operatorPassword)
	if r := reqJSON(t, srv, dns, http.MethodPost, "/api/rpz/apply", `{"enabled":true,"domains":["x.example.com"],"feeds":[]}`); r.StatusCode != http.StatusOK {
		t.Fatalf("dns-operator rpz apply: got %d, want 200", r.StatusCode)
	}
}
