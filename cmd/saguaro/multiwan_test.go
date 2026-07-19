package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"saguaro.local/network-manager/internal/adapters/multiwan"
	"saguaro.local/network-manager/internal/adapters/nftgen"
)

const multiwanBody = `{"enabled":true,"uplinks":[` +
	`{"name":"wan1","interface":"enp1","gateway":"192.168.50.1","weight":2,"healthCheck":"1.1.1.1"},` +
	`{"name":"wan2","interface":"enp2","gateway":"192.168.205.1","weight":1,"healthCheck":"8.8.8.8"}]}`

func TestMultiWANApply(t *testing.T) {
	srv, c, a := newTestServer(t)
	var actions []string
	a.runWAN = func(_ context.Context, action string) ([]byte, error) {
		actions = append(actions, action)
		return []byte("ok"), nil
	}
	if r := doLogin(t, srv, c, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("login: %d", r.StatusCode)
	}
	// Multi-WAN needs gateway mode; without it, enabling is refused.
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/multiwan/apply", multiwanBody); r.StatusCode != http.StatusConflict {
		t.Fatalf("apply without gateway: got %d, want 409", r.StatusCode)
	}
	// Fewer than two uplinks is a validation error.
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/multiwan/apply",
		`{"enabled":true,"uplinks":[{"name":"wan1","interface":"enp1","gateway":"192.168.50.1","weight":1}]}`); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("single uplink: got %d, want 400", r.StatusCode)
	}
	// Enable gateway mode, then apply succeeds, stages the spec and calls apply.
	if err := a.setGateway(nftgen.Config{AdminNetwork: "192.168.50.0/24", ClientNetwork: "10.10.10.0/24",
		GatewayEnabled: true, WANInterface: "enp1", LANInterface: "enp2", NATEnabled: true}); err != nil {
		t.Fatal(err)
	}
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/multiwan/apply", multiwanBody); r.StatusCode != http.StatusOK {
		t.Fatalf("apply with gateway: got %d", r.StatusCode)
	}
	spec, err := os.ReadFile(filepath.Join(filepath.Dir(a.store.path), stagedWANName))
	if err != nil || !strings.Contains(string(spec), "enp1") || !strings.Contains(string(spec), "enp2") {
		t.Fatalf("staged multi-WAN spec wrong: %v %s", err, spec)
	}
	if cfg := a.getWAN(); !cfg.Enabled || len(cfg.Uplinks) != 2 || cfg.Uplinks[0].Weight != 2 {
		t.Fatalf("persisted config wrong: %+v", cfg)
	}
	// Disable calls the adapter's disable and clears the enabled flag.
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/multiwan/apply",
		`{"enabled":false,"uplinks":[]}`); r.StatusCode != http.StatusOK {
		t.Fatalf("disable: got %d", r.StatusCode)
	}
	if cfg := a.getWAN(); cfg.Enabled {
		t.Fatal("disable did not clear enabled flag")
	}
	if strings.Join(actions, ",") != "apply,disable" {
		t.Fatalf("adapter sequence wrong: %v", actions)
	}

	// GET returns the stored config as JSON.
	resp, _ := c.Get(srv.URL + "/api/multiwan")
	var got multiwan.Config
	json.NewDecoder(resp.Body).Decode(&got)
	resp.Body.Close()
	if got.Enabled {
		t.Fatalf("GET should reflect disabled config: %+v", got)
	}
}

func TestMultiWANRequiresFirewallRole(t *testing.T) {
	srv, admin, a := newTestServer(t)
	a.runWAN = func(_ context.Context, _ string) ([]byte, error) { return nil, nil }
	if r := doLogin(t, srv, admin, testPassword); r.StatusCode != http.StatusOK {
		t.Fatalf("admin login: %d", r.StatusCode)
	}
	createUser(t, srv, admin, a, "dnswan", roleDNSOperator)
	dns := loginAs(t, srv, "dnswan", operatorPassword)
	if r := reqJSON(t, srv, dns, http.MethodPost, "/api/multiwan/apply", multiwanBody); r.StatusCode != http.StatusForbidden {
		t.Fatalf("dns-operator multiwan apply: got %d, want 403", r.StatusCode)
	}
}
