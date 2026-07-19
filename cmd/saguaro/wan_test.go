package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"saguaro.local/network-manager/internal/adapters/wancfg"
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
	// two WAN interfaces: DHCP primary + static secondary
	body := `{"wans":[
		{"interface":"enp1s0","mode":"dhcp","metric":100},
		{"interface":"enp2s0","mode":"static","address":"203.0.113.5/24","gateway":"203.0.113.1","dns":["1.1.1.1"],"metric":200}
	]}`
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/wan/apply", body); r.StatusCode != http.StatusOK {
		t.Fatalf("wan apply: got %d", r.StatusCode)
	}
	if len(calls) != 1 || calls[0] != "wan-apply" {
		t.Fatalf("adapter call wrong: %v", calls)
	}
	yaml, err := os.ReadFile(filepath.Join(filepath.Dir(a.store.path), stagedWANNetplanName))
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"enp1s0:", "route-metric: 100", "enp2s0:", "203.0.113.5/24", "via: 203.0.113.1", "metric: 200"} {
		if !strings.Contains(string(yaml), w) {
			t.Fatalf("staged netplan missing %q:\n%s", w, yaml)
		}
	}
	if wans := a.getWANs(); len(wans) != 2 {
		t.Fatalf("WANs not persisted: %+v", wans)
	}
	// invalid static address rejected before the adapter runs
	if r := reqJSON(t, srv, c, http.MethodPost, "/api/wan/apply",
		`{"wans":[{"interface":"enp1s0","mode":"static","address":"203.0.113.5","gateway":"203.0.113.1"}]}`); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad address: got %d, want 400", r.StatusCode)
	}
}

func TestWANLegacyMigration(t *testing.T) {
	_, _, a := newTestServer(t)
	// simulate a pre-list install with a single WANConfig
	legacy := wancfg.WAN{Interface: "enp1s0", Mode: "dhcp"}
	a.store.mu.Lock()
	a.store.data.WANConfig = &legacy
	a.store.mu.Unlock()
	wans := a.getWANs()
	if len(wans) != 1 || wans[0].Interface != "enp1s0" {
		t.Fatalf("legacy WAN not migrated: %+v", wans)
	}
	if a.store.data.WANConfig != nil {
		t.Fatal("legacy field not cleared after migration")
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
	if r := reqJSON(t, srv, aud, http.MethodPost, "/api/wan/apply", `{"wans":[{"interface":"enp1s0","mode":"dhcp"}]}`); r.StatusCode != http.StatusForbidden {
		t.Fatalf("auditor apply: got %d, want 403", r.StatusCode)
	}
}
